//! Интеграционные тесты: настоящий релей на случайном порту + WebSocket-клиенты.

use crypto_core::{Bundle, Identity, PeerKeys, PrekeySecrets, SessionSet};
use futures_util::{SinkExt, StreamExt};
use protocol::{ClientMessage, EnvelopeB64, ServerMessage, SignedPrekey, b64, decode_fixed};
use relay_server::ratelimit::Rate;
use relay_server::{Config, Relay};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite::Message};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct Server {
    addr: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    async fn start(config: Config) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let relay = Relay::new(config).unwrap();
        let (stop, rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            relay
                .serve(listener, async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });
        Self {
            addr,
            stop: Some(stop),
            task,
        }
    }

    async fn stop(mut self) {
        let _ = self.stop.take().unwrap().send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), self.task).await;
    }

    fn url(&self) -> String {
        format!("ws://{}/ws", self.addr)
    }
}

struct Client {
    ws: Ws,
    id: Identity,
    sessions: HashMap<String, SessionSet>,
}

/// Подписанный предключ каждого тестового участника (по ключу подписи —
/// имена вроде "alice" повторяются в параллельных тестах).
type PrekeyRegistry = Mutex<HashMap<[u8; 32], ([u8; 32], SignedPrekey)>>;

fn prekey_of(id: &Identity) -> ([u8; 32], SignedPrekey) {
    static KEYS: OnceLock<PrekeyRegistry> = OnceLock::new();
    *KEYS
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .entry(id.sign_public_bytes())
        .or_insert_with(|| id.new_signed_prekey(1))
}

fn keys_of(id: &Identity) -> PeerKeys {
    PeerKeys {
        account_id: id.account_id().into(),
        device_id: id.device_id(),
        x25519_pub: id.x_public_bytes(),
        ed25519_pub: id.sign_public_bytes(),
    }
}

/// Конверт от `from` к `to` (через свежую сессию).
fn make_envelope(from: &Identity, to: &Identity, text: &str) -> EnvelopeB64 {
    let mut set = SessionSet::default();
    let bundle = Bundle {
        signed_prekey: prekey_of(to).1,
        one_time: None,
    };
    from.start_session(&keys_of(to), &bundle, &mut set).unwrap();
    EnvelopeB64::from(&from.seal(&keys_of(to), &mut set, text.as_bytes()).unwrap())
}

impl Client {
    async fn raw(url: &str) -> Ws {
        tokio_tungstenite::connect_async(url).await.unwrap().0
    }

    /// Подключиться и пройти вход.
    async fn connect(url: &str, id: &Identity) -> Client {
        let mut c = Client::unauthenticated(url, id).await;
        let nonce = c.challenge().await;
        c.auth_with(&nonce, id).await;
        match c.recv().await {
            ServerMessage::Authenticated {
                account_id,
                device_id,
            } => assert_eq!(
                (account_id.as_str(), device_id),
                (id.account_id(), id.device_id())
            ),
            other => panic!("expected Authenticated, got {other:?}"),
        }
        c
    }

    /// Подключиться и получить первое сообщение после входа (ожидается ошибка).
    async fn connect_err(url: &str, id: &Identity) -> ServerMessage {
        let mut c = Client::unauthenticated(url, id).await;
        let nonce = c.challenge().await;
        c.auth_with(&nonce, id).await;
        c.recv().await
    }

    async fn unauthenticated(url: &str, id: &Identity) -> Client {
        Client {
            ws: Self::raw(url).await,
            id: id.clone(),
            sessions: HashMap::new(),
        }
    }

    async fn challenge(&mut self) -> [u8; 32] {
        match self.recv().await {
            ServerMessage::Challenge { nonce_b64 } => {
                decode_fixed::<32>(&nonce_b64, "nonce").unwrap()
            }
            other => panic!("expected Challenge, got {other:?}"),
        }
    }

    async fn auth_with(&mut self, nonce: &[u8; 32], signer: &Identity) {
        let account_id = self.id.account_id().to_string();
        let device_id = self.id.device_id();
        let sig = signer.sign(&protocol::relay_auth_signing_bytes(
            nonce,
            &account_id,
            device_id,
        ));
        self.send(ClientMessage::Auth {
            account_id,
            device_id,
            sign_pub_b64: b64(signer.sign_public_bytes()),
            sig_b64: b64(sig),
        })
        .await;
    }

    async fn send(&mut self, m: ClientMessage) {
        self.ws
            .send(Message::Text(serde_json::to_string(&m).unwrap()))
            .await
            .unwrap();
    }

    /// Следующее сообщение, кроме служебного `PrekeyStatus`.
    async fn recv(&mut self) -> ServerMessage {
        loop {
            match self.recv_any().await {
                ServerMessage::PrekeyStatus { .. } => continue,
                other => return other,
            }
        }
    }

    async fn recv_any(&mut self) -> ServerMessage {
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(3), self.ws.next())
                .await
                .expect("timed out waiting for a server message")
                .expect("connection closed")
                .unwrap();
            if let Message::Text(t) = msg {
                return serde_json::from_str(&t).unwrap();
            }
        }
    }

    /// Убедиться, что релей ничего не присылает (служебный статус не в счёт).
    async fn expect_silence(&mut self) {
        let until = tokio::time::Instant::now() + Duration::from_millis(300);
        while let Ok(Some(Ok(msg))) = tokio::time::timeout_at(until, self.ws.next()).await {
            if let Message::Text(t) = msg {
                if !t.contains(r#""type":"prekey_status""#) {
                    panic!("expected no messages, got {t}");
                }
            }
        }
    }

    fn envelope(&mut self, to: &Identity, text: &str) -> EnvelopeB64 {
        let set = self.sessions.entry(dev(to)).or_default();
        if set.is_empty() {
            let bundle = Bundle {
                signed_prekey: prekey_of(to).1,
                one_time: None,
            };
            self.id.start_session(&keys_of(to), &bundle, set).unwrap();
        }
        EnvelopeB64::from(&self.id.seal(&keys_of(to), set, text.as_bytes()).unwrap())
    }

    async fn send_text(&mut self, to: &Identity, msg_id: &str, text: &str) -> ServerMessage {
        let envelope = self.envelope(to, text);
        self.send(ClientMessage::Send {
            to: to.account_id().into(),
            to_device: to.device_id(),
            msg_id: msg_id.into(),
            envelope,
        })
        .await;
        self.recv().await
    }

    /// Получить сообщение и расшифровать его.
    async fn recv_text(&mut self, from: &Identity) -> (String, String) {
        match self.recv().await {
            ServerMessage::Deliver {
                from: f,
                from_device,
                msg_id,
                envelope,
            } => {
                assert_eq!(
                    (f.as_str(), from_device),
                    (from.account_id(), from.device_id())
                );
                let env = protocol::Envelope::try_from(envelope).unwrap();
                let secrets = PrekeySecrets {
                    signed_prekey: Some(prekey_of(&self.id).0),
                    ..Default::default()
                };
                let set = self.sessions.entry(dev(from)).or_default();
                let opened = self.id.open(&keys_of(from), set, &env, &secrets).unwrap();
                (msg_id, String::from_utf8(opened.plaintext).unwrap())
            }
            other => panic!("expected Deliver, got {other:?}"),
        }
    }

    async fn ack(&mut self, to: &Identity, msg_id: &str) {
        self.send(ClientMessage::Ack {
            to: to.account_id().into(),
            to_device: to.device_id(),
            msg_id: msg_id.into(),
        })
        .await;
    }
}

/// Ключ сессии: «аккаунт/устройство».
fn dev(id: &Identity) -> String {
    format!("{}/{}", id.account_id(), id.device_id())
}

fn accepted(m: &ServerMessage, id: &str) {
    assert_eq!(m, &ServerMessage::Accepted { msg_id: id.into() });
}

fn tmp_db(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("relay-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("relay.sqlite")
}

#[tokio::test]
async fn online_delivery_with_ack() {
    let server = Server::start(Config::default()).await;
    let (alice, bob) = (Identity::generate("alice"), Identity::generate("bob"));
    let mut a = Client::connect(&server.url(), &alice).await;
    let mut b = Client::connect(&server.url(), &bob).await;

    accepted(&a.send_text(&bob, "m1", "привет, Боб").await, "m1");
    assert_eq!(
        b.recv_text(&alice).await,
        ("m1".into(), "привет, Боб".into())
    );

    b.ack(&alice, "m1").await;
    assert_eq!(
        a.recv().await,
        ServerMessage::DeliverAck {
            from: "bob".into(),
            from_device: 1,
            msg_id: "m1".into()
        }
    );

    // Повторный ack ничего не делает.
    b.ack(&alice, "m1").await;
    a.expect_silence().await;
    server.stop().await;
}

#[tokio::test]
async fn offline_queue_is_kept_until_ack() {
    let server = Server::start(Config::default()).await;
    let (alice, bob) = (Identity::generate("alice"), Identity::generate("bob"));
    let mut a = Client::connect(&server.url(), &alice).await;

    // Боб офлайн.
    accepted(&a.send_text(&bob, "m1", "первое").await, "m1");
    accepted(&a.send_text(&bob, "m2", "второе").await, "m2");
    // Повторная отправка того же msg_id не создаёт дубль в очереди.
    accepted(&a.send_text(&bob, "m1", "первое").await, "m1");

    // Боб пришёл, но не подтвердил — сообщения должны остаться.
    {
        let mut b = Client::connect(&server.url(), &bob).await;
        assert_eq!(b.recv_text(&alice).await.1, "первое");
        assert_eq!(b.recv_text(&alice).await.1, "второе");
        b.expect_silence().await;
    }

    // Переподключился — получил то же самое, подтвердил первое.
    let mut b = Client::connect(&server.url(), &bob).await;
    assert_eq!(b.recv_text(&alice).await.0, "m1");
    assert_eq!(b.recv_text(&alice).await.0, "m2");
    b.ack(&alice, "m1").await;
    assert_eq!(
        a.recv().await,
        ServerMessage::DeliverAck {
            from: "bob".into(),
            from_device: 1,
            msg_id: "m1".into()
        }
    );
    drop(b);

    let mut b = Client::connect(&server.url(), &bob).await;
    assert_eq!(b.recv_text(&alice).await.0, "m2");
    b.expect_silence().await;
    server.stop().await;
}

#[tokio::test]
async fn delivery_ack_waits_for_offline_sender() {
    let server = Server::start(Config::default()).await;
    let (alice, bob) = (Identity::generate("alice"), Identity::generate("bob"));
    {
        let mut a = Client::connect(&server.url(), &alice).await;
        accepted(&a.send_text(&bob, "m1", "hi").await, "m1");
    }
    let mut b = Client::connect(&server.url(), &bob).await;
    b.recv_text(&alice).await;
    b.ack(&alice, "m1").await;
    b.expect_silence().await;

    let mut a = Client::connect(&server.url(), &alice).await;
    assert_eq!(
        a.recv().await,
        ServerMessage::DeliverAck {
            from: "bob".into(),
            from_device: 1,
            msg_id: "m1".into()
        }
    );
    drop(a);
    // Уведомление о доставке приходит один раз.
    let mut a = Client::connect(&server.url(), &alice).await;
    a.expect_silence().await;
    server.stop().await;
}

#[tokio::test]
async fn impersonation_is_rejected() {
    let server = Server::start(Config::default()).await;
    let alice = Identity::generate("alice");
    let _a = Client::connect(&server.url(), &alice).await; // ключ Алисы закреплён

    // Мэллори пытается войти как "alice" со своим ключом.
    let mallory_as_alice = Identity::generate("alice");
    let mut m = Client::unauthenticated(&server.url(), &mallory_as_alice).await;
    let nonce = m.challenge().await;
    m.auth_with(&nonce, &mallory_as_alice).await;
    assert!(
        matches!(m.recv().await, ServerMessage::Error { message, .. } if message.contains("different key"))
    );

    // Подпись не того nonce.
    let mut m = Client::unauthenticated(&server.url(), &alice).await;
    let _ = m.challenge().await;
    m.auth_with(&[0u8; 32], &alice).await;
    assert!(
        matches!(m.recv().await, ServerMessage::Error { message, .. } if message.contains("signature"))
    );
    server.stop().await;
}

/// Регрессия: TOFU позволял «застолбить» чужой ID до того, как владелец
/// впервые подключится. ID, выведенный из ключа, проверяется сразу.
#[tokio::test]
async fn key_derived_ids_cannot_be_squatted() {
    let server = Server::start(Config::default()).await;
    let alice = Identity::generate_new(); // ещё ни разу не заходила на релей

    let squatter = Identity::from_secrets(
        alice.account_id(),
        Identity::generate_new().x_secret_bytes(),
        Identity::generate_new().sign_secret_bytes(),
    );
    let mut m = Client::unauthenticated(&server.url(), &squatter).await;
    let nonce = m.challenge().await;
    m.auth_with(&nonce, &squatter).await;
    assert!(
        matches!(m.recv().await, ServerMessage::Error { message, .. } if message.contains("does not belong"))
    );

    // Настоящая Алиса заходит спокойно.
    Client::connect(&server.url(), &alice).await;
    server.stop().await;
}

#[tokio::test]
async fn nothing_works_before_auth() {
    let server = Server::start(Config::default()).await;
    let (alice, bob) = (Identity::generate("alice"), Identity::generate("bob"));
    let mut c = Client::unauthenticated(&server.url(), &alice).await;
    let _ = c.challenge().await;
    let envelope = c.envelope(&bob, "x");
    c.send(ClientMessage::Send {
        to: "bob".into(),
        to_device: 1,
        msg_id: "m".into(),
        envelope,
    })
    .await;
    assert!(
        matches!(c.recv().await, ServerMessage::Error { message, .. } if message.contains("authenticate"))
    );
    server.stop().await;
}

#[tokio::test]
async fn auth_times_out() {
    let server = Server::start(Config {
        auth_timeout: Duration::from_millis(200),
        ..Config::default()
    })
    .await;
    let mut c = Client::unauthenticated(&server.url(), &Identity::generate("x")).await;
    let _ = c.challenge().await;
    assert!(
        matches!(c.recv().await, ServerMessage::Error { message, .. } if message.contains("timeout"))
    );
    server.stop().await;
}

#[tokio::test]
async fn forged_or_mismatched_envelopes_are_rejected() {
    let server = Server::start(Config::default()).await;
    let (alice, bob, carol) = (
        Identity::generate("alice"),
        Identity::generate("bob"),
        Identity::generate("carol"),
    );
    let mut a = Client::connect(&server.url(), &alice).await;
    let mut b = Client::connect(&server.url(), &bob).await;

    // Конверт, подписанный не Алисой.
    let impostor = Identity::generate("alice");
    let forged = make_envelope(&impostor, &bob, "x");
    a.send(ClientMessage::Send {
        to: "bob".into(),
        to_device: 1,
        msg_id: "f1".into(),
        envelope: forged,
    })
    .await;
    assert!(matches!(a.recv().await, ServerMessage::Error { msg_id: Some(id), .. } if id == "f1"));

    // Конверт для Кэрол, отправленный Бобу.
    let for_carol = a.envelope(&carol, "x");
    a.send(ClientMessage::Send {
        to: "bob".into(),
        to_device: 1,
        msg_id: "f2".into(),
        envelope: for_carol,
    })
    .await;
    assert!(matches!(a.recv().await, ServerMessage::Error { msg_id: Some(id), .. } if id == "f2"));

    // Мусор в JSON.
    a.ws.send(Message::Text("{not json".into())).await.unwrap();
    assert!(matches!(a.recv().await, ServerMessage::Error { .. }));

    b.expect_silence().await;
    server.stop().await;
}

#[tokio::test]
async fn fake_ack_does_not_reach_sender() {
    let server = Server::start(Config::default()).await;
    let (alice, mallory) = (Identity::generate("alice"), Identity::generate("mallory"));
    let mut a = Client::connect(&server.url(), &alice).await;
    let mut m = Client::connect(&server.url(), &mallory).await;
    m.ack(&alice, "never-sent").await;
    a.expect_silence().await;
    server.stop().await;
}

/// Регрессия: раньше отключение старого сокета выкидывало из онлайна новый.
#[tokio::test]
async fn reconnect_keeps_newest_connection_online() {
    let server = Server::start(Config::default()).await;
    let (alice, bob) = (Identity::generate("alice"), Identity::generate("bob"));
    let old = Client::connect(&server.url(), &bob).await;
    let mut new = Client::connect(&server.url(), &bob).await;
    drop(old);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut a = Client::connect(&server.url(), &alice).await;
    accepted(&a.send_text(&bob, "m1", "ты тут?").await, "m1");
    assert_eq!(new.recv_text(&alice).await.1, "ты тут?");
    server.stop().await;
}

#[tokio::test]
async fn silent_connections_are_dropped() {
    let server = Server::start(Config {
        ping_interval: Duration::from_millis(100),
        ..Config::default()
    })
    .await;
    let mut c = Client::connect(&server.url(), &Identity::generate("ghost")).await;
    // Не читаем сокет — значит, не отвечаем на пинги, как «пропавший» телефон.
    tokio::time::sleep(Duration::from_millis(600)).await;
    let closed = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match c.ws.next().await {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return true,
                Some(Ok(_)) => {}
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(closed, "relay should close an unresponsive connection");
    server.stop().await;
}

#[tokio::test]
async fn live_connections_survive_pings() {
    let server = Server::start(Config {
        ping_interval: Duration::from_millis(100),
        ..Config::default()
    })
    .await;
    let (alice, bob) = (Identity::generate("alice"), Identity::generate("bob"));
    let mut b = Client::connect(&server.url(), &bob).await;
    assert!(matches!(
        b.recv_any().await,
        ServerMessage::PrekeyStatus { .. }
    ));
    // Боб «слушает» дольше трёх интервалов пинга: читает сокет и тем самым отвечает на пинги.
    let until = tokio::time::Instant::now() + Duration::from_millis(600);
    while let Ok(Some(Ok(msg))) = tokio::time::timeout_at(until, b.ws.next()).await {
        assert!(
            !matches!(msg, Message::Close(_) | Message::Text(_)),
            "unexpected {msg:?}"
        );
    }
    let mut a = Client::connect(&server.url(), &alice).await;
    accepted(&a.send_text(&bob, "m1", "всё ещё тут").await, "m1");
    assert_eq!(b.recv_text(&alice).await.1, "всё ещё тут");
    server.stop().await;
}

/// Регрессия: `listen` и `send` одного пользователя подключены одновременно.
/// Раньше второе соединение вытесняло первое, а после его закрытия релей
/// забывал и про первое — сообщения переставали доходить до `listen`.
#[tokio::test]
async fn several_connections_of_one_account_all_receive() {
    let server = Server::start(Config::default()).await;
    let (alice, bob) = (Identity::generate("alice"), Identity::generate("bob"));
    let mut listen = Client::connect(&server.url(), &bob).await;
    let mut a = Client::connect(&server.url(), &alice).await;

    {
        let mut send = Client::connect(&server.url(), &bob).await;
        accepted(&a.send_text(&bob, "m1", "обоим").await, "m1");
        assert_eq!(listen.recv_text(&alice).await.1, "обоим");
        assert_eq!(send.recv_text(&alice).await.1, "обоим");
        send.ack(&alice, "m1").await;
        assert_eq!(
            a.recv().await,
            ServerMessage::DeliverAck {
                from: "bob".into(),
                from_device: 1,
                msg_id: "m1".into()
            }
        );
    }
    // Второе соединение закрылось — первое по-прежнему получает.
    tokio::time::sleep(Duration::from_millis(100)).await;
    accepted(&a.send_text(&bob, "m2", "только listen").await, "m2");
    assert_eq!(listen.recv_text(&alice).await.1, "только listen");
    server.stop().await;
}

#[tokio::test]
async fn queue_limit_is_enforced() {
    let server = Server::start(Config {
        max_queue_per_recipient: 2,
        ..Config::default()
    })
    .await;
    let (alice, bob) = (Identity::generate("alice"), Identity::generate("bob"));
    let mut a = Client::connect(&server.url(), &alice).await;
    accepted(&a.send_text(&bob, "m1", "1").await, "m1");
    accepted(&a.send_text(&bob, "m2", "2").await, "m2");
    assert!(
        matches!(a.send_text(&bob, "m3", "3").await, ServerMessage::Error { msg_id: Some(id), .. } if id == "m3")
    );
    // Повтор уже лежащего в очереди — не ошибка.
    accepted(&a.send_text(&bob, "m2", "2").await, "m2");
    server.stop().await;
}

#[tokio::test]
async fn queue_and_key_bindings_survive_restart() {
    let db = tmp_db("restart");
    let config = Config {
        db_path: Some(db.clone()),
        ..Config::default()
    };
    let (alice, bob) = (Identity::generate("alice"), Identity::generate("bob"));

    let server = Server::start(config.clone()).await;
    {
        let mut a = Client::connect(&server.url(), &alice).await;
        accepted(&a.send_text(&bob, "m1", "переживёт рестарт").await, "m1");
    }
    server.stop().await;

    let server = Server::start(config).await;
    let mut b = Client::connect(&server.url(), &bob).await;
    assert_eq!(b.recv_text(&alice).await.1, "переживёт рестарт");

    // И ключ Алисы всё ещё закреплён.
    let impostor = Identity::generate("alice");
    let mut m = Client::unauthenticated(&server.url(), &impostor).await;
    let nonce = m.challenge().await;
    m.auth_with(&nonce, &impostor).await;
    assert!(matches!(m.recv().await, ServerMessage::Error { .. }));
    server.stop().await;
    let _ = std::fs::remove_dir_all(db.parent().unwrap());
}

fn publish(id: &Identity, spk_id: u32, opk_ids: std::ops::Range<u32>) -> ClientMessage {
    let (_, spk) = id.new_signed_prekey(spk_id);
    ClientMessage::PublishPrekeys {
        signed_prekey: (&spk).into(),
        one_time: opk_ids
            .map(|i| (&crypto_core::new_one_time_prekey(i).1).into())
            .collect(),
    }
}

#[tokio::test]
async fn prekeys_are_published_and_handed_out_once() {
    let server = Server::start(Config::default()).await;
    let (alice, bob) = (Identity::generate("alice"), Identity::generate("bob"));
    let mut b = Client::connect(&server.url(), &bob).await;
    let mut a = Client::connect(&server.url(), &alice).await;

    // Пока Боб ничего не публиковал — пустой набор.
    a.send(ClientMessage::FetchBundle {
        account_id: "bob".into(),
        device_id: 1,
    })
    .await;
    assert_eq!(
        a.recv().await,
        ServerMessage::Bundle {
            account_id: "bob".into(),
            device_id: 1,
            signed_prekey: None,
            one_time: None
        }
    );

    // Статус сразу после входа: ничего не опубликовано.
    assert_eq!(
        b.recv_any().await,
        ServerMessage::PrekeyStatus {
            has_signed_prekey: false,
            one_time_left: 0,
            device_list_version: None
        }
    );
    b.send(publish(&bob, 1, 1..3)).await;
    assert_eq!(
        b.recv_any().await,
        ServerMessage::PrekeyStatus {
            has_signed_prekey: true,
            one_time_left: 2,
            device_list_version: None
        }
    );

    let mut handed_out = vec![];
    for _ in 0..3 {
        a.send(ClientMessage::FetchBundle {
            account_id: "bob".into(),
            device_id: 1,
        })
        .await;
        match a.recv().await {
            ServerMessage::Bundle {
                signed_prekey: Some(spk),
                one_time,
                ..
            } => {
                let spk = SignedPrekey::try_from(&spk).unwrap();
                crypto_core::verify_signed_prekey(&bob.sign_public_bytes(), &spk).unwrap();
                handed_out.push(one_time.map(|k| k.id));
            }
            other => panic!("expected bundle, got {other:?}"),
        }
    }
    // Каждый одноразовый ключ выдан ровно один раз, дальше — только подписанный.
    assert_eq!(handed_out, [Some(1), Some(2), None]);

    // При следующем входе Боб узнаёт, что запас кончился.
    drop(b);
    let mut b = Client::unauthenticated(&server.url(), &bob).await;
    let nonce = b.challenge().await;
    b.auth_with(&nonce, &bob).await;
    assert!(matches!(
        b.recv().await,
        ServerMessage::Authenticated { .. }
    ));
    assert_eq!(
        b.recv_any().await,
        ServerMessage::PrekeyStatus {
            has_signed_prekey: true,
            one_time_left: 0,
            device_list_version: None
        }
    );
    server.stop().await;
}

#[tokio::test]
async fn foreign_or_oversized_prekey_uploads_are_rejected() {
    let server = Server::start(Config {
        max_one_time_prekeys: 3,
        ..Config::default()
    })
    .await;
    let bob = Identity::generate("bob");
    let mallory = Identity::generate("mallory");
    let mut b = Client::connect(&server.url(), &bob).await;

    // Предключ, подписанный чужим ключом.
    b.send(publish(&mallory, 1, 0..0)).await;
    assert!(
        matches!(b.recv().await, ServerMessage::Error { message, .. } if message.contains("not signed"))
    );

    // Слишком много за раз.
    b.send(publish(
        &bob,
        1,
        0..(protocol::MAX_ONE_TIME_PREKEYS_PER_UPLOAD as u32 + 1),
    ))
    .await;
    assert!(
        matches!(b.recv().await, ServerMessage::Error { message, .. } if message.contains("too many"))
    );

    // Сверх лимита релей просто не хранит.
    b.send(publish(&bob, 1, 0..10)).await;
    assert_eq!(
        b.recv_any().await,
        ServerMessage::PrekeyStatus {
            has_signed_prekey: true,
            one_time_left: 3,
            device_list_version: None
        }
    );
    server.stop().await;
}

fn limited(f: impl FnOnce(&mut relay_server::Limits)) -> Config {
    let mut c = Config::default();
    f(&mut c.limits);
    c
}

async fn fetch(c: &mut Client, target: &str) -> Option<u32> {
    c.send(ClientMessage::FetchBundle {
        account_id: target.into(),
        device_id: 1,
    })
    .await;
    match c.recv().await {
        ServerMessage::Bundle {
            signed_prekey: Some(_),
            one_time,
            ..
        } => one_time.map(|k| k.id),
        other => panic!("expected bundle, got {other:?}"),
    }
}

/// Злоумышленник заводит много аккаунтов и с каждого запрашивает предключи
/// жертвы. Лимит на получателя не даёт раздать больше одноразовых ключей,
/// а подписанный предключ выдаётся всегда — переписка не ломается.
#[tokio::test]
async fn one_time_prekeys_cannot_be_drained_with_many_accounts() {
    let server = Server::start(limited(|l| l.one_time_per_target = Rate::per_hour(2))).await;
    let bob = Identity::generate("bob");
    let mut b = Client::connect(&server.url(), &bob).await;
    b.send(publish(&bob, 1, 1..6)).await;
    assert!(matches!(
        b.recv_any().await,
        ServerMessage::PrekeyStatus { .. }
    ));
    assert!(matches!(
        b.recv_any().await,
        ServerMessage::PrekeyStatus {
            one_time_left: 5,
            ..
        }
    ));

    let mut got = vec![];
    for i in 0..4 {
        let attacker = Identity::generate(format!("sybil{i}"));
        let mut a = Client::connect(&server.url(), &attacker).await;
        got.push(fetch(&mut a, "bob").await);
    }
    assert_eq!(got, [Some(1), Some(2), None, None]);
    server.stop().await;
}

/// Один и тот же аккаунт часто запрашивает предключи — сверх лимита без OPK,
/// и это не тратит бюджет получателя.
#[tokio::test]
async fn frequent_bundle_requests_get_no_one_time_prekeys() {
    let server = Server::start(limited(|l| l.bundle_fetches = Rate::per_hour(1))).await;
    let bob = Identity::generate("bob");
    let mut b = Client::connect(&server.url(), &bob).await;
    b.send(publish(&bob, 1, 1..4)).await;

    let mut a = Client::connect(&server.url(), &Identity::generate("alice")).await;
    assert_eq!(fetch(&mut a, "bob").await, Some(1));
    assert_eq!(fetch(&mut a, "bob").await, None);
    assert_eq!(fetch(&mut a, "bob").await, None);

    // Другой честный собеседник по-прежнему получает одноразовый ключ.
    let mut c = Client::connect(&server.url(), &Identity::generate("carol")).await;
    assert_eq!(fetch(&mut c, "bob").await, Some(2));
    server.stop().await;
}

#[tokio::test]
async fn message_flood_is_rate_limited() {
    let server = Server::start(limited(|l| l.sends = Rate::per_hour(3))).await;
    let (alice, bob) = (Identity::generate("alice"), Identity::generate("bob"));
    let mut a = Client::connect(&server.url(), &alice).await;
    for i in 0..3 {
        accepted(
            &a.send_text(&bob, &format!("m{i}"), "x").await,
            &format!("m{i}"),
        );
    }
    assert!(matches!(
        a.send_text(&bob, "m3", "x").await,
        ServerMessage::Error { message, msg_id: Some(id) } if message.contains("rate limited") && id == "m3"
    ));
    // Лимит — на отправителя: другие пишут Бобу спокойно.
    let mut c = Client::connect(&server.url(), &Identity::generate("carol")).await;
    accepted(&c.send_text(&bob, "c1", "x").await, "c1");
    server.stop().await;
}

#[tokio::test]
async fn frame_flood_is_rate_limited() {
    let server = Server::start(limited(|l| l.frames_per_connection = Rate::per_hour(3))).await;
    let mut a = Client::connect(&server.url(), &Identity::generate("alice")).await;
    for _ in 0..3 {
        a.ack(&Identity::generate("x"), "nothing").await; // молча игнорируются
    }
    a.ack(&Identity::generate("x"), "nothing").await;
    assert!(matches!(
        a.recv().await,
        ServerMessage::Error { message, .. } if message.contains("rate limited")
    ));
    server.stop().await;
}

#[tokio::test]
async fn too_many_connections_from_one_ip_get_http_429() {
    let server = Server::start(limited(|l| l.connections_per_ip = Rate::per_hour(3))).await;
    let mut open = vec![];
    for _ in 0..3 {
        open.push(Client::raw(&server.url()).await);
    }
    let err = tokio_tungstenite::connect_async(server.url())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("429"), "{err}");
    server.stop().await;
}

#[tokio::test]
async fn simultaneous_connections_per_account_are_capped() {
    let server = Server::start(limited(|l| l.max_connections_per_account = 2)).await;
    let bob = Identity::generate("bob");
    let _c1 = Client::connect(&server.url(), &bob).await;
    let _c2 = Client::connect(&server.url(), &bob).await;

    let mut c3 = Client::unauthenticated(&server.url(), &bob).await;
    let nonce = c3.challenge().await;
    c3.auth_with(&nonce, &bob).await;
    assert!(matches!(
        c3.recv().await,
        ServerMessage::Error { message, .. } if message.contains("too many")
    ));

    // Когда одно закрылось — место освободилось.
    drop(_c1);
    tokio::time::sleep(Duration::from_millis(100)).await;
    Client::connect(&server.url(), &bob).await;
    server.stop().await;
}

#[tokio::test]
async fn prekey_publish_spam_is_rate_limited() {
    let server = Server::start(limited(|l| l.publishes = Rate::per_hour(2))).await;
    let bob = Identity::generate("bob");
    let mut b = Client::connect(&server.url(), &bob).await;
    for _ in 0..2 {
        b.send(publish(&bob, 1, 0..0)).await;
    }
    b.send(publish(&bob, 1, 0..0)).await;
    assert!(matches!(
        b.recv().await,
        ServerMessage::Error { message, .. } if message.contains("rate limited")
    ));
    server.stop().await;
}

async fn connect_as_ip(url: &str, ip: &str) -> Result<(), String> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut req = url.into_client_request().unwrap();
    req.headers_mut()
        .insert("x-forwarded-for", ip.parse().unwrap());
    tokio_tungstenite::connect_async(req)
        .await
        .map(drop)
        .map_err(|e| e.to_string())
}

#[tokio::test]
async fn forwarded_for_is_ignored_unless_trusted() {
    // Без доверия к прокси заголовок не помогает обойти лимит по IP.
    let server = Server::start(limited(|l| l.connections_per_ip = Rate::per_hour(2))).await;
    for ip in ["1.1.1.1", "2.2.2.2"] {
        connect_as_ip(&server.url(), ip).await.unwrap();
    }
    assert!(
        connect_as_ip(&server.url(), "3.3.3.3")
            .await
            .unwrap_err()
            .contains("429")
    );
    server.stop().await;

    // За своим прокси каждый клиент считается по своему адресу (берётся последний).
    let mut config = limited(|l| l.connections_per_ip = Rate::per_hour(2));
    config.trust_forwarded_for = true;
    let server = Server::start(config).await;
    for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3", "9.9.9.9, 4.4.4.4"] {
        connect_as_ip(&server.url(), ip).await.unwrap();
    }
    connect_as_ip(&server.url(), "1.1.1.1").await.unwrap();
    assert!(
        connect_as_ip(&server.url(), "1.1.1.1")
            .await
            .unwrap_err()
            .contains("429")
    );
    // Подделанное начало цепочки не помогает: считается последний адрес.
    assert!(
        connect_as_ip(&server.url(), "5.5.5.5, 1.1.1.1")
            .await
            .unwrap_err()
            .contains("429")
    );
    // Битое последнее значение: берём TCP-адрес (127.0.0.1), а не подделанное раньше в цепочке.
    for _ in 0..2 {
        connect_as_ip(&server.url(), "6.6.6.6, garbage")
            .await
            .unwrap();
    }
    assert!(
        connect_as_ip(&server.url(), "7.7.7.7, garbage")
            .await
            .unwrap_err()
            .contains("429")
    );
    server.stop().await;
}

// ---------- Несколько устройств ----------

/// Подписанный список устройств аккаунта `primary` (версия `version`).
fn device_list(
    primary: &Identity,
    others: &[&Identity],
    version: u64,
) -> protocol::SignedDeviceListB64 {
    let mut devices = vec![primary.device_info("ноутбук")];
    devices.extend(others.iter().map(|d| d.device_info("телефон")));
    primary
        .sign_device_list(&protocol::DeviceList {
            account_id: primary.account_id().into(),
            account_pub: primary.sign_public_bytes(),
            version,
            devices,
        })
        .unwrap()
}

fn second_device(primary: &Identity, device_id: u32) -> Identity {
    Identity::generate(primary.account_id()).with_device(device_id)
}

async fn publish_list(c: &mut Client, list: protocol::SignedDeviceListB64) -> ServerMessage {
    c.send(ClientMessage::PublishDeviceList { list }).await;
    c.recv().await
}

async fn auth_error(url: &str, id: &Identity) -> String {
    let mut c = Client::unauthenticated(url, id).await;
    let nonce = c.challenge().await;
    c.auth_with(&nonce, id).await;
    match c.recv().await {
        ServerMessage::Error { message, .. } => message,
        other => panic!("expected auth error, got {other:?}"),
    }
}

#[tokio::test]
async fn secondary_device_needs_a_signed_device_list() {
    let server = Server::start(Config::default()).await;
    let bob = Identity::generate_new();
    let phone = second_device(&bob, 2);

    // Пока основное устройство не внесло телефон в список — не пускаем.
    assert!(
        auth_error(&server.url(), &phone)
            .await
            .contains("not in the account's device list")
    );

    let mut laptop = Client::connect(&server.url(), &bob).await;
    let list = device_list(&bob, &[&phone], 2);
    assert_eq!(
        publish_list(&mut laptop, list.clone()).await,
        ServerMessage::DeviceList {
            account_id: bob.account_id().into(),
            list: Some(list.clone())
        }
    );
    // Тот же список ещё раз — не ошибка.
    assert!(matches!(
        publish_list(&mut laptop, list.clone()).await,
        ServerMessage::DeviceList { .. }
    ));

    let mut p = Client::connect(&server.url(), &phone).await;
    // Релей сообщает версию списка — так основное устройство видит, что он актуален.
    assert!(matches!(
        p.recv_any().await,
        ServerMessage::PrekeyStatus {
            device_list_version: Some(2),
            ..
        }
    ));

    // Чужой ключ под номером телефона не войдёт.
    let fake_phone = second_device(&bob, 2);
    assert!(
        auth_error(&server.url(), &fake_phone)
            .await
            .contains("not in the account's device list")
    );

    // Список доступен всем.
    let mut a = Client::connect(&server.url(), &Identity::generate("alice")).await;
    a.send(ClientMessage::FetchDeviceList {
        account_id: bob.account_id().into(),
    })
    .await;
    assert_eq!(
        a.recv().await,
        ServerMessage::DeviceList {
            account_id: bob.account_id().into(),
            list: Some(list)
        }
    );
    server.stop().await;
}

#[tokio::test]
async fn each_device_has_its_own_queue_and_acks() {
    let server = Server::start(Config::default()).await;
    let alice = Identity::generate("alice");
    let bob = Identity::generate_new();
    let phone = second_device(&bob, 2);
    let mut laptop = Client::connect(&server.url(), &bob).await;
    publish_list(&mut laptop, device_list(&bob, &[&phone], 2)).await;

    let mut a = Client::connect(&server.url(), &alice).await;
    accepted(
        &a.send_text(&bob, "to-laptop", "ноутбуку").await,
        "to-laptop",
    );
    accepted(
        &a.send_text(&phone, "to-phone", "телефону").await,
        "to-phone",
    );

    // Каждому устройству — только его конверт.
    assert_eq!(laptop.recv_text(&alice).await.1, "ноутбуку");
    laptop.expect_silence().await;
    let mut p = Client::connect(&server.url(), &phone).await;
    assert_eq!(p.recv_text(&alice).await.1, "телефону");
    p.expect_silence().await;

    // Подтверждение приходит от конкретного устройства.
    p.ack(&alice, "to-phone").await;
    assert_eq!(
        a.recv().await,
        ServerMessage::DeliverAck {
            from: bob.account_id().into(),
            from_device: 2,
            msg_id: "to-phone".into()
        }
    );
    // Ноутбук не может подтвердить чужой конверт.
    laptop.ack(&alice, "to-phone").await;
    a.expect_silence().await;
    server.stop().await;
}

#[tokio::test]
async fn devices_of_one_account_can_message_each_other() {
    let server = Server::start(Config::default()).await;
    let bob = Identity::generate_new();
    let phone = second_device(&bob, 2);
    let mut laptop = Client::connect(&server.url(), &bob).await;
    publish_list(&mut laptop, device_list(&bob, &[&phone], 2)).await;
    let mut p = Client::connect(&server.url(), &phone).await;

    accepted(&laptop.send_text(&phone, "copy", "копия").await, "copy");
    assert_eq!(p.recv_text(&bob).await.1, "копия");
    accepted(&p.send_text(&bob, "back", "назад").await, "back");
    assert_eq!(laptop.recv_text(&phone).await.1, "назад");
    server.stop().await;
}

#[tokio::test]
async fn bad_device_lists_and_unknown_devices_are_rejected() {
    let server = Server::start(Config::default()).await;
    let bob = Identity::generate_new();
    let phone = second_device(&bob, 2);
    let mallory = Identity::generate_new();
    let mut laptop = Client::connect(&server.url(), &bob).await;

    // Чужой список.
    assert!(matches!(
        publish_list(&mut laptop, device_list(&mallory, &[], 1)).await,
        ServerMessage::Error { message, .. } if message.contains("bad device list")
    ));

    publish_list(&mut laptop, device_list(&bob, &[&phone], 3)).await;
    // Откат на старую версию.
    assert!(matches!(
        publish_list(&mut laptop, device_list(&bob, &[], 2)).await,
        ServerMessage::Error { message, .. } if message.contains("stale")
    ));
    // Та же версия, но другое содержимое.
    assert!(matches!(
        publish_list(&mut laptop, device_list(&bob, &[], 3)).await,
        ServerMessage::Error { message, .. } if message.contains("stale")
    ));

    // Устройство без ключа аккаунта подписывает список своим ключом: релей
    // сверяет подпись с закреплённым ключом аккаунта и отвергает.
    let mut p = Client::connect(&server.url(), &phone).await;
    let own_key = Identity::generate(bob.account_id());
    assert!(matches!(
        publish_list(&mut p, device_list(&own_key, &[&phone], 4)).await,
        ServerMessage::Error { message, .. } if message.contains("bad device list")
    ));

    // Отправка на устройство, которого нет в списке.
    let mut a = Client::connect(&server.url(), &Identity::generate("alice")).await;
    let ghost = second_device(&bob, 7);
    assert!(matches!(
        a.send_text(&ghost, "g", "x").await,
        ServerMessage::Error { message, msg_id: Some(id) } if message.contains("no such device") && id == "g"
    ));

    // Телефон не может выдать свой конверт за конверт ноутбука.
    let mut env = p.envelope(&bob, "подделка");
    env.from_device = 1;
    p.send(ClientMessage::Send {
        to: bob.account_id().into(),
        to_device: 1,
        msg_id: "spoof".into(),
        envelope: env,
    })
    .await;
    assert!(matches!(
        p.recv().await,
        ServerMessage::Error { msg_id: Some(id), .. } if id == "spoof"
    ));
    laptop.expect_silence().await;
    server.stop().await;
}

#[tokio::test]
async fn removed_device_is_disconnected_and_forgotten() {
    let server = Server::start(Config::default()).await;
    let alice = Identity::generate("alice");
    let bob = Identity::generate_new();
    let phone = second_device(&bob, 2);
    let tablet = second_device(&bob, 3);
    let mut laptop = Client::connect(&server.url(), &bob).await;
    publish_list(&mut laptop, device_list(&bob, &[&phone, &tablet], 2)).await;

    let mut p = Client::connect(&server.url(), &phone).await;
    let mut t = Client::connect(&server.url(), &tablet).await;
    // Пока телефон в сети, для него копится очередь от Алисы.
    let mut a = Client::connect(&server.url(), &alice).await;
    accepted(&a.send_text(&phone, "m1", "для телефона").await, "m1");
    p.recv_text(&alice).await;

    // Телефон потерян: отключаем.
    let list = device_list(&bob, &[&tablet], 3);
    publish_list(&mut laptop, list.clone()).await;

    // Его соединение закрыто с объяснением…
    assert!(matches!(
        p.recv().await,
        ServerMessage::Error { message, .. } if message.contains("removed")
    ));
    // …а планшет узнал о новом списке сразу.
    assert_eq!(
        t.recv().await,
        ServerMessage::DeviceList {
            account_id: bob.account_id().into(),
            list: Some(list)
        }
    );
    // Войти снова телефон не может, писать ему — тоже.
    assert!(
        auth_error(&server.url(), &phone)
            .await
            .contains("not in the account's device list")
    );
    assert!(matches!(
        a.send_text(&phone, "m2", "x").await,
        ServerMessage::Error { message, .. } if message.contains("no such device")
    ));
    server.stop().await;
}

#[tokio::test]
async fn device_with_account_key_can_publish_device_list() {
    let server = Server::start(Config::default()).await;
    let bob = Identity::generate_new();
    let phone = second_device(&bob, 2).with_account_key(bob.sign_secret_bytes());
    let mut laptop = Client::connect(&server.url(), &bob).await;
    publish_list(&mut laptop, device_list(&bob, &[&phone], 2)).await;
    let mut p = Client::connect(&server.url(), &phone).await;

    // Телефон с ключом аккаунта добавляет планшет: список v3 подписан им.
    let tablet = second_device(&bob, 3);
    let mut devices = vec![bob.device_info("ноутбук"), phone.device_info("телефон")];
    devices.push(tablet.device_info("планшет"));
    let list = protocol::DeviceList {
        account_id: bob.account_id().into(),
        account_pub: bob.sign_public_bytes(),
        version: 3,
        devices,
    };
    let wire = phone.sign_device_list(&list).unwrap();
    assert!(matches!(
        publish_list(&mut p, wire.clone()).await,
        ServerMessage::DeviceList { list: Some(l), .. } if l == wire
    ));
    // Ноутбук получил список сразу.
    assert_eq!(
        laptop.recv().await,
        ServerMessage::DeviceList {
            account_id: bob.account_id().into(),
            list: Some(wire)
        }
    );
    // Планшет теперь может войти.
    Client::connect(&server.url(), &tablet).await;
    server.stop().await;
}

#[tokio::test]
async fn list_changing_primary_entry_is_rejected() {
    let server = Server::start(Config::default()).await;
    let bob = Identity::generate_new();
    let phone = second_device(&bob, 2).with_account_key(bob.sign_secret_bytes());
    let mut laptop = Client::connect(&server.url(), &bob).await;
    publish_list(&mut laptop, device_list(&bob, &[&phone], 2)).await;
    let mut p = Client::connect(&server.url(), &phone).await;

    let make = |primary: protocol::DeviceInfo| {
        phone
            .sign_device_list(&protocol::DeviceList {
                account_id: bob.account_id().into(),
                account_pub: bob.sign_public_bytes(),
                version: 3,
                devices: vec![primary, phone.device_info("телефон")],
            })
            .unwrap()
    };
    // Подмена x25519 у №1.
    let mut swapped = bob.device_info("ноутбук");
    swapped.x25519_pub = Identity::generate_new().x_public_bytes();
    assert!(matches!(
        publish_list(&mut p, make(swapped)).await,
        ServerMessage::Error { message, .. } if message.contains("bad device list")
    ));
    // Смена имени у №1.
    assert!(matches!(
        publish_list(&mut p, make(bob.device_info("чужое имя"))).await,
        ServerMessage::Error { message, .. } if message.contains("bad device list")
    ));
    // №1 не выкинут и в сети.
    laptop.expect_silence().await;
    let a = Identity::generate("alice");
    let mut ac = Client::connect(&server.url(), &a).await;
    accepted(&ac.send_text(&bob, "still", "жив").await, "still");
    assert_eq!(laptop.recv_text(&a).await.1, "жив");
    server.stop().await;
}

#[tokio::test]
async fn republishing_same_list_has_no_side_effects() {
    let server = Server::start(Config::default()).await;
    let bob = Identity::generate_new();
    let phone = second_device(&bob, 2);
    let mut laptop = Client::connect(&server.url(), &bob).await;
    let list = device_list(&bob, &[&phone], 2);
    publish_list(&mut laptop, list.clone()).await;
    let mut p = Client::connect(&server.url(), &phone).await;

    assert!(matches!(
        publish_list(&mut laptop, list).await,
        ServerMessage::DeviceList { list: Some(_), .. }
    ));
    // Телефон не получил повторной рассылки и не отключён.
    p.expect_silence().await;
    laptop.expect_silence().await;
    let a = Identity::generate("alice");
    let mut ac = Client::connect(&server.url(), &a).await;
    accepted(&ac.send_text(&phone, "m", "x").await, "m");
    assert_eq!(p.recv_text(&a).await.1, "x");
    server.stop().await;
}

// ---------- Сессия ключом аккаунта ----------

/// Сессия аккаунта: тот же аккаунт и ключ, номер устройства 0.
fn account_session(id: &Identity) -> Identity {
    id.clone().with_device(protocol::ACCOUNT_SESSION_DEVICE)
}

async fn open_session(url: &str, id: &Identity) -> Client {
    Client::connect(url, &account_session(id)).await
}

fn expect_error(m: ServerMessage, part: &str) {
    match m {
        ServerMessage::Error { message, .. } => {
            assert!(message.contains(part), "unexpected error: {message}")
        }
        other => panic!("expected error {part:?}, got {other:?}"),
    }
}

#[tokio::test]
async fn account_session_needs_the_bound_account_key() {
    let server = Server::start(Config::default()).await;
    let bob = Identity::generate_new();

    // Аккаунт релею ещё не известен: привязку сессия не создаёт.
    expect_error(
        Client::connect_err(&server.url(), &account_session(&bob)).await,
        "needs a known account",
    );
    Client::connect(&server.url(), &bob).await;
    open_session(&server.url(), &bob).await;

    // Чужой ключ под номером аккаунта.
    let other = Identity::generate_new();
    let forged = Identity::from_secrets(
        bob.account_id(),
        other.x_secret_bytes(),
        other.sign_secret_bytes(),
    )
    .with_device(0);
    assert!(
        auth_error(&server.url(), &forged)
            .await
            .contains("does not belong")
    );
    // Для аккаунта с произвольным ID чужой ключ — тоже отказ.
    let alice = Identity::generate("alice-sess");
    Client::connect(&server.url(), &alice).await;
    let forged = Identity::generate("alice-sess").with_device(0);
    assert!(
        auth_error(&server.url(), &forged)
            .await
            .contains("different key")
    );
    // Ключ устройства №2 не годится.
    let phone = second_device(&bob, 2);
    let mut laptop = Client::connect(&server.url(), &bob).await;
    publish_list(&mut laptop, device_list(&bob, &[&phone], 2)).await;
    let phone_as_session = Identity::from_secrets(
        bob.account_id(),
        phone.x_secret_bytes(),
        phone.sign_secret_bytes(),
    )
    .with_device(0);
    assert!(
        auth_error(&server.url(), &phone_as_session)
            .await
            .contains("does not belong")
    );
    server.stop().await;
}

#[tokio::test]
async fn account_session_works_for_non_key_derived_account() {
    let server = Server::start(Config::default()).await;
    let alice = Identity::generate("alice-legacy");
    expect_error(
        Client::connect_err(&server.url(), &account_session(&alice)).await,
        "needs a known account",
    );
    Client::connect(&server.url(), &alice).await;
    open_session(&server.url(), &alice).await;
    server.stop().await;
}

#[tokio::test]
async fn account_session_does_not_touch_queues() {
    let server = Server::start(Config::default()).await;
    let alice = Identity::generate("alice");
    let bob = Identity::generate_new();
    // Бобу пишут, пока он не в сети.
    drop(Client::connect(&server.url(), &bob).await);
    let mut a = Client::connect(&server.url(), &alice).await;
    accepted(&a.send_text(&bob, "m1", "привет").await, "m1");
    accepted(&a.send_text(&bob, "m2", "ещё").await, "m2");
    drop(a);
    // Боб подтверждает только первое; DeliverAck для Алисы остаётся в очереди.
    let mut b = Client::connect(&server.url(), &bob).await;
    assert_eq!(b.recv_text(&alice).await.1, "привет");
    assert_eq!(b.recv_text(&alice).await.1, "ещё");
    b.ack(&alice, "m1").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(b);

    let mut s = open_session(&server.url(), &bob).await;
    s.expect_silence().await;
    drop(s);
    let mut sa = open_session(&server.url(), &alice).await;
    sa.expect_silence().await;
    drop(sa);

    // Ничего не потеряно и не отдано сессии.
    let mut b = Client::connect(&server.url(), &bob).await;
    assert_eq!(b.recv_text(&alice).await.1, "ещё");
    let mut a = Client::connect(&server.url(), &alice).await;
    assert!(matches!(a.recv().await, ServerMessage::DeliverAck { .. }));
    server.stop().await;
}

#[tokio::test]
async fn account_session_allows_only_device_list_requests() {
    let server = Server::start(Config::default()).await;
    let bob = Identity::generate_new();
    Client::connect(&server.url(), &bob).await;
    let mut s = open_session(&server.url(), &bob).await;
    let alice = Identity::generate("alice");

    let envelope = s.envelope(&alice, "x");
    for m in [
        ClientMessage::Send {
            to: alice.account_id().into(),
            to_device: 1,
            msg_id: "x".into(),
            envelope,
        },
        ClientMessage::Ack {
            to: alice.account_id().into(),
            to_device: 1,
            msg_id: "x".into(),
        },
        publish(&bob, 1, 0..1),
        ClientMessage::FetchBundle {
            account_id: bob.account_id().into(),
            device_id: 1,
        },
        ClientMessage::FetchDeviceList {
            account_id: alice.account_id().into(),
        },
    ] {
        s.send(m).await;
        expect_error(s.recv_any().await, "not allowed in an account session");
    }
    // Свой список — можно.
    s.send(ClientMessage::FetchDeviceList {
        account_id: bob.account_id().into(),
    })
    .await;
    assert!(matches!(
        s.recv_any().await,
        ServerMessage::DeviceList { list: None, .. }
    ));
    server.stop().await;
}

#[tokio::test]
async fn account_session_publishes_device_list_and_notifies_devices() {
    let server = Server::start(Config::default()).await;
    let bob = Identity::generate_new();
    let phone = second_device(&bob, 2);
    let mut laptop = Client::connect(&server.url(), &bob).await;
    let mut s = open_session(&server.url(), &bob).await;

    let list = device_list(&bob, &[&phone], 2);
    assert_eq!(
        publish_list(&mut s, list.clone()).await,
        ServerMessage::DeviceList {
            account_id: bob.account_id().into(),
            list: Some(list.clone())
        }
    );
    assert_eq!(
        laptop.recv().await,
        ServerMessage::DeviceList {
            account_id: bob.account_id().into(),
            list: Some(list)
        }
    );
    Client::connect(&server.url(), &phone).await;

    // Откат версии из сессии отвергается, как и у обычного устройства.
    expect_error(
        publish_list(&mut s, device_list(&bob, &[], 1)).await,
        "stale",
    );
    // Убираем телефон: он отключается, ноутбук получает список.
    let mut p = Client::connect(&server.url(), &phone).await;
    let list3 = device_list(&bob, &[], 3);
    assert!(matches!(
        publish_list(&mut s, list3.clone()).await,
        ServerMessage::DeviceList { .. }
    ));
    assert!(matches!(
        laptop.recv().await,
        ServerMessage::DeviceList { list: Some(l), .. } if l == list3
    ));
    expect_error(p.recv().await, "removed");
    server.stop().await;
}

#[tokio::test]
async fn nothing_can_be_sent_to_the_account_session_device() {
    let server = Server::start(Config::default()).await;
    let alice = Identity::generate("alice");
    let bob = Identity::generate_new();
    Client::connect(&server.url(), &bob).await;
    let mut a = Client::connect(&server.url(), &alice).await;
    let _s = open_session(&server.url(), &bob).await;
    let to = account_session(&bob);
    expect_error(a.send_text(&to, "z", "в никуда").await, "no such device");
    server.stop().await;
}

#[tokio::test]
async fn account_sessions_are_capped_and_released() {
    let server = Server::start(limited(|l| l.max_connections_per_account = 2)).await;
    let bob = Identity::generate_new();
    // Обычные соединения лимит сессий не занимают.
    let _c = Client::connect(&server.url(), &bob).await;
    let s1 = open_session(&server.url(), &bob).await;
    let _s2 = open_session(&server.url(), &bob).await;
    expect_error(
        Client::connect_err(&server.url(), &account_session(&bob)).await,
        "too many",
    );
    drop(s1);
    tokio::time::sleep(Duration::from_millis(100)).await;
    open_session(&server.url(), &bob).await;
    server.stop().await;
}
