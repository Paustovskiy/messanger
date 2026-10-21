//! Интеграционные тесты: настоящий релей на случайном порту + WebSocket-клиенты.

use crypto_core::Identity;
use futures_util::{SinkExt, StreamExt};
use protocol::{ClientMessage, EnvelopeB64, ServerMessage, b64, decode_fixed};
use relay_server::{Config, Relay};
use std::net::SocketAddr;
use std::path::PathBuf;
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
}

impl Client {
    async fn raw(url: &str) -> Ws {
        tokio_tungstenite::connect_async(url).await.unwrap().0
    }

    /// Подключиться и пройти вход.
    async fn connect(url: &str, id: &Identity) -> Client {
        let mut c = Client {
            ws: Self::raw(url).await,
            id: id.clone(),
        };
        let nonce = c.challenge().await;
        c.auth_with(&nonce, id).await;
        match c.recv().await {
            ServerMessage::Authenticated { account_id } => assert_eq!(account_id, id.account_id()),
            other => panic!("expected Authenticated, got {other:?}"),
        }
        c
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
        let sig = signer.sign(&protocol::relay_auth_signing_bytes(nonce, &account_id));
        self.send(ClientMessage::Auth {
            account_id,
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

    async fn recv(&mut self) -> ServerMessage {
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

    async fn expect_silence(&mut self) {
        if let Ok(Some(Ok(Message::Text(t)))) =
            tokio::time::timeout(Duration::from_millis(300), self.ws.next()).await
        {
            panic!("expected no messages, got {t}");
        }
    }

    fn envelope(&self, to: &Identity, text: &str) -> EnvelopeB64 {
        let env = self
            .id
            .encrypt_to(to.account_id(), &to.x_public_bytes(), text.as_bytes())
            .unwrap();
        EnvelopeB64::from(&env)
    }

    async fn send_text(&mut self, to: &Identity, msg_id: &str, text: &str) -> ServerMessage {
        let envelope = self.envelope(to, text);
        self.send(ClientMessage::Send {
            to: to.account_id().into(),
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
                msg_id,
                envelope,
            } => {
                assert_eq!(f, from.account_id());
                let env = protocol::Envelope::try_from(envelope).unwrap();
                let pt = self.id.decrypt(&env, &from.sign_public_bytes()).unwrap();
                (msg_id, String::from_utf8(pt).unwrap())
            }
            other => panic!("expected Deliver, got {other:?}"),
        }
    }

    async fn ack(&mut self, to: &Identity, msg_id: &str) {
        self.send(ClientMessage::Ack {
            to: to.account_id().into(),
            msg_id: msg_id.into(),
        })
        .await;
    }
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
    let mut m = Client {
        ws: Client::raw(&server.url()).await,
        id: mallory_as_alice.clone(),
    };
    let nonce = m.challenge().await;
    m.auth_with(&nonce, &mallory_as_alice).await;
    assert!(
        matches!(m.recv().await, ServerMessage::Error { message, .. } if message.contains("different key"))
    );

    // Подпись не того nonce.
    let mut m = Client {
        ws: Client::raw(&server.url()).await,
        id: alice.clone(),
    };
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
    let mut m = Client {
        ws: Client::raw(&server.url()).await,
        id: squatter.clone(),
    };
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
    let mut c = Client {
        ws: Client::raw(&server.url()).await,
        id: alice.clone(),
    };
    let _ = c.challenge().await;
    let envelope = c.envelope(&bob, "x");
    c.send(ClientMessage::Send {
        to: "bob".into(),
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
    let mut c = Client {
        ws: Client::raw(&server.url()).await,
        id: Identity::generate("x"),
    };
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
    let forged = EnvelopeB64::from(
        &impostor
            .encrypt_to("bob", &bob.x_public_bytes(), b"x")
            .unwrap(),
    );
    a.send(ClientMessage::Send {
        to: "bob".into(),
        msg_id: "f1".into(),
        envelope: forged,
    })
    .await;
    assert!(matches!(a.recv().await, ServerMessage::Error { msg_id: Some(id), .. } if id == "f1"));

    // Конверт для Кэрол, отправленный Бобу.
    let for_carol = a.envelope(&carol, "x");
    a.send(ClientMessage::Send {
        to: "bob".into(),
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
    let mut m = Client {
        ws: Client::raw(&server.url()).await,
        id: impostor.clone(),
    };
    let nonce = m.challenge().await;
    m.auth_with(&nonce, &impostor).await;
    assert!(matches!(m.recv().await, ServerMessage::Error { .. }));
    server.stop().await;
    let _ = std::fs::remove_dir_all(db.parent().unwrap());
}
