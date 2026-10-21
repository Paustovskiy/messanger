//! Релей мессенджера.
//!
//! Релей — «почтовый ящик»: он видит, кто кому пишет, но не видит, что
//! (содержимое зашифровано на клиентах). Его задачи:
//!
//! 1. **Пустить только владельца аккаунта.** При подключении релей присылает
//!    случайный nonce, клиент подписывает его ключом Ed25519. Первый успешный
//!    вход закрепляет ключ за `account_id` (trust-on-first-use), дальше войти
//!    под этим `account_id` с другим ключом нельзя.
//! 2. **Не пропустить мусор и подделки.** Конверт должен быть подписан
//!    отправителем, а его `from`/`to` — совпадать с реальными.
//! 3. **Не потерять сообщение.** Конверт лежит в SQLite, пока получатель
//!    не подтвердит (`ack`), что сохранил его у себя. Доставка «хотя бы один
//!    раз»; дубли клиент отбрасывает по `msg_id`.

pub mod store;

use anyhow::Result;
use axum::{
    Router,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
    routing::get,
};
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use protocol::{ClientMessage, Envelope, ServerMessage, b64, check_id, decode_fixed};
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use store::{Binding, Enqueue, Kind, Store};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Настройки релея.
#[derive(Debug, Clone)]
pub struct Config {
    /// Файл базы. `None` — в памяти (всё пропадёт при перезапуске).
    pub db_path: Option<PathBuf>,
    /// Сколько хранить недоставленные сообщения.
    pub message_ttl: Duration,
    /// Максимум сообщений в очереди одного получателя.
    pub max_queue_per_recipient: usize,
    /// Сколько ждать входа после подключения.
    pub auth_timeout: Duration,
    /// Максимальный размер одного WebSocket-сообщения.
    pub max_frame_bytes: usize,
    /// Как часто пинговать клиента. Если от клиента ничего не слышно три
    /// интервала подряд, соединение считается мёртвым и закрывается.
    pub ping_interval: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            db_path: None,
            message_ttl: Duration::from_secs(30 * 24 * 3600),
            max_queue_per_recipient: 1000,
            auth_timeout: Duration::from_secs(10),
            max_frame_bytes: 128 * 1024,
            ping_interval: Duration::from_secs(30),
        }
    }
}

struct Client {
    conn_id: u64,
    tx: mpsc::UnboundedSender<String>,
}

struct Inner {
    config: Config,
    store: Store,
    /// Кто сейчас онлайн: account_id → канал в его сокет.
    online: DashMap<String, Client>,
    next_conn_id: AtomicU64,
}

#[derive(Clone)]
pub struct Relay(Arc<Inner>);

impl Relay {
    pub fn new(config: Config) -> Result<Self> {
        let store = Store::open(config.db_path.as_deref())?;
        Ok(Self(Arc::new(Inner {
            config,
            store,
            online: DashMap::new(),
            next_conn_id: AtomicU64::new(1),
        })))
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/ws", get(ws_handler))
            .route("/health", get(|| async { "ok" }))
            .with_state(self.clone())
    }

    /// Обслуживать `listener`, пока не завершится `shutdown`.
    pub async fn serve(
        self,
        listener: TcpListener,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> Result<()> {
        let purger = tokio::spawn(purge_loop(self.clone()));
        let result = axum::serve(listener, self.router())
            .with_graceful_shutdown(shutdown)
            .await;
        purger.abort();
        Ok(result?)
    }

    /// Отправить JSON в сокет получателя, если он онлайн.
    fn push(&self, account_id: &str, json: String) -> bool {
        self.0
            .online
            .get(account_id)
            .is_some_and(|c| c.tx.send(json).is_ok())
    }
}

async fn purge_loop(relay: Relay) {
    let ttl = relay.0.config.message_ttl.as_secs();
    let mut tick = tokio::time::interval(Duration::from_secs(3600));
    loop {
        tick.tick().await;
        match relay.0.store.purge_older_than(ttl) {
            Ok(0) => {}
            Ok(n) => info!("purged {n} expired queued messages"),
            Err(e) => warn!("purge failed: {e:#}"),
        }
    }
}

async fn ws_handler(ws: WebSocketUpgrade, State(relay): State<Relay>) -> impl IntoResponse {
    let max = relay.0.config.max_frame_bytes;
    ws.max_message_size(max)
        .max_frame_size(max)
        .on_upgrade(move |socket| handle_socket(relay, socket))
}

fn to_json(msg: &ServerMessage) -> String {
    serde_json::to_string(msg).expect("ServerMessage is always serializable")
}

fn error(message: impl Into<String>, msg_id: Option<String>) -> String {
    to_json(&ServerMessage::Error {
        message: message.into(),
        msg_id,
    })
}

async fn handle_socket(relay: Relay, socket: WebSocket) {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    let ping_interval = relay.0.config.ping_interval;
    let idle_timeout = ping_interval * 3;
    let writer = tokio::spawn(async move {
        let mut ping = tokio::time::interval(ping_interval);
        ping.tick().await;
        loop {
            let out = tokio::select! {
                msg = rx.recv() => match msg {
                    Some(text) => Message::Text(text),
                    None => break,
                },
                _ = ping.tick() => Message::Ping(Vec::new()),
            };
            if ws_tx.send(out).await.is_err() {
                break;
            }
        }
        let _ = ws_tx.close().await;
    });

    // Следующее сообщение от клиента; `None` — соединение закрыто или молчит
    // дольше `idle_timeout` (клиент отвечает на пинги, так что живой не молчит).
    let mut next_msg = async || match tokio::time::timeout(idle_timeout, ws_rx.next()).await {
        Ok(Some(Ok(msg))) => Some(msg),
        _ => None,
    };

    let conn_id = relay.0.next_conn_id.fetch_add(1, Ordering::Relaxed);
    let nonce: [u8; 32] = crypto_core::random_bytes();
    let _ = tx.send(to_json(&ServerMessage::Challenge {
        nonce_b64: b64(nonce),
    }));

    // --- 1. вход ---------------------------------------------------------
    let auth = tokio::time::timeout(relay.0.config.auth_timeout, async {
        while let Some(msg) = next_msg().await {
            let Message::Text(text) = msg else {
                if matches!(msg, Message::Close(_)) {
                    return None;
                }
                continue;
            };
            match serde_json::from_str::<ClientMessage>(&text) {
                Ok(ClientMessage::Auth {
                    account_id,
                    sign_pub_b64,
                    sig_b64,
                }) => {
                    return match authenticate(&relay, &nonce, &account_id, &sign_pub_b64, &sig_b64)
                    {
                        Ok(sign_pub) => Some((account_id, sign_pub)),
                        Err(reason) => {
                            warn!(account_id, "auth rejected: {reason}");
                            let _ = tx.send(error(reason, None));
                            None
                        }
                    };
                }
                Ok(_) => {
                    let _ = tx.send(error("authenticate first", None));
                }
                Err(_) => {
                    let _ = tx.send(error("invalid json", None));
                }
            }
        }
        None
    })
    .await;

    let Ok(Some((me, my_sign_pub))) = auth else {
        if auth.is_err() {
            let _ = tx.send(error("authentication timeout", None));
        }
        drop(tx);
        let _ = writer.await;
        return;
    };

    relay.0.online.insert(
        me.clone(),
        Client {
            conn_id,
            tx: tx.clone(),
        },
    );
    let _ = tx.send(to_json(&ServerMessage::Authenticated {
        account_id: me.clone(),
    }));
    info!(account_id = %me, conn_id, "client authenticated");

    flush_queue(&relay, &me);

    // --- 2. основной цикл ------------------------------------------------
    while let Some(msg) = next_msg().await {
        match msg {
            Message::Text(text) => match serde_json::from_str::<ClientMessage>(&text) {
                Ok(ClientMessage::Send {
                    to,
                    msg_id,
                    envelope,
                }) => {
                    let reply = handle_send(&relay, &me, &my_sign_pub, &to, &msg_id, envelope);
                    let _ = tx.send(reply);
                }
                Ok(ClientMessage::Ack { to, msg_id }) => handle_ack(&relay, &me, &to, &msg_id),
                Ok(ClientMessage::Auth { .. }) => {
                    let _ = tx.send(error("already authenticated", None));
                }
                Err(_) => {
                    let _ = tx.send(error("invalid json", None));
                }
            },
            Message::Close(_) => break,
            _ => {}
        }
    }

    // Убираем из онлайна, только если это всё ещё наше соединение:
    // клиент мог уже переподключиться, и новый сокет трогать нельзя.
    relay.0.online.remove_if(&me, |_, c| c.conn_id == conn_id);
    info!(account_id = %me, conn_id, "client disconnected");
    drop(tx);
    writer.abort();
}

fn authenticate(
    relay: &Relay,
    nonce: &[u8; 32],
    account_id: &str,
    sign_pub_b64: &str,
    sig_b64: &str,
) -> Result<[u8; 32], String> {
    check_id(account_id, "account_id").map_err(|e| e.to_string())?;
    let sign_pub = decode_fixed::<32>(sign_pub_b64, "sign_pub_b64").map_err(|e| e.to_string())?;
    let sig = decode_fixed::<64>(sig_b64, "sig_b64").map_err(|e| e.to_string())?;

    let data = protocol::relay_auth_signing_bytes(nonce, account_id);
    if !crypto_core::verify_signature(&sign_pub, &data, &sig) {
        return Err("invalid auth signature".into());
    }
    // Новые ID выведены из ключа — их можно проверить ещё до первого входа,
    // поэтому «застолбить» чужой ID своим ключом нельзя.
    if crypto_core::check_account_id(account_id, &sign_pub).is_err() {
        return Err("account_id does not belong to this key".into());
    }
    match relay.0.store.bind_account(account_id, &sign_pub) {
        Ok(Binding::New) => {
            info!(account_id, "new account bound to its key");
            Ok(sign_pub)
        }
        Ok(Binding::Known) => Ok(sign_pub),
        Ok(Binding::Mismatch) => Err("this account_id is bound to a different key".into()),
        Err(e) => {
            warn!("store error during auth: {e:#}");
            Err("internal error".into())
        }
    }
}

fn flush_queue(relay: &Relay, me: &str) {
    let items = match relay.0.store.pending_for(me) {
        Ok(items) => items,
        Err(e) => {
            warn!(account_id = me, "cannot read queue: {e:#}");
            return;
        }
    };
    if !items.is_empty() {
        debug!(account_id = me, count = items.len(), "flushing queue");
    }
    for item in items {
        if !relay.push(me, item.payload) {
            break; // клиент уже отвалился — остальное доставим в следующий раз
        }
        // Конверты ждут ack получателя, уведомления о доставке — нет.
        if item.kind == Kind::DeliverAck {
            if let Err(e) = relay.0.store.remove(item.id) {
                warn!("cannot remove delivered ack: {e:#}");
            }
        }
    }
}

fn handle_send(
    relay: &Relay,
    me: &str,
    my_sign_pub: &[u8; 32],
    to: &str,
    msg_id: &str,
    envelope: protocol::EnvelopeB64,
) -> String {
    let reject = |reason: String| error(reason, Some(msg_id.to_owned()));

    if let Err(e) = check_id(to, "to").and_then(|_| check_id(msg_id, "msg_id")) {
        return reject(e.to_string());
    }
    let env = match Envelope::try_from(&envelope) {
        Ok(env) => env,
        Err(e) => return reject(format!("bad envelope: {e}")),
    };
    if env.from != me || env.to != to {
        return reject("envelope from/to does not match the sender/recipient".into());
    }
    if crypto_core::verify_envelope(&env, my_sign_pub).is_err() {
        return reject("envelope is not signed by the sender".into());
    }

    let deliver = to_json(&ServerMessage::Deliver {
        from: me.to_owned(),
        msg_id: msg_id.to_owned(),
        envelope,
    });
    let max = relay.0.config.max_queue_per_recipient;
    match relay
        .0
        .store
        .enqueue(to, me, msg_id, Kind::Deliver, &deliver, max)
    {
        Ok(Enqueue::Queued | Enqueue::Duplicate) => {
            // Повтор тоже пушим: прошлая попытка могла потеряться в пути.
            relay.push(to, deliver);
            to_json(&ServerMessage::Accepted {
                msg_id: msg_id.to_owned(),
            })
        }
        Ok(Enqueue::Full) => reject("recipient's queue is full, try again later".into()),
        Err(e) => {
            warn!("enqueue failed: {e:#}");
            reject("internal error".into())
        }
    }
}

fn handle_ack(relay: &Relay, me: &str, to: &str, msg_id: &str) {
    // Пересылаем подтверждение, только если такое сообщение действительно
    // ждало `me` от `to`. Так нельзя заспамить кого-то фальшивыми ack.
    match relay.0.store.remove_delivered(me, to, msg_id) {
        Ok(true) => {}
        Ok(false) => return,
        Err(e) => {
            warn!("ack failed: {e:#}");
            return;
        }
    }
    let ack = to_json(&ServerMessage::DeliverAck {
        from: me.to_owned(),
        msg_id: msg_id.to_owned(),
    });
    if !relay.push(to, ack.clone()) {
        let max = relay.0.config.max_queue_per_recipient;
        if let Err(e) = relay
            .0
            .store
            .enqueue(to, me, msg_id, Kind::DeliverAck, &ack, max)
        {
            warn!("cannot queue delivery ack: {e:#}");
        }
    }
}
