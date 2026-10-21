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

pub mod ratelimit;
pub mod store;

use anyhow::Result;
use axum::{
    Router,
    extract::{
        ConnectInfo, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use protocol::{
    ClientMessage, Envelope, OneTimePrekey, OneTimePrekeyB64, ServerMessage, SignedPrekey,
    SignedPrekeyB64, b64, check_id, decode_fixed,
};
use ratelimit::{Rate, RateLimiter};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
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
    /// Сколько одноразовых предключей храним на аккаунт.
    pub max_one_time_prekeys: usize,
    /// Максимальный размер одного WebSocket-сообщения.
    pub max_frame_bytes: usize,
    /// Как часто пинговать клиента. Если от клиента ничего не слышно три
    /// интервала подряд, соединение считается мёртвым и закрывается.
    pub ping_interval: Duration,
    /// Ограничения частоты.
    pub limits: Limits,
    /// Брать адрес клиента из `X-Forwarded-For` (последнее значение).
    /// Включать, только если релей стоит за своим обратным прокси: иначе
    /// клиент сможет подставить любой адрес.
    pub trust_forwarded_for: bool,
}

/// Ограничения частоты. Всё, что сверх, получает ошибку `rate limited`;
/// исключение — выдача предключей, которая просто обходится без одноразового ключа.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Новых подключений с одного IP.
    pub connections_per_ip: Rate,
    /// Одновременных соединений одного аккаунта.
    pub max_connections_per_account: usize,
    /// Любых сообщений от одного соединения (защита от флуда).
    pub frames_per_connection: Rate,
    /// Отправленных конвертов от одного аккаунта.
    pub sends: Rate,
    /// Публикаций предключей от одного аккаунта.
    pub publishes: Rate,
    /// Запросов предключей от одного аккаунта; сверх — без одноразового ключа.
    pub bundle_fetches: Rate,
    /// Сколько одноразовых ключей одного аккаунта можно раздать. Защищает от
    /// «выкачивания» с помощью множества аккаунтов.
    pub one_time_per_target: Rate,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connections_per_ip: Rate::per_minute(60),
            max_connections_per_account: 10,
            frames_per_connection: Rate::per_minute(600),
            sends: Rate::per_minute(120),
            publishes: Rate::per_hour(30),
            bundle_fetches: Rate::per_minute(30),
            one_time_per_target: Rate::per_hour(50),
        }
    }
}

struct Limiters {
    connections_per_ip: RateLimiter,
    sends: RateLimiter,
    publishes: RateLimiter,
    bundle_fetches: RateLimiter,
    one_time_per_target: RateLimiter,
}

impl Limiters {
    fn new(l: &Limits) -> Self {
        Self {
            connections_per_ip: RateLimiter::new(l.connections_per_ip),
            sends: RateLimiter::new(l.sends),
            publishes: RateLimiter::new(l.publishes),
            bundle_fetches: RateLimiter::new(l.bundle_fetches),
            one_time_per_target: RateLimiter::new(l.one_time_per_target),
        }
    }

    fn cleanup(&self) {
        for l in [
            &self.connections_per_ip,
            &self.sends,
            &self.publishes,
            &self.bundle_fetches,
            &self.one_time_per_target,
        ] {
            l.cleanup();
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            db_path: None,
            message_ttl: Duration::from_secs(30 * 24 * 3600),
            max_queue_per_recipient: 1000,
            auth_timeout: Duration::from_secs(10),
            max_one_time_prekeys: 200,
            max_frame_bytes: 128 * 1024,
            ping_interval: Duration::from_secs(30),
            limits: Limits::default(),
            trust_forwarded_for: false,
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
    /// У одного аккаунта может быть несколько соединений одновременно
    /// (например, `listen` и `send` в соседних терминалах) — шлём всем.
    online: DashMap<String, Vec<Client>>,
    next_conn_id: AtomicU64,
    limiters: Limiters,
}

#[derive(Clone)]
pub struct Relay(Arc<Inner>);

impl Relay {
    pub fn new(config: Config) -> Result<Self> {
        let store = Store::open(config.db_path.as_deref())?;
        let limiters = Limiters::new(&config.limits);
        Ok(Self(Arc::new(Inner {
            config,
            store,
            online: DashMap::new(),
            next_conn_id: AtomicU64::new(1),
            limiters,
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
        let cleaner = tokio::spawn(limiter_cleanup_loop(self.clone()));
        let result = axum::serve(
            listener,
            self.router()
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown)
        .await;
        purger.abort();
        cleaner.abort();
        Ok(result?)
    }

    /// Отправить JSON во все соединения получателя. `true`, если хоть одно живо.
    fn push(&self, account_id: &str, json: String) -> bool {
        let Some(clients) = self.0.online.get(account_id) else {
            return false;
        };
        // Именно во все: короткое замыкание (`any`) пропустило бы остальные соединения.
        let mut delivered = false;
        for c in clients.iter() {
            delivered |= c.tx.send(json.clone()).is_ok();
        }
        delivered
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

async fn limiter_cleanup_loop(relay: Relay) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        relay.0.limiters.cleanup();
    }
}

/// Адрес клиента: из `X-Forwarded-For`, если мы за своим прокси, иначе из TCP.
fn client_ip(relay: &Relay, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    if relay.0.config.trust_forwarded_for {
        // Берём строго последнее значение: его добавил наш прокси, а более ранние
        // клиент мог подделать. Если оно битое — не ищем «подходящее» раньше в цепочке.
        let last = headers
            .get_all("x-forwarded-for")
            .iter()
            .next_back()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|ip| ip.trim().parse::<IpAddr>().ok());
        if let Some(ip) = last {
            return ip;
        }
    }
    peer.ip()
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(relay): State<Relay>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let ip = client_ip(&relay, peer, &headers);
    if !relay.0.limiters.connections_per_ip.check(&ip.to_string()) {
        warn!(%ip, "too many connections from this address");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "too many connections, retry later",
        )
            .into_response();
    }
    let max = relay.0.config.max_frame_bytes;
    ws.max_message_size(max)
        .max_frame_size(max)
        .on_upgrade(move |socket| handle_socket(relay, socket))
        .into_response()
}

const RATE_LIMITED: &str = "rate limited, retry later";

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

    {
        let mut clients = relay.0.online.entry(me.clone()).or_default();
        if clients.len() >= relay.0.config.limits.max_connections_per_account {
            drop(clients);
            warn!(account_id = %me, "too many simultaneous connections");
            let _ = tx.send(error(
                "too many simultaneous connections for this account",
                None,
            ));
            drop(tx);
            let _ = writer.await;
            return;
        }
        clients.push(Client {
            conn_id,
            tx: tx.clone(),
        });
    }
    let _ = tx.send(to_json(&ServerMessage::Authenticated {
        account_id: me.clone(),
    }));
    info!(account_id = %me, conn_id, "client authenticated");

    flush_queue(&relay, &me, &tx);
    // Статус предключей идёт после очереди и заодно говорит клиенту:
    // «всё, что накопилось, ты уже получил».
    let _ = tx.send(prekey_status(&relay, &me));

    // --- 2. основной цикл ------------------------------------------------
    let frames = RateLimiter::new(relay.0.config.limits.frames_per_connection);
    while let Some(msg) = next_msg().await {
        if matches!(msg, Message::Text(_) | Message::Binary(_)) && !frames.check("") {
            let _ = tx.send(error(RATE_LIMITED, None));
            continue;
        }
        match msg {
            Message::Text(text) => match serde_json::from_str::<ClientMessage>(&text) {
                Ok(ClientMessage::Send {
                    to,
                    msg_id,
                    envelope,
                }) => {
                    let reply = if relay.0.limiters.sends.check(&me) {
                        handle_send(&relay, &me, &my_sign_pub, &to, &msg_id, envelope)
                    } else {
                        error(RATE_LIMITED, Some(msg_id))
                    };
                    let _ = tx.send(reply);
                }
                Ok(ClientMessage::Ack { to, msg_id }) => handle_ack(&relay, &me, &to, &msg_id),
                Ok(ClientMessage::PublishPrekeys {
                    signed_prekey,
                    one_time,
                }) => {
                    let reply = if relay.0.limiters.publishes.check(&me) {
                        handle_publish(&relay, &me, &my_sign_pub, &signed_prekey, &one_time)
                    } else {
                        error(RATE_LIMITED, None)
                    };
                    let _ = tx.send(reply);
                }
                Ok(ClientMessage::FetchBundle { account_id }) => {
                    let _ = tx.send(handle_fetch_bundle(&relay, &me, &account_id));
                }
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

    // Убираем из онлайна только это соединение: остальные соединения
    // того же аккаунта (другой терминал, переподключение) продолжают работать.
    if let Some(mut clients) = relay.0.online.get_mut(&me) {
        clients.retain(|c| c.conn_id != conn_id);
    }
    relay
        .0
        .online
        .remove_if(&me, |_, clients| clients.is_empty());
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

/// Отдать накопившуюся очередь новому соединению (остальные её уже получали).
fn flush_queue(relay: &Relay, me: &str, tx: &mpsc::UnboundedSender<String>) {
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
        if tx.send(item.payload).is_err() {
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

fn prekey_status(relay: &Relay, me: &str) -> String {
    match relay.0.store.prekey_status(me) {
        Ok((has_signed_prekey, one_time_left)) => to_json(&ServerMessage::PrekeyStatus {
            has_signed_prekey,
            one_time_left,
        }),
        Err(e) => {
            warn!("prekey status failed: {e:#}");
            error("internal error", None)
        }
    }
}

fn handle_publish(
    relay: &Relay,
    me: &str,
    my_sign_pub: &[u8; 32],
    signed: &SignedPrekeyB64,
    one_time: &[OneTimePrekeyB64],
) -> String {
    if one_time.len() > protocol::MAX_ONE_TIME_PREKEYS_PER_UPLOAD {
        return error("too many one-time prekeys in one upload", None);
    }
    let signed = match SignedPrekey::try_from(signed) {
        Ok(k) => k,
        Err(e) => return error(format!("bad signed prekey: {e}"), None),
    };
    // Релей не принимает предключи, не подписанные владельцем аккаунта.
    if crypto_core::verify_signed_prekey(my_sign_pub, &signed).is_err() {
        return error("signed prekey is not signed by this account", None);
    }
    let one_time: Result<Vec<OneTimePrekey>, _> =
        one_time.iter().map(OneTimePrekey::try_from).collect();
    let one_time = match one_time {
        Ok(k) => k,
        Err(e) => return error(format!("bad one-time prekey: {e}"), None),
    };
    match relay
        .0
        .store
        .publish_prekeys(me, &signed, &one_time, relay.0.config.max_one_time_prekeys)
    {
        Ok(left) => to_json(&ServerMessage::PrekeyStatus {
            has_signed_prekey: true,
            one_time_left: left,
        }),
        Err(e) => {
            warn!("publish prekeys failed: {e:#}");
            error("internal error", None)
        }
    }
}

fn handle_fetch_bundle(relay: &Relay, me: &str, account_id: &str) -> String {
    if let Err(e) = check_id(account_id, "account_id") {
        return error(e.to_string(), None);
    }
    // Сверх лимитов набор выдаётся без одноразового ключа: переписка работает,
    // а «выкачать» чужие одноразовые ключи не получится.
    let requester_ok = relay.0.limiters.bundle_fetches.check(me);
    let allow_one_time = || {
        let ok = requester_ok && relay.0.limiters.one_time_per_target.check(account_id);
        if !ok {
            debug!(
                requester = me,
                target = account_id,
                "one-time prekey withheld by rate limit"
            );
        }
        ok
    };
    match relay.0.store.take_bundle(account_id, allow_one_time) {
        Ok(bundle) => {
            let (signed_prekey, one_time) = match bundle {
                Some((s, o)) => (
                    Some(SignedPrekeyB64::from(&s)),
                    o.as_ref().map(OneTimePrekeyB64::from),
                ),
                None => (None, None),
            };
            to_json(&ServerMessage::Bundle {
                account_id: account_id.to_owned(),
                signed_prekey,
                one_time,
            })
        }
        Err(e) => {
            warn!("fetch bundle failed: {e:#}");
            error("internal error", None)
        }
    }
}
