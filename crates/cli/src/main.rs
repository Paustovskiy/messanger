//! `messenger` — консольный клиент.

mod display;
mod messaging;
mod relay_client;
mod session;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use crypto_core::{Identity, envelope_id, verify_contact_card};
use messaging::Incoming;
use protocol::{ContactCardV2, Envelope, EnvelopeB64, normalize_username};
use session::{Session, Step};
use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use storage::{ContactRow, Db, DeliveryStatus, Direction, IdentityRow, PendingOutgoing};

/// Сколько ждать, пока релей примет сообщение.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Parser)]
#[command(name = "messenger", version)]
#[command(about = "Мессенджер со сквозным шифрованием: консольный клиент")]
struct Cli {
    /// Имя профиля. У каждого профиля своя база и своя личность,
    /// так можно запустить «Алису» и «Боба» на одном компьютере.
    #[arg(
        long,
        global = true,
        env = "MESSENGER_PROFILE",
        default_value = "messenger",
        alias = "app"
    )]
    profile: String,

    /// Явный путь к файлу базы (вместо стандартного каталога профиля).
    #[arg(long, global = true, env = "MESSENGER_DB")]
    db: Option<PathBuf>,

    /// Адрес релея.
    #[arg(
        long,
        global = true,
        env = "MESSENGER_RELAY",
        default_value = "ws://127.0.0.1:8080/ws"
    )]
    relay: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Создать свою личность (ключи) — один раз.
    Init,

    /// Показать свой account_id, username и отпечаток ключей.
    Whoami,

    /// Задать свой @username (5–32 символа: a–z, 0–9, _).
    SetUsername { username: String },

    /// Выдать свою карточку контакта (JSON), чтобы передать собеседнику.
    ExportContact {
        /// Записать в файл вместо вывода на экран.
        #[arg(long, short)]
        out: Option<PathBuf>,
    },

    /// Добавить собеседника по его карточке (строкой, из файла или через stdin).
    AddContact {
        #[arg(long, conflicts_with = "contact_file")]
        contact: Option<String>,
        #[arg(long)]
        contact_file: Option<PathBuf>,
    },

    /// Список контактов.
    #[command(alias = "contacts")]
    ListContacts,

    /// Удалить контакт (по @username или account_id).
    RemoveContact { who: String },

    /// Отправить сообщение через релей.
    Send {
        /// Кому: @username или account_id.
        to: String,
        text: String,
        /// Не ходить на релей, а просто вывести зашифрованный конверт (JSON),
        /// чтобы передать его любым способом. Получатель откроет его `receive`.
        #[arg(long)]
        offline: bool,
        /// Сколько секунд ждать подтверждения доставки.
        #[arg(long, default_value_t = 3)]
        wait: u64,
    },

    /// Открыть конверт, полученный вне релея (строкой, из файла или через stdin).
    Receive {
        #[arg(long, conflicts_with = "envelope_file")]
        envelope: Option<String>,
        #[arg(long)]
        envelope_file: Option<PathBuf>,
    },

    /// Быть онлайн: получать сообщения, дослать исходящие, переподключаться при обрыве.
    Listen,

    /// Подключиться один раз: забрать всё, что ждёт на релее, дослать исходящие и выйти.
    #[command(alias = "retry-outbox")]
    Sync {
        #[arg(long, default_value_t = 100)]
        limit: usize,
        /// Сколько секунд ждать подтверждений доставки исходящих.
        #[arg(long, default_value_t = 3)]
        wait: u64,
    },

    /// История переписки с собеседником.
    Chat {
        with: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },

    /// Список диалогов.
    Threads {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Криптопровайдер для TLS (wss://). Ошибка значит «уже установлен» — это нормально.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let db = match &cli.db {
        Some(path) => Db::open(path)?,
        None => Db::open_default(&cli.profile)?.0,
    };

    match cli.command {
        Command::Init => cmd_init(&db, &cli),
        Command::Whoami => cmd_whoami(&db, &cli),
        Command::SetUsername { username } => cmd_set_username(&db, &username),
        Command::ExportContact { out } => cmd_export_contact(&db, out),
        Command::AddContact {
            contact,
            contact_file,
        } => cmd_add_contact(&db, contact, contact_file),
        Command::ListContacts => cmd_list_contacts(&db),
        Command::RemoveContact { who } => cmd_remove_contact(&db, &who),
        Command::Send {
            to,
            text,
            offline,
            wait,
        } => cmd_send(&db, &cli.relay, &to, &text, offline, wait),
        Command::Receive {
            envelope,
            envelope_file,
        } => cmd_receive(&db, envelope, envelope_file),
        Command::Listen => cmd_listen(&db, &cli.relay),
        Command::Sync { limit, wait } => cmd_sync(&db, &cli.relay, limit, wait),
        Command::Chat { with, limit } => cmd_chat(&db, &with, limit),
        Command::Threads { limit } => cmd_threads(&db, limit),
    }
}

// ---------------------------------------------------------------------------
// Личность
// ---------------------------------------------------------------------------

/// Загрузить свою личность. Личность из старой версии без ключа подписи
/// автоматически получает его.
fn load_identity(db: &Db) -> Result<(IdentityRow, Identity)> {
    let Some(mut row) = db.get_local_identity()? else {
        bail!("личность ещё не создана — сначала выполните `messenger init`");
    };

    let sign_secret = match row.sign_secret {
        Some(s) => s,
        None => {
            let upgraded =
                Identity::from_secrets(&row.account_id, row.secret, crypto_core::random_bytes());
            row.sign_secret = Some(upgraded.sign_secret_bytes());
            row.sign_public = Some(upgraded.sign_public_bytes());
            db.upsert_identity(&row)?;
            eprintln!(
                "Обратите внимание: ваша личность создана старой версией и не имела ключа подписи. \
                 Он только что сгенерирован — разошлите контактам свежую карточку (`messenger export-contact`)."
            );
            upgraded.sign_secret_bytes()
        }
    };

    let id = Identity::from_secrets(&row.account_id, row.secret, sign_secret);
    Ok((row, id))
}

fn cmd_init(db: &Db, cli: &Cli) -> Result<()> {
    if db.get_local_identity()?.is_some() {
        let (row, _) = load_identity(db)?;
        println!("Личность уже есть: {}", row.account_id);
        return Ok(());
    }
    let id = Identity::generate_new();
    let account_id = id.account_id().to_string();
    db.upsert_identity(&IdentityRow {
        account_id: account_id.clone(),
        username: None,
        secret: id.x_secret_bytes(),
        public: id.x_public_bytes(),
        sign_secret: Some(id.sign_secret_bytes()),
        sign_public: Some(id.sign_public_bytes()),
    })?;
    messaging::ensure_signed_prekey(db, &id)?;
    println!("Создана новая личность для профиля `{}`.", cli.profile);
    println!("account_id: {account_id}");
    println!("отпечаток:  {}", id.fingerprint());
    println!();
    println!("Дальше: `messenger set-username <имя>`, затем `messenger export-contact`.");
    Ok(())
}

fn cmd_whoami(db: &Db, cli: &Cli) -> Result<()> {
    let (row, id) = load_identity(db)?;
    println!("account_id: {}", row.account_id);
    println!(
        "username:   {}",
        row.username.as_deref().unwrap_or("(не задан)")
    );
    println!("отпечаток:  {}", id.fingerprint());
    println!("профиль:    {}", cli.profile);
    Ok(())
}

fn cmd_set_username(db: &Db, username: &str) -> Result<()> {
    let (row, _) = load_identity(db)?;
    let norm = normalize_username(username)?;
    db.set_username(&row.account_id, Some(&norm))?;
    println!("Username теперь {norm}. Выгрузите карточку заново, чтобы его увидели собеседники.");
    Ok(())
}

fn cmd_export_contact(db: &Db, out: Option<PathBuf>) -> Result<()> {
    let (row, id) = load_identity(db)?;
    let mut card = id.contact_card(row.username);
    // Свежий предключ в карточке позволяет начать переписку даже без релея.
    let (spk, _) = messaging::ensure_signed_prekey(db, &id)?;
    card.signed_prekey = Some(messaging::signed_prekey_wire(&spk));
    let json = serde_json::to_string_pretty(&card)?;
    match out {
        Some(path) => {
            std::fs::write(&path, format!("{json}\n"))
                .with_context(|| format!("не удалось записать {}", path.display()))?;
            eprintln!("Карточка сохранена в {}", path.display());
        }
        None => println!("{json}"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Контакты
// ---------------------------------------------------------------------------

fn cmd_add_contact(db: &Db, contact: Option<String>, file: Option<PathBuf>) -> Result<()> {
    let (me, _) = load_identity(db)?;
    let json = read_input(contact, file, "contact", "карточку контакта")?;
    let card: ContactCardV2 =
        serde_json::from_str(&json).context("это не похоже на карточку контакта")?;
    let v = verify_contact_card(&card).context("карточка контакта не прошла проверку подписи")?;

    if v.account_id == me.account_id {
        bail!("это ваша собственная карточка");
    }
    if let Some(u) = &v.username {
        normalize_username(u).with_context(|| format!("в карточке недопустимый username {u:?}"))?;
    }
    if let Some(old) = db.get_contact(&v.account_id)? {
        if old.sign_public.is_some_and(|k| k != v.ed25519_pub) || old.public != v.x25519_pub {
            eprintln!(
                "ВНИМАНИЕ: ключи этого контакта ИЗМЕНИЛИСЬ с момента добавления. Обязательно сверьте отпечаток!"
            );
        }
    }

    let signed_prekey = card
        .signed_prekey
        .as_ref()
        .map(|k| messaging::verified_card_prekey(&v.ed25519_pub, k))
        .transpose()?;

    db.upsert_contact(&ContactRow {
        account_id: v.account_id.clone(),
        username: v.username.clone(),
        public: v.x25519_pub,
        sign_public: Some(v.ed25519_pub),
        signed_prekey,
    })?;

    println!(
        "Контакт сохранён: {}",
        v.username.as_deref().unwrap_or(&v.account_id)
    );
    println!("отпечаток: {}", v.fingerprint());
    println!(
        "Сверьте его с тем, что собеседник видит в `messenger whoami` (голосом или при встрече)."
    );
    Ok(())
}

fn cmd_list_contacts(db: &Db) -> Result<()> {
    let contacts = db.list_contacts()?;
    if contacts.is_empty() {
        println!("(контактов пока нет — добавьте через `messenger add-contact`)");
        return Ok(());
    }
    for c in contacts {
        let fp = match c.sign_public {
            Some(k) => crypto_core::fingerprint(&c.public, &k),
            None => "⚠ старая карточка без ключа подписи — добавьте заново".into(),
        };
        println!("{:<20} {}  {}", display::contact_name(&c), c.account_id, fp);
    }
    Ok(())
}

fn cmd_remove_contact(db: &Db, who: &str) -> Result<()> {
    let c = find_contact(db, who)?;
    db.delete_contact(&c.account_id)?;
    db.delete_sessions(&c.account_id)?;
    println!("Удалён контакт {}", display::contact_name(&c));
    Ok(())
}

fn find_contact(db: &Db, who: &str) -> Result<ContactRow> {
    db.find_contact(who)?
        .with_context(|| format!("контакт {who:?} не найден — см. `messenger list-contacts`"))
}

// ---------------------------------------------------------------------------
// Отправка и приём
// ---------------------------------------------------------------------------

fn cmd_send(db: &Db, relay: &str, to: &str, text: &str, offline: bool, wait: u64) -> Result<()> {
    let (_, me) = load_identity(db)?;
    let contact = find_contact(db, to)?;
    messaging::peer_keys(&contact)?;
    if text.trim().is_empty() {
        bail!("пустое сообщение");
    }

    if offline {
        let (wire, _) = messaging::seal_and_store(db, &me, &contact, None, text)?;
        println!("{}", serde_json::to_string_pretty(&wire)?);
        eprintln!(
            "Передайте этот конверт собеседнику ({}) — он откроет его командой `messenger receive`.",
            display::contact_name(&contact)
        );
        return Ok(());
    }

    const SAVED: &str = "релей недоступен; сообщение сохранено в исходящих и уйдёт при \
                         `messenger listen` или `messenger sync`";

    runtime()?.block_on(async {
        // Если сессия уже есть — шифруем и сохраняем до похода в сеть,
        // чтобы сообщение не потерялось, даже если релей недоступен.
        let mut sealed = if messaging::can_send_now(db, &contact.account_id)? {
            Some(messaging::seal_and_store(db, &me, &contact, None, text)?)
        } else {
            None
        };

        let mut s = match Session::open(relay, db, &me).await {
            Ok(s) => s,
            Err(e) if sealed.is_some() => return Err(e.context(SAVED)),
            // Сессии нет, релея нет — выручит предключ из карточки, если он есть.
            Err(e) if contact.signed_prekey.is_some() => {
                messaging::seal_and_store(db, &me, &contact, None, text)?;
                return Err(e.context(SAVED));
            }
            Err(e) => {
                return Err(e.context(
                    "релей недоступен, а сессии с собеседником ещё нет — сообщение не отправлено",
                ));
            }
        };

        if sealed.is_none() {
            // Первое сообщение: берём у релея свежие предключи собеседника.
            let peer = contact.account_id.clone();
            s.fetch_bundle(&peer).await?;
            wait_for(&mut s, ACCEPT_TIMEOUT, |s| s.bundles.contains_key(&peer)).await?;
            let bundle = s.bundles.get(&peer).cloned().flatten();
            sealed = Some(messaging::seal_and_store(db, &me, &contact, bundle, text)?);
        }
        let (wire, msg_id) = sealed.expect("sealed above");
        let pending = PendingOutgoing {
            peer_account_id: contact.account_id.clone(),
            msg_id: msg_id.clone(),
            envelope_json: serde_json::to_string(&wire)?,
        };
        s.send_pending(&pending).await?;

        let ids = [msg_id.clone()];
        wait_for(&mut s, ACCEPT_TIMEOUT, |s| all_settled(s, &ids)).await?;
        if let Some(reason) = s.rejected.get(&msg_id) {
            if reason.contains("rate limited") {
                bail!(
                    "релей просит подождать (слишком много сообщений подряд); \
                     сообщение осталось в исходящих и уйдёт при `messenger sync`"
                );
            }
            bail!("релей отклонил сообщение: {reason}");
        }
        if !s.accepted.contains(&msg_id) {
            bail!("релей не подтвердил приём; сообщение осталось в исходящих");
        }
        println!("✓  отправлено: {}", display::contact_name(&contact));

        wait_for(&mut s, Duration::from_secs(wait), |s| {
            s.delivered.contains(&msg_id)
        })
        .await?;
        if !s.delivered.contains(&msg_id) {
            println!("   собеседник не в сети — релей доставит, как только он подключится");
        }
        s.close().await;
        Ok(())
    })
}

fn cmd_receive(db: &Db, envelope: Option<String>, file: Option<PathBuf>) -> Result<()> {
    let (_, me) = load_identity(db)?;
    let json = read_input(envelope, file, "envelope", "конверт")?;
    let wire: EnvelopeB64 =
        serde_json::from_str(&json).context("это не похоже на конверт сообщения")?;
    let env = Envelope::try_from(&wire)?;

    let contact = db.get_contact(&env.from)?.with_context(|| {
        format!(
            "сообщение от неизвестного аккаунта {}; сначала добавьте его карточку",
            env.from
        )
    })?;

    match messaging::open_and_store(db, &me, &contact, &wire, &envelope_id(&env))
        .context("не удалось открыть сообщение")?
    {
        Incoming::New(text) => println!("{}: {}", display::contact_name(&contact), text),
        Incoming::Duplicate => eprintln!("(это сообщение уже было получено раньше)"),
    }
    Ok(())
}

fn cmd_listen(db: &Db, relay: &str) -> Result<()> {
    let (row, me) = load_identity(db)?;
    let name = row.username.unwrap_or(row.account_id);

    runtime()?.block_on(async {
        let listen = async {
            let mut backoff = Duration::from_secs(1);
            loop {
                match Session::open(relay, db, &me).await {
                    Ok(mut s) => {
                        backoff = Duration::from_secs(1);
                        println!("В сети как {name} ({relay}). Ctrl+C — выйти.");

                        let pending = db.list_pending_outgoing(1000)?;
                        for p in &pending {
                            s.send_pending(p).await?;
                        }
                        if !pending.is_empty() {
                            println!("Досылаю из исходящих: {}", pending.len());
                        }

                        loop {
                            match s.step(None).await {
                                Ok(Step::Closed) => break,
                                Ok(_) => {}
                                Err(e) => {
                                    eprintln!("ошибка соединения: {e:#}");
                                    break;
                                }
                            }
                        }
                        eprintln!("Соединение потеряно.");
                    }
                    Err(e) => eprintln!("{e:#}"),
                }
                eprintln!("Переподключение через {} с…", backoff.as_secs());
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
            #[allow(unreachable_code)]
            Ok::<_, anyhow::Error>(())
        };

        tokio::select! {
            r = listen => r,
            _ = shutdown_signal() => {
                println!();
                Ok(())
            }
        }
    })
}

fn cmd_sync(db: &Db, relay: &str, limit: usize, wait: u64) -> Result<()> {
    let (_, me) = load_identity(db)?;
    let pending = db.list_pending_outgoing(limit)?;

    runtime()?.block_on(async {
        let mut s = Session::open(relay, db, &me).await?;
        for p in &pending {
            s.send_pending(p).await?;
        }
        let ids: Vec<String> = pending.iter().map(|p| p.msg_id.clone()).collect();

        // Входящие: релей выдаёт очередь сразу после входа и отмечает её конец.
        wait_for(&mut s, ACCEPT_TIMEOUT, |s| s.synced && all_settled(s, &ids)).await?;
        if ids.is_empty() {
            println!("Исходящие пусты — всё доставлено.");
        } else {
            wait_for(&mut s, Duration::from_secs(wait), |s| {
                ids.iter().all(|id| s.delivered.contains(id) || s.rejected.contains_key(id))
            })
            .await?;
            let accepted = ids.iter().filter(|id| s.accepted.contains(*id)).count();
            let delivered = ids.iter().filter(|id| s.delivered.contains(*id)).count();
            let rejected = ids.iter().filter(|id| s.rejected.contains_key(*id)).count();
            println!(
                "Исходящих: {} — принято релеем {accepted}, доставлено {delivered}, отклонено {rejected}.",
                ids.len()
            );
        }
        s.close().await;
        Ok(())
    })
}

fn all_settled(s: &Session<'_>, ids: &[String]) -> bool {
    ids.iter()
        .all(|id| s.accepted.contains(id) || s.rejected.contains_key(id))
}

/// Обрабатывать события релея, пока не выполнится `done` или не выйдет время.
async fn wait_for(
    s: &mut Session<'_>,
    timeout: Duration,
    done: impl Fn(&Session<'_>) -> bool,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while !done(s) {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match s.step(Some(left)).await? {
            Step::Handled => {}
            Step::Timeout => break,
            Step::Closed => bail!("релей закрыл соединение"),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// История
// ---------------------------------------------------------------------------

fn cmd_chat(db: &Db, with: &str, limit: usize) -> Result<()> {
    let peer = find_contact(db, with)?;
    let messages = db.list_messages_for_peer(&peer.account_id, limit)?;
    if messages.is_empty() {
        println!("(с {} пока нет сообщений)", display::contact_name(&peer));
        return Ok(());
    }
    let name = display::contact_name(&peer);
    for m in messages {
        let (who, mark) = match m.direction {
            Direction::In => (name.as_str(), ""),
            Direction::Out => (
                "я",
                match m.status {
                    DeliveryStatus::Delivered => " ✓✓",
                    DeliveryStatus::Pending => " ✓",
                    DeliveryStatus::Failed => " ✗",
                },
            ),
        };
        println!(
            "[{}] {who}{mark}: {}",
            display::timestamp(m.created_at),
            m.plaintext
        );
    }
    db.mark_thread_read(&peer.account_id)?;
    Ok(())
}

fn cmd_threads(db: &Db, limit: usize) -> Result<()> {
    let threads = db.list_threads(limit)?;
    if threads.is_empty() {
        println!("(диалогов пока нет)");
        return Ok(());
    }
    for t in threads {
        let who = t.peer_username.as_deref().unwrap_or(&t.peer_account_id);
        let unread = if t.unread_count > 0 {
            format!(" ({} новых)", t.unread_count)
        } else {
            String::new()
        };
        let prefix = match (t.last_direction, t.last_status) {
            (Direction::In, _) => "",
            (Direction::Out, DeliveryStatus::Delivered) => "я ✓✓: ",
            (Direction::Out, DeliveryStatus::Pending) => "я ✓: ",
            (Direction::Out, DeliveryStatus::Failed) => "я ✗: ",
        };
        println!(
            "[{}] {who}{unread} — {prefix}{}",
            display::timestamp(t.last_created_at),
            display::preview(&t.last_plaintext, 60)
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Помощники
// ---------------------------------------------------------------------------

/// Взять JSON из аргумента, из файла или из stdin.
fn read_input(
    direct: Option<String>,
    file: Option<PathBuf>,
    flag: &str,
    what: &str,
) -> Result<String> {
    if let Some(s) = direct {
        return Ok(s);
    }
    if let Some(path) = file {
        return std::fs::read_to_string(&path)
            .with_context(|| format!("не удалось прочитать {}", path.display()));
    }
    if std::io::stdin().is_terminal() {
        bail!("передайте {what}: --{flag} '<json>', --{flag}-file <путь> или через stdin");
    }
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .with_context(|| format!("не удалось прочитать {what} из stdin"))?;
    let buf = buf.trim().to_string();
    if buf.is_empty() {
        bail!("stdin пуст — ожидался {what} в формате JSON");
    }
    Ok(buf)
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}

/// Ждать Ctrl+C или SIGTERM (так завершают процесс systemd и `docker stop`).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
