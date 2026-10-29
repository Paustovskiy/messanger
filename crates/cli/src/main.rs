//! `messenger` — консольный клиент.

mod backup;
mod devices;
mod display;
mod messaging;
mod password;
mod relay_client;
mod session;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use crypto_core::{Identity, envelope_id, verify_contact_card};
use devices::{LinkPayload, LinkRequest, LinkResponse, LinkedContact};
use messaging::Incoming;
use protocol::{
    ContactCardV2, DeviceInfo, DeviceList, Envelope, EnvelopeB64, MAX_DEVICE_NAME, MAX_DEVICES,
    PRIMARY_DEVICE, SignedDeviceListB64, b64, decode_fixed, normalize_username,
};
use session::{Session, Step};
use std::collections::HashMap;
use std::io::{BufRead, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use storage::{
    ContactRow, Db, DeliveryStatus, Direction, FileState, IdentityRow, OutboxItem, PendingLink,
};

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
    /// Создать свою личность (ключи) — один раз. База шифруется паролем.
    Init {
        /// Не шифровать базу паролем (не рекомендуется).
        #[arg(long)]
        no_password: bool,
    },

    /// Зашифровать базу паролем или сменить пароль.
    SetPassword,

    /// Снять пароль с базы (не рекомендуется).
    RemovePassword,

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

    /// Устройства аккаунта.
    Devices,

    /// Подключить этот профиль как новое устройство существующего аккаунта
    /// (шаг 1 из 3: выдаёт код для основного устройства).
    Link {
        /// Как назвать устройство (видно в `messenger devices`).
        #[arg(long, default_value = "новое устройство")]
        name: String,
        /// Не шифровать базу паролем (не рекомендуется).
        #[arg(long)]
        no_password: bool,
    },

    /// На основном устройстве: разрешить подключение нового (шаг 2 из 3).
    LinkApprove {
        /// Код подключения, который показала команда `link`.
        code: String,
        /// Записать ответ в файл вместо вывода на экран.
        #[arg(long, short)]
        out: Option<PathBuf>,
        /// Не спрашивать подтверждение (отпечаток сверен заранее).
        #[arg(long)]
        yes: bool,
    },

    /// На новом устройстве: завершить подключение по ответу основного (шаг 3 из 3).
    LinkFinish {
        #[arg(long, conflicts_with = "response_file")]
        response: Option<String>,
        #[arg(long)]
        response_file: Option<PathBuf>,
    },

    /// Сделать резервную копию ключа аккаунта в файл и показать код для записи на бумагу.
    BackupKey {
        /// Куда записать файл копии.
        #[arg(long, short)]
        out: PathBuf,
        /// Заменить файл, если он уже есть.
        #[arg(long)]
        force: bool,
        /// Разрешить вывод, перенаправленный в файл или канал (код попадёт туда же).
        #[arg(long)]
        allow_redirect: bool,
    },

    /// На устройстве с ключом аккаунта: отключить другое устройство от аккаунта.
    Unlink {
        /// Номер устройства (см. `messenger devices`).
        device_id: u32,
        /// Не спрашивать подтверждение.
        #[arg(long)]
        yes: bool,
    },
}

fn main() -> std::process::ExitCode {
    // Ошибки — для человека: одной строкой с причинами, без стека вызовов
    // (его печатал бы anyhow при выставленном RUST_BACKTRACE).
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Ошибка: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    // Криптопровайдер для TLS (wss://). Ошибка значит «уже установлен» — это нормально.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let path = match &cli.db {
        Some(path) => path.clone(),
        None => Db::default_path(&cli.profile)?,
    };

    match &cli.command {
        Command::Init { no_password } => return cmd_init(&path, &cli.profile, *no_password),
        Command::SetPassword => return cmd_set_password(&path),
        Command::RemovePassword => return cmd_remove_password(&path),
        Command::Link { name, no_password } => return cmd_link(&path, name, *no_password),
        _ => {}
    }

    let db = open_db(&path, true)?;
    match cli.command {
        Command::Init { .. }
        | Command::SetPassword
        | Command::RemovePassword
        | Command::Link { .. } => unreachable!(),
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
        Command::Devices => cmd_devices(&db),
        Command::LinkApprove { code, out, yes } => {
            cmd_link_approve(&db, &cli.relay, &code, out, yes)
        }
        Command::LinkFinish {
            response,
            response_file,
        } => cmd_link_finish(&db, response, response_file),
        Command::BackupKey {
            out,
            force,
            allow_redirect,
        } => backup::cmd_backup_key(&db, &out, force, allow_redirect),
        Command::Unlink { device_id, yes } => cmd_unlink(&db, &cli.relay, device_id, yes),
    }
}

// ---------------------------------------------------------------------------
// Личность
// ---------------------------------------------------------------------------

/// Загрузить свою личность (ключи этого устройства). Личность из старой
/// версии без ключа подписи автоматически получает его, а основное
/// устройство — список устройств аккаунта.
fn load_identity(db: &Db) -> Result<(IdentityRow, Identity)> {
    let Some(mut row) = db.get_local_identity()? else {
        if db.pending_link()?.is_some() {
            bail!(
                "устройство ещё не подключено: разрешите подключение на основном устройстве \
                 (`messenger link-approve`) и завершите здесь (`messenger link-finish`)"
            );
        }
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

    let mut id =
        Identity::from_secrets(&row.account_id, row.secret, sign_secret).with_device(row.device_id);
    if let Some(account_secret) = row.account_sign_secret {
        id = id.with_account_key(account_secret);
    }
    devices::check_account_key(db, &id)?;
    if id.device_id() == PRIMARY_DEVICE {
        devices::own_list(db, &id)?;
    }
    Ok((row, id))
}

/// Открыть базу профиля, спросив пароль, если она зашифрована.
fn open_db(path: &Path, warn_if_plain: bool) -> Result<Db> {
    match storage::file_state(path)? {
        FileState::Missing => {
            bail!("личность ещё не создана — сначала выполните `messenger init`")
        }
        FileState::Plain => {
            let db = Db::open(path, None)?;
            if warn_if_plain {
                eprintln!(
                    "⚠ база не зашифрована паролем: история и ключи лежат на диске открыто. \
                     Зашифровать: `messenger set-password`"
                );
            }
            Ok(db)
        }
        FileState::Encrypted => {
            let pw = password::ask(password::ENV_PASSWORD, "Пароль от базы: ")?;
            Db::open(path, Some(&pw))
        }
    }
}

fn cmd_init(path: &Path, profile: &str, no_password: bool) -> Result<()> {
    let state = storage::file_state(path)?;
    if state != FileState::Missing {
        let db = open_db(path, false)?;
        if let Some(row) = db.get_local_identity()? {
            println!("Личность уже есть: {}", row.account_id);
            if state == FileState::Plain {
                println!(
                    "База не зашифрована — это можно сделать командой `messenger set-password`."
                );
            }
            return Ok(());
        }
        if state == FileState::Encrypted {
            // Зашифрованная база без личности: пароль уже введён, просто создаём.
            return create_identity(&db, profile, true);
        }
    }

    let pw = if no_password {
        None
    } else {
        Some(password::ask_new(
            password::ENV_PASSWORD,
            "Придумайте пароль для базы",
        )?)
    };
    match state {
        FileState::Missing => {
            let db = Db::open(path, pw.as_deref().map(|p| p.as_str()))?;
            create_identity(&db, profile, pw.is_some())
        }
        _ => {
            // Пустая незашифрованная база (например, от прошлой версии): создаём
            // личность, затем шифруем файл целиком.
            create_identity(&Db::open(path, None)?, profile, false)?;
            if let Some(pw) = pw {
                storage::reencrypt(path, None, Some(&pw))?;
                println!("База зашифрована паролем.");
            }
            Ok(())
        }
    }
}

fn create_identity(db: &Db, profile: &str, encrypted: bool) -> Result<()> {
    let id = Identity::generate_new();
    let account_id = id.account_id().to_string();
    db.upsert_identity(&IdentityRow {
        account_id: account_id.clone(),
        device_id: PRIMARY_DEVICE,
        username: None,
        secret: id.x_secret_bytes(),
        public: id.x_public_bytes(),
        sign_secret: Some(id.sign_secret_bytes()),
        sign_public: Some(id.sign_public_bytes()),
        account_sign_secret: None,
    })?;
    messaging::ensure_signed_prekey(db, &id)?;
    devices::own_list(db, &id)?;
    println!("Создана новая личность для профиля `{profile}`.");
    println!("account_id: {account_id}");
    println!("отпечаток:  {}", id.fingerprint());
    if !encrypted {
        println!("⚠ база не зашифрована паролем. Зашифровать: `messenger set-password`.");
    }
    println!();
    println!("Дальше: `messenger set-username <имя>`, затем `messenger export-contact`.");
    Ok(())
}

fn cmd_set_password(path: &Path) -> Result<()> {
    match storage::file_state(path)? {
        FileState::Missing => bail!("личность ещё не создана — сначала выполните `messenger init`"),
        FileState::Plain => {
            let new = password::ask_new(password::ENV_NEW_PASSWORD, "Придумайте пароль для базы")?;
            storage::reencrypt(path, None, Some(&new))?;
            println!("Готово: база зашифрована паролем.");
        }
        FileState::Encrypted => {
            let current = password::ask(password::ENV_PASSWORD, "Текущий пароль: ")?;
            let new = password::ask_new(password::ENV_NEW_PASSWORD, "Придумайте новый пароль")?;
            storage::reencrypt(path, Some(&current), Some(&new))?;
            println!("Готово: пароль изменён.");
        }
    }
    Ok(())
}

fn cmd_remove_password(path: &Path) -> Result<()> {
    match storage::file_state(path)? {
        FileState::Missing => bail!("личность ещё не создана — сначала выполните `messenger init`"),
        FileState::Plain => println!("База и так без пароля."),
        FileState::Encrypted => {
            let current = password::ask(password::ENV_PASSWORD, "Текущий пароль: ")?;
            storage::reencrypt(path, Some(&current), None)?;
            println!("Пароль снят. ⚠ Теперь история и ключи лежат на диске открыто.");
        }
    }
    Ok(())
}

fn cmd_whoami(db: &Db, cli: &Cli) -> Result<()> {
    let (row, id) = load_identity(db)?;
    let (list, _) = devices::own_list(db, &id)?;
    let device_name = list
        .device(id.device_id())
        .map(|d| d.name.as_str())
        .unwrap_or("отключено от аккаунта");
    println!("account_id: {}", row.account_id);
    println!(
        "username:   {}",
        row.username.as_deref().unwrap_or("(не задан)")
    );
    println!("отпечаток:  {}", devices::account_fingerprint(&list));
    println!("устройство: №{} «{device_name}»", id.device_id());
    if list.devices.len() > 1 {
        println!("устройств в аккаунте: {}", list.devices.len());
    }
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
    if !id.has_account_key() {
        bail!(
            "карточку подписывает ключ аккаунта, а его на этом устройстве нет — \
             выгрузите карточку на устройстве с ключом аккаунта"
        );
    }
    let (list, list_wire) = devices::own_list(db, &id)?;
    let mut card = if id.device_id() == PRIMARY_DEVICE {
        let mut card = id.contact_card(row.username);
        // Свежий предключ в карточке позволяет начать переписку даже без релея.
        let (spk, _) = messaging::ensure_signed_prekey(db, &id)?;
        card.signed_prekey = Some(messaging::signed_prekey_wire(&spk));
        card
    } else {
        // Предключ принадлежит устройству №1, поэтому в такой карточке его нет.
        let primary = list
            .device(PRIMARY_DEVICE)
            .context("в списке устройств нет основного устройства")?;
        id.account_contact_card(row.username, primary.x25519_pub)?
    };
    // Список устройств: собеседник сразу будет писать на все.
    card.devices = Some(list_wire);
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
    let (me, my_id) = load_identity(db)?;
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
    if let Some(list) = &card.devices {
        if list.account_id != v.account_id {
            bail!("список устройств в карточке — от другого аккаунта");
        }
        devices::accept(db, &my_id, list)
            .context("список устройств в карточке не прошёл проверку")?;
    }

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
        let devices = match devices::stored(db, &c.account_id)? {
            Some((l, _)) if l.devices.len() > 1 => format!("  (устройств: {})", l.devices.len()),
            _ => String::new(),
        };
        println!(
            "{:<20} {}  {}{devices}",
            display::contact_name(&c),
            c.account_id,
            fp
        );
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
    devices::primary_of(&contact)?;
    if text.trim().is_empty() {
        bail!("пустое сообщение");
    }
    let name = display::contact_name(&contact);

    if offline {
        // Без релея — только устройствам собеседника, с которыми уже есть
        // сессия (или основному — по предключу из карточки).
        let recipients = devices::devices_of_contact(db, &contact)?;
        let sealed =
            messaging::seal_message(db, &me, &contact, &recipients, &[], &HashMap::new(), text)?;
        report_skipped(db, &sealed.skipped);
        let envelopes: Vec<serde_json::Value> = sealed
            .items
            .iter()
            .map(|i| serde_json::from_str(&i.envelope_json))
            .collect::<Result<_, _>>()?;
        let json = match envelopes.as_slice() {
            [one] => serde_json::to_string_pretty(one)?,
            many => serde_json::to_string_pretty(many)?,
        };
        println!("{json}");
        eprintln!(
            "Передайте {} собеседнику ({name}) — он откроет его командой `messenger receive`.",
            if envelopes.len() == 1 {
                "этот конверт".to_string()
            } else {
                format!(
                    "эти конверты (по одному на каждое из {} устройств)",
                    envelopes.len()
                )
            }
        );
        return Ok(());
    }

    const SAVED: &str = "релей недоступен; сообщение сохранено в исходящих и уйдёт при \
                         `messenger listen` или `messenger sync`";

    runtime()?.block_on(async {
        let mut session = Session::open(relay, db, &me).await;
        let mut bundles = HashMap::new();
        if let Ok(s) = &mut session {
            // Свежие списки устройств: собеседника и свой (копии — на свои устройства).
            s.fetch_device_list(&contact.account_id).await?;
            s.fetch_device_list(me.account_id()).await?;
            wait_for(s, ACCEPT_TIMEOUT, |s| {
                s.device_lists.contains(&contact.account_id)
                    && s.device_lists.contains(me.account_id())
            })
            .await?;
            // Предключи для устройств, с которыми ещё нет сессии.
            let mut need = vec![];
            for k in devices::devices_of_contact(db, &contact)?
                .into_iter()
                .chain(devices::other_own_devices(db, &me)?)
            {
                if !messaging::can_send_now(db, &k)? {
                    s.fetch_bundle(&k.account_id, k.device_id).await?;
                    need.push(messaging::device_key(&k));
                }
            }
            wait_for(s, ACCEPT_TIMEOUT, |s| {
                need.iter().all(|k| s.bundles.contains_key(k))
            })
            .await?;
            bundles = s.bundles.clone();
        }
        let recipients = devices::devices_of_contact(db, &contact)?;
        let own = devices::other_own_devices(db, &me)?;
        let sealed = messaging::seal_message(db, &me, &contact, &recipients, &own, &bundles, text);

        let (mut s, sealed) = match (session, sealed) {
            (Ok(s), Ok(sealed)) => {
                report_skipped(db, &sealed.skipped);
                (s, sealed)
            }
            (Ok(s), Err(e)) => {
                s.close().await;
                return Err(e);
            }
            (Err(e), Ok(sealed)) => {
                report_skipped(db, &sealed.skipped);
                return Err(e.context(SAVED));
            }
            (Err(e), Err(_)) => {
                return Err(e.context(
                    "релей недоступен, а сессии с собеседником ещё нет — сообщение не отправлено",
                ));
            }
        };
        for item in &sealed.items {
            s.send_outbox(item).await?;
        }
        let ids: Vec<String> = sealed.items.iter().map(|i| i.envelope_id.clone()).collect();
        wait_for(&mut s, ACCEPT_TIMEOUT, |s| all_settled(s, &ids)).await?;

        let to_peer: Vec<&OutboxItem> = sealed
            .items
            .iter()
            .filter(|i| i.to_account_id == contact.account_id)
            .collect();
        let accepted = to_peer
            .iter()
            .filter(|i| s.accepted.contains(&i.envelope_id))
            .count();
        if accepted == 0 {
            let reason = to_peer
                .iter()
                .find_map(|i| s.rejected.get(&i.envelope_id))
                .cloned();
            match reason {
                Some(r) if r.contains("rate limited") => bail!(
                    "релей просит подождать (слишком много сообщений подряд); \
                     сообщение осталось в исходящих и уйдёт при `messenger sync`"
                ),
                Some(r) => bail!("релей отклонил сообщение: {r}"),
                None => bail!("релей не подтвердил приём; сообщение осталось в исходящих"),
            }
        }
        if to_peer.len() > 1 {
            println!("✓  отправлено: {name} (устройств: {accepted})");
        } else {
            println!("✓  отправлено: {name}");
        }

        let id = sealed.message_id.clone();
        wait_for(&mut s, Duration::from_secs(wait), |s| {
            s.delivered.contains(&id)
        })
        .await?;
        if !s.delivered.contains(&id) {
            println!("   собеседник не в сети — релей доставит, как только он подключится");
        }
        s.close().await;
        Ok(())
    })
}

/// Сказать, каким устройствам сообщение не ушло.
fn report_skipped(db: &Db, skipped: &[(crypto_core::PeerKeys, String)]) {
    for (k, why) in skipped {
        eprintln!(
            "! устройство №{} {}: {why} — туда сообщение не ушло",
            k.device_id,
            display::peer_name(db, &k.account_id)
        );
    }
}

fn cmd_receive(db: &Db, envelope: Option<String>, file: Option<PathBuf>) -> Result<()> {
    let (_, me) = load_identity(db)?;
    let json = read_input(envelope, file, "envelope", "конверт")?;
    // Один конверт или массив (по одному на каждое устройство получателя).
    let wires: Vec<EnvelopeB64> = match serde_json::from_str::<serde_json::Value>(&json)
        .context("это не похоже на конверт сообщения")?
    {
        serde_json::Value::Array(items) => items
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<_, _>>(),
        one => serde_json::from_value(one).map(|e| vec![e]),
    }
    .context("это не похоже на конверт сообщения")?;

    let mut opened = 0;
    for wire in &wires {
        let env = Envelope::try_from(wire)?;
        if env.to != me.account_id() || env.to_device != me.device_id() {
            continue; // конверт для другого устройства
        }
        opened += 1;
        let sender =
            devices::sender_keys(db, &me, &env.from, env.from_device)?.with_context(|| {
                if db.get_contact(&env.from).ok().flatten().is_none() && env.from != me.account_id()
                {
                    format!(
                        "сообщение от неизвестного аккаунта {}; сначала добавьте его карточку",
                        env.from
                    )
                } else {
                    format!(
                        "сообщение с неизвестного устройства №{} — обновите список устройств \
                     (`messenger sync`) и попробуйте снова",
                        env.from_device
                    )
                }
            })?;
        match messaging::open_and_store(db, &me, &sender, wire, &envelope_id(&env))
            .context("не удалось открыть сообщение")?
        {
            Incoming::New {
                peer,
                direction: Direction::In,
                text,
            } => println!("{}: {}", display::peer_name(db, &peer), text),
            Incoming::New { peer, text, .. } => println!(
                "я → {} (с другого устройства): {}",
                display::peer_name(db, &peer),
                text
            ),
            Incoming::Duplicate => eprintln!("(это сообщение уже было получено раньше)"),
        }
    }
    if opened == 0 {
        bail!("среди конвертов нет адресованного этому устройству");
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

                        let pending = db.list_outbox(1000)?;
                        for p in &pending {
                            s.send_outbox(p).await?;
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
                        if s.removed {
                            bail!("это устройство отключено от аккаунта");
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
    let pending = db.list_outbox(limit)?;

    runtime()?.block_on(async {
        let mut s = Session::open(relay, db, &me).await?;
        for p in &pending {
            s.send_outbox(p).await?;
        }
        let ids: Vec<String> = pending.iter().map(|p| p.envelope_id.clone()).collect();

        // Входящие: релей выдаёт очередь сразу после входа и отмечает её конец.
        wait_for(&mut s, ACCEPT_TIMEOUT, |s| s.synced && all_settled(s, &ids)).await?;
        if ids.is_empty() {
            println!("Исходящие пусты — всё доставлено.");
        } else {
            wait_for(&mut s, Duration::from_secs(wait), |s| {
                ids.iter().all(|id| s.acked.contains(id) || s.rejected.contains_key(id))
            })
            .await?;
            let accepted = ids.iter().filter(|id| s.accepted.contains(*id)).count();
            let delivered = ids.iter().filter(|id| s.acked.contains(*id)).count();
            let rejected = ids.iter().filter(|id| s.rejected.contains_key(*id)).count();
            println!(
                "Исходящих конвертов: {} — принято релеем {accepted}, доставлено {delivered}, отклонено {rejected}.",
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
// Устройства
// ---------------------------------------------------------------------------

fn cmd_devices(db: &Db) -> Result<()> {
    let (_, me) = load_identity(db)?;
    let (list, _) = devices::own_list(db, &me)?;
    println!("Устройства аккаунта (версия списка {}):", list.version);
    for d in &list.devices {
        let mut marks = vec![];
        if d.device_id == PRIMARY_DEVICE {
            marks.push("основное");
        }
        if d.device_id == me.device_id() {
            marks.push("это устройство");
        }
        let marks = if marks.is_empty() {
            String::new()
        } else {
            format!("  ({})", marks.join(", "))
        };
        println!(
            "  №{:<2} {:<20} {}{marks}",
            d.device_id,
            d.name,
            devices::device_fingerprint(d)
        );
    }
    if list.devices.len() == 1 {
        println!();
        println!("Подключить ещё одно: `messenger --profile <новый> link` на новом устройстве.");
    }
    Ok(())
}

/// Шаг 1 (новое устройство): завести ключи и выдать код подключения.
fn cmd_link(path: &Path, name: &str, no_password: bool) -> Result<()> {
    let name = name.trim();
    if name.is_empty()
        || name.chars().count() > MAX_DEVICE_NAME
        || name.chars().any(char::is_control)
    {
        bail!("название устройства — от 1 до {MAX_DEVICE_NAME} символов");
    }
    let db = match storage::file_state(path)? {
        FileState::Missing => {
            let pw = if no_password {
                None
            } else {
                Some(password::ask_new(
                    password::ENV_PASSWORD,
                    "Придумайте пароль для базы этого устройства",
                )?)
            };
            Db::open(path, pw.as_deref().map(|p| p.as_str()))?
        }
        _ => open_db(path, false)?,
    };
    if db.get_local_identity()?.is_some() {
        bail!(
            "в этом профиле уже есть личность. Новое устройство подключают в новом, \
             пустом профиле: `messenger --profile <имя> link`"
        );
    }
    let link = match db.pending_link()? {
        Some(l) => PendingLink {
            name: name.to_string(),
            ..l
        },
        None => PendingLink {
            x_secret: crypto_core::random_bytes(),
            sign_secret: crypto_core::random_bytes(),
            name: name.to_string(),
        },
    };
    db.set_pending_link(&link)?;
    let keys = Identity::from_secrets("pending", link.x_secret, link.sign_secret);
    let code = LinkRequest {
        name: link.name.clone(),
        x25519_pub_b64: b64(keys.x_public_bytes()),
        ed25519_pub_b64: b64(keys.sign_public_bytes()),
    }
    .encode();

    println!("{code}");
    eprintln!();
    eprintln!("Отпечаток этого устройства: {}", keys.fingerprint());
    eprintln!();
    eprintln!("Дальше, на основном устройстве:");
    eprintln!("  messenger link-approve <код выше> -o link-response.json");
    eprintln!("Оно покажет отпечаток — он должен совпасть с этим.");
    eprintln!("Затем здесь: messenger link-finish --response-file link-response.json");
    Ok(())
}

/// Шаг 2 (основное устройство): внести новое устройство в список и выдать ответ.
fn cmd_link_approve(
    db: &Db,
    relay: &str,
    code: &str,
    out: Option<PathBuf>,
    yes: bool,
) -> Result<()> {
    let (row, me) = load_identity(db)?;
    if !me.has_account_key() {
        bail!("подключать устройства может только устройство с ключом аккаунта");
    }
    let req = LinkRequest::decode(code)?;
    let (x25519_pub, ed25519_pub) = req.keys()?;
    let (list, _) = devices::own_list(db, &me)?;
    check_can_add(&list, &x25519_pub, &ed25519_pub)?;

    let fingerprint = crypto_core::fingerprint(&x25519_pub, &ed25519_pub);
    println!("Новое устройство «{}»", req.name);
    println!("отпечаток: {fingerprint}");
    if !yes {
        if !std::io::stdin().is_terminal() {
            bail!("сверьте отпечаток и подтвердите флагом --yes");
        }
        eprint!("Он совпадает с тем, что показало новое устройство? [y/N] ");
        let mut answer = String::new();
        std::io::stdin().lock().read_line(&mut answer)?;
        if !matches!(
            answer.trim().to_lowercase().as_str(),
            "y" | "yes" | "д" | "да"
        ) {
            bail!("подключение отменено");
        }
    }

    // Список берём свежий с релея: его мог изменить другой держатель ключа.
    // Локально новый список сохранится только после ответа релея.
    let (list, wire) = change_own_list(db, relay, &me, |cur| {
        check_can_add(cur, &x25519_pub, &ed25519_pub)?;
        let (version, device_id) = devices::next_device_number(cur)?;
        let mut new = cur.clone();
        new.version = version;
        new.devices.push(DeviceInfo {
            device_id,
            x25519_pub,
            ed25519_pub,
            name: req.name.clone(),
        });
        Ok(new)
    })?;
    let device_id = list
        .devices
        .iter()
        .find(|d| d.x25519_pub == x25519_pub && d.ed25519_pub == ed25519_pub)
        .map(|d| d.device_id)
        .context("устройство не попало в опубликованный список")?;

    let mut contacts = vec![];
    for c in db.list_contacts()? {
        let Some(sign_public) = c.sign_public else {
            continue; // контакт из старой версии без ключа подписи — переносить нечего
        };
        contacts.push(LinkedContact {
            username: c.username.clone(),
            x25519_pub_b64: b64(c.public),
            ed25519_pub_b64: b64(sign_public),
            signed_prekey: c.signed_prekey.map(|k| {
                protocol::SignedPrekeyB64::from(&protocol::SignedPrekey {
                    id: k.id,
                    public: k.public,
                    sig: k.sig,
                })
            }),
            devices: devices::stored(db, &c.account_id)?.map(|(_, w)| w),
            account_id: c.account_id,
        });
    }
    let response = LinkResponse::sign(
        &me,
        &LinkPayload {
            account_id: me.account_id().into(),
            device_id,
            username: row.username,
            devices: wire,
            contacts,
        },
    )?;
    let json = serde_json::to_string_pretty(&response)?;
    match &out {
        Some(path) => std::fs::write(path, format!("{json}\n"))
            .with_context(|| format!("не удалось записать {}", path.display()))?,
        None => println!("{json}"),
    }

    eprintln!();
    eprintln!("Устройство «{}» добавлено как №{device_id}.", req.name);
    match out {
        Some(path) => eprintln!(
            "Перенесите {} на новое устройство и выполните там `messenger link-finish --response-file <файл>`.",
            path.display()
        ),
        None => eprintln!("Передайте этот ответ на новое устройство: `messenger link-finish`."),
    }
    Ok(())
}

fn check_can_add(list: &DeviceList, x25519_pub: &[u8; 32], ed25519_pub: &[u8; 32]) -> Result<()> {
    if let Some(d) = list
        .devices
        .iter()
        .find(|d| d.x25519_pub == *x25519_pub || d.ed25519_pub == *ed25519_pub)
    {
        bail!("это устройство уже подключено (№{})", d.device_id);
    }
    if list.devices.len() >= MAX_DEVICES {
        bail!("в аккаунте уже {MAX_DEVICES} устройств — отключите лишнее (`messenger unlink`)");
    }
    Ok(())
}

/// Сколько раз пересобирать список, если пока мы публиковали, его изменили на релее.
const LIST_ATTEMPTS: usize = 3;

/// Изменить свой список устройств через релей: взять свежий список с релея,
/// собрать новый (`change`), опубликовать и только после ответа релея сохранить
/// у себя. Без релея список не меняется.
fn change_own_list(
    db: &Db,
    relay: &str,
    me: &Identity,
    mut change: impl FnMut(&DeviceList) -> Result<DeviceList>,
) -> Result<(DeviceList, SignedDeviceListB64)> {
    let offline = "список устройств не изменён";
    runtime()?.block_on(async {
        let mut s = Session::open(relay, db, me)
            .await
            .with_context(|| format!("релей недоступен, {offline}"))?;
        wait_for(&mut s, ACCEPT_TIMEOUT, |s| s.synced || s.removed).await?;
        if s.removed {
            bail!("это устройство отключено от аккаунта");
        }
        if !s.synced {
            bail!("релей не ответил, {offline}");
        }
        let mut result = Err(anyhow::anyhow!("не удалось опубликовать список устройств"));
        for _ in 0..LIST_ATTEMPTS {
            // Свежий список с релея (при необходимости on_device_list его примет).
            s.device_lists.remove(me.account_id());
            s.fetch_device_list(me.account_id()).await?;
            wait_for(&mut s, ACCEPT_TIMEOUT, |s| {
                s.device_lists.contains(me.account_id())
            })
            .await?;
            if !s.device_lists.contains(me.account_id()) {
                result = Err(anyhow::anyhow!(
                    "релей не прислал список устройств, {offline}"
                ));
                break;
            }
            let (cur, _) = devices::own_list(db, me)?;
            let new = change(&cur)?;
            protocol::backup::check_list_update(Some(&cur), &new)
                .map_err(|e| anyhow::anyhow!("новый список устройств недопустим: {e}"))?;
            let wire = me.sign_device_list(&new)?;
            match s.publish_own(wire.clone()).await {
                Ok(()) => {
                    // Обычно список уже сохранён при ответе релея; accept это повторно не сделает.
                    devices::accept(db, me, &wire)?;
                    result = Ok((new, wire));
                    break;
                }
                Err(e) if format!("{e:#}").contains(protocol::ERR_STALE_DEVICE_LIST) => {
                    result = Err(anyhow::anyhow!(
                        "список устройств на релее изменился во время публикации, \
                         повторите команду"
                    ));
                }
                Err(e) => {
                    result = Err(e.context(format!("релей не принял список, {offline}")));
                    break;
                }
            }
        }
        s.close().await;
        result
    })
}

/// Шаг 3 (новое устройство): проверить ответ и стать устройством аккаунта.
fn cmd_link_finish(db: &Db, response: Option<String>, file: Option<PathBuf>) -> Result<()> {
    if db.get_local_identity()?.is_some() {
        bail!("в этом профиле уже есть личность");
    }
    let link = db
        .pending_link()?
        .context("сначала выполните `messenger link` в этом профиле")?;
    let json = read_input(response, file, "response", "ответ на подключение")?;
    let resp: LinkResponse =
        serde_json::from_str(&json).context("это не похоже на ответ на подключение")?;
    let (payload, list) = resp.verify()?;

    let keys = Identity::from_secrets("pending", link.x_secret, link.sign_secret);
    let mine = list.device(payload.device_id).filter(|d| {
        d.x25519_pub == keys.x_public_bytes() && d.ed25519_pub == keys.sign_public_bytes()
    });
    if mine.is_none() {
        bail!("в ответе нет этого устройства — он выдан на другой код подключения");
    }
    let me = Identity::from_secrets(&payload.account_id, link.x_secret, link.sign_secret)
        .with_device(payload.device_id);

    db.immediate(|| {
        db.upsert_identity(&IdentityRow {
            account_id: me.account_id().into(),
            device_id: me.device_id(),
            username: payload.username.clone(),
            secret: me.x_secret_bytes(),
            public: me.x_public_bytes(),
            sign_secret: Some(me.sign_secret_bytes()),
            sign_public: Some(me.sign_public_bytes()),
            account_sign_secret: None,
        })?;
        // Список уже проверен: подпись ключом аккаунта и сам ID.
        db.save_device_list(
            me.account_id(),
            list.version,
            &serde_json::to_string(&payload.devices)?,
        )?;
        for c in &payload.contacts {
            let sign_public = decode_fixed::<32>(&c.ed25519_pub_b64, "ed25519_pub_b64")?;
            db.upsert_contact(&ContactRow {
                account_id: c.account_id.clone(),
                username: c.username.clone(),
                public: decode_fixed::<32>(&c.x25519_pub_b64, "x25519_pub_b64")?,
                sign_public: Some(sign_public),
                signed_prekey: c
                    .signed_prekey
                    .as_ref()
                    .map(|k| messaging::verified_card_prekey(&sign_public, k))
                    .transpose()?,
            })?;
        }
        db.clear_pending_link()
    })?;
    for c in &payload.contacts {
        if let Some(wire) = &c.devices {
            if let Err(e) = devices::accept(db, &me, wire) {
                eprintln!(
                    "! список устройств контакта {} пропущен: {e:#}",
                    c.account_id
                );
            }
        }
    }
    messaging::ensure_signed_prekey(db, &me)?;

    println!(
        "Готово: это устройство №{} аккаунта {}.",
        me.device_id(),
        me.account_id()
    );
    println!(
        "отпечаток аккаунта: {}",
        devices::account_fingerprint(&list)
    );
    println!("Сверьте его с `messenger whoami` на основном устройстве.");
    println!("Перенесено контактов: {}.", payload.contacts.len());
    println!();
    println!("Дальше: `messenger listen` — устройство выйдет в сеть и опубликует свои предключи.");
    Ok(())
}

/// Отключить устройство: убрать из списка, релей закроет его соединения и
/// перестанет пускать, собеседники перестанут ему писать.
fn cmd_unlink(db: &Db, relay: &str, device_id: u32, yes: bool) -> Result<()> {
    let (_, me) = load_identity(db)?;
    if !me.has_account_key() {
        bail!("отключать устройства может только устройство с ключом аккаунта");
    }
    if device_id == me.device_id() {
        bail!("нельзя отключить это устройство");
    }
    if device_id == PRIMARY_DEVICE {
        bail!("основное устройство отключить нельзя: его ключ — это ключ аккаунта");
    }
    let (list, _) = devices::own_list(db, &me)?;
    let Some(target) = list.device(device_id) else {
        bail!("устройства №{device_id} нет в аккаунте — см. `messenger devices`");
    };
    let name = target.name.clone();
    if !yes {
        if !std::io::stdin().is_terminal() {
            bail!("подтвердите отключение флагом --yes");
        }
        println!("Устройство №{device_id} «{name}»");
        println!(
            "Если на этом устройстве восстановлен ключ аккаунта, отключение не отнимает ключ: \
             оно сможет снова добавить себя."
        );
        eprint!("Отключить? [y/N] ");
        let mut answer = String::new();
        std::io::stdin().lock().read_line(&mut answer)?;
        if !matches!(
            answer.trim().to_lowercase().as_str(),
            "y" | "yes" | "д" | "да"
        ) {
            bail!("отключение отменено");
        }
    }
    change_own_list(db, relay, &me, |cur| {
        let mut new = cur.clone();
        let Some(pos) = new.devices.iter().position(|d| d.device_id == device_id) else {
            bail!("устройства №{device_id} уже нет в аккаунте — см. `messenger devices`");
        };
        new.devices.remove(pos);
        new.version = new
            .version
            .checked_add(1)
            .context("слишком много изменений списка")?;
        Ok(new)
    })?;
    println!("Устройство №{device_id} «{name}» отключено.");
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
