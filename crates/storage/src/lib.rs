//! Локальная база клиента (SQLite).
//!
//! Что хранится:
//! * `identities`   — своя личность (одна на базу: это ключи **этого устройства**)
//!   вместе с **секретными ключами**;
//! * `contacts`     — проверенные карточки собеседников;
//! * `device_lists` — подписанные списки устройств: свой и собеседников;
//! * `messages`     — история переписки (одно сообщение — одна строка, сколько бы
//!   устройств его ни получало);
//! * `outbox`       — исходящие конверты: по одному на каждое устройство получателя;
//! * `sessions`, `signed_prekeys`, `one_time_prekeys`, `used_prekey_eks`,
//!   `seen_envelopes` — состояние Double Ratchet и предключи X3DH (тоже
//!   **секретные**). Сессии свои у каждого устройства собеседника;
//! * `pending_link` — ключи устройства, которое ждёт подключения к аккаунту.
//!
//! Операции, которые читают и меняют состояние сессии, выполняются внутри
//! [`Db::immediate`] — так два процесса (`listen` и `send`) не затрут друг другу
//! состояние храповика.
//!
//! Схема версионируется через `PRAGMA user_version`; [`Db::open`] сам доводит
//! любую старую базу до текущей версии.

use anyhow::{Context, Result, bail};
use directories::ProjectDirs;
use rusqlite::{Connection, OptionalExtension, Row, params};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod encryption;
pub use encryption::{FileState, PasswordRequired, WrongPassword, file_state, reencrypt};

/// Текущая версия схемы.
pub const SCHEMA_VERSION: i64 = 6;

pub struct Db {
    conn: Connection,
    /// Общая блокировка файла базы, пока она открыта (см. [`encryption::reencrypt`]).
    _lock: Option<fs::File>,
}

#[derive(Clone)]
pub struct IdentityRow {
    pub account_id: String,
    /// Номер этого устройства в аккаунте (1 — основное).
    pub device_id: u32,
    pub username: Option<String>,
    /// X25519 secret.
    pub secret: [u8; 32],
    /// X25519 public.
    pub public: [u8; 32],
    /// Ed25519 signing secret. `None` — личность из старой версии без ключа подписи.
    pub sign_secret: Option<[u8; 32]>,
    /// Ed25519 verifying key.
    pub sign_public: Option<[u8; 32]>,
    /// Секрет ключа аккаунта на устройстве не №1 (восстановление из резервной
    /// копии). У №1 — `None`: там ключ аккаунта это `sign_secret`.
    pub account_sign_secret: Option<[u8; 32]>,
}

impl std::fmt::Debug for IdentityRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Секреты в Debug не попадают.
        f.debug_struct("IdentityRow")
            .field("account_id", &self.account_id)
            .field("device_id", &self.device_id)
            .field("username", &self.username)
            .field("has_account_key", &self.account_sign_secret.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactRow {
    pub account_id: String,
    pub username: Option<String>,
    /// X25519 public.
    pub public: [u8; 32],
    /// Ed25519 public. `None` — контакт добавлен старой версией, его сообщения
    /// проверить нельзя, нужно заново импортировать карточку.
    pub sign_public: Option<[u8; 32]>,
    /// Подписанный предключ из карточки — для переписки без релея.
    pub signed_prekey: Option<StoredPrekey>,
}

/// Публичный предключ с подписью (как его прислал собеседник).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredPrekey {
    pub id: u32,
    pub public: [u8; 32],
    pub sig: [u8; 64],
}

/// Наш подписанный предключ вместе с секретом.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnSignedPrekey {
    pub id: u32,
    pub secret: [u8; 32],
    pub public: [u8; 32],
    pub sig: [u8; 64],
    pub created_at: i64,
}

/// Наш одноразовый предключ вместе с секретом.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnOneTimePrekey {
    pub id: u32,
    pub secret: [u8; 32],
    pub public: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
}

impl Direction {
    fn to_db(self) -> i64 {
        match self {
            Direction::In => 0,
            Direction::Out => 1,
        }
    }

    fn from_db(v: i64) -> rusqlite::Result<Self> {
        match v {
            0 => Ok(Direction::In),
            1 => Ok(Direction::Out),
            other => Err(rusqlite::Error::IntegralValueOutOfRange(2, other)),
        }
    }
}

/// Статус исходящего сообщения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryStatus {
    /// Ещё не подтверждено получателем (✓).
    Pending,
    /// Получатель подтвердил, что сохранил сообщение (✓✓).
    Delivered,
    /// Отправить невозможно (например, сохранено старой версией в устаревшем формате).
    Failed,
}

impl DeliveryStatus {
    fn from_db(v: i64) -> Self {
        match v {
            0 => Self::Pending,
            2 => Self::Failed,
            _ => Self::Delivered,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MessageRow {
    pub id: i64,
    pub msg_id: Option<String>,
    pub direction: Direction,
    pub peer_account_id: String,
    pub peer_username: Option<String>,
    pub created_at: i64,
    pub plaintext: String,
    pub envelope_json: String,
    pub is_read: bool,
    pub status: DeliveryStatus,
    pub delivered_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct ThreadRow {
    pub peer_account_id: String,
    pub peer_username: Option<String>,
    pub last_created_at: i64,
    pub last_direction: Direction,
    pub last_plaintext: String,
    pub last_status: DeliveryStatus,
    pub unread_count: i64,
}

/// Исходящий конверт для одного устройства, ещё не подтверждённый им.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxItem {
    /// Какому сообщению из `messages` принадлежит конверт.
    pub message_id: String,
    /// Собеседник этого сообщения (для копий на свои устройства — тоже он).
    pub peer_account_id: String,
    /// Куда идёт конверт: аккаунт и устройство.
    pub to_account_id: String,
    pub to_device_id: u32,
    /// ID конверта (то, что подтверждает релей и получатель).
    pub envelope_id: String,
    pub envelope_json: String,
}

/// Чем закончилось подтверждение конверта.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acked {
    pub message_id: String,
    pub peer_account_id: String,
    /// Сообщение только что стало «доставлено» (первое подтверждение от собеседника).
    pub newly_delivered: bool,
}

/// Ключи устройства, которое ещё только подключается к аккаунту.
#[derive(Clone)]
pub struct PendingLink {
    pub x_secret: [u8; 32],
    pub sign_secret: [u8; 32],
    pub name: String,
}

impl std::fmt::Debug for PendingLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingLink")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Устройство, которое восстанавливает ключ аккаунта из резервной копии: ключи уже
/// выбраны и записаны, но список устройств ещё не опубликован.
#[derive(Clone)]
pub struct PendingRestore {
    pub account_id: String,
    /// Ключ аккаунта из копии (seed Ed25519).
    pub account_secret: [u8; 32],
    /// Ключи нового устройства.
    pub x_secret: [u8; 32],
    pub sign_secret: [u8; 32],
    pub name: String,
}

impl std::fmt::Debug for PendingRestore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingRestore")
            .field("account_id", &self.account_id)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Новое сообщение для [`Db::insert_message`].
#[derive(Debug, Clone)]
pub struct NewMessage<'a> {
    pub direction: Direction,
    pub peer_account_id: &'a str,
    pub peer_username: Option<&'a str>,
    pub plaintext: &'a str,
    pub envelope_json: &'a str,
    pub msg_id: &'a str,
}

impl Db {
    /// Открыть (или создать) базу по пути и мигрировать до актуальной схемы.
    ///
    /// `password`: для зашифрованной базы — обязателен; для новой — если задан,
    /// база создаётся зашифрованной; для существующей незашифрованной — ошибка
    /// (зашифровать её можно через [`encryption::reencrypt`]).
    pub fn open(path: impl AsRef<Path>, password: Option<&str>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)
                .with_context(|| format!("create dir {}", parent.display()))?;
        }
        let lock = encryption::shared_lock(path)?;
        let state = encryption::file_state(path)?;
        let conn =
            Connection::open(path).with_context(|| format!("open sqlite {}", path.display()))?;
        match (state, password) {
            (FileState::Encrypted, None) => return Err(PasswordRequired.into()),
            (FileState::Encrypted, Some(pw)) => encryption::unlock(&conn, path, pw, false)?,
            (FileState::Missing, Some(pw)) => encryption::unlock(&conn, path, pw, true)?,
            (FileState::Plain, Some(_)) => {
                bail!("база не зашифрована паролем — сначала зашифруйте её")
            }
            (FileState::Missing | FileState::Plain, None) => {}
        }
        restrict_file_permissions(path)?;
        let mut db = Self::init(conn)?;
        db._lock = Some(lock);
        Ok(db)
    }

    /// База в памяти — для тестов.
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    /// Путь к базе профиля в стандартном каталоге данных ОС
    /// (например, `~/.local/share/<app_name>/messenger.sqlite` на Linux).
    /// Каталог создаётся и закрывается от других пользователей.
    pub fn default_path(app_name: &str) -> Result<PathBuf> {
        let proj = ProjectDirs::from("ru", "messenger", app_name)
            .context("cannot determine the data directory for this OS")?;
        let dir = proj.data_dir();
        fs::create_dir_all(dir).with_context(|| format!("create dir {}", dir.display()))?;
        restrict_permissions(dir)?;
        Ok(dir.join("messenger.sqlite"))
    }

    fn init(mut conn: Connection) -> Result<Self> {
        // Другой процесс с той же базой (например, `listen`) может держать запись —
        // подождём, а не упадём. Ставим до всего остального, включая смену журнала.
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;",
        )?;
        migrate(&mut conn)?;
        Ok(Self { conn, _lock: None })
    }

    /// Выполнить `f` в эксклюзивной транзакции (`BEGIN IMMEDIATE`): всё, что
    /// `f` делает с базой, применяется целиком или не применяется вовсе, а другие
    /// процессы ждут. Вложенные вызовы не поддерживаются.
    pub fn immediate<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        match f() {
            Ok(v) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(v)
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    // ----- личность -------------------------------------------------------

    /// Своя личность. В текущей версии — одна на базу.
    pub fn get_local_identity(&self) -> Result<Option<IdentityRow>> {
        self.conn
            .query_row(
                "SELECT account_id, username, secret, public, sign_secret, sign_public, device_id,
                        account_sign_secret
                 FROM identities ORDER BY created_at ASC, rowid ASC LIMIT 1",
                [],
                |r| {
                    Ok(IdentityRow {
                        account_id: r.get(0)?,
                        username: r.get(1)?,
                        secret: blob32(r, 2)?,
                        public: blob32(r, 3)?,
                        sign_secret: blob32_opt(r, 4)?,
                        sign_public: blob32_opt(r, 5)?,
                        device_id: r.get(6)?,
                        account_sign_secret: blob32_opt(r, 7)?,
                    })
                },
            )
            .optional()
            .context("load local identity")
    }

    /// Создать или обновить личность по `account_id`.
    pub fn upsert_identity(&self, row: &IdentityRow) -> Result<()> {
        self.conn.execute(
            "INSERT INTO identities (account_id, username, secret, public, sign_secret, sign_public, created_at, device_id, account_sign_secret)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(account_id) DO UPDATE SET
                 username    = excluded.username,
                 secret      = excluded.secret,
                 public      = excluded.public,
                 sign_secret = excluded.sign_secret,
                 sign_public = excluded.sign_public,
                 device_id   = excluded.device_id,
                 account_sign_secret = excluded.account_sign_secret",
            params![
                row.account_id,
                row.username,
                &row.secret[..],
                &row.public[..],
                row.sign_secret.as_ref().map(|k| &k[..]),
                row.sign_public.as_ref().map(|k| &k[..]),
                unix_now(),
                row.device_id,
                row.account_sign_secret.as_ref().map(|k| &k[..]),
            ],
        )?;
        Ok(())
    }

    pub fn set_username(&self, account_id: &str, username: Option<&str>) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE identities SET username = ?2 WHERE account_id = ?1",
            params![account_id, username],
        )?;
        if n == 0 {
            bail!("identity {account_id} not found");
        }
        Ok(())
    }

    // ----- контакты -------------------------------------------------------

    /// Добавить или обновить контакт.
    ///
    /// Отказывает, если такой `@username` уже занят *другим* контактом:
    /// username в карточке никто не проверяет, и без этой проверки чужая
    /// карточка с `@alice` могла бы тихо перехватить отправку «для Алисы».
    pub fn upsert_contact(&self, c: &ContactRow) -> Result<()> {
        if let Some(username) = &c.username {
            let clash: Option<String> = self
                .conn
                .query_row(
                    "SELECT account_id FROM contacts
                     WHERE LOWER(username) = LOWER(?1) AND account_id <> ?2",
                    params![username, c.account_id],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(other) = clash {
                bail!(
                    "username {username} already belongs to another contact ({other}); \
                     remove that contact first if this is intentional"
                );
            }
        }

        let spk = c.signed_prekey.as_ref();
        self.conn.execute(
            "INSERT INTO contacts (account_id, username, public, sign_public, spk_id, spk_pub, spk_sig, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(account_id) DO UPDATE SET
                 username    = excluded.username,
                 public      = excluded.public,
                 sign_public = excluded.sign_public,
                 spk_id      = COALESCE(excluded.spk_id, contacts.spk_id),
                 spk_pub     = COALESCE(excluded.spk_pub, contacts.spk_pub),
                 spk_sig     = COALESCE(excluded.spk_sig, contacts.spk_sig)",
            params![
                c.account_id,
                c.username,
                &c.public[..],
                c.sign_public.as_ref().map(|k| &k[..]),
                spk.map(|k| k.id),
                spk.map(|k| &k.public[..]),
                spk.map(|k| &k.sig[..]),
                unix_now()
            ],
        )?;
        Ok(())
    }

    /// Удалить контакт вместе с его списком устройств. Возвращает `false`,
    /// если такого не было.
    pub fn delete_contact(&self, account_id: &str) -> Result<bool> {
        self.conn.execute(
            "DELETE FROM device_lists WHERE account_id = ?1",
            params![account_id],
        )?;
        Ok(self.conn.execute(
            "DELETE FROM contacts WHERE account_id = ?1",
            params![account_id],
        )? > 0)
    }

    // ----- списки устройств ----------------------------------------------

    /// Сохранённый подписанный список устройств аккаунта: `(версия, JSON)`.
    pub fn device_list(&self, account_id: &str) -> Result<Option<(u64, String)>> {
        Ok(self
            .conn
            .query_row(
                "SELECT version, list_json FROM device_lists WHERE account_id = ?1",
                params![account_id],
                |r| Ok((r.get::<_, i64>(0)? as u64, r.get(1)?)),
            )
            .optional()?)
    }

    /// Сохранить список устройств, если он новее сохранённого. Подпись проверяет
    /// вызывающий. Возвращает `true`, если список заменён: откатить список на
    /// старую версию (и вернуть удалённое устройство) нельзя.
    pub fn save_device_list(
        &self,
        account_id: &str,
        version: u64,
        list_json: &str,
    ) -> Result<bool> {
        let version = i64::try_from(version).context("device list version is too large")?;
        Ok(self.conn.execute(
            "INSERT INTO device_lists (account_id, version, list_json, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(account_id) DO UPDATE SET
                 version    = excluded.version,
                 list_json  = excluded.list_json,
                 updated_at = excluded.updated_at
             WHERE excluded.version > device_lists.version",
            params![account_id, version, list_json, unix_now()],
        )? > 0)
    }

    // ----- подключение нового устройства ----------------------------------

    pub fn pending_link(&self) -> Result<Option<PendingLink>> {
        Ok(self
            .conn
            .query_row(
                "SELECT x_secret, sign_secret, name FROM pending_link WHERE id = 1",
                [],
                |r| {
                    Ok(PendingLink {
                        x_secret: blob32(r, 0)?,
                        sign_secret: blob32(r, 1)?,
                        name: r.get(2)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn set_pending_link(&self, link: &PendingLink) -> Result<()> {
        self.conn.execute(
            "INSERT INTO pending_link (id, x_secret, sign_secret, name, created_at)
             VALUES (1, ?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET
                 x_secret = excluded.x_secret, sign_secret = excluded.sign_secret,
                 name = excluded.name, created_at = excluded.created_at",
            params![
                &link.x_secret[..],
                &link.sign_secret[..],
                link.name,
                unix_now()
            ],
        )?;
        Ok(())
    }

    pub fn clear_pending_link(&self) -> Result<()> {
        self.conn.execute("DELETE FROM pending_link", [])?;
        Ok(())
    }

    // ----- восстановление ключа аккаунта ----------------------------------

    pub fn pending_restore(&self) -> Result<Option<PendingRestore>> {
        Ok(self
            .conn
            .query_row(
                "SELECT account_id, account_secret, x_secret, sign_secret, name
                 FROM pending_restore WHERE id = 1",
                [],
                |r| {
                    Ok(PendingRestore {
                        account_id: r.get(0)?,
                        account_secret: blob32(r, 1)?,
                        x_secret: blob32(r, 2)?,
                        sign_secret: blob32(r, 3)?,
                        name: r.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn set_pending_restore(&self, p: &PendingRestore) -> Result<()> {
        self.conn.execute(
            "INSERT INTO pending_restore
                 (id, account_id, account_secret, x_secret, sign_secret, name, created_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET
                 account_id = excluded.account_id,
                 account_secret = excluded.account_secret,
                 x_secret = excluded.x_secret, sign_secret = excluded.sign_secret,
                 name = excluded.name, created_at = excluded.created_at",
            params![
                p.account_id,
                &p.account_secret[..],
                &p.x_secret[..],
                &p.sign_secret[..],
                p.name,
                unix_now()
            ],
        )?;
        Ok(())
    }

    pub fn clear_pending_restore(&self) -> Result<()> {
        self.conn.execute("DELETE FROM pending_restore", [])?;
        Ok(())
    }

    pub fn list_contacts(&self) -> Result<Vec<ContactRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT account_id, username, public, sign_public, spk_id, spk_pub, spk_sig FROM contacts
             ORDER BY COALESCE(username, account_id) ASC",
        )?;
        let rows = stmt.query_map([], contact_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Контакт строго по `account_id`.
    pub fn get_contact(&self, account_id: &str) -> Result<Option<ContactRow>> {
        Ok(self
            .conn
            .query_row(
                "SELECT account_id, username, public, sign_public, spk_id, spk_pub, spk_sig FROM contacts WHERE account_id = ?1",
                params![account_id],
                contact_from_row,
            )
            .optional()?)
    }

    /// Найти контакт по `account_id` или по `@username` (`@` можно не писать,
    /// регистр не важен).
    pub fn find_contact(&self, key: &str) -> Result<Option<ContactRow>> {
        let key = key.trim();
        let by_id = self.get_contact(key)?;
        if by_id.is_some() {
            return Ok(by_id);
        }

        let uname = format!("@{}", key.trim_start_matches('@'));
        let mut stmt = self.conn.prepare(
            "SELECT account_id, username, public, sign_public, spk_id, spk_pub, spk_sig FROM contacts
             WHERE LOWER(username) = LOWER(?1)",
        )?;
        let mut found: Vec<ContactRow> = stmt
            .query_map(params![uname], contact_from_row)?
            .collect::<rusqlite::Result<_>>()?;
        match found.len() {
            0 => Ok(None),
            1 => Ok(found.pop()),
            _ => bail!("username {uname} is ambiguous; use the account_id instead"),
        }
    }

    // ----- сообщения ------------------------------------------------------

    /// Сохранить сообщение. Возвращает `None`, если сообщение с таким
    /// `(peer, direction, msg_id)` уже есть — повторная доставка безопасна.
    pub fn insert_message(&self, m: &NewMessage<'_>) -> Result<Option<i64>> {
        let is_read = matches!(m.direction, Direction::Out);
        let n = self.conn.execute(
            "INSERT OR IGNORE INTO messages
                 (direction, peer_account_id, peer_username, created_at, plaintext,
                  envelope_json, is_read, msg_id, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)",
            params![
                m.direction.to_db(),
                m.peer_account_id,
                m.peer_username,
                unix_now(),
                m.plaintext,
                m.envelope_json,
                is_read,
                m.msg_id,
            ],
        )?;
        Ok((n > 0).then(|| self.conn.last_insert_rowid()))
    }

    /// Последние `limit` сообщений с собеседником, от старых к новым.
    pub fn list_messages_for_peer(
        &self,
        peer_account_id: &str,
        limit: usize,
    ) -> Result<Vec<MessageRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT * FROM (
                 SELECT m.id, m.msg_id, m.direction, m.peer_account_id,
                        COALESCE(c.username, m.peer_username),
                        m.created_at, m.plaintext, m.envelope_json,
                        m.is_read, m.status, m.delivered_at
                 FROM messages m
                 LEFT JOIN contacts c ON c.account_id = m.peer_account_id
                 WHERE m.peer_account_id = ?1
                 ORDER BY m.created_at DESC, m.id DESC
                 LIMIT ?2
             ) ORDER BY created_at ASC, id ASC",
        )?;
        let rows = stmt.query_map(params![peer_account_id, limit as i64], |r| {
            Ok(MessageRow {
                id: r.get(0)?,
                msg_id: r.get(1)?,
                direction: Direction::from_db(r.get(2)?)?,
                peer_account_id: r.get(3)?,
                peer_username: r.get(4)?,
                created_at: r.get(5)?,
                plaintext: r.get(6)?,
                envelope_json: r.get(7)?,
                is_read: r.get::<_, i64>(8)? != 0,
                status: DeliveryStatus::from_db(r.get(9)?),
                delivered_at: r.get(10)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Список диалогов: по одному на собеседника, с последним сообщением.
    pub fn list_threads(&self, limit: usize) -> Result<Vec<ThreadRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT t.peer_account_id,
                    COALESCE(c.username, t.peer_username),
                    t.created_at, t.direction, t.plaintext, t.status,
                    (SELECT COUNT(1) FROM messages m2
                     WHERE m2.peer_account_id = t.peer_account_id
                       AND m2.direction = 0 AND m2.is_read = 0)
             FROM (
                 SELECT peer_account_id, peer_username, created_at, direction, plaintext, status,
                        ROW_NUMBER() OVER (PARTITION BY peer_account_id
                                           ORDER BY created_at DESC, id DESC) AS rn
                 FROM messages
             ) t
             LEFT JOIN contacts c ON c.account_id = t.peer_account_id
             WHERE t.rn = 1
             ORDER BY t.created_at DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |r| {
            Ok(ThreadRow {
                peer_account_id: r.get(0)?,
                peer_username: r.get(1)?,
                last_created_at: r.get(2)?,
                last_direction: Direction::from_db(r.get(3)?)?,
                last_plaintext: r.get(4)?,
                last_status: DeliveryStatus::from_db(r.get(5)?),
                unread_count: r.get(6)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn mark_thread_read(&self, peer_account_id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE messages SET is_read = 1
             WHERE peer_account_id = ?1 AND direction = 0 AND is_read = 0",
            params![peer_account_id],
        )?;
        Ok(())
    }

    /// Отметить исходящее сообщение доставленным. Возвращает `true`, если
    /// статус действительно изменился.
    pub fn mark_out_delivered(&self, peer_account_id: &str, msg_id: &str) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE messages
             SET status = 1, delivered_at = COALESCE(delivered_at, ?3)
             WHERE direction = 1 AND peer_account_id = ?1 AND msg_id = ?2 AND status = 0",
            params![peer_account_id, msg_id, unix_now()],
        )?;
        Ok(n > 0)
    }

    /// Текст исходящего сообщения по его `msg_id`.
    pub fn outgoing_text(&self, peer_account_id: &str, msg_id: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT plaintext FROM messages
                 WHERE direction = 1 AND peer_account_id = ?1 AND msg_id = ?2",
                params![peer_account_id, msg_id],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Пометить исходящее сообщение как неотправляемое.
    pub fn mark_out_failed(&self, peer_account_id: &str, msg_id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE messages SET status = 2
             WHERE direction = 1 AND peer_account_id = ?1 AND msg_id = ?2 AND status = 0",
            params![peer_account_id, msg_id],
        )?;
        Ok(())
    }

    /// Есть ли уже входящее сообщение с таким `msg_id` от этого собеседника.
    pub fn has_incoming(&self, peer_account_id: &str, msg_id: &str) -> Result<bool> {
        Ok(self
            .conn
            .prepare_cached(
                "SELECT 1 FROM messages WHERE direction = 0 AND peer_account_id = ?1 AND msg_id = ?2",
            )?
            .exists(params![peer_account_id, msg_id])?)
    }

    // ----- исходящие конверты ----------------------------------------------

    /// Положить конверт в исходящие (повтор того же конверта игнорируется).
    pub fn insert_outbox(&self, item: &OutboxItem) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO outbox
                 (message_id, peer_account_id, to_account_id, to_device_id, envelope_id,
                  envelope_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                item.message_id,
                item.peer_account_id,
                item.to_account_id,
                item.to_device_id,
                item.envelope_id,
                item.envelope_json,
                unix_now()
            ],
        )?;
        Ok(())
    }

    /// Конверты, которые ещё никто не подтвердил, от старых к новым.
    pub fn list_outbox(&self, limit: usize) -> Result<Vec<OutboxItem>> {
        let mut stmt = self.conn.prepare(
            "SELECT message_id, peer_account_id, to_account_id, to_device_id, envelope_id, envelope_json
             FROM outbox ORDER BY created_at ASC, id ASC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |r| {
            Ok(OutboxItem {
                message_id: r.get(0)?,
                peer_account_id: r.get(1)?,
                to_account_id: r.get(2)?,
                to_device_id: r.get(3)?,
                envelope_id: r.get(4)?,
                envelope_json: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Устройство подтвердило конверт: убрать его из исходящих. Если это
    /// устройство собеседника, сообщение становится доставленным.
    /// `None` — такого конверта в исходящих нет (повторное подтверждение).
    pub fn ack_outbox(
        &self,
        to_account_id: &str,
        to_device_id: u32,
        envelope_id: &str,
    ) -> Result<Option<Acked>> {
        let row: Option<(String, String)> = self
            .conn
            .query_row(
                "SELECT message_id, peer_account_id FROM outbox
                 WHERE to_account_id = ?1 AND to_device_id = ?2 AND envelope_id = ?3",
                params![to_account_id, to_device_id, envelope_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((message_id, peer_account_id)) = row else {
            return Ok(None);
        };
        self.conn.execute(
            "DELETE FROM outbox WHERE to_account_id = ?1 AND to_device_id = ?2 AND envelope_id = ?3",
            params![to_account_id, to_device_id, envelope_id],
        )?;
        let newly_delivered = to_account_id == peer_account_id
            && self.mark_out_delivered(&peer_account_id, &message_id)?;
        Ok(Some(Acked {
            message_id,
            peer_account_id,
            newly_delivered,
        }))
    }

    /// Убрать конверт из исходящих без отметки о доставке (его не доставить).
    pub fn delete_outbox(
        &self,
        to_account_id: &str,
        to_device_id: u32,
        envelope_id: &str,
    ) -> Result<()> {
        self.conn.execute(
            "DELETE FROM outbox WHERE to_account_id = ?1 AND to_device_id = ?2 AND envelope_id = ?3",
            params![to_account_id, to_device_id, envelope_id],
        )?;
        Ok(())
    }

    /// Убрать из исходящих конверты для устройств аккаунта, которых больше
    /// нет в его списке. Возвращает, сколько убрано.
    pub fn drop_outbox_except(&self, to_account_id: &str, keep_devices: &[u32]) -> Result<usize> {
        let mut dropped = 0;
        for item in self.list_outbox(usize::MAX >> 1)? {
            if item.to_account_id == to_account_id && !keep_devices.contains(&item.to_device_id) {
                dropped += self.conn.execute(
                    "DELETE FROM outbox WHERE to_account_id = ?1 AND to_device_id = ?2 AND envelope_id = ?3",
                    params![item.to_account_id, item.to_device_id, item.envelope_id],
                )?;
            }
        }
        Ok(dropped)
    }

    /// Видели ли мы уже конверт с этим ID от этого устройства. Повторную
    /// доставку надо отсекать до расшифровки: ключ сообщения уже стёрт.
    pub fn is_envelope_seen(
        &self,
        peer_account_id: &str,
        peer_device_id: u32,
        envelope_id: &str,
    ) -> Result<bool> {
        Ok(self
            .conn
            .prepare_cached(
                "SELECT 1 FROM seen_envelopes
                 WHERE peer_account_id = ?1 AND peer_device_id = ?2 AND envelope_id = ?3",
            )?
            .exists(params![peer_account_id, peer_device_id, envelope_id])?)
    }

    pub fn mark_envelope_seen(
        &self,
        peer_account_id: &str,
        peer_device_id: u32,
        envelope_id: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO seen_envelopes (peer_account_id, peer_device_id, envelope_id, seen_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![peer_account_id, peer_device_id, envelope_id, unix_now()],
        )?;
        Ok(())
    }

    // ----- сессии ---------------------------------------------------------

    /// Состояние сессий с устройством собеседника (непрозрачный JSON из `crypto_core`).
    pub fn load_sessions(
        &self,
        peer_account_id: &str,
        peer_device_id: u32,
    ) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT state FROM sessions WHERE peer_account_id = ?1 AND peer_device_id = ?2",
                params![peer_account_id, peer_device_id],
                |r| r.get(0),
            )
            .optional()?)
    }

    pub fn save_sessions(
        &self,
        peer_account_id: &str,
        peer_device_id: u32,
        state: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sessions (peer_account_id, peer_device_id, state, updated_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(peer_account_id, peer_device_id)
             DO UPDATE SET state = excluded.state, updated_at = excluded.updated_at",
            params![peer_account_id, peer_device_id, state, unix_now()],
        )?;
        Ok(())
    }

    /// Забыть сессии со всеми устройствами собеседника (например, при удалении контакта).
    pub fn delete_sessions(&self, peer_account_id: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM sessions WHERE peer_account_id = ?1",
            params![peer_account_id],
        )?;
        Ok(())
    }

    /// Забыть сессии с одним устройством (его отключили от аккаунта).
    pub fn delete_device_sessions(&self, peer_account_id: &str, peer_device_id: u32) -> Result<()> {
        self.conn.execute(
            "DELETE FROM sessions WHERE peer_account_id = ?1 AND peer_device_id = ?2",
            params![peer_account_id, peer_device_id],
        )?;
        Ok(())
    }

    /// Встречался ли уже этот одноразовый ключ X3DH от устройства собеседника.
    pub fn is_ek_used(
        &self,
        peer_account_id: &str,
        peer_device_id: u32,
        ek: &[u8; 32],
    ) -> Result<bool> {
        Ok(self
            .conn
            .prepare_cached(
                "SELECT 1 FROM used_prekey_eks
                 WHERE peer_account_id = ?1 AND peer_device_id = ?2 AND ek = ?3",
            )?
            .exists(params![peer_account_id, peer_device_id, &ek[..]])?)
    }

    pub fn mark_ek_used(
        &self,
        peer_account_id: &str,
        peer_device_id: u32,
        ek: &[u8; 32],
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO used_prekey_eks (peer_account_id, peer_device_id, ek, used_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![peer_account_id, peer_device_id, &ek[..], unix_now()],
        )?;
        Ok(())
    }

    // ----- наши предключи -------------------------------------------------

    /// Следующий свободный ID для подписанного предключа.
    pub fn next_signed_prekey_id(&self) -> Result<u32> {
        let max: Option<u32> =
            self.conn
                .query_row("SELECT MAX(id) FROM signed_prekeys", [], |r| r.get(0))?;
        Ok(max.map_or(1, |m| m + 1))
    }

    pub fn insert_signed_prekey(&self, k: &OwnSignedPrekey) -> Result<()> {
        self.conn.execute(
            "INSERT INTO signed_prekeys (id, secret, public, sig, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![k.id, &k.secret[..], &k.public[..], &k.sig[..], k.created_at],
        )?;
        Ok(())
    }

    /// Самый свежий подписанный предключ.
    pub fn current_signed_prekey(&self) -> Result<Option<OwnSignedPrekey>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, secret, public, sig, created_at FROM signed_prekeys ORDER BY id DESC LIMIT 1",
                [],
                |r| {
                    Ok(OwnSignedPrekey {
                        id: r.get(0)?,
                        secret: blob32(r, 1)?,
                        public: blob32(r, 2)?,
                        sig: blob64(r, 3)?,
                        created_at: r.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn signed_prekey_secret(&self, id: u32) -> Result<Option<[u8; 32]>> {
        Ok(self
            .conn
            .query_row(
                "SELECT secret FROM signed_prekeys WHERE id = ?1",
                params![id],
                |r| blob32(r, 0),
            )
            .optional()?)
    }

    /// Удалить подписанные предключи старше `before` (unix-время), кроме самого свежего.
    pub fn prune_signed_prekeys(&self, before: i64) -> Result<usize> {
        Ok(self.conn.execute(
            "DELETE FROM signed_prekeys
             WHERE created_at < ?1 AND id <> (SELECT MAX(id) FROM signed_prekeys)",
            params![before],
        )?)
    }

    /// Следующий свободный ID для одноразового предключа.
    pub fn next_one_time_prekey_id(&self) -> Result<u32> {
        // ID не переиспользуются, даже если ключ уже удалён: храним счётчик.
        let v: Option<u32> = self
            .conn
            .query_row(
                "SELECT value FROM counters WHERE name = 'one_time_prekey'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        Ok(v.unwrap_or(0) + 1)
    }

    pub fn insert_one_time_prekeys(&self, keys: &[OwnOneTimePrekey]) -> Result<()> {
        let now = unix_now();
        let mut max = None;
        for k in keys {
            self.conn.execute(
                "INSERT INTO one_time_prekeys (id, secret, public, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![k.id, &k.secret[..], &k.public[..], now],
            )?;
            max = max.max(Some(k.id));
        }
        if let Some(max) = max {
            self.conn.execute(
                "INSERT INTO counters (name, value) VALUES ('one_time_prekey', ?1)
                 ON CONFLICT(name) DO UPDATE SET value = MAX(value, excluded.value)",
                params![max],
            )?;
        }
        Ok(())
    }

    pub fn one_time_prekey_secret(&self, id: u32) -> Result<Option<[u8; 32]>> {
        Ok(self
            .conn
            .query_row(
                "SELECT secret FROM one_time_prekeys WHERE id = ?1",
                params![id],
                |r| blob32(r, 0),
            )
            .optional()?)
    }

    pub fn delete_one_time_prekey(&self, id: u32) -> Result<()> {
        self.conn
            .execute("DELETE FROM one_time_prekeys WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn count_one_time_prekeys(&self) -> Result<u32> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(1) FROM one_time_prekeys", [], |r| r.get(0))?)
    }
}

// ---------------------------------------------------------------------------
// Миграции
// ---------------------------------------------------------------------------

const SCHEMA_V3: &str = "
    CREATE TABLE IF NOT EXISTS identities (
        account_id  TEXT PRIMARY KEY,
        username    TEXT NULL,
        secret      BLOB NOT NULL,
        public      BLOB NOT NULL,
        sign_secret BLOB NULL,
        sign_public BLOB NULL,
        created_at  INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_identities_created_at ON identities(created_at);

    CREATE TABLE IF NOT EXISTS contacts (
        account_id  TEXT PRIMARY KEY,
        username    TEXT NULL,
        public      BLOB NOT NULL,
        sign_public BLOB NULL,
        added_at    INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_contacts_username ON contacts(username);

    CREATE TABLE IF NOT EXISTS messages (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        direction       INTEGER NOT NULL, -- 0 = входящее, 1 = исходящее
        peer_account_id TEXT NOT NULL,
        peer_username   TEXT NULL,
        created_at      INTEGER NOT NULL,
        plaintext       TEXT NOT NULL,
        envelope_json   TEXT NOT NULL,
        is_read         INTEGER NOT NULL DEFAULT 1,
        msg_id          TEXT NULL,
        delivered_at    INTEGER NULL,
        status          INTEGER NOT NULL DEFAULT 0 -- 0 = ждёт, 1 = доставлено, 2 = не отправить
    );
    CREATE INDEX IF NOT EXISTS idx_messages_peer_time ON messages(peer_account_id, created_at);
";

/// v4: прямая секретность (X3DH + Double Ratchet).
/// (Таблицы `sessions` и `used_prekey_eks` из v4 с v5 устроены иначе — см. [`SESSIONS_V5`].)
const SCHEMA_V4: &str = "
    CREATE TABLE IF NOT EXISTS signed_prekeys (
        id         INTEGER PRIMARY KEY,
        secret     BLOB NOT NULL,
        public     BLOB NOT NULL,
        sig        BLOB NOT NULL,
        created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS one_time_prekeys (
        id         INTEGER PRIMARY KEY,
        secret     BLOB NOT NULL,
        public     BLOB NOT NULL,
        created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS counters (
        name  TEXT PRIMARY KEY,
        value INTEGER NOT NULL
    );
";

/// v5: несколько устройств на аккаунт.
const SCHEMA_V5: &str = "
    CREATE TABLE IF NOT EXISTS device_lists (
        account_id TEXT PRIMARY KEY,
        version    INTEGER NOT NULL,
        list_json  TEXT NOT NULL,
        updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS outbox (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id      TEXT NOT NULL,
        peer_account_id TEXT NOT NULL,
        to_account_id   TEXT NOT NULL,
        to_device_id    INTEGER NOT NULL,
        envelope_id     TEXT NOT NULL,
        envelope_json   TEXT NOT NULL,
        created_at      INTEGER NOT NULL,
        UNIQUE (to_account_id, to_device_id, envelope_id)
    );
    CREATE TABLE IF NOT EXISTS seen_envelopes (
        peer_account_id TEXT NOT NULL,
        peer_device_id  INTEGER NOT NULL,
        envelope_id     TEXT NOT NULL,
        seen_at         INTEGER NOT NULL,
        PRIMARY KEY (peer_account_id, peer_device_id, envelope_id)
    );
    CREATE TABLE IF NOT EXISTS pending_link (
        id          INTEGER PRIMARY KEY CHECK (id = 1),
        x_secret    BLOB NOT NULL,
        sign_secret BLOB NOT NULL,
        name        TEXT NOT NULL,
        created_at  INTEGER NOT NULL
    );
";

/// v6: восстановление ключа аккаунта из резервной копии. Колонка
/// `identities.account_sign_secret` добавляется ниже вместе с остальными.
const SCHEMA_V6: &str = "
    CREATE TABLE IF NOT EXISTS pending_restore (
        id             INTEGER PRIMARY KEY CHECK (id = 1),
        account_id     TEXT NOT NULL,
        account_secret BLOB NOT NULL,
        x_secret       BLOB NOT NULL,
        sign_secret    BLOB NOT NULL,
        name           TEXT NOT NULL,
        created_at     INTEGER NOT NULL
    );
";

/// Сессии и метки X3DH v5: ключ — (собеседник, его устройство).
const SESSIONS_V5: &str = "
    CREATE TABLE sessions (
        peer_account_id TEXT NOT NULL,
        peer_device_id  INTEGER NOT NULL,
        state           TEXT NOT NULL,
        updated_at      INTEGER NOT NULL,
        PRIMARY KEY (peer_account_id, peer_device_id)
    );
    CREATE TABLE used_prekey_eks (
        peer_account_id TEXT NOT NULL,
        peer_device_id  INTEGER NOT NULL,
        ek              BLOB NOT NULL,
        used_at         INTEGER NOT NULL,
        PRIMARY KEY (peer_account_id, peer_device_id, ek)
    );
";

/// Довести базу любой из прошлых версий до [`SCHEMA_VERSION`].
///
/// Миграция идемпотентна и выполняется в одной транзакции.
fn migrate(conn: &mut Connection) -> Result<()> {
    let version = get_user_version(conn)?;
    if version > SCHEMA_VERSION {
        bail!(
            "database schema v{version} is newer than this build supports (v{SCHEMA_VERSION}); \
             please update the app"
        );
    }

    // IMMEDIATE: сразу берём блокировку на запись (с ожиданием), иначе при
    // одновременном открытии базы двумя процессами один получал бы SQLITE_BUSY.
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

    // Самая первая схема: identities(user_id, …) без username.
    if table_exists(&tx, "identities")?
        && column_exists(&tx, "identities", "user_id")?
        && !column_exists(&tx, "identities", "account_id")?
    {
        tx.execute_batch("ALTER TABLE identities RENAME TO identities_old;")?;
        tx.execute_batch(SCHEMA_V3)?;
        tx.execute_batch(
            "INSERT INTO identities (account_id, username, secret, public, created_at)
             SELECT user_id, NULL, secret, public, created_at FROM identities_old;
             DROP TABLE identities_old;",
        )?;
    }

    tx.execute_batch(SCHEMA_V3)?;
    if !column_exists(&tx, "sessions", "peer_device_id")? {
        if table_exists(&tx, "sessions")? {
            // v4 → v5: всё, что было, — с основным устройством собеседника.
            tx.execute_batch(
                "ALTER TABLE sessions RENAME TO sessions_v4;
                 ALTER TABLE used_prekey_eks RENAME TO used_prekey_eks_v4;",
            )?;
            tx.execute_batch(SESSIONS_V5)?;
            tx.execute_batch(
                "INSERT INTO sessions (peer_account_id, peer_device_id, state, updated_at)
                     SELECT peer_account_id, 1, state, updated_at FROM sessions_v4;
                 INSERT INTO used_prekey_eks (peer_account_id, peer_device_id, ek, used_at)
                     SELECT peer_account_id, 1, ek, used_at FROM used_prekey_eks_v4;
                 DROP TABLE sessions_v4;
                 DROP TABLE used_prekey_eks_v4;",
            )?;
        } else {
            tx.execute_batch(SESSIONS_V5)?;
        }
    }
    tx.execute_batch(SCHEMA_V4)?;
    tx.execute_batch(SCHEMA_V5)?;
    tx.execute_batch(SCHEMA_V6)?;

    // Колонки, которые появлялись по ходу развития.
    for (table, column, ddl) in [
        (
            "identities",
            "sign_secret",
            "ALTER TABLE identities ADD COLUMN sign_secret BLOB NULL",
        ),
        (
            "identities",
            "sign_public",
            "ALTER TABLE identities ADD COLUMN sign_public BLOB NULL",
        ),
        (
            "contacts",
            "sign_public",
            "ALTER TABLE contacts ADD COLUMN sign_public BLOB NULL",
        ),
        (
            "messages",
            "is_read",
            "ALTER TABLE messages ADD COLUMN is_read INTEGER NOT NULL DEFAULT 1",
        ),
        (
            "messages",
            "status",
            "ALTER TABLE messages ADD COLUMN status INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "messages",
            "msg_id",
            "ALTER TABLE messages ADD COLUMN msg_id TEXT NULL",
        ),
        (
            "messages",
            "delivered_at",
            "ALTER TABLE messages ADD COLUMN delivered_at INTEGER NULL",
        ),
        (
            "contacts",
            "spk_id",
            "ALTER TABLE contacts ADD COLUMN spk_id INTEGER NULL",
        ),
        (
            "contacts",
            "spk_pub",
            "ALTER TABLE contacts ADD COLUMN spk_pub BLOB NULL",
        ),
        (
            "contacts",
            "spk_sig",
            "ALTER TABLE contacts ADD COLUMN spk_sig BLOB NULL",
        ),
        (
            "identities",
            "device_id",
            "ALTER TABLE identities ADD COLUMN device_id INTEGER NOT NULL DEFAULT 1",
        ),
        (
            "identities",
            "account_sign_secret",
            "ALTER TABLE identities ADD COLUMN account_sign_secret BLOB NULL",
        ),
    ] {
        if !column_exists(&tx, table, column)? {
            tx.execute_batch(ddl)?;
        }
    }

    // v2 требовала глобальную уникальность msg_id — это позволяло собеседнику
    // «занять» id нашего же сообщения. В v3 уникальность в рамках
    // (собеседник, направление).
    tx.execute_batch(
        "DROP INDEX IF EXISTS idx_messages_msg_id;
         CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_peer_dir_msg_id
             ON messages(peer_account_id, direction, msg_id);",
    )?;

    if version < 5 {
        // Неотправленное до v5 зашифровано старым форматом конверта: новый релей
        // его не примет. Честно помечаем «не отправлено» — пусть пользователь
        // отправит заново.
        tx.execute_batch("UPDATE messages SET status = 2 WHERE direction = 1 AND status = 0")?;
    }

    tx.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))?;
    tx.commit()?;
    Ok(())
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![table],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn.prepare("SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2")?;
    Ok(stmt.exists(params![table, column])?)
}

fn get_user_version(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row("PRAGMA user_version", [], |r| r.get(0))?)
}

// ---------------------------------------------------------------------------
// Помощники
// ---------------------------------------------------------------------------

fn contact_from_row(r: &Row<'_>) -> rusqlite::Result<ContactRow> {
    let spk_id: Option<u32> = r.get(4)?;
    let spk_pub = blob32_opt(r, 5)?;
    let spk_sig: Option<Vec<u8>> = r.get(6)?;
    let signed_prekey = match (spk_id, spk_pub, spk_sig) {
        (Some(id), Some(public), Some(sig)) => Some(StoredPrekey {
            id,
            public,
            sig: to64(sig, 6)?,
        }),
        _ => None,
    };
    Ok(ContactRow {
        account_id: r.get(0)?,
        username: r.get(1)?,
        public: blob32(r, 2)?,
        sign_public: blob32_opt(r, 3)?,
        signed_prekey,
    })
}

fn blob64(r: &Row<'_>, idx: usize) -> rusqlite::Result<[u8; 64]> {
    to64(r.get(idx)?, idx)
}

fn to64(v: Vec<u8>, idx: usize) -> rusqlite::Result<[u8; 64]> {
    v.try_into().map_err(|v: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            idx,
            rusqlite::types::Type::Blob,
            format!("expected 64 bytes, got {}", v.len()).into(),
        )
    })
}

fn blob32(r: &Row<'_>, idx: usize) -> rusqlite::Result<[u8; 32]> {
    let v: Vec<u8> = r.get(idx)?;
    to32(v, idx)
}

fn blob32_opt(r: &Row<'_>, idx: usize) -> rusqlite::Result<Option<[u8; 32]>> {
    let v: Option<Vec<u8>> = r.get(idx)?;
    v.map(|v| to32(v, idx)).transpose()
}

fn to32(v: Vec<u8>, idx: usize) -> rusqlite::Result<[u8; 32]> {
    v.try_into().map_err(|v: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            idx,
            rusqlite::types::Type::Blob,
            format!("expected 32-byte key, got {} bytes", v.len()).into(),
        )
    })
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// В базе лежат секретные ключи — закрываем каталог от других пользователей.
#[cfg(unix)]
fn restrict_permissions(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 700 {}", dir.display()))
}

#[cfg(not(unix))]
fn restrict_permissions(_dir: &Path) -> Result<()> {
    Ok(())
}

/// Сам файл базы — только для владельца (SQLite наследует эти права для -wal/-shm).
#[cfg(unix)]
fn restrict_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 600 {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}
