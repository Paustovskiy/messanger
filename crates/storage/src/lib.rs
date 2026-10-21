//! Локальная база клиента (SQLite).
//!
//! Что хранится:
//! * `identities` — своя личность (одна на базу) вместе с **секретными ключами**;
//! * `contacts`   — проверенные карточки собеседников;
//! * `messages`   — история переписки и исходящая очередь.
//!
//! Схема версионируется через `PRAGMA user_version`; [`Db::open`] сам доводит
//! любую старую базу до текущей версии.

use anyhow::{Context, Result, bail};
use directories::ProjectDirs;
use rusqlite::{Connection, OptionalExtension, Row, params};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Текущая версия схемы.
pub const SCHEMA_VERSION: i64 = 3;

pub struct Db {
    conn: Connection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRow {
    pub account_id: String,
    pub username: Option<String>,
    /// X25519 secret.
    pub secret: [u8; 32],
    /// X25519 public.
    pub public: [u8; 32],
    /// Ed25519 signing secret. `None` — личность из старой версии без ключа подписи.
    pub sign_secret: Option<[u8; 32]>,
    /// Ed25519 verifying key.
    pub sign_public: Option<[u8; 32]>,
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
}

impl DeliveryStatus {
    fn from_db(v: i64) -> Self {
        if v >= 1 {
            Self::Delivered
        } else {
            Self::Pending
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

/// Исходящее сообщение, которое ещё не подтверждено получателем.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingOutgoing {
    pub peer_account_id: String,
    pub msg_id: String,
    pub envelope_json: String,
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
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)
                .with_context(|| format!("create dir {}", parent.display()))?;
        }
        let conn =
            Connection::open(path).with_context(|| format!("open sqlite {}", path.display()))?;
        restrict_file_permissions(path)?;
        Self::init(conn)
    }

    /// База в памяти — для тестов.
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    /// Открыть базу в стандартном каталоге данных ОС для профиля `app_name`
    /// (например, `~/.local/share/<app_name>/messenger.sqlite` на Linux).
    pub fn open_default(app_name: &str) -> Result<(Self, PathBuf)> {
        let proj = ProjectDirs::from("ru", "messenger", app_name)
            .context("cannot determine the data directory for this OS")?;
        let dir = proj.data_dir();
        fs::create_dir_all(dir).with_context(|| format!("create dir {}", dir.display()))?;
        restrict_permissions(dir)?;

        let path = dir.join("messenger.sqlite");
        let db = Self::open(&path)?;
        Ok((db, path))
    }

    fn init(mut conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;",
        )?;
        migrate(&mut conn)?;
        Ok(Self { conn })
    }

    // ----- личность -------------------------------------------------------

    /// Своя личность. В текущей версии — одна на базу.
    pub fn get_local_identity(&self) -> Result<Option<IdentityRow>> {
        self.conn
            .query_row(
                "SELECT account_id, username, secret, public, sign_secret, sign_public
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
                    })
                },
            )
            .optional()
            .context("load local identity")
    }

    /// Создать или обновить личность по `account_id`.
    pub fn upsert_identity(&self, row: &IdentityRow) -> Result<()> {
        self.conn.execute(
            "INSERT INTO identities (account_id, username, secret, public, sign_secret, sign_public, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(account_id) DO UPDATE SET
                 username    = excluded.username,
                 secret      = excluded.secret,
                 public      = excluded.public,
                 sign_secret = excluded.sign_secret,
                 sign_public = excluded.sign_public",
            params![
                row.account_id,
                row.username,
                &row.secret[..],
                &row.public[..],
                row.sign_secret.as_ref().map(|k| &k[..]),
                row.sign_public.as_ref().map(|k| &k[..]),
                unix_now()
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

        self.conn.execute(
            "INSERT INTO contacts (account_id, username, public, sign_public, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(account_id) DO UPDATE SET
                 username    = excluded.username,
                 public      = excluded.public,
                 sign_public = excluded.sign_public",
            params![
                c.account_id,
                c.username,
                &c.public[..],
                c.sign_public.as_ref().map(|k| &k[..]),
                unix_now()
            ],
        )?;
        Ok(())
    }

    /// Удалить контакт. Возвращает `false`, если такого не было.
    pub fn delete_contact(&self, account_id: &str) -> Result<bool> {
        Ok(self.conn.execute(
            "DELETE FROM contacts WHERE account_id = ?1",
            params![account_id],
        )? > 0)
    }

    pub fn list_contacts(&self) -> Result<Vec<ContactRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT account_id, username, public, sign_public FROM contacts
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
                "SELECT account_id, username, public, sign_public FROM contacts WHERE account_id = ?1",
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
            "SELECT account_id, username, public, sign_public FROM contacts
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

    /// Исходящие сообщения, которые получатель ещё не подтвердил.
    pub fn list_pending_outgoing(&self, limit: usize) -> Result<Vec<PendingOutgoing>> {
        let mut stmt = self.conn.prepare(
            "SELECT peer_account_id, msg_id, envelope_json FROM messages
             WHERE direction = 1 AND msg_id IS NOT NULL AND status = 0
             ORDER BY created_at ASC, id ASC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |r| {
            Ok(PendingOutgoing {
                peer_account_id: r.get(0)?,
                msg_id: r.get(1)?,
                envelope_json: r.get(2)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
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
        status          INTEGER NOT NULL DEFAULT 0 -- 0 = ждёт, 1 = доставлено
    );
    CREATE INDEX IF NOT EXISTS idx_messages_peer_time ON messages(peer_account_id, created_at);
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

    let tx = conn.transaction()?;

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
    Ok(ContactRow {
        account_id: r.get(0)?,
        username: r.get(1)?,
        public: blob32(r, 2)?,
        sign_public: blob32_opt(r, 3)?,
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
