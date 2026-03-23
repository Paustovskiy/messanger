use anyhow::{bail, Context, Result};
use directories::ProjectDirs;
use rusqlite::{params, Connection, OptionalExtension};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Db {
    conn: Connection,
}

#[derive(Debug, Clone)]
pub struct IdentityRow {
    pub account_id: String,          // UUID (внутренний ID)
    pub username: Option<String>,    // @username (человекочитаемый, опционально)
    pub secret: [u8; 32],       // x25519 secret
    pub public: [u8; 32],       // x25519 public
    pub sign_secret: [u8; 32],  // ed25519 signing secret
    pub sign_public: [u8; 32],  // ed25519 verifying public
}
#[derive(Debug, Clone)]
pub struct ContactRow {
    pub account_id: String,
    pub username: Option<String>,
    pub public: [u8; 32],
}

#[derive(Debug, Clone)]
pub enum Direction {
    In,
    Out,
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
    pub status: i32,
    pub delivered_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct ThreadRow {
    pub peer_account_id: String,
    pub peer_username: Option<String>,
    pub last_created_at: i64,
    pub last_direction: Direction,
    pub last_plaintext: String,
    pub unread_count: i64,
    pub last_status: i32,
}

impl Db {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create dir: {:?}", parent))?;
        }

        let conn = Connection::open(path).with_context(|| format!("open sqlite: {:?}", path))?;

        conn.execute_batch(
            r#"
            PRAGMA foreign_keys = ON;
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            "#,
        )?;

        migrate(&conn)?;
        Ok(Self { conn })
    }

    pub fn open_default(app_name: &str) -> Result<(Self, PathBuf)> {
        let proj = ProjectDirs::from("ru", "messenger", app_name)
            .context("ProjectDirs::from returned None")?;

        let dir = proj.data_dir();
        let path = dir.join("messenger.sqlite");
        let db = Self::open(&path)?;
        Ok((db, path))
    }

    /// Для текущего MVP предполагаем одну identity на устройство:
    /// берём первую строку (если есть).
    pub fn get_local_identity(&self) -> Result<Option<IdentityRow>> {
        let mut stmt = self.conn.prepare(
            r#"
        SELECT account_id, username, secret, public, sign_secret, sign_public
        FROM identities
        ORDER BY created_at ASC
        LIMIT 1
        "#,
        )?;

        let raw: Option<(String, Option<String>, Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>)> =
            stmt.query_row([], |r| {
                let account_id: String = r.get(0)?;
                let username: Option<String> = r.get(1)?;
                let secret: Vec<u8> = r.get(2)?;
                let public: Vec<u8> = r.get(3)?;
                let sign_secret: Option<Vec<u8>> = r.get(4)?;
                let sign_public: Option<Vec<u8>> = r.get(5)?;
                Ok((account_id, username, secret, public, sign_secret, sign_public))
            })
                .optional()?;

        let Some((account_id, username, secret_vec, public_vec, sign_secret_vec, sign_public_vec)) = raw else {
            return Ok(None);
        };

        let secret = vec32(secret_vec, "secret")?;
        let public = vec32(public_vec, "public")?;

        // Для старых БД sign_* могут быть NULL — caller должен уметь это обработать.
        // Но storage-level лучше не гадать: если их нет, считаем identity неполной.
        let sign_secret = match sign_secret_vec {
            Some(v) => vec32(v, "sign_secret")?,
            None => return Ok(None),
        };

        let sign_public = match sign_public_vec {
            Some(v) => vec32(v, "sign_public")?,
            None => return Ok(None),
        };

        Ok(Some(IdentityRow {
            account_id,
            username,
            secret,
            public,
            sign_secret,
            sign_public,
        }))
    }

    /// Upsert identity по account_id.
    pub fn upsert_identity(&self, row: &IdentityRow) -> Result<()> {
        let now = unix_now();

        self.conn.execute(
            r#"
        INSERT INTO identities (
            account_id, username, secret, public, sign_secret, sign_public, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT(account_id) DO UPDATE SET
            username    = excluded.username,
            secret      = excluded.secret,
            public      = excluded.public,
            sign_secret = excluded.sign_secret,
            sign_public = excluded.sign_public
        "#,
            params![
            row.account_id,
            row.username,
            row.secret.as_slice(),
            row.public.as_slice(),
            row.sign_secret.as_slice(),
            row.sign_public.as_slice(),
            now
        ],
        )?;

        Ok(())
    }

    /// Обновить username для account_id.
    pub fn set_username(&self, account_id: &str, username: Option<&str>) -> Result<()> {
        self.conn.execute(
            r#"
            UPDATE identities
            SET username = ?2
            WHERE account_id = ?1
            "#,
            params![account_id, username],
        )?;
        Ok(())
    }

    pub fn upsert_contact(&self, c: &ContactRow) -> Result<()> {
        let now = unix_now();
        self.conn.execute(
            r#"
        INSERT INTO contacts (account_id, username, public, added_at)
        VALUES (?1, ?2, ?3, ?4)
        ON CONFLICT(account_id) DO UPDATE SET
            username = excluded.username,
            public   = excluded.public
        "#,
            params![c.account_id, c.username, c.public.as_slice(), now],
        )?;
        Ok(())
    }

    pub fn delete_contact(&self, account_id: &str) -> Result<()> {
        self.conn.execute(
            r#"DELETE FROM contacts WHERE account_id = ?1"#,
            params![account_id],
        )?;
        Ok(())
    }

    pub fn list_contacts(&self) -> Result<Vec<ContactRow>> {
        let mut stmt = self.conn.prepare(
            r#"
        SELECT account_id, username, public
        FROM contacts
        ORDER BY COALESCE(username, account_id) ASC
        "#,
        )?;

        let mut rows = stmt.query([])?;
        let mut out = Vec::new();

        while let Some(r) = rows.next()? {
            let account_id: String = r.get(0)?;
            let username: Option<String> = r.get(1)?;
            let public_vec: Vec<u8> = r.get(2)?;
            let public = vec32(public_vec, "public")?;
            out.push(ContactRow {
                account_id,
                username,
                public,
            });
        }

        Ok(out)
    }

    /// Найти контакт по account_id или по @username (case-insensitive).
    pub fn find_contact(&self, key: &str) -> Result<Option<ContactRow>> {
        // Нормализация username для поиска
        let key_trim = key.trim();

        // если похоже на UUID/account_id — ищем по account_id
        if !key_trim.starts_with('@') {
            let mut stmt = self.conn.prepare(
                r#"
            SELECT account_id, username, public
            FROM contacts
            WHERE account_id = ?1
            "#,
            )?;

            let raw: Option<(String, Option<String>, Vec<u8>)> = stmt
                .query_row(params![key_trim], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })
                .optional()?;

            if let Some((account_id, username, public_vec)) = raw {
                let public = vec32(public_vec, "public")?;
                return Ok(Some(ContactRow {
                    account_id,
                    username,
                    public,
                }));
            }
            return Ok(None);
        }

        // Поиск по username, регистр не важен
        let uname = key_trim.to_ascii_lowercase();

        let mut stmt = self.conn.prepare(
            r#"
        SELECT account_id, username, public
        FROM contacts
        WHERE LOWER(username) = ?1
        "#,
        )?;

        let raw: Option<(String, Option<String>, Vec<u8>)> = stmt
            .query_row(params![uname], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .optional()?;

        let Some((account_id, username, public_vec)) = raw else {
            return Ok(None);
        };

        let public = vec32(public_vec, "public")?;
        Ok(Some(ContactRow {
            account_id,
            username,
            public,
        }))
    }

    pub fn insert_message(
        &self,
        direction: Direction,
        peer_account_id: &str,
        peer_username: Option<&str>,
        plaintext: &str,
        envelope_json: &str,
        msg_id: Option<&str>,
    ) -> Result<i64> {
        let now = unix_now();
        let dir_int = match direction {
            Direction::In => 0,
            Direction::Out => 1,
        };
        // Входящие при вставке считаем "непрочитанными", исходящие — прочитанными.
        let is_read = match direction {
            Direction::In => 0,
            Direction::Out => 1,
        };

        let status = match direction {
            Direction::Out => 0,
            Direction::In => 0,
        };


        self.conn.execute(
            r#"
        INSERT INTO messages (direction, peer_account_id, peer_username, created_at, plaintext, envelope_json, is_read, msg_id, status)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
            params![dir_int, peer_account_id, peer_username, now, plaintext, envelope_json, is_read, msg_id, status],
        )?;

        Ok(self.conn.last_insert_rowid())
    }


    pub fn list_messages_for_peer_resolved(&self, peer_account_id: &str, limit: usize) -> Result<Vec<MessageRow>> {
        let mut stmt = self.conn.prepare(
            r#"
        SELECT
            m.id,
            m.msg_id,
            m.direction,
            m.peer_account_id,
            COALESCE(c.username, m.peer_username) AS peer_username,
            m.created_at,
            m.plaintext,
            m.envelope_json,
            m.is_read,
            m.status,
            m.delivered_at
        FROM messages m
        LEFT JOIN contacts c
            ON c.account_id = m.peer_account_id
        WHERE m.peer_account_id = ?1
        ORDER BY m.created_at ASC, m.id ASC
        LIMIT ?2
        "#,
        )?;

        let mut rows = stmt.query(params![peer_account_id, limit as i64])?;
        let mut out = Vec::new();

        while let Some(r) = rows.next()? {
            let id: i64 = r.get(0)?;
            let msg_id: Option<String> = r.get(1)?;
            let dir_int: i64 = r.get(2)?;
            let peer_account_id: String = r.get(3)?;
            let peer_username: Option<String> = r.get(4)?;
            let created_at: i64 = r.get(5)?;
            let plaintext: String = r.get(6)?;
            let envelope_json: String = r.get(7)?;
            let is_read_int: i64 = r.get(8)?;
            let status: i32 = r.get(9)?;
            let delivered_at: Option<i64> = r.get(10)?;

            let direction = match dir_int {
                0 => Direction::In,
                1 => Direction::Out,
                _ => bail!("invalid direction in db: {}", dir_int),
            };

            let is_read = is_read_int != 0;

            out.push(MessageRow {
                id,
                msg_id,
                direction,
                peer_account_id,
                peer_username,
                created_at,
                plaintext,
                envelope_json,
                is_read,
                status,
                delivered_at,
            });

        }

        Ok(out)
    }


    pub fn list_threads_resolved(&self, limit: usize) -> Result<Vec<ThreadRow>> {
        let mut stmt = self.conn.prepare(
            r#"
        SELECT
            t.peer_account_id,
            COALESCE(c.username, t.peer_username) AS peer_username,
            t.created_at,
            t.direction,
            t.plaintext,
            t.status AS last_status,
            (
              SELECT COUNT(1)
              FROM messages m2
              WHERE m2.peer_account_id = t.peer_account_id
                AND m2.direction = 0
                AND m2.is_read = 0
            ) AS unread_count
        FROM (
        SELECT peer_account_id, peer_username, created_at, direction, plaintext, status
        FROM (
            SELECT
                peer_account_id,
                peer_username,
                created_at,
                direction,
                plaintext,
                status,
                ROW_NUMBER() OVER (
                    PARTITION BY peer_account_id
                    ORDER BY created_at DESC, id DESC
                ) AS rn
            FROM messages
        )
        WHERE rn = 1
    ) t
    LEFT JOIN contacts c
        ON c.account_id = t.peer_account_id
    ORDER BY t.created_at DESC
    LIMIT ?1
    "#,
    )?;

        let mut rows = stmt.query(params![limit as i64])?;
        let mut out = Vec::new();

        while let Some(r) = rows.next()? {
            let peer_account_id: String = r.get(0)?;
            let peer_username: Option<String> = r.get(1)?;
            let last_created_at: i64 = r.get(2)?;
            let dir_int: i64 = r.get(3)?;
            let last_plaintext: String = r.get(4)?;
            let last_status: i32 = r.get(5)?;
            let unread_count: i64 = r.get(6)?;

            let last_direction = match dir_int {
                0 => Direction::In,
                1 => Direction::Out,
                _ => bail!("invalid direction in db: {}", dir_int),
            };

            out.push(ThreadRow {
                peer_account_id,
                peer_username,
                last_created_at,
                last_direction,
                last_plaintext,
                unread_count,
                last_status,
            });
        }

        Ok(out)
    }

    pub fn mark_thread_read(&self, peer_account_id: &str) -> Result<()> {
        self.conn.execute(
            r#"
        UPDATE messages
        SET is_read = 1
        WHERE peer_account_id = ?1
          AND direction = 0
          AND is_read = 0
        "#,
            params![peer_account_id],
        )?;
        Ok(())
    }

    pub fn mark_delivered(&self, msg_id: &str) -> Result<()> {
        let now = unix_now();
        self.conn.execute(
            r#"
        UPDATE messages
        SET delivered_at = ?2
        WHERE msg_id = ?1
        "#,
            params![msg_id, now],
        )?;
        Ok(())
    }

    pub fn mark_out_delivered(&self, peer_account_id: &str, msg_id: &str) -> Result<()> {
        let now = unix_now();
        self.conn.execute(
            r#"
        UPDATE messages
        SET status = 1,
            delivered_at = COALESCE(delivered_at, ?3)
        WHERE direction = 1
          AND peer_account_id = ?1
          AND msg_id = ?2
        "#,
            params![peer_account_id, msg_id, now],
        )?;
        Ok(())
    }

    pub fn list_pending_outgoing(&self, limit: usize) -> Result<Vec<(String, String, String)>> {
        // returns: (peer_account_id, msg_id, envelope_json)
        let mut stmt = self.conn.prepare(
            r#"
        SELECT peer_account_id, msg_id, envelope_json
        FROM messages
        WHERE direction = 1
          AND msg_id IS NOT NULL
          AND status = 0
        ORDER BY created_at ASC, id ASC
        LIMIT ?1
        "#,
        )?;

        let mut rows = stmt.query(params![limit as i64])?;
        let mut out = Vec::new();

        while let Some(r) = rows.next()? {
            let peer_account_id: String = r.get(0)?;
            let msg_id: String = r.get(1)?;
            let envelope_json: String = r.get(2)?;
            out.push((peer_account_id, msg_id, envelope_json));
        }

        Ok(out)
    }
    
}

fn migrate(conn: &Connection) -> Result<()> {
    // Если таблиц нет — создаём новую схему.
    if !table_exists(conn, "identities")? {
        create_v2(conn)?;
        set_user_version(conn, 2)?;
        return Ok(());
    }
    if !column_exists(conn, "identities", "sign_secret")? {
        conn.execute_batch(r#"ALTER TABLE identities ADD COLUMN sign_secret BLOB NULL;"#)?;
    }
    if !column_exists(conn, "identities", "sign_public")? {
        conn.execute_batch(r#"ALTER TABLE identities ADD COLUMN sign_public BLOB NULL;"#)?;
    }

    // Таблица identities есть. Проверим, старая ли схема (user_id вместо account_id).
    let has_user_id = column_exists(conn, "identities", "user_id")?;
    let has_account_id = column_exists(conn, "identities", "account_id")?;

    if has_user_id && !has_account_id {
        // Миграция identities -> новая схема
        conn.execute_batch(
            r#"
            ALTER TABLE identities RENAME TO identities_old;

            CREATE TABLE IF NOT EXISTS identities (
                account_id TEXT PRIMARY KEY,
                username   TEXT NULL,
                secret      BLOB NOT NULL,
                public      BLOB NOT NULL,
                sign_secret BLOB NULL,
                sign_public BLOB NULL,
                created_at  INTEGER NOT NULL
            );

            INSERT INTO identities (account_id, username, secret, public, created_at)
            SELECT user_id, NULL, secret, public, created_at
            FROM identities_old;

            DROP TABLE identities_old;

            CREATE INDEX IF NOT EXISTS idx_identities_created_at
            ON identities(created_at);
            "#,
        )?;

        set_user_version(conn, 2)?;
        // ВАЖНО: не return — ниже гарантируем contacts/messages и добавим is_read
    } else {
        // Уже новая схема identities — просто гарантируем индекс и версию.
        conn.execute_batch(
            r#"
            CREATE INDEX IF NOT EXISTS idx_identities_created_at
            ON identities(created_at);
            "#,
        )?;

        let v = get_user_version(conn)?;
        if v < 2 {
            set_user_version(conn, 2)?;
        }
    }

    // Гарантируем contacts
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS contacts (
            account_id TEXT PRIMARY KEY,
            username   TEXT NULL,
            public     BLOB NOT NULL,
            added_at   INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_contacts_username
        ON contacts(username);
        "#,
    )?;

    // Гарантируем messages (может существовать старая версия без is_read)
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS messages (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            direction       INTEGER NOT NULL, -- 0=in, 1=out
            peer_account_id TEXT NOT NULL,
            peer_username   TEXT NULL,
            created_at      INTEGER NOT NULL,
            plaintext       TEXT NOT NULL,
            envelope_json   TEXT NOT NULL,
            is_read         INTEGER NOT NULL DEFAULT 1,
            msg_id          TEXT NULL,
            delivered_at    INTEGER NULL,
            status          INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_messages_peer_time
        ON messages(peer_account_id, created_at);
        "#,
    )?;

    // Добавляем колонку is_read для существующих баз (если её ещё нет)
    if !column_exists(conn, "messages", "is_read")? {
        conn.execute_batch(
            r#"
            ALTER TABLE messages ADD COLUMN is_read INTEGER NOT NULL DEFAULT 1;
            "#,
        )?;
    }

    if !column_exists(conn, "messages", "status")? {
        conn.execute_batch(
            r#"ALTER TABLE messages ADD COLUMN status INTEGER NOT NULL DEFAULT 0;"#,
        )?;
    }

    if !column_exists(conn, "messages", "msg_id")? {
        conn.execute_batch(r#"ALTER TABLE messages ADD COLUMN msg_id TEXT NULL;"#)?;
    }

    if !column_exists(conn, "messages", "delivered_at")? {
        conn.execute_batch(r#"ALTER TABLE messages ADD COLUMN delivered_at INTEGER NULL;"#)?;
    }

    // Индекс уникальности по msg_id (в SQLite допускаются множественные NULL — это нормально)
    conn.execute_batch(
        r#"
    CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_msg_id
    ON messages(msg_id);
    "#,
    )?;

    Ok(())
}

fn create_v2(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS identities (
            account_id TEXT PRIMARY KEY,
            username   TEXT NULL,
            secret     BLOB NOT NULL,
            public     BLOB NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_identities_created_at
        ON identities(created_at);

        CREATE TABLE IF NOT EXISTS contacts (
            account_id TEXT PRIMARY KEY,
            username   TEXT NULL,
            public     BLOB NOT NULL,
            added_at   INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_contacts_username
        ON contacts(username);

        CREATE TABLE IF NOT EXISTS messages (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            direction       INTEGER NOT NULL, -- 0=in, 1=out
            peer_account_id TEXT NOT NULL,
            peer_username   TEXT NULL,
            created_at      INTEGER NOT NULL,
            plaintext       TEXT NOT NULL,
            envelope_json   TEXT NOT NULL,
            is_read         INTEGER NOT NULL DEFAULT 1,
            msg_id        TEXT NULL,
            delivered_at  INTEGER NULL,
            status          INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_messages_peer_time
        ON messages(peer_account_id, created_at);
        "#,
    )?;
    Ok(())
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    let exists: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?1",
            params![table],
            |r| r.get(0),
        )
        .optional()?;
    Ok(exists.is_some())
}

fn column_exists(conn: &Connection, table: &str, col: &str) -> Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", table))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == col {
            return Ok(true);
        }
    }
    Ok(false)
}

fn get_user_version(conn: &Connection) -> Result<i64> {
    let v: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    Ok(v)
}

fn set_user_version(conn: &Connection, v: i64) -> Result<()> {
    conn.execute(&format!("PRAGMA user_version = {}", v), [])?;
    Ok(())
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn vec32(v: Vec<u8>, field: &'static str) -> Result<[u8; 32]> {
    if v.len() != 32 {
        bail!("invalid {} length: expected 32, got {}", field, v.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}