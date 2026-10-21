//! Постоянное хранилище релея: привязки аккаунтов к ключам и очередь доставки.

use anyhow::{Context, Result};
use protocol::{OneTimePrekey, SignedPrekey};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Что лежит в очереди.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Конверт для получателя. Удаляется, только когда получатель пришлёт `ack`.
    Deliver,
    /// Уведомление отправителю «доставлено». Удаляется после отправки.
    DeliverAck,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Deliver => "deliver",
            Kind::DeliverAck => "deliver_ack",
        }
    }

    fn parse(s: &str) -> Self {
        if s == "deliver" {
            Kind::Deliver
        } else {
            Kind::DeliverAck
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Binding {
    /// Аккаунт впервые зашёл, ключ запомнен.
    New,
    /// Ключ совпал с запомненным.
    Known,
    /// Аккаунт уже привязан к другому ключу — вход запрещён.
    Mismatch,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Enqueue {
    Queued,
    /// Такое сообщение уже в очереди (повторная отправка).
    Duplicate,
    /// Очередь получателя переполнена.
    Full,
}

#[derive(Debug, Clone)]
pub struct QueuedItem {
    pub id: i64,
    pub kind: Kind,
    pub payload: String,
}

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: Option<&Path>) -> Result<Self> {
        let conn = match path {
            Some(p) => Connection::open(p).with_context(|| format!("open {}", p.display()))?,
            None => Connection::open_in_memory()?,
        };
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS accounts (
                 account_id TEXT PRIMARY KEY,
                 sign_pub   BLOB NOT NULL,
                 first_seen INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS queue (
                 id         INTEGER PRIMARY KEY AUTOINCREMENT,
                 recipient  TEXT NOT NULL,
                 sender     TEXT NOT NULL,
                 msg_id     TEXT NOT NULL,
                 kind       TEXT NOT NULL,
                 payload    TEXT NOT NULL,
                 created_at INTEGER NOT NULL,
                 UNIQUE (recipient, sender, msg_id, kind)
             );
             CREATE INDEX IF NOT EXISTS idx_queue_recipient ON queue(recipient, id);
             CREATE INDEX IF NOT EXISTS idx_queue_created ON queue(created_at);
             CREATE TABLE IF NOT EXISTS signed_prekeys (
                 account_id TEXT PRIMARY KEY,
                 id         INTEGER NOT NULL,
                 public     BLOB NOT NULL,
                 sig        BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS one_time_prekeys (
                 account_id TEXT NOT NULL,
                 id         INTEGER NOT NULL,
                 public     BLOB NOT NULL,
                 PRIMARY KEY (account_id, id)
             );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        // Паника внутри блокировки не оставляет SQLite в плохом состоянии.
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Trust-on-first-use: первый успешный вход закрепляет ключ за аккаунтом.
    pub fn bind_account(&self, account_id: &str, sign_pub: &[u8; 32]) -> Result<Binding> {
        let conn = self.conn();
        let existing: Option<Vec<u8>> = conn
            .query_row(
                "SELECT sign_pub FROM accounts WHERE account_id = ?1",
                params![account_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(match existing {
            Some(k) if k == sign_pub => Binding::Known,
            Some(_) => Binding::Mismatch,
            None => {
                conn.execute(
                    "INSERT INTO accounts (account_id, sign_pub, first_seen) VALUES (?1, ?2, ?3)",
                    params![account_id, &sign_pub[..], now()],
                )?;
                Binding::New
            }
        })
    }

    pub fn enqueue(
        &self,
        recipient: &str,
        sender: &str,
        msg_id: &str,
        kind: Kind,
        payload: &str,
        max_per_recipient: usize,
    ) -> Result<Enqueue> {
        let conn = self.conn();
        let queued: i64 = conn.query_row(
            "SELECT COUNT(1) FROM queue WHERE recipient = ?1",
            params![recipient],
            |r| r.get(0),
        )?;
        if queued as usize >= max_per_recipient {
            let exists: bool = conn
                .prepare_cached(
                    "SELECT 1 FROM queue WHERE recipient = ?1 AND sender = ?2 AND msg_id = ?3 AND kind = ?4",
                )?
                .exists(params![recipient, sender, msg_id, kind.as_str()])?;
            return Ok(if exists {
                Enqueue::Duplicate
            } else {
                Enqueue::Full
            });
        }
        let n = conn.execute(
            "INSERT OR IGNORE INTO queue (recipient, sender, msg_id, kind, payload, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![recipient, sender, msg_id, kind.as_str(), payload, now()],
        )?;
        Ok(if n > 0 {
            Enqueue::Queued
        } else {
            Enqueue::Duplicate
        })
    }

    pub fn pending_for(&self, recipient: &str) -> Result<Vec<QueuedItem>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT id, kind, payload FROM queue WHERE recipient = ?1 ORDER BY id ASC",
        )?;
        let rows = stmt.query_map(params![recipient], |r| {
            Ok(QueuedItem {
                id: r.get(0)?,
                kind: Kind::parse(&r.get::<_, String>(1)?),
                payload: r.get(2)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn remove(&self, id: i64) -> Result<()> {
        self.conn()
            .execute("DELETE FROM queue WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Удалить конверт после `ack` получателя. `true`, если он был в очереди.
    pub fn remove_delivered(&self, recipient: &str, sender: &str, msg_id: &str) -> Result<bool> {
        let n = self.conn().execute(
            "DELETE FROM queue WHERE recipient = ?1 AND sender = ?2 AND msg_id = ?3 AND kind = 'deliver'",
            params![recipient, sender, msg_id],
        )?;
        Ok(n > 0)
    }

    // ----- предключи -------------------------------------------------------

    /// Заменить подписанный предключ и добавить одноразовые (сверх `max_one_time`
    /// не храним). Возвращает, сколько одноразовых теперь лежит.
    pub fn publish_prekeys(
        &self,
        account_id: &str,
        signed: &SignedPrekey,
        one_time: &[OneTimePrekey],
        max_one_time: usize,
    ) -> Result<u32> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO signed_prekeys (account_id, id, public, sig) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(account_id) DO UPDATE SET id = excluded.id, public = excluded.public, sig = excluded.sig",
            params![account_id, signed.id, &signed.public[..], &signed.sig[..]],
        )?;
        let mut count: u32 = tx.query_row(
            "SELECT COUNT(1) FROM one_time_prekeys WHERE account_id = ?1",
            params![account_id],
            |r| r.get(0),
        )?;
        for k in one_time {
            if count as usize >= max_one_time {
                break;
            }
            count += tx.execute(
                "INSERT OR IGNORE INTO one_time_prekeys (account_id, id, public) VALUES (?1, ?2, ?3)",
                params![account_id, k.id, &k.public[..]],
            )? as u32;
        }
        tx.commit()?;
        Ok(count)
    }

    /// Есть ли подписанный предключ и сколько одноразовых осталось.
    pub fn prekey_status(&self, account_id: &str) -> Result<(bool, u32)> {
        let conn = self.conn();
        let has_signed = conn
            .prepare_cached("SELECT 1 FROM signed_prekeys WHERE account_id = ?1")?
            .exists(params![account_id])?;
        let count = conn.query_row(
            "SELECT COUNT(1) FROM one_time_prekeys WHERE account_id = ?1",
            params![account_id],
            |r| r.get(0),
        )?;
        Ok((has_signed, count))
    }

    /// Набор предключей для новой сессии. Одноразовый ключ выдаётся один раз.
    ///
    /// `allow_one_time` спрашивается, только если одноразовый ключ вообще есть:
    /// так лимит выдачи тратится лишь на реально выданные ключи.
    pub fn take_bundle(
        &self,
        account_id: &str,
        allow_one_time: impl FnOnce() -> bool,
    ) -> Result<Option<(SignedPrekey, Option<OneTimePrekey>)>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let signed = tx
            .query_row(
                "SELECT id, public, sig FROM signed_prekeys WHERE account_id = ?1",
                params![account_id],
                |r| {
                    Ok((
                        r.get::<_, u32>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((id, public, sig)) = signed else {
            return Ok(None);
        };
        let signed = SignedPrekey {
            id,
            public: public
                .try_into()
                .map_err(|_| anyhow::anyhow!("corrupt prekey"))?,
            sig: sig
                .try_into()
                .map_err(|_| anyhow::anyhow!("corrupt prekey"))?,
        };
        let one_time = tx
            .query_row(
                "SELECT id, public FROM one_time_prekeys WHERE account_id = ?1 ORDER BY id LIMIT 1",
                params![account_id],
                |r| Ok((r.get::<_, u32>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        let one_time = match one_time {
            Some(_) if !allow_one_time() => None,
            None => None,
            Some((id, public)) => {
                tx.execute(
                    "DELETE FROM one_time_prekeys WHERE account_id = ?1 AND id = ?2",
                    params![account_id, id],
                )?;
                Some(OneTimePrekey {
                    id,
                    public: public
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("corrupt prekey"))?,
                })
            }
        };
        tx.commit()?;
        Ok(Some((signed, one_time)))
    }

    /// Выбросить всё, что пролежало в очереди дольше `ttl_secs`.
    pub fn purge_older_than(&self, ttl_secs: u64) -> Result<usize> {
        let cutoff = now() - ttl_secs as i64;
        Ok(self
            .conn()
            .execute("DELETE FROM queue WHERE created_at < ?1", params![cutoff])?)
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
