//! Постоянное хранилище релея: привязки аккаунтов к ключам, списки устройств,
//! очередь доставки и предключи. Очередь и предключи — у каждого устройства свои.

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

/// Адрес устройства: аккаунт + номер устройства.
pub type Device<'a> = (&'a str, u32);

#[derive(Debug, Clone)]
pub struct QueuedItem {
    pub id: i64,
    pub kind: Kind,
    pub payload: String,
}

pub struct Store {
    conn: Mutex<Connection>,
}

/// Версия схемы релея. v2: несколько устройств на аккаунт.
const SCHEMA_VERSION: i64 = 2;

impl Store {
    pub fn open(path: Option<&Path>) -> Result<Self> {
        let conn = match path {
            Some(p) => Connection::open(p).with_context(|| format!("open {}", p.display()))?,
            None => Connection::open_in_memory()?,
        };
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;",
        )?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version < SCHEMA_VERSION {
            // v1 → v2: формат конверта сменился, старую очередь клиенты всё равно
            // не откроют, а предключи у каждого устройства теперь свои.
            // Привязки аккаунтов к ключам сохраняются.
            conn.execute_batch(
                "DROP TABLE IF EXISTS queue;
                 DROP TABLE IF EXISTS signed_prekeys;
                 DROP TABLE IF EXISTS one_time_prekeys;",
            )?;
        }
        conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS accounts (
                 account_id TEXT PRIMARY KEY,
                 sign_pub   BLOB NOT NULL,
                 first_seen INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS device_lists (
                 account_id TEXT PRIMARY KEY,
                 version    INTEGER NOT NULL,
                 list_json  TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS queue (
                 id               INTEGER PRIMARY KEY AUTOINCREMENT,
                 recipient        TEXT NOT NULL,
                 recipient_device INTEGER NOT NULL,
                 sender           TEXT NOT NULL,
                 sender_device    INTEGER NOT NULL,
                 msg_id           TEXT NOT NULL,
                 kind             TEXT NOT NULL,
                 payload          TEXT NOT NULL,
                 created_at       INTEGER NOT NULL,
                 UNIQUE (recipient, recipient_device, sender, sender_device, msg_id, kind)
             );
             CREATE INDEX IF NOT EXISTS idx_queue_recipient ON queue(recipient, recipient_device, id);
             CREATE INDEX IF NOT EXISTS idx_queue_created ON queue(created_at);
             CREATE TABLE IF NOT EXISTS signed_prekeys (
                 account_id TEXT NOT NULL,
                 device_id  INTEGER NOT NULL,
                 id         INTEGER NOT NULL,
                 public     BLOB NOT NULL,
                 sig        BLOB NOT NULL,
                 PRIMARY KEY (account_id, device_id)
             );
             CREATE TABLE IF NOT EXISTS one_time_prekeys (
                 account_id TEXT NOT NULL,
                 device_id  INTEGER NOT NULL,
                 id         INTEGER NOT NULL,
                 public     BLOB NOT NULL,
                 PRIMARY KEY (account_id, device_id, id)
             );
             PRAGMA user_version = {SCHEMA_VERSION};"
        ))?;
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

    /// Ключ аккаунта (ключ его основного устройства), если аккаунт уже входил.
    pub fn account_key(&self, account_id: &str) -> Result<Option<[u8; 32]>> {
        let k: Option<Vec<u8>> = self
            .conn()
            .query_row(
                "SELECT sign_pub FROM accounts WHERE account_id = ?1",
                params![account_id],
                |r| r.get(0),
            )
            .optional()?;
        k.map(|k| {
            k.try_into()
                .map_err(|_| anyhow::anyhow!("corrupt account key"))
        })
        .transpose()
    }

    // ----- списки устройств ------------------------------------------------

    /// Последний принятый список устройств аккаунта: `(версия, JSON)`.
    pub fn device_list(&self, account_id: &str) -> Result<Option<(u64, String)>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT version, list_json FROM device_lists WHERE account_id = ?1",
                params![account_id],
                |r| Ok((r.get::<_, i64>(0)? as u64, r.get(1)?)),
            )
            .optional()?)
    }

    /// Сохранить список, если он строго новее. Проверку подписи делает вызывающий.
    pub fn save_device_list(
        &self,
        account_id: &str,
        version: u64,
        list_json: &str,
    ) -> Result<bool> {
        let version = i64::try_from(version).context("version too large")?;
        Ok(self.conn().execute(
            "INSERT INTO device_lists (account_id, version, list_json) VALUES (?1, ?2, ?3)
             ON CONFLICT(account_id) DO UPDATE SET version = excluded.version, list_json = excluded.list_json
             WHERE excluded.version > device_lists.version",
            params![account_id, version, list_json],
        )? > 0)
    }

    /// Забыть всё, что лежит для устройства: его отключили от аккаунта.
    pub fn forget_device(&self, (account_id, device_id): Device<'_>) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        for sql in [
            "DELETE FROM queue WHERE recipient = ?1 AND recipient_device = ?2",
            "DELETE FROM signed_prekeys WHERE account_id = ?1 AND device_id = ?2",
            "DELETE FROM one_time_prekeys WHERE account_id = ?1 AND device_id = ?2",
        ] {
            tx.execute(sql, params![account_id, device_id])?;
        }
        tx.commit()?;
        Ok(())
    }

    // ----- очередь -----------------------------------------------------------

    pub fn enqueue(
        &self,
        (recipient, recipient_device): Device<'_>,
        (sender, sender_device): Device<'_>,
        msg_id: &str,
        kind: Kind,
        payload: &str,
        max_per_recipient: usize,
    ) -> Result<Enqueue> {
        let conn = self.conn();
        let queued: i64 = conn.query_row(
            "SELECT COUNT(1) FROM queue WHERE recipient = ?1 AND recipient_device = ?2",
            params![recipient, recipient_device],
            |r| r.get(0),
        )?;
        if queued as usize >= max_per_recipient {
            let exists: bool = conn
                .prepare_cached(
                    "SELECT 1 FROM queue WHERE recipient = ?1 AND recipient_device = ?2
                     AND sender = ?3 AND sender_device = ?4 AND msg_id = ?5 AND kind = ?6",
                )?
                .exists(params![
                    recipient,
                    recipient_device,
                    sender,
                    sender_device,
                    msg_id,
                    kind.as_str()
                ])?;
            return Ok(if exists {
                Enqueue::Duplicate
            } else {
                Enqueue::Full
            });
        }
        let n = conn.execute(
            "INSERT OR IGNORE INTO queue
                 (recipient, recipient_device, sender, sender_device, msg_id, kind, payload, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                recipient,
                recipient_device,
                sender,
                sender_device,
                msg_id,
                kind.as_str(),
                payload,
                now()
            ],
        )?;
        Ok(if n > 0 {
            Enqueue::Queued
        } else {
            Enqueue::Duplicate
        })
    }

    pub fn pending_for(&self, (recipient, device): Device<'_>) -> Result<Vec<QueuedItem>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT id, kind, payload FROM queue WHERE recipient = ?1 AND recipient_device = ?2
             ORDER BY id ASC",
        )?;
        let rows = stmt.query_map(params![recipient, device], |r| {
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
    pub fn remove_delivered(
        &self,
        (recipient, recipient_device): Device<'_>,
        (sender, sender_device): Device<'_>,
        msg_id: &str,
    ) -> Result<bool> {
        let n = self.conn().execute(
            "DELETE FROM queue WHERE recipient = ?1 AND recipient_device = ?2
             AND sender = ?3 AND sender_device = ?4 AND msg_id = ?5 AND kind = 'deliver'",
            params![recipient, recipient_device, sender, sender_device, msg_id],
        )?;
        Ok(n > 0)
    }

    // ----- предключи -------------------------------------------------------

    /// Заменить подписанный предключ и добавить одноразовые (сверх `max_one_time`
    /// не храним). Возвращает, сколько одноразовых теперь лежит.
    pub fn publish_prekeys(
        &self,
        (account_id, device_id): Device<'_>,
        signed: &SignedPrekey,
        one_time: &[OneTimePrekey],
        max_one_time: usize,
    ) -> Result<u32> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO signed_prekeys (account_id, device_id, id, public, sig) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(account_id, device_id)
             DO UPDATE SET id = excluded.id, public = excluded.public, sig = excluded.sig",
            params![account_id, device_id, signed.id, &signed.public[..], &signed.sig[..]],
        )?;
        let mut count: u32 = tx.query_row(
            "SELECT COUNT(1) FROM one_time_prekeys WHERE account_id = ?1 AND device_id = ?2",
            params![account_id, device_id],
            |r| r.get(0),
        )?;
        for k in one_time {
            if count as usize >= max_one_time {
                break;
            }
            count += tx.execute(
                "INSERT OR IGNORE INTO one_time_prekeys (account_id, device_id, id, public)
                 VALUES (?1, ?2, ?3, ?4)",
                params![account_id, device_id, k.id, &k.public[..]],
            )? as u32;
        }
        tx.commit()?;
        Ok(count)
    }

    /// Есть ли подписанный предключ и сколько одноразовых осталось.
    pub fn prekey_status(&self, (account_id, device_id): Device<'_>) -> Result<(bool, u32)> {
        let conn = self.conn();
        let has_signed = conn
            .prepare_cached(
                "SELECT 1 FROM signed_prekeys WHERE account_id = ?1 AND device_id = ?2",
            )?
            .exists(params![account_id, device_id])?;
        let count = conn.query_row(
            "SELECT COUNT(1) FROM one_time_prekeys WHERE account_id = ?1 AND device_id = ?2",
            params![account_id, device_id],
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
        (account_id, device_id): Device<'_>,
        allow_one_time: impl FnOnce() -> bool,
    ) -> Result<Option<(SignedPrekey, Option<OneTimePrekey>)>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let signed = tx
            .query_row(
                "SELECT id, public, sig FROM signed_prekeys WHERE account_id = ?1 AND device_id = ?2",
                params![account_id, device_id],
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
                "SELECT id, public FROM one_time_prekeys WHERE account_id = ?1 AND device_id = ?2
                 ORDER BY id LIMIT 1",
                params![account_id, device_id],
                |r| Ok((r.get::<_, u32>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        let one_time = match one_time {
            Some(_) if !allow_one_time() => None,
            None => None,
            Some((id, public)) => {
                tx.execute(
                    "DELETE FROM one_time_prekeys WHERE account_id = ?1 AND device_id = ?2 AND id = ?3",
                    params![account_id, device_id, id],
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_list_of_the_same_or_older_version_is_not_saved() {
        let store = Store::open(None).unwrap();
        assert!(store.save_device_list("acc", 2, "first").unwrap());
        // Проигравший гонку: та же версия с другим содержимым и более старая.
        assert!(!store.save_device_list("acc", 2, "other").unwrap());
        assert!(!store.save_device_list("acc", 1, "older").unwrap());
        assert_eq!(
            store.device_list("acc").unwrap(),
            Some((2, "first".to_owned()))
        );
        assert!(store.save_device_list("acc", 3, "newer").unwrap());
    }
}
