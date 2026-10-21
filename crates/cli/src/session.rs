//! Онлайн-сессия: соединение с релеем + обработка всего, что от него приходит.
//!
//! Любое подключение к релею сразу получает накопившуюся очередь, поэтому
//! входящие сообщения обрабатываются в любой команде (`send`, `sync`,
//! `listen`), а не только в `listen`. Там же, при каждом подключении, клиент
//! следит за запасом своих предключей на релее и пополняет его.

use crate::display;
use crate::messaging::{self, Incoming};
use crate::relay_client::RelayConn;
use anyhow::Result;
use crypto_core::{Bundle, Identity};
use protocol::{ClientMessage, EnvelopeB64, OneTimePrekey, ServerMessage, SignedPrekey};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use storage::{Db, PendingOutgoing};

pub enum Step {
    Handled,
    Timeout,
    Closed,
}

pub struct Session<'a> {
    db: &'a Db,
    me: &'a Identity,
    conn: RelayConn,
    /// msg_id, которые релей принял к доставке.
    pub accepted: HashSet<String>,
    /// msg_id, доставку которых подтвердил получатель.
    pub delivered: HashSet<String>,
    /// msg_id, которые релей отклонил, с причиной.
    pub rejected: HashMap<String, String>,
    /// Ответы на `FetchBundle`: `None` — собеседник ещё не публиковал предключи.
    pub bundles: HashMap<String, Option<Bundle>>,
    /// Релей выдал всю накопившуюся очередь (пришёл первый `PrekeyStatus`).
    pub synced: bool,
}

impl<'a> Session<'a> {
    pub async fn open(url: &str, db: &'a Db, me: &'a Identity) -> Result<Self> {
        let conn = RelayConn::connect(url, me).await?;
        Ok(Self {
            db,
            me,
            conn,
            accepted: HashSet::new(),
            delivered: HashSet::new(),
            rejected: HashMap::new(),
            bundles: HashMap::new(),
            synced: false,
        })
    }

    /// Отправить одно сообщение из исходящей очереди.
    pub async fn send_pending(&mut self, p: &PendingOutgoing) -> Result<()> {
        let envelope: EnvelopeB64 = match serde_json::from_str(&p.envelope_json) {
            Ok(e) => e,
            Err(_) => {
                // Сообщение, зашифрованное старой версией: новый релей его не примет,
                // а получатель не откроет. Убираем из очереди, чтобы не крутилось вечно.
                let reason = "зашифровано старой версией — отправьте его заново";
                eprintln!(
                    "! сообщение {} из исходящих не отправить: {reason}",
                    p.msg_id
                );
                self.db.mark_out_failed(&p.peer_account_id, &p.msg_id)?;
                self.rejected.insert(p.msg_id.clone(), reason.into());
                return Ok(());
            }
        };
        self.conn
            .send(&ClientMessage::Send {
                to: p.peer_account_id.clone(),
                msg_id: p.msg_id.clone(),
                envelope,
            })
            .await
    }

    /// Запросить предключи собеседника; ответ появится в [`bundles`](Self::bundles).
    pub async fn fetch_bundle(&mut self, account_id: &str) -> Result<()> {
        self.conn
            .send(&ClientMessage::FetchBundle {
                account_id: account_id.into(),
            })
            .await
    }

    /// Обработать следующее событие от релея (ждать не дольше `wait`, если задано).
    pub async fn step(&mut self, wait: Option<Duration>) -> Result<Step> {
        let next = match wait {
            Some(d) => match tokio::time::timeout(d, self.conn.recv()).await {
                Ok(r) => r?,
                Err(_) => return Ok(Step::Timeout),
            },
            None => self.conn.recv().await?,
        };
        let Some(msg) = next else {
            return Ok(Step::Closed);
        };
        self.handle(msg).await?;
        Ok(Step::Handled)
    }

    async fn handle(&mut self, msg: ServerMessage) -> Result<()> {
        match msg {
            ServerMessage::Deliver {
                from,
                msg_id,
                envelope,
            } => {
                self.on_deliver(from, msg_id, envelope).await?;
            }
            ServerMessage::DeliverAck { from, msg_id } => {
                if self.db.mark_out_delivered(&from, &msg_id)? {
                    let text = self.db.outgoing_text(&from, &msg_id)?.unwrap_or_default();
                    println!(
                        "✓✓ доставлено {}: «{}»",
                        display::peer_name(self.db, &from),
                        display::preview(&text, 40)
                    );
                }
                self.delivered.insert(msg_id);
            }
            ServerMessage::Accepted { msg_id } => {
                self.accepted.insert(msg_id);
            }
            ServerMessage::PrekeyStatus {
                has_signed_prekey,
                one_time_left,
            } => {
                self.synced = true;
                if let Some(publish) = messaging::prekeys_to_publish(
                    self.db,
                    self.me,
                    has_signed_prekey,
                    one_time_left,
                )? {
                    self.conn.send(&publish).await?;
                }
            }
            ServerMessage::Bundle {
                account_id,
                signed_prekey,
                one_time,
            } => {
                let bundle = match signed_prekey {
                    Some(spk) => Some(Bundle {
                        signed_prekey: SignedPrekey::try_from(&spk)?,
                        one_time: one_time.as_ref().map(OneTimePrekey::try_from).transpose()?,
                    }),
                    None => None,
                };
                self.bundles.insert(account_id, bundle);
            }
            ServerMessage::Error {
                message,
                msg_id: Some(id),
            } => {
                eprintln!("релей отклонил сообщение {id}: {message}");
                self.rejected.insert(id, message);
            }
            ServerMessage::Error {
                message,
                msg_id: None,
            } => eprintln!("ошибка релея: {message}"),
            ServerMessage::Challenge { .. } | ServerMessage::Authenticated { .. } => {}
        }
        Ok(())
    }

    async fn on_deliver(&mut self, from: String, msg_id: String, wire: EnvelopeB64) -> Result<()> {
        // Без нашего подтверждения релей сохранит сообщение и пришлёт ещё раз —
        // поэтому не подтверждаем то, что не смогли сохранить по нашей вине.
        let Some(contact) = self.db.get_contact(&from)? else {
            eprintln!(
                "! на релее ждёт сообщение от неизвестного аккаунта {from}. \
                 Добавьте его карточку (`messenger add-contact`) — и оно придёт."
            );
            return Ok(());
        };
        if contact.sign_public.is_none() {
            eprintln!(
                "! на релее ждёт сообщение от {}, но этот контакт добавлен старой версией \
                 без ключа подписи. Добавьте его карточку заново.",
                display::contact_name(&contact)
            );
            return Ok(());
        }

        match messaging::open_and_store(self.db, self.me, &contact, &wire, &msg_id) {
            Ok(Incoming::New(text)) => {
                println!(
                    "{} {}: {}",
                    display::now(),
                    display::contact_name(&contact),
                    text
                );
            }
            Ok(Incoming::Duplicate) => {}
            // Подделку, повтор или битое сообщение подтверждаем, чтобы релей перестал его слать.
            Err(e) if messaging::is_message_error(&e) => {
                eprintln!(
                    "! отброшено сообщение, якобы от {}: {e:#}",
                    display::contact_name(&contact)
                );
            }
            // А вот ошибку базы — нет: сообщение придёт снова.
            Err(e) => return Err(e),
        }

        self.conn
            .send(&ClientMessage::Ack { to: from, msg_id })
            .await
    }

    pub async fn close(self) {
        self.conn.close().await;
    }
}
