//! Онлайн-сессия: соединение с релеем + обработка всего, что от него приходит.
//!
//! Любое подключение к релею сразу получает накопившуюся очередь, поэтому
//! входящие сообщения обрабатываются в любой команде (`send`, `retry-outbox`,
//! `listen`), а не только в `listen`.

use crate::display;
use crate::relay_client::RelayConn;
use anyhow::Result;
use crypto_core::Identity;
use protocol::{ClientMessage, Envelope, EnvelopeB64, ServerMessage};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use storage::{Db, Direction, NewMessage, PendingOutgoing};

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
        })
    }

    /// Отправить одно сообщение из исходящей очереди.
    pub async fn send_pending(&mut self, p: &PendingOutgoing) -> Result<()> {
        let envelope: EnvelopeB64 = match serde_json::from_str(&p.envelope_json) {
            Ok(e) => e,
            Err(_) => {
                // Сообщение из старой версии без подписи — релей его не примет.
                let reason = "сохранено старой версией в устаревшем формате — отправьте заново";
                eprintln!("! пропускаю сообщение {} из исходящих: {reason}", p.msg_id);
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
        let Some(sign_pub) = contact.sign_public else {
            eprintln!(
                "! на релее ждёт сообщение от {}, но этот контакт добавлен старой версией \
                 без ключа подписи. Добавьте его карточку заново.",
                display::contact_name(&contact)
            );
            return Ok(());
        };

        let opened = Envelope::try_from(&wire)
            .map_err(anyhow::Error::from)
            .and_then(|env| {
                if env.from != from {
                    anyhow::bail!(
                        "отправитель в конверте не совпадает с отправителем по данным релея"
                    );
                }
                Ok(self.me.decrypt(&env, &sign_pub)?)
            });

        match opened {
            Ok(plaintext) => {
                let text = String::from_utf8_lossy(&plaintext);
                let envelope_json = serde_json::to_string(&wire)?;
                let inserted = self.db.insert_message(&NewMessage {
                    direction: Direction::In,
                    peer_account_id: &from,
                    peer_username: contact.username.as_deref(),
                    plaintext: &text,
                    envelope_json: &envelope_json,
                    msg_id: &msg_id,
                })?;
                if inserted.is_some() {
                    println!(
                        "{} {}: {}",
                        display::now(),
                        display::contact_name(&contact),
                        text
                    );
                }
            }
            Err(e) => {
                // Подделку или битое сообщение подтверждаем, чтобы релей перестал его слать.
                eprintln!(
                    "! отброшено сообщение, якобы от {}: {e:#}",
                    display::contact_name(&contact)
                );
            }
        }

        self.conn
            .send(&ClientMessage::Ack { to: from, msg_id })
            .await
    }

    pub async fn close(self) {
        self.conn.close().await;
    }
}
