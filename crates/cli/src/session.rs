//! Онлайн-сессия: соединение с релеем + обработка всего, что от него приходит.
//!
//! Любое подключение к релею сразу получает накопившуюся очередь, поэтому
//! входящие сообщения обрабатываются в любой команде (`send`, `sync`,
//! `listen`), а не только в `listen`. Там же, при каждом подключении, клиент
//! следит за запасом своих предключей на релее, а устройство с ключом
//! аккаунта — ещё и за тем, чтобы на релее лежал актуальный список устройств.

use crate::devices;
use crate::display;
use crate::messaging::{self, DeviceKey, Incoming};
use crate::relay_client::RelayConn;
use anyhow::{Result, bail};
use crypto_core::{Bundle, Identity};
use protocol::{
    ClientMessage, EnvelopeB64, OneTimePrekey, PRIMARY_DEVICE, ServerMessage, SignedDeviceListB64,
    SignedPrekey,
};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use storage::{Db, Direction, OutboxItem};

/// Сколько ждать ответа релея на публикацию списка устройств.
const PUBLISH_TIMEOUT: Duration = Duration::from_secs(10);

/// Текст ошибки, когда ответ на публикацию списка не пришёл: релей мог его принять.
pub const PUBLISH_UNKNOWN: &str =
    "неизвестно, принял ли релей список; проверьте `messenger devices` после sync";

pub enum Step {
    Handled,
    Timeout,
    Closed,
}

/// Входящий конверт от устройства, которого мы пока не знаем: ждёт свежего
/// списка устройств отправителя.
struct Parked {
    from: String,
    from_device: u32,
    msg_id: String,
    envelope: EnvelopeB64,
}

pub struct Session<'a> {
    db: &'a Db,
    me: &'a Identity,
    conn: RelayConn,
    /// ID конвертов, которые релей принял к доставке.
    pub accepted: HashSet<String>,
    /// ID конвертов, получение которых подтвердило устройство-получатель.
    pub acked: HashSet<String>,
    /// ID сообщений, которые стали «доставлено» (✓✓).
    pub delivered: HashSet<String>,
    /// ID конвертов, которые релей отклонил, с причиной.
    pub rejected: HashMap<String, String>,
    /// Ответы на `FetchBundle`: `None` — устройство ещё не публиковало предключи.
    pub bundles: HashMap<DeviceKey, Option<Bundle>>,
    /// Аккаунты, чей список устройств пришёл в этой сессии.
    pub device_lists: HashSet<String>,
    /// Релей выдал всю накопившуюся очередь (пришёл первый `PrekeyStatus`).
    pub synced: bool,
    /// Это устройство отключили от аккаунта.
    pub removed: bool,
    /// Куда шёл конверт: нужно, чтобы убрать недоставляемое из исходящих.
    sent_to: HashMap<String, (String, u32)>,
    parked: Vec<Parked>,
    list_checked: bool,
    /// Список, который мы публикуем и ответа на который ждём (см. `publish_own`).
    publishing: Option<SignedDeviceListB64>,
    /// Итог последней публикации: `Err` — релей отклонил список.
    list_publish: Option<Result<(), String>>,
}

impl<'a> Session<'a> {
    pub async fn open(url: &str, db: &'a Db, me: &'a Identity) -> Result<Self> {
        let conn = RelayConn::connect(url, me).await?;
        Ok(Self {
            db,
            me,
            conn,
            accepted: HashSet::new(),
            acked: HashSet::new(),
            delivered: HashSet::new(),
            rejected: HashMap::new(),
            bundles: HashMap::new(),
            device_lists: HashSet::new(),
            synced: false,
            removed: false,
            sent_to: HashMap::new(),
            parked: Vec::new(),
            list_checked: false,
            publishing: None,
            list_publish: None,
        })
    }

    /// Отправить один конверт из исходящих.
    pub async fn send_outbox(&mut self, item: &OutboxItem) -> Result<()> {
        let envelope: EnvelopeB64 = serde_json::from_str(&item.envelope_json)?;
        self.sent_to.insert(
            item.envelope_id.clone(),
            (item.to_account_id.clone(), item.to_device_id),
        );
        self.conn
            .send(&ClientMessage::Send {
                to: item.to_account_id.clone(),
                to_device: item.to_device_id,
                msg_id: item.envelope_id.clone(),
                envelope,
            })
            .await
    }

    /// Запросить предключи устройства; ответ появится в [`bundles`](Self::bundles).
    pub async fn fetch_bundle(&mut self, account_id: &str, device_id: u32) -> Result<()> {
        self.conn
            .send(&ClientMessage::FetchBundle {
                account_id: account_id.into(),
                device_id,
            })
            .await
    }

    /// Запросить список устройств; ответ отметится в [`device_lists`](Self::device_lists).
    pub async fn fetch_device_list(&mut self, account_id: &str) -> Result<()> {
        self.conn
            .send(&ClientMessage::FetchDeviceList {
                account_id: account_id.into(),
            })
            .await
    }

    async fn publish_device_list(&mut self, list: SignedDeviceListB64) -> Result<()> {
        self.conn
            .send(&ClientMessage::PublishDeviceList { list })
            .await
    }

    /// Опубликовать свой список и дождаться ответа релея. Успех — релей прислал
    /// ровно этот список (`on_device_list` при этом сам его сохранит); ошибка —
    /// релей отклонил список (в том числе как устаревший) или не ответил.
    pub async fn publish_own(&mut self, wire: SignedDeviceListB64) -> Result<()> {
        self.list_publish = None;
        self.publishing = Some(wire.clone());
        let result = self.wait_publish(wire).await;
        self.publishing = None;
        result
    }

    async fn wait_publish(&mut self, wire: SignedDeviceListB64) -> Result<()> {
        self.publish_device_list(wire).await?;
        let deadline = Instant::now() + PUBLISH_TIMEOUT;
        loop {
            match self.list_publish.take() {
                Some(Ok(())) => return Ok(()),
                Some(Err(m)) => bail!("{m}"),
                None => {}
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                bail!("{PUBLISH_UNKNOWN}");
            }
            match self.step(Some(left)).await? {
                Step::Handled => {}
                Step::Timeout => bail!("{PUBLISH_UNKNOWN}"),
                Step::Closed => bail!("релей закрыл соединение; {PUBLISH_UNKNOWN}"),
            }
        }
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
                from_device,
                msg_id,
                envelope,
            } => {
                self.on_deliver(Parked {
                    from,
                    from_device,
                    msg_id,
                    envelope,
                })
                .await?;
            }
            ServerMessage::DeliverAck {
                from,
                from_device,
                msg_id,
            } => {
                if let Some(acked) = self.db.ack_outbox(&from, from_device, &msg_id)? {
                    if acked.newly_delivered {
                        let text = self
                            .db
                            .outgoing_text(&acked.peer_account_id, &acked.message_id)?
                            .unwrap_or_default();
                        println!(
                            "✓✓ доставлено {}: «{}»",
                            display::peer_name(self.db, &acked.peer_account_id),
                            display::preview(&text, 40)
                        );
                        self.delivered.insert(acked.message_id);
                    }
                }
                self.acked.insert(msg_id);
            }
            ServerMessage::Accepted { msg_id } => {
                self.accepted.insert(msg_id);
            }
            ServerMessage::PrekeyStatus {
                has_signed_prekey,
                one_time_left,
                device_list_version,
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
                if !self.list_checked {
                    self.list_checked = true;
                    self.check_own_list(device_list_version).await?;
                }
            }
            ServerMessage::Bundle {
                account_id,
                device_id,
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
                self.bundles.insert((account_id, device_id), bundle);
            }
            ServerMessage::DeviceList { account_id, list } => {
                if let Some(wire) = list.filter(|l| l.account_id == account_id) {
                    let ours = self.publishing.as_ref() == Some(&wire);
                    self.on_device_list(&wire, ours);
                    if ours {
                        self.list_publish = Some(Ok(()));
                    }
                }
                self.device_lists.insert(account_id.clone());
                // Конверты, ждавшие этого списка, — ещё раз.
                let (retry, keep) = std::mem::take(&mut self.parked)
                    .into_iter()
                    .partition(|p| p.from == account_id);
                self.parked = keep;
                for p in retry {
                    self.on_deliver(p).await?;
                }
            }
            ServerMessage::Error {
                message,
                msg_id: Some(id),
            } => {
                if message.contains("no such device") {
                    // Устройство отключили от аккаунта — этот конверт не доставить никогда.
                    if let Some((to, device)) = self.sent_to.get(&id) {
                        self.db.delete_outbox(to, *device, &id)?;
                    }
                } else {
                    eprintln!("релей отклонил сообщение {id}: {message}");
                }
                self.rejected.insert(id, message);
            }
            ServerMessage::Error {
                message,
                msg_id: None,
            } => {
                if message.contains("removed from the account") {
                    self.removed = true;
                    eprintln!("! это устройство отключено от аккаунта");
                } else if self.publishing.is_some() {
                    // Ответ на нашу публикацию списка: его разберёт `publish_own`.
                    let text = if message.contains("only the primary") {
                        "релей старой версии: обновите релей".to_owned()
                    } else {
                        message
                    };
                    self.list_publish = Some(Err(text));
                } else if message.contains("only the primary") {
                    eprintln!("ошибка релея: релей старой версии: обновите релей");
                } else {
                    eprintln!("ошибка релея: {message}");
                }
            }
            ServerMessage::Challenge { .. } | ServerMessage::Authenticated { .. } => {}
        }
        Ok(())
    }

    /// Свой список устройств на релее должен быть актуальным: его по нему
    /// пускают остальные устройства, а собеседники узнают, кому писать.
    /// Устройство с ключом аккаунта публикует свой список, если на релее старее
    /// или пусто, а если там новее (другое устройство с ключом изменило список) —
    /// забирает его. Публикаций «по кругу» нет: публикует только тот, у кого
    /// версия больше, а получивший новый список своей версии уже не повышает.
    async fn check_own_list(&mut self, relay_version: Option<u64>) -> Result<()> {
        let me = self.me.account_id().to_owned();
        let stored = if self.me.device_id() == PRIMARY_DEVICE && self.me.has_account_key() {
            Some(devices::own_list(self.db, self.me)?)
        } else {
            devices::stored(self.db, &me)?
        };
        let local = stored.as_ref().map(|(l, _)| l.version);
        match (stored, relay_version) {
            (_, None) if local.is_none() => {}
            (Some((_, wire)), None) if self.me.has_account_key() => {
                self.publish_device_list(wire).await?;
            }
            (Some((l, wire)), Some(v)) if self.me.has_account_key() && v < l.version => {
                self.publish_device_list(wire).await?;
            }
            (_, Some(v)) if Some(v) > local => self.fetch_device_list(&me).await?,
            // Та же версия: у держателя ключа сверяем содержимое (см. `on_device_list`).
            (_, Some(v)) if Some(v) == local && self.me.has_account_key() => {
                self.fetch_device_list(&me).await?;
            }
            _ => {}
        }
        Ok(())
    }

    fn on_device_list(&mut self, wire: &SignedDeviceListB64, ours: bool) {
        let account = wire.account_id.clone();
        let before = if account == self.me.account_id() {
            devices::stored(self.db, &account)
                .ok()
                .flatten()
                .map(|(l, _)| l.version)
        } else {
            None
        };
        match devices::accept(self.db, self.me, wire) {
            Ok(Some(list)) if account == self.me.account_id() => {
                if let (Some(old), true) = (before, self.me.has_account_key() && !ours) {
                    eprintln!(
                        "! список устройств изменён на другом устройстве с ключом аккаунта \
                         (v{old}→v{}); если это не вы — ключ аккаунта у постороннего",
                        list.version
                    );
                }
                let still_here = list.device(self.me.device_id()).is_some_and(|d| {
                    d.ed25519_pub == self.me.sign_public_bytes()
                        && d.x25519_pub == self.me.x_public_bytes()
                });
                if !still_here {
                    self.removed = true;
                    eprintln!("! это устройство отключено от аккаунта");
                }
            }
            Ok(None) if account == self.me.account_id() && self.me.has_account_key() => {
                if let Ok(Some((l, mine))) = devices::stored(self.db, &account) {
                    if l.version == wire.version && mine != *wire {
                        eprintln!(
                            "! на релее список устройств той же версии v{}, но с другим \
                             содержимым: проверьте `messenger devices`",
                            l.version
                        );
                    }
                }
            }
            Ok(_) => {}
            Err(e) => eprintln!("! список устройств {account} отклонён: {e:#}"),
        }
    }

    async fn on_deliver(&mut self, p: Parked) -> Result<()> {
        let Parked {
            from,
            from_device,
            msg_id,
            envelope,
        } = p;
        // Без нашего подтверждения релей сохранит сообщение и пришлёт ещё раз —
        // поэтому не подтверждаем то, что не смогли сохранить по нашей вине.
        let own = from == self.me.account_id();
        if !own {
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
        }

        let Some(sender) = devices::sender_keys(self.db, self.me, &from, from_device)? else {
            if !self.device_lists.contains(&from) {
                // Новое устройство собеседника (или наше) — узнаем о нём из свежего списка.
                self.fetch_device_list(&from).await?;
                self.parked.push(Parked {
                    from,
                    from_device,
                    msg_id,
                    envelope,
                });
                return Ok(());
            }
            // Даже в свежем списке устройства нет: его уже отключили. Проверить
            // такое сообщение нечем — подтверждаем и выбрасываем.
            eprintln!(
                "! отброшено сообщение от устройства №{from_device} {}: его нет в списке устройств",
                display::peer_name(self.db, &from)
            );
            return self.ack(from, from_device, msg_id).await;
        };

        match messaging::open_and_store(self.db, self.me, &sender, &envelope, &msg_id) {
            Ok(Incoming::New {
                peer,
                direction: Direction::In,
                text,
            }) => println!(
                "{} {}: {}",
                display::now(),
                display::peer_name(self.db, &peer),
                text
            ),
            Ok(Incoming::New { peer, text, .. }) => println!(
                "{} я → {} (с другого устройства): {}",
                display::now(),
                display::peer_name(self.db, &peer),
                text
            ),
            Ok(Incoming::Duplicate) => {}
            // Подделку, повтор или битое сообщение подтверждаем, чтобы релей перестал его слать.
            Err(e) if messaging::is_message_error(&e) => {
                eprintln!(
                    "! отброшено сообщение, якобы от {}: {e:#}",
                    display::peer_name(self.db, &from)
                );
            }
            // А вот ошибку базы — нет: сообщение придёт снова.
            Err(e) => return Err(e),
        }
        self.ack(from, from_device, msg_id).await
    }

    async fn ack(&mut self, to: String, to_device: u32, msg_id: String) -> Result<()> {
        self.conn
            .send(&ClientMessage::Ack {
                to,
                to_device,
                msg_id,
            })
            .await
    }

    pub async fn close(self) {
        self.conn.close().await;
    }
}
