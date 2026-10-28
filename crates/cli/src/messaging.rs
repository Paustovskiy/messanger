//! Шифрование и расшифровка через сессии + управление нашими предключами.
//!
//! Каждая операция «прочитать состояние сессии → зашифровать/расшифровать →
//! сохранить состояние и сообщение» выполняется одной транзакцией
//! ([`Db::immediate`]). Поэтому `listen` и `send`, запущенные одновременно,
//! не портят друг другу состояние храповика, а сбой посередине ничего не ломает.

use anyhow::{Context, Result, bail};
use crypto_core::{
    Bundle, CryptoError, Identity, PeerKeys, PrekeySecrets, SessionSet, envelope_id,
    new_one_time_prekey, verify_signed_prekey,
};
use protocol::{
    ClientMessage, Content, Envelope, EnvelopeB64, OneTimePrekeyB64, PRIMARY_DEVICE, ProtocolError,
    SignedPrekey, SignedPrekeyB64,
};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use storage::{
    ContactRow, Db, Direction, NewMessage, OutboxItem, OwnOneTimePrekey, OwnSignedPrekey,
    StoredPrekey,
};

/// Как часто менять подписанный предключ.
const SIGNED_PREKEY_ROTATE_SECS: i64 = 7 * 24 * 3600;
/// Сколько хранить старые подписанные предключи: релей держит сообщения до
/// 30 дней, плюс запас на ротацию.
const SIGNED_PREKEY_KEEP_SECS: i64 = 40 * 24 * 3600;
/// Когда одноразовых предключей на релее меньше этого — пополняем.
const ONE_TIME_LOW_WATER: u32 = 20;
/// Сколько одноразовых предключей добавлять за раз.
const ONE_TIME_BATCH: u32 = 50;

/// Предключ из карточки собеседника — запасной вариант без релея
/// (только для его основного устройства: карточку выдаёт оно).
pub fn card_bundle(c: &ContactRow) -> Option<Bundle> {
    c.signed_prekey.map(|k| Bundle {
        signed_prekey: SignedPrekey {
            id: k.id,
            public: k.public,
            sig: k.sig,
        },
        one_time: None,
    })
}

/// Проверить предключ из карточки и превратить в запись для базы.
pub fn verified_card_prekey(owner_ed25519: &[u8; 32], k: &SignedPrekeyB64) -> Result<StoredPrekey> {
    let spk = SignedPrekey::try_from(k)?;
    verify_signed_prekey(owner_ed25519, &spk)
        .context("предключ в карточке подписан не владельцем")?;
    Ok(StoredPrekey {
        id: spk.id,
        public: spk.public,
        sig: spk.sig,
    })
}

/// Можем ли мы прямо сейчас писать этому устройству без новых предключей.
pub fn can_send_now(db: &Db, peer: &PeerKeys) -> Result<bool> {
    Ok(load_set(db, peer)?.can_send())
}

/// Адрес устройства — ключ для словарей.
pub type DeviceKey = (String, u32);

pub fn device_key(k: &PeerKeys) -> DeviceKey {
    (k.account_id.clone(), k.device_id)
}

/// Результат шифрования одного сообщения для всех устройств.
pub struct Sealed {
    /// ID сообщения (общий для всех его конвертов).
    pub message_id: String,
    /// Конверты — уже лежат в исходящих.
    pub items: Vec<OutboxItem>,
    /// Устройства, которым зашифровать не удалось, и почему.
    pub skipped: Vec<(PeerKeys, String)>,
}

/// Зашифровать сообщение для каждого устройства собеседника (`recipients`)
/// и копию для остальных своих устройств (`own`), сохранить сообщение и
/// положить конверты в исходящие — одной транзакцией.
///
/// Если с устройством ещё нет сессии, она начинается по предключам из
/// `bundles` (свежие, с релея) или — для основного устройства собеседника —
/// по предключу из его карточки.
pub fn seal_message(
    db: &Db,
    me: &Identity,
    contact: &ContactRow,
    recipients: &[PeerKeys],
    own: &[PeerKeys],
    bundles: &HashMap<DeviceKey, Option<Bundle>>,
    text: &str,
) -> Result<Sealed> {
    let message_id = hex(&crypto_core::random_bytes::<16>());
    let to_peer = Content::Text {
        id: message_id.clone(),
        body: text.into(),
    }
    .to_bytes();
    let copy = Content::Sent {
        id: message_id.clone(),
        to: contact.account_id.clone(),
        body: text.into(),
    }
    .to_bytes();

    db.immediate(|| {
        let mut items = vec![];
        let mut skipped = vec![];
        let targets = recipients
            .iter()
            .map(|k| (k, &to_peer))
            .chain(own.iter().map(|k| (k, &copy)));
        for (peer, content) in targets {
            let mut set = load_set(db, peer)?;
            if !set.can_send() {
                let bundle = bundles
                    .get(&device_key(peer))
                    .cloned()
                    .flatten()
                    .or_else(|| {
                        (peer.account_id == contact.account_id && peer.device_id == PRIMARY_DEVICE)
                            .then(|| card_bundle(contact))
                            .flatten()
                    });
                let Some(bundle) = bundle else {
                    skipped.push((
                        peer.clone(),
                        "нет предключей: устройство ещё ни разу не подключалось к релею".into(),
                    ));
                    continue;
                };
                if let Err(e) = me.start_session(peer, &bundle, &mut set) {
                    skipped.push((peer.clone(), format!("не удалось начать сессию: {e}")));
                    continue;
                }
            }
            let env = me.seal(peer, &mut set, content)?;
            db.save_sessions(&peer.account_id, peer.device_id, &set.to_json())?;
            items.push(OutboxItem {
                message_id: message_id.clone(),
                peer_account_id: contact.account_id.clone(),
                to_account_id: peer.account_id.clone(),
                to_device_id: peer.device_id,
                envelope_id: envelope_id(&env),
                envelope_json: serde_json::to_string(&EnvelopeB64::from(&env))?,
            });
        }
        if !items.iter().any(|i| i.to_account_id == contact.account_id) {
            bail!(
                "у собеседника ещё нет предключей: пусть он хоть раз подключится к релею \
                 (`messenger listen`) или пришлёт свежую карточку"
            );
        }
        db.insert_message(&NewMessage {
            direction: Direction::Out,
            peer_account_id: &contact.account_id,
            peer_username: contact.username.as_deref(),
            plaintext: text,
            envelope_json: "",
            msg_id: &message_id,
        })?;
        for item in &items {
            db.insert_outbox(item)?;
        }
        Ok(Sealed {
            message_id: message_id.clone(),
            items,
            skipped,
        })
    })
}

pub enum Incoming {
    /// Новое сообщение. `Out` — копия того, что мы сами отправили `peer`
    /// с другого своего устройства.
    New {
        peer: String,
        direction: Direction,
        text: String,
    },
    Duplicate,
}

fn bad_content(why: &str) -> anyhow::Error {
    ProtocolError::InvalidContent(why.into()).into()
}

/// Проверить, расшифровать и сохранить входящий конверт от устройства `sender`.
pub fn open_and_store(
    db: &Db,
    me: &Identity,
    sender: &PeerKeys,
    wire: &EnvelopeB64,
    envelope_id: &str,
) -> Result<Incoming> {
    let env = Envelope::try_from(wire)?;
    let (from, device) = (sender.account_id.as_str(), sender.device_id);
    db.immediate(|| {
        // Дубль отбрасываем до расшифровки: ключ этого сообщения уже стёрт.
        if db.is_envelope_seen(from, device, envelope_id)? {
            return Ok(Incoming::Duplicate);
        }
        let mut set = load_set(db, sender)?;
        let secrets = match env.prekey {
            None => PrekeySecrets::default(),
            Some(p) => PrekeySecrets {
                signed_prekey: db.signed_prekey_secret(p.spk_id)?,
                one_time: match p.opk_id {
                    Some(id) => db.one_time_prekey_secret(id)?,
                    None => None,
                },
                ek_already_used: db.is_ek_used(from, device, &p.ek_pub)?,
            },
        };
        let opened = me.open(sender, &mut set, &env, &secrets)?;
        let own_device = from == me.account_id();
        let (direction, peer, id, text) = match Content::from_bytes(&opened.plaintext)? {
            Content::Text { .. } if own_device => {
                return Err(bad_content("own device sent a text instead of a copy"));
            }
            Content::Text { id, body } => (Direction::In, from.to_owned(), id, body),
            // Копию «я отправил» принимаем только от своих устройств: иначе
            // кто угодно мог бы приписать нам сообщения.
            Content::Sent { id, to, body } if own_device => (Direction::Out, to, id, body),
            Content::Sent { .. } => return Err(bad_content("a copy from a foreign account")),
        };

        if let Some(ek) = opened.new_session_ek {
            db.mark_ek_used(from, device, &ek)?;
        }
        if let Some(id) = opened.consumed_one_time {
            // Одноразовый ключ стирается сразу — в этом его смысл.
            db.delete_one_time_prekey(id)?;
        }
        db.save_sessions(from, device, &set.to_json())?;
        db.mark_envelope_seen(from, device, envelope_id)?;

        let username = db.get_contact(&peer)?.and_then(|c| c.username);
        let inserted = db.insert_message(&NewMessage {
            direction,
            peer_account_id: &peer,
            peer_username: username.as_deref(),
            plaintext: &text,
            envelope_json: &serde_json::to_string(wire)?,
            msg_id: &id,
        })?;
        Ok(match inserted {
            Some(_) => Incoming::New {
                peer,
                direction,
                text,
            },
            None => Incoming::Duplicate,
        })
    })
}

/// Ошибка относится к самому сообщению (подделка, повтор, мусор), а не к нам
/// (база, сеть)? Такие сообщения можно подтверждать и выбрасывать.
pub fn is_message_error(e: &anyhow::Error) -> bool {
    e.chain()
        .any(|c| c.is::<CryptoError>() || c.is::<ProtocolError>())
}

/// Убедиться, что есть свежий подписанный предключ. Возвращает его и признак
/// того, что он только что создан (значит, его надо опубликовать).
pub fn ensure_signed_prekey(db: &Db, me: &Identity) -> Result<(OwnSignedPrekey, bool)> {
    db.immediate(|| {
        let now = unix_now();
        if let Some(current) = db.current_signed_prekey()? {
            if now - current.created_at < SIGNED_PREKEY_ROTATE_SECS {
                return Ok((current, false));
            }
        }
        let id = db.next_signed_prekey_id()?;
        let (secret, spk) = me.new_signed_prekey(id);
        let row = OwnSignedPrekey {
            id,
            secret,
            public: spk.public,
            sig: spk.sig,
            created_at: now,
        };
        db.insert_signed_prekey(&row)?;
        db.prune_signed_prekeys(now - SIGNED_PREKEY_KEEP_SECS)?;
        Ok((row, true))
    })
}

/// Текущий подписанный предключ в виде для карточки и релея.
pub fn signed_prekey_wire(k: &OwnSignedPrekey) -> SignedPrekeyB64 {
    SignedPrekeyB64::from(&SignedPrekey {
        id: k.id,
        public: k.public,
        sig: k.sig,
    })
}

/// Что опубликовать на релее, судя по его отчёту о наших предключах.
pub fn prekeys_to_publish(
    db: &Db,
    me: &Identity,
    relay_has_signed: bool,
    relay_one_time_left: u32,
) -> Result<Option<ClientMessage>> {
    let (spk, rotated) = ensure_signed_prekey(db, me)?;
    let need_one_time = relay_one_time_left < ONE_TIME_LOW_WATER;
    if relay_has_signed && !rotated && !need_one_time {
        return Ok(None);
    }

    let one_time = if need_one_time {
        db.immediate(|| {
            let first = db.next_one_time_prekey_id()?;
            let keys: Vec<OwnOneTimePrekey> = (first..first + ONE_TIME_BATCH)
                .map(|id| {
                    let (secret, public) = new_one_time_prekey(id);
                    OwnOneTimePrekey {
                        id,
                        secret,
                        public: public.public,
                    }
                })
                .collect();
            db.insert_one_time_prekeys(&keys)?;
            Ok(keys
                .iter()
                .map(|k| {
                    OneTimePrekeyB64::from(&protocol::OneTimePrekey {
                        id: k.id,
                        public: k.public,
                    })
                })
                .collect())
        })?
    } else {
        vec![]
    };

    Ok(Some(ClientMessage::PublishPrekeys {
        signed_prekey: signed_prekey_wire(&spk),
        one_time,
    }))
}

fn load_set(db: &Db, peer: &PeerKeys) -> Result<SessionSet> {
    Ok(match db.load_sessions(&peer.account_id, peer.device_id)? {
        Some(json) => SessionSet::from_json(&json)?,
        None => SessionSet::default(),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
