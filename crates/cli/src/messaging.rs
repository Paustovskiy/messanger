//! Шифрование и расшифровка через сессии + управление нашими предключами.
//!
//! Каждая операция «прочитать состояние сессии → зашифровать/расшифровать →
//! сохранить состояние и сообщение» выполняется одной транзакцией
//! ([`Db::immediate`]). Поэтому `listen` и `send`, запущенные одновременно,
//! не портят друг другу состояние храповика, а сбой посередине ничего не ломает.

use anyhow::{Context, Result};
use crypto_core::{
    Bundle, CryptoError, Identity, PeerKeys, PrekeySecrets, SessionSet, envelope_id,
    new_one_time_prekey, verify_signed_prekey,
};
use protocol::{
    ClientMessage, Envelope, EnvelopeB64, OneTimePrekeyB64, ProtocolError, SignedPrekey,
    SignedPrekeyB64,
};
use std::time::{SystemTime, UNIX_EPOCH};
use storage::{
    ContactRow, Db, Direction, NewMessage, OwnOneTimePrekey, OwnSignedPrekey, StoredPrekey,
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

/// Ключи собеседника для сессии. Без ключа подписи (контакт из старой версии)
/// безопасно переписываться нельзя.
pub fn peer_keys(c: &ContactRow) -> Result<PeerKeys> {
    let ed25519_pub = c.sign_public.context(
        "контакт добавлен старой версией без ключа подписи; добавьте его карточку заново",
    )?;
    Ok(PeerKeys {
        account_id: c.account_id.clone(),
        x25519_pub: c.public,
        ed25519_pub,
    })
}

/// Предключ из карточки собеседника — запасной вариант без релея.
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

/// Можем ли мы прямо сейчас писать этому контакту без новых предключей.
pub fn can_send_now(db: &Db, peer: &str) -> Result<bool> {
    Ok(match db.load_sessions(peer)? {
        Some(json) => SessionSet::from_json(&json)?.can_send(),
        None => false,
    })
}

/// Зашифровать сообщение и положить его в исходящие.
/// Если сессии ещё нет, она начинается по `bundle` (с релея) или по предключу
/// из карточки. Возвращает `(конверт, msg_id)`.
pub fn seal_and_store(
    db: &Db,
    me: &Identity,
    contact: &ContactRow,
    bundle: Option<Bundle>,
    text: &str,
) -> Result<(EnvelopeB64, String)> {
    let peer = peer_keys(contact)?;
    db.immediate(|| {
        let mut set = load_set(db, &peer.account_id)?;
        if !set.can_send() {
            let bundle = bundle.or_else(|| card_bundle(contact)).context(
                "у собеседника ещё нет предключей: пусть он хоть раз подключится к релею \
                 (`messenger listen`) или пришлёт свежую карточку",
            )?;
            me.start_session(&peer, &bundle, &mut set)
                .context("не удалось начать сессию")?;
        }
        let env = me.seal(&peer, &mut set, text.as_bytes())?;
        let msg_id = envelope_id(&env);
        let wire = EnvelopeB64::from(&env);
        db.save_sessions(&peer.account_id, &set.to_json())?;
        db.insert_message(&NewMessage {
            direction: Direction::Out,
            peer_account_id: &peer.account_id,
            peer_username: contact.username.as_deref(),
            plaintext: text,
            envelope_json: &serde_json::to_string(&wire)?,
            msg_id: &msg_id,
        })?;
        Ok((wire, msg_id))
    })
}

pub enum Incoming {
    New(String),
    Duplicate,
}

/// Проверить, расшифровать и сохранить входящее сообщение.
pub fn open_and_store(
    db: &Db,
    me: &Identity,
    contact: &ContactRow,
    wire: &EnvelopeB64,
    msg_id: &str,
) -> Result<Incoming> {
    let peer = peer_keys(contact)?;
    let env = Envelope::try_from(wire)?;
    db.immediate(|| {
        // Дубль отбрасываем до расшифровки: ключ этого сообщения уже стёрт.
        if db.has_incoming(&peer.account_id, msg_id)? {
            return Ok(Incoming::Duplicate);
        }
        let mut set = load_set(db, &peer.account_id)?;
        let secrets = match env.prekey {
            None => PrekeySecrets::default(),
            Some(p) => PrekeySecrets {
                signed_prekey: db.signed_prekey_secret(p.spk_id)?,
                one_time: match p.opk_id {
                    Some(id) => db.one_time_prekey_secret(id)?,
                    None => None,
                },
                ek_already_used: db.is_ek_used(&peer.account_id, &p.ek_pub)?,
            },
        };
        let opened = me.open(&peer, &mut set, &env, &secrets)?;
        if let Some(ek) = opened.new_session_ek {
            db.mark_ek_used(&peer.account_id, &ek)?;
        }
        if let Some(id) = opened.consumed_one_time {
            // Одноразовый ключ стирается сразу — в этом его смысл.
            db.delete_one_time_prekey(id)?;
        }
        db.save_sessions(&peer.account_id, &set.to_json())?;
        let text = String::from_utf8_lossy(&opened.plaintext).into_owned();
        db.insert_message(&NewMessage {
            direction: Direction::In,
            peer_account_id: &peer.account_id,
            peer_username: contact.username.as_deref(),
            plaintext: &text,
            envelope_json: &serde_json::to_string(wire)?,
            msg_id,
        })?;
        Ok(Incoming::New(text))
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

fn load_set(db: &Db, peer: &str) -> Result<SessionSet> {
    Ok(match db.load_sessions(peer)? {
        Some(json) => SessionSet::from_json(&json)?,
        None => SessionSet::default(),
    })
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
