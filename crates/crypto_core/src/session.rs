//! Сессии: X3DH (первое знакомство) + Double Ratchet (переписка).
//!
//! X3DH — по спецификации Signal (<https://signal.org/docs/specifications/x3dh/>):
//! инициатор берёт подписанный предключ собеседника (и, если есть, одноразовый),
//! делает три-четыре Диффи — Хеллмана со своим постоянным и свежим одноразовым
//! ключом и получает общий секрет. Собеседник может быть офлайн: всё нужное
//! для того же вычисления придёт ему в заголовке первого сообщения.
//!
//! С одним собеседником может быть несколько сессий: он переустановил клиент,
//! или оба начали переписку одновременно. Принимаем через любую из последних
//! [`MAX_SESSIONS`], а отправляем через текущую. Текущая меняется только когда
//! появляется новая сессия, и правило детерминированное:
//!
//! * собеседник начал новую сессию — она становится текущей;
//! * но если мы сами только что начали свою и ещё не получили ответа
//!   (одновременный старт), побеждает сессия того, чей `account_id` меньше.
//!   Обе стороны считают одинаково и сходятся без лишних сообщений.
//!
//! Запоздавшее письмо из старой сессии читается, но текущую не меняет —
//! иначе один задержавшийся конверт переключил бы нас на заброшенную сессию.

use crate::ratchet::{Ratchet, dh};
use crate::{CryptoError, Identity, verify_signature};
use hkdf::Hkdf;
use protocol::{
    Envelope, MAX_PLAINTEXT_LEN, OneTimePrekey, PreKeyHeader, SignedPrekey, envelope_header_bytes,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// Сколько сессий с одним собеседником помним.
pub const MAX_SESSIONS: usize = 5;

const INFO_X3DH: &[u8] = b"messenger/x3dh/v1";
const DOMAIN_AD: &[u8] = b"messenger/x3dh-ad/v1";

/// Публичные ключи собеседника из *нашей* базы контактов.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerKeys {
    pub account_id: String,
    /// Постоянный X25519-ключ (identity key).
    pub x25519_pub: [u8; 32],
    /// Ключ подписи Ed25519.
    pub ed25519_pub: [u8; 32],
}

/// Предключи собеседника, по которым начинаем сессию.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    pub signed_prekey: SignedPrekey,
    pub one_time: Option<OneTimePrekey>,
}

/// Наши секретные предключи, которые понадобились для первого сообщения.
/// Их достаёт из базы вызывающий код — по `spk_id`/`opk_id` из заголовка.
#[derive(Debug, Clone, Default)]
pub struct PrekeySecrets {
    pub signed_prekey: Option<[u8; 32]>,
    pub one_time: Option<[u8; 32]>,
    /// Этот `ek` уже встречался: повтор старого первого сообщения.
    pub ek_already_used: bool,
}

/// Результат открытия конверта.
#[derive(Debug)]
pub struct Opened {
    pub plaintext: Vec<u8>,
    /// Создана новая сессия по этому `ek` — его нужно запомнить как использованный.
    pub new_session_ek: Option<[u8; 32]>,
    /// Израсходован одноразовый предключ — его нужно удалить.
    pub consumed_one_time: Option<u32>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Session {
    ratchet: Ratchet,
    /// Associated data из X3DH: ключи и ID обеих сторон.
    ad: Vec<u8>,
    /// Заголовок X3DH, который инициатор прикладывает к сообщениям,
    /// пока не получит первый ответ.
    pending_prekey: Option<PendingPrekey>,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
struct PendingPrekey {
    ek_pub: [u8; 32],
    spk_id: u32,
    opk_id: Option<u32>,
}

/// Все сессии с одним собеседником. Хранится в базе как непрозрачный JSON.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SessionSet {
    /// `[0]` — текущая.
    sessions: Vec<Session>,
}

impl std::fmt::Debug for SessionSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionSet")
            .field("sessions", &self.sessions.len())
            .finish()
    }
}

impl SessionSet {
    pub fn from_json(s: &str) -> Result<Self, CryptoError> {
        serde_json::from_str(s).map_err(|_| CryptoError::CorruptState)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("session state is always serializable")
    }

    /// Есть ли сессия, через которую можно отправлять.
    pub fn can_send(&self) -> bool {
        self.sessions.first().is_some_and(|s| s.ratchet.can_send())
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    fn push_front(&mut self, s: Session) {
        self.sessions.insert(0, s);
        self.sessions.truncate(MAX_SESSIONS);
    }

    /// Положить сессию, созданную собеседником, с учётом одновременного старта.
    fn insert_incoming(&mut self, s: Session, peer_wins_tie: bool) {
        let our_unanswered_start = self
            .sessions
            .first()
            .is_some_and(|c| c.pending_prekey.is_some());
        if our_unanswered_start && !peer_wins_tie {
            self.sessions.insert(1, s);
            self.sessions.truncate(MAX_SESSIONS);
        } else {
            self.push_front(s);
        }
    }
}

/// X3DH associated data: инициатор, затем ответчик.
fn x3dh_ad(
    initiator: &str,
    initiator_ik: &[u8; 32],
    responder: &str,
    responder_ik: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(DOMAIN_AD.len() + 64 + initiator.len() + responder.len() + 16);
    out.extend_from_slice(DOMAIN_AD);
    out.extend_from_slice(initiator_ik);
    out.extend_from_slice(responder_ik);
    for id in [initiator, responder] {
        out.extend_from_slice(&(id.len() as u64).to_le_bytes());
        out.extend_from_slice(id.as_bytes());
    }
    out
}

fn x3dh_kdf(dhs: &[[u8; 32]]) -> [u8; 32] {
    // Как в спецификации: 32 байта 0xFF перед DH-выходами для X25519.
    let mut ikm = vec![0xFFu8; 32];
    for d in dhs {
        ikm.extend_from_slice(d);
    }
    let mut sk = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&[0u8; 32]), &ikm)
        .expand(INFO_X3DH, &mut sk)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    sk
}

/// Проверить подпись предключа ключом владельца.
pub fn verify_signed_prekey(
    owner_ed25519: &[u8; 32],
    spk: &SignedPrekey,
) -> Result<(), CryptoError> {
    if verify_signature(
        owner_ed25519,
        &SignedPrekey::signing_bytes(spk.id, &spk.public),
        &spk.sig,
    ) {
        Ok(())
    } else {
        Err(CryptoError::BadSignature)
    }
}

impl Identity {
    /// Выпустить подписанный предключ: `(секрет, публичная часть с подписью)`.
    pub fn new_signed_prekey(&self, id: u32) -> ([u8; 32], SignedPrekey) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret).to_bytes();
        let sig = self.sign(&SignedPrekey::signing_bytes(id, &public));
        (secret.to_bytes(), SignedPrekey { id, public, sig })
    }

    /// Начать новую сессию с собеседником (X3DH, сторона инициатора).
    /// Новая сессия становится текущей.
    pub fn start_session(
        &self,
        peer: &PeerKeys,
        bundle: &Bundle,
        sessions: &mut SessionSet,
    ) -> Result<(), CryptoError> {
        // Предключ должен быть подписан ключом собеседника из НАШЕЙ базы —
        // так подменить его не сможет даже релей.
        verify_signed_prekey(&peer.ed25519_pub, &bundle.signed_prekey)?;

        let ek = StaticSecret::random_from_rng(OsRng);
        let ek_secret = ek.to_bytes();
        let ek_pub = PublicKey::from(&ek).to_bytes();
        let spk = bundle.signed_prekey.public;

        let mut dhs = vec![
            dh(&self.x_secret_bytes(), &spk)?,
            dh(&ek_secret, &peer.x25519_pub)?,
            dh(&ek_secret, &spk)?,
        ];
        if let Some(opk) = &bundle.one_time {
            dhs.push(dh(&ek_secret, &opk.public)?);
        }
        let sk = x3dh_kdf(&dhs);

        sessions.push_front(Session {
            ratchet: Ratchet::init_initiator(sk, spk)?,
            ad: x3dh_ad(
                self.account_id(),
                &self.x_public_bytes(),
                &peer.account_id,
                &peer.x25519_pub,
            ),
            pending_prekey: Some(PendingPrekey {
                ek_pub,
                spk_id: bundle.signed_prekey.id,
                opk_id: bundle.one_time.map(|k| k.id),
            }),
        });
        Ok(())
    }

    /// Зашифровать сообщение через текущую сессию и подписать конверт.
    pub fn seal(
        &self,
        peer: &PeerKeys,
        sessions: &mut SessionSet,
        plaintext: &[u8],
    ) -> Result<Envelope, CryptoError> {
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(CryptoError::MessageTooLarge(plaintext.len()));
        }
        protocol::check_id(&peer.account_id, "to")?;
        let session = sessions
            .sessions
            .first_mut()
            .ok_or(CryptoError::NoSession)?;
        if !session.ratchet.can_send() {
            return Err(CryptoError::NoSession);
        }

        let header = session.ratchet.next_header();
        let prekey = session.pending_prekey.map(|p| PreKeyHeader {
            ek_pub: p.ek_pub,
            spk_id: p.spk_id,
            opk_id: p.opk_id,
        });
        let header_bytes = envelope_header_bytes(
            self.account_id(),
            &peer.account_id,
            prekey.as_ref(),
            &header,
        );
        let aad = [session.ad.as_slice(), &header_bytes].concat();
        let body = session.ratchet.encrypt(plaintext, &aad)?;

        let mut env = Envelope {
            from: self.account_id().to_owned(),
            to: peer.account_id.clone(),
            prekey,
            header,
            body,
            sig: [0; 64],
        };
        env.sig = self.sign(&env.signing_bytes());
        Ok(env)
    }

    /// Проверить подпись и расшифровать конверт.
    ///
    /// `prekeys` нужны, только если это первое сообщение новой сессии
    /// (`env.prekey.is_some()`) — вызывающий код достаёт их из базы по ID.
    /// При ошибке `sessions` не меняются.
    pub fn open(
        &self,
        peer: &PeerKeys,
        sessions: &mut SessionSet,
        env: &Envelope,
        prekeys: &PrekeySecrets,
    ) -> Result<Opened, CryptoError> {
        if env.to != self.account_id() {
            return Err(CryptoError::WrongRecipient(env.to.clone()));
        }
        if env.from != peer.account_id {
            return Err(CryptoError::BadSignature);
        }
        crate::verify_envelope(env, &peer.ed25519_pub)?;
        let header_bytes = env.header_bytes();

        // 1. Одна из уже известных сессий.
        for idx in 0..sessions.sessions.len() {
            let mut s = sessions.sessions[idx].clone();
            let aad = [s.ad.as_slice(), &header_bytes].concat();
            if let Ok(plaintext) = s.ratchet.decrypt(&env.header, &env.body, &aad) {
                // Собеседник ответил — значит, X3DH-заголовок ему больше не нужен.
                s.pending_prekey = None;
                sessions.sessions[idx] = s;
                return Ok(Opened {
                    plaintext,
                    new_session_ek: None,
                    consumed_one_time: None,
                });
            }
        }

        // 2. Первое сообщение новой сессии (X3DH, сторона ответчика).
        let Some(pk) = env.prekey else {
            return Err(CryptoError::NoSession);
        };
        if prekeys.ek_already_used {
            return Err(CryptoError::Replay);
        }
        let spk_secret = prekeys.signed_prekey.ok_or(CryptoError::UnknownPrekey)?;
        let opk_secret = match pk.opk_id {
            Some(_) => Some(prekeys.one_time.ok_or(CryptoError::UnknownPrekey)?),
            None => None,
        };

        let mut dhs = vec![
            dh(&spk_secret, &peer.x25519_pub)?,
            dh(&self.x_secret_bytes(), &pk.ek_pub)?,
            dh(&spk_secret, &pk.ek_pub)?,
        ];
        if let Some(opk) = opk_secret {
            dhs.push(dh(&opk, &pk.ek_pub)?);
        }
        let sk = x3dh_kdf(&dhs);

        let mut s = Session {
            ratchet: Ratchet::init_responder(sk, spk_secret),
            ad: x3dh_ad(
                &peer.account_id,
                &peer.x25519_pub,
                self.account_id(),
                &self.x_public_bytes(),
            ),
            pending_prekey: None,
        };
        let aad = [s.ad.as_slice(), &header_bytes].concat();
        let plaintext = s.ratchet.decrypt(&env.header, &env.body, &aad)?;
        sessions.insert_incoming(s, peer.account_id.as_str() < self.account_id());
        Ok(Opened {
            plaintext,
            new_session_ek: Some(pk.ek_pub),
            consumed_one_time: pk.opk_id,
        })
    }
}

/// Новый одноразовый предключ: `(секрет, публичная часть)`.
pub fn new_one_time_prekey(id: u32) -> ([u8; 32], OneTimePrekey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret).to_bytes();
    (secret.to_bytes(), OneTimePrekey { id, public })
}
