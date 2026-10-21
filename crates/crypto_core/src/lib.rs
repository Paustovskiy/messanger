//! Криптография мессенджера.
//!
//! У каждого аккаунта две пары ключей:
//! * **X25519** — чтобы ему можно было что-то зашифровать;
//! * **Ed25519** — чтобы подписывать карточку контакта, сообщения и вход на релей.
//!
//! Шифрование сообщения (по сути ECIES + подпись):
//! 1. отправитель генерирует одноразовую X25519-пару и делает DH с постоянным
//!    X25519-ключом получателя;
//! 2. из общего секрета через HKDF-SHA256 выводится ключ ChaCha20-Poly1305
//!    (в `info` входят оба публичных ключа);
//! 3. заголовок (`from`, `to`, `eph_pub`) идёт в AEAD как associated data;
//! 4. весь конверт подписывается Ed25519-ключом отправителя.
//!
//! Чего здесь пока **нет** (см. README): forward secrecy для получателя
//! (Double Ratchet / X3DH) и защиты от повторной отправки старого конверта —
//! последнее закрывается на уровне приложения уникальным `msg_id`.

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use protocol::{ContactCardPayload, ContactCardV2, Envelope, MAX_PLAINTEXT_LEN, ProtocolError};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

const HKDF_INFO_AEAD: &[u8] = b"messenger/aead/v1";
const FINGERPRINT_DOMAIN: &[u8] = b"messenger/fingerprint/v1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("message is too large ({0} bytes, max {MAX_PLAINTEXT_LEN})")]
    MessageTooLarge(usize),
    #[error("envelope is addressed to `{0}`, not to us")]
    WrongRecipient(String),
    #[error("invalid signature")]
    BadSignature,
    #[error("peer public key is invalid (low-order point)")]
    InvalidPeerKey,
    #[error("decryption failed: message is corrupted or not for us")]
    DecryptFailed,
    #[error("account_id does not match the signing key")]
    AccountIdMismatch,
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

/// Локальная личность: `account_id` + обе пары ключей.
#[derive(Clone)]
pub struct Identity {
    account_id: String,
    x_secret: StaticSecret,
    x_public: PublicKey,
    sign: SigningKey,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Секреты в логи не попадают никогда.
        f.debug_struct("Identity")
            .field("account_id", &self.account_id)
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// Новая личность, у которой `account_id` выведен из ключа подписи
    /// (см. [`account_id_for`]). Так и создаются новые аккаунты.
    pub fn generate_new() -> Self {
        let x_secret = StaticSecret::random_from_rng(OsRng);
        let sign = SigningKey::generate(&mut OsRng);
        let account_id = account_id_for(&sign.verifying_key().to_bytes());
        Self::from_keys(account_id, x_secret, sign)
    }

    /// Личность со свежими ключами и произвольным `account_id`.
    /// Нужна для тестов и для старых аккаунтов с UUID.
    pub fn generate(account_id: impl Into<String>) -> Self {
        let x_secret = StaticSecret::random_from_rng(OsRng);
        let sign = SigningKey::generate(&mut OsRng);
        Self::from_keys(account_id.into(), x_secret, sign)
    }

    /// Восстановить личность из сохранённых секретов.
    pub fn from_secrets(
        account_id: impl Into<String>,
        x_secret_bytes: [u8; 32],
        sign_secret_bytes: [u8; 32],
    ) -> Self {
        Self::from_keys(
            account_id.into(),
            StaticSecret::from(x_secret_bytes),
            SigningKey::from_bytes(&sign_secret_bytes),
        )
    }

    fn from_keys(account_id: String, x_secret: StaticSecret, sign: SigningKey) -> Self {
        let x_public = PublicKey::from(&x_secret);
        Self {
            account_id,
            x_secret,
            x_public,
            sign,
        }
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn x_secret_bytes(&self) -> [u8; 32] {
        self.x_secret.to_bytes()
    }

    pub fn x_public_bytes(&self) -> [u8; 32] {
        self.x_public.to_bytes()
    }

    pub fn sign_secret_bytes(&self) -> [u8; 32] {
        self.sign.to_bytes()
    }

    pub fn sign_public_bytes(&self) -> [u8; 32] {
        self.sign.verifying_key().to_bytes()
    }

    /// Отпечаток собственных ключей — чтобы сверить его с собеседником голосом.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.x_public_bytes(), &self.sign_public_bytes())
    }

    /// Подписать произвольные байты.
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        self.sign.sign(data).to_bytes()
    }

    /// Выпустить самоподписанную карточку контакта.
    pub fn contact_card(&self, username: Option<String>) -> ContactCardV2 {
        let payload = ContactCardPayload {
            account_id: self.account_id.clone(),
            username,
            x25519_pub: self.x_public_bytes(),
            ed25519_pub: self.sign_public_bytes(),
        };
        let sig = self.sign(&payload.signing_bytes());
        ContactCardV2::from_parts(&payload, sig)
    }

    /// Зашифровать `plaintext` для `to` (его X25519-ключ — `peer_x_pub`)
    /// и подписать конверт.
    pub fn encrypt_to(
        &self,
        to: &str,
        peer_x_pub: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<Envelope, CryptoError> {
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(CryptoError::MessageTooLarge(plaintext.len()));
        }
        protocol::check_id(to, "to")?;

        let peer = PublicKey::from(*peer_x_pub);
        let eph_secret = EphemeralSecret::random_from_rng(OsRng);
        let eph_pub = PublicKey::from(&eph_secret).to_bytes();

        let shared = eph_secret.diffie_hellman(&peer);
        if !shared.was_contributory() {
            return Err(CryptoError::InvalidPeerKey);
        }
        let aead = aead_for(shared.as_bytes(), &eph_pub, peer_x_pub);

        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let aad = protocol::envelope_aad(&self.account_id, to, &eph_pub);
        let body = aead
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("ChaCha20-Poly1305 encryption cannot fail for in-memory buffers");

        let sig_bytes =
            protocol::envelope_signing_bytes(&self.account_id, to, &eph_pub, &nonce, &body);
        let sig = self.sign(&sig_bytes);

        Ok(Envelope {
            from: self.account_id.clone(),
            to: to.to_owned(),
            eph_pub,
            nonce,
            body,
            sig,
        })
    }

    /// Проверить подпись отправителя и расшифровать конверт.
    ///
    /// `sender_sign_pub` — Ed25519-ключ отправителя из *нашей* базы контактов,
    /// а не из самого конверта: иначе подпись ничего бы не доказывала.
    pub fn decrypt(
        &self,
        env: &Envelope,
        sender_sign_pub: &[u8; 32],
    ) -> Result<Vec<u8>, CryptoError> {
        if env.to != self.account_id {
            return Err(CryptoError::WrongRecipient(env.to.clone()));
        }
        verify_envelope(env, sender_sign_pub)?;

        let sender_eph = PublicKey::from(env.eph_pub);
        let shared = self.x_secret.diffie_hellman(&sender_eph);
        if !shared.was_contributory() {
            return Err(CryptoError::InvalidPeerKey);
        }
        let aead = aead_for(shared.as_bytes(), &env.eph_pub, &self.x_public_bytes());

        aead.decrypt(
            Nonce::from_slice(&env.nonce),
            Payload {
                msg: &env.body,
                aad: &env.aad(),
            },
        )
        .map_err(|_| CryptoError::DecryptFailed)
    }
}

/// Проверить подпись конверта (без расшифровки). Этим пользуется и релей.
pub fn verify_envelope(env: &Envelope, sender_sign_pub: &[u8; 32]) -> Result<(), CryptoError> {
    if verify_signature(sender_sign_pub, &env.signing_bytes(), &env.sig) {
        Ok(())
    } else {
        Err(CryptoError::BadSignature)
    }
}

/// Проверка Ed25519-подписи в строгом режиме (без «мягких» некононических форм).
pub fn verify_signature(sign_pub: &[u8; 32], data: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(sign_pub) else {
        return false;
    };
    vk.verify_strict(data, &Signature::from_bytes(sig)).is_ok()
}

/// Проверенная карточка контакта.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedContact {
    pub account_id: String,
    pub username: Option<String>,
    pub x25519_pub: [u8; 32],
    pub ed25519_pub: [u8; 32],
}

impl VerifiedContact {
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.x25519_pub, &self.ed25519_pub)
    }
}

/// Проверить самоподпись карточки контакта.
///
/// Это доказывает, что карточку выпустил владелец ключа Ed25519, но **не** то,
/// что этот ключ принадлежит тому, кому вы думаете. Для этого сверяйте
/// отпечатки (`fingerprint`) по независимому каналу.
pub fn verify_contact_card(card: &ContactCardV2) -> Result<VerifiedContact, CryptoError> {
    let (payload, sig) = card.parts()?;
    if !verify_signature(&payload.ed25519_pub, &payload.signing_bytes(), &sig) {
        return Err(CryptoError::BadSignature);
    }
    check_account_id(&payload.account_id, &payload.ed25519_pub)?;
    Ok(VerifiedContact {
        account_id: payload.account_id,
        username: payload.username,
        x25519_pub: payload.x25519_pub,
        ed25519_pub: payload.ed25519_pub,
    })
}

/// `account_id`, выведенный из ключа подписи: 32 hex-символа
/// (первые 16 байт `SHA-256("messenger/account-id/v1" ‖ ed25519_pub)`).
///
/// Такой ID нельзя «занять» чужим ключом: любой, включая релей, может
/// проверить, что ID и ключ подходят друг к другу.
pub fn account_id_for(ed25519_pub: &[u8; 32]) -> String {
    let digest = Sha256::new()
        .chain_update(b"messenger/account-id/v1")
        .chain_update(ed25519_pub)
        .finalize();
    digest[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// Похож ли `account_id` на выведенный из ключа (32 строчных hex-символа).
/// Старые аккаунты — это UUID с дефисами, их так проверить нельзя.
pub fn is_key_derived_account_id(account_id: &str) -> bool {
    account_id.len() == 32
        && account_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Если `account_id` в формате «из ключа», он обязан совпадать с ключом.
pub fn check_account_id(account_id: &str, ed25519_pub: &[u8; 32]) -> Result<(), CryptoError> {
    if is_key_derived_account_id(account_id) && account_id != account_id_for(ed25519_pub) {
        return Err(CryptoError::AccountIdMismatch);
    }
    Ok(())
}

/// Человекочитаемый отпечаток пары публичных ключей: 40 hex-символов
/// группами по 4, например `3f2a 91c0 …`.
pub fn fingerprint(x25519_pub: &[u8; 32], ed25519_pub: &[u8; 32]) -> String {
    let digest = Sha256::new()
        .chain_update(FINGERPRINT_DOMAIN)
        .chain_update(x25519_pub)
        .chain_update(ed25519_pub)
        .finalize();
    digest[..20]
        .chunks(2)
        .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Идентификатор сообщения, выведенный из самого конверта (32 hex-символа).
///
/// Детерминированный: один и тот же конверт всегда получает один и тот же
/// `msg_id`, поэтому повторная отправка или повторный `receive` не создают
/// дублей ни на релее, ни в базе получателя.
pub fn envelope_id(env: &Envelope) -> String {
    let digest = Sha256::new()
        .chain_update(b"messenger/msg-id/v1")
        .chain_update(env.sig)
        .finalize();
    digest[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// Случайные байты из системного ГСЧ.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

fn aead_for(shared: &[u8; 32], eph_pub: &[u8; 32], recipient_pub: &[u8; 32]) -> ChaCha20Poly1305 {
    let mut info = Vec::with_capacity(HKDF_INFO_AEAD.len() + 64);
    info.extend_from_slice(HKDF_INFO_AEAD);
    info.extend_from_slice(eph_pub);
    info.extend_from_slice(recipient_pub);

    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, shared)
        .expand(&info, &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    ChaCha20Poly1305::new(Key::from_slice(&key))
}
