//! Криптография мессенджера.
//!
//! У каждого аккаунта две постоянные пары ключей:
//! * **X25519** (identity key) — участвует в X3DH при знакомстве;
//! * **Ed25519** — подписывает карточку контакта, предключи, сообщения и вход на релей.
//!
//! Сами сообщения шифруются в сессиях: X3DH даёт общий секрет, Double Ratchet
//! выводит из него новый ключ на каждое сообщение (см. модули [`session`] и
//! [`ratchet`]). Поверх этого каждый конверт подписан отправителем, чтобы релей
//! мог отсеивать подделки, не умея ничего расшифровать.

pub mod ratchet;
pub mod session;

pub use session::{
    Bundle, Opened, PeerKeys, PrekeySecrets, SessionSet, new_one_time_prekey, verify_signed_prekey,
};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use protocol::{
    ContactCardPayload, ContactCardV2, DeviceInfo, DeviceList, Envelope, MAX_PLAINTEXT_LEN,
    ProtocolError, SignedDeviceListB64,
};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

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
    #[error("no session with this contact yet")]
    NoSession,
    #[error("message refers to a prekey we don't have (already used or expired)")]
    UnknownPrekey,
    #[error("this first message was already processed (replay)")]
    Replay,
    #[error("message is too far ahead in its chain")]
    TooManySkipped,
    #[error("stored session state is corrupted")]
    CorruptState,
    #[error("only the primary device holds the account key")]
    NotAccountKey,
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

/// Локальная личность **устройства**: аккаунт, номер устройства и его ключи.
///
/// На основном устройстве (№1) ключ подписи — это ключ аккаунта: им же
/// подписываются карточка контакта и список устройств. На остальных устройствах
/// ключ подписи свой, а ключа аккаунта нет вовсе.
#[derive(Clone)]
pub struct Identity {
    account_id: String,
    device_id: u32,
    x_secret: StaticSecret,
    x_public: PublicKey,
    sign: SigningKey,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Секреты в логи не попадают никогда.
        f.debug_struct("Identity")
            .field("account_id", &self.account_id)
            .field("device_id", &self.device_id)
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
            device_id: protocol::PRIMARY_DEVICE,
            x_secret,
            x_public,
            sign,
        }
    }

    /// То же устройство, но с другим номером (для дополнительных устройств).
    pub fn with_device(mut self, device_id: u32) -> Self {
        self.device_id = device_id;
        self
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn device_id(&self) -> u32 {
        self.device_id
    }

    /// Описание этого устройства для списка устройств.
    pub fn device_info(&self, name: impl Into<String>) -> DeviceInfo {
        DeviceInfo {
            device_id: self.device_id,
            x25519_pub: self.x_public_bytes(),
            ed25519_pub: self.sign_public_bytes(),
            name: name.into(),
        }
    }

    /// Подписать список устройств. Может только основное устройство: его ключ
    /// подписи и есть ключ аккаунта.
    pub fn sign_device_list(&self, list: &DeviceList) -> Result<SignedDeviceListB64, CryptoError> {
        if list.account_id != self.account_id || list.account_pub != self.sign_public_bytes() {
            return Err(CryptoError::NotAccountKey);
        }
        list.validate()?;
        Ok(SignedDeviceListB64::from_parts(
            list,
            self.sign(&list.signing_bytes()),
        ))
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
}

/// Проверить подписанный список устройств аккаунта `account_id`.
///
/// `known_account_pub` — ключ аккаунта, который мы уже знаем (из карточки
/// контакта или из прошлого списка). Если он есть, ключ в списке обязан с ним
/// совпасть. Если нет, ключ проверяется по `account_id` (ID выведен из ключа);
/// для старых UUID-аккаунтов без известного ключа список не принимается.
pub fn verify_device_list(
    wire: &SignedDeviceListB64,
    account_id: &str,
    known_account_pub: Option<&[u8; 32]>,
) -> Result<DeviceList, CryptoError> {
    let (list, sig) = wire.parts()?;
    if list.account_id != account_id {
        return Err(CryptoError::AccountIdMismatch);
    }
    match known_account_pub {
        Some(k) if *k != list.account_pub => return Err(CryptoError::AccountIdMismatch),
        Some(_) => {}
        None if is_key_derived_account_id(account_id) => {
            check_account_id(account_id, &list.account_pub)?
        }
        None => return Err(CryptoError::AccountIdMismatch),
    }
    if !verify_signature(&list.account_pub, &list.signing_bytes(), &sig) {
        return Err(CryptoError::BadSignature);
    }
    Ok(list)
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
