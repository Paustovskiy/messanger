//! Wire-форматы мессенджера.
//!
//! Здесь живёт всё, что пересекает границу процесса: конверт с зашифрованным
//! сообщением, карточка контакта и сообщения между клиентом и релеем.
//! Криптографии тут нет — только структуры и *канонические* байтовые
//! представления, которые подписываются и привязываются к шифротексту.
//!
//! Правило: всё, что подписывается, кодируется вручную и детерминированно
//! (длина `u64 LE` + байты), а не через serde — чтобы подпись не зависела от
//! версии сериализатора.

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Текущая версия формата конверта.
pub const ENVELOPE_VERSION: u8 = 2;

/// Максимальный размер открытого текста одного сообщения (байт).
pub const MAX_PLAINTEXT_LEN: usize = 32 * 1024;

/// Максимальный размер шифротекста: открытый текст + тег Poly1305.
pub const MAX_CIPHERTEXT_LEN: usize = MAX_PLAINTEXT_LEN + 16;

/// Максимальная длина `account_id` и `msg_id` в протоколе релея.
pub const MAX_ID_LEN: usize = 64;

/// Сколько одноразовых предключей можно передать за один раз.
pub const MAX_ONE_TIME_PREKEYS_PER_UPLOAD: usize = 100;

const DOMAIN_ENVELOPE_SIG: &[u8] = b"messenger/envelope-sig/v2";
const DOMAIN_ENVELOPE_HEADER: &[u8] = b"messenger/envelope-header/v2";
const DOMAIN_RELAY_AUTH: &[u8] = b"messenger/relay-auth/v1";
const DOMAIN_SIGNED_PREKEY: &[u8] = b"messenger/signed-prekey/v1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("invalid base64 in field `{field}`")]
    InvalidBase64 { field: &'static str },
    #[error("invalid length of `{field}`: expected {expected}, got {got}")]
    InvalidLength {
        field: &'static str,
        expected: usize,
        got: usize,
    },
    #[error("field `{field}` is too long ({got} > {max})")]
    TooLong {
        field: &'static str,
        max: usize,
        got: usize,
    },
    #[error("field `{field}` contains control characters")]
    ControlCharacters { field: &'static str },
    #[error("unsupported envelope version {0} (this build understands v{ENVELOPE_VERSION})")]
    UnsupportedVersion(u8),
    #[error("invalid username: {0}")]
    InvalidUsername(String),
}

// ---------------------------------------------------------------------------
// Конверт
// ---------------------------------------------------------------------------

/// Заголовок «первого сообщения» (X3DH): по нему получатель вычисляет общий
/// секрет, даже если отправитель писал, пока получатель был офлайн.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreKeyHeader {
    /// Одноразовый X25519-ключ отправителя для X3DH.
    pub ek_pub: [u8; 32],
    /// Какой подписанный предключ получателя использован.
    pub spk_id: u32,
    /// Какой одноразовый предключ получателя использован (если был).
    pub opk_id: Option<u32>,
}

/// Заголовок Double Ratchet: текущий ratchet-ключ отправителя и номера.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RatchetHeader {
    pub dh_pub: [u8; 32],
    /// Длина предыдущей цепочки отправки.
    pub pn: u32,
    /// Номер сообщения в текущей цепочке.
    pub n: u32,
}

/// Зашифрованное сообщение от `from` к `to` (оба — `account_id`).
///
/// * `prekey` — есть только в первых сообщениях сессии;
/// * `header` — заголовок Double Ratchet;
/// * `body` — шифротекст ChaCha20-Poly1305, весь заголовок привязан к нему как AAD;
/// * `sig` — Ed25519-подпись отправителя над [`Envelope::signing_bytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub from: String,
    pub to: String,
    pub prekey: Option<PreKeyHeader>,
    pub header: RatchetHeader,
    pub body: Vec<u8>,
    pub sig: [u8; 64],
}

impl Envelope {
    /// Канонические байты заголовка (всё, кроме шифротекста и подписи).
    /// Идут в AEAD как associated data.
    pub fn header_bytes(&self) -> Vec<u8> {
        envelope_header_bytes(&self.from, &self.to, self.prekey.as_ref(), &self.header)
    }

    /// Байты, которые подписывает отправитель.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let header = self.header_bytes();
        let mut out =
            Vec::with_capacity(DOMAIN_ENVELOPE_SIG.len() + header.len() + self.body.len() + 8);
        out.extend_from_slice(DOMAIN_ENVELOPE_SIG);
        put_bytes(&mut out, &header);
        put_bytes(&mut out, &self.body);
        out
    }
}

/// Канонические байты заголовка конверта.
pub fn envelope_header_bytes(
    from: &str,
    to: &str,
    prekey: Option<&PreKeyHeader>,
    header: &RatchetHeader,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(DOMAIN_ENVELOPE_HEADER.len() + from.len() + to.len() + 128);
    out.extend_from_slice(DOMAIN_ENVELOPE_HEADER);
    out.push(ENVELOPE_VERSION);
    put_bytes(&mut out, from.as_bytes());
    put_bytes(&mut out, to.as_bytes());
    match prekey {
        None => out.push(0),
        Some(p) => {
            out.push(1);
            out.extend_from_slice(&p.ek_pub);
            out.extend_from_slice(&p.spk_id.to_le_bytes());
            match p.opk_id {
                None => out.push(0),
                Some(id) => {
                    out.push(1);
                    out.extend_from_slice(&id.to_le_bytes());
                }
            }
        }
    }
    out.extend_from_slice(&header.dh_pub);
    out.extend_from_slice(&header.pn.to_le_bytes());
    out.extend_from_slice(&header.n.to_le_bytes());
    out
}

/// JSON-представление заголовка X3DH.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreKeyHeaderB64 {
    pub ek_pub_b64: String,
    pub spk_id: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opk_id: Option<u32>,
}

/// JSON-представление конверта: так он ходит по сети и хранится в базе.
/// Все байтовые поля — base64 без паддинга.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeB64 {
    pub v: u8,
    pub from: String,
    pub to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prekey: Option<PreKeyHeaderB64>,
    pub dh_pub_b64: String,
    pub pn: u32,
    pub n: u32,
    pub body_b64: String,
    pub sig_b64: String,
}

impl From<&Envelope> for EnvelopeB64 {
    fn from(e: &Envelope) -> Self {
        Self {
            v: ENVELOPE_VERSION,
            from: e.from.clone(),
            to: e.to.clone(),
            prekey: e.prekey.map(|p| PreKeyHeaderB64 {
                ek_pub_b64: b64(p.ek_pub),
                spk_id: p.spk_id,
                opk_id: p.opk_id,
            }),
            dh_pub_b64: b64(e.header.dh_pub),
            pn: e.header.pn,
            n: e.header.n,
            body_b64: b64(&e.body),
            sig_b64: b64(e.sig),
        }
    }
}

impl From<Envelope> for EnvelopeB64 {
    fn from(e: Envelope) -> Self {
        Self::from(&e)
    }
}

impl TryFrom<&EnvelopeB64> for Envelope {
    type Error = ProtocolError;

    fn try_from(e: &EnvelopeB64) -> Result<Self, Self::Error> {
        if e.v != ENVELOPE_VERSION {
            return Err(ProtocolError::UnsupportedVersion(e.v));
        }
        check_id(&e.from, "from")?;
        check_id(&e.to, "to")?;

        let body = decode_vec(&e.body_b64, "body_b64")?;
        if body.len() > MAX_CIPHERTEXT_LEN {
            return Err(ProtocolError::TooLong {
                field: "body_b64",
                max: MAX_CIPHERTEXT_LEN,
                got: body.len(),
            });
        }

        let prekey = match &e.prekey {
            None => None,
            Some(p) => Some(PreKeyHeader {
                ek_pub: decode_fixed::<32>(&p.ek_pub_b64, "prekey.ek_pub_b64")?,
                spk_id: p.spk_id,
                opk_id: p.opk_id,
            }),
        };

        Ok(Envelope {
            from: e.from.clone(),
            to: e.to.clone(),
            prekey,
            header: RatchetHeader {
                dh_pub: decode_fixed::<32>(&e.dh_pub_b64, "dh_pub_b64")?,
                pn: e.pn,
                n: e.n,
            },
            body,
            sig: decode_fixed::<64>(&e.sig_b64, "sig_b64")?,
        })
    }
}

impl TryFrom<EnvelopeB64> for Envelope {
    type Error = ProtocolError;

    fn try_from(e: EnvelopeB64) -> Result<Self, Self::Error> {
        Envelope::try_from(&e)
    }
}

// ---------------------------------------------------------------------------
// Предключи (prekeys)
// ---------------------------------------------------------------------------

/// Подписанный предключ: X25519-ключ, подписанный Ed25519-ключом владельца.
/// Меняется периодически; по нему можно начать сессию, когда владелец офлайн.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedPrekey {
    pub id: u32,
    pub public: [u8; 32],
    pub sig: [u8; 64],
}

impl SignedPrekey {
    /// Байты, которые подписывает владелец.
    pub fn signing_bytes(id: u32, public: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(DOMAIN_SIGNED_PREKEY.len() + 36);
        out.extend_from_slice(DOMAIN_SIGNED_PREKEY);
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(public);
        out
    }
}

/// Одноразовый предключ: используется ровно для одной новой сессии.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OneTimePrekey {
    pub id: u32,
    pub public: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPrekeyB64 {
    pub id: u32,
    pub pub_b64: String,
    pub sig_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneTimePrekeyB64 {
    pub id: u32,
    pub pub_b64: String,
}

impl From<&SignedPrekey> for SignedPrekeyB64 {
    fn from(k: &SignedPrekey) -> Self {
        Self {
            id: k.id,
            pub_b64: b64(k.public),
            sig_b64: b64(k.sig),
        }
    }
}

impl TryFrom<&SignedPrekeyB64> for SignedPrekey {
    type Error = ProtocolError;
    fn try_from(k: &SignedPrekeyB64) -> Result<Self, Self::Error> {
        Ok(Self {
            id: k.id,
            public: decode_fixed::<32>(&k.pub_b64, "signed_prekey.pub_b64")?,
            sig: decode_fixed::<64>(&k.sig_b64, "signed_prekey.sig_b64")?,
        })
    }
}

impl From<&OneTimePrekey> for OneTimePrekeyB64 {
    fn from(k: &OneTimePrekey) -> Self {
        Self {
            id: k.id,
            pub_b64: b64(k.public),
        }
    }
}

impl TryFrom<&OneTimePrekeyB64> for OneTimePrekey {
    type Error = ProtocolError;
    fn try_from(k: &OneTimePrekeyB64) -> Result<Self, Self::Error> {
        Ok(Self {
            id: k.id,
            public: decode_fixed::<32>(&k.pub_b64, "one_time.pub_b64")?,
        })
    }
}

// ---------------------------------------------------------------------------
// Карточка контакта
// ---------------------------------------------------------------------------

/// Карточка, которой пользователи обмениваются, чтобы добавить друг друга.
/// Самоподписана ключом Ed25519 владельца.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactCardV2 {
    pub account_id: String,
    pub username: Option<String>,
    pub x25519_pub_b64: String,
    pub ed25519_pub_b64: String,
    pub sig_b64: String,
    /// Текущий подписанный предключ. Нужен, чтобы начать переписку без релея
    /// (`send --offline`). Подписан отдельно, поэтому в подпись карточки не входит.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_prekey: Option<SignedPrekeyB64>,
}

/// Подписываемая часть карточки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactCardPayload {
    pub account_id: String,
    pub username: Option<String>,
    pub x25519_pub: [u8; 32],
    pub ed25519_pub: [u8; 32],
}

impl ContactCardPayload {
    /// Канонические байты для подписи.
    ///
    /// Формат совпадает байт-в-байт с тем, что раньше выдавал `bincode 1`
    /// (`u64 LE` длина строки, `0/1` тег `Option`, массивы как есть), поэтому
    /// карточки, экспортированные старыми версиями, по-прежнему проходят проверку.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.account_id.len() + 96);
        put_bytes(&mut out, self.account_id.as_bytes());
        match &self.username {
            None => out.push(0),
            Some(u) => {
                out.push(1);
                put_bytes(&mut out, u.as_bytes());
            }
        }
        out.extend_from_slice(&self.x25519_pub);
        out.extend_from_slice(&self.ed25519_pub);
        out
    }
}

impl ContactCardV2 {
    pub fn from_parts(payload: &ContactCardPayload, sig: [u8; 64]) -> Self {
        Self {
            account_id: payload.account_id.clone(),
            username: payload.username.clone(),
            x25519_pub_b64: b64(payload.x25519_pub),
            ed25519_pub_b64: b64(payload.ed25519_pub),
            sig_b64: b64(sig),
            signed_prekey: None,
        }
    }

    /// Разобрать карточку на подписываемую часть и подпись.
    pub fn parts(&self) -> Result<(ContactCardPayload, [u8; 64]), ProtocolError> {
        check_id(&self.account_id, "account_id")?;
        let payload = ContactCardPayload {
            account_id: self.account_id.clone(),
            username: self.username.clone(),
            x25519_pub: decode_fixed::<32>(&self.x25519_pub_b64, "x25519_pub_b64")?,
            ed25519_pub: decode_fixed::<32>(&self.ed25519_pub_b64, "ed25519_pub_b64")?,
        };
        let sig = decode_fixed::<64>(&self.sig_b64, "sig_b64")?;
        Ok((payload, sig))
    }
}

// ---------------------------------------------------------------------------
// Протокол релея (JSON поверх WebSocket)
// ---------------------------------------------------------------------------

/// Клиент → релей.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Ответ на [`ServerMessage::Challenge`]: подпись над
    /// [`relay_auth_signing_bytes`]. При первом входе релей запоминает пару
    /// `account_id` ↔ `sign_pub_b64` и дальше пускает только с этим ключом.
    Auth {
        account_id: String,
        sign_pub_b64: String,
        sig_b64: String,
    },
    /// Отправить конверт получателю `to`.
    Send {
        to: String,
        msg_id: String,
        envelope: EnvelopeB64,
    },
    /// Подтвердить, что сообщение `msg_id` от `to` сохранено у получателя.
    Ack { to: String, msg_id: String },
    /// Опубликовать свои предключи: подписанный заменяет прежний,
    /// одноразовые добавляются к уже лежащим на релее.
    PublishPrekeys {
        signed_prekey: SignedPrekeyB64,
        #[serde(default)]
        one_time: Vec<OneTimePrekeyB64>,
    },
    /// Запросить набор предключей собеседника, чтобы начать с ним сессию.
    FetchBundle { account_id: String },
}

/// Релей → клиент.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Первое сообщение после подключения: случайный nonce для входа.
    Challenge { nonce_b64: String },
    /// Вход выполнен.
    Authenticated { account_id: String },
    /// Релей сохранил сообщение и доставит его, как только получатель появится.
    Accepted { msg_id: String },
    /// Входящее сообщение.
    Deliver {
        from: String,
        msg_id: String,
        envelope: EnvelopeB64,
    },
    /// Получатель подтвердил доставку нашего сообщения.
    DeliverAck { from: String, msg_id: String },
    /// Сколько наших предключей лежит на релее. Приходит после публикации и
    /// после входа — в последнем случае **после** всей накопившейся очереди,
    /// так что это ещё и знак «старые сообщения выданы полностью».
    PrekeyStatus {
        has_signed_prekey: bool,
        one_time_left: u32,
    },
    /// Набор предключей собеседника. Одноразовый ключ выдаётся один раз
    /// и сразу удаляется с релея. `signed_prekey: None` — собеседник ещё
    /// не публиковал ключи.
    Bundle {
        account_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signed_prekey: Option<SignedPrekeyB64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        one_time: Option<OneTimePrekeyB64>,
    },
    /// Ошибка. `msg_id` заполнен, если ошибка относится к конкретному `Send`.
    Error {
        message: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        msg_id: Option<String>,
    },
}

/// Байты, которые клиент подписывает при входе на релей.
pub fn relay_auth_signing_bytes(nonce: &[u8; 32], account_id: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(DOMAIN_RELAY_AUTH.len() + 32 + 8 + account_id.len());
    out.extend_from_slice(DOMAIN_RELAY_AUTH);
    out.extend_from_slice(nonce);
    put_bytes(&mut out, account_id.as_bytes());
    out
}

// ---------------------------------------------------------------------------
// Username
// ---------------------------------------------------------------------------

/// Нормализация username:
/// - допускаем ввод с `@` или без;
/// - приводим к нижнему регистру (уникальность без учёта регистра);
/// - 5..=32 символов `[a-z0-9_]`, начинается с буквы, не кончается `_`, без `__`.
///
/// Возвращает строку вида `@name`.
pub fn normalize_username(input: &str) -> Result<String, ProtocolError> {
    let s = input.trim();
    let s = s.strip_prefix('@').unwrap_or(s).trim();

    if !(5..=32).contains(&s.len()) {
        return Err(ProtocolError::InvalidUsername(
            "length must be 5..32".into(),
        ));
    }

    let s = s.to_ascii_lowercase();
    let bytes = s.as_bytes();

    if !bytes
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(ProtocolError::InvalidUsername(
            "allowed only [a-z0-9_]".into(),
        ));
    }
    if !bytes[0].is_ascii_lowercase() {
        return Err(ProtocolError::InvalidUsername(
            "must start with a letter [a-z]".into(),
        ));
    }
    if bytes[bytes.len() - 1] == b'_' {
        return Err(ProtocolError::InvalidUsername(
            "must not end with '_'".into(),
        ));
    }
    if s.contains("__") {
        return Err(ProtocolError::InvalidUsername(
            "must not contain consecutive '__'".into(),
        ));
    }

    Ok(format!("@{s}"))
}

// ---------------------------------------------------------------------------
// base64 и прочие помощники
// ---------------------------------------------------------------------------

/// base64 без паддинга — единый формат для всех байтовых полей.
pub fn b64(bytes: impl AsRef<[u8]>) -> String {
    STANDARD_NO_PAD.encode(bytes)
}

/// Декодировать base64 ровно в `N` байт.
pub fn decode_fixed<const N: usize>(
    s: &str,
    field: &'static str,
) -> Result<[u8; N], ProtocolError> {
    let v = decode_vec(s, field)?;
    v.try_into()
        .map_err(|v: Vec<u8>| ProtocolError::InvalidLength {
            field,
            expected: N,
            got: v.len(),
        })
}

fn decode_vec(s: &str, field: &'static str) -> Result<Vec<u8>, ProtocolError> {
    STANDARD_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|_| ProtocolError::InvalidBase64 { field })
}

/// Проверить идентификатор (`account_id` / `msg_id`): непустой, разумной длины,
/// без управляющих символов.
pub fn check_id(s: &str, field: &'static str) -> Result<(), ProtocolError> {
    if s.is_empty() {
        return Err(ProtocolError::InvalidLength {
            field,
            expected: 1,
            got: 0,
        });
    }
    if s.len() > MAX_ID_LEN {
        return Err(ProtocolError::TooLong {
            field,
            max: MAX_ID_LEN,
            got: s.len(),
        });
    }
    if s.chars().any(char::is_control) {
        return Err(ProtocolError::ControlCharacters { field });
    }
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope() -> Envelope {
        Envelope {
            from: "alice".into(),
            to: "bob".into(),
            prekey: Some(PreKeyHeader {
                ek_pub: [5; 32],
                spk_id: 7,
                opk_id: Some(9),
            }),
            header: RatchetHeader {
                dh_pub: [1; 32],
                pn: 2,
                n: 3,
            },
            body: vec![3; 40],
            sig: [4; 64],
        }
    }

    #[test]
    fn envelope_b64_roundtrip() {
        for prekey in [
            None,
            Some(PreKeyHeader {
                ek_pub: [5; 32],
                spk_id: 7,
                opk_id: None,
            }),
            Some(PreKeyHeader {
                ek_pub: [5; 32],
                spk_id: 7,
                opk_id: Some(9),
            }),
        ] {
            let env = Envelope {
                prekey,
                ..sample_envelope()
            };
            let wire = EnvelopeB64::from(&env);
            let json = serde_json::to_string(&wire).unwrap();
            let back: EnvelopeB64 = serde_json::from_str(&json).unwrap();
            assert_eq!(Envelope::try_from(back).unwrap(), env);
        }
    }

    #[test]
    fn envelope_rejects_unknown_version() {
        let mut wire = EnvelopeB64::from(sample_envelope());
        wire.v = 7;
        assert_eq!(
            Envelope::try_from(wire),
            Err(ProtocolError::UnsupportedVersion(7))
        );
    }

    #[test]
    fn envelope_rejects_bad_lengths() {
        let mut wire = EnvelopeB64::from(sample_envelope());
        wire.sig_b64 = b64([0u8; 10]);
        assert!(matches!(
            Envelope::try_from(wire),
            Err(ProtocolError::InvalidLength {
                field: "sig_b64",
                ..
            })
        ));

        let mut wire = EnvelopeB64::from(sample_envelope());
        wire.body_b64 = b64(vec![0u8; MAX_CIPHERTEXT_LEN + 1]);
        assert!(matches!(
            Envelope::try_from(wire),
            Err(ProtocolError::TooLong { .. })
        ));
    }

    #[test]
    fn older_envelopes_are_rejected() {
        // v0: без версии и подписи.
        let v0 = r#"{"from":"a","to":"b","eph_pub_b64":"AA","nonce_b64":"AA","body_b64":"AA"}"#;
        assert!(serde_json::from_str::<EnvelopeB64>(v0).is_err());
        // v1: без ratchet-заголовка.
        let v1 = r#"{"v":1,"from":"a","to":"b","eph_pub_b64":"AA","nonce_b64":"AA","body_b64":"AA","sig_b64":"AA"}"#;
        assert!(serde_json::from_str::<EnvelopeB64>(v1).is_err());
    }

    #[test]
    fn signing_bytes_cover_every_header_field() {
        let base = sample_envelope();
        let mut variants = vec![];
        let mut e = base.clone();
        e.from = "mallory".into();
        variants.push(e);
        let mut e = base.clone();
        e.to = "carol".into();
        variants.push(e);
        let mut e = base.clone();
        e.prekey = None;
        variants.push(e);
        let mut e = base.clone();
        e.prekey.as_mut().unwrap().ek_pub[0] ^= 1;
        variants.push(e);
        let mut e = base.clone();
        e.prekey.as_mut().unwrap().spk_id += 1;
        variants.push(e);
        let mut e = base.clone();
        e.prekey.as_mut().unwrap().opk_id = None;
        variants.push(e);
        let mut e = base.clone();
        e.header.dh_pub[0] ^= 1;
        variants.push(e);
        let mut e = base.clone();
        e.header.pn += 1;
        variants.push(e);
        let mut e = base.clone();
        e.header.n += 1;
        variants.push(e);
        let mut e = base.clone();
        e.body.push(0);
        variants.push(e);

        for v in &variants {
            assert_ne!(v.signing_bytes(), base.signing_bytes());
        }
        // Шифротекст не входит в заголовок, всё остальное — входит.
        for v in &variants[..variants.len() - 1] {
            assert_ne!(v.header_bytes(), base.header_bytes());
        }
        // Длины в префиксе не дают «перетечь» байтам из from в to.
        let h = RatchetHeader {
            dh_pub: [0; 32],
            pn: 0,
            n: 0,
        };
        assert_ne!(
            envelope_header_bytes("ab", "c", None, &h),
            envelope_header_bytes("a", "bc", None, &h)
        );
    }

    #[test]
    fn prekeys_roundtrip_and_card_stays_compatible() {
        let spk = SignedPrekey {
            id: 3,
            public: [1; 32],
            sig: [2; 64],
        };
        assert_eq!(
            SignedPrekey::try_from(&SignedPrekeyB64::from(&spk)).unwrap(),
            spk
        );
        let opk = OneTimePrekey {
            id: 4,
            public: [3; 32],
        };
        assert_eq!(
            OneTimePrekey::try_from(&OneTimePrekeyB64::from(&opk)).unwrap(),
            opk
        );
        assert_ne!(
            SignedPrekey::signing_bytes(1, &[0; 32]),
            SignedPrekey::signing_bytes(2, &[0; 32])
        );

        // Карточка без предключа (из прошлой версии) по-прежнему читается.
        let old = r#"{"account_id":"a","username":null,"x25519_pub_b64":"AA","ed25519_pub_b64":"AA","sig_b64":"AA"}"#;
        assert_eq!(
            serde_json::from_str::<ContactCardV2>(old)
                .unwrap()
                .signed_prekey,
            None
        );
    }

    #[test]
    fn contact_payload_is_byte_compatible_with_legacy_bincode() {
        #[derive(Serialize)]
        struct Legacy {
            account_id: String,
            username: Option<String>,
            x25519_pub: [u8; 32],
            ed25519_pub: [u8; 32],
        }
        for username in [None, Some("@alice_1".to_string())] {
            let p = ContactCardPayload {
                account_id: "2d723969-b478-4ff4-af0a-477541df0441".into(),
                username: username.clone(),
                x25519_pub: [7; 32],
                ed25519_pub: [9; 32],
            };
            let legacy = bincode::serialize(&Legacy {
                account_id: p.account_id.clone(),
                username,
                x25519_pub: p.x25519_pub,
                ed25519_pub: p.ed25519_pub,
            })
            .unwrap();
            assert_eq!(p.signing_bytes(), legacy);
        }
    }

    #[test]
    fn contact_card_parts_roundtrip() {
        let p = ContactCardPayload {
            account_id: "acc".into(),
            username: Some("@alice".into()),
            x25519_pub: [5; 32],
            ed25519_pub: [6; 32],
        };
        let card = ContactCardV2::from_parts(&p, [8; 64]);
        assert_eq!(card.parts().unwrap(), (p, [8; 64]));
    }

    #[test]
    fn padded_base64_is_accepted() {
        let padded = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        assert!(padded.ends_with('='));
        assert_eq!(decode_fixed::<32>(&padded, "x").unwrap(), [1u8; 32]);
    }

    #[test]
    fn relay_messages_have_stable_json_shape() {
        let m = ClientMessage::Ack {
            to: "a".into(),
            msg_id: "m".into(),
        };
        assert_eq!(
            serde_json::to_string(&m).unwrap(),
            r#"{"type":"ack","to":"a","msg_id":"m"}"#
        );

        let m = ServerMessage::Error {
            message: "x".into(),
            msg_id: None,
        };
        assert_eq!(
            serde_json::to_string(&m).unwrap(),
            r#"{"type":"error","message":"x"}"#
        );
    }

    #[test]
    fn username_normalization() {
        assert_eq!(normalize_username("  @Alice_01 ").unwrap(), "@alice_01");
        assert_eq!(normalize_username("bobby").unwrap(), "@bobby");

        for bad in [
            "abc",
            "1alice",
            "alice_",
            "al__ice",
            "алиса",
            "ali ce",
            &"a".repeat(33),
        ] {
            assert!(normalize_username(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn ids_are_validated() {
        assert!(check_id("ok", "f").is_ok());
        assert!(check_id("", "f").is_err());
        assert!(check_id(&"x".repeat(MAX_ID_LEN + 1), "f").is_err());
        assert!(check_id("a\nb", "f").is_err());
    }
}
