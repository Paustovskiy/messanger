use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub from: UserId,
    pub to: UserId,
    pub eph_pub: [u8; 32],
    pub nonce: [u8; 12],
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RelayEnvelope {
    pub msg_id: String,
    pub from_account_id: String,
    pub to_account_id: String,
    pub envelope_b64: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RelayAck {
    pub msg_id: String,
    pub from_account_id: String, // кто подтверждает (получатель)
    pub to_account_id: String,   // кому (отправителю)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum WsIn {
    Register { account_id: String },
    Envelope(RelayEnvelope),
    Ack(RelayAck),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum WsOut {
    Envelope(RelayEnvelope),
    Ack(RelayAck),
}

pub fn encode(env: &Envelope) -> Vec<u8> {
    bincode::serialize(env).expect("encode envelope")
}

pub fn decode(bytes: &[u8]) -> Envelope {
    bincode::deserialize(bytes).expect("decode envelope")
}

/// Для копипаста/JSON: байтовые поля как base64.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeB64 {
    pub from: String,
    pub to: String,
    pub eph_pub_b64: String,
    pub nonce_b64: String,
    pub body_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactCard {
    pub account_id: String,               // UUID
    pub username: Option<String>,         // "@name" или None
    pub identity_pubkey_b64: String,      // 32 bytes b64
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("invalid base64 for {field}")]
    InvalidBase64 { field: &'static str },
    #[error("invalid length for {field}: expected {expected}, got {got}")]
    InvalidLength {
        field: &'static str,
        expected: usize,
        got: usize,
    },
    #[error("invalid username: {0}")]
    InvalidUsername(String),
}

impl From<Envelope> for EnvelopeB64 {
    fn from(e: Envelope) -> Self {
        Self {
            from: e.from.0,
            to: e.to.0,
            eph_pub_b64: STANDARD_NO_PAD.encode(e.eph_pub),
            nonce_b64: STANDARD_NO_PAD.encode(e.nonce),
            body_b64: STANDARD_NO_PAD.encode(e.body),
        }
    }
}

impl TryFrom<EnvelopeB64> for Envelope {
    type Error = ProtocolError;

    fn try_from(e: EnvelopeB64) -> Result<Self, Self::Error> {
        let eph_pub = decode_fixed::<32>(&e.eph_pub_b64, "eph_pub_b64")?;
        let nonce = decode_fixed::<12>(&e.nonce_b64, "nonce_b64")?;
        let body = decode_vec(&e.body_b64, "body_b64")?;

        Ok(Envelope {
            from: UserId(e.from),
            to: UserId(e.to),
            eph_pub,
            nonce,
            body,
        })
    }
}

impl ContactCard {
    pub fn from_parts(account_id: String, username: Option<String>, pubkey: [u8; 32]) -> Self {
        Self {
            account_id,
            username,
            identity_pubkey_b64: STANDARD_NO_PAD.encode(pubkey),
        }
    }

    pub fn pubkey_bytes(&self) -> Result<[u8; 32], ProtocolError> {
        decode_fixed::<32>(&self.identity_pubkey_b64, "identity_pubkey_b64")
    }
}

/// Нормализация username:
/// - допускаем ввод с '@' или без
/// - приводим к lower-case
/// - валидируем правила
pub fn normalize_username(input: &str) -> Result<String, ProtocolError> {
    let mut s = input.trim();
    if s.starts_with('@') {
        s = &s[1..];
    }
    let s = s.trim();

    if s.len() < 5 || s.len() > 32 {
        return Err(ProtocolError::InvalidUsername(
            "length must be 5..32".to_string(),
        ));
    }

    // Нормализуем в lower-case (уникальность case-insensitive)
    let s = s.to_ascii_lowercase();

    // Правила: [a-z0-9_], начинать с буквы, не заканчивать '_'
    let bytes = s.as_bytes();

    if !(bytes[0] as char).is_ascii_lowercase() {
        return Err(ProtocolError::InvalidUsername(
            "must start with a letter [a-z]".to_string(),
        ));
    }
    if bytes[bytes.len() - 1] == b'_' {
        return Err(ProtocolError::InvalidUsername(
            "must not end with '_'".to_string(),
        ));
    }

    for &b in bytes {
        let c = b as char;
        let ok = c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_';
        if !ok {
            return Err(ProtocolError::InvalidUsername(
                "allowed only [a-z0-9_]".to_string(),
            ));
        }
    }

    // Опционально (как анти-спам): запрет "__"
    if s.contains("__") {
        return Err(ProtocolError::InvalidUsername(
            "must not contain consecutive '__'".to_string(),
        ));
    }

    Ok(format!("@{}", s))
}

fn decode_vec(b64: &str, field: &'static str) -> Result<Vec<u8>, ProtocolError> {
    STANDARD_NO_PAD
        .decode(b64)
        .map_err(|_| ProtocolError::InvalidBase64 { field })
}

fn decode_fixed<const N: usize>(b64: &str, field: &'static str) -> Result<[u8; N], ProtocolError> {
    let v = decode_vec(b64, field)?;
    if v.len() != N {
        return Err(ProtocolError::InvalidLength {
            field,
            expected: N,
            got: v.len(),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    Ok(out)
}