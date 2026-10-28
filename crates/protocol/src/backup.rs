//! Резервная копия ключа аккаунта: формат файла и содержимое.
//!
//! Здесь только байты и разбор; шифрование (Argon2id + ChaCha20-Poly1305) живёт
//! в `crypto_core::backup`.
//!
//! Файл — одна строка текста: `mkeybackup1.` ‖ base64url-без-паддинга(header ‖
//! шифротекст) ‖ `\n`. Заголовок (50 байт, числа little-endian) целиком идёт в AEAD
//! как associated data, поэтому подмена любого его байта ломает расшифровку.
//!
//! Параметры Argon2 в заголовке приходят из недоверенного файла, поэтому их границы
//! проверяются при разборе, до запуска Argon2 (иначе файл с `m = 4 ТиБ` мог бы
//! повесить или уронить программу).

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use super::{DeviceList, PRIMARY_DEVICE, ProtocolError, check_id, put_bytes};

/// Начало файла резервной копии.
pub const BACKUP_FILE_PREFIX: &str = "mkeybackup1.";
/// Магическая строка в заголовке.
pub const BACKUP_MAGIC: &[u8; 8] = b"MSNGRKEY";
/// Версия формата файла.
pub const BACKUP_FORMAT_VERSION: u8 = 1;
/// Идентификатор KDF: Argon2id версии 0x13.
pub const BACKUP_KDF_ARGON2ID_V13: u8 = 1;
/// Размер заголовка в байтах.
pub const BACKUP_HEADER_LEN: usize = 50;
pub const BACKUP_SALT_LEN: usize = 16;
pub const BACKUP_NONCE_LEN: usize = 12;
/// Тег Poly1305.
pub const BACKUP_TAG_LEN: usize = 16;
/// Больше этого файл не читаем (настоящий весит около 300 символов).
pub const MAX_BACKUP_FILE_LEN: usize = 4096;

pub const BACKUP_M_COST_MIN_KIB: u32 = 65_536;
pub const BACKUP_M_COST_MAX_KIB: u32 = 1_048_576;
pub const BACKUP_T_COST_MIN: u32 = 2;
pub const BACKUP_T_COST_MAX: u32 = 16;
pub const BACKUP_LANES_MIN: u32 = 1;
pub const BACKUP_LANES_MAX: u32 = 8;

const DOMAIN_KEY_BACKUP: &[u8] = b"messenger/key-backup/v1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BackupFormatError {
    #[error("это не файл резервной копии ключа")]
    NotABackup,
    #[error("файл резервной копии повреждён или обрезан")]
    Truncated,
    #[error("неизвестная версия формата резервной копии: {0}")]
    UnsupportedVersion(u8),
    #[error("неизвестный алгоритм выработки ключа в резервной копии: {0}")]
    UnsupportedKdf(u8),
    #[error("параметры Argon2 в файле вне допустимых границ")]
    ParamsOutOfRange,
    #[error("содержимое резервной копии некорректно: {0}")]
    BadPayload(String),
}

/// Параметры Argon2id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupKdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub lanes: u32,
}

impl BackupKdfParams {
    /// Параметры по умолчанию: 256 МиБ, 3 прохода, 1 поток.
    pub const DEFAULT: Self = Self {
        m_cost_kib: 262_144,
        t_cost: 3,
        lanes: 1,
    };

    /// Укладываются ли параметры в границы формата.
    pub fn check(&self) -> Result<(), BackupFormatError> {
        let ok = (BACKUP_M_COST_MIN_KIB..=BACKUP_M_COST_MAX_KIB).contains(&self.m_cost_kib)
            && (BACKUP_T_COST_MIN..=BACKUP_T_COST_MAX).contains(&self.t_cost)
            && (BACKUP_LANES_MIN..=BACKUP_LANES_MAX).contains(&self.lanes);
        if ok {
            Ok(())
        } else {
            Err(BackupFormatError::ParamsOutOfRange)
        }
    }
}

/// Заголовок файла (не секретный).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupHeader {
    pub kdf: BackupKdfParams,
    pub salt: [u8; BACKUP_SALT_LEN],
    pub nonce: [u8; BACKUP_NONCE_LEN],
}

impl BackupHeader {
    /// Канонические байты заголовка; они же — AAD шифрования.
    pub fn to_bytes(&self) -> [u8; BACKUP_HEADER_LEN] {
        let mut out = [0u8; BACKUP_HEADER_LEN];
        out[..8].copy_from_slice(BACKUP_MAGIC);
        out[8] = BACKUP_FORMAT_VERSION;
        out[9] = BACKUP_KDF_ARGON2ID_V13;
        out[10..14].copy_from_slice(&self.kdf.m_cost_kib.to_le_bytes());
        out[14..18].copy_from_slice(&self.kdf.t_cost.to_le_bytes());
        out[18..22].copy_from_slice(&self.kdf.lanes.to_le_bytes());
        out[22..38].copy_from_slice(&self.salt);
        out[38..50].copy_from_slice(&self.nonce);
        out
    }

    /// Разобрать заголовок из начала `bytes`; вернуть его и остаток (шифротекст).
    /// Границы параметров проверяются здесь.
    pub fn parse(bytes: &[u8]) -> Result<(Self, &[u8]), BackupFormatError> {
        if bytes.len() < BACKUP_HEADER_LEN {
            return Err(BackupFormatError::Truncated);
        }
        let (h, rest) = bytes.split_at(BACKUP_HEADER_LEN);
        if &h[..8] != BACKUP_MAGIC {
            return Err(BackupFormatError::NotABackup);
        }
        if h[8] != BACKUP_FORMAT_VERSION {
            return Err(BackupFormatError::UnsupportedVersion(h[8]));
        }
        if h[9] != BACKUP_KDF_ARGON2ID_V13 {
            return Err(BackupFormatError::UnsupportedKdf(h[9]));
        }
        let u32_at = |i: usize| u32::from_le_bytes([h[i], h[i + 1], h[i + 2], h[i + 3]]);
        let kdf = BackupKdfParams {
            m_cost_kib: u32_at(10),
            t_cost: u32_at(14),
            lanes: u32_at(18),
        };
        kdf.check()?;
        let mut salt = [0u8; BACKUP_SALT_LEN];
        salt.copy_from_slice(&h[22..38]);
        let mut nonce = [0u8; BACKUP_NONCE_LEN];
        nonce.copy_from_slice(&h[38..50]);
        Ok((Self { kdf, salt, nonce }, rest))
    }
}

/// Собрать текст файла из заголовка и шифротекста.
pub fn encode_backup_file(header: &BackupHeader, ciphertext: &[u8]) -> String {
    let mut raw = Vec::with_capacity(BACKUP_HEADER_LEN + ciphertext.len());
    raw.extend_from_slice(&header.to_bytes());
    raw.extend_from_slice(ciphertext);
    format!("{BACKUP_FILE_PREFIX}{}\n", URL_SAFE_NO_PAD.encode(raw))
}

/// Разобрать файл: заголовок, его байты (AAD) и шифротекст. Argon2 не запускается.
pub fn decode_backup_file(
    bytes: &[u8],
) -> Result<(BackupHeader, [u8; BACKUP_HEADER_LEN], Vec<u8>), BackupFormatError> {
    if bytes.len() > MAX_BACKUP_FILE_LEN {
        return Err(BackupFormatError::NotABackup);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| BackupFormatError::NotABackup)?;
    let body = text
        .trim_end_matches(['\n', '\r'])
        .strip_prefix(BACKUP_FILE_PREFIX)
        .ok_or(BackupFormatError::NotABackup)?;
    let raw = URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| BackupFormatError::Truncated)?;
    let (header, ct) = BackupHeader::parse(&raw)?;
    if ct.len() < BACKUP_TAG_LEN {
        return Err(BackupFormatError::Truncated);
    }
    Ok((header, header.to_bytes(), ct.to_vec()))
}

/// Содержимое резервной копии (секретное).
///
/// `account_secret` — seed Ed25519-ключа аккаунта. Остальное нужно, чтобы новое
/// устройство продолжило аккаунт с актуального списка: `primary_x25519_pub` — IK
/// устройства №1 (он входит в его запись в списке), `list_version_at_backup` — версия
/// списка на момент копии.
#[derive(Clone)]
pub struct BackupPayload {
    pub account_id: String,
    pub account_secret: [u8; 32],
    pub primary_x25519_pub: [u8; 32],
    pub list_version_at_backup: u64,
    pub created_at: u64,
}

impl std::fmt::Debug for BackupPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupPayload")
            .field("account_id", &self.account_id)
            .field("list_version_at_backup", &self.list_version_at_backup)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

impl Drop for BackupPayload {
    fn drop(&mut self) {
        self.account_secret.zeroize();
    }
}

impl BackupPayload {
    /// Канонические байты (секретные: вызывающий обязан обнулить результат).
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(
            DOMAIN_KEY_BACKUP.len() + self.account_id.len() + 120,
        ));
        out.extend_from_slice(DOMAIN_KEY_BACKUP);
        put_bytes(&mut out, self.account_id.as_bytes());
        out.extend_from_slice(&self.account_secret);
        out.extend_from_slice(&self.primary_x25519_pub);
        out.extend_from_slice(&self.list_version_at_backup.to_le_bytes());
        out.extend_from_slice(&self.created_at.to_le_bytes());
        out
    }

    /// Разобрать; лишние байты в конце — ошибка.
    pub fn parse(bytes: &[u8]) -> Result<Self, BackupFormatError> {
        let bad = |m: &str| BackupFormatError::BadPayload(m.into());
        let rest = bytes
            .strip_prefix(DOMAIN_KEY_BACKUP)
            .ok_or_else(|| bad("unknown domain"))?;
        let (len_bytes, rest) = rest
            .split_first_chunk::<8>()
            .ok_or_else(|| bad("truncated"))?;
        let len = usize::try_from(u64::from_le_bytes(*len_bytes))
            .map_err(|_| bad("bad account_id length"))?;
        if len > super::MAX_ID_LEN || rest.len() < len {
            return Err(bad("bad account_id length"));
        }
        let (id, rest) = rest.split_at(len);
        let account_id = std::str::from_utf8(id)
            .map_err(|_| bad("account_id is not utf-8"))?
            .to_owned();
        check_id(&account_id, "account_id").map_err(|e: ProtocolError| bad(&e.to_string()))?;
        let (account_secret, rest) = rest
            .split_first_chunk::<32>()
            .ok_or_else(|| bad("truncated"))?;
        let (primary_x25519_pub, rest) = rest
            .split_first_chunk::<32>()
            .ok_or_else(|| bad("truncated"))?;
        let (version, rest) = rest
            .split_first_chunk::<8>()
            .ok_or_else(|| bad("truncated"))?;
        let (created, rest) = rest
            .split_first_chunk::<8>()
            .ok_or_else(|| bad("truncated"))?;
        if !rest.is_empty() {
            return Err(bad("trailing bytes"));
        }
        Ok(Self {
            account_id,
            account_secret: *account_secret,
            primary_x25519_pub: *primary_x25519_pub,
            list_version_at_backup: u64::from_le_bytes(*version),
            created_at: u64::from_le_bytes(*created),
        })
    }
}

/// Можно ли принять новый список устройств после известного.
///
/// Нужна устройству, которое восстановило ключ аккаунта из копии и теперь хочет
/// опубликовать свой список: версия обязана расти, а запись основного устройства
/// (ключи и имя) — остаться прежней, иначе «восстановленное» устройство могло бы
/// молча подменить №1. Подпись здесь не проверяется (это делает `crypto_core`).
pub fn check_list_update(old: Option<&DeviceList>, new: &DeviceList) -> Result<(), ProtocolError> {
    let bad = |m: &str| Err(ProtocolError::InvalidDeviceList(m.into()));
    new.validate()?;
    let Some(old) = old else {
        return Ok(());
    };
    if old.account_id != new.account_id || old.account_pub != new.account_pub {
        return bad("list belongs to another account");
    }
    if new.version < old.version {
        return bad("list version went backwards");
    }
    if new.version == old.version && new != old {
        return bad("same list version with different content");
    }
    if old.device(PRIMARY_DEVICE) != new.device(PRIMARY_DEVICE) {
        return bad("primary device entry changed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceInfo;

    fn header() -> BackupHeader {
        BackupHeader {
            kdf: BackupKdfParams {
                m_cost_kib: 65_536,
                t_cost: 2,
                lanes: 1,
            },
            salt: [7; 16],
            nonce: [9; 12],
        }
    }

    fn payload() -> BackupPayload {
        BackupPayload {
            account_id: "0123456789abcdef0123456789abcdef".into(),
            account_secret: [0x11; 32],
            primary_x25519_pub: [0x22; 32],
            list_version_at_backup: 5,
            created_at: 1_700_000_000,
        }
    }

    #[test]
    fn header_layout_and_roundtrip() {
        let h = header();
        let b = h.to_bytes();
        assert_eq!(b.len(), 50);
        assert_eq!(&b[..8], b"MSNGRKEY");
        assert_eq!(b[8], 1);
        assert_eq!(b[9], 1);
        assert_eq!(&b[10..14], &65_536u32.to_le_bytes());
        let mut with_ct = b.to_vec();
        with_ct.extend_from_slice(&[1, 2, 3]);
        let (back, rest) = BackupHeader::parse(&with_ct).unwrap();
        assert_eq!(back, h);
        assert_eq!(rest, &[1, 2, 3]);
    }

    #[test]
    fn every_header_field_changes_bytes() {
        let base = header().to_bytes();
        let mut h = header();
        h.kdf.m_cost_kib += 1;
        assert_ne!(h.to_bytes(), base);
        let mut h = header();
        h.kdf.t_cost += 1;
        assert_ne!(h.to_bytes(), base);
        let mut h = header();
        h.kdf.lanes += 1;
        assert_ne!(h.to_bytes(), base);
        let mut h = header();
        h.salt[15] ^= 1;
        assert_ne!(h.to_bytes(), base);
        let mut h = header();
        h.nonce[0] ^= 1;
        assert_ne!(h.to_bytes(), base);
    }

    #[test]
    fn header_rejects_bad_input() {
        let good = header().to_bytes();
        for n in 0..BACKUP_HEADER_LEN {
            assert_eq!(
                BackupHeader::parse(&good[..n]).unwrap_err(),
                BackupFormatError::Truncated
            );
        }
        let mut b = good;
        b[0] ^= 1;
        assert_eq!(
            BackupHeader::parse(&b).unwrap_err(),
            BackupFormatError::NotABackup
        );
        let mut b = good;
        b[8] = 2;
        assert_eq!(
            BackupHeader::parse(&b).unwrap_err(),
            BackupFormatError::UnsupportedVersion(2)
        );
        let mut b = good;
        b[9] = 2;
        assert_eq!(
            BackupHeader::parse(&b).unwrap_err(),
            BackupFormatError::UnsupportedKdf(2)
        );
    }

    #[test]
    fn header_param_bounds() {
        let with = |m: u32, t: u32, l: u32| {
            let mut h = header();
            h.kdf = BackupKdfParams {
                m_cost_kib: m,
                t_cost: t,
                lanes: l,
            };
            BackupHeader::parse(&h.to_bytes()).map(|_| ())
        };
        assert!(with(65_536, 2, 1).is_ok());
        assert!(with(1_048_576, 16, 8).is_ok());
        let err = Err(BackupFormatError::ParamsOutOfRange);
        assert_eq!(with(65_535, 2, 1), err);
        assert_eq!(with(1_048_577, 2, 1), err);
        assert_eq!(with(u32::MAX, 2, 1), err);
        assert_eq!(with(65_536, 1, 1), err);
        assert_eq!(with(65_536, 17, 1), err);
        assert_eq!(with(65_536, 2, 0), err);
        assert_eq!(with(65_536, 2, 9), err);
        assert!(BackupKdfParams::DEFAULT.check().is_ok());
    }

    #[test]
    fn file_roundtrip_and_rejects() {
        let h = header();
        let ct = vec![5u8; 40];
        let text = encode_backup_file(&h, &ct);
        assert!(text.starts_with("mkeybackup1."));
        assert!(text.ends_with('\n'));
        assert!(!text.trim_end().contains(['=', '+', '/']));
        let (h2, aad, ct2) = decode_backup_file(text.as_bytes()).unwrap();
        assert_eq!(h2, h);
        assert_eq!(aad, h.to_bytes());
        assert_eq!(ct2, ct);
        // Без перевода строки и с CRLF тоже читается.
        assert!(decode_backup_file(text.trim_end().as_bytes()).is_ok());
        assert!(decode_backup_file(text.replace('\n', "\r\n").as_bytes()).is_ok());

        assert_eq!(
            decode_backup_file(b"").unwrap_err(),
            BackupFormatError::NotABackup
        );
        assert_eq!(
            decode_backup_file(b"hello").unwrap_err(),
            BackupFormatError::NotABackup
        );
        assert_eq!(
            decode_backup_file(&[0xff, 0xfe]).unwrap_err(),
            BackupFormatError::NotABackup
        );
        assert_eq!(
            decode_backup_file(b"mkeybackup1.!!!").unwrap_err(),
            BackupFormatError::Truncated
        );
        // Обрезка в любом месте: не паника; короче заголовка с тегом - всегда ошибка
        // (обрезку длиннее поймает AEAD).
        let min_chars = BACKUP_FILE_PREFIX.len() + (BACKUP_HEADER_LEN + BACKUP_TAG_LEN) * 4 / 3;
        for n in 0..text.len() {
            let r = decode_backup_file(&text.as_bytes()[..n]);
            if n < min_chars {
                assert!(r.is_err(), "n={n}");
            }
        }
        // Шифротекст короче тега.
        let short = encode_backup_file(&h, &[0u8; 15]);
        assert_eq!(
            decode_backup_file(short.as_bytes()).unwrap_err(),
            BackupFormatError::Truncated
        );
        // Слишком большой файл.
        let huge = vec![b'a'; MAX_BACKUP_FILE_LEN + 1];
        assert!(decode_backup_file(&huge).is_err());
    }

    #[test]
    fn payload_roundtrip() {
        let p = payload();
        let back = BackupPayload::parse(&p.to_bytes()).unwrap();
        assert_eq!(back.account_id, p.account_id);
        assert_eq!(back.account_secret, p.account_secret);
        assert_eq!(back.primary_x25519_pub, p.primary_x25519_pub);
        assert_eq!(back.list_version_at_backup, p.list_version_at_backup);
        assert_eq!(back.created_at, p.created_at);
    }

    #[test]
    fn every_payload_field_changes_bytes() {
        let base = payload().to_bytes();
        let mut p = payload();
        p.account_id.push('x');
        assert_ne!(p.to_bytes(), base);
        let mut p = payload();
        p.account_secret[0] ^= 1;
        assert_ne!(p.to_bytes(), base);
        let mut p = payload();
        p.primary_x25519_pub[0] ^= 1;
        assert_ne!(p.to_bytes(), base);
        let mut p = payload();
        p.list_version_at_backup += 1;
        assert_ne!(p.to_bytes(), base);
        let mut p = payload();
        p.created_at += 1;
        assert_ne!(p.to_bytes(), base);
    }

    #[test]
    fn payload_rejects_trailing_truncated_and_foreign() {
        let good = payload().to_bytes();
        let mut extra = good.clone();
        extra.push(0);
        assert!(BackupPayload::parse(&extra).is_err());
        for n in 0..good.len() {
            assert!(BackupPayload::parse(&good[..n]).is_err(), "n={n}");
        }
        let mut wrong = good.clone();
        wrong[0] ^= 1;
        assert!(BackupPayload::parse(&wrong).is_err());
        // Огромная длина account_id.
        let mut huge = DOMAIN_KEY_BACKUP.to_vec();
        huge.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(BackupPayload::parse(&huge).is_err());
    }

    #[test]
    fn payload_debug_has_no_secret() {
        let p = payload();
        let s = format!("{p:?}");
        assert!(!s.contains("17, 17"), "{s}");
        assert!(!s.contains("account_secret"), "{s}");
        assert!(s.contains(&p.account_id));
    }

    fn list(version: u64) -> DeviceList {
        DeviceList {
            account_id: "acc".into(),
            account_pub: [1; 32],
            version,
            devices: vec![DeviceInfo {
                device_id: 1,
                x25519_pub: [2; 32],
                ed25519_pub: [1; 32],
                name: "Ноутбук".into(),
            }],
        }
    }

    #[test]
    fn list_update_rules() {
        let old = list(3);
        // Первый список.
        assert!(check_list_update(None, &old).is_ok());
        // Та же версия, то же содержимое.
        assert!(check_list_update(Some(&old), &old.clone()).is_ok());
        // Нормальное добавление.
        let mut added = list(4);
        added.devices.push(DeviceInfo {
            device_id: 4,
            x25519_pub: [3; 32],
            ed25519_pub: [5; 32],
            name: "Телефон".into(),
        });
        assert!(check_list_update(Some(&old), &added).is_ok());
        // Откат.
        assert!(check_list_update(Some(&list(4)), &old).is_err());
        // Та же версия, другое содержимое.
        assert!(check_list_update(Some(&old), &added.clone_with_version(3)).is_err());
        // Смена X25519 №1.
        let mut n = list(4);
        n.devices[0].x25519_pub = [9; 32];
        assert!(check_list_update(Some(&old), &n).is_err());
        // Смена имени №1.
        let mut n = list(4);
        n.devices[0].name = "Другое".into();
        assert!(check_list_update(Some(&old), &n).is_err());
        // Чужой аккаунт.
        let mut n = list(4);
        n.account_id = "other".into();
        assert!(check_list_update(Some(&old), &n).is_err());
        // Структурно неверный новый список.
        let mut n = list(4);
        n.devices.clear();
        assert!(check_list_update(Some(&old), &n).is_err());
    }

    impl DeviceList {
        fn clone_with_version(&self, version: u64) -> Self {
            Self {
                version,
                ..self.clone()
            }
        }
    }
}
