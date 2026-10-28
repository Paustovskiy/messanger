//! Резервная копия ключа аккаунта, зашифрованная кодом на бумаге.
//!
//! Ключ AEAD = Argon2id(код, соль) — 32 байта; сам файл шифруется
//! ChaCha20-Poly1305, весь заголовок файла идёт в AAD. Формат байтов описан в
//! `protocol::backup`, здесь только криптография.
//!
//! **Код** (пароль копии) придумывает не человек, а программа: 28 знаков из 32 без
//! похожих (`A–Z` без `I`, `O`, плюс `2–9`) — ровно 5 бит на знак, итого 140 бит
//! энтропии (минимум 128). Перебирать такой код нечем, Argon2 — лишь запас прочности.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{AeadInPlace, KeyInit, generic_array::GenericArray};
use ed25519_dalek::SigningKey;
use protocol::backup::{
    BACKUP_TAG_LEN, BackupFormatError, BackupHeader, BackupKdfParams, BackupPayload,
    decode_backup_file, encode_backup_file,
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{check_account_id, random_bytes};

/// Алфавит кода: 32 знака без `0 1 I O`, чтобы не путать на бумаге.
const CODE_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
/// Знаков в коде: 28 * 5 бит = 140 бит.
pub const BACKUP_CODE_LEN: usize = 28;
/// Знаков в группе при показе.
pub const BACKUP_CODE_GROUP: usize = 4;
/// Энтропия кода в битах.
pub const BACKUP_CODE_BITS: usize = BACKUP_CODE_LEN * 5;
/// Дольше этого код при вводе не разбираем.
const MAX_CODE_INPUT: usize = 128;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BackupCodeError {
    #[error("в коде должно быть {BACKUP_CODE_LEN} знаков, введено {0}")]
    WrongLength(usize),
    #[error("в коде есть недопустимый знак (позиция {0}); допустимы A-Z (кроме I и O) и 2-9")]
    InvalidChar(usize),
    #[error("код слишком длинный")]
    TooLong,
}

/// Код резервной копии в нормализованном виде (28 заглавных знаков без разделителей).
pub struct BackupCode(Zeroizing<String>);

impl std::fmt::Debug for BackupCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BackupCode(..)")
    }
}

impl BackupCode {
    /// Новый случайный код.
    pub fn generate() -> Self {
        let bytes = Zeroizing::new(random_bytes::<BACKUP_CODE_LEN>());
        let mut s = Zeroizing::new(String::with_capacity(BACKUP_CODE_LEN));
        for b in bytes.iter() {
            s.push(CODE_ALPHABET[usize::from(b & 31)] as char);
        }
        Self(s)
    }

    /// Разобрать введённый человеком код: регистр, пробелы и дефисы не важны.
    pub fn parse(input: &str) -> Result<Self, BackupCodeError> {
        if input.len() > MAX_CODE_INPUT {
            return Err(BackupCodeError::TooLong);
        }
        let mut s = Zeroizing::new(String::with_capacity(BACKUP_CODE_LEN));
        for (i, c) in input.chars().enumerate() {
            if c.is_whitespace() || c == '-' {
                continue;
            }
            let up = c.to_ascii_uppercase();
            if !up.is_ascii() || !CODE_ALPHABET.contains(&(up as u8)) {
                return Err(BackupCodeError::InvalidChar(i + 1));
            }
            s.push(up);
        }
        if s.len() != BACKUP_CODE_LEN {
            return Err(BackupCodeError::WrongLength(s.len()));
        }
        Ok(Self(s))
    }

    /// Показать группами: `ABCD-EFGH-…`.
    pub fn display_grouped(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(BACKUP_CODE_LEN + 8));
        for (i, c) in self.0.chars().enumerate() {
            if i > 0 && i % BACKUP_CODE_GROUP == 0 {
                out.push('-');
            }
            out.push(c);
        }
        out
    }

    /// Совпадает ли введённое человеком с последней группой кода (подтверждение, что код
    /// записан верно). Нормализация как в [`BackupCode::parse`]: регистр, пробелы и
    /// дефисы не важны. Сравнение без раннего выхода по первому отличию.
    pub fn last_group_matches(&self, input: &str) -> bool {
        if input.len() > MAX_CODE_INPUT {
            return false;
        }
        let mut typed = Zeroizing::new(Vec::<u8>::with_capacity(MAX_CODE_INPUT));
        for c in input.chars() {
            if c.is_whitespace() || c == '-' {
                continue;
            }
            if !c.is_ascii() {
                return false;
            }
            typed.push(c.to_ascii_uppercase() as u8);
        }
        let want = &self.0.as_bytes()[self.0.len().saturating_sub(BACKUP_CODE_GROUP)..];
        if typed.len() != want.len() {
            return false;
        }
        typed
            .iter()
            .zip(want)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }

    /// Байты, из которых Argon2 выводит ключ.
    pub fn password(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BackupError {
    #[error(transparent)]
    Format(#[from] BackupFormatError),
    #[error("неверный пароль или файл повреждён")]
    WrongPasswordOrCorrupt,
    #[error("не удалось выработать ключ из пароля")]
    Kdf,
    #[error("не удалось зашифровать резервную копию")]
    Encrypt,
    #[error("содержимое резервной копии не годится: {0}")]
    Invalid(String),
}

/// Что лежит в резервной копии: ключ аккаунта и данные для продолжения аккаунта.
pub struct AccountBackup {
    account_id: String,
    account_sign: SigningKey,
    primary_x25519_pub: [u8; 32],
    list_version_at_backup: u64,
    created_at: u64,
}

impl std::fmt::Debug for AccountBackup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Секрет ключа аккаунта не печатается никогда.
        f.debug_struct("AccountBackup")
            .field("account_id", &self.account_id)
            .field("list_version_at_backup", &self.list_version_at_backup)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

impl AccountBackup {
    pub fn new(
        account_id: impl Into<String>,
        account_sign: SigningKey,
        primary_x25519_pub: [u8; 32],
        list_version_at_backup: u64,
        created_at: u64,
    ) -> Self {
        Self {
            account_id: account_id.into(),
            account_sign,
            primary_x25519_pub,
            list_version_at_backup,
            created_at,
        }
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn account_sign(&self) -> &SigningKey {
        &self.account_sign
    }

    pub fn account_pub(&self) -> [u8; 32] {
        self.account_sign.verifying_key().to_bytes()
    }

    pub fn primary_x25519_pub(&self) -> [u8; 32] {
        self.primary_x25519_pub
    }

    pub fn list_version_at_backup(&self) -> u64 {
        self.list_version_at_backup
    }

    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    fn check(&self) -> Result<(), BackupError> {
        protocol::check_id(&self.account_id, "account_id")
            .map_err(|e| BackupError::Invalid(e.to_string()))?;
        // Для ID «из ключа» он обязан быть выведен из этого ключа аккаунта.
        check_account_id(&self.account_id, &self.account_pub())
            .map_err(|_| BackupError::Invalid("account_id не соответствует ключу".into()))
    }
}

fn derive_key(
    password: &[u8],
    salt: &[u8],
    p: &BackupKdfParams,
) -> Result<Zeroizing<[u8; 32]>, BackupError> {
    // Границы проверяются до Argon2: параметры могли прийти из чужого файла.
    p.check()?;
    let params =
        Params::new(p.m_cost_kib, p.t_cost, p.lanes, Some(32)).map_err(|_| BackupError::Kdf)?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|_| BackupError::Kdf)?;
    Ok(key)
}

/// Зашифровать копию с параметрами по умолчанию (Argon2id 256 МиБ, t=3, p=1).
/// Возвращает текст файла.
pub fn seal_account_backup(password: &[u8], backup: &AccountBackup) -> Result<String, BackupError> {
    seal_account_backup_with_params(password, backup, BackupKdfParams::DEFAULT)
}

/// То же с явными параметрами (в границах формата). Для тестов и для будущей смены
/// значений по умолчанию.
pub fn seal_account_backup_with_params(
    password: &[u8],
    backup: &AccountBackup,
    params: BackupKdfParams,
) -> Result<String, BackupError> {
    params.check()?;
    backup.check()?;
    let header = BackupHeader {
        kdf: params,
        salt: random_bytes(),
        nonce: random_bytes(),
    };
    let key = derive_key(password, &header.salt, &header.kdf)?;
    let payload = BackupPayload {
        account_id: backup.account_id.clone(),
        account_secret: backup.account_sign.to_bytes(),
        primary_x25519_pub: backup.primary_x25519_pub,
        list_version_at_backup: backup.list_version_at_backup,
        created_at: backup.created_at,
    };
    let plain = payload.to_bytes(); // Zeroizing: обнуляется при выходе из области
    // Буфер с запасом под тег: без перевыделения, чтобы секрет не остался в старой памяти.
    let mut buf = Zeroizing::new(Vec::with_capacity(plain.len() + BACKUP_TAG_LEN));
    buf.extend_from_slice(&plain);
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key.as_ref()));
    cipher
        .encrypt_in_place(
            GenericArray::from_slice(&header.nonce),
            &header.to_bytes(),
            &mut *buf,
        )
        .map_err(|_| BackupError::Encrypt)?;
    Ok(encode_backup_file(&header, &buf))
}

/// Расшифровать файл копии. Argon2 запускается только после проверки заголовка.
pub fn open_account_backup(bytes: &[u8], password: &[u8]) -> Result<AccountBackup, BackupError> {
    let (header, aad, ct) = decode_backup_file(bytes)?;
    let key = derive_key(password, &header.salt, &header.kdf)?;
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key.as_ref()));
    let mut buf = Zeroizing::new(ct);
    cipher
        .decrypt_in_place(GenericArray::from_slice(&header.nonce), &aad, &mut *buf)
        .map_err(|_| BackupError::WrongPasswordOrCorrupt)?;
    let payload = BackupPayload::parse(&buf)?;
    let backup = AccountBackup {
        account_id: payload.account_id.clone(),
        account_sign: SigningKey::from_bytes(&payload.account_secret),
        primary_x25519_pub: payload.primary_x25519_pub,
        list_version_at_backup: payload.list_version_at_backup,
        created_at: payload.created_at,
    };
    backup.check()?;
    Ok(backup)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_has_enough_entropy_and_unique_alphabet() {
        const { assert!(BACKUP_CODE_BITS >= 128) };
        assert_eq!(CODE_ALPHABET.len(), 32, "5 бит на знак без смещения");
        let mut seen = std::collections::HashSet::new();
        assert!(CODE_ALPHABET.iter().all(|c| seen.insert(*c)));
        assert!(!CODE_ALPHABET.iter().any(|c| b"0O1I".contains(c)));
    }

    #[test]
    fn code_generation_and_display() {
        let a = BackupCode::generate();
        let b = BackupCode::generate();
        assert_ne!(a.password(), b.password());
        assert_eq!(a.password().len(), BACKUP_CODE_LEN);
        let shown = a.display_grouped();
        assert_eq!(
            shown.len(),
            BACKUP_CODE_LEN + BACKUP_CODE_LEN / BACKUP_CODE_GROUP - 1
        );
        assert!(shown.split('-').all(|g| g.len() == BACKUP_CODE_GROUP));
        // Показанное разбирается обратно в тот же код.
        assert_eq!(BackupCode::parse(&shown).unwrap().password(), a.password());
    }

    #[test]
    fn code_parse_normalizes() {
        let c = BackupCode::generate();
        let shown = c.display_grouped();
        let lower = shown.to_lowercase();
        let spaced = shown.replace('-', "  ");
        let padded = format!("  {}\n", shown.replace('-', " - "));
        for v in [lower, spaced, padded, shown.replace('-', "")] {
            assert_eq!(
                BackupCode::parse(&v).unwrap().password(),
                c.password(),
                "{v}"
            );
        }
    }

    #[test]
    fn last_group_confirmation() {
        let code = BackupCode::generate();
        let grouped = code.display_grouped();
        let last = grouped.rsplit('-').next().unwrap().to_string();
        assert_eq!(last.len(), BACKUP_CODE_GROUP);
        assert!(code.last_group_matches(&last));
        assert!(code.last_group_matches(&format!("  {}  ", last.to_lowercase())));
        assert!(code.last_group_matches(&format!("{}-{}", &last[..2], &last[2..])));
        // Другая группа, неполный ввод, лишнее, пустой ввод, не-ASCII.
        let first = grouped.split('-').next().unwrap().to_string();
        if first != last {
            assert!(!code.last_group_matches(&first));
        }
        assert!(!code.last_group_matches(&last[..3]));
        assert!(!code.last_group_matches(&format!("{last}A")));
        assert!(!code.last_group_matches(&grouped));
        assert!(!code.last_group_matches(""));
        assert!(!code.last_group_matches("ЖЖЖЖ"));
        assert!(!code.last_group_matches(&"A".repeat(10_000)));
    }

    #[test]
    fn code_parse_rejects_bad_input() {
        let e = |s: &str| BackupCode::parse(s).unwrap_err();
        assert_eq!(e(""), BackupCodeError::WrongLength(0));
        assert_eq!(e("ABCD-EFGH"), BackupCodeError::WrongLength(8));
        let ok = "ABCDEFGHJKLMNPQRSTUVWXYZ2345";
        assert!(BackupCode::parse(ok).is_ok());
        assert_eq!(e(&format!("{ok}A")), BackupCodeError::WrongLength(29));
        // Похожие знаки не из алфавита не угадываются молча.
        assert_eq!(e(&ok.replace('A', "0")), BackupCodeError::InvalidChar(1));
        assert_eq!(e(&ok.replace('B', "O")), BackupCodeError::InvalidChar(2));
        assert_eq!(e(&ok.replace('C', "1")), BackupCodeError::InvalidChar(3));
        assert_eq!(e(&ok.replace('D', "I")), BackupCodeError::InvalidChar(4));
        assert_eq!(e("ЖЖЖЖ"), BackupCodeError::InvalidChar(1));
        assert_eq!(e(&"A".repeat(500)), BackupCodeError::TooLong);
        // Сообщения не содержат введённого кода.
        assert!(!e(&ok.replace('A', "0")).to_string().contains("BCDE"));
    }

    #[test]
    fn code_debug_hides_value() {
        let c = BackupCode::generate();
        let s = format!("{c:?}");
        assert!(!s.contains(std::str::from_utf8(c.password()).unwrap()));
    }

    // Параметры для скорости: нижняя граница формата.
    const FAST: BackupKdfParams = BackupKdfParams {
        m_cost_kib: 65_536,
        t_cost: 2,
        lanes: 1,
    };

    fn sample() -> AccountBackup {
        let sign = SigningKey::from_bytes(&[0x42; 32]);
        AccountBackup::new(
            crate::account_id_for(&sign.verifying_key().to_bytes()),
            sign,
            [0x24; 32],
            7,
            1_700_000_000,
        )
    }

    #[test]
    fn roundtrip() {
        let b = sample();
        let file = seal_account_backup_with_params(b"pw", &b, FAST).unwrap();
        let back = open_account_backup(file.as_bytes(), b"pw").unwrap();
        assert_eq!(back.account_id(), b.account_id());
        assert_eq!(back.account_sign().to_bytes(), [0x42; 32]);
        assert_eq!(back.primary_x25519_pub(), [0x24; 32]);
        assert_eq!(back.list_version_at_backup(), 7);
        assert_eq!(back.created_at(), 1_700_000_000);
    }

    #[test]
    fn roundtrip_with_default_params() {
        let b = sample();
        let code = BackupCode::generate();
        let file = seal_account_backup(code.password(), &b).unwrap();
        let (h, _, _) = decode_backup_file(file.as_bytes()).unwrap();
        assert_eq!(h.kdf, BackupKdfParams::DEFAULT);
        assert_eq!(
            (h.kdf.m_cost_kib, h.kdf.t_cost, h.kdf.lanes),
            (262_144, 3, 1)
        );
        let typed = BackupCode::parse(&code.display_grouped().to_lowercase()).unwrap();
        let back = open_account_backup(file.as_bytes(), typed.password()).unwrap();
        assert_eq!(back.account_id(), b.account_id());
    }

    #[test]
    fn wrong_password_has_one_message() {
        let file = seal_account_backup_with_params(b"pw", &sample(), FAST).unwrap();
        let e = open_account_backup(file.as_bytes(), b"other").unwrap_err();
        assert_eq!(e, BackupError::WrongPasswordOrCorrupt);
        assert_eq!(e.to_string(), "неверный пароль или файл повреждён");
    }

    /// Подмена любого байта заголовка и шифротекста (в сыром виде до base64).
    #[test]
    fn every_tampered_byte_is_rejected() {
        let file = seal_account_backup_with_params(b"pw", &sample(), FAST).unwrap();
        let raw = {
            use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
            URL_SAFE_NO_PAD
                .decode(file.trim_end().strip_prefix("mkeybackup1.").unwrap())
                .unwrap()
        };
        let results: Vec<usize> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..4)
                .map(|t| {
                    let raw = &raw;
                    s.spawn(move || {
                        let mut bad = vec![];
                        for i in (t..raw.len()).step_by(4) {
                            let mut m = raw.clone();
                            m[i] ^= 1;
                            let text = encode_raw(&m);
                            if open_account_backup(text.as_bytes(), b"pw").is_ok() {
                                bad.push(i);
                            }
                        }
                        bad
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|h| h.join().unwrap())
                .collect()
        });
        assert!(results.is_empty(), "приняты подмены байтов: {results:?}");
    }

    fn encode_raw(raw: &[u8]) -> String {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        format!("mkeybackup1.{}\n", URL_SAFE_NO_PAD.encode(raw))
    }

    #[test]
    fn two_backups_differ() {
        let b = sample();
        let f1 = seal_account_backup_with_params(b"pw", &b, FAST).unwrap();
        let f2 = seal_account_backup_with_params(b"pw", &b, FAST).unwrap();
        let (h1, _, c1) = decode_backup_file(f1.as_bytes()).unwrap();
        let (h2, _, c2) = decode_backup_file(f2.as_bytes()).unwrap();
        assert_ne!(h1.salt, h2.salt);
        assert_ne!(h1.nonce, h2.nonce);
        assert_ne!(c1, c2);
    }

    #[test]
    fn foreign_account_id_is_refused() {
        // ID выведен из другого ключа: seal отказывается...
        let other = SigningKey::from_bytes(&[1; 32]);
        let bad = AccountBackup::new(
            crate::account_id_for(&other.verifying_key().to_bytes()),
            SigningKey::from_bytes(&[2; 32]),
            [0; 32],
            1,
            1,
        );
        assert!(matches!(
            seal_account_backup_with_params(b"pw", &bad, FAST),
            Err(BackupError::Invalid(_))
        ));
        // ...и open отказывается, даже если AEAD сошёлся (файл собран вручную).
        let header = BackupHeader {
            kdf: FAST,
            salt: [1; 16],
            nonce: [2; 12],
        };
        let payload = BackupPayload {
            account_id: bad.account_id().into(),
            account_secret: [2; 32],
            primary_x25519_pub: [0; 32],
            list_version_at_backup: 1,
            created_at: 1,
        };
        let key = derive_key(b"pw", &header.salt, &header.kdf).unwrap();
        let mut buf = payload.to_bytes().to_vec();
        ChaCha20Poly1305::new(GenericArray::from_slice(key.as_ref()))
            .encrypt_in_place(
                GenericArray::from_slice(&header.nonce),
                &header.to_bytes(),
                &mut buf,
            )
            .unwrap();
        let file = encode_backup_file(&header, &buf);
        assert!(matches!(
            open_account_backup(file.as_bytes(), b"pw"),
            Err(BackupError::Invalid(_))
        ));
    }

    #[test]
    fn huge_memory_cost_is_rejected_fast() {
        let header = BackupHeader {
            kdf: BackupKdfParams {
                m_cost_kib: u32::MAX,
                t_cost: 3,
                lanes: 1,
            },
            salt: [0; 16],
            nonce: [0; 12],
        };
        let file = encode_backup_file(&header, &[0u8; 64]);
        let t = std::time::Instant::now();
        let e = open_account_backup(file.as_bytes(), b"pw").unwrap_err();
        assert_eq!(e, BackupError::Format(BackupFormatError::ParamsOutOfRange));
        assert!(t.elapsed() < std::time::Duration::from_millis(200));
        // И при запечатывании.
        let too_big = BackupKdfParams {
            m_cost_kib: u32::MAX,
            ..FAST
        };
        assert!(seal_account_backup_with_params(b"pw", &sample(), too_big).is_err());
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        for input in [&b""[..], b"x", b"mkeybackup1.", b"mkeybackup1.AAAA\n"] {
            assert!(open_account_backup(input, b"pw").is_err());
        }
    }

    #[test]
    fn debug_has_no_secret() {
        let s = format!("{:?}", sample());
        assert!(!s.contains("66, 66"), "{s}");
        assert!(!s.contains("account_sign"), "{s}");
        assert!(s.contains("account_id"));
    }
}
