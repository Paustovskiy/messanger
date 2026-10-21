//! Шифрование файла базы паролем (SQLCipher + Argon2id).
//!
//! * Ключ получается из пароля через **Argon2id** (64 МиБ памяти, 3 прохода) —
//!   так перебор паролей на видеокартах становится дорогим.
//! * Соль (16 случайных байт) SQLCipher хранит в начале самого файла, поэтому
//!   для расшифровки достаточно одного файла и пароля — бэкап не разваливается.
//! * Шифруется всё: история, контакты, ключи, метаданные. Без пароля файл —
//!   случайные байты.

use anyhow::{Context, Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use fs4::fs_std::FileExt;
use rusqlite::Connection;
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";
const SALT_LEN: usize = 16;

// Параметры Argon2id. Менять только с миграцией: от них зависит ключ.
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_PASSES: u32 = 3;
const ARGON2_LANES: u32 = 1;

/// Неверный пароль.
#[derive(Debug)]
pub struct WrongPassword;

impl fmt::Display for WrongPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("неверный пароль")
    }
}
impl std::error::Error for WrongPassword {}

/// База зашифрована, а пароль не передан.
#[derive(Debug)]
pub struct PasswordRequired;

impl fmt::Display for PasswordRequired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("база зашифрована — нужен пароль")
    }
}
impl std::error::Error for PasswordRequired {}

/// Как сейчас хранится файл базы.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileState {
    Missing,
    Plain,
    Encrypted,
}

/// Посмотреть на файл, не открывая его как базу.
pub fn file_state(path: &Path) -> Result<FileState> {
    let mut f = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(FileState::Missing),
        Err(e) => return Err(e).with_context(|| format!("open {}", path.display())),
    };
    let mut header = [0u8; 16];
    let n = read_up_to(&mut f, &mut header)?;
    Ok(match n {
        0 => FileState::Missing, // пустой файл — как будто его нет
        _ if n == 16 && &header == SQLITE_MAGIC => FileState::Plain,
        _ => FileState::Encrypted,
    })
}

fn read_up_to(f: &mut fs::File, buf: &mut [u8]) -> Result<usize> {
    let mut read = 0;
    while read < buf.len() {
        match f.read(&mut buf[read..])? {
            0 => break,
            n => read += n,
        }
    }
    Ok(read)
}

/// Соль из начала зашифрованного файла.
fn read_salt(path: &Path) -> Result<[u8; SALT_LEN]> {
    let mut f = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut salt = [0u8; SALT_LEN];
    if read_up_to(&mut f, &mut salt)? != SALT_LEN {
        bail!("файл базы повреждён: слишком короткий");
    }
    Ok(salt)
}

/// Ключ из пароля и соли.
fn derive_key(password: &str, salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_PASSES, ARGON2_LANES, Some(32))
        .map_err(|e| anyhow::anyhow!("argon2 params: {e}"))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| anyhow::anyhow!("argon2: {e}"))?;
    Ok(key)
}

/// Значение для `PRAGMA key` / `ATTACH … KEY`: «сырой» ключ и соль в hex.
fn key_literal(key: &[u8; 32], salt: &[u8; SALT_LEN]) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(4 + 96));
    s.push_str("x'");
    for b in key.iter().chain(salt.iter()) {
        s.push_str(&format!("{b:02x}"));
    }
    s.push('\'');
    s
}

/// Подготовить соединение к зашифрованной базе: задать ключ и убедиться, что
/// он подходит. Для нового файла соль создаётся случайно, для существующего —
/// читается из его начала.
pub(crate) fn unlock(conn: &Connection, path: &Path, password: &str, new_file: bool) -> Result<()> {
    let salt = if new_file {
        random_salt()?
    } else {
        read_salt(path)?
    };
    let key = derive_key(password, &salt)?;
    conn.execute_batch(&format!(
        "PRAGMA key = \"{}\";",
        key_literal(&key, &salt).as_str()
    ))?;
    verify_key(conn)
}

/// SQLCipher принимает любой ключ и ругается только при первом чтении.
fn verify_key(conn: &Connection) -> Result<()> {
    match conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    }) {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(e, _))
            if e.code == rusqlite::ErrorCode::NotADatabase =>
        {
            Err(WrongPassword.into())
        }
        Err(e) => Err(e.into()),
    }
}

fn random_salt() -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    getrandom(&mut salt)?;
    Ok(salt)
}

/// Случайные байты от SQLCipher/OpenSSL — без лишней зависимости.
fn getrandom(buf: &mut [u8]) -> Result<()> {
    let conn = Connection::open_in_memory()?;
    let bytes: Vec<u8> =
        conn.query_row("SELECT randomblob(?1)", [buf.len() as i64], |r| r.get(0))?;
    buf.copy_from_slice(&bytes);
    Ok(())
}

/// Перешифровать файл базы: поставить пароль, сменить его или снять.
///
/// Работает через копию: данные экспортируются в новый файл рядом, новый файл
/// проверяется, и только потом атомарно подменяет старый. Если что-то пойдёт
/// не так, исходная база остаётся как была. Другие процессы с этой базой
/// (`listen`) на это время нужно остановить.
pub fn reencrypt(path: &Path, current: Option<&str>, new: Option<&str>) -> Result<()> {
    // Никто другой не должен держать базу открытой: иначе он продолжит писать
    // в старый файл, и всё записанное после подмены пропадёт.
    let lock = open_lock_file(path)?;
    if !FileExt::try_lock_exclusive(&lock)? {
        bail!(
            "база сейчас открыта другим процессом (например, `messenger listen`) — \
             закройте его и повторите"
        );
    }

    let state = file_state(path)?;
    match (state, current) {
        (FileState::Missing, _) => bail!("базы {} нет", path.display()),
        (FileState::Encrypted, None) => return Err(PasswordRequired.into()),
        (FileState::Plain, Some(_)) => bail!("база не зашифрована — текущий пароль не нужен"),
        _ => {}
    }

    let tmp = sibling(path, "reencrypt-tmp");
    remove_db_files(&tmp)?;

    {
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        if let Some(pw) = current {
            unlock(&conn, path, pw, false)?;
        }
        // Всё из журнала WAL — в основной файл, чтобы экспорт ничего не потерял.
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;

        // Ключ — параметром: `x'…'` SQLCipher понимает как «сырой» ключ с солью,
        // пустая строка — как «без шифрования».
        let attach_key = match new {
            Some(pw) => {
                let salt = random_salt()?;
                key_literal(&*derive_key(pw, &salt)?, &salt)
            }
            None => Zeroizing::new(String::new()),
        };
        conn.execute(
            "ATTACH DATABASE ?1 AS target KEY ?2",
            rusqlite::params![tmp.to_string_lossy(), attach_key.as_str()],
        )?;
        conn.query_row("SELECT sqlcipher_export('target')", [], |_| Ok(()))?;
        conn.execute_batch(&format!(
            "PRAGMA target.user_version = {version}; DETACH DATABASE target;"
        ))?;
    }

    // Новый файл должен открываться новым паролем — проверяем до подмены.
    {
        let check = Connection::open(&tmp)?;
        if let Some(pw) = new {
            unlock(&check, &tmp, pw, false).context("проверка перешифрованной базы")?;
        } else {
            verify_key(&check)?;
        }
        check.execute_batch("PRAGMA journal_mode = DELETE;")?;
    }
    restrict(&tmp)?;

    remove_db_files_except_main(path)?;
    fs::rename(&tmp, path).with_context(|| format!("replace {}", path.display()))?;
    Ok(())
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{suffix}"));
    path.with_file_name(name)
}

fn remove_db_files(path: &Path) -> Result<()> {
    remove_db_files_except_main(path)?;
    match fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

/// Убрать `-wal`/`-shm` старого файла: после полного checkpoint они пусты,
/// а к новому файлу не подходят.
fn remove_db_files_except_main(path: &Path) -> Result<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        match fs::remove_file(PathBuf::from(name)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(unix)]
fn restrict(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> Result<()> {
    Ok(())
}

/// Файл-замок рядом с базой. Каждый, кто открыл базу, держит на нём общую
/// блокировку; перешифровка требует исключительной.
pub(crate) fn open_lock_file(db: &Path) -> Result<fs::File> {
    let path = sibling(db, "lock");
    let f = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    restrict(&path)?;
    Ok(f)
}

/// Общая блокировка на время работы с базой.
pub(crate) fn shared_lock(db: &Path) -> Result<fs::File> {
    let f = open_lock_file(db)?;
    FileExt::lock_shared(&f).context("lock database")?;
    Ok(f)
}
