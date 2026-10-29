//! Пароль от базы: спросить у человека или взять из окружения.
//!
//! Переменные окружения — для скриптов и автоматизации. Они удобны, но менее
//! безопасны: значение видно другим процессам того же пользователя и может
//! попасть в историю оболочки. Человеку лучше вводить пароль с клавиатуры.

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

/// Пароль от базы (и при `init` — пароль для новой базы).
pub const ENV_PASSWORD: &str = "MESSENGER_PASSWORD";
/// Новый пароль для `set-password`.
pub const ENV_NEW_PASSWORD: &str = "MESSENGER_NEW_PASSWORD";

/// Код восстановления ключа аккаунта для `restore-key`.
pub const ENV_BACKUP_CODE: &str = "MESSENGER_BACKUP_CODE";

const MIN_CHARS: usize = 8;

/// Спросить существующий пароль.
pub fn ask(env_var: &str, prompt: &str) -> Result<Zeroizing<String>> {
    if let Some(pw) = from_env(env_var) {
        return Ok(pw);
    }
    prompt_hidden(prompt, env_var)
}

/// Придумать новый пароль: из окружения или дважды с клавиатуры.
pub fn ask_new(env_var: &str, what: &str) -> Result<Zeroizing<String>> {
    if let Some(pw) = from_env(env_var) {
        check_strength(&pw)?;
        return Ok(pw);
    }
    eprintln!("{what}. Без него восстановить данные будет невозможно — запомните его.");
    loop {
        let first = prompt_hidden("Пароль: ", env_var)?;
        if let Err(e) = check_strength(&first) {
            eprintln!("{e}");
            continue;
        }
        let second = prompt_hidden("Ещё раз: ", env_var)?;
        if *first == *second {
            return Ok(first);
        }
        eprintln!("Пароли не совпали, попробуйте снова.");
    }
}

fn from_env(var: &str) -> Option<Zeroizing<String>> {
    std::env::var(var)
        .ok()
        .filter(|v| !v.is_empty())
        .map(Zeroizing::new)
}

fn prompt_hidden(prompt: &str, env_var: &str) -> Result<Zeroizing<String>> {
    rpassword::prompt_password(prompt).map(Zeroizing::new).with_context(|| {
        format!("не удалось спросить пароль (нет терминала?) — передайте его через переменную {env_var}")
    })
}

fn check_strength(pw: &str) -> Result<()> {
    if pw.chars().count() < MIN_CHARS {
        bail!("пароль слишком короткий: нужно хотя бы {MIN_CHARS} символов");
    }
    Ok(())
}
