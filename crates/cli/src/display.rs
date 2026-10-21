//! Мелочи для красивого вывода.

use chrono::{Local, TimeZone};
use storage::{ContactRow, Db};

/// Как называть собеседника: `@username`, если есть, иначе `account_id`.
pub fn contact_name(c: &ContactRow) -> String {
    c.username.clone().unwrap_or_else(|| c.account_id.clone())
}

pub fn peer_name(db: &Db, account_id: &str) -> String {
    match db.get_contact(account_id) {
        Ok(Some(c)) => contact_name(&c),
        _ => account_id.to_string(),
    }
}

pub fn timestamp(unix: i64) -> String {
    Local
        .timestamp_opt(unix, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| unix.to_string())
}

pub fn now() -> String {
    format!("[{}]", Local::now().format("%H:%M"))
}

/// Первые `max_chars` символов в одну строку.
pub fn preview(s: &str, max_chars: usize) -> String {
    let one_line = s.replace('\n', " ");
    if one_line.chars().count() <= max_chars {
        one_line
    } else {
        format!("{}…", one_line.chars().take(max_chars).collect::<String>())
    }
}
