//! `restore-key`: восстановить ключ аккаунта из резервной копии в новом профиле.
//!
//! Профиль становится новым устройством аккаунта: оно получает ключ аккаунта,
//! добавляет себя в список устройств (подписав его этим ключом) и публикует список
//! на релее. №1 в списке остаётся как есть, контакты и история не переносятся.
//! Формат файла и криптография: `protocol::backup` и `crypto_core::backup`.

use crate::relay_client::RelayConn;
use crate::session::Session;
use crate::{ACCEPT_TIMEOUT, LIST_ATTEMPTS, devices, messaging, password};
use anyhow::{Context, Result, anyhow, bail};
use crypto_core::Identity;
use crypto_core::backup::{AccountBackup, BackupCode, BackupError, open_account_backup};
use protocol::backup::{BackupKdfParams, MAX_BACKUP_FILE_LEN, check_list_update};
use protocol::{
    ClientMessage, DeviceInfo, DeviceList, MAX_DEVICES, PRIMARY_DEVICE, ServerMessage,
    SignedDeviceListB64,
};
use std::cell::Cell;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use storage::{Db, FileState, IdentityRow, PendingRestore};
use zeroize::Zeroizing;

/// Почему восстановление остановилось и что делать с записью о нём.
enum Fail {
    /// Релей точно не хранит наших ключей (свежий список без них, явный отказ):
    /// запись можно убрать всегда.
    Clear(anyhow::Error),
    /// Список не отправлялся, но свежего списка без наших ключей мы не видели. При
    /// первом запуске запись убираем; при повторе она остаётся: прошлый запуск мог
    /// успеть опубликовать эти ключи.
    Early(anyhow::Error),
    /// Список мог дойти до релея, ответа нет: запись остаётся для продолжения.
    Keep(anyhow::Error),
}

/// Итог публикации: список, который теперь на релее, и наш номер в нём.
struct Published {
    list: DeviceList,
    wire: SignedDeviceListB64,
    number: u32,
}

pub fn cmd_restore_key(path: &Path, file: &Path, name: &str, relay: &str) -> Result<()> {
    let name = crate::check_device_name(name)?;

    // Состояние профиля. Новую базу пока не создаём: сначала убедимся, что копия
    // открывается.
    let (mut db, saved) = match storage::file_state(path)? {
        FileState::Plain => bail!(
            "restore-key только в базу с паролем: этот профиль не зашифрован. \
             Используйте новый профиль"
        ),
        FileState::Missing => (None, None),
        FileState::Encrypted => {
            let pw = password::ask(password::ENV_PASSWORD, "Пароль от базы: ")?;
            let db = Db::open(path, Some(&pw))?;
            if db.get_local_identity()?.is_some() {
                bail!(
                    "в этом профиле уже есть личность. Ключ аккаунта восстанавливают в новом, \
                     пустом профиле: `messenger --profile <имя> restore-key …`"
                );
            }
            if db.pending_link()?.is_some() {
                bail!(
                    "в этом профиле начато подключение (`link`). Используйте новый профиль: \
                     `messenger --profile <имя> restore-key …`"
                );
            }
            let saved = db.pending_restore()?;
            (Some(db), saved)
        }
    };

    let bytes = read_limited(file, MAX_BACKUP_FILE_LEN)?;
    let (header, _, _) = protocol::backup::decode_backup_file(&bytes)
        .map_err(|e| anyhow!("это не файл резервной копии: {e}"))?;
    if let Some(w) = kdf_warning(&header.kdf) {
        eprintln!("! {w}");
    }

    let code = password::ask(password::ENV_BACKUP_CODE, "Код восстановления: ")?;
    let code = BackupCode::parse(&code).map_err(|e| anyhow!("код восстановления: {e}"))?;
    let backup = open_account_backup(&bytes, code.password()).map_err(|e| match e {
        BackupError::WrongPasswordOrCorrupt => {
            anyhow!("неверный код восстановления или файл повреждён")
        }
        other => anyhow!("{other}"),
    })?;
    drop(code);
    let account_secret = Zeroizing::new(backup.account_sign().to_bytes());
    let fingerprint = crypto_core::fingerprint(&backup.primary_x25519_pub(), &backup.account_pub());
    println!("Копия открыта.");
    println!("account_id: {}", backup.account_id());
    println!("отпечаток аккаунта: {fingerprint}");
    match i64::try_from(backup.created_at()) {
        Ok(t) => println!("копия сделана: {}", crate::display::timestamp(t)),
        Err(_) => println!("копия сделана: неизвестно когда"),
    }

    // Недоделанное восстановление другого аккаунта (или с другим ключом) не трогаем.
    let saved = match saved {
        Some(p) if p.account_id == backup.account_id() && p.account_secret == *account_secret => {
            Some(p)
        }
        Some(_) => bail!(
            "в этом профиле не завершено восстановление другого аккаунта. \
             Используйте новый профиль: `messenger --profile <имя> restore-key …`"
        ),
        None => None,
    };

    let db = match db.take() {
        Some(db) => db,
        None => {
            let pw = password::ask_new(
                password::ENV_PASSWORD,
                "Придумайте пароль для базы этого устройства",
            )?;
            Db::open(path, Some(&pw))?
        }
    };

    // Ключи устройства записываем ДО выхода в сеть: если ответ релея потеряется,
    // повтор команды продолжит с теми же ключами, а не добавит второе устройство.
    let pending = PendingRestore {
        account_id: backup.account_id().to_owned(),
        account_secret: *account_secret,
        x_secret: saved
            .as_ref()
            .map_or_else(crypto_core::random_bytes, |p| p.x_secret),
        sign_secret: saved
            .as_ref()
            .map_or_else(crypto_core::random_bytes, |p| p.sign_secret),
        name: name.to_owned(),
    };
    db.set_pending_restore(&pending)?;

    let resumed = saved.is_some();
    let sent = Cell::new(false);
    let outcome = crate::runtime()?.block_on(async {
        tokio::select! {
            r = publish_flow(relay, &backup, &pending, &sent) => r,
            _ = crate::shutdown_signal() => Err(if sent.get() {
                Fail::Keep(anyhow!(
                    "прервано после отправки: повторите `restore-key` с теми же файлом и \
                     кодом, восстановление продолжится"
                ))
            } else {
                Fail::Early(anyhow!("прервано"))
            }),
        }
    });
    let done = match outcome {
        Ok(d) => d,
        Err(Fail::Clear(e)) => {
            clear_pending(&db);
            return Err(e);
        }
        Err(Fail::Early(e)) => {
            if resumed {
                return Err(e.context(
                    "запись о восстановлении сохранена: повторите `restore-key` с теми же \
                     файлом и кодом или используйте новый профиль",
                ));
            }
            clear_pending(&db);
            return Err(e);
        }
        Err(Fail::Keep(e)) => return Err(e),
    };

    // Финиш одной транзакцией: либо устройство готово целиком, либо запись о
    // восстановлении остаётся и команду можно повторить.
    let keys = Identity::from_secrets(&pending.account_id, pending.x_secret, pending.sign_secret);
    db.immediate(|| {
        db.upsert_identity(&IdentityRow {
            account_id: pending.account_id.clone(),
            device_id: done.number,
            username: None,
            secret: keys.x_secret_bytes(),
            public: keys.x_public_bytes(),
            sign_secret: Some(keys.sign_secret_bytes()),
            sign_public: Some(keys.sign_public_bytes()),
            account_sign_secret: Some(*account_secret),
        })?;
        db.save_device_list(
            &pending.account_id,
            done.list.version,
            &serde_json::to_string(&done.wire)?,
        )?;
        db.clear_pending_restore()
    })?;

    if let Err(e) = announce_device(&db, relay) {
        eprintln!(
            "! устройство восстановлено, но предключи пока не опубликованы: {e:#}. \
             Выполните `messenger sync` или `messenger listen`."
        );
    }

    println!();
    println!(
        "Готово: устройство №{}, ключ аккаунта восстановлен.",
        done.number
    );
    println!("Контакты и история переписки не переносятся: добавьте контакты заново.");
    println!("Если нужен @username, задайте его заново: `messenger set-username`.");
    println!("Устройство №{PRIMARY_DEVICE} осталось в списке, и отключить его нельзя.");
    println!();
    println!("Устройства аккаунта:");
    for d in &done.list.devices {
        println!("  №{:<2} {}", d.device_id, d.name);
    }
    println!("Если среди них есть незнакомые, отключите их: `messenger unlink <номер>`.");
    Ok(())
}

fn clear_pending(db: &Db) {
    if let Err(e) = db.clear_pending_restore() {
        eprintln!("! не удалось убрать запись о восстановлении: {e:#}");
    }
}

/// Выйти в сеть уже как новое устройство, чтобы опубликовать предключи.
fn announce_device(db: &Db, relay: &str) -> Result<()> {
    let (_, me) = crate::load_identity(db)?;
    messaging::ensure_signed_prekey(db, &me)?;
    // Устройство уже сохранено целиком, так что Ctrl+C здесь безопасен: предключи
    // опубликует следующий `sync` или `listen`.
    crate::runtime()?.block_on(async {
        tokio::select! {
            r = async {
                let mut s = Session::open(relay, db, &me).await?;
                crate::wait_for(&mut s, ACCEPT_TIMEOUT, |s| s.synced || s.removed).await?;
                let synced = s.synced;
                s.close().await;
                if !synced {
                    bail!("релей не ответил");
                }
                Ok(())
            } => r,
            _ = crate::shutdown_signal() => bail!("прервано"),
        }
    })
}

/// Прочитать файл не больше `max` байт. Размер проверяется до чтения, а само чтение
/// ограничено: файл мог вырасти между проверкой и чтением.
fn read_limited(path: &Path, max: usize) -> Result<Vec<u8>> {
    let meta =
        fs::metadata(path).with_context(|| format!("не удалось открыть {}", path.display()))?;
    if !meta.is_file() {
        bail!("{} — не файл резервной копии", path.display());
    }
    let too_big = || {
        anyhow!(
            "{} слишком велик для резервной копии (больше {max} байт)",
            path.display()
        )
    };
    if meta.len() > max as u64 {
        return Err(too_big());
    }
    let mut buf = Vec::new();
    File::open(path)
        .with_context(|| format!("не удалось открыть {}", path.display()))?
        .take(max as u64 + 1)
        .read_to_end(&mut buf)
        .with_context(|| format!("не удалось прочитать {}", path.display()))?;
    if buf.len() > max {
        return Err(too_big());
    }
    Ok(buf)
}

/// Предупреждение, если параметры Argon2 в файле тяжелее обычных.
fn kdf_warning(p: &BackupKdfParams) -> Option<String> {
    let d = BackupKdfParams::DEFAULT;
    if p.m_cost_kib <= d.m_cost_kib && p.t_cost <= d.t_cost && p.lanes <= d.lanes {
        return None;
    }
    Some(format!(
        "параметры защиты файла тяжелее обычных (память {} КиБ, проходов {}, потоков {}; \
         обычно {} КиБ, {}, {}): расшифровка займёт больше памяти и времени. Если вы их не \
         меняли, файл могли подменить",
        p.m_cost_kib, p.t_cost, p.lanes, d.m_cost_kib, d.t_cost, d.lanes
    ))
}

/// Проверить список устройств, пришедший с релея, перед тем как дописать в него себя.
fn check_restore_list(
    wire: Option<&SignedDeviceListB64>,
    backup: &AccountBackup,
) -> Result<DeviceList> {
    let Some(wire) = wire else {
        bail!(
            "на релее нет списка устройств этого аккаунта. Восстановление не публикует список \
             с нуля: так можно было бы незаметно подменить аккаунт. Убедитесь, что вы \
             подключаетесь к тому же релею, что и раньше"
        );
    };
    let list =
        crypto_core::verify_device_list(wire, backup.account_id(), Some(&backup.account_pub()))
            .context("список устройств на релее не подписан ключом из копии")?;
    if list.version < backup.list_version_at_backup() {
        bail!(
            "релей откатил список устройств (версия {} старше, чем в копии: {}): \
             восстановление остановлено",
            list.version,
            backup.list_version_at_backup()
        );
    }
    match list.device(PRIMARY_DEVICE) {
        Some(d) if d.x25519_pub == backup.primary_x25519_pub() => Ok(list),
        _ => bail!(
            "устройство №{PRIMARY_DEVICE} в списке на релее не то, что в копии: \
             восстановление остановлено"
        ),
    }
}

/// Дождаться списка своего аккаунта от релея.
async fn await_list(conn: &mut RelayConn, account_id: &str) -> Result<Option<SignedDeviceListB64>> {
    loop {
        match conn.recv_timeout(ACCEPT_TIMEOUT).await? {
            Some(ServerMessage::DeviceList {
                account_id: id,
                list,
            }) if id == account_id => return Ok(list),
            Some(ServerMessage::Error { message, .. }) => bail!("релей: {message}"),
            Some(_) => {}
            None => bail!("релей не прислал список устройств"),
        }
    }
}

/// Что ответил релей на публикацию.
enum Answer {
    Done,
    Stale,
    Rejected(String),
    Silent,
}

async fn await_publish(
    conn: &mut RelayConn,
    account_id: &str,
    wire: &SignedDeviceListB64,
) -> Answer {
    loop {
        match conn.recv_timeout(ACCEPT_TIMEOUT).await {
            Ok(Some(ServerMessage::DeviceList {
                account_id: id,
                list: Some(l),
            })) if id == account_id && l == *wire => return Answer::Done,
            Ok(Some(ServerMessage::Error { message, .. })) => {
                return if message.contains(protocol::ERR_STALE_DEVICE_LIST) {
                    Answer::Stale
                } else {
                    Answer::Rejected(message)
                };
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => return Answer::Silent,
        }
    }
}

/// Войти сессией ключа аккаунта, дописать в список устройств себя и опубликовать.
/// `sent` — отправка списка началась (результат неизвестен).
async fn publish_flow(
    relay: &str,
    backup: &AccountBackup,
    pending: &PendingRestore,
    sent: &Cell<bool>,
) -> std::result::Result<Published, Fail> {
    let account_id = backup.account_id();
    let mut conn = RelayConn::connect_account(relay, account_id, backup.account_sign())
        .await
        .map_err(Fail::Early)?;
    let keys = Identity::from_secrets(account_id, pending.x_secret, pending.sign_secret);
    let result = async {
        for _ in 0..LIST_ATTEMPTS {
            conn.send(&ClientMessage::FetchDeviceList {
                account_id: account_id.to_owned(),
            })
            .await
            .map_err(Fail::Early)?;
            let cur_wire = await_list(&mut conn, account_id)
                .await
                .map_err(Fail::Early)?;
            let cur = check_restore_list(cur_wire.as_ref(), backup).map_err(Fail::Early)?;
            let cur_wire = cur_wire.context("списка нет").map_err(Fail::Early)?;

            // Прошлый запуск успел опубликовать наши ключи — второй раз не добавляем.
            if let Some(d) = cur.devices.iter().find(|d| {
                d.x25519_pub == keys.x_public_bytes() && d.ed25519_pub == keys.sign_public_bytes()
            }) {
                return Ok(Published {
                    number: d.device_id,
                    list: cur,
                    wire: cur_wire,
                });
            }

            if cur.devices.len() >= MAX_DEVICES {
                return Err(Fail::Clear(anyhow!(
                    "в аккаунте уже {MAX_DEVICES} устройств. Отключите лишнее с устройства, \
                     где есть ключ аккаунта (`messenger unlink`), и повторите"
                )));
            }
            let (version, number) = devices::next_device_number(&cur).map_err(Fail::Clear)?;
            let mut new = cur.clone();
            new.version = version;
            new.devices.push(DeviceInfo {
                device_id: number,
                x25519_pub: keys.x_public_bytes(),
                ed25519_pub: keys.sign_public_bytes(),
                name: pending.name.clone(),
            });
            check_list_update(Some(&cur), &new)
                .map_err(|e| Fail::Clear(anyhow!("новый список устройств недопустим: {e}")))?;
            let signer = keys
                .clone()
                .with_device(number)
                .with_account_key(pending.account_secret);
            let wire = signer
                .sign_device_list(&new)
                .map_err(|e| Fail::Clear(anyhow!("не удалось подписать список: {e}")))?;

            sent.set(true);
            conn.send(&ClientMessage::PublishDeviceList { list: wire.clone() })
                .await
                .map_err(|e| Fail::Keep(unknown_result(e)))?;
            match await_publish(&mut conn, account_id, &wire).await {
                Answer::Done => {
                    return Ok(Published {
                        list: new,
                        wire,
                        number,
                    });
                }
                // Список на релее изменился, пока мы собирали свой: берём свежий.
                Answer::Stale => sent.set(false),
                Answer::Rejected(m) => {
                    sent.set(false);
                    return Err(Fail::Clear(anyhow!(
                        "релей не принял список устройств: {m}"
                    )));
                }
                Answer::Silent => {
                    return Err(Fail::Keep(unknown_result(anyhow!("релей не ответил"))));
                }
            }
        }
        Err(Fail::Clear(anyhow!(
            "список устройств на релее постоянно меняется, повторите команду позже"
        )))
    }
    .await;
    conn.close().await;
    result
}

fn unknown_result(cause: anyhow::Error) -> anyhow::Error {
    cause.context(
        "неизвестно, принял ли релей список устройств. Повторите `restore-key` с теми же \
         файлом и кодом: восстановление продолжится",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    /// Копия и список для Боба: №1 с ключом аккаунта, версия списка `version`.
    fn setup(version: u64) -> (AccountBackup, Identity, DeviceList) {
        let primary = Identity::generate_new();
        let backup = AccountBackup::new(
            primary.account_id(),
            SigningKey::from_bytes(&primary.sign_secret_bytes()),
            primary.x_public_bytes(),
            3,
            1_700_000_000,
        );
        let list = DeviceList {
            account_id: primary.account_id().to_owned(),
            account_pub: primary.sign_public_bytes(),
            version,
            devices: vec![primary.device_info("основное")],
        };
        (backup, primary, list)
    }

    #[test]
    fn restore_list_accepts_a_good_list() {
        let (backup, primary, list) = setup(3);
        let wire = primary.sign_device_list(&list).unwrap();
        let got = check_restore_list(Some(&wire), &backup).unwrap();
        assert_eq!(got, list);
        // Новее копии — тоже годится.
        let (backup, primary, list) = setup(9);
        let wire = primary.sign_device_list(&list).unwrap();
        assert!(check_restore_list(Some(&wire), &backup).is_ok());
    }

    #[test]
    fn restore_list_refuses_missing_list() {
        let (backup, _, _) = setup(3);
        let e = check_restore_list(None, &backup).unwrap_err().to_string();
        assert!(e.contains("нет списка устройств"), "{e}");
    }

    #[test]
    fn restore_list_refuses_rolled_back_version() {
        let (backup, primary, list) = setup(2);
        let wire = primary.sign_device_list(&list).unwrap();
        let e = check_restore_list(Some(&wire), &backup)
            .unwrap_err()
            .to_string();
        assert!(e.contains("откатил"), "{e}");
    }

    #[test]
    fn restore_list_refuses_foreign_primary_x25519() {
        let (backup, primary, mut list) = setup(3);
        list.devices[0].x25519_pub = [7; 32];
        let wire = primary.sign_device_list(&list).unwrap();
        let e = check_restore_list(Some(&wire), &backup)
            .unwrap_err()
            .to_string();
        assert!(e.contains("не то, что в копии"), "{e}");
    }

    #[test]
    fn restore_list_refuses_foreign_account_key() {
        let (backup, _, _) = setup(3);
        // Тот же account_id, но список подписан другим ключом.
        let other = Identity::generate(backup.account_id());
        let list = DeviceList {
            account_id: backup.account_id().to_owned(),
            account_pub: other.sign_public_bytes(),
            version: 3,
            devices: vec![other.device_info("основное")],
        };
        let wire = other.sign_device_list(&list).unwrap();
        assert!(check_restore_list(Some(&wire), &backup).is_err());
    }

    #[test]
    fn kdf_warning_only_for_heavier_params() {
        let d = BackupKdfParams::DEFAULT;
        assert!(kdf_warning(&d).is_none());
        let lighter = BackupKdfParams {
            m_cost_kib: d.m_cost_kib / 2,
            ..d
        };
        assert!(kdf_warning(&lighter).is_none());
        for heavier in [
            BackupKdfParams {
                m_cost_kib: d.m_cost_kib + 1,
                ..d
            },
            BackupKdfParams {
                t_cost: d.t_cost + 1,
                ..d
            },
            BackupKdfParams {
                lanes: d.lanes + 1,
                ..d
            },
        ] {
            let w = kdf_warning(&heavier).unwrap();
            assert!(w.contains("подменить"), "{w}");
        }
    }

    #[test]
    fn oversized_file_is_refused_before_reading() {
        let dir = std::env::temp_dir().join(format!("messenger-restore-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Разреженный файл огромного размера: прочитать его целиком было бы дорого.
        let big = dir.join("big");
        let f = File::create(&big).unwrap();
        f.set_len(1 << 40).unwrap();
        let e = read_limited(&big, MAX_BACKUP_FILE_LEN)
            .unwrap_err()
            .to_string();
        assert!(e.contains("слишком велик"), "{e}");

        // Ровно предел — читается; на байт больше — отказ.
        let edge = dir.join("edge");
        std::fs::write(&edge, vec![b'x'; MAX_BACKUP_FILE_LEN]).unwrap();
        assert_eq!(
            read_limited(&edge, MAX_BACKUP_FILE_LEN).unwrap().len(),
            MAX_BACKUP_FILE_LEN
        );
        std::fs::write(&edge, vec![b'x'; MAX_BACKUP_FILE_LEN + 1]).unwrap();
        assert!(read_limited(&edge, MAX_BACKUP_FILE_LEN).is_err());

        // Не обычный файл.
        assert!(read_limited(&dir, MAX_BACKUP_FILE_LEN).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
