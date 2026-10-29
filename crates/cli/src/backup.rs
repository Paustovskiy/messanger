//! `backup-key`: резервная копия ключа аккаунта.
//!
//! Копия — файл, зашифрованный случайным кодом (его человек записывает на бумагу).
//! Формат и криптография: `protocol::backup` и `crypto_core::backup`.

use anyhow::{Context, Result, bail, ensure};
use crypto_core::backup::{AccountBackup, BackupCode, open_account_backup, seal_account_backup};
use fs4::fs_std::FileExt;
use protocol::PRIMARY_DEVICE;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, IsTerminal, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use storage::Db;
use zeroize::Zeroizing;

/// Сколько раз можно ошибиться при подтверждении кода.
const CONFIRM_ATTEMPTS: u32 = 3;

/// Сколько байт ответа читается за одну попытку.
const MAX_LINE: usize = 256;

pub fn cmd_backup_key(db: &Db, out: &Path, force: bool, allow_redirect: bool) -> Result<()> {
    let (_, me) = crate::load_identity(db)?;
    if !me.has_account_key() {
        bail!(
            "на этом устройстве нет ключа аккаунта: резервную копию можно сделать только на \
             основном устройстве (№{PRIMARY_DEVICE}) или на устройстве, куда ключ аккаунта \
             восстановлен из копии"
        );
    }
    // Код показывается один раз и должен попасть на бумагу, а не в файл или журнал:
    // до генерации и записи отказываем, если вывод перенаправлен.
    if !allow_redirect && !std::io::stdout().is_terminal() {
        bail!(
            "вывод перенаправлен (не терминал): код восстановления попал бы в файл или \
             журнал. Запустите команду в терминале; если вы понимаете риск, добавьте \
             --allow-redirect"
        );
    }
    let (list, _) = crate::devices::own_list(db, &me)?;
    let primary = list
        .device(PRIMARY_DEVICE)
        .context("в списке устройств нет основного")?;
    // Ключ на устройстве обязан быть тем самым ключом аккаунта из нашего списка:
    // иначе копия открывала бы чужой или устаревший аккаунт.
    ensure!(
        me.account_public_bytes() == Some(list.account_pub),
        "ключ аккаунта на этом устройстве не совпадает с ключом в списке устройств \
         (account_pub): копия не сделана; база повреждена или подменена"
    );
    let account_sign = ed25519_dalek_key(&me)?;
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let backup = AccountBackup::new(
        me.account_id(),
        account_sign,
        primary.x25519_pub,
        list.version,
        created_at,
    );
    let fingerprint = crypto_core::fingerprint(&primary.x25519_pub, &backup.account_pub());

    if !force && fs::symlink_metadata(out).is_ok() {
        bail!(
            "файл {} уже существует; чтобы заменить его, добавьте --force",
            out.display()
        );
    }

    let code = BackupCode::generate();
    let text = seal_account_backup(code.password(), &backup).context("не удалось зашифровать")?;
    // Файл пока лежит под временным именем: настоящий (и прежняя копия при --force)
    // не тронут, пока человек не подтвердил, что записал код.
    let staged = stage_verified(out, &text, &code, &backup)?;

    println!(
        "Резервная копия ключа аккаунта подготовлена: {}",
        out.display()
    );
    println!("account_id: {}", backup.account_id());
    println!("отпечаток аккаунта: {fingerprint}");
    println!();
    println!("КОД ВОССТАНОВЛЕНИЯ (запишите на бумагу):");
    println!();
    println!("    {}", code.display_grouped().as_str());
    println!();
    println!("Код показан один раз и нигде не сохранён: без него файл не открыть.");
    println!("Храните бумагу отдельно от файла.");
    println!("Файл вместе с кодом даёт полный контроль над аккаунтом, а отозвать копию");
    println!("нельзя. Не передавайте их никому и не делайте снимков экрана.");
    println!();

    let confirmed = confirm_last_group(&code, &mut std::io::stdin().lock());
    if !confirmed {
        staged.discard();
        bail!(
            "код не подтверждён за {CONFIRM_ATTEMPTS} попытки: резервная копия НЕ создана{}",
            if force && fs::symlink_metadata(out).is_ok() {
                " (прежний файл не тронут)"
            } else {
                ""
            }
        );
    }
    staged.publish(force, &text)?;
    println!("Резервная копия ключа аккаунта записана: {}", out.display());
    Ok(())
}

/// Попросить ввести последнюю группу кода. Ввод читается из stdin (по строке), приглашение
/// идёт в stderr. EOF или ошибка чтения — провал без дальнейших попыток.
fn confirm_last_group(code: &BackupCode, input: &mut impl BufRead) -> bool {
    for attempt in 1..=CONFIRM_ATTEMPTS {
        eprint!(
            "Чтобы убедиться, что код записан верно, введите его последнюю группу \
             (4 знака) [{attempt}/{CONFIRM_ATTEMPTS}]: "
        );
        let _ = std::io::stderr().flush();
        // Строку ограничиваем, чтобы бесконечный ввод не съел память. Ёмкость берётся с
        // запасом сразу, чтобы String не перевыделялся, оставляя старый буфер с
        // необнулённым содержимым. Длинная строка читается кусками по MAX_LINE байт:
        // каждый кусок считается отдельной попыткой.
        let mut line = Zeroizing::new(String::with_capacity(MAX_LINE + 1));
        match input.take(MAX_LINE as u64).read_line(&mut line) {
            Ok(0) | Err(_) => {
                eprintln!();
                return false;
            }
            Ok(_) => {}
        }
        if code.last_group_matches(&line) {
            return true;
        }
        eprintln!("Не совпадает с последней группой кода.");
    }
    false
}

/// Ключ аккаунта устройства как `SigningKey`. Секрет живёт в `Identity`, наружу
/// отдаётся только копией в нужный тип.
fn ed25519_dalek_key(me: &crypto_core::Identity) -> Result<ed25519_dalek::SigningKey> {
    let secret = if me.device_id() == PRIMARY_DEVICE {
        zeroize::Zeroizing::new(me.sign_secret_bytes())
    } else {
        zeroize::Zeroizing::new(
            me.account_sign_secret_bytes()
                .context("на этом устройстве нет ключа аккаунта")?,
        )
    };
    Ok(ed25519_dalek::SigningKey::from_bytes(&secret))
}

/// Записанный под временным именем и уже проверенный файл копии.
struct Staged {
    tmp: PathBuf,
    out: PathBuf,
    /// Папка для fsync после публикации (только unix: на Windows папку так не открыть).
    #[cfg(unix)]
    dir: PathBuf,
    done: bool,
    /// Пока `true`, обработчик SIGINT/SIGTERM удаляет временный файл. Кто первым
    /// сбросит флаг (`claim`) — обработчик или основной поток, — тот и распоряжается файлом.
    armed: Arc<AtomicBool>,
    /// Эксклюзивный flock на временном файле на всё время жизни: чужой запуск не сочтёт
    /// файл сиротой.
    lock: Option<File>,
}

/// Забрать право распоряжаться временным файлом. `true` — только первому вызвавшему.
fn claim(armed: &AtomicBool) -> bool {
    armed.swap(false, Ordering::SeqCst)
}

impl Staged {
    /// Выбросить временный файл.
    fn discard(mut self) {
        let _ = claim(&self.armed);
        self.remove_tmp();
        self.done = true;
    }

    /// Удалить временный файл, пока на нём наш lock (порядок: unlink, потом закрытие).
    /// На не-unix открытый файл удалить нельзя, поэтому lock снимается перед удалением.
    fn remove_tmp(&mut self) {
        #[cfg(not(unix))]
        drop(self.lock.take());
        let _ = fs::remove_file(&self.tmp);
        drop(self.lock.take());
    }

    /// Положить файл на место и убедиться, что на месте лежит именно он.
    fn publish(mut self, force: bool, text: &str) -> Result<()> {
        // Если флаг уже сброшен, обработчик сигнала удаляет файл и завершает процесс:
        // не публикуем и не рапортуем об успехе. Дальше сигналы игнорируются, и итог
        // (успех или ошибка) честно сообщает этот поток.
        if !claim(&self.armed) {
            self.done = true;
            // Обработчик сам завершит процесс; ожидание ограничено на случай сбоя.
            std::thread::sleep(std::time::Duration::from_secs(10));
            bail!("прервано сигналом: резервная копия НЕ создана");
        }
        // На не-unix переименовывать открытый файл нельзя: lock снимается перед этим.
        #[cfg(not(unix))]
        drop(self.lock.take());
        let res = (|| -> Result<()> {
            publish(&self.tmp, &self.out, force)?;
            // fsync папки, чтобы переименование пережило сбой питания (best effort).
            #[cfg(unix)]
            if let Ok(d) = File::open(&self.dir) {
                let _ = d.sync_all();
            }
            let final_bytes = fs::read(&self.out).with_context(|| {
                format!(
                    "не удалось перечитать {} после записи: убедиться, что это наша копия, \
                     нельзя, пользоваться этим файлом не следует",
                    self.out.display()
                )
            })?;
            if final_bytes != text.as_bytes() {
                bail!(
                    "содержимое {} после записи отличается от ожидаемого: это НЕ наша копия \
                     и пользоваться ею нельзя (файл могли подменить или повредить); \
                     удалите его и повторите команду",
                    self.out.display()
                );
            }
            Ok(())
        })();
        self.done = true;
        if res.is_err() {
            self.remove_tmp();
        }
        res
    }
}

impl Drop for Staged {
    /// Паника или ранний выход не оставляют временный файл.
    fn drop(&mut self) {
        if !self.done {
            let _ = claim(&self.armed);
            self.remove_tmp();
        }
    }
}

/// Записать копию во временный файл рядом с целевым и проверить, что он расшифровывается
/// кодом.
///
/// Временный файл создаётся в той же папке (`create_new`, права 0600 на unix), в него
/// пишется текст и делается fsync. Затем файл читается обратно и расшифровывается.
/// Содержимое сверяется по несекретным полям (account_pub, account_id, версия списка,
/// время): копий секрета для сравнения не делается.
fn stage_verified(
    out: &Path,
    text: &str,
    code: &BackupCode,
    backup: &AccountBackup,
) -> Result<Staged> {
    let (dir, name) = split_out(out)?;
    let stale = remove_stale_tmp(&dir, &name);
    for p in &stale.removed {
        eprintln!(
            "Предупреждение: удалён временный файл от прошлого запуска: {}",
            p.display()
        );
    }
    for p in &stale.busy {
        eprintln!(
            "Предупреждение: {} занят, идёт другой backup-key на этот файл; не трогаю",
            p.display()
        );
    }
    let tmp = dir.join(format!(
        ".{name}.tmp-{}",
        hex(&crypto_core::random_bytes::<6>())
    ));
    // Перехват сигналов ставится до создания файла: Ctrl+C между ними не оставит сироту.
    // Обработчик удаляет временный файл при Ctrl+C / SIGTERM (Drop при них не вызывается).
    let armed = Arc::new(AtomicBool::new(true));
    install_signal_cleanup(tmp.clone(), armed.clone())?;
    let file = match create_locked(&tmp) {
        Ok(f) => f,
        Err(e) => {
            let _ = claim(&armed);
            return Err(e);
        }
    };
    // С этого момента Drop уберёт временный файл при любой ошибке.
    let mut staged = Staged {
        tmp,
        out: out.to_path_buf(),
        #[cfg(unix)]
        dir,
        done: false,
        armed,
        lock: Some(file),
    };
    // Читаем обратно через тот же хэндл: на Windows блокировка LockFileEx обязательная,
    // и чтение через другой хэндл упало бы с ошибкой блокировки.
    let mut written = Vec::new();
    if let Some(f) = staged.lock.as_mut() {
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        f.seek(SeekFrom::Start(0))?;
        f.read_to_end(&mut written)
            .context("не удалось перечитать записанный файл")?;
    }

    let back = open_account_backup(&written, code.password())
        .map_err(|e| anyhow::anyhow!("проверка записанной копии не прошла: {e}"))?;
    if back.account_pub() != backup.account_pub()
        || back.account_id() != backup.account_id()
        || back.list_version_at_backup() != backup.list_version_at_backup()
        || back.created_at() != backup.created_at()
    {
        bail!("проверка записанной копии не прошла: содержимое отличается");
    }
    Ok(staged)
}

/// Папка и имя целевого файла.
fn split_out(out: &Path) -> Result<(PathBuf, String)> {
    let dir = match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let name = out
        .file_name()
        .context("укажите путь к файлу, а не к папке")?
        .to_string_lossy()
        .into_owned();
    Ok((dir, name))
}

/// Итог очистки сирот.
#[derive(Debug, Default, PartialEq, Eq)]
struct StaleReport {
    removed: Vec<PathBuf>,
    /// Файлы, занятые другим запуском `backup-key` (на них чужой lock).
    busy: Vec<PathBuf>,
}

/// Удалить в папке временные файлы `.<name>.tmp-<12 hex в нижнем регистре>`, оставшиеся от
/// прошлых запусков (например, после kill -9). Ошибки чтения папки и удаления не
/// фатальны: настоящую ошибку покажет создание нового файла.
///
/// Каждый запуск держит эксклюзивный flock на своём временном файле. Здесь удаляются
/// только обычные файлы (не ссылки; открытый файл должен быть тем же inode, что и по
/// имени), на которые удаётся взять неблокирующий эксклюзивный lock; порядок: lock,
/// проверка, unlink, закрытие. Занятые файлы пропускаются, так что параллельный запуск
/// на тот же файл не ломается. Одинаковое имя `out` у двух запусков при этом не
/// гарантирует, кто опубликует: без `--force` проиграет тот, кто позже (файл уже есть),
/// с `--force` останется последняя публикация.
///
/// На не-unix lock берётся так же (LockFileEx), но чужой открытый файл удалить нельзя,
/// а свой удаляется после снятия lock: окно гонки там чуть шире, ошибки удаления
/// игнорируются.
fn remove_stale_tmp(dir: &Path, name: &str) -> StaleReport {
    let prefix = format!(".{name}.tmp-");
    let mut report = StaleReport::default();
    let Ok(entries) = fs::read_dir(dir) else {
        return report;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name().to_string_lossy().into_owned();
        let Some(rest) = file_name.strip_prefix(&prefix) else {
            continue;
        };
        if rest.len() != 12 || !rest.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            continue;
        }
        let path = entry.path();
        // Только обычные файлы: ссылки и папки не трогаем.
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let Ok(file) = File::open(&path) else {
            continue;
        };
        // Открыли именно тот файл, что видели по имени (не подмена ссылкой).
        if !file.metadata().is_ok_and(|m| same_file(&meta, &m)) {
            continue;
        }
        match FileExt::try_lock_exclusive(&file) {
            Ok(true) => {}
            Ok(false) => {
                report.busy.push(path);
                continue;
            }
            Err(_) => continue,
        }
        // Lock взят: имя ещё указывает на этот же файл?
        let still_ours = fs::symlink_metadata(&path).is_ok_and(|m| same_file(&meta, &m));
        if !still_ours {
            continue;
        }
        #[cfg(not(unix))]
        drop(file);
        if fs::remove_file(&path).is_ok() {
            report.removed.push(path);
        }
    }
    report
}

#[cfg(unix)]
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.is_file() && b.is_file() && a.len() == b.len()
}

/// На время ожидания подтверждения: по SIGINT/SIGTERM удалить временный файл и выйти.
///
/// Основной поток блокируется на чтении stdin, поэтому обработчик живёт в отдельном
/// потоке со своим однопоточным runtime tokio (tokio уже подключён, новых зависимостей
/// нет). Возвращается, когда сигналы уже перехвачены. Поток не снимается: команда
/// короткая; если право на файл уже у основного потока, сигнал игнорируется.
fn install_signal_cleanup(tmp: PathBuf, armed: Arc<AtomicBool>) -> Result<()> {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<std::result::Result<(), String>>();
    std::thread::Builder::new()
        .name("backup-signal".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = ready_tx.send(Err(e.to_string()));
                    return;
                }
            };
            rt.block_on(async move {
                let code = match wait_for_signal(&ready_tx).await {
                    Some(code) => code,
                    None => return,
                };
                // Флаг уже сброшен: основной поток публикует или закончил. Файл не
                // трогаем и не завершаем процесс: он сам честно сообщит результат.
                if claim(&armed) {
                    let _ = fs::remove_file(&tmp);
                    eprintln!();
                    eprintln!("Прервано: резервная копия НЕ создана, временный файл удалён.");
                    std::process::exit(code);
                }
            });
        })
        .context("не удалось запустить обработчик сигналов")?;
    match ready_rx.recv() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => bail!("не удалось установить обработчик сигналов: {e}"),
        Err(_) => bail!("не удалось установить обработчик сигналов"),
    }
}

/// Перехватить сигналы, сообщить о готовности и дождаться первого. `None` — ошибка
/// установки (она уже отправлена в `ready`). Результат — код выхода процесса.
async fn wait_for_signal(
    ready: &std::sync::mpsc::Sender<std::result::Result<(), String>>,
) -> Option<i32> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let (mut int, mut term) = match (
            signal(SignalKind::interrupt()),
            signal(SignalKind::terminate()),
        ) {
            (Ok(i), Ok(t)) => (i, t),
            (Err(e), _) | (_, Err(e)) => {
                let _ = ready.send(Err(e.to_string()));
                return None;
            }
        };
        let _ = ready.send(Ok(()));
        Some(tokio::select! {
            _ = int.recv() => 130,
            _ = term.recv() => 143,
        })
    }
    #[cfg(windows)]
    {
        // windows::ctrl_c() регистрирует обработчик сразу (tokio::signal::ctrl_c() — только
        // при первом опросе): о готовности сообщаем, когда перехват уже стоит.
        let mut ctrl_c = match tokio::signal::windows::ctrl_c() {
            Ok(c) => c,
            Err(e) => {
                let _ = ready.send(Err(e.to_string()));
                return None;
            }
        };
        let _ = ready.send(Ok(()));
        // None — поток событий закрыт, это не Ctrl+C: файл не трогаем.
        ctrl_c.recv().await?;
        Some(130)
    }
    #[cfg(not(any(unix, windows)))]
    {
        // Перехвата сигналов нет: временный файл после прерывания уберёт следующий запуск.
        let _ = ready.send(Ok(()));
        std::future::pending::<()>().await;
        None
    }
}

/// Положить готовый временный файл на место. Без `--force` не затираем чужой файл
/// даже при гонке: жёсткая ссылка не заменяет существующее имя.
fn publish(tmp: &Path, out: &Path, force: bool) -> Result<()> {
    if force {
        fs::rename(tmp, out).with_context(|| format!("не удалось записать {}", out.display()))?;
        return Ok(());
    }
    match fs::hard_link(tmp, out) {
        Ok(()) => {
            if let Err(e) = fs::remove_file(tmp) {
                eprintln!(
                    "Предупреждение: копия записана, но временный файл {} не удалён ({e}); \
                     удалите его вручную",
                    tmp.display()
                );
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => bail!(
            "файл {} уже существует; чтобы заменить его, добавьте --force",
            out.display()
        ),
        Err(_) => {
            // Файловая система без жёстких ссылок: проверка и переименование.
            if fs::symlink_metadata(out).is_ok() {
                bail!(
                    "файл {} уже существует; чтобы заменить его, добавьте --force",
                    out.display()
                );
            }
            fs::rename(tmp, out).with_context(|| format!("не удалось записать {}", out.display()))
        }
    }
}

/// Создать файл и взять на него эксклюзивный lock. Если пока брали lock, чужая очистка
/// успела удалить файл (окно между созданием и lock), это ошибка, а не тихая потеря.
fn create_locked(path: &Path) -> Result<File> {
    let file = create_private(path)?;
    if !FileExt::try_lock_exclusive(&file).context("не удалось заблокировать временный файл")?
    {
        bail!(
            "временный файл {} уже занят другим процессом",
            path.display()
        );
    }
    let same = match (fs::symlink_metadata(path), file.metadata()) {
        (Ok(a), Ok(b)) => same_file(&a, &b),
        _ => false,
    };
    if !same {
        bail!(
            "временный файл {} был удалён другим запуском; повторите команду",
            path.display()
        );
    }
    Ok(file)
}

fn create_private(path: &Path) -> Result<File> {
    let mut opts = OpenOptions::new();
    // read: файл перечитывается через этот же хэндл (см. stage_verified).
    opts.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
        .with_context(|| format!("не удалось создать файл в папке {}", path.display()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn tmp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("messenger-backup-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn last_group_of(code: &BackupCode) -> String {
        code.display_grouped()
            .rsplit('-')
            .next()
            .unwrap()
            .to_string()
    }

    #[test]
    fn publish_without_force_keeps_existing_out() {
        let dir = tmp_dir("publish");
        let tmp = dir.join(".k.tmp-aabbccddeeff");
        let out = dir.join("k");
        fs::write(&tmp, b"new").unwrap();
        fs::write(&out, b"old").unwrap();
        let err = publish(&tmp, &out, false).unwrap_err().to_string();
        assert!(err.contains("--force"), "{err}");
        assert_eq!(fs::read(&out).unwrap(), b"old");
        // С --force файл заменяется.
        publish(&tmp, &out, true).unwrap();
        assert_eq!(fs::read(&out).unwrap(), b"new");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn confirm_accepts_correct_group_within_attempts() {
        let code = BackupCode::generate();
        let good = last_group_of(&code);
        let mut input = Cursor::new(format!("0000\n0000\n{good}\n").into_bytes());
        assert!(confirm_last_group(&code, &mut input));
    }

    #[test]
    fn confirm_fails_after_three_wrong_answers() {
        let code = BackupCode::generate();
        let good = last_group_of(&code);
        // Верный ответ четвёртым уже не принимается.
        let mut input = Cursor::new(format!("0000\n0000\n0000\n{good}\n").into_bytes());
        assert!(!confirm_last_group(&code, &mut input));
        // Не прочитано ничего лишнего: остался четвёртый ответ.
        let mut rest = String::new();
        input.read_line(&mut rest).unwrap();
        assert_eq!(rest.trim(), good);
    }

    #[test]
    fn confirm_fails_on_eof() {
        let code = BackupCode::generate();
        assert!(!confirm_last_group(&code, &mut Cursor::new(Vec::new())));
        // EOF после неверного ответа.
        assert!(!confirm_last_group(
            &code,
            &mut Cursor::new(b"0000\n".to_vec())
        ));
        // Последняя строка без перевода строки принимается.
        let good = last_group_of(&code);
        assert!(confirm_last_group(
            &code,
            &mut Cursor::new(good.into_bytes())
        ));
    }

    #[test]
    fn confirm_reads_long_line_in_chunks_counted_as_attempts() {
        let code = BackupCode::generate();
        let good = last_group_of(&code);
        // 300 байт без перевода строки: первый кусок (256) и остаток (44) — две неудачные
        // попытки; третья читает верный ответ.
        let mut text = "A".repeat(300);
        text.push('\n');
        text.push_str(&good);
        text.push('\n');
        assert!(confirm_last_group(
            &code,
            &mut Cursor::new(text.into_bytes())
        ));

        // Бесконечно длинный ввод без \n: три куска по 256 байт, провал, остальное не читается.
        let mut input = Cursor::new(vec![b'A'; 10_000]);
        assert!(!confirm_last_group(&code, &mut input));
        assert_eq!(
            input.position(),
            (CONFIRM_ATTEMPTS as usize * MAX_LINE) as u64
        );
    }

    #[test]
    fn stale_tmp_files_are_removed_and_others_kept() {
        let dir = tmp_dir("stale");
        let stale = dir.join(".k.backup.tmp-0123456789ab");
        let other_name = dir.join(".other.tmp-0123456789ab");
        let bad_suffix = dir.join(".k.backup.tmp-xyz");
        let out = dir.join("k.backup");
        for p in [&stale, &other_name, &bad_suffix, &out] {
            fs::write(p, b"x").unwrap();
        }
        let removed = remove_stale_tmp(&dir, "k.backup").removed;
        assert_eq!(removed, vec![stale.clone()]);
        assert!(!stale.exists());
        assert!(other_name.exists() && bad_suffix.exists() && out.exists());
        // Несуществующая папка — не паника.
        assert_eq!(
            remove_stale_tmp(&dir.join("nope"), "k.backup"),
            StaleReport::default()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn locked_tmp_is_kept_and_unlocked_orphan_removed() {
        let dir = tmp_dir("locked");
        let held = dir.join(".k.tmp-0123456789ab");
        let orphan = dir.join(".k.tmp-ba9876543210");
        let upper = dir.join(".k.tmp-0123456789AB");
        for p in [&held, &orphan, &upper] {
            fs::write(p, b"x").unwrap();
        }
        let owner = create_locked(&dir.join(".k.tmp-aaaaaaaaaaaa")).unwrap();
        let other = File::open(&held).unwrap();
        assert!(FileExt::try_lock_exclusive(&other).unwrap());
        let report = remove_stale_tmp(&dir, "k");
        assert_eq!(report.removed, vec![orphan.clone()]);
        assert!(report.busy.contains(&held));
        assert!(report.busy.contains(&dir.join(".k.tmp-aaaaaaaaaaaa")));
        assert!(held.exists() && upper.exists() && !orphan.exists());
        // После снятия lock файл становится сиротой.
        drop(other);
        drop(owner);
        let report = remove_stale_tmp(&dir, "k");
        assert_eq!(report.removed.len(), 2);
        assert!(!held.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_tmp_is_not_followed() {
        let dir = tmp_dir("symlink");
        let target = dir.join("target");
        fs::write(&target, b"x").unwrap();
        let link = dir.join(".k.tmp-0123456789ab");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(remove_stale_tmp(&dir, "k"), StaleReport::default());
        assert!(target.exists() && link.symlink_metadata().is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    /// Обработчик и publish соревнуются за флаг: выигрывает ровно один.
    #[test]
    fn exactly_one_claims_the_flag() {
        for _ in 0..200 {
            let armed = Arc::new(AtomicBool::new(true));
            let (a, b) = (armed.clone(), armed.clone());
            let t1 = std::thread::spawn(move || claim(&a));
            let t2 = std::thread::spawn(move || claim(&b));
            let wins = [t1.join().unwrap(), t2.join().unwrap()];
            assert_eq!(wins.iter().filter(|w| **w).count(), 1);
            assert!(!claim(&armed));
        }
    }
}
