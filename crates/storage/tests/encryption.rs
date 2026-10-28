//! Шифрование базы паролем.

use storage::*;

fn tmp_path(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("messenger-enc-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("db.sqlite")
}

const SECRET: &str = "совершенно секретный текст 7f3a";

fn write_secret(db: &Db) {
    db.insert_message(&NewMessage {
        direction: Direction::In,
        peer_account_id: "bob-account",
        peer_username: Some("@bobby"),
        plaintext: SECRET,
        envelope_json: "{}",
        msg_id: "m1",
    })
    .unwrap();
}

fn read_secret(db: &Db) -> String {
    db.list_messages_for_peer("bob-account", 1).unwrap()[0]
        .plaintext
        .clone()
}

/// Все байты базы на диске, включая журнал WAL.
fn raw_bytes(path: &std::path::Path) -> Vec<u8> {
    let mut all = std::fs::read(path).unwrap();
    for suffix in ["-wal", "-shm"] {
        let mut p = path.as_os_str().to_os_string();
        p.push(suffix);
        if let Ok(b) = std::fs::read(p) {
            all.extend(b);
        }
    }
    all
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

#[test]
fn encrypted_database_reveals_nothing_on_disk() {
    let path = tmp_path("ondisk");
    {
        let db = Db::open(&path, Some("пароль")).unwrap();
        write_secret(&db);
        let bytes = raw_bytes(&path);
        for needle in [
            SECRET,
            "bob-account",
            "@bobby",
            "messages",
            "SQLite format 3",
        ] {
            assert!(!contains(&bytes, needle), "{needle:?} is visible on disk");
        }
    }
    assert_eq!(file_state(&path).unwrap(), FileState::Encrypted);

    // Для сравнения: без пароля всё лежит открытым текстом.
    let plain = tmp_path("ondisk-plain");
    write_secret(&Db::open(&plain, None).unwrap());
    assert!(contains(&raw_bytes(&plain), SECRET));
    assert_eq!(file_state(&plain).unwrap(), FileState::Plain);
}

#[test]
fn right_wrong_and_missing_password() {
    let path = tmp_path("passwords");
    write_secret(&Db::open(&path, Some("верный")).unwrap());

    assert_eq!(
        read_secret(&Db::open(&path, Some("верный")).unwrap()),
        SECRET
    );

    let err = Db::open(&path, Some("неверный")).err().unwrap();
    assert!(err.is::<WrongPassword>(), "{err:#}");
    let err = Db::open(&path, None).err().unwrap();
    assert!(err.is::<PasswordRequired>(), "{err:#}");

    // Неудачные попытки базу не портят.
    assert_eq!(
        read_secret(&Db::open(&path, Some("верный")).unwrap()),
        SECRET
    );
}

#[test]
fn encrypt_change_and_remove_password_keep_data() {
    let path = tmp_path("reencrypt");
    {
        let db = Db::open(&path, None).unwrap();
        write_secret(&db);
        db.save_sessions("bob-account", 1, "{\"ratchet\":1}")
            .unwrap();
    }

    // Поставить пароль на существующую базу.
    reencrypt(&path, None, Some("первый")).unwrap();
    assert_eq!(file_state(&path).unwrap(), FileState::Encrypted);
    assert!(!contains(&raw_bytes(&path), SECRET));
    {
        let db = Db::open(&path, Some("первый")).unwrap();
        assert_eq!(read_secret(&db), SECRET);
        assert_eq!(
            db.load_sessions("bob-account", 1).unwrap().as_deref(),
            Some("{\"ratchet\":1}")
        );
    }

    // Сменить пароль: старый больше не подходит.
    reencrypt(&path, Some("первый"), Some("второй")).unwrap();
    assert!(
        Db::open(&path, Some("первый"))
            .err()
            .unwrap()
            .is::<WrongPassword>()
    );
    assert_eq!(
        read_secret(&Db::open(&path, Some("второй")).unwrap()),
        SECRET
    );

    // Неверный текущий пароль — отказ, база цела.
    let err = reencrypt(&path, Some("не тот"), Some("третий")).unwrap_err();
    assert!(err.is::<WrongPassword>(), "{err:#}");
    assert_eq!(
        read_secret(&Db::open(&path, Some("второй")).unwrap()),
        SECRET
    );

    // Снять пароль.
    reencrypt(&path, Some("второй"), None).unwrap();
    assert_eq!(file_state(&path).unwrap(), FileState::Plain);
    assert_eq!(read_secret(&Db::open(&path, None).unwrap()), SECRET);

    // Схема и её версия пережили все перешифровки: база открывается без миграций.
    let conn = rusqlite::Connection::open(&path).unwrap();
    let v: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, SCHEMA_VERSION);
}

#[test]
fn reencrypt_includes_data_still_in_the_wal() {
    // Пока соединение открыто, свежие записи лежат в журнале WAL, а не в основном файле.
    let path = tmp_path("wal");
    let db = Db::open(&path, None).unwrap();
    write_secret(&db);
    drop(db);
    reencrypt(&path, None, Some("pw")).unwrap();
    assert_eq!(read_secret(&Db::open(&path, Some("pw")).unwrap()), SECRET);
}

#[test]
fn two_processes_share_an_encrypted_database() {
    let path = tmp_path("shared");
    Db::open(&path, Some("pw"))
        .unwrap()
        .save_sessions("bob", 1, "0")
        .unwrap();
    let workers: Vec<_> = (0..3)
        .map(|_| {
            let path = path.clone();
            std::thread::spawn(move || {
                let db = Db::open(&path, Some("pw")).unwrap();
                for _ in 0..10 {
                    db.immediate(|| {
                        let n: u32 = db.load_sessions("bob", 1)?.unwrap().parse()?;
                        db.save_sessions("bob", 1, &(n + 1).to_string())
                    })
                    .unwrap();
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    let db = Db::open(&path, Some("pw")).unwrap();
    assert_eq!(db.load_sessions("bob", 1).unwrap().as_deref(), Some("30"));
}

#[test]
fn plain_database_refuses_a_password() {
    let path = tmp_path("plain-refuses");
    Db::open(&path, None).unwrap();
    assert!(Db::open(&path, Some("pw")).is_err());
    assert!(reencrypt(&path, Some("pw"), None).is_err());
}

#[test]
fn every_database_gets_its_own_salt() {
    // Одинаковый пароль — разные ключи: соль у каждого файла своя.
    let a = tmp_path("salt-a");
    let b = tmp_path("salt-b");
    Db::open(&a, Some("same"))
        .unwrap()
        .save_sessions("x", 1, "1")
        .unwrap();
    Db::open(&b, Some("same"))
        .unwrap()
        .save_sessions("x", 1, "1")
        .unwrap();
    assert_ne!(
        std::fs::read(&a).unwrap()[..16],
        std::fs::read(&b).unwrap()[..16]
    );
}

#[test]
fn reencrypt_refuses_while_database_is_open_elsewhere() {
    let path = tmp_path("busy");
    let listen = Db::open(&path, None).unwrap(); // «listen» в соседнем терминале
    write_secret(&listen);
    let err = reencrypt(&path, None, Some("pw")).unwrap_err();
    assert!(err.to_string().contains("другим процессом"), "{err:#}");
    assert_eq!(file_state(&path).unwrap(), FileState::Plain);

    drop(listen);
    reencrypt(&path, None, Some("pw")).unwrap();
    assert_eq!(read_secret(&Db::open(&path, Some("pw")).unwrap()), SECRET);
}

/// Ключ аккаунта и данные восстановления лежат на диске только зашифрованными.
#[test]
fn account_key_is_not_visible_on_disk() {
    let key = [0xA7u8; 32];
    let restore_key = [0xB9u8; 32];
    let fill = |db: &Db| {
        db.upsert_identity(&IdentityRow {
            account_id: "acc".into(),
            device_id: 2,
            username: None,
            secret: [0x11; 32],
            public: [0x12; 32],
            sign_secret: Some([0x13; 32]),
            sign_public: Some([0x14; 32]),
            account_sign_secret: Some(key),
        })
        .unwrap();
        db.set_pending_restore(&PendingRestore {
            account_id: "acc".into(),
            account_secret: restore_key,
            x_secret: [0x15; 32],
            sign_secret: [0x16; 32],
            name: "n".into(),
        })
        .unwrap();
    };
    let has = |bytes: &[u8], k: &[u8; 32]| bytes.windows(32).any(|w| w == k);

    // Контроль: в открытой базе ключи видны, значит проверка что-то проверяет.
    let plain = tmp_path("acc-key-plain");
    {
        let db = Db::open(&plain, None).unwrap();
        fill(&db);
        let raw = raw_bytes(&plain);
        assert!(has(&raw, &key) && has(&raw, &restore_key));
    }

    let path = tmp_path("acc-key-enc");
    let db = Db::open(&path, Some("пароль")).unwrap();
    fill(&db);
    let raw = raw_bytes(&path);
    assert!(!has(&raw, &key), "ключ аккаунта виден на диске");
    assert!(
        !has(&raw, &restore_key),
        "ключ из pending_restore виден на диске"
    );
    drop(db);
    let db = Db::open(&path, Some("пароль")).unwrap();
    assert_eq!(
        db.get_local_identity()
            .unwrap()
            .unwrap()
            .account_sign_secret,
        Some(key)
    );
}
