use crypto_core::Identity;
use storage::*;

fn tmp_path(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("messenger-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("db.sqlite")
}

fn identity_row(id: &Identity) -> IdentityRow {
    IdentityRow {
        account_id: id.account_id().to_string(),
        device_id: id.device_id(),
        username: None,
        secret: id.x_secret_bytes(),
        public: id.x_public_bytes(),
        sign_secret: Some(id.sign_secret_bytes()),
        sign_public: Some(id.sign_public_bytes()),
    }
}

fn contact(account_id: &str, username: Option<&str>) -> ContactRow {
    let id = Identity::generate(account_id);
    ContactRow {
        account_id: account_id.into(),
        username: username.map(Into::into),
        public: id.x_public_bytes(),
        sign_public: Some(id.sign_public_bytes()),
        signed_prekey: None,
    }
}

fn msg<'a>(dir: Direction, peer: &'a str, text: &'a str, msg_id: &'a str) -> NewMessage<'a> {
    NewMessage {
        direction: dir,
        peer_account_id: peer,
        peer_username: None,
        plaintext: text,
        envelope_json: "{}",
        msg_id,
    }
}

/// Регрессия: в исходной версии первый `init` на пустой базе падал с
/// `no such column: sign_secret`.
#[test]
fn fresh_database_stores_and_loads_identity() {
    let path = tmp_path("fresh");
    let me = Identity::generate("acc-1");
    {
        let db = Db::open(&path, None).unwrap();
        assert!(db.get_local_identity().unwrap().is_none());
        db.upsert_identity(&identity_row(&me)).unwrap();
    }
    let db = Db::open(&path, None).unwrap();
    let row = db.get_local_identity().unwrap().unwrap();
    assert_eq!(row, identity_row(&me));

    db.set_username("acc-1", Some("@alice")).unwrap();
    assert_eq!(
        db.get_local_identity()
            .unwrap()
            .unwrap()
            .username
            .as_deref(),
        Some("@alice")
    );
    assert!(db.set_username("nope", None).is_err());
}

#[test]
fn reopening_is_idempotent() {
    let path = tmp_path("reopen");
    for _ in 0..3 {
        Db::open(&path, None).unwrap();
    }
}

#[test]
fn contacts_lookup_by_id_and_username() {
    let db = Db::open_in_memory().unwrap();
    db.upsert_contact(&contact("id-alice", Some("@alice")))
        .unwrap();
    db.upsert_contact(&contact("id-bob", None)).unwrap();

    assert_eq!(
        db.find_contact("id-alice").unwrap().unwrap().account_id,
        "id-alice"
    );
    assert_eq!(
        db.find_contact("@ALICE").unwrap().unwrap().account_id,
        "id-alice"
    );
    assert_eq!(
        db.find_contact("alice").unwrap().unwrap().account_id,
        "id-alice"
    );
    assert!(db.find_contact("@carol").unwrap().is_none());
    assert_eq!(db.list_contacts().unwrap().len(), 2);

    assert!(db.delete_contact("id-bob").unwrap());
    assert!(!db.delete_contact("id-bob").unwrap());
}

#[test]
fn username_cannot_be_hijacked_by_another_contact() {
    let db = Db::open_in_memory().unwrap();
    db.upsert_contact(&contact("id-alice", Some("@alice")))
        .unwrap();

    let err = db
        .upsert_contact(&contact("id-mallory", Some("@Alice")))
        .unwrap_err();
    assert!(err.to_string().contains("already belongs"), "{err}");
    assert_eq!(
        db.find_contact("@alice").unwrap().unwrap().account_id,
        "id-alice"
    );

    // А обновить собственную карточку можно.
    db.upsert_contact(&contact("id-alice", Some("@alice")))
        .unwrap();
}

#[test]
fn duplicate_delivery_is_ignored() {
    let db = Db::open_in_memory().unwrap();
    assert!(
        db.insert_message(&msg(Direction::In, "bob", "hi", "m1"))
            .unwrap()
            .is_some()
    );
    assert!(
        db.insert_message(&msg(Direction::In, "bob", "hi", "m1"))
            .unwrap()
            .is_none()
    );
    assert_eq!(db.list_messages_for_peer("bob", 10).unwrap().len(), 1);

    // Тот же msg_id от другого собеседника или в другую сторону — другое сообщение.
    assert!(
        db.insert_message(&msg(Direction::In, "carol", "hi", "m1"))
            .unwrap()
            .is_some()
    );
    assert!(
        db.insert_message(&msg(Direction::Out, "bob", "hi", "m1"))
            .unwrap()
            .is_some()
    );
}

#[test]
fn chat_limit_returns_latest_messages_in_order() {
    let db = Db::open_in_memory().unwrap();
    for i in 0..5 {
        db.insert_message(&msg(Direction::In, "bob", &i.to_string(), &format!("m{i}")))
            .unwrap();
    }
    let last: Vec<_> = db
        .list_messages_for_peer("bob", 2)
        .unwrap()
        .into_iter()
        .map(|m| m.plaintext)
        .collect();
    assert_eq!(last, ["3", "4"]);
}

#[test]
fn threads_unread_and_delivery_status() {
    let db = Db::open_in_memory().unwrap();
    db.upsert_contact(&contact("bob", Some("@bobby"))).unwrap();
    db.insert_message(&msg(Direction::In, "bob", "one", "a"))
        .unwrap();
    db.insert_message(&msg(Direction::In, "bob", "two", "b"))
        .unwrap();
    db.insert_message(&msg(Direction::Out, "bob", "reply", "c"))
        .unwrap();

    let t = &db.list_threads(10).unwrap()[0];
    assert_eq!(t.peer_username.as_deref(), Some("@bobby"));
    assert_eq!(t.unread_count, 2);
    assert_eq!(t.last_plaintext, "reply");
    assert_eq!(t.last_status, DeliveryStatus::Pending);

    db.mark_thread_read("bob").unwrap();
    assert_eq!(db.list_threads(10).unwrap()[0].unread_count, 0);

    assert!(db.mark_out_delivered("bob", "c").unwrap());
    assert!(
        !db.mark_out_delivered("bob", "c").unwrap(),
        "second ack changes nothing"
    );
    assert!(
        !db.mark_out_delivered("mallory", "c").unwrap(),
        "ack from wrong peer is ignored"
    );
    assert_eq!(
        db.list_threads(10).unwrap()[0].last_status,
        DeliveryStatus::Delivered
    );
}

/// База, созданная исходной версией проекта (схема v2 + ALTER-ы), открывается,
/// данные сохраняются, а старая глобальная уникальность msg_id снимается.
#[test]
fn migrates_database_from_previous_version() {
    let path = tmp_path("legacy-v2");
    let legacy = Identity::generate("legacy-acc");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE identities (account_id TEXT PRIMARY KEY, username TEXT NULL,
                 secret BLOB NOT NULL, public BLOB NOT NULL, created_at INTEGER NOT NULL);
             ALTER TABLE identities ADD COLUMN sign_secret BLOB NULL;
             ALTER TABLE identities ADD COLUMN sign_public BLOB NULL;
             CREATE TABLE contacts (account_id TEXT PRIMARY KEY, username TEXT NULL,
                 public BLOB NOT NULL, added_at INTEGER NOT NULL);
             CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, direction INTEGER NOT NULL,
                 peer_account_id TEXT NOT NULL, peer_username TEXT NULL, created_at INTEGER NOT NULL,
                 plaintext TEXT NOT NULL, envelope_json TEXT NOT NULL,
                 is_read INTEGER NOT NULL DEFAULT 1, msg_id TEXT NULL, delivered_at INTEGER NULL,
                 status INTEGER NOT NULL DEFAULT 0);
             CREATE UNIQUE INDEX idx_messages_msg_id ON messages(msg_id);
             PRAGMA user_version = 2;",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO identities (account_id, username, secret, public, created_at, sign_secret, sign_public)
             VALUES (?1, '@old', ?2, ?3, 1, ?4, ?5)",
            rusqlite::params![
                legacy.account_id(),
                &legacy.x_secret_bytes()[..],
                &legacy.x_public_bytes()[..],
                &legacy.sign_secret_bytes()[..],
                &legacy.sign_public_bytes()[..],
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO contacts VALUES ('bob', '@bobby', ?1, 1)",
            rusqlite::params![&[7u8; 32][..]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages (direction, peer_account_id, created_at, plaintext, envelope_json, msg_id)
             VALUES (1, 'bob', 1, 'old message', '{}', 'm1')",
            [],
        )
        .unwrap();
    }

    let db = Db::open(&path, None).unwrap();
    let me = db.get_local_identity().unwrap().unwrap();
    assert_eq!(me.account_id, "legacy-acc");
    assert_eq!(me.sign_secret, Some(legacy.sign_secret_bytes()));

    let bob = db.find_contact("@bobby").unwrap().unwrap();
    assert_eq!(
        bob.sign_public, None,
        "old contacts have no signing key yet"
    );

    assert_eq!(
        db.list_messages_for_peer("bob", 10).unwrap()[0].plaintext,
        "old message"
    );
    // Раньше это упало бы на UNIQUE(msg_id).
    assert!(
        db.insert_message(&msg(Direction::In, "bob", "x", "m1"))
            .unwrap()
            .is_some()
    );

    let v: i64 = rusqlite::Connection::open(&path)
        .unwrap()
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, SCHEMA_VERSION);
    // v4: таблицы сессий появились и пусты.
    assert!(db.load_sessions("bob", 1).unwrap().is_none());
}

/// Самая первая схема с `user_id` вместо `account_id` и без ключа подписи.
#[test]
fn migrates_very_first_schema() {
    let path = tmp_path("legacy-v1");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE identities (user_id TEXT PRIMARY KEY, secret BLOB NOT NULL,
                 public BLOB NOT NULL, created_at INTEGER NOT NULL);
             CREATE INDEX idx_identities_created_at ON identities(created_at);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO identities VALUES ('first-user', ?1, ?2, 1)",
            rusqlite::params![&[1u8; 32][..], &[2u8; 32][..]],
        )
        .unwrap();
    }
    let db = Db::open(&path, None).unwrap();
    let me = db.get_local_identity().unwrap().unwrap();
    assert_eq!(me.account_id, "first-user");
    assert_eq!(me.sign_secret, None);
}

#[test]
fn refuses_database_from_the_future() {
    let path = tmp_path("future");
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch("PRAGMA user_version = 99;")
        .unwrap();
    let err = Db::open(&path, None).err().unwrap();
    assert!(err.to_string().contains("newer"), "{err}");
}

#[cfg(unix)]
#[test]
fn database_file_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let path = tmp_path("perms");
    Db::open(&path, None).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn contact_keeps_signed_prekey_until_a_newer_one_arrives() {
    let db = Db::open_in_memory().unwrap();
    let spk = StoredPrekey {
        id: 3,
        public: [1; 32],
        sig: [2; 64],
    };
    db.upsert_contact(&ContactRow {
        signed_prekey: Some(spk),
        ..contact("bob", Some("@bobby"))
    })
    .unwrap();
    assert_eq!(
        db.get_contact("bob").unwrap().unwrap().signed_prekey,
        Some(spk)
    );

    // Повторное добавление карточки без предключа не стирает известный.
    db.upsert_contact(&contact("bob", Some("@bobby"))).unwrap();
    assert_eq!(
        db.get_contact("bob").unwrap().unwrap().signed_prekey,
        Some(spk)
    );

    let newer = StoredPrekey {
        id: 4,
        public: [3; 32],
        sig: [4; 64],
    };
    db.upsert_contact(&ContactRow {
        signed_prekey: Some(newer),
        ..contact("bob", Some("@bobby"))
    })
    .unwrap();
    assert_eq!(
        db.get_contact("bob").unwrap().unwrap().signed_prekey,
        Some(newer)
    );
}

#[test]
fn sessions_and_replay_markers() {
    let db = Db::open_in_memory().unwrap();
    assert!(db.load_sessions("bob", 1).unwrap().is_none());
    db.save_sessions("bob", 1, "{\"v\":1}").unwrap();
    db.save_sessions("bob", 1, "{\"v\":2}").unwrap();
    assert_eq!(
        db.load_sessions("bob", 1).unwrap().as_deref(),
        Some("{\"v\":2}")
    );
    db.delete_sessions("bob").unwrap();
    assert!(db.load_sessions("bob", 1).unwrap().is_none());

    assert!(!db.is_ek_used("bob", 1, &[1; 32]).unwrap());
    db.mark_ek_used("bob", 1, &[1; 32]).unwrap();
    db.mark_ek_used("bob", 1, &[1; 32]).unwrap();
    assert!(db.is_ek_used("bob", 1, &[1; 32]).unwrap());
    assert!(!db.is_ek_used("carol", 1, &[1; 32]).unwrap());

    db.insert_message(&msg(Direction::In, "bob", "x", "m1"))
        .unwrap();
    assert!(db.has_incoming("bob", "m1").unwrap());
    assert!(!db.has_incoming("bob", "m2").unwrap());
    assert!(!db.has_incoming("carol", "m1").unwrap());
}

#[test]
fn own_prekeys() {
    let db = Db::open_in_memory().unwrap();
    assert!(db.current_signed_prekey().unwrap().is_none());
    assert_eq!(db.next_signed_prekey_id().unwrap(), 1);
    for (id, created_at) in [(1, 100), (2, 200), (3, 300)] {
        db.insert_signed_prekey(&OwnSignedPrekey {
            id,
            secret: [id as u8; 32],
            public: [0; 32],
            sig: [0; 64],
            created_at,
        })
        .unwrap();
    }
    assert_eq!(db.current_signed_prekey().unwrap().unwrap().id, 3);
    assert_eq!(db.signed_prekey_secret(2).unwrap(), Some([2; 32]));
    assert_eq!(db.prune_signed_prekeys(250).unwrap(), 2);
    assert_eq!(db.signed_prekey_secret(2).unwrap(), None);
    // Самый свежий не удаляется, даже если он «старый».
    assert_eq!(db.prune_signed_prekeys(10_000).unwrap(), 0);
    assert_eq!(db.next_signed_prekey_id().unwrap(), 4);

    assert_eq!(db.next_one_time_prekey_id().unwrap(), 1);
    let keys: Vec<_> = (1..=3)
        .map(|id| OwnOneTimePrekey {
            id,
            secret: [id as u8; 32],
            public: [0; 32],
        })
        .collect();
    db.insert_one_time_prekeys(&keys).unwrap();
    assert_eq!(db.count_one_time_prekeys().unwrap(), 3);
    assert_eq!(db.one_time_prekey_secret(2).unwrap(), Some([2; 32]));
    db.delete_one_time_prekey(3).unwrap();
    assert_eq!(db.one_time_prekey_secret(3).unwrap(), None);
    // ID не переиспользуются, даже если последний ключ удалён.
    assert_eq!(db.next_one_time_prekey_id().unwrap(), 4);
}

#[test]
fn failed_messages_are_marked() {
    let db = Db::open_in_memory().unwrap();
    db.insert_message(&msg(Direction::Out, "bob", "old format", "m1"))
        .unwrap();
    db.mark_out_failed("bob", "m1").unwrap();
    assert_eq!(
        db.list_messages_for_peer("bob", 10).unwrap()[0].status,
        DeliveryStatus::Failed
    );
}

fn out(message: &str, peer: &str, to: &str, device: u32, env: &str) -> OutboxItem {
    OutboxItem {
        message_id: message.into(),
        peer_account_id: peer.into(),
        to_account_id: to.into(),
        to_device_id: device,
        envelope_id: env.into(),
        envelope_json: format!("{{\"e\":\"{env}\"}}"),
    }
}

#[test]
fn one_message_many_envelopes() {
    // Боб с двумя устройствами + копия на наше второе устройство.
    let db = Db::open_in_memory().unwrap();
    db.insert_message(&msg(Direction::Out, "bob", "привет", "m1"))
        .unwrap();
    for item in [
        out("m1", "bob", "bob", 1, "e1"),
        out("m1", "bob", "bob", 2, "e2"),
        out("m1", "bob", "me", 2, "e3"),
    ] {
        db.insert_outbox(&item).unwrap();
        db.insert_outbox(&item).unwrap(); // повтор — не дубль
    }
    assert_eq!(db.list_outbox(10).unwrap().len(), 3);

    // Копию подтвердило наше устройство — сообщение ещё не «доставлено».
    let acked = db.ack_outbox("me", 2, "e3").unwrap().unwrap();
    assert!(!acked.newly_delivered);
    assert_eq!(
        db.list_messages_for_peer("bob", 1).unwrap()[0].status,
        DeliveryStatus::Pending
    );

    // Подтверждение с чужого устройства или на чужой конверт ничего не делает.
    assert!(db.ack_outbox("bob", 1, "e2").unwrap().is_none());
    assert!(db.ack_outbox("mallory", 2, "e2").unwrap().is_none());

    // Первое устройство Боба — доставлено.
    let acked = db.ack_outbox("bob", 2, "e2").unwrap().unwrap();
    assert!(acked.newly_delivered);
    assert_eq!(acked.message_id, "m1");
    assert_eq!(
        db.list_messages_for_peer("bob", 1).unwrap()[0].status,
        DeliveryStatus::Delivered
    );
    // Второе — тоже подтвердило, но «доставлено» уже было.
    assert!(
        !db.ack_outbox("bob", 1, "e1")
            .unwrap()
            .unwrap()
            .newly_delivered
    );
    assert!(db.list_outbox(10).unwrap().is_empty());
    // Повторное подтверждение.
    assert!(db.ack_outbox("bob", 1, "e1").unwrap().is_none());
}

#[test]
fn outbox_forgets_removed_devices() {
    let db = Db::open_in_memory().unwrap();
    for item in [
        out("m1", "bob", "bob", 1, "e1"),
        out("m1", "bob", "bob", 2, "e2"),
        out("m1", "bob", "bob", 3, "e3"),
        out("m2", "carol", "carol", 2, "e4"),
    ] {
        db.insert_outbox(&item).unwrap();
    }
    assert_eq!(db.drop_outbox_except("bob", &[1, 3]).unwrap(), 1);
    let left: Vec<_> = db
        .list_outbox(10)
        .unwrap()
        .into_iter()
        .map(|i| i.envelope_id)
        .collect();
    assert_eq!(left, ["e1", "e3", "e4"]);
}

#[test]
fn sessions_are_per_device() {
    let db = Db::open_in_memory().unwrap();
    db.save_sessions("bob", 1, "laptop").unwrap();
    db.save_sessions("bob", 2, "phone").unwrap();
    assert_eq!(
        db.load_sessions("bob", 1).unwrap().as_deref(),
        Some("laptop")
    );
    assert_eq!(
        db.load_sessions("bob", 2).unwrap().as_deref(),
        Some("phone")
    );

    db.delete_device_sessions("bob", 2).unwrap();
    assert!(db.load_sessions("bob", 2).unwrap().is_none());
    assert!(db.load_sessions("bob", 1).unwrap().is_some());

    db.mark_ek_used("bob", 2, &[5; 32]).unwrap();
    assert!(db.is_ek_used("bob", 2, &[5; 32]).unwrap());
    assert!(!db.is_ek_used("bob", 1, &[5; 32]).unwrap());

    db.mark_envelope_seen("bob", 2, "e1").unwrap();
    db.mark_envelope_seen("bob", 2, "e1").unwrap();
    assert!(db.is_envelope_seen("bob", 2, "e1").unwrap());
    assert!(!db.is_envelope_seen("bob", 1, "e1").unwrap());
    assert!(!db.is_envelope_seen("carol", 2, "e1").unwrap());
}

#[test]
fn device_lists_never_roll_back() {
    let db = Db::open_in_memory().unwrap();
    assert!(db.device_list("bob").unwrap().is_none());
    assert!(db.save_device_list("bob", 2, "v2").unwrap());
    // Старая версия (например, подсунутая релеем) не заменяет новую.
    assert!(!db.save_device_list("bob", 1, "v1").unwrap());
    assert!(!db.save_device_list("bob", 2, "v2 again").unwrap());
    assert_eq!(db.device_list("bob").unwrap(), Some((2, "v2".into())));
    assert!(db.save_device_list("bob", 3, "v3").unwrap());
    assert_eq!(db.device_list("bob").unwrap(), Some((3, "v3".into())));

    // Удаление контакта забывает и его устройства.
    db.upsert_contact(&contact("bob", None)).unwrap();
    db.delete_contact("bob").unwrap();
    assert!(db.device_list("bob").unwrap().is_none());
}

#[test]
fn pending_link_roundtrip() {
    let db = Db::open_in_memory().unwrap();
    assert!(db.pending_link().unwrap().is_none());
    let link = PendingLink {
        x_secret: [1; 32],
        sign_secret: [2; 32],
        name: "телефон".into(),
    };
    db.set_pending_link(&link).unwrap();
    db.set_pending_link(&link).unwrap();
    assert_eq!(db.pending_link().unwrap(), Some(link));
    db.clear_pending_link().unwrap();
    assert!(db.pending_link().unwrap().is_none());
}

/// База v4 (одно устройство): сессии переезжают на устройство №1, а
/// неотправленное помечается «не отправлено» — формат конверта сменился.
#[test]
fn migrates_v4_sessions_to_primary_device() {
    let path = tmp_path("legacy-v4");
    let me = Identity::generate("me");
    {
        let db = Db::open(&path, None).unwrap();
        db.upsert_identity(&identity_row(&me)).unwrap();
        db.insert_message(&msg(Direction::Out, "bob", "застряло", "m1"))
            .unwrap();
        db.insert_message(&msg(Direction::Out, "bob", "дошло", "m2"))
            .unwrap();
        db.mark_out_delivered("bob", "m2").unwrap();
    }
    // Превращаем базу в v4: старые таблицы сессий и без device_id.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "DROP TABLE sessions; DROP TABLE used_prekey_eks;
             CREATE TABLE sessions (peer_account_id TEXT PRIMARY KEY, state TEXT NOT NULL,
                 updated_at INTEGER NOT NULL);
             CREATE TABLE used_prekey_eks (peer_account_id TEXT NOT NULL, ek BLOB NOT NULL,
                 used_at INTEGER NOT NULL, PRIMARY KEY (peer_account_id, ek));
             INSERT INTO sessions VALUES ('bob', 'ratchet-state', 1);
             INSERT INTO used_prekey_eks VALUES ('bob', x'0909090909090909090909090909090909090909090909090909090909090909', 1);
             ALTER TABLE identities DROP COLUMN device_id;
             DROP TABLE device_lists; DROP TABLE outbox; DROP TABLE seen_envelopes;
             DROP TABLE pending_link;
             PRAGMA user_version = 4;",
        )
        .unwrap();
    }

    let db = Db::open(&path, None).unwrap();
    assert_eq!(db.get_local_identity().unwrap().unwrap().device_id, 1);
    assert_eq!(
        db.load_sessions("bob", 1).unwrap().as_deref(),
        Some("ratchet-state")
    );
    assert!(db.is_ek_used("bob", 1, &[9; 32]).unwrap());
    let status: Vec<_> = db
        .list_messages_for_peer("bob", 10)
        .unwrap()
        .into_iter()
        .map(|m| m.status)
        .collect();
    assert_eq!(status, [DeliveryStatus::Failed, DeliveryStatus::Delivered]);
    assert!(db.list_outbox(10).unwrap().is_empty());
    drop(db);
    // Повторное открытие ничего не ломает.
    let db = Db::open(&path, None).unwrap();
    assert!(db.load_sessions("bob", 1).unwrap().is_some());
}

#[test]
fn immediate_rolls_back_on_error() {
    let db = Db::open_in_memory().unwrap();
    let r: anyhow::Result<()> = db.immediate(|| {
        db.save_sessions("bob", 1, "half-written")?;
        anyhow::bail!("decryption failed")
    });
    assert!(r.is_err());
    assert!(db.load_sessions("bob", 1).unwrap().is_none());

    db.immediate(|| db.save_sessions("bob", 1, "ok")).unwrap();
    assert_eq!(db.load_sessions("bob", 1).unwrap().as_deref(), Some("ok"));
}

/// Два процесса (`listen` и `send`) с одной базой: каждый читает состояние,
/// меняет и записывает. Без эксклюзивной транзакции часть обновлений терялась бы.
#[test]
fn concurrent_writers_do_not_lose_updates() {
    let path = tmp_path("concurrent");
    Db::open(&path, None)
        .unwrap()
        .save_sessions("bob", 1, "0")
        .unwrap();

    let workers: Vec<_> = (0..4)
        .map(|_| {
            let path = path.clone();
            std::thread::spawn(move || {
                let db = Db::open(&path, None).unwrap();
                for _ in 0..25 {
                    db.immediate(|| {
                        let n: u32 = db.load_sessions("bob", 1)?.unwrap().parse()?;
                        std::thread::yield_now();
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
    assert_eq!(
        Db::open(&path, None)
            .unwrap()
            .load_sessions("bob", 1)
            .unwrap()
            .as_deref(),
        Some("100")
    );
}
