//! Сквозной тест: два настоящих процесса `messenger` (Алиса и Боб) и релей.

use relay_server::{Config, Relay};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const TEST_PASSWORD: &str = "correct horse battery staple";

struct User {
    db: PathBuf,
    relay: String,
}

impl User {
    fn new(dir: &Path, name: &str, relay: &str) -> Self {
        Self {
            db: dir.join(format!("{name}.sqlite")),
            relay: relay.into(),
        }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_messenger"));
        c.arg("--db")
            .arg(&self.db)
            .arg("--relay")
            .arg(&self.relay)
            .args(args);
        c.env_remove("MESSENGER_PROFILE")
            .env_remove("MESSENGER_RELAY")
            .env_remove("MESSENGER_DB");
        // Все тестовые базы зашифрованы — как у настоящего пользователя.
        c.env("MESSENGER_PASSWORD", TEST_PASSWORD)
            .env_remove("MESSENGER_NEW_PASSWORD");
        c
    }

    fn run(&self, args: &[&str]) -> Output {
        self.cmd(args).stdin(Stdio::null()).output().unwrap()
    }

    /// Выполнить и вернуть stdout; упасть с понятным сообщением при ошибке.
    fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "`messenger {}` failed:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    fn ok_with_stdin(&self, args: &[&str], input: &str) -> String {
        let mut child = self
            .cmd(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }
}

fn start_relay() -> String {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                tx.send(listener.local_addr().unwrap()).unwrap();
                Relay::new(Config::default())
                    .unwrap()
                    .serve(listener, std::future::pending())
                    .await
                    .unwrap();
            });
    });
    format!("ws://{}/ws", rx.recv().unwrap())
}

fn tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("messenger-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn alice_and_bob_chat_through_the_relay() {
    let dir = tmp_dir("relay");
    let relay = start_relay();
    let alice = User::new(&dir, "alice", &relay);
    let bob = User::new(&dir, "bob", &relay);

    // Знакомство.
    for (u, name) in [(&alice, "alice"), (&bob, "bobby")] {
        assert!(u.ok(&["init"]).contains("Создана новая личность"));
        u.ok(&["set-username", name]);
    }
    let alice_card = alice.ok(&["export-contact"]);
    let bob_card = bob.ok(&["export-contact"]);
    let saved = alice.ok(&["add-contact", "--contact", &bob_card]);
    assert!(saved.contains("@bobby"));
    bob.ok_with_stdin(&["add-contact"], &alice_card);

    // Отпечаток, который видит Алиса, совпадает с тем, что показывает Боб.
    let bob_fp = bob
        .ok(&["whoami"])
        .lines()
        .find(|l| l.starts_with("отпечаток"))
        .unwrap()
        .to_string();
    assert!(saved.contains(bob_fp.trim_start_matches("отпечаток:").trim()));

    // Боб офлайн — сообщение ждёт на релее.
    let sent = alice.ok(&["send", "@bobby", "Привет, Боб! 🚀", "--wait", "0"]);
    assert!(sent.contains("отправлено: @bobby"), "{sent}");
    assert!(
        alice
            .ok(&["chat", "@bobby"])
            .contains("я ✓: Привет, Боб! 🚀")
    );

    // Боб выходит в сеть и получает сообщение.
    let mut listen = bob
        .cmd(&["listen"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let (line_tx, line_rx) = mpsc::channel();
    let stdout = listen.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = line_tx.send(line);
        }
    });
    let got = loop {
        let line = line_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("bob did not receive the message");
        if line.contains("@alice:") {
            break line;
        }
    };
    assert!(got.ends_with("@alice: Привет, Боб! 🚀"), "{got}");

    // Пока Боб онлайн, Алиса пишет ещё — доставка мгновенная, с ✓✓.
    let out = alice.run(&["send", "nobody", "x"]);
    assert!(!out.status.success());

    let sent = alice.ok(&["send", "@bobby", "ты онлайн?"]);
    assert!(sent.contains("✓✓ доставлено @bobby"), "{sent}");
    let line = line_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(line.ends_with("@alice: ты онлайн?"), "{line}");

    listen.kill().unwrap();
    let _ = listen.wait();

    // Подтверждение первого сообщения пришло, пока Алиса была офлайн, — заберём его.
    alice.ok(&["sync", "--wait", "1"]);
    let chat = alice.ok(&["chat", "@bobby"]);
    assert!(chat.contains("я ✓✓: Привет, Боб! 🚀"), "{chat}");
    assert!(chat.contains("я ✓✓: ты онлайн?"), "{chat}");
    assert!(alice.ok(&["sync"]).contains("Исходящие пусты"));

    // У Боба два непрочитанных; после просмотра чата — ноль.
    assert!(bob.ok(&["threads"]).contains("@alice (2 новых)"));
    bob.ok(&["chat", "@alice"]);
    assert!(!bob.ok(&["threads"]).contains("новых)"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn offline_envelope_exchange_without_relay() {
    let dir = tmp_dir("offline");
    let alice = User::new(&dir, "alice", "ws://127.0.0.1:9/ws");
    let bob = User::new(&dir, "bob", "ws://127.0.0.1:9/ws");
    alice.ok(&["init"]);
    bob.ok(&["init"]);
    alice.ok(&["add-contact", "--contact", &bob.ok(&["export-contact"])]);
    bob.ok(&["add-contact", "--contact", &alice.ok(&["export-contact"])]);
    let bob_id = bob
        .ok(&["whoami"])
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .last()
        .unwrap()
        .to_string();

    let envelope = alice.ok(&["send", &bob_id, "по секрету", "--offline"]);
    assert!(
        bob.ok_with_stdin(&["receive"], &envelope)
            .ends_with(": по секрету\n")
    );

    // Повторное открытие не создаёт дубль.
    bob.ok_with_stdin(&["receive"], &envelope);
    let alice_id = alice
        .ok(&["whoami"])
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .last()
        .unwrap()
        .to_string();
    assert_eq!(bob.ok(&["chat", &alice_id]).lines().count(), 1);

    // Чужой человек не может открыть конверт.
    let carol = User::new(&dir, "carol", "ws://127.0.0.1:9/ws");
    carol.ok(&["init"]);
    carol.ok(&["add-contact", "--contact", &alice.ok(&["export-contact"])]);
    let out = carol
        .cmd(&["receive", "--envelope", &envelope])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("нет адресованного этому устройству"));

    // Без доступного релея сообщение остаётся в исходящих.
    let out = alice.run(&["send", &bob_id, "позже"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("сохранено в исходящих"));

    let _ = std::fs::remove_dir_all(&dir);
}

/// `listen` и `send` одного пользователя работают одновременно с одной базой,
/// а собеседник пишет встречно. Состояние храповика не должно разъехаться.
#[test]
fn listen_and_send_in_parallel_keep_sessions_consistent() {
    let dir = tmp_dir("parallel");
    let relay = start_relay();
    let alice = User::new(&dir, "alice", &relay);
    let bob = User::new(&dir, "bob", &relay);
    for (u, name) in [(&alice, "alice"), (&bob, "bobby")] {
        u.ok(&["init"]);
        u.ok(&["set-username", name]);
    }
    alice.ok(&["add-contact", "--contact", &bob.ok(&["export-contact"])]);
    bob.ok(&["add-contact", "--contact", &alice.ok(&["export-contact"])]);

    // Боб в сети: публикует предключи и принимает сообщения.
    let mut listen = bob
        .cmd(&["listen"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let (line_tx, line_rx) = mpsc::channel();
    let stdout = listen.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = line_tx.send(line);
        }
    });
    let ready = line_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(ready.starts_with("В сети"), "{ready}");

    // Встречная переписка: Алиса пишет, а Боб из другого процесса отвечает,
    // пока его `listen` в это же время принимает её сообщения.
    std::thread::scope(|scope| {
        scope.spawn(|| {
            for i in 0..5 {
                alice.ok(&["send", "@bobby", &format!("от Алисы {i}"), "--wait", "0"]);
            }
        });
        scope.spawn(|| {
            for i in 0..5 {
                bob.ok(&["send", "@alice", &format!("от Боба {i}"), "--wait", "0"]);
            }
        });
    });

    // Сообщения Алисы мог принять любой процесс Боба (`listen` или `send`) —
    // проверяем, что все они оказались в его базе ровно по одному разу.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let chat = loop {
        let chat = bob.ok(&["chat", "@alice"]);
        if (0..5).all(|i| chat.contains(&format!("@alice: от Алисы {i}\n"))) {
            break chat;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "bob is missing messages:\n{chat}"
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    assert_eq!(chat.matches("@alice: от Алисы").count(), 5, "{chat}");

    listen.kill().unwrap();
    let _ = listen.wait();

    // Алиса забирает ответы Боба (и подтверждения).
    alice.ok(&["sync", "--wait", "1"]);
    let chat = alice.ok(&["chat", "@bobby"]);
    for i in 0..5 {
        assert!(chat.contains(&format!("@bobby: от Боба {i}")), "{chat}");
    }

    // После всего этого сессии живы: переписка продолжается в обе стороны.
    let mut listen = bob
        .cmd(&["listen"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(500));
    // Короткий `send` Боба подключается и отключается, пока `listen` работает…
    bob.ok(&["send", "@alice", "пока слушаю", "--wait", "0"]);
    // …и `listen` после этого всё равно получает сообщения вживую.
    let sent = alice.ok(&["send", "@bobby", "финал", "--wait", "2"]);
    assert!(sent.contains("✓✓ доставлено @bobby: «финал»"), "{sent}");
    listen.kill().unwrap();
    let _ = listen.wait();
    assert!(bob.ok(&["chat", "@alice"]).contains("@alice: финал"));
    bob.ok(&["send", "@alice", "и тебе", "--wait", "0"]);
    alice.ok(&["sync", "--wait", "1"]);
    assert!(alice.ok(&["chat", "@bobby"]).contains("@bobby: и тебе"));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Команда с явно заданными паролями (`None` — переменная не задана).
fn with_passwords(user: &User, args: &[&str], current: Option<&str>, new: Option<&str>) -> Output {
    let mut c = user.cmd(args);
    c.env_remove("MESSENGER_PASSWORD");
    if let Some(pw) = current {
        c.env("MESSENGER_PASSWORD", pw);
    }
    if let Some(pw) = new {
        c.env("MESSENGER_NEW_PASSWORD", pw);
    }
    c.stdin(Stdio::null()).output().unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn database_password_lifecycle() {
    let dir = tmp_dir("passwords");
    let alice = User::new(&dir, "alice", "ws://127.0.0.1:9/ws");
    alice.ok(&["init"]);
    alice.ok(&["set-username", "alice"]);
    let id = alice
        .ok(&["whoami"])
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .last()
        .unwrap()
        .to_string();

    // На диске нет ни ID, ни имени.
    let raw = std::fs::read(&alice.db).unwrap();
    for needle in [id.as_str(), "@alice"] {
        assert!(
            !raw.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "{needle} on disk"
        );
    }

    // Неверный пароль.
    let out = with_passwords(&alice, &["whoami"], Some("wrong password"), None);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("неверный пароль"), "{}", stderr(&out));

    // Смена пароля: слишком короткий не принимается.
    let out = with_passwords(
        &alice,
        &["set-password"],
        Some(TEST_PASSWORD),
        Some("short"),
    );
    assert!(
        stderr(&out).contains("слишком короткий"),
        "{}",
        stderr(&out)
    );
    let out = with_passwords(
        &alice,
        &["set-password"],
        Some(TEST_PASSWORD),
        Some("новый длинный пароль"),
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        !with_passwords(&alice, &["whoami"], Some(TEST_PASSWORD), None)
            .status
            .success()
    );
    let out = with_passwords(&alice, &["whoami"], Some("новый длинный пароль"), None);
    assert!(String::from_utf8_lossy(&out.stdout).contains("@alice"));

    // Снять пароль — данные на месте, но клиент предупреждает.
    let out = with_passwords(
        &alice,
        &["remove-password"],
        Some("новый длинный пароль"),
        None,
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let out = with_passwords(&alice, &["whoami"], None, None);
    assert!(String::from_utf8_lossy(&out.stdout).contains("@alice"));
    assert!(stderr(&out).contains("не зашифрована"), "{}", stderr(&out));

    // И зашифровать снова.
    let out = with_passwords(&alice, &["set-password"], None, Some(TEST_PASSWORD));
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(alice.ok(&["whoami"]).contains("@alice"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unencrypted_profile_and_busy_database() {
    let dir = tmp_dir("plain");
    let relay = start_relay();
    let bob = User::new(&dir, "bob", &relay);
    let out = with_passwords(&bob, &["init", "--no-password"], None, None);
    assert!(String::from_utf8_lossy(&out.stdout).contains("не зашифрована"));
    assert!(
        with_passwords(&bob, &["whoami"], None, None)
            .status
            .success()
    );

    // Пока работает `listen`, базу перешифровывать нельзя.
    let mut listen = bob.cmd(&["listen"]);
    listen.env_remove("MESSENGER_PASSWORD");
    let mut listen = listen
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut first = String::new();
    BufReader::new(listen.stdout.as_mut().unwrap())
        .read_line(&mut first)
        .unwrap();
    assert!(first.starts_with("В сети"), "{first}");

    let out = with_passwords(&bob, &["set-password"], None, Some(TEST_PASSWORD));
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("другим процессом"),
        "{}",
        stderr(&out)
    );

    listen.kill().unwrap();
    let _ = listen.wait();
    let out = with_passwords(&bob, &["set-password"], None, Some(TEST_PASSWORD));
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(bob.ok(&["whoami"]).contains("account_id"));

    let _ = std::fs::remove_dir_all(&dir);
}

fn field(output: &str, prefix: &str) -> String {
    output
        .lines()
        .find(|l| l.starts_with(prefix))
        .unwrap_or_else(|| panic!("no {prefix:?} in:\n{output}"))
        .trim_start_matches(prefix)
        .trim()
        .to_string()
}

/// Боб подключает телефон к своему аккаунту: оба устройства получают
/// сообщения Алисы, видят отправленное с другого устройства, а отключённый
/// телефон больше никуда не пускают.
#[test]
fn second_device_joins_receives_and_is_unlinked() {
    let dir = tmp_dir("devices");
    let relay = start_relay();
    let alice = User::new(&dir, "alice", &relay);
    let bob = User::new(&dir, "bob", &relay);
    let phone = User::new(&dir, "bob-phone", &relay);
    for (u, name) in [(&alice, "alice"), (&bob, "bobby")] {
        u.ok(&["init"]);
        u.ok(&["set-username", name]);
    }
    alice.ok(&["add-contact", "--contact", &bob.ok(&["export-contact"])]);
    bob.ok(&["add-contact", "--contact", &alice.ok(&["export-contact"])]);

    // Шаг 1: новое устройство выдаёт код и показывает свой отпечаток.
    let out = phone.run(&["link", "--name", "телефон"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let code = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let phone_fp = field(&stderr(&out), "Отпечаток этого устройства:");
    // Пока подключение не завершено, профилем пользоваться нельзя.
    assert!(stderr(&phone.run(&["whoami"])).contains("ещё не подключено"));

    // Шаг 2: основное устройство видит тот же отпечаток и выдаёт ответ.
    let response = dir.join("link-response.json");
    let approved = bob.ok(&[
        "link-approve",
        &code,
        "--yes",
        "-o",
        response.to_str().unwrap(),
    ]);
    assert_eq!(field(&approved, "отпечаток:"), phone_fp);
    // Без подтверждения (и без терминала) — отказ.
    assert!(!bob.run(&["link-approve", &code]).status.success());

    // Шаг 3: телефон становится устройством №2 того же аккаунта.
    let finished = phone.ok(&["link-finish", "--response-file", response.to_str().unwrap()]);
    assert!(finished.contains("устройство №2"), "{finished}");
    let (bob_who, phone_who) = (bob.ok(&["whoami"]), phone.ok(&["whoami"]));
    for f in ["account_id:", "отпечаток:", "username:"] {
        assert_eq!(field(&bob_who, f), field(&phone_who, f));
    }
    assert!(phone_who.contains("№2 «телефон»"), "{phone_who}");
    let devices = bob.ok(&["devices"]);
    assert!(devices.contains("телефон"), "{devices}");
    // Ответ одноразовый: повторно подключиться с ним нельзя.
    assert!(
        !phone
            .run(&["link-finish", "--response-file", response.to_str().unwrap()])
            .status
            .success()
    );

    // Телефон выходит в сеть и публикует предключи.
    phone.ok(&["sync"]);

    // Алиса пишет — сообщение уходит на оба устройства Боба.
    let sent = alice.ok(&["send", "@bobby", "всем твоим устройствам", "--wait", "0"]);
    assert!(sent.contains("отправлено: @bobby (устройств: 2)"), "{sent}");
    bob.ok(&["sync"]);
    phone.ok(&["sync"]);
    for u in [&bob, &phone] {
        let chat = u.ok(&["chat", "@alice"]);
        assert!(chat.contains("@alice: всем твоим устройствам"), "{chat}");
    }

    // Телефон отвечает; ноутбук Боба видит отправленное с телефона.
    phone.ok(&["send", "@alice", "пишу с телефона", "--wait", "0"]);
    alice.ok(&["sync"]);
    assert!(
        alice
            .ok(&["chat", "@bobby"])
            .contains("@bobby: пишу с телефона")
    );
    bob.ok(&["sync"]);
    let chat = bob.ok(&["chat", "@alice"]);
    assert!(chat.contains("я ✓: пишу с телефона"), "{chat}");

    // Ответ Алисы получают оба устройства — через уже готовые сессии.
    alice.ok(&["send", "@bobby", "вижу", "--wait", "0"]);
    for u in [&bob, &phone] {
        u.ok(&["sync"]);
        assert!(u.ok(&["chat", "@alice"]).contains("@alice: вижу"));
    }

    // Телефон потерян: Боб отключает его.
    let out = bob.ok(&["unlink", "2", "--yes"]);
    assert!(out.contains("отключено"), "{out}");
    assert!(!bob.ok(&["devices"]).contains("телефон"));
    let out = phone.run(&["sync"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("not in the account's device list"),
        "{}",
        stderr(&out)
    );
    // Алиса узнаёт об этом сама и пишет только на ноутбук.
    let sent = alice.ok(&["send", "@bobby", "только ноутбуку", "--wait", "0"]);
    assert!(sent.contains("отправлено: @bobby\n"), "{sent}");

    // Подключать и отключать может только устройство с ключом аккаунта.
    assert!(stderr(&phone.run(&["unlink", "1"])).contains("ключом аккаунта"));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Номер отключённого устройства не выдаётся заново, даже если оно было с
/// наибольшим номером.
#[test]
fn unlinked_device_number_is_not_reused() {
    let dir = tmp_dir("devices-reuse");
    let relay = start_relay();
    let bob = User::new(&dir, "bob", &relay);
    bob.ok(&["init"]);
    bob.ok(&["set-username", "bobby"]);

    let link = |name: &str| -> String {
        let phone = User::new(&dir, name, &relay);
        let out = phone.run(&["link", "--name", name]);
        assert!(out.status.success(), "{}", stderr(&out));
        let code = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let response = dir.join(format!("{name}.json"));
        bob.ok(&[
            "link-approve",
            &code,
            "--yes",
            "-o",
            response.to_str().unwrap(),
        ]);
        phone.ok(&["link-finish", "--response-file", response.to_str().unwrap()])
    };

    let first = link("phone-a");
    let number = |text: &str| -> String {
        let at = text.find("устройство №").expect("номер в выводе");
        text[at..]
            .chars()
            .skip("устройство №".chars().count())
            .take_while(char::is_ascii_digit)
            .collect()
    };
    let n1 = number(&first);
    bob.ok(&["unlink", &n1, "--yes"]);
    let second = link("phone-b");
    let n2 = number(&second);
    assert_ne!(n1, n2, "номер отключённого устройства выдан повторно");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Подключает новое устройство и возвращает его код и профиль.
fn pending_phone(dir: &Path, relay: &str, name: &str) -> (User, String) {
    let phone = User::new(dir, name, relay);
    let out = phone.run(&["link", "--name", name]);
    assert!(out.status.success(), "{}", stderr(&out));
    let code = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (phone, code)
}

/// Менять список устройств можно только через релей, а отключать — осознанно:
/// без релея, без подтверждения и самого себя нельзя; локальный список при этом
/// не меняется.
#[test]
fn list_changes_need_relay_and_confirmation() {
    let dir = tmp_dir("devices-guards");
    let relay = start_relay();
    let bob = User::new(&dir, "bob", &relay);
    bob.ok(&["init"]);
    bob.ok(&["set-username", "bobby"]);
    let (phone, code) = pending_phone(&dir, &relay, "phone");
    let response = dir.join("r.json");
    bob.ok(&[
        "link-approve",
        &code,
        "--yes",
        "-o",
        response.to_str().unwrap(),
    ]);
    phone.ok(&["link-finish", "--response-file", response.to_str().unwrap()]);
    let before = bob.ok(&["devices"]);
    assert!(before.contains("phone"), "{before}");

    // Нельзя отключить само это устройство; №1 — тоже.
    let out = bob.run(&["unlink", "1", "--yes"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("нельзя отключить это устройство"),
        "{}",
        stderr(&out)
    );

    // Без --yes и без терминала — отказ, список прежний.
    let out = bob.run(&["unlink", "2"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("--yes"), "{}", stderr(&out));
    assert_eq!(bob.ok(&["devices"]), before);

    // Релей недоступен: понятная ошибка, список прежний.
    let offline = User {
        db: bob.db.clone(),
        relay: "ws://127.0.0.1:1/ws".into(),
    };
    let out = offline.run(&["unlink", "2", "--yes"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("релей недоступен"),
        "{}",
        stderr(&out)
    );
    assert_eq!(bob.ok(&["devices"]), before);

    let (phone2, code2) = pending_phone(&dir, &relay, "phone2");
    let _ = phone2;
    let out = offline.run(&["link-approve", &code2, "--yes"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("релей недоступен"),
        "{}",
        stderr(&out)
    );
    assert_eq!(bob.ok(&["devices"]), before);

    let _ = std::fs::remove_dir_all(&dir);
}

/// Код восстановления из вывода `backup-key`: единственная строка с отступом из 4 пробелов.
fn backup_code(output: &str) -> String {
    output
        .lines()
        .find(|l| l.starts_with("    ") && l.trim().len() > 20)
        .unwrap_or_else(|| panic!("нет кода в выводе:\n{output}"))
        .trim()
        .to_string()
}

fn open_backup(path: &Path, code: &str) -> Result<crypto_core::backup::AccountBackup, String> {
    let code = crypto_core::backup::BackupCode::parse(code).map_err(|e| e.to_string())?;
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    crypto_core::backup::open_account_backup(&bytes, code.password()).map_err(|e| e.to_string())
}

/// Результат `backup-key` с подтверждением кода через stdin.
struct BackupRun {
    success: bool,
    stdout: String,
    stderr: String,
}

/// Запустить `backup-key --allow-redirect`, дождаться кода в stdout и ответить на запрос
/// подтверждения строками, которые вернёт `answer(код)`.
fn backup_key_confirm(
    user: &User,
    out: &Path,
    extra: &[&str],
    answer: impl Fn(&str) -> String,
) -> BackupRun {
    let mut args = vec![
        "backup-key",
        "--allow-redirect",
        "--out",
        out.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    // До ответа на подтверждение целевой файл не должен меняться (его нет, либо он прежний).
    let before = std::fs::read(out).ok();
    let mut child = user
        .cmd(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut stdout = String::new();
    let mut code = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap() == 0 {
            break;
        }
        stdout.push_str(&line);
        if line.starts_with("    ") && line.trim().len() > 20 {
            code = Some(line.trim().to_string());
            break;
        }
    }
    // Код уже показан, а ответа ещё нет: настоящий файл не создан и не заменён.
    assert_eq!(
        std::fs::read(out).ok(),
        before,
        "целевой файл изменился до подтверждения кода"
    );
    let mut stdin = child.stdin.take().unwrap();
    if let Some(code) = &code {
        // Ошибка записи возможна, если процесс уже закрыл stdin, — это не ошибка теста.
        let _ = stdin.write_all(answer(code).as_bytes());
    }
    drop(stdin);
    std::io::Read::read_to_string(&mut reader, &mut stdout).unwrap();
    let mut stderr = String::new();
    std::io::Read::read_to_string(child.stderr.as_mut().unwrap(), &mut stderr).unwrap();
    let status = child.wait().unwrap();
    BackupRun {
        success: status.success(),
        stdout,
        stderr,
    }
}

/// Верный ответ: последняя группа кода (в нижнем регистре — нормализация).
fn last_group(code: &str) -> String {
    format!("{}\n", code.rsplit('-').next().unwrap().to_lowercase())
}

/// Три неверных ответа (символа «0» нет в алфавите кода).
fn wrong_answers(_: &str) -> String {
    "0000\n0000\n0000\n".into()
}

/// `backup-key`: файл с правами 0600, расшифровывается выведенным кодом, не
/// перезаписывается без `--force`, не оставляет временных файлов.
#[test]
fn backup_key_writes_private_file_and_refuses_overwrite() {
    let dir = tmp_dir("backup");
    let relay = start_relay();
    let bob = User::new(&dir, "bob", &relay);
    bob.ok(&["init"]);
    let account_id = field(&bob.ok(&["whoami"]), "account_id:");
    let file = dir.join("key.backup");
    let file_arg = file.to_str().unwrap();

    let run = backup_key_confirm(&bob, &file, &[], last_group);
    assert!(run.success, "{}", run.stderr);
    let shown = run.stdout;
    let code = backup_code(&shown);
    assert!(shown.contains("отпечаток аккаунта:"), "{shown}");
    assert!(shown.contains("отозвать"), "{shown}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    assert!(
        std::fs::read_to_string(&file)
            .unwrap()
            .starts_with("mkeybackup1.")
    );
    // Файл открывается выведенным кодом (в любом регистре, без дефисов) и содержит наш аккаунт.
    let backup = open_backup(&file, &code).unwrap();
    assert_eq!(backup.account_id(), account_id);
    let alt = code.replace('-', "").to_lowercase();
    assert!(open_backup(&file, &alt).is_ok());
    assert!(open_backup(&file, "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA").is_err());
    // В выводе нет ничего, кроме кода, из секретов: ключ аккаунта не печатается.
    let secret_hex: String = backup
        .account_sign()
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(!shown.contains(&secret_hex));

    // Без --force файл не заменяется.
    let before = std::fs::read(&file).unwrap();
    let out = bob.run(&["backup-key", "--allow-redirect", "--out", file_arg]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("--force"), "{}", stderr(&out));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("КОД"));
    assert_eq!(std::fs::read(&file).unwrap(), before);

    // С --force — заменяется новым файлом с новым кодом.
    let run2 = backup_key_confirm(&bob, &file, &["--force"], last_group);
    assert!(run2.success, "{}", run2.stderr);
    let shown2 = run2.stdout;
    let code2 = backup_code(&shown2);
    assert_ne!(code, code2);
    assert_ne!(std::fs::read(&file).unwrap(), before);
    assert!(
        open_backup(&file, &code).is_err(),
        "старый код не должен подходить"
    );
    assert_eq!(open_backup(&file, &code2).unwrap().account_id(), account_id);

    // Временных файлов не осталось.
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");

    // Несуществующая папка — ошибка, не паника.
    let bad = dir.join("no-such-dir").join("k.backup");
    assert!(
        !bob.run(&[
            "backup-key",
            "--allow-redirect",
            "--out",
            bad.to_str().unwrap()
        ])
        .status
        .success()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Подключённое устройство ключа аккаунта не имеет: копию с него сделать нельзя.
#[test]
fn backup_key_is_refused_on_a_linked_device() {
    let dir = tmp_dir("backup-linked");
    let relay = start_relay();
    let bob = User::new(&dir, "bob", &relay);
    let phone = User::new(&dir, "bob-phone", &relay);
    bob.ok(&["init"]);
    let out = phone.run(&["link", "--name", "телефон"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let code = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let response = dir.join("response.json");
    bob.ok(&[
        "link-approve",
        &code,
        "--yes",
        "-o",
        response.to_str().unwrap(),
    ]);
    phone.ok(&["link-finish", "--response-file", response.to_str().unwrap()]);

    let file = dir.join("phone.backup");
    let out = phone.run(&[
        "backup-key",
        "--allow-redirect",
        "--out",
        file.to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("нет ключа аккаунта"),
        "{}",
        stderr(&out)
    );
    assert!(!file.exists());

    let _ = std::fs::remove_dir_all(&dir);
}

/// Перенаправленный вывод: без `--allow-redirect` отказ до создания файла.
#[test]
fn backup_key_refuses_redirected_stdout_without_flag() {
    let dir = tmp_dir("backup-redirect");
    let relay = start_relay();
    let bob = User::new(&dir, "bob", &relay);
    bob.ok(&["init"]);
    let file = dir.join("key.backup");
    let out = bob.run(&["backup-key", "--out", file.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("--allow-redirect"),
        "{}",
        stderr(&out)
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("КОД"));
    assert!(!file.exists());
    let leftovers = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().contains("key.backup"));
    assert!(!leftovers, "остались файлы копии");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Подтверждение кода: неверная группа три раза — ошибка, файл не создан; при `--force`
/// прежняя копия не тронута; верная группа — успех.
#[test]
fn backup_key_requires_code_confirmation() {
    let dir = tmp_dir("backup-confirm");
    let relay = start_relay();
    let bob = User::new(&dir, "bob", &relay);
    bob.ok(&["init"]);
    let file = dir.join("key.backup");

    // Новый файл: три неверных ввода.
    let run = backup_key_confirm(&bob, &file, &[], wrong_answers);
    assert!(!run.success);
    assert!(run.stderr.contains("не подтверждён"), "{}", run.stderr);
    assert!(!run.stdout.contains("записана:"), "{}", run.stdout);
    assert!(!file.exists());

    // Обрыв ввода (EOF без ответа) тоже провал.
    let run = backup_key_confirm(&bob, &file, &[], |_| String::new());
    assert!(!run.success);
    assert!(!file.exists());

    // Две ошибки и верный ответ с третьей попытки.
    let run = backup_key_confirm(&bob, &file, &[], |c| {
        format!("0000\n0000\n{}", last_group(c))
    });
    assert!(run.success, "{}", run.stderr);
    let code = backup_code(&run.stdout);
    assert!(open_backup(&file, &code).is_ok());
    let before = std::fs::read(&file).unwrap();

    // --force, но код не подтверждён: старая копия остаётся нетронутой.
    let run = backup_key_confirm(&bob, &file, &["--force"], wrong_answers);
    assert!(!run.success);
    assert!(run.stderr.contains("не подтверждён"), "{}", run.stderr);
    assert_eq!(std::fs::read(&file).unwrap(), before);
    assert!(open_backup(&file, &code).is_ok());

    // Временных файлов нет.
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Прерывание SIGTERM во время ожидания подтверждения: временный файл удаляется,
/// целевой не создаётся. Сиротский временный файл от прошлого запуска убирается со
/// следующим запуском с предупреждением.
#[cfg(unix)]
#[test]
fn backup_key_cleans_tmp_on_sigterm_and_removes_stale_tmp() {
    let dir = tmp_dir("backup-signal");
    let relay = start_relay();
    let bob = User::new(&dir, "bob", &relay);
    bob.ok(&["init"]);
    let file = dir.join("key.backup");
    let tmp_files = |dir: &Path| -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp-"))
            .collect()
    };

    let mut child = bob
        .cmd(&[
            "backup-key",
            "--allow-redirect",
            "--out",
            file.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // wait() закрывает stdin ребёнка: EOF успел бы раньше сигнала дать отказ
    // подтверждения (выход 1). Держим stdin открытым до конца процесса.
    let stdin = child.stdin.take();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    loop {
        let mut line = String::new();
        assert!(reader.read_line(&mut line).unwrap() > 0, "код не показан");
        if line.starts_with("    ") && line.trim().len() > 20 {
            break;
        }
    }
    assert_eq!(
        tmp_files(&dir).len(),
        1,
        "временный файл должен существовать"
    );
    let killed = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    let status = child.wait().unwrap();
    drop(stdin);
    assert_eq!(status.code(), Some(143));
    assert!(!file.exists());
    assert!(tmp_files(&dir).is_empty(), "{:?}", tmp_files(&dir));

    // Сирота от прошлого запуска (например, после kill -9) убирается со следующим запуском.
    let stale = dir.join(".key.backup.tmp-0123456789ab");
    std::fs::write(&stale, b"left over").unwrap();
    let run = backup_key_confirm(&bob, &file, &[], last_group);
    assert!(run.success, "{}", run.stderr);
    assert!(!stale.exists());
    assert!(run.stderr.contains("прошлого запуска"), "{}", run.stderr);
    assert!(file.exists());
    assert!(tmp_files(&dir).is_empty());
}

/// Старый аккаунт с ID в виде UUID (не выведенным из ключа) продолжает работать.
#[test]
fn legacy_uuid_account_still_loads() {
    let dir = tmp_dir("legacy-uuid");
    let relay = start_relay();
    for (name, with_sign_key) in [("with-key", true), ("no-sign-key", false)] {
        let user = User::new(&dir, name, &relay);
        let uuid = "1b4e28ba-2fa1-11d2-883f-0016d3cca427";
        let id = crypto_core::Identity::generate(uuid);
        {
            let db = storage::Db::open(&user.db, Some(TEST_PASSWORD)).unwrap();
            db.upsert_identity(&storage::IdentityRow {
                account_id: uuid.into(),
                device_id: 1,
                username: None,
                secret: id.x_secret_bytes(),
                public: id.x_public_bytes(),
                sign_secret: with_sign_key.then(|| id.sign_secret_bytes()),
                sign_public: with_sign_key.then(|| id.sign_public_bytes()),
                account_sign_secret: None,
            })
            .unwrap();
        }
        let out = user.run(&["whoami"]);
        assert!(
            out.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stdout).contains(uuid));
        // Второй запуск (список устройств уже сохранён) тоже проходит.
        user.ok(&["whoami"]);
    }
}

/// Незавершённый link не даёт создать в профиле новую личность; профиль не меняется.
#[test]
fn init_is_refused_while_link_is_pending() {
    let dir = tmp_dir("init-pending-link");
    let relay = start_relay();
    let (phone, code) = pending_phone(&dir, &relay, "phone");
    let out = phone.run(&["init"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("link-finish"), "{}", stderr(&out));
    {
        let db = storage::Db::open(&phone.db, Some(TEST_PASSWORD)).unwrap();
        assert!(db.get_local_identity().unwrap().is_none());
        assert!(db.pending_link().unwrap().is_some());
    }
    // Тот же код подключения по-прежнему выдаётся.
    let again = phone.ok(&["link", "--name", "phone"]);
    assert_eq!(again.trim(), code);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Незавершённое восстановление ключа блокирует init, link и обычные команды.
#[test]
fn pending_restore_blocks_init_link_and_commands() {
    let dir = tmp_dir("pending-restore");
    let relay = start_relay();
    let user = User::new(&dir, "restoring", &relay);
    {
        let db = storage::Db::open(&user.db, Some(TEST_PASSWORD)).unwrap();
        db.set_pending_restore(&storage::PendingRestore {
            account_id: "acc".into(),
            account_secret: [1; 32],
            x_secret: [2; 32],
            sign_secret: [3; 32],
            name: "phone".into(),
        })
        .unwrap();
    }
    for args in [&["init"][..], &["link", "--name", "phone"], &["whoami"]] {
        let out = user.run(args);
        assert!(!out.status.success(), "{args:?}");
        assert!(
            stderr(&out).contains("restore-key"),
            "{args:?}: {}",
            stderr(&out)
        );
    }
    let db = storage::Db::open(&user.db, Some(TEST_PASSWORD)).unwrap();
    assert!(db.pending_restore().unwrap().is_some());
    assert!(db.get_local_identity().unwrap().is_none());
    assert!(db.pending_link().unwrap().is_none());
    let _ = std::fs::remove_dir_all(&dir);
}
