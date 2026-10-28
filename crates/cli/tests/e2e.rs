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
    let out = bob.ok(&["unlink", "2"]);
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

    // Подключать и отключать может только основное устройство.
    assert!(stderr(&phone.run(&["unlink", "1"])).contains("основное"));

    let _ = std::fs::remove_dir_all(&dir);
}
