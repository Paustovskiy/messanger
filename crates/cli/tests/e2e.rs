//! Сквозной тест: два настоящих процесса `messenger` (Алиса и Боб) и релей.

use relay_server::{Config, Relay};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

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
    alice.ok(&["retry-outbox", "--wait", "1"]);
    let chat = alice.ok(&["chat", "@bobby"]);
    assert!(chat.contains("я ✓✓: Привет, Боб! 🚀"), "{chat}");
    assert!(chat.contains("я ✓✓: ты онлайн?"), "{chat}");
    assert!(alice.ok(&["retry-outbox"]).contains("Исходящие пусты"));

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
    assert!(String::from_utf8_lossy(&out.stderr).contains("не удалось открыть сообщение"));

    // Без доступного релея сообщение остаётся в исходящих.
    let out = alice.run(&["send", &bob_id, "позже"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("сохранено в исходящих"));

    let _ = std::fs::remove_dir_all(&dir);
}
