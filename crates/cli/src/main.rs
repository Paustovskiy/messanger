use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use crypto_core::Identity;
use protocol::{normalize_username, ContactCard, EnvelopeB64, UserId};
use storage::{Db, IdentityRow};
use uuid::Uuid;
use x25519_dalek::PublicKey;
use base64::Engine as _;
use chrono::{DateTime, Local, TimeZone};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio::time::{timeout, Duration};



#[derive(Parser)]
#[command(name = "messenger-cli")]
#[command(about = "Local E2EE CLI for testing without server", long_about = None)]
struct Cli {
    /// App name for storage directory (affects DB path)
    #[arg(long, default_value = "messenger")]
    app: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create identity if absent, otherwise show existing one
    Init,

    /// Set local @username (validated + normalized)
    SetUsername {
        username: String,
    },

    /// Show who am I: account_id, username, pubkey
    Whoami,

    /// Export ContactCard JSON for sharing
    ExportContact,

    /// Encrypt plaintext to recipient ContactCard (string or file)
    Encrypt {
        /// Recipient key: @username or account_id from saved contacts
        to: String,
        text: String,
    },

    /// Decrypt EnvelopeB64 JSON (string or file)
    Decrypt {
        /// EnvelopeB64 JSON string
        #[arg(long, conflicts_with = "envelope_file")]
        envelope: Option<String>,

        /// Path to file containing EnvelopeB64 JSON
        #[arg(long)]
        envelope_file: Option<String>,
    },

    /// Add or update contact from ContactCard JSON (string or file)
    AddContact {
        #[arg(long, conflicts_with = "contact_file")]
        contact: Option<String>,
        #[arg(long)]
        contact_file: Option<String>,
    },

    /// List saved contacts
    ListContacts,

    /// Remove contact by account_id
    RemoveContact {
        account_id: String,
    },

    /// Send message to saved contact (@username or account_id), save to outbox, print envelope JSON
    Send {
        to: String,
        text: String,
    },

    /// Receive (decrypt) envelope JSON, save to inbox, print plaintext
    Receive {
        #[arg(long, conflicts_with = "envelope_file")]
        envelope: Option<String>,
        #[arg(long)]
        envelope_file: Option<String>,
    },

    /// Show chat history with contact (@username or account_id)
    Chat {
        with: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },

    /// List dialogs (one per peer) with last message
    Threads {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },

    /// Send message via relay server (encrypt + store outbox + send over WS)
    SendOnline {
        #[arg(long, default_value = "ws://127.0.0.1:8080/ws")]
        url: String,
        to: String,
        text: String,
    },

    /// Listen on relay server, auto-decrypt incoming and store inbox
    Listen {
        #[arg(long, default_value = "ws://127.0.0.1:8080/ws")]
        url: String,
    },

    /// Retry sending undelivered OUT messages (status=0) via relay
    RetryOutbox {
        #[arg(long, default_value = "ws://127.0.0.1:8080/ws")]
        url: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WsIn {
    Register { account_id: String },
    Send { to: String, msg_id: String, envelope: EnvelopeB64 },
    Ack { to: String, msg_id: String },
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WsOut {
    Ack { message: String },
    Error { message: String },
    Deliver { from: String, msg_id: String, envelope: EnvelopeB64 },
    DeliverAck { from: String, msg_id: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let (db, path) = Db::open_default(&cli.app)?;
    // Удобно видеть путь при отладке
    eprintln!("DB: {:?}", path);

    match cli.command {
        Commands::Init => cmd_init(&db)?,
        Commands::SetUsername { username } => cmd_set_username(&db, &username)?,
        Commands::Whoami => cmd_whoami(&db)?,
        Commands::ExportContact => cmd_export_contact(&db)?,
        Commands::Encrypt { to, text } => cmd_encrypt_to_saved(&db, &to, &text)?,
        Commands::Decrypt {
            envelope,
            envelope_file,
        } => cmd_decrypt(&db, envelope, envelope_file)?,
        Commands::AddContact { contact, contact_file } => cmd_add_contact(&db, contact, contact_file)?,
        Commands::ListContacts => cmd_list_contacts(&db)?,
        Commands::RemoveContact { account_id } => cmd_remove_contact(&db, &account_id)?,
        Commands::Send { to, text } => cmd_send(&db, &to, &text)?,
        Commands::Receive { envelope, envelope_file } => cmd_receive(&db, envelope, envelope_file)?,
        Commands::Chat { with, limit } => cmd_chat(&db, &with, limit)?,
        Commands::Threads { limit } => cmd_threads(&db, limit)?,
        Commands::SendOnline { url, to, text } => cmd_send_online(&db, &url, &to, &text)?,
        Commands::Listen { url } => cmd_listen(&db, &url)?,
        Commands::RetryOutbox { url, limit } => cmd_retry_outbox(&db, &url, limit)?,
    }

    Ok(())
}

fn load_or_create_identity(db: &Db) -> Result<(IdentityRow, Identity)> {
    if let Some(row) = db.get_local_identity()? {
        let id = Identity::from_secret_bytes(row.account_id.clone(), row.secret);
        return Ok((row, id));
    }

    let account_id = Uuid::new_v4().to_string();
    let id = Identity::generate(&account_id);

    let row = IdentityRow {
        account_id,
        username: None,
        secret: id.secret_bytes(),
        public: id.public_bytes(),
        sign_secret: id.sign_secret_bytes(),
        sign_public: id.sign_public_bytes(),
    };

    db.upsert_identity(&row)?;
    Ok((row, id))
}

fn cmd_init(db: &Db) -> Result<()> {
    let (row, _id) = load_or_create_identity(db)?;
    println!(
        "OK: account_id={}, username={:?}",
        row.account_id, row.username
    );
    Ok(())
}

fn cmd_set_username(db: &Db, username: &str) -> Result<()> {
    let (row, _id) = load_or_create_identity(db)?;

    let norm = normalize_username(username)
        .map_err(|e| anyhow::anyhow!(e))
        .context("username validation failed")?;

    db.set_username(&row.account_id, Some(&norm))?;
    println!("OK: username set to {}", norm);
    Ok(())
}

fn cmd_whoami(db: &Db) -> Result<()> {
    let (row, id) = load_or_create_identity(db)?;
    println!("account_id: {}", row.account_id);
    println!("username:   {}", row.username.as_deref().unwrap_or("(none)"));
    println!(
        "pubkey_b64: {}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(id.public_bytes())
    );
    Ok(())
}

fn cmd_export_contact(db: &Db) -> Result<()> {
    let (row, id) = load_or_create_identity(db)?;
    let card = ContactCard::from_parts(row.account_id, row.username, id.public_bytes());
    let json = serde_json::to_string_pretty(&card)?;
    println!("{}", json);
    Ok(())
}

fn read_input_string(direct: Option<String>, file: Option<String>, what: &str) -> Result<String> {
    if let Some(s) = direct {
        return Ok(s);
    }
    if let Some(path) = file {
        return Ok(std::fs::read_to_string(&path).with_context(|| format!("read {} file", what))?);
    }

    // Если не указано ни --what, ни --what-file, читаем stdin
    use std::io::Read;
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf).with_context(|| format!("read {} from stdin", what))?;
    let buf = buf.trim().to_string();

    if buf.is_empty() {
        anyhow::bail!("provide --{} or --{}-file, or pipe {} JSON via stdin", what, what, what);
    }
    Ok(buf)
}


fn cmd_decrypt(db: &Db, envelope: Option<String>, envelope_file: Option<String>) -> Result<()> {
    let (_row, me) = load_or_create_identity(db)?;

    let env_json = read_input_string(envelope, envelope_file, "envelope")?;
    let env_b64: EnvelopeB64 = serde_json::from_str(&env_json).context("parse EnvelopeB64 JSON")?;

    let env = protocol::Envelope::try_from(env_b64).map_err(|e| anyhow::anyhow!(e))?;
    let pt = me.decrypt(&env).map_err(|e| anyhow::anyhow!(e))?;

    println!("{}", String::from_utf8_lossy(&pt));
    Ok(())
}

fn cmd_add_contact(db: &Db, contact: Option<String>, contact_file: Option<String>) -> Result<()> {
    let contact_json = read_input_string(contact, contact_file, "contact")?;
    let card: ContactCard = serde_json::from_str(&contact_json).context("parse ContactCard JSON")?;

    let public = card.pubkey_bytes()?;
    let row = storage::ContactRow {
        account_id: card.account_id.clone(),
        username: card.username.clone(),
        public,
    };

    db.upsert_contact(&row)?;
    println!(
        "OK: saved contact account_id={}, username={}",
        row.account_id,
        row.username.as_deref().unwrap_or("(none)")
    );
    Ok(())
}

fn cmd_list_contacts(db: &Db) -> Result<()> {
    let items = db.list_contacts()?;
    if items.is_empty() {
        println!("(no contacts)");
        return Ok(());
    }

    for c in items {
        println!(
            "{}\t{}\t{}",
            c.account_id,
            c.username.as_deref().unwrap_or("(none)"),
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(c.public)
        );
    }
    Ok(())
}

fn cmd_remove_contact(db: &Db, account_id: &str) -> Result<()> {
    db.delete_contact(account_id)?;
    println!("OK: removed {}", account_id);
    Ok(())
}

fn cmd_encrypt_to_saved(db: &Db, to_key: &str, text: &str) -> Result<()> {
    let (_row, me) = load_or_create_identity(db)?;

    let c = db
        .find_contact(to_key)?
        .with_context(|| format!("contact not found: {}", to_key))?;

    let peer_pub = PublicKey::from(c.public);
    let to = UserId(c.account_id.clone());

    let env = me.encrypt_to(&peer_pub, to, text.as_bytes());
    let env_b64: EnvelopeB64 = env.into();

    let json = serde_json::to_string_pretty(&env_b64)?;
    println!("{}", json);
    Ok(())
}
fn cmd_send(db: &Db, to_key: &str, text: &str) -> Result<()> {
    let (_row, me) = load_or_create_identity(db)?;

    let c = db
        .find_contact(to_key)?
        .with_context(|| format!("contact not found: {}", to_key))?;

    let peer_pub = PublicKey::from(c.public);
    let to = UserId(c.account_id.clone());

    let env = me.encrypt_to(&peer_pub, to, text.as_bytes());
    let env_b64: EnvelopeB64 = env.into();

    let env_json = serde_json::to_string_pretty(&env_b64)?;

    let msg_id = Uuid::new_v4().to_string();
    // save outbox
    db.insert_message(
        storage::Direction::Out,
        &c.account_id,
        c.username.as_deref(),
        text,
        &env_json,
        Some(&msg_id)
    )?;

    // print envelope for copy/paste or transport layer
    println!("{}", env_json);
    Ok(())
}

fn cmd_receive(db: &Db, envelope: Option<String>, envelope_file: Option<String>) -> Result<()> {
    let (_row, me) = load_or_create_identity(db)?;

    let env_json = read_input_string(envelope, envelope_file, "envelope")?;
    let env_b64: EnvelopeB64 = serde_json::from_str(&env_json).context("parse EnvelopeB64 JSON")?;
    let env = protocol::Envelope::try_from(env_b64).map_err(|e| anyhow::anyhow!(e))?;

    let pt = me.decrypt(&env).map_err(|e| anyhow::anyhow!(e))?;
    let plaintext = String::from_utf8_lossy(&pt).to_string();

    // sender is env.from (account_id)
    let peer_id = env.from.0.clone();

    // try to resolve username snapshot from contacts (optional)
    let peer_username = db
        .find_contact(&peer_id)?
        .and_then(|c| c.username);

    let msg_id = Uuid::new_v4().to_string();
    db.insert_message(
        storage::Direction::In,
        &peer_id,
        peer_username.as_deref(),
        &plaintext,
        &env_json,
        Some(&msg_id)
    )?;

    println!("{}", plaintext);
    Ok(())
}

fn cmd_chat(db: &Db, with_key: &str, limit: usize) -> Result<()> {
    // Resolve peer account_id
    let peer = db
        .find_contact(with_key)?
        .with_context(|| format!("contact not found: {}", with_key))?;

    let items = db.list_messages_for_peer_resolved(&peer.account_id, limit)?;

    if items.is_empty() {
        println!("(no messages with {})", peer.username.as_deref().unwrap_or(&peer.account_id));
        return Ok(());
    }

    for m in items {
        let dir = match m.direction {
            storage::Direction::In => "IN ",
            storage::Direction::Out => "OUT",
        };

        // Пока выводим unix timestamp. Позже красиво отформатируем на клиенте/UI.
        let dt: DateTime<Local> = Local.timestamp_opt(m.created_at, 0).single().unwrap();

        let status_mark = match m.direction {
            storage::Direction::Out => {
                if m.status >= 1 { " ✓✓" } else { " ✓" }
            }
            storage::Direction::In => "",
        };

        println!(
            "[{}] {} {}{}: {}",
            dt.format("%Y-%m-%d %H:%M:%S"),
            dir,
            m.peer_username.as_deref().unwrap_or(&m.peer_account_id),
            status_mark,
            m.plaintext
        );
    }

    db.mark_thread_read(&peer.account_id)?;

    Ok(())
}

fn cmd_threads(db: &Db, limit: usize) -> Result<()> {
    let items = db.list_threads_resolved(limit)?;

    if items.is_empty() {
        println!("(no dialogs yet)");
        return Ok(());
    }

    for t in items {
        let dt: DateTime<Local> = Local.timestamp_opt(t.last_created_at, 0).single().unwrap();

        let dir = match t.last_direction {
            storage::Direction::In => "IN ",
            storage::Direction::Out => "OUT",
        };

        let who = t.peer_username.as_deref().unwrap_or(&t.peer_account_id);

        let unread = if t.unread_count > 0 {
            format!(" (+{})", t.unread_count)
        } else {
            String::new()
        };

        
        let mark: &str = match t.last_direction {
            storage::Direction::Out => {
                if t.last_status >= 1 { " ✓✓" } else { " ✓" }
            }
            storage::Direction::In => "",
        };

        println!(
            "[{}] {} {}{}{}: {}",
            dt.format("%Y-%m-%d %H:%M:%S"),
            dir,
            who,
            unread,
            mark,
            t.last_plaintext
        );
    }

    Ok(())
}

fn cmd_send_online(db: &Db, url: &str, to_key: &str, text: &str) -> Result<()> {
    // создаём runtime, чтобы не переписывать весь CLI на async
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let (_row, me) = load_or_create_identity(db)?;

        let c = db
            .find_contact(to_key)?
            .with_context(|| format!("contact not found: {}", to_key))?;

        let peer_pub = PublicKey::from(c.public);
        let to = UserId(c.account_id.clone());

        let env = me.encrypt_to(&peer_pub, to, text.as_bytes());
        let env_b64: EnvelopeB64 = env.into();

        let env_json = serde_json::to_string_pretty(&env_b64)?;

        let msg_id = Uuid::new_v4().to_string();
        // сохранить outbox (как в send)
        db.insert_message(
            storage::Direction::Out,
            &c.account_id,
            c.username.as_deref(),
            text,
            &env_json,
            Some(&msg_id)
        )?;

        // WS connect + register + send
        let (mut ws, _resp) = tokio_tungstenite::connect_async(url).await?;

        // register
        let reg = WsIn::Register {
            account_id: me.user_id.0.clone(),
        };
        ws.send(WsMessage::Text(serde_json::to_string(&reg)?)).await?;

        // send
        let msg = WsIn::Send {
            to: c.account_id.clone(),
            msg_id: msg_id.clone(),
            envelope: env_b64,
        };

        ws.send(WsMessage::Text(serde_json::to_string(&msg)?)).await?;

        let mut delivered = false;

        while let Ok(Some(Ok(WsMessage::Text(t)))) =
            timeout(Duration::from_secs(5), ws.next()).await
        {
            if let Ok(ev) = serde_json::from_str::<WsOut>(&t) {
                match ev {
                    WsOut::DeliverAck { from, msg_id: ack_msg_id } => {
                        // важно: сверяем msg_id, чтобы не поймать "чужой" ack
                        if ack_msg_id == msg_id {
                            db.mark_out_delivered(&from, &ack_msg_id)?;
                            println!("DELIVERED to {} msg_id={}", from, ack_msg_id);
                            delivered = true;
                            break;
                        }
                    }
                    WsOut::Error { message } => {
                        eprintln!("server error: {}", message);
                        break;
                    }
                    _ => {}
                }
            }
        }

        if !delivered {
            eprintln!("WARN: no DeliverAck within timeout for msg_id={}", msg_id);
        }

        // optionally read quickly (non-blocking best-effort)
        // then close
        let _ = ws.close(None).await;

        println!("OK: sent online to {}", c.username.as_deref().unwrap_or(&c.account_id));
        Ok::<_, anyhow::Error>(())
    })
}

fn cmd_listen(db: &Db, url: &str) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let (_row, me) = load_or_create_identity(db)?;

        let (mut ws, _resp) = tokio_tungstenite::connect_async(url).await?;

        // register
        let reg = WsIn::Register {
            account_id: me.user_id.0.clone(),
        };
        ws.send(WsMessage::Text(serde_json::to_string(&reg)?)).await?;

        println!("Listening on {} as {}", url, me.user_id.0);
        while let Some(msg) = ws.next().await {
            let msg = msg?;
            if let WsMessage::Text(text) = msg {
                let parsed: Result<WsOut, _> = serde_json::from_str(&text);
                let Ok(ev) = parsed else {
                    continue;
                };

                match ev {
                    WsOut::Ack { .. } => {}

                    WsOut::DeliverAck { from, msg_id } => {
                        // тут дальше будет логика "пометить OUT как доставленное/прочитанное"
                        // пока можно просто вывести:
                        db.mark_out_delivered(&from, &msg_id)?;
                        println!("DELIVERED to {} msg_id={}", from, msg_id);
                    }

                    WsOut::Error { message } => {
                        eprintln!("server error: {}", message);
                    }

                    WsOut::Deliver { from, msg_id, envelope } => {
                        // decrypt
                        let env = protocol::Envelope::try_from(envelope)
                            .map_err(|e| anyhow::anyhow!(e))?;

                        let pt = me.decrypt(&env).map_err(|e| anyhow::anyhow!(e))?;
                        let plaintext = String::from_utf8_lossy(&pt).to_string();

                        // resolve username snapshot if present in contacts
                        let peer_username = db
                            .find_contact(&from)?
                            .and_then(|c| c.username);

                        let env_json = serde_json::to_string_pretty(&EnvelopeB64::from(env))?;

                        // сохраняем входящее с тем же msg_id, что пришёл по сети
                        db.insert_message(
                            storage::Direction::In,
                            &from,
                            peer_username.as_deref(),
                            &plaintext,
                            &env_json,
                            Some(&msg_id),
                        )?;

                        // <-- ВОТ ЗДЕСЬ ACK (после успешного сохранения)
                        let ack = WsIn::Ack {
                            to: from.clone(),
                            msg_id: msg_id.clone(),
                        };
                        ws.send(WsMessage::Text(serde_json::to_string(&ack)?)).await?;

                        println!(
                            "FROM {}: {}",
                            peer_username.as_deref().unwrap_or(&from),
                            plaintext
                        );
                    }
                }
            }
        }

        Ok::<_, anyhow::Error>(())
    })
}

fn cmd_retry_outbox(db: &Db, url: &str, limit: usize) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let (_row, me) = load_or_create_identity(db)?;

        // 1) load pending
        let pending = db.list_pending_outgoing(limit)?;
        if pending.is_empty() {
            println!("OK: no pending outgoing messages");
            return Ok::<_, anyhow::Error>(());
        }

        // 2) connect + register
        let (mut ws, _resp) = tokio_tungstenite::connect_async(url).await?;

        let reg = WsIn::Register {
            account_id: me.user_id.0.clone(),
        };
        ws.send(WsMessage::Text(serde_json::to_string(&reg)?)).await?;

        println!("Retrying {} pending messages...", pending.len());

        // 3) send all
        for (peer_account_id, msg_id, env_json) in pending {
            let env_b64: EnvelopeB64 =
                serde_json::from_str(&env_json).context("parse EnvelopeB64 from db")?;

            let msg = WsIn::Send {
                to: peer_account_id.clone(),
                msg_id: msg_id.clone(),
                envelope: env_b64,
            };

            ws.send(WsMessage::Text(serde_json::to_string(&msg)?)).await?;
            println!("SENT retry to={} msg_id={}", peer_account_id, msg_id);
        }

        // 4) wait for acks (best-effort window)
        // Мы просто слушаем входящие DeliverAck и отмечаем delivered.
        let deadline = Duration::from_secs(5);
        loop {
            let next = timeout(deadline, ws.next()).await;
            let Ok(Some(Ok(WsMessage::Text(t)))) = next else {
                break; // timeout or closed
            };

            if let Ok(ev) = serde_json::from_str::<WsOut>(&t) {
                match ev {
                    WsOut::DeliverAck { from, msg_id } => {
                        db.mark_out_delivered(&from, &msg_id)?;
                        println!("ACK from={} msg_id={}", from, msg_id);
                    }
                    WsOut::Error { message } => {
                        eprintln!("server error: {}", message);
                    }
                    _ => {}
                }
            }
        }

        let _ = ws.close(None).await;
        println!("OK: retry done");
        Ok::<_, anyhow::Error>(())
    })
}