use anyhow::{Context, Result};
use clap::Parser;
use relay_server::{Config, Relay};
use std::path::PathBuf;
use std::time::Duration;
use tracing::info;

/// Релей мессенджера: хранит и доставляет зашифрованные сообщения.
#[derive(Parser, Debug)]
#[command(name = "messenger-relay", version)]
struct Args {
    /// Адрес, на котором слушать.
    #[arg(long, env = "RELAY_BIND", default_value = "127.0.0.1:8080")]
    bind: String,

    /// Файл базы (очередь сообщений и ключи аккаунтов).
    #[arg(long, env = "RELAY_DB", default_value = "relay.sqlite")]
    db: PathBuf,

    /// Держать всё в памяти (удобно для экспериментов; при перезапуске всё теряется).
    #[arg(long, conflicts_with = "db")]
    in_memory: bool,

    /// Сколько дней хранить недоставленные сообщения.
    #[arg(long, default_value_t = 30)]
    ttl_days: u64,

    /// Максимум сообщений в очереди одного получателя.
    #[arg(long, default_value_t = 1000)]
    max_queue: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let config = Config {
        db_path: (!args.in_memory).then_some(args.db.clone()),
        message_ttl: Duration::from_secs(args.ttl_days * 24 * 3600),
        max_queue_per_recipient: args.max_queue,
        ..Config::default()
    };

    let relay = Relay::new(config).context("start relay")?;
    let listener = tokio::net::TcpListener::bind(&args.bind)
        .await
        .with_context(|| format!("bind {}", args.bind))?;

    info!(
        "relay listening on ws://{}/ws ({})",
        listener.local_addr()?,
        if args.in_memory {
            "in-memory".to_string()
        } else {
            format!("db: {}", args.db.display())
        }
    );

    relay
        .serve(listener, async {
            shutdown_signal().await;
            info!("shutting down");
        })
        .await
}

/// Ждать Ctrl+C или SIGTERM (так завершают процесс systemd и `docker stop`).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
