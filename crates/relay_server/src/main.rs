use anyhow::Result;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use clap::Parser;
use dashmap::DashMap;
use futures_util::{sink::SinkExt, stream::StreamExt};
use protocol::EnvelopeB64;
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, net::SocketAddr, sync::Arc};
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(name = "relay_server")]
struct Args {
    /// Bind address, e.g. 127.0.0.1:8080
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: String,
}

#[derive(Clone)]
struct AppState {
    // connected clients: account_id -> sender(json)
    clients: Arc<DashMap<String, UnboundedSender<String>>>,
    // offline queue: account_id -> list of pending deliver messages(json)
    pending: Arc<DashMap<String, VecDeque<String>>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WsIn {
    Register { account_id: String },

    // обычная доставка
    Send {
        to: String,
        msg_id: String,
        envelope: EnvelopeB64,
    },

    // подтверждение доставки
    Ack {
        to: String,     // кому отправить ack (отправителю)
        msg_id: String, // id сообщения
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WsOut {
    Ack { message: String },
    Error { message: String },

    // доставка сообщения получателю
    Deliver {
        from: String,
        msg_id: String,
        envelope: EnvelopeB64,
    },

    // ack отправителю
    DeliverAck {
        from: String,
        msg_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let addr: SocketAddr = args.bind.parse()?;

    let state = AppState {
        clients: Arc::new(DashMap::new()),
        pending: Arc::new(DashMap::new()),
    };

    let app = Router::new()
        .route("/ws", get(ws_handler))
        .with_state(state);

    info!("relay_server listening on https://{}", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;

    Ok(())
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(state, socket))
}

async fn handle_socket(state: AppState, socket: WebSocket) {
    let (mut ws_tx, mut ws_rx) = socket.split();

    // channel used to push server->client messages
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    // task: forward from rx -> websocket
    let  forward = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_tx.send(Message::Text(msg)).await.is_err() {
                break;
            }
        }
    });

    fn require_registered(
        my_id: &Option<String>,
        tx: &UnboundedSender<String>,
    ) -> Option<String> {
        match my_id.clone() {
            Some(id) => Some(id),
            None => {
                let msg = serde_json::to_string(&WsOut::Error {
                    message: "must register first".to_string(),
                }).unwrap();

                if let Err(e) = tx.send(msg) {
                    error!("failed to send error to unregistered client: {}", e);
                }
                None
            }
        }
    }

    fn deliver_or_queue(state: &AppState, to: String, json: String) {
        if let Some(target) = state.clients.get(&to) {
            if let Err(e) = target.send(json) {
                error!("failed to send to {}: {}", to, e);
            }
        } else {
            state
                .pending
                .entry(to)
                .or_insert_with(VecDeque::new)
                .push_back(json);
        }
    }

    // must register first
    let mut my_id: Option<String> = None;

    while let Some(Ok(msg)) = ws_rx.next().await {
        match msg {
            Message::Text(text) => {
                let parsed: Result<WsIn, _> = serde_json::from_str(&text);
                let Ok(input) = parsed else {
                    let _ = tx.send(
                        serde_json::to_string(&WsOut::Error {
                            message: "invalid json".to_string(),
                        })
                            .unwrap(),
                    );
                    continue;
                };

                match input {
                    WsIn::Register { account_id } => {
                        my_id = Some(account_id.clone());
                        state.clients.insert(account_id.clone(), tx.clone());

                        // flush pending
                        if let Some(mut entry) = state.pending.get_mut(&account_id) {
                            while let Some(pending_msg) = entry.pop_front() {
                                let _ = tx.send(pending_msg);
                            }
                        }

                        let _ = tx.send(
                            serde_json::to_string(&WsOut::Ack {
                                message: "registered".to_string(),
                            })
                                .unwrap(),
                        );

                        info!("client registered: {}", account_id);
                    }
                    WsIn::Send { to, msg_id, envelope } => {
                        let Some(from) = require_registered(&my_id, &tx) else {
                            continue;
                        };

                        let deliver_json = serde_json::to_string(&WsOut::Deliver {
                            from,
                            msg_id,
                            envelope,
                        })
                            .unwrap();

                        deliver_or_queue(&state, to, deliver_json);
                    }

                    WsIn::Ack { to, msg_id } => {
                        let Some(from) = require_registered(&my_id, &tx) else {
                            continue;
                        };

                        let ack_json = serde_json::to_string(&WsOut::DeliverAck {
                            from,
                            msg_id,
                        })
                            .unwrap();

                        deliver_or_queue(&state, to, ack_json);
                    }
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    // cleanup
    if let Some(id) = my_id {
        state.clients.remove(&id);
        info!("client disconnected: {}", id);
    }

    forward.abort();
}