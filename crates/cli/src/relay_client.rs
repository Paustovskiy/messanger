//! WebSocket-соединение с релеем: подключение, вход, отправка/приём JSON.

use anyhow::{Context, Result, bail};
use crypto_core::Identity;
use futures_util::{SinkExt, StreamExt};
use protocol::{ClientMessage, ServerMessage, b64, decode_fixed};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite::Message};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct RelayConn {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl RelayConn {
    /// Подключиться к релею и войти как это устройство.
    pub async fn connect(url: &str, me: &Identity) -> Result<Self> {
        let (ws, _) = tokio::time::timeout(CONNECT_TIMEOUT, tokio_tungstenite::connect_async(url))
            .await
            .with_context(|| format!("не дождался подключения к {url}"))?
            .with_context(|| format!("не удалось подключиться к релею {url}"))?;
        let mut conn = Self { ws };

        let nonce = match conn.recv_timeout(CONNECT_TIMEOUT).await? {
            Some(ServerMessage::Challenge { nonce_b64 }) => {
                decode_fixed::<32>(&nonce_b64, "nonce_b64")?
            }
            Some(other) => bail!("неожиданное первое сообщение от релея: {other:?}"),
            None => bail!("релей закрыл соединение, не начав вход"),
        };

        let account_id = me.account_id().to_string();
        let device_id = me.device_id();
        let sig = me.sign(&protocol::relay_auth_signing_bytes(
            &nonce,
            &account_id,
            device_id,
        ));
        conn.send(&ClientMessage::Auth {
            account_id,
            device_id,
            sign_pub_b64: b64(me.sign_public_bytes()),
            sig_b64: b64(sig),
        })
        .await?;

        match conn.recv_timeout(CONNECT_TIMEOUT).await? {
            Some(ServerMessage::Authenticated { .. }) => Ok(conn),
            Some(ServerMessage::Error { message, .. }) => bail!("релей не пустил: {message}"),
            Some(other) => bail!("неожиданный ответ на вход: {other:?}"),
            None => bail!("релей закрыл соединение во время входа"),
        }
    }

    pub async fn send(&mut self, msg: &ClientMessage) -> Result<()> {
        let json = serde_json::to_string(msg)?;
        self.ws
            .send(Message::Text(json))
            .await
            .context("не удалось отправить на релей")
    }

    /// Следующее сообщение от релея. `None` — соединение закрыто.
    pub async fn recv(&mut self) -> Result<Option<ServerMessage>> {
        while let Some(msg) = self.ws.next().await {
            match msg.context("ошибка соединения с релеем")? {
                Message::Text(text) => match serde_json::from_str(&text) {
                    Ok(m) => return Ok(Some(m)),
                    Err(e) => {
                        eprintln!("предупреждение: непонятное сообщение от релея пропущено: {e}")
                    }
                },
                Message::Close(_) => return Ok(None),
                _ => {}
            }
        }
        Ok(None)
    }

    /// Как [`recv`](Self::recv), но не дольше `d`. `None` — тайм-аут или закрытие.
    pub async fn recv_timeout(&mut self, d: Duration) -> Result<Option<ServerMessage>> {
        match tokio::time::timeout(d, self.recv()).await {
            Ok(r) => r,
            Err(_) => Ok(None),
        }
    }

    pub async fn close(mut self) {
        let _ = self.ws.close(None).await;
    }
}
