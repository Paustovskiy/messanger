//! WebSocket-соединение с релеем: подключение, вход, отправка/приём JSON.

use anyhow::{Context, Result, bail};
use crypto_core::Identity;
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use protocol::{ACCOUNT_SESSION_DEVICE, ClientMessage, ServerMessage, b64, decode_fixed};
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
        Self::connect_with(
            url,
            me.account_id(),
            me.device_id(),
            me.sign_public_bytes(),
            |data| me.sign(data),
        )
        .await
    }

    /// Подключиться к релею сессией ключа аккаунта (device_id 0): только список
    /// устройств своего аккаунта.
    pub async fn connect_account(url: &str, account_id: &str, key: &SigningKey) -> Result<Self> {
        Self::connect_with(
            url,
            account_id,
            ACCOUNT_SESSION_DEVICE,
            key.verifying_key().to_bytes(),
            |data| key.sign(data).to_bytes(),
        )
        .await
        .map_err(|e| map_account_auth_error(&format!("{e:#}")).map_or(e, anyhow::Error::msg))
    }

    async fn connect_with(
        url: &str,
        account_id: &str,
        device_id: u32,
        sign_pub: [u8; 32],
        sign_fn: impl FnOnce(&[u8]) -> [u8; 64],
    ) -> Result<Self> {
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

        let sig = sign_fn(&protocol::relay_auth_signing_bytes(
            &nonce, account_id, device_id,
        ));
        conn.send(&ClientMessage::Auth {
            account_id: account_id.to_owned(),
            device_id,
            sign_pub_b64: b64(sign_pub),
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

/// Понятный текст для отказа релея во входе сессией ключа аккаунта. `None` — отказ
/// по другой причине, текст остаётся как есть.
///
/// Старый релей не знает устройство 0 и отвечает, что его нет в списке устройств.
fn map_account_auth_error(message: &str) -> Option<String> {
    if message.contains(protocol::ERR_NOT_IN_DEVICE_LIST) {
        Some("релей не поддерживает восстановление ключа — обновите релей".into())
    } else if message.contains("account key session needs a known account") {
        Some("релей не знает этот аккаунт".into())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_auth_errors_become_readable() {
        let old = format!("релей не пустил: {}", protocol::ERR_NOT_IN_DEVICE_LIST);
        assert!(
            map_account_auth_error(&old)
                .unwrap()
                .contains("обновите релей")
        );
        assert_eq!(
            map_account_auth_error("релей не пустил: account key session needs a known account")
                .as_deref(),
            Some("релей не знает этот аккаунт")
        );
        assert_eq!(
            map_account_auth_error("релей не пустил: internal error"),
            None
        );
    }
}
