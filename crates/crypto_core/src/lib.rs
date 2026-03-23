use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use protocol::{Envelope, UserId};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("decrypt failed")]
    DecryptFailed,
    #[error("invalid secret bytes length")]
    InvalidSecretBytes,
}

#[derive(Clone)]
pub struct Identity {
    pub user_id: UserId,
    x_secret: StaticSecret,
    pub x_public: PublicKey,
    sign: SigningKey,
}

impl Identity {
    pub fn generate(user_id: impl Into<String>) -> Self {
        let mut rng = OsRng;

        let x_secret = StaticSecret::random_from_rng(&mut rng);
        let x_public = PublicKey::from(&x_secret);

        let mut sign_secret = [0u8; 32];
        rng.fill_bytes(&mut sign_secret);
        let sign = SigningKey::from_bytes(&sign_secret);

        Self {
            user_id: UserId(user_id.into()),
            x_secret,
            x_public,
            sign,
        }
    }

    /// Восстановление identity из двух 32-байтных секретов:
    /// - x25519 static secret
    /// - ed25519 signing secret
    pub fn from_secrets(
        user_id: impl Into<String>,
        x_secret_bytes: [u8; 32],
        sign_secret_bytes: [u8; 32],
    ) -> Self {
        let x_secret = StaticSecret::from(x_secret_bytes);
        let x_public = PublicKey::from(&x_secret);
        let sign = SigningKey::from_bytes(&sign_secret_bytes);

        Self {
            user_id: UserId(user_id.into()),
            x_secret,
            x_public,
            sign,
        }
    }

    /// Старый совместимый конструктор.
    /// Временно оставляем, но он создаёт deterministic signing key из x_secret_bytes нельзя.
    /// Поэтому лучше больше не использовать.
    pub fn from_secret_bytes(user_id: impl Into<String>, secret_bytes: [u8; 32]) -> Self {
        let x_secret = StaticSecret::from(secret_bytes);
        let x_public = PublicKey::from(&x_secret);

        // ВРЕМЕННО: отдельный случай для старых вызовов.
        // Лучше как можно скорее перейти на from_secrets(...)
        let mut rng = OsRng;
        let mut sign_secret = [0u8; 32];
        rng.fill_bytes(&mut sign_secret);
        let sign = SigningKey::from_bytes(&sign_secret);

        Self {
            user_id: UserId(user_id.into()),
            x_secret,
            x_public,
            sign,
        }
    }

    /// Экспорт x25519 приватного ключа
    pub fn x_secret_bytes(&self) -> [u8; 32] {
        self.x_secret.to_bytes()
    }

    /// Старое имя, если у тебя уже много вызовов в проекте
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.x_secret.to_bytes()
    }

    /// Экспорт x25519 публичного ключа
    pub fn x_public_bytes(&self) -> [u8; 32] {
        self.x_public.to_bytes()
    }

    /// Старое имя, если уже используется
    pub fn public_bytes(&self) -> [u8; 32] {
        self.x_public.to_bytes()
    }

    /// Экспорт ed25519 приватного ключа (32 bytes)
    pub fn sign_secret_bytes(&self) -> [u8; 32] {
        self.sign.to_bytes()
    }

    /// Экспорт ed25519 публичного ключа (32 bytes)
    pub fn sign_public_bytes(&self) -> [u8; 32] {
        self.sign.verifying_key().to_bytes()
    }

    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        self.sign.sign(data).to_bytes()
    }

    pub fn verify(sign_public: [u8; 32], data: &[u8], sig: [u8; 64]) -> bool {
        let vk = match VerifyingKey::from_bytes(&sign_public) {
            Ok(v) => v,
            Err(_) => return false,
        };

        let sig = Signature::from_bytes(&sig);
        vk.verify(data, &sig).is_ok()
    }

    pub fn encrypt_to(&self, peer: &PublicKey, to: UserId, plaintext: &[u8]) -> Envelope {
        let mut rng = OsRng;

        let eph_secret = EphemeralSecret::random_from_rng(&mut rng);
        let eph_pub = PublicKey::from(&eph_secret);

        let shared = eph_secret.diffie_hellman(peer);

        let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(b"messenger-aead-v0", &mut okm)
            .expect("hkdf expand");

        let aead = ChaCha20Poly1305::new(Key::from_slice(&okm));

        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);

        let nonce = Nonce::from_slice(&nonce_bytes);
        let body = aead.encrypt(nonce, plaintext).expect("encrypt");

        Envelope {
            from: self.user_id.clone(),
            to,
            eph_pub: eph_pub.to_bytes(),
            nonce: nonce_bytes,
            body,
        }
    }

    pub fn decrypt(&self, env: &Envelope) -> Result<Vec<u8>, CryptoError> {
        let sender_eph = PublicKey::from(env.eph_pub);
        let shared = self.x_secret.diffie_hellman(&sender_eph);

        let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(b"messenger-aead-v0", &mut okm)
            .expect("hkdf expand");

        let aead = ChaCha20Poly1305::new(Key::from_slice(&okm));

        let nonce = Nonce::from_slice(&env.nonce);
        aead.decrypt(nonce, env.body.as_ref())
            .map_err(|_| CryptoError::DecryptFailed)
    }
}