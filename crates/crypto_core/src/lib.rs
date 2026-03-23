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
    secret: StaticSecret,
    pub public: PublicKey,
}

impl Identity {
    pub fn generate(user_id: impl Into<String>) -> Self {
        let mut rng = OsRng;
        let secret = StaticSecret::random_from_rng(&mut rng);
        let public = PublicKey::from(&secret);

        Self {
            user_id: UserId(user_id.into()),
            secret,
            public,
        }
    }

    /// Восстановление identity из 32 байт приватного ключа (StaticSecret).
    pub fn from_secret_bytes(user_id: impl Into<String>, secret_bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);

        Self {
            user_id: UserId(user_id.into()),
            secret,
            public,
        }
    }

    /// Экспорт приватного ключа (для сохранения в SQLite).
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Экспорт публичного ключа (для контакт-карточек и т.п.).
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
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
        let shared = self.secret.diffie_hellman(&sender_eph);

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