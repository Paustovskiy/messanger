//! Double Ratchet — по спецификации Signal
//! (<https://signal.org/docs/specifications/doubleratchet/>).
//!
//! Каждое сообщение шифруется своим ключом. Ключи выводятся из «цепочек»
//! (symmetric ratchet), а цепочки обновляются новым Диффи — Хеллманом при
//! каждой смене говорящего (DH ratchet). Отсюда два свойства:
//!
//! * **прямая секретность** — использованные ключи стираются, и украденное
//!   сегодня состояние не открывает вчерашние сообщения;
//! * **восстановление после компрометации** — после очередного DH-шага
//!   украденное состояние перестаёт помогать атакующему.
//!
//! Все операции, которые могут не удаться, работают с копией состояния и
//! применяют её только при успехе: битое или поддельное сообщение не портит сессию.

use crate::CryptoError;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use protocol::RatchetHeader;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::VecDeque;
use x25519_dalek::{PublicKey, StaticSecret};

/// Сколько сообщений одной цепочки можно «перепрыгнуть» (потерянные или
/// пришедшие не по порядку). Защита от DoS огромным `n` в заголовке.
pub const MAX_SKIP: u32 = 1000;

/// Сколько пропущенных ключей храним на сессию; самые старые вытесняются.
pub const MAX_SKIPPED_KEYS: usize = 2000;

const INFO_RK: &[u8] = b"messenger/ratchet-root/v1";
const INFO_MSG: &[u8] = b"messenger/ratchet-message/v1";

#[derive(Clone, Serialize, Deserialize)]
struct SkippedKey {
    dh: [u8; 32],
    n: u32,
    mk: [u8; 32],
}

/// Состояние Double Ratchet одной сессии.
#[derive(Clone, Serialize, Deserialize)]
pub struct Ratchet {
    dhs_secret: [u8; 32],
    dhs_pub: [u8; 32],
    dhr: Option<[u8; 32]>,
    rk: [u8; 32],
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped: VecDeque<SkippedKey>,
}

impl std::fmt::Debug for Ratchet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ratchet")
            .field("ns", &self.ns)
            .field("nr", &self.nr)
            .field("pn", &self.pn)
            .field("skipped", &self.skipped.len())
            .finish_non_exhaustive()
    }
}

impl Ratchet {
    /// Инициатор (Алиса): знает общий секрет `sk` и ratchet-ключ Боба
    /// (его подписанный предключ).
    pub fn init_initiator(sk: [u8; 32], remote_dh: [u8; 32]) -> Result<Self, CryptoError> {
        let (dhs_secret, dhs_pub) = generate_dh();
        let (rk, cks) = kdf_rk(&sk, &dh(&dhs_secret, &remote_dh)?);
        Ok(Self {
            dhs_secret,
            dhs_pub,
            dhr: Some(remote_dh),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: VecDeque::new(),
        })
    }

    /// Ответчик (Боб): знает общий секрет `sk` и секрет своей ratchet-пары
    /// (подписанного предключа, по которому его нашли).
    pub fn init_responder(sk: [u8; 32], own_dh_secret: [u8; 32]) -> Self {
        let dhs_pub = PublicKey::from(&StaticSecret::from(own_dh_secret)).to_bytes();
        Self {
            dhs_secret: own_dh_secret,
            dhs_pub,
            dhr: None,
            rk: sk,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: VecDeque::new(),
        }
    }

    /// Заголовок, с которым уйдёт следующее сообщение.
    pub fn next_header(&self) -> RatchetHeader {
        RatchetHeader {
            dh_pub: self.dhs_pub,
            pn: self.pn,
            n: self.ns,
        }
    }

    /// Можем ли мы отправлять (у ответчика цепочка появляется после первого входящего).
    pub fn can_send(&self) -> bool {
        self.cks.is_some()
    }

    /// Зашифровать следующее сообщение. `aad` должен включать
    /// [`next_header`](Self::next_header) (в составе заголовка конверта).
    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let ck = self.cks.ok_or(CryptoError::NoSession)?;
        let (next_ck, mk) = kdf_ck(&ck);
        let body = aead_seal(&mk, plaintext, aad);
        self.cks = Some(next_ck);
        self.ns = self.ns.checked_add(1).ok_or(CryptoError::NoSession)?;
        Ok(body)
    }

    /// Расшифровать сообщение. При любой ошибке состояние не меняется.
    pub fn decrypt(
        &mut self,
        header: &RatchetHeader,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut st = self.clone();
        let plaintext = st.decrypt_inner(header, ciphertext, aad)?;
        *self = st;
        Ok(plaintext)
    }

    fn decrypt_inner(
        &mut self,
        header: &RatchetHeader,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        // 1. Это сообщение мы уже «перепрыгнули» раньше?
        if let Some(pos) = self
            .skipped
            .iter()
            .position(|k| k.dh == header.dh_pub && k.n == header.n)
        {
            let mk = self.skipped[pos].mk;
            let pt = aead_open(&mk, ciphertext, aad)?;
            self.skipped.remove(pos);
            return Ok(pt);
        }

        // 2. Собеседник сменил ratchet-ключ — делаем DH-шаг.
        if self.dhr != Some(header.dh_pub) {
            self.skip_until(header.pn)?;
            self.dh_ratchet(&header.dh_pub)?;
        }

        // 3. Дошагать по цепочке до нужного номера и открыть.
        self.skip_until(header.n)?;
        let ck = self.ckr.ok_or(CryptoError::DecryptFailed)?;
        let (next_ck, mk) = kdf_ck(&ck);
        let pt = aead_open(&mk, ciphertext, aad)?;
        self.ckr = Some(next_ck);
        self.nr = self.nr.checked_add(1).ok_or(CryptoError::DecryptFailed)?;
        Ok(pt)
    }

    fn skip_until(&mut self, until: u32) -> Result<(), CryptoError> {
        if until < self.nr {
            // Старый номер, ключа для которого нет: повтор или уже прочитанное.
            return Ok(());
        }
        if until - self.nr > MAX_SKIP {
            return Err(CryptoError::TooManySkipped);
        }
        let (Some(mut ck), Some(dhr)) = (self.ckr, self.dhr) else {
            return Ok(());
        };
        while self.nr < until {
            let (next_ck, mk) = kdf_ck(&ck);
            self.skipped.push_back(SkippedKey {
                dh: dhr,
                n: self.nr,
                mk,
            });
            if self.skipped.len() > MAX_SKIPPED_KEYS {
                self.skipped.pop_front();
            }
            ck = next_ck;
            self.nr += 1;
        }
        self.ckr = Some(ck);
        Ok(())
    }

    fn dh_ratchet(&mut self, remote: &[u8; 32]) -> Result<(), CryptoError> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(*remote);
        let (rk, ckr) = kdf_rk(&self.rk, &dh(&self.dhs_secret, remote)?);
        self.rk = rk;
        self.ckr = Some(ckr);
        let (secret, public) = generate_dh();
        self.dhs_secret = secret;
        self.dhs_pub = public;
        let (rk, cks) = kdf_rk(&self.rk, &dh(&self.dhs_secret, remote)?);
        self.rk = rk;
        self.cks = Some(cks);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn skipped_len(&self) -> usize {
        self.skipped.len()
    }
}

fn generate_dh() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret).to_bytes();
    (secret.to_bytes(), public)
}

/// X25519 с проверкой на «слабую» точку.
pub(crate) fn dh(secret: &[u8; 32], public: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let shared = StaticSecret::from(*secret).diffie_hellman(&PublicKey::from(*public));
    if !shared.was_contributory() {
        return Err(CryptoError::InvalidPeerKey);
    }
    Ok(shared.to_bytes())
}

fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut out = [0u8; 64];
    Hkdf::<Sha256>::new(Some(rk), dh_out)
        .expand(INFO_RK, &mut out)
        .expect("64 bytes is a valid HKDF-SHA256 output length");
    let (a, b) = out.split_at(32);
    (a.try_into().unwrap(), b.try_into().unwrap())
}

/// Шаг симметричной цепочки: (следующий ключ цепочки, ключ сообщения).
fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let step = |byte: u8| -> [u8; 32] {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(ck).expect("HMAC accepts any key length");
        mac.update(&[byte]);
        mac.finalize().into_bytes().into()
    };
    (step(0x02), step(0x01))
}

/// Из ключа сообщения — ключ и nonce для ChaCha20-Poly1305. Ключ сообщения
/// используется ровно один раз, поэтому детерминированный nonce безопасен.
fn message_cipher(mk: &[u8; 32]) -> (ChaCha20Poly1305, [u8; 12]) {
    let mut out = [0u8; 44];
    Hkdf::<Sha256>::new(Some(&[0u8; 32]), mk)
        .expand(INFO_MSG, &mut out)
        .expect("44 bytes is a valid HKDF-SHA256 output length");
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&out[..32]));
    (cipher, out[32..].try_into().unwrap())
}

fn aead_seal(mk: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let (cipher, nonce) = message_cipher(mk);
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("ChaCha20-Poly1305 encryption cannot fail for in-memory buffers")
}

fn aead_open(mk: &[u8; 32], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let (cipher, nonce) = message_cipher(mk);
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Пара сессий Алиса/Боб, как после X3DH.
    fn pair() -> (Ratchet, Ratchet) {
        let sk = [7u8; 32];
        let (bob_secret, bob_pub) = generate_dh();
        let alice = Ratchet::init_initiator(sk, bob_pub).unwrap();
        let bob = Ratchet::init_responder(sk, bob_secret);
        (alice, bob)
    }

    fn send(from: &mut Ratchet, text: &str) -> (RatchetHeader, Vec<u8>) {
        let h = from.next_header();
        let aad = header_aad(&h);
        (h, from.encrypt(text.as_bytes(), &aad).unwrap())
    }

    fn recv(to: &mut Ratchet, msg: &(RatchetHeader, Vec<u8>)) -> Result<String, CryptoError> {
        to.decrypt(&msg.0, &msg.1, &header_aad(&msg.0))
            .map(|p| String::from_utf8(p).unwrap())
    }

    fn header_aad(h: &RatchetHeader) -> Vec<u8> {
        protocol::envelope_header_bytes("a", "b", None, h)
    }

    #[test]
    fn ping_pong() {
        let (mut a, mut b) = pair();
        assert!(!b.can_send());
        for i in 0..5 {
            let m = send(&mut a, &format!("a{i}"));
            assert_eq!(recv(&mut b, &m).unwrap(), format!("a{i}"));
            let m = send(&mut b, &format!("b{i}"));
            assert_eq!(recv(&mut a, &m).unwrap(), format!("b{i}"));
        }
    }

    #[test]
    fn ratchet_key_changes_on_every_turn() {
        let (mut a, mut b) = pair();
        let m1 = send(&mut a, "1");
        let m2 = send(&mut a, "2");
        assert_eq!(m1.0.dh_pub, m2.0.dh_pub, "same chain while one side talks");
        recv(&mut b, &m1).unwrap();
        recv(&mut b, &m2).unwrap();
        let r = send(&mut b, "r");
        recv(&mut a, &r).unwrap();
        let m3 = send(&mut a, "3");
        assert_ne!(m3.0.dh_pub, m1.0.dh_pub, "new DH key after a reply");
        assert_eq!(m3.0.pn, 2);
    }

    #[test]
    fn out_of_order_and_lost_messages() {
        let (mut a, mut b) = pair();
        let msgs: Vec<_> = (0..6).map(|i| send(&mut a, &i.to_string())).collect();
        // 5, 1, 3 приходят; 0, 2, 4 — позже, а один так и теряется.
        assert_eq!(recv(&mut b, &msgs[5]).unwrap(), "5");
        assert_eq!(recv(&mut b, &msgs[1]).unwrap(), "1");
        assert_eq!(recv(&mut b, &msgs[3]).unwrap(), "3");
        assert_eq!(b.skipped_len(), 3);

        // Смена говорящего посреди пропусков.
        let r = send(&mut b, "reply");
        assert_eq!(recv(&mut a, &r).unwrap(), "reply");
        let late = send(&mut a, "after reply");
        assert_eq!(recv(&mut b, &late).unwrap(), "after reply");

        assert_eq!(recv(&mut b, &msgs[0]).unwrap(), "0");
        assert_eq!(recv(&mut b, &msgs[4]).unwrap(), "4");
        assert_eq!(b.skipped_len(), 1, "msg 2 is still missing");
    }

    #[test]
    fn replayed_message_does_not_decrypt_twice() {
        let (mut a, mut b) = pair();
        let m = send(&mut a, "once");
        recv(&mut b, &m).unwrap();
        assert_eq!(recv(&mut b, &m), Err(CryptoError::DecryptFailed));
        // И сессия после этого жива.
        let m2 = send(&mut a, "still works");
        assert_eq!(recv(&mut b, &m2).unwrap(), "still works");
    }

    #[test]
    fn tampering_leaves_state_untouched() {
        let (mut a, mut b) = pair();
        let mut m = send(&mut a, "x");
        m.1[0] ^= 1;
        assert_eq!(recv(&mut b, &m), Err(CryptoError::DecryptFailed));
        m.1[0] ^= 1;
        assert_eq!(recv(&mut b, &m).unwrap(), "x");

        // Подменённый заголовок ловится, потому что он входит в AAD.
        let m = send(&mut a, "y");
        for forged in [
            RatchetHeader {
                pn: m.0.pn + 1,
                ..m.0
            },
            RatchetHeader {
                n: m.0.n + 1,
                ..m.0
            },
        ] {
            assert!(b.decrypt(&forged, &m.1, &header_aad(&forged)).is_err());
            assert!(b.decrypt(&m.0, &m.1, &header_aad(&forged)).is_err());
        }
        assert_eq!(recv(&mut b, &m).unwrap(), "y");
    }

    #[test]
    fn huge_skip_is_rejected() {
        let (mut a, mut b) = pair();
        let mut m = send(&mut a, "x");
        m.0.n = MAX_SKIP + 5;
        assert_eq!(
            b.decrypt(&m.0, &m.1, &header_aad(&m.0)),
            Err(CryptoError::TooManySkipped)
        );
    }

    #[test]
    fn stolen_state_stops_working_after_a_round_trip() {
        // Восстановление после компрометации. Вор скопировал состояние Боба и
        // дальше пассивно получает всё, что приходит Бобу. Пока Боб не сгенерирует
        // новый ratchet-ключ, вор читает переписку; после круга обмена — уже нет.
        let (mut a, mut b) = pair();
        recv(&mut b, &send(&mut a, "hi")).unwrap();
        let mut thief = b.clone();

        recv(&mut a, &send(&mut b, "reply")).unwrap();
        let ping = send(&mut a, "ping");
        assert_eq!(recv(&mut b, &ping).unwrap(), "ping");
        assert_eq!(recv(&mut thief, &ping).unwrap(), "ping", "not healed yet");

        // Боб отвечает уже с новым ключом, которого у вора нет.
        let pong = send(&mut b, "pong");
        assert!(recv(&mut thief.clone(), &pong).is_err());
        recv(&mut a, &pong).unwrap();

        let secret = send(&mut a, "secret after healing");
        assert!(recv(&mut thief, &secret).is_err());
        assert_eq!(recv(&mut b, &secret).unwrap(), "secret after healing");
    }

    #[test]
    fn used_keys_are_forgotten() {
        // Прямая секретность: после расшифровки ключ сообщения нигде не хранится.
        let (mut a, mut b) = pair();
        let m = send(&mut a, "gone");
        recv(&mut b, &m).unwrap();
        let state = serde_json::to_string(&b).unwrap();
        let again =
            serde_json::from_str::<Ratchet>(&state)
                .unwrap()
                .decrypt(&m.0, &m.1, &header_aad(&m.0));
        assert!(again.is_err());
    }

    #[test]
    fn state_survives_serialization() {
        let (mut a, mut b) = pair();
        recv(&mut b, &send(&mut a, "1")).unwrap();
        let mut b: Ratchet = serde_json::from_str(&serde_json::to_string(&b).unwrap()).unwrap();
        let mut a: Ratchet = serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
        recv(&mut a, &send(&mut b, "2")).unwrap();
        assert_eq!(recv(&mut b, &send(&mut a, "3")).unwrap(), "3");
    }
}
