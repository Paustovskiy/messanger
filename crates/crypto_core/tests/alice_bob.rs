//! Сессии целиком: X3DH + Double Ratchet + подписи, как их видит приложение.

use crypto_core::{
    Bundle, CryptoError, Identity, PeerKeys, PrekeySecrets, SessionSet, new_one_time_prekey,
    verify_contact_card, verify_envelope,
};
use protocol::{Envelope, EnvelopeB64, MAX_PLAINTEXT_LEN, SignedPrekey};
use std::collections::{HashMap, HashSet};

/// Участник со всем, что клиент хранит в базе.
struct Party {
    id: Identity,
    spk_id: u32,
    spk_secrets: HashMap<u32, [u8; 32]>,
    spk_public: SignedPrekey,
    opks: HashMap<u32, ([u8; 32], protocol::OneTimePrekey)>,
    used_eks: HashSet<[u8; 32]>,
    /// Сессии по (аккаунт, устройство) собеседника.
    sessions: HashMap<String, SessionSet>,
}

/// Ключ сессии в тестах: «аккаунт/устройство».
fn sk(p: &Party) -> String {
    format!("{}/{}", p.id.account_id(), p.id.device_id())
}

impl Party {
    fn new(name: &str) -> Self {
        Self::with_identity(Identity::generate(name))
    }

    fn with_identity(id: Identity) -> Self {
        let (secret, spk) = id.new_signed_prekey(1);
        let opks = (100..105).map(|i| (i, new_one_time_prekey(i))).collect();
        Self {
            id,
            spk_id: 1,
            spk_secrets: HashMap::from([(1, secret)]),
            spk_public: spk,
            opks,
            used_eks: HashSet::new(),
            sessions: HashMap::new(),
        }
    }

    fn keys(&self) -> PeerKeys {
        PeerKeys {
            account_id: self.id.account_id().into(),
            device_id: self.id.device_id(),
            x25519_pub: self.id.x_public_bytes(),
            ed25519_pub: self.id.sign_public_bytes(),
        }
    }

    /// То, что выдал бы релей (одноразовый ключ «уходит» с релея).
    fn bundle(&mut self, with_opk: bool) -> Bundle {
        let one_time = if with_opk {
            let id = *self.opks.keys().min().unwrap();
            Some(self.opks[&id].1)
        } else {
            None
        };
        Bundle {
            signed_prekey: self.spk_public,
            one_time,
        }
    }

    fn rotate_spk(&mut self) {
        self.spk_id += 1;
        let (secret, spk) = self.id.new_signed_prekey(self.spk_id);
        self.spk_secrets.insert(self.spk_id, secret);
        self.spk_public = spk;
    }

    fn start(&mut self, peer: &mut Party, with_opk: bool) {
        let bundle = peer.bundle(with_opk);
        let set = self.sessions.entry(sk(peer)).or_default();
        self.id.start_session(&peer.keys(), &bundle, set).unwrap();
    }

    fn send(&mut self, to: &Party, text: &str) -> Envelope {
        let set = self.sessions.get_mut(&sk(to)).expect("no session");
        let env = self.id.seal(&to.keys(), set, text.as_bytes()).unwrap();
        // По сети конверт идёт как JSON.
        let json = serde_json::to_string(&EnvelopeB64::from(&env)).unwrap();
        Envelope::try_from(serde_json::from_str::<EnvelopeB64>(&json).unwrap()).unwrap()
    }

    fn recv(&mut self, from: &Party, env: &Envelope) -> Result<String, CryptoError> {
        let secrets = match env.prekey {
            None => PrekeySecrets::default(),
            Some(p) => PrekeySecrets {
                signed_prekey: self.spk_secrets.get(&p.spk_id).copied(),
                one_time: p.opk_id.and_then(|id| self.opks.get(&id).map(|k| k.0)),
                ek_already_used: self.used_eks.contains(&p.ek_pub),
            },
        };
        // Как в приложении: работаем с копией и сохраняем только при успехе.
        let mut set = self.sessions.get(&sk(from)).cloned().unwrap_or_default();
        let opened = self.id.open(&from.keys(), &mut set, env, &secrets)?;
        if let Some(ek) = opened.new_session_ek {
            self.used_eks.insert(ek);
        }
        if let Some(id) = opened.consumed_one_time {
            self.opks.remove(&id);
        }
        // Сохраняем через JSON — ровно как в базе.
        let set = SessionSet::from_json(&set.to_json()).unwrap();
        self.sessions.insert(sk(from), set);
        Ok(String::from_utf8(opened.plaintext).unwrap())
    }
}

fn pair() -> (Party, Party) {
    (Party::new("alice"), Party::new("bob"))
}

#[test]
fn first_contact_with_and_without_one_time_prekey() {
    for with_opk in [true, false] {
        let (mut alice, mut bob) = pair();
        alice.start(&mut bob, with_opk);

        let m = alice.send(&bob, "привет, Боб");
        let pk = m.prekey.expect("first message carries X3DH header");
        assert_eq!(pk.opk_id.is_some(), with_opk);
        assert_eq!(bob.recv(&alice, &m).unwrap(), "привет, Боб");
        assert_eq!(
            bob.opks.len(),
            if with_opk { 4 } else { 5 },
            "used OPK is deleted"
        );

        let r = bob.send(&alice, "привет, Алиса");
        assert!(r.prekey.is_none());
        assert_eq!(alice.recv(&bob, &r).unwrap(), "привет, Алиса");

        // После ответа X3DH-заголовок больше не прикладывается.
        let m = alice.send(&bob, "как дела?");
        assert!(m.prekey.is_none());
        assert_eq!(bob.recv(&alice, &m).unwrap(), "как дела?");
    }
}

#[test]
fn long_conversation() {
    let (mut alice, mut bob) = pair();
    alice.start(&mut bob, true);
    for i in 0..50 {
        let m = alice.send(&bob, &format!("a{i}"));
        assert_eq!(bob.recv(&alice, &m).unwrap(), format!("a{i}"));
        if i % 3 == 0 {
            let r = bob.send(&alice, &format!("b{i}"));
            assert_eq!(alice.recv(&bob, &r).unwrap(), format!("b{i}"));
        }
    }
}

#[test]
fn several_messages_before_reply_arrive_out_of_order() {
    let (mut alice, mut bob) = pair();
    alice.start(&mut bob, true);
    let msgs: Vec<_> = (0..4).map(|i| alice.send(&bob, &i.to_string())).collect();
    // Пока Боб офлайн, все сообщения несут один и тот же X3DH-заголовок.
    assert!(msgs.iter().all(|m| m.prekey == msgs[0].prekey));

    assert_eq!(bob.recv(&alice, &msgs[2]).unwrap(), "2");
    assert_eq!(bob.recv(&alice, &msgs[0]).unwrap(), "0");
    assert_eq!(bob.recv(&alice, &msgs[3]).unwrap(), "3");
    assert_eq!(bob.recv(&alice, &msgs[1]).unwrap(), "1");
    assert_eq!(
        bob.sessions["alice/1"].len(),
        1,
        "all four belong to one session"
    );
}

#[test]
fn replayed_first_message_is_rejected() {
    let (mut alice, mut bob) = pair();
    alice.start(&mut bob, false); // без OPK — самый уязвимый к повтору случай
    let first = alice.send(&bob, "hi");
    bob.recv(&alice, &first).unwrap();
    assert_eq!(bob.recv(&alice, &first), Err(CryptoError::Replay));

    // Даже если сессия давно вытеснена из памяти.
    bob.sessions.clear();
    assert_eq!(bob.recv(&alice, &first), Err(CryptoError::Replay));
}

#[test]
fn reused_one_time_prekey_is_rejected() {
    let (mut alice, mut bob) = pair();
    let mut carol = Party::new("carol");
    let bundle = bob.bundle(true);
    for p in [&mut alice, &mut carol] {
        let set = p.sessions.entry("bob/1".into()).or_default();
        p.id.start_session(&bob.keys(), &bundle, set).unwrap();
    }
    let from_alice = alice.send(&bob, "a");
    let from_carol = carol.send(&bob, "c");
    bob.recv(&alice, &from_alice).unwrap();
    // Релей должен был отдать OPK только одному; второй, получивший тот же, получит отказ.
    assert_eq!(
        bob.recv(&carol, &from_carol),
        Err(CryptoError::UnknownPrekey)
    );
}

#[test]
fn rotated_signed_prekey_still_works_for_queued_messages() {
    let (mut alice, mut bob) = pair();
    alice.start(&mut bob, false);
    let queued = alice.send(&bob, "лежало на релее");
    bob.rotate_spk();
    assert_eq!(bob.recv(&alice, &queued).unwrap(), "лежало на релее");

    // А если старый предключ уже удалён — честная ошибка.
    let (mut alice, mut bob) = pair();
    alice.start(&mut bob, false);
    let queued = alice.send(&bob, "слишком старое");
    bob.spk_secrets.remove(&1);
    assert_eq!(bob.recv(&alice, &queued), Err(CryptoError::UnknownPrekey));
}

#[test]
fn substituted_prekey_is_detected() {
    // Злой релей подсовывает свой предключ вместо предключа Боба.
    let (alice, mut bob) = pair();
    let mallory = Identity::generate("mallory");
    let (_, fake) = mallory.new_signed_prekey(1);
    let mut bundle = bob.bundle(true);
    bundle.signed_prekey = fake;
    let mut set = SessionSet::default();
    assert_eq!(
        alice.id.start_session(&bob.keys(), &bundle, &mut set),
        Err(CryptoError::BadSignature)
    );
    assert!(set.is_empty());
}

#[test]
fn simultaneous_start_converges() {
    // Оба начали переписку, не дождавшись друг друга — в любом порядке доставки.
    for alice_reads_first in [true, false] {
        simultaneous_case(alice_reads_first);
    }
}

fn simultaneous_case(alice_reads_first: bool) {
    let (mut alice, mut bob) = pair();
    alice.start(&mut bob, true);
    bob.start(&mut alice, true);
    let a1 = alice.send(&bob, "a1");
    let b1 = bob.send(&alice, "b1");
    if alice_reads_first {
        assert_eq!(alice.recv(&bob, &b1).unwrap(), "b1");
        assert_eq!(bob.recv(&alice, &a1).unwrap(), "a1");
    } else {
        assert_eq!(bob.recv(&alice, &a1).unwrap(), "a1");
        assert_eq!(alice.recv(&bob, &b1).unwrap(), "b1");
    }

    // Дальше переписка идёт нормально в обе стороны.
    for i in 0..5 {
        let m = alice.send(&bob, &format!("a{i}"));
        assert_eq!(bob.recv(&alice, &m).unwrap(), format!("a{i}"));
        let m = bob.send(&alice, &format!("b{i}"));
        assert_eq!(alice.recv(&bob, &m).unwrap(), format!("b{i}"));
    }
    // И обе стороны пишут через одну и ту же сессию: X3DH-заголовки исчезли.
    assert!(alice.send(&bob, "x").prekey.is_none());
    assert!(bob.send(&alice, "y").prekey.is_none());
}

#[test]
fn simultaneous_start_when_one_first_message_is_lost() {
    let (mut alice, mut bob) = pair();
    alice.start(&mut bob, true);
    bob.start(&mut alice, true);
    let _lost = alice.send(&bob, "a1 (lost)");
    let b1 = bob.send(&alice, "b1");
    assert_eq!(alice.recv(&bob, &b1).unwrap(), "b1");
    // Алиса продолжает писать, Боб отвечает — переписка налаживается.
    let a2 = alice.send(&bob, "a2");
    assert_eq!(bob.recv(&alice, &a2).unwrap(), "a2");
    let b2 = bob.send(&alice, "b2");
    assert_eq!(alice.recv(&bob, &b2).unwrap(), "b2");
    let a3 = alice.send(&bob, "a3");
    assert_eq!(bob.recv(&alice, &a3).unwrap(), "a3");
}

#[test]
fn new_session_after_peer_lost_state() {
    // Алиса переустановила клиент и начала новую сессию; Боб принимает и её,
    // и запоздавшие сообщения старой.
    let (mut alice, mut bob) = pair();
    alice.start(&mut bob, true);
    let old1 = alice.send(&bob, "old 1");
    bob.recv(&alice, &old1).unwrap();
    let late = alice.send(&bob, "old 2 (late)");

    alice.sessions.clear();
    alice.start(&mut bob, true);
    let new = alice.send(&bob, "new");
    assert_eq!(bob.recv(&alice, &new).unwrap(), "new");
    assert_eq!(bob.recv(&alice, &late).unwrap(), "old 2 (late)");

    // Боб отвечает через самую свежую сессию, и Алиса это читает.
    let r = bob.send(&alice, "reply");
    assert_eq!(alice.recv(&bob, &r).unwrap(), "reply");
}

#[test]
fn forged_and_misdirected_envelopes_are_rejected() {
    let (mut alice, mut bob) = pair();
    let mut carol = Party::new("carol");
    alice.start(&mut bob, true);
    let m = alice.send(&bob, "for bob");

    // Чужой получатель.
    assert_eq!(
        carol.recv(&alice, &m),
        Err(CryptoError::WrongRecipient("bob/1".into()))
    );

    // Изменённый шифротекст или заголовок — подпись не сходится.
    let mut tampered = m.clone();
    tampered.body[0] ^= 1;
    assert_eq!(bob.recv(&alice, &tampered), Err(CryptoError::BadSignature));
    let mut tampered = m.clone();
    tampered.header.n += 1;
    assert_eq!(bob.recv(&alice, &tampered), Err(CryptoError::BadSignature));

    // Мэллори переподписала конверт Алисы от своего имени: подпись верна,
    // но заголовок привязан к шифротексту, и X3DH не сходится.
    let mallory = Party::new("mallory");
    let mut stolen = m.clone();
    stolen.from = "mallory".into();
    stolen.sig = mallory.id.sign(&stolen.signing_bytes());
    assert!(verify_envelope(&stolen, &mallory.id.sign_public_bytes()).is_ok());
    assert!(bob.recv(&mallory, &stolen).is_err());

    // Сессия Боба с Алисой от всего этого не пострадала.
    assert_eq!(bob.recv(&alice, &m).unwrap(), "for bob");
}

#[test]
fn no_session_and_limits() {
    let (mut alice, bob) = pair();
    let mut empty = SessionSet::default();
    assert_eq!(
        alice.id.seal(&bob.keys(), &mut empty, b"x").unwrap_err(),
        CryptoError::NoSession
    );

    let mut bob = bob;
    alice.start(&mut bob, true);
    let set = alice.sessions.get_mut("bob/1").unwrap();
    let big = vec![0u8; MAX_PLAINTEXT_LEN + 1];
    assert_eq!(
        alice.id.seal(&bob.keys(), set, &big).unwrap_err(),
        CryptoError::MessageTooLarge(MAX_PLAINTEXT_LEN + 1)
    );
    assert!(
        alice
            .id
            .seal(&bob.keys(), set, &big[..MAX_PLAINTEXT_LEN])
            .is_ok()
    );
}

#[test]
fn session_count_is_bounded() {
    let (mut alice, mut bob) = pair();
    for _ in 0..10 {
        alice.start(&mut bob, false);
    }
    assert_eq!(
        alice.sessions["bob/1"].len(),
        crypto_core::session::MAX_SESSIONS
    );
}

#[test]
fn corrupt_state_is_reported() {
    assert_eq!(
        SessionSet::from_json("{nope").unwrap_err(),
        CryptoError::CorruptState
    );
}

#[test]
fn restored_identity_is_the_same_identity() {
    let alice = Identity::generate("alice");
    let restored =
        Identity::from_secrets("alice", alice.x_secret_bytes(), alice.sign_secret_bytes());
    assert_eq!(restored.x_public_bytes(), alice.x_public_bytes());
    assert_eq!(restored.sign_public_bytes(), alice.sign_public_bytes());
    assert_eq!(restored.fingerprint(), alice.fingerprint());
}

#[test]
fn envelope_id_is_stable_and_unique() {
    let (mut alice, mut bob) = pair();
    alice.start(&mut bob, true);
    let a = alice.send(&bob, "x");
    let b = alice.send(&bob, "x");
    assert_eq!(
        crypto_core::envelope_id(&a),
        crypto_core::envelope_id(&a.clone())
    );
    assert_ne!(crypto_core::envelope_id(&a), crypto_core::envelope_id(&b));
    assert_eq!(crypto_core::envelope_id(&a).len(), 32);
}

#[test]
fn contact_card_verifies_and_detects_tampering() {
    let alice = Identity::generate("alice-id");
    let card = alice.contact_card(Some("@alice".into()));

    let v = verify_contact_card(&card).unwrap();
    assert_eq!(v.account_id, "alice-id");
    assert_eq!(v.username.as_deref(), Some("@alice"));
    assert_eq!(v.x25519_pub, alice.x_public_bytes());
    assert_eq!(v.fingerprint(), alice.fingerprint());

    let mut forged = card.clone();
    forged.username = Some("@bank_support".into());
    assert_eq!(verify_contact_card(&forged), Err(CryptoError::BadSignature));

    let mut forged = card;
    forged.x25519_pub_b64 = protocol::b64(Identity::generate("x").x_public_bytes());
    assert_eq!(verify_contact_card(&forged), Err(CryptoError::BadSignature));
}

#[test]
fn new_accounts_have_key_derived_ids() {
    let a = Identity::generate_new();
    assert!(crypto_core::is_key_derived_account_id(a.account_id()));
    assert_eq!(
        a.account_id(),
        crypto_core::account_id_for(&a.sign_public_bytes())
    );
    assert_ne!(a.account_id(), Identity::generate_new().account_id());

    assert!(!crypto_core::is_key_derived_account_id(
        "2d723969-b478-4ff4-af0a-477541df0441"
    ));
    assert!(!crypto_core::is_key_derived_account_id("alice"));
}

#[test]
fn card_cannot_claim_someone_elses_derived_id() {
    let alice = Identity::generate_new();
    let mallory = Identity::generate_new();
    let payload = protocol::ContactCardPayload {
        account_id: alice.account_id().into(),
        username: Some("@alice".into()),
        x25519_pub: mallory.x_public_bytes(),
        ed25519_pub: mallory.sign_public_bytes(),
    };
    let card =
        protocol::ContactCardV2::from_parts(&payload, mallory.sign(&payload.signing_bytes()));
    assert_eq!(
        verify_contact_card(&card),
        Err(CryptoError::AccountIdMismatch)
    );
    assert!(verify_contact_card(&alice.contact_card(None)).is_ok());
}

#[test]
fn fingerprint_format() {
    let fp = Identity::generate("a").fingerprint();
    assert_eq!(fp.len(), 10 * 4 + 9);
    assert!(
        fp.split(' ')
            .all(|g| g.len() == 4 && g.chars().all(|c| c.is_ascii_hexdigit()))
    );
}

// ---------- Несколько устройств ----------

/// Второе устройство того же аккаунта: свои ключи, общий account_id.
fn second_device(primary: &Identity, device_id: u32) -> Identity {
    Identity::generate(primary.account_id()).with_device(device_id)
}

fn device_list(primary: &Identity, others: &[&Identity], version: u64) -> protocol::DeviceList {
    let mut devices = vec![primary.device_info("ноутбук")];
    devices.extend(
        others
            .iter()
            .map(|d| d.device_info(format!("устройство {}", d.device_id()))),
    );
    protocol::DeviceList {
        account_id: primary.account_id().into(),
        account_pub: primary.sign_public_bytes(),
        version,
        devices,
    }
}

#[test]
fn each_device_has_its_own_session() {
    let mut alice = Party::new("alice");
    let mut bob1 = Party::new("bob");
    let mut bob2 = Party::with_identity(second_device(&bob1.id, 2));

    alice.start(&mut bob1, true);
    alice.start(&mut bob2, true);
    let to1 = alice.send(&bob1, "для ноутбука");
    let to2 = alice.send(&bob2, "для телефона");
    assert_eq!((to1.to_device, to2.to_device), (1, 2));

    // Конверт для одного устройства другое открыть не может.
    assert_eq!(
        bob1.recv(&alice, &to2),
        Err(CryptoError::WrongRecipient("bob/2".into()))
    );
    assert_eq!(bob1.recv(&alice, &to1).unwrap(), "для ноутбука");
    assert_eq!(bob2.recv(&alice, &to2).unwrap(), "для телефона");

    // Оба устройства отвечают, Алиса различает их по номеру.
    let r2 = bob2.send(&alice, "с телефона");
    assert_eq!(r2.from_device, 2);
    assert_eq!(alice.recv(&bob2, &r2).unwrap(), "с телефона");
    // Подменить номер устройства отправителя нельзя: он под подписью.
    let r1 = bob1.send(&alice, "с ноутбука");
    let mut spoofed = r1.clone();
    spoofed.from_device = 2;
    assert_eq!(alice.recv(&bob2, &spoofed), Err(CryptoError::BadSignature));
    assert_eq!(alice.recv(&bob1, &r1).unwrap(), "с ноутбука");
}

#[test]
fn devices_of_one_account_talk_to_each_other() {
    // Расшифровки «я отправил» на свои же устройства — обычные сессии внутри аккаунта.
    let mut one = Party::new("me");
    let mut two = Party::with_identity(second_device(&one.id, 2));
    one.start(&mut two, true);
    let m = one.send(&two, "копия");
    assert_eq!(two.recv(&one, &m).unwrap(), "копия");
    let r = two.send(&one, "ок");
    assert_eq!(one.recv(&two, &r).unwrap(), "ок");
}

#[test]
fn simultaneous_start_between_devices_of_one_account() {
    for first in [true, false] {
        let mut one = Party::new("me");
        let mut two = Party::with_identity(second_device(&one.id, 2));
        one.start(&mut two, true);
        two.start(&mut one, true);
        let a = one.send(&two, "a");
        let b = two.send(&one, "b");
        if first {
            assert_eq!(one.recv(&two, &b).unwrap(), "b");
            assert_eq!(two.recv(&one, &a).unwrap(), "a");
        } else {
            assert_eq!(two.recv(&one, &a).unwrap(), "a");
            assert_eq!(one.recv(&two, &b).unwrap(), "b");
        }
        for i in 0..3 {
            let m = one.send(&two, &i.to_string());
            assert_eq!(two.recv(&one, &m).unwrap(), i.to_string());
            let m = two.send(&one, &i.to_string());
            assert_eq!(one.recv(&two, &m).unwrap(), i.to_string());
        }
        assert!(one.send(&two, "x").prekey.is_none());
        assert!(two.send(&one, "y").prekey.is_none());
    }
}

#[test]
fn device_list_signs_and_verifies() {
    let primary = Identity::generate_new();
    let phone = second_device(&primary, 2);
    let list = device_list(&primary, &[&phone], 2);
    let signed = primary.sign_device_list(&list).unwrap();

    // По JSON, как по сети.
    let wire: protocol::SignedDeviceListB64 =
        serde_json::from_str(&serde_json::to_string(&signed).unwrap()).unwrap();
    // Без известного ключа — проверка по ID, выведенному из ключа аккаунта.
    let got = crypto_core::verify_device_list(&wire, primary.account_id(), None).unwrap();
    assert_eq!(got, list);
    assert_eq!(got.device(2).unwrap().x25519_pub, phone.x_public_bytes());
    // С известным ключом — тоже.
    let pk = primary.sign_public_bytes();
    assert!(crypto_core::verify_device_list(&wire, primary.account_id(), Some(&pk)).is_ok());
}

#[test]
fn forged_device_lists_are_rejected() {
    let primary = Identity::generate_new();
    let phone = second_device(&primary, 2);
    let mallory = Identity::generate_new();
    let list = device_list(&primary, &[&phone], 2);
    let signed = primary.sign_device_list(&list).unwrap();

    // Подставить своё устройство в чужой список — подпись не сходится.
    let mut forged = list.clone();
    forged.devices[1].x25519_pub = mallory.x_public_bytes();
    let forged = protocol::SignedDeviceListB64::from_parts(&forged, signed.parts().unwrap().1);
    assert_eq!(
        crypto_core::verify_device_list(&forged, primary.account_id(), None),
        Err(CryptoError::BadSignature)
    );

    // Мэллори подписала список своим ключом от имени чужого аккаунта.
    let mut fake = device_list(&primary, &[], 3);
    fake.account_pub = mallory.sign_public_bytes();
    fake.devices[0].ed25519_pub = mallory.sign_public_bytes();
    let sig = mallory.sign(&fake.signing_bytes());
    let fake = protocol::SignedDeviceListB64::from_parts(&fake, sig);
    assert_eq!(
        crypto_core::verify_device_list(&fake, primary.account_id(), None),
        Err(CryptoError::AccountIdMismatch)
    );
    let pk = primary.sign_public_bytes();
    assert_eq!(
        crypto_core::verify_device_list(&fake, primary.account_id(), Some(&pk)),
        Err(CryptoError::AccountIdMismatch)
    );

    // Список другого аккаунта под чужим ID.
    assert_eq!(
        crypto_core::verify_device_list(&signed, mallory.account_id(), None),
        Err(CryptoError::AccountIdMismatch)
    );

    // Подписать список может только основное устройство.
    let phone_list = device_list(&primary, &[&phone], 3);
    assert_eq!(
        phone.sign_device_list(&phone_list),
        Err(CryptoError::NotAccountKey)
    );
}

#[test]
fn legacy_account_lists_need_a_known_key() {
    // У старых UUID-аккаунтов ID не выведен из ключа: без ключа из карточки — не доверяем.
    let legacy = Identity::generate("2d723969-b478-4ff4-af0a-477541df0441");
    let signed = legacy
        .sign_device_list(&device_list(&legacy, &[], 1))
        .unwrap();
    assert_eq!(
        crypto_core::verify_device_list(&signed, legacy.account_id(), None),
        Err(CryptoError::AccountIdMismatch)
    );
    let pk = legacy.sign_public_bytes();
    assert!(crypto_core::verify_device_list(&signed, legacy.account_id(), Some(&pk)).is_ok());
}

/// Устройство №2 с ключом аккаунта из резервной копии.
fn restored_device(primary: &Identity, device_id: u32) -> Identity {
    Identity::generate(primary.account_id())
        .with_device(device_id)
        .with_account_key(primary.sign_secret_bytes())
}

#[test]
fn account_key_flags() {
    let primary = Identity::generate_new();
    let phone = second_device(&primary, 2);
    assert!(primary.has_account_key());
    assert!(!phone.has_account_key());
    assert_eq!(phone.account_public_bytes(), None);
    assert_eq!(phone.sign_as_account(b"x"), Err(CryptoError::NotAccountKey));
    // У №1 дополнительное поле не нужно, вызов ничего не меняет.
    let same = primary
        .clone()
        .with_account_key(Identity::generate_new().sign_secret_bytes());
    assert_eq!(same.account_public_bytes(), primary.account_public_bytes());
    assert_eq!(same.account_sign_secret_bytes(), None);
    assert_eq!(same.sign(b"m"), primary.sign(b"m"));

    let restored = restored_device(&primary, 2);
    assert!(restored.has_account_key());
    assert_eq!(
        restored.account_public_bytes(),
        Some(primary.sign_public_bytes())
    );
    assert_eq!(
        restored.account_sign_secret_bytes(),
        Some(primary.sign_secret_bytes())
    );
    // Своя подпись устройства осталась своей.
    assert_ne!(restored.sign_public_bytes(), primary.sign_public_bytes());
    let sig = restored.sign_as_account(b"data").unwrap();
    assert!(crypto_core::verify_signature(
        &primary.sign_public_bytes(),
        b"data",
        &sig
    ));
    // Debug не печатает секрет.
    let dbg = format!("{restored:?}");
    assert!(!dbg.contains("account_sign"), "{dbg}");
}

#[test]
fn restored_device_signs_next_list_and_peer_accepts_it() {
    let primary = Identity::generate_new();
    let phone = second_device(&primary, 2);
    let v2 = device_list(&primary, &[&phone], 2);
    primary.sign_device_list(&v2).unwrap();

    // Утрата №1; новое устройство №3 с ключом аккаунта публикует v3.
    let restored = restored_device(&primary, 3);
    let mut v3 = v2.clone();
    v3.version = 3;
    v3.devices.push(restored.device_info("восстановленное"));
    let wire = restored.sign_device_list(&v3).unwrap();

    // Собеседник знает ключ аккаунта по карточке и принимает список.
    let pk = primary.sign_public_bytes();
    let got = crypto_core::verify_device_list(&wire, primary.account_id(), Some(&pk)).unwrap();
    assert_eq!(got, v3);
    assert!(protocol::backup::check_list_update(Some(&v2), &got).is_ok());
    // Подпись настоящая подпись аккаунта: проверяется и без известного ключа.
    assert!(crypto_core::verify_device_list(&wire, primary.account_id(), None).is_ok());
}

#[test]
fn restored_device_cannot_swap_primary_or_roll_back() {
    let primary = Identity::generate_new();
    let phone = second_device(&primary, 2);
    let v2 = device_list(&primary, &[&phone], 2);
    let restored = restored_device(&primary, 3);

    // Подмена записи №1 подписана верно, но правило обновления её отвергает.
    let mut swapped = v2.clone();
    swapped.version = 3;
    swapped.devices[0].x25519_pub = restored.x_public_bytes();
    let wire = restored.sign_device_list(&swapped).unwrap();
    let pk = primary.sign_public_bytes();
    let got = crypto_core::verify_device_list(&wire, primary.account_id(), Some(&pk)).unwrap();
    assert!(protocol::backup::check_list_update(Some(&v2), &got).is_err());

    let mut renamed = v2.clone();
    renamed.version = 3;
    renamed.devices[0].name = "чужое имя".into();
    assert!(protocol::backup::check_list_update(Some(&v2), &renamed).is_err());

    // Откат версии.
    let mut old = v2.clone();
    old.version = 1;
    let wire = restored.sign_device_list(&old).unwrap();
    let got = crypto_core::verify_device_list(&wire, primary.account_id(), Some(&pk)).unwrap();
    assert!(protocol::backup::check_list_update(Some(&v2), &got).is_err());

    // Список чужого аккаунта подписать нельзя.
    let mallory = Identity::generate_new();
    let foreign = device_list(&mallory, &[], 5);
    assert_eq!(
        restored.sign_device_list(&foreign),
        Err(CryptoError::NotAccountKey)
    );
}

#[test]
fn restored_device_card_verifies() {
    let primary = Identity::generate_new();
    let restored = restored_device(&primary, 2);
    let card = restored
        .account_contact_card(Some("@alice".into()), primary.x_public_bytes())
        .unwrap();
    assert!(card.signed_prekey.is_none());
    let v = verify_contact_card(&card).unwrap();
    assert_eq!(v.account_id, primary.account_id());
    assert_eq!(v.ed25519_pub, primary.sign_public_bytes());
    assert_eq!(v.x25519_pub, primary.x_public_bytes());
    assert_eq!(v.fingerprint(), primary.fingerprint());

    // Для №1 то же, что обычная карточка (X25519 берётся свой).
    let own = primary
        .account_contact_card(Some("@alice".into()), [9; 32])
        .unwrap();
    assert_eq!(own, primary.contact_card(Some("@alice".into())));

    // Устройство без ключа аккаунта карточку выпустить не может.
    let phone = second_device(&primary, 3);
    assert_eq!(
        phone.account_contact_card(None, primary.x_public_bytes()),
        Err(CryptoError::NotAccountKey)
    );
}
