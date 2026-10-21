use crypto_core::{CryptoError, Identity, verify_contact_card, verify_envelope};
use protocol::{Envelope, EnvelopeB64, MAX_PLAINTEXT_LEN};

fn pair() -> (Identity, Identity) {
    (Identity::generate("alice"), Identity::generate("bob"))
}

#[test]
fn alice_bob_roundtrip() {
    let (alice, bob) = pair();

    let env = alice
        .encrypt_to("bob", &bob.x_public_bytes(), b"hello bob")
        .unwrap();
    assert_eq!(
        bob.decrypt(&env, &alice.sign_public_bytes()).unwrap(),
        b"hello bob"
    );

    let env = bob
        .encrypt_to("alice", &alice.x_public_bytes(), b"hello alice")
        .unwrap();
    assert_eq!(
        alice.decrypt(&env, &bob.sign_public_bytes()).unwrap(),
        b"hello alice"
    );
}

#[test]
fn roundtrip_through_json_wire_format() {
    let (alice, bob) = pair();
    let env = alice
        .encrypt_to("bob", &bob.x_public_bytes(), "привет 👋".as_bytes())
        .unwrap();

    let json = serde_json::to_string(&EnvelopeB64::from(&env)).unwrap();
    let back = Envelope::try_from(serde_json::from_str::<EnvelopeB64>(&json).unwrap()).unwrap();

    let pt = bob.decrypt(&back, &alice.sign_public_bytes()).unwrap();
    assert_eq!(String::from_utf8(pt).unwrap(), "привет 👋");
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
fn every_encryption_is_unique() {
    let (alice, bob) = pair();
    let a = alice
        .encrypt_to("bob", &bob.x_public_bytes(), b"same")
        .unwrap();
    let b = alice
        .encrypt_to("bob", &bob.x_public_bytes(), b"same")
        .unwrap();
    assert_ne!(a.eph_pub, b.eph_pub);
    assert_ne!(a.body, b.body);
}

#[test]
fn tampered_body_is_rejected() {
    let (alice, bob) = pair();
    let mut env = alice
        .encrypt_to("bob", &bob.x_public_bytes(), b"pay 10")
        .unwrap();
    env.body[0] ^= 0x01;
    assert_eq!(
        bob.decrypt(&env, &alice.sign_public_bytes()),
        Err(CryptoError::BadSignature)
    );
}

#[test]
fn signature_from_someone_else_is_rejected() {
    let (alice, bob) = pair();
    let mallory = Identity::generate("mallory");
    let env = mallory
        .encrypt_to("bob", &bob.x_public_bytes(), b"I am alice")
        .unwrap();
    // Боб проверяет ключом Алисы из своей базы — подпись не сходится.
    assert_eq!(
        bob.decrypt(&env, &alice.sign_public_bytes()),
        Err(CryptoError::BadSignature)
    );
}

#[test]
fn resigned_envelope_with_forged_sender_does_not_decrypt() {
    // Мэллори перехватила конверт Алисы, поменяла `from` на себя и подписала своим ключом.
    // Подпись валидна, но заголовок привязан к шифротексту через AAD.
    let (alice, bob) = pair();
    let mallory = Identity::generate("mallory");
    let mut env = alice
        .encrypt_to("bob", &bob.x_public_bytes(), b"secret")
        .unwrap();
    env.from = "mallory".into();
    env.sig = mallory.sign(&env.signing_bytes());

    assert!(verify_envelope(&env, &mallory.sign_public_bytes()).is_ok());
    assert_eq!(
        bob.decrypt(&env, &mallory.sign_public_bytes()),
        Err(CryptoError::DecryptFailed)
    );
}

#[test]
fn envelope_for_someone_else_is_rejected() {
    let (alice, bob) = pair();
    let carol = Identity::generate("carol");
    let env = alice
        .encrypt_to("carol", &carol.x_public_bytes(), b"hi carol")
        .unwrap();
    assert_eq!(
        bob.decrypt(&env, &alice.sign_public_bytes()),
        Err(CryptoError::WrongRecipient("carol".into()))
    );
}

#[test]
fn low_order_peer_key_is_rejected() {
    let alice = Identity::generate("alice");
    assert_eq!(
        alice.encrypt_to("bob", &[0u8; 32], b"x").unwrap_err(),
        CryptoError::InvalidPeerKey
    );
}

#[test]
fn oversized_message_is_rejected() {
    let (alice, bob) = pair();
    let big = vec![0u8; MAX_PLAINTEXT_LEN + 1];
    assert_eq!(
        alice
            .encrypt_to("bob", &bob.x_public_bytes(), &big)
            .unwrap_err(),
        CryptoError::MessageTooLarge(MAX_PLAINTEXT_LEN + 1)
    );
    assert!(
        alice
            .encrypt_to("bob", &bob.x_public_bytes(), &big[..MAX_PLAINTEXT_LEN])
            .is_ok()
    );
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
fn envelope_id_is_stable_and_unique() {
    let (alice, bob) = pair();
    let a = alice
        .encrypt_to("bob", &bob.x_public_bytes(), b"x")
        .unwrap();
    let b = alice
        .encrypt_to("bob", &bob.x_public_bytes(), b"x")
        .unwrap();
    assert_eq!(
        crypto_core::envelope_id(&a),
        crypto_core::envelope_id(&a.clone())
    );
    assert_ne!(crypto_core::envelope_id(&a), crypto_core::envelope_id(&b));
    assert_eq!(crypto_core::envelope_id(&a).len(), 32);
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

    // Старые UUID и тестовые имена — не «из ключа».
    assert!(!crypto_core::is_key_derived_account_id(
        "2d723969-b478-4ff4-af0a-477541df0441"
    ));
    assert!(!crypto_core::is_key_derived_account_id("alice"));
}

#[test]
fn card_cannot_claim_someone_elses_derived_id() {
    let alice = Identity::generate_new();
    let mallory = Identity::generate_new();
    // Мэллори делает карточку с ID Алисы, но своими ключами и своей подписью.
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
