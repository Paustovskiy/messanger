use crypto_core::Identity;
use protocol::UserId;

#[test]
fn alice_bob_roundtrip() {
    let alice = Identity::generate("alice");
    let bob = Identity::generate("bob");

    let env = alice.encrypt_to(&bob.x_public, UserId("bob".into()), b"hello bob");
    let p1 = bob.decrypt(&env).expect("bob decrypt");
    assert_eq!(p1, b"hello bob");

    let env2 = bob.encrypt_to(&alice.x_public, UserId("alice".into()), b"hello alice");
    let p2 = alice.decrypt(&env2).expect("alice decrypt");
    assert_eq!(p2, b"hello alice");
}