use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use crypto_core::Identity;
use storage::{Db, IdentityRow};
use uuid::Uuid;

fn main() -> anyhow::Result<()> {
    let (db, path) = Db::open_default("messenger")?;
    println!("DB: {:?}", path);

    // Пытаемся загрузить существующую identity (одна на устройство)
    let identity = match db.get_local_identity()? {
        Some(row) => {
            println!(
                "Loaded identity: account_id={}, username={:?}",
                row.account_id, row.username
            );
            Identity::from_secret_bytes(row.account_id, row.secret)
        }
        None => {
            println!("No identity found. Generating new...");

            let account_id = Uuid::new_v4().to_string(); // внутренний ID
            let id = Identity::generate(&account_id);

            let row = IdentityRow {
                account_id,
                username: None, // потом зададим @username
                secret: id.secret_bytes(),
                public: id.public_bytes(),
            };

            db.upsert_identity(&row)?;
            id
        }
    };

    let pub_b64 = STANDARD_NO_PAD.encode(identity.public_bytes());
    println!("PublicKey (base64): {}", pub_b64);
    println!("AccountId (UUID):   {}", identity.user_id.0);

    Ok(())
}