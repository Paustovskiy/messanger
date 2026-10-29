//! Устройства аккаунта: свой список, списки собеседников и подключение новых
//! устройств.
//!
//! Каждое устройство — отдельная пара ключей и отдельные сессии. Какие
//! устройства принадлежат аккаунту, говорит список, подписанный ключом
//! аккаунта (это ключ основного устройства, №1, либо копия этого ключа на другом
//! устройстве). Список только растёт по версиям: старый список (например,
//! подсунутый релеем, чтобы вернуть отключённое устройство) не принимается.

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crypto_core::{Identity, PeerKeys, is_key_derived_account_id, verify_device_list};
use protocol::{
    DeviceInfo, DeviceList, PRIMARY_DEVICE, SignedDeviceListB64, SignedPrekeyB64, b64, decode_fixed,
};
use serde::{Deserialize, Serialize};
use storage::{ContactRow, Db};

/// Как называется основное устройство, пока его не переименовали.
pub const PRIMARY_NAME: &str = "основное";

/// Сохранённый (уже проверенный) список устройств аккаунта.
pub fn stored(db: &Db, account_id: &str) -> Result<Option<(DeviceList, SignedDeviceListB64)>> {
    let Some((_, json)) = db.device_list(account_id)? else {
        return Ok(None);
    };
    let wire: SignedDeviceListB64 =
        serde_json::from_str(&json).context("сохранённый список устройств повреждён")?;
    let (list, _) = wire.parts()?;
    Ok(Some((list, wire)))
}

/// Сверить ключ аккаунта на устройстве с тем, что известно о своём аккаунте независимо
/// от этого ключа. Если account_id выводится из ключа (32 hex), он обязан совпасть с
/// ключом: чужой ключ не подойдёт к чужому ID. Старые аккаунты с ID в виде UUID так не
/// проверить (их ID не связан с ключом), для них эта сверка пропускается. Если у
/// устройства уже есть сохранённый свой список, его `account_pub` должен совпасть в
/// любом случае. Иначе база повреждена или подменена, и работать с таким ключом
/// нельзя: подписи вышли бы не тем ключом.
pub fn check_account_key(db: &Db, me: &Identity) -> Result<()> {
    let Some(public) = me.account_public_bytes() else {
        return Ok(());
    };
    if crypto_core::check_account_id(me.account_id(), &public).is_err() {
        bail!(
            "ключ аккаунта на этом устройстве не подходит к account_id {}: база повреждена \
             или ключ из чужой копии; работа остановлена",
            me.account_id()
        );
    }
    if let Some((list, _)) = stored(db, me.account_id())? {
        if list.account_pub != public {
            bail!(
                "ключ аккаунта на этом устройстве не совпадает с ключом в сохранённом списке \
                 устройств; база повреждена или подменена, работа остановлена"
            );
        }
    }
    Ok(())
}

/// Свой список устройств. Основное устройство при первом обращении заводит
/// его само (так обновляются аккаунты, созданные до появления устройств).
pub fn own_list(db: &Db, me: &Identity) -> Result<(DeviceList, SignedDeviceListB64)> {
    if let Some(found) = stored(db, me.account_id())? {
        return Ok(found);
    }
    if me.device_id() != PRIMARY_DEVICE {
        bail!("на этом устройстве нет списка устройств аккаунта — подключите его заново");
    }
    let list = DeviceList {
        account_id: me.account_id().into(),
        account_pub: me.sign_public_bytes(),
        version: 1,
        devices: vec![me.device_info(PRIMARY_NAME)],
    };
    let wire = me.sign_device_list(&list)?;
    db.save_device_list(
        me.account_id(),
        list.version,
        &serde_json::to_string(&wire)?,
    )?;
    Ok((list, wire))
}

/// Ключ аккаунта, которым должен быть подписан его список устройств.
fn account_key(db: &Db, me: &Identity, account_id: &str) -> Result<Option<[u8; 32]>> {
    if account_id == me.account_id() {
        return Ok(Some(match stored(db, account_id)? {
            Some((l, _)) => l.account_pub,
            None => me.sign_public_bytes(),
        }));
    }
    Ok(db.get_contact(account_id)?.and_then(|c| c.sign_public))
}

/// Проверить чужой (или свой) список устройств и сохранить, если он новее.
/// Возвращает `Some(список)`, если сохранённый список изменился.
///
/// Об устройствах, которых в новом списке нет, мы забываем: их сессии и
/// неотправленные им конверты удаляются.
pub fn accept(db: &Db, me: &Identity, wire: &SignedDeviceListB64) -> Result<Option<DeviceList>> {
    let account_id = wire.account_id.as_str();
    let known = account_key(db, me, account_id)?;
    if known.is_none() {
        bail!("список устройств неизвестного аккаунта {account_id}");
    }
    let list = verify_device_list(wire, account_id, known.as_ref())
        .context("список устройств не прошёл проверку подписи")?;
    let old = stored(db, account_id)?;
    if let Some((old, _)) = &old {
        // Старый список (например, из старой карточки) молча пропускаем.
        if old.version > list.version {
            return Ok(None);
        }
        protocol::backup::check_list_update(Some(old), &list)
            .map_err(|e| anyhow::anyhow!("список устройств отклонён: {e}"))?;
    }
    db.immediate(|| {
        if !db.save_device_list(account_id, list.version, &serde_json::to_string(wire)?)? {
            return Ok(None);
        }
        if let Some((old, _)) = &old {
            for d in &old.devices {
                if list.device(d.device_id) != Some(d) {
                    db.delete_device_sessions(account_id, d.device_id)?;
                }
            }
        }
        let keep: Vec<u32> = list.devices.iter().map(|d| d.device_id).collect();
        db.drop_outbox_except(account_id, &keep)?;
        Ok(Some(list.clone()))
    })
}

/// Версия и номер для нового устройства (§4а): список растёт на единицу, а номер не
/// меньше новой версии и больше всех номеров в списке, поэтому номер отключённого
/// устройства никогда не повторится.
pub fn next_device_number(list: &DeviceList) -> Result<(u64, u32)> {
    let version = list
        .version
        .checked_add(1)
        .context("слишком много изменений списка")?;
    let by_version = u32::try_from(version).context("слишком много изменений списка")?;
    let after_max = list
        .devices
        .iter()
        .map(|d| d.device_id)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .context("закончились номера устройств")?;
    Ok((version, by_version.max(after_max)))
}

fn peer(account_id: &str, d: &DeviceInfo) -> PeerKeys {
    PeerKeys {
        account_id: account_id.into(),
        device_id: d.device_id,
        x25519_pub: d.x25519_pub,
        ed25519_pub: d.ed25519_pub,
    }
}

/// Основное устройство контакта по его карточке (если списка устройств нет).
pub fn primary_of(c: &ContactRow) -> Result<PeerKeys> {
    let ed25519_pub = c.sign_public.context(
        "контакт добавлен старой версией без ключа подписи; добавьте его карточку заново",
    )?;
    Ok(PeerKeys {
        account_id: c.account_id.clone(),
        device_id: PRIMARY_DEVICE,
        x25519_pub: c.public,
        ed25519_pub,
    })
}

/// Все устройства собеседника, которым надо отправить сообщение.
pub fn devices_of_contact(db: &Db, c: &ContactRow) -> Result<Vec<PeerKeys>> {
    let primary = primary_of(c)?;
    Ok(match stored(db, &c.account_id)? {
        Some((list, _)) => list
            .devices
            .iter()
            .map(|d| peer(&c.account_id, d))
            .collect(),
        None => vec![primary],
    })
}

/// Остальные устройства своего аккаунта (им идут копии отправленного).
pub fn other_own_devices(db: &Db, me: &Identity) -> Result<Vec<PeerKeys>> {
    let (list, _) = own_list(db, me)?;
    Ok(list
        .devices
        .iter()
        .filter(|d| d.device_id != me.device_id())
        .map(|d| peer(me.account_id(), d))
        .collect())
}

/// Ключи устройства-отправителя. `None` — такого устройства мы не знаем
/// (возможно, наш список устарел — стоит запросить свежий).
pub fn sender_keys(
    db: &Db,
    me: &Identity,
    account_id: &str,
    device_id: u32,
) -> Result<Option<PeerKeys>> {
    if account_id == me.account_id() {
        if device_id == me.device_id() {
            return Ok(None);
        }
        let (list, _) = own_list(db, me)?;
        return Ok(list.device(device_id).map(|d| peer(account_id, d)));
    }
    let Some(c) = db.get_contact(account_id)? else {
        return Ok(None);
    };
    Ok(match stored(db, account_id)? {
        Some((list, _)) => list.device(device_id).map(|d| peer(account_id, d)),
        None if device_id == PRIMARY_DEVICE => Some(primary_of(&c)?),
        None => None,
    })
}

/// Отпечаток аккаунта: по ключам основного устройства. Его собеседники
/// сверяют с тем, что показывает `whoami`.
pub fn account_fingerprint(list: &DeviceList) -> String {
    let primary = list
        .device(PRIMARY_DEVICE)
        .expect("validated list has the primary device");
    crypto_core::fingerprint(&primary.x25519_pub, &list.account_pub)
}

pub fn device_fingerprint(d: &DeviceInfo) -> String {
    crypto_core::fingerprint(&d.x25519_pub, &d.ed25519_pub)
}

// ---------------------------------------------------------------------------
// Подключение нового устройства
// ---------------------------------------------------------------------------

const REQUEST_PREFIX: &str = "mlink1.";
const DOMAIN_LINK_RESPONSE: &[u8] = b"messenger/link-response/v1";

/// Запрос на подключение: публичные ключи нового устройства.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkRequest {
    pub name: String,
    pub x25519_pub_b64: String,
    pub ed25519_pub_b64: String,
}

impl LinkRequest {
    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(self).expect("serializable");
        format!("{REQUEST_PREFIX}{}", URL_SAFE_NO_PAD.encode(json))
    }

    pub fn decode(code: &str) -> Result<Self> {
        let raw = code
            .trim()
            .strip_prefix(REQUEST_PREFIX)
            .context("это не код подключения устройства (он начинается с mlink1.)")?;
        let json = URL_SAFE_NO_PAD
            .decode(raw)
            .context("код подключения повреждён")?;
        serde_json::from_slice(&json).context("код подключения повреждён")
    }

    pub fn keys(&self) -> Result<([u8; 32], [u8; 32])> {
        Ok((
            decode_fixed::<32>(&self.x25519_pub_b64, "x25519_pub_b64")?,
            decode_fixed::<32>(&self.ed25519_pub_b64, "ed25519_pub_b64")?,
        ))
    }
}

/// Ответ основного устройства: новый список устройств и контакты.
/// Подписан ключом аккаунта, чтобы по дороге в нём ничего не подменили.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkResponse {
    /// JSON [`LinkPayload`] — подписываются ровно эти байты.
    pub payload: String,
    pub sig_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkPayload {
    pub account_id: String,
    pub device_id: u32,
    pub username: Option<String>,
    pub devices: SignedDeviceListB64,
    pub contacts: Vec<LinkedContact>,
}

/// Контакт в том виде, в каком его хранит основное устройство.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkedContact {
    pub account_id: String,
    pub username: Option<String>,
    pub x25519_pub_b64: String,
    pub ed25519_pub_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_prekey: Option<SignedPrekeyB64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub devices: Option<SignedDeviceListB64>,
}

fn link_signing_bytes(payload: &str) -> Vec<u8> {
    [DOMAIN_LINK_RESPONSE, payload.as_bytes()].concat()
}

impl LinkResponse {
    pub fn sign(me: &Identity, payload: &LinkPayload) -> Result<Self> {
        let payload = serde_json::to_string(payload)?;
        let sig = me
            .sign_as_account(&link_signing_bytes(&payload))
            .context("ответ на подключение подписывает только устройство с ключом аккаунта")?;
        Ok(Self {
            payload,
            sig_b64: b64(sig),
        })
    }

    /// Проверить ответ: подпись ключом аккаунта из списка устройств и сам список.
    pub fn verify(&self) -> Result<(LinkPayload, DeviceList)> {
        let payload: LinkPayload =
            serde_json::from_str(&self.payload).context("ответ на подключение повреждён")?;
        let (unverified, _) = payload.devices.parts()?;
        // Новые ID выведены из ключа аккаунта — проверяем по ID. У старых
        // UUID-аккаунтов ключ берём из самого списка (его надо сверить по отпечатку).
        let known =
            (!is_key_derived_account_id(&payload.account_id)).then_some(unverified.account_pub);
        let list = verify_device_list(&payload.devices, &payload.account_id, known.as_ref())
            .context("список устройств в ответе не прошёл проверку")?;
        let sig = decode_fixed::<64>(&self.sig_b64, "sig_b64")?;
        if !crypto_core::verify_signature(
            &list.account_pub,
            &link_signing_bytes(&self.payload),
            &sig,
        ) {
            bail!("ответ на подключение подписан не владельцем аккаунта");
        }
        Ok((payload, list))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device_with_key(primary: &Identity, key: &Identity) -> Identity {
        Identity::generate(primary.account_id())
            .with_device(2)
            .with_account_key(key.sign_secret_bytes())
    }

    #[test]
    fn matching_account_key_is_accepted() {
        let db = Db::open_in_memory().unwrap();
        let primary = Identity::generate_new();
        own_list(&db, &primary).unwrap();
        check_account_key(&db, &primary).unwrap();
        let dev = device_with_key(&primary, &primary);
        check_account_key(&db, &dev).unwrap();
        // Устройство без ключа аккаунта проверять нечего.
        check_account_key(
            &db,
            &Identity::generate(primary.account_id()).with_device(2),
        )
        .unwrap();
    }

    const LEGACY_UUID: &str = "1b4e28ba-2fa1-11d2-883f-0016d3cca427";

    #[test]
    fn legacy_uuid_account_with_stored_list_is_accepted() {
        let db = Db::open_in_memory().unwrap();
        let me = Identity::generate(LEGACY_UUID);
        own_list(&db, &me).unwrap();
        check_account_key(&db, &me).unwrap();
    }

    #[test]
    fn legacy_uuid_account_without_list_is_accepted() {
        let db = Db::open_in_memory().unwrap();
        let me = Identity::generate(LEGACY_UUID);
        check_account_key(&db, &me).unwrap();
    }

    #[test]
    fn legacy_uuid_account_foreign_key_on_device_2_is_rejected() {
        let db = Db::open_in_memory().unwrap();
        let primary = Identity::generate(LEGACY_UUID);
        own_list(&db, &primary).unwrap();
        let other = Identity::generate_new();
        let dev = device_with_key(&primary, &other);
        let err = check_account_key(&db, &dev).unwrap_err().to_string();
        assert!(err.contains("не совпадает"), "{err}");
    }

    /// UUID-аккаунт, устройство №2 без списка, ключ чужой: сверка с ID для UUID
    /// невозможна и проходит, но списка нет, так что own_list (а с ним и backup-key)
    /// отказывает.
    #[test]
    fn legacy_uuid_device_without_list_and_foreign_key_cannot_get_own_list() {
        let db = Db::open_in_memory().unwrap();
        let primary = Identity::generate(LEGACY_UUID);
        let other = Identity::generate_new();
        let dev = device_with_key(&primary, &other);
        check_account_key(&db, &dev).unwrap();
        let err = own_list(&db, &dev).unwrap_err().to_string();
        assert!(err.contains("нет списка устройств"), "{err}");
    }

    #[test]
    fn foreign_account_key_is_rejected_without_list() {
        let db = Db::open_in_memory().unwrap();
        let primary = Identity::generate_new();
        let other = Identity::generate_new();
        let dev = device_with_key(&primary, &other);
        let err = check_account_key(&db, &dev).unwrap_err().to_string();
        assert!(err.contains("не подходит к account_id"), "{err}");
    }

    #[test]
    fn account_key_not_matching_stored_list_is_rejected() {
        let db = Db::open_in_memory().unwrap();
        let primary = Identity::generate_new();
        let other = Identity::generate_new();
        // Сохранённый «свой» список с чужим account_pub.
        let list = DeviceList {
            account_id: other.account_id().into(),
            account_pub: other.sign_public_bytes(),
            version: 1,
            devices: vec![other.device_info(PRIMARY_NAME)],
        };
        let wire = other.sign_device_list(&list).unwrap();
        db.save_device_list(
            primary.account_id(),
            1,
            &serde_json::to_string(&wire).unwrap(),
        )
        .unwrap();
        let dev = device_with_key(&primary, &primary);
        let err = check_account_key(&db, &dev).unwrap_err().to_string();
        assert!(err.contains("не совпадает"), "{err}");
    }

    fn list_of(primary: &Identity, version: u64, extra: &[u32]) -> DeviceList {
        let mut devices = vec![primary.device_info(PRIMARY_NAME)];
        for &id in extra {
            devices.push(
                Identity::generate(primary.account_id())
                    .with_device(id)
                    .device_info(format!("d{id}")),
            );
        }
        DeviceList {
            account_id: primary.account_id().into(),
            account_pub: primary.sign_public_bytes(),
            version,
            devices,
        }
    }

    fn put(db: &Db, me: &Identity, list: &DeviceList) -> Result<Option<DeviceList>> {
        accept(db, me, &me.sign_device_list(list).unwrap())
    }

    #[test]
    fn accept_skips_older_list_silently() {
        let db = Db::open_in_memory().unwrap();
        let me = Identity::generate_new();
        put(&db, &me, &list_of(&me, 1, &[])).unwrap();
        put(&db, &me, &list_of(&me, 3, &[4])).unwrap();
        assert!(put(&db, &me, &list_of(&me, 2, &[])).unwrap().is_none());
        assert_eq!(stored(&db, me.account_id()).unwrap().unwrap().0.version, 3);
    }

    #[test]
    fn accept_rejects_same_version_with_other_content() {
        let db = Db::open_in_memory().unwrap();
        let me = Identity::generate_new();
        put(&db, &me, &list_of(&me, 2, &[3])).unwrap();
        let err = put(&db, &me, &list_of(&me, 2, &[5]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("отклонён"), "{err}");
    }

    #[test]
    fn accept_rejects_changed_primary_entry() {
        let db = Db::open_in_memory().unwrap();
        let me = Identity::generate_new();
        put(&db, &me, &list_of(&me, 1, &[])).unwrap();
        let mut list = list_of(&me, 2, &[]);
        list.devices[0].name = "другое имя".into();
        let err = put(&db, &me, &list).unwrap_err().to_string();
        assert!(err.contains("отклонён"), "{err}");
    }

    #[test]
    fn accept_takes_normal_update() {
        let db = Db::open_in_memory().unwrap();
        let me = Identity::generate_new();
        put(&db, &me, &list_of(&me, 1, &[])).unwrap();
        let got = put(&db, &me, &list_of(&me, 2, &[2])).unwrap().unwrap();
        assert_eq!(got.version, 2);
    }

    fn numbered(version: u64, ids: &[u32]) -> DeviceList {
        let me = Identity::generate_new();
        let mut l = list_of(&me, version, &[]);
        l.devices = ids
            .iter()
            .map(|&id| {
                Identity::generate(me.account_id())
                    .with_device(id)
                    .device_info("x")
            })
            .collect();
        l
    }

    #[test]
    fn next_device_number_follows_rule() {
        assert_eq!(
            next_device_number(&numbered(5, &[1, 2, 3])).unwrap(),
            (6, 6)
        );
        assert_eq!(next_device_number(&numbered(2, &[1, 7])).unwrap(), (3, 8));
    }

    #[test]
    fn next_device_number_overflow_is_error() {
        assert!(next_device_number(&numbered(u64::MAX, &[1])).is_err());
        assert!(next_device_number(&numbered(u64::from(u32::MAX), &[1])).is_err());
        assert!(next_device_number(&numbered(2, &[1, u32::MAX])).is_err());
    }

    #[test]
    fn link_response_signed_by_account_key_device_verifies() {
        let primary = Identity::generate_new();
        let (_, wire) = {
            let db = Db::open_in_memory().unwrap();
            own_list(&db, &primary).unwrap()
        };
        let phone = device_with_key(&primary, &primary);
        let payload = LinkPayload {
            account_id: primary.account_id().into(),
            device_id: 3,
            username: None,
            devices: wire,
            contacts: vec![],
        };
        let resp = LinkResponse::sign(&phone, &payload).unwrap();
        resp.verify().unwrap();
        // Устройство без ключа аккаунта подписать не может.
        let plain = Identity::generate(primary.account_id()).with_device(4);
        assert!(LinkResponse::sign(&plain, &payload).is_err());
    }
}
