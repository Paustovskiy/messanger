//! Устройства аккаунта: свой список, списки собеседников и подключение новых
//! устройств.
//!
//! Каждое устройство — отдельная пара ключей и отдельные сессии. Какие
//! устройства принадлежат аккаунту, говорит список, подписанный ключом
//! аккаунта (это ключ основного устройства, №1). Список только растёт по
//! версиям: старый список (например, подсунутый релеем, чтобы вернуть
//! отключённое устройство) не принимается.

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

/// Подписать и сохранить новую версию своего списка (только основное устройство).
pub fn save_own(db: &Db, me: &Identity, list: &DeviceList) -> Result<SignedDeviceListB64> {
    let wire = me
        .sign_device_list(list)
        .context("менять список устройств может только основное устройство")?;
    accept(db, me, &wire)?;
    Ok(wire)
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
        let sig = me.sign(&link_signing_bytes(&payload));
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
