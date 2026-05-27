use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, SecondsFormat, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;

use crate::errors::SkeyStatus;
use crate::license::canonical_json_bytes;

type HmacSha256 = Hmac<Sha256>;

pub const STATE_SCHEMA: &str = "skey-state-v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustedTimeState {
    pub schema: String,
    pub product_id: String,
    pub package_id: String,
    pub activation_id: String,
    pub package_hash: String,
    pub last_seen_utc: DateTime<Utc>,
    pub last_server_utc: Option<DateTime<Utc>>,
    pub last_lease_until: DateTime<Utc>,
    pub boot_counter: u64,
    pub hmac: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateUpdate {
    pub product_id: String,
    pub package_id: String,
    pub activation_id: String,
    pub package_hash: String,
    pub last_seen_utc: DateTime<Utc>,
    pub last_server_utc: Option<DateTime<Utc>>,
    pub last_lease_until: DateTime<Utc>,
    pub boot_counter: u64,
}

pub fn read_state(
    license_dir: &Path,
    hmac_key: &[u8],
) -> Result<Option<TrustedTimeState>, SkeyStatus> {
    let path = license_dir.join("state.dat");
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(SkeyStatus::ClockRollback),
    };
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| SkeyStatus::ClockRollback)?;
    verify_state_hmac(&value, hmac_key)?;
    let state: TrustedTimeState =
        serde_json::from_value(value).map_err(|_| SkeyStatus::ClockRollback)?;
    if state.schema != STATE_SCHEMA {
        return Err(SkeyStatus::ClockRollback);
    }
    Ok(Some(state))
}

pub fn write_state_atomic(
    license_dir: &Path,
    update: &StateUpdate,
    hmac_key: &[u8],
) -> Result<(), SkeyStatus> {
    fs::create_dir_all(license_dir).map_err(|_| SkeyStatus::Internal)?;
    let path = license_dir.join("state.dat");
    let temp_path = license_dir.join("state.dat.new");
    let mut value = state_value(update);
    let mac = state_hmac(&value, hmac_key)?;
    value["hmac"] = json!(URL_SAFE_NO_PAD.encode(mac));
    let bytes = canonical_json_bytes(&value).map_err(|_| SkeyStatus::Internal)?;
    let mut file = File::create(&temp_path).map_err(|_| SkeyStatus::Internal)?;
    file.write_all(&bytes).map_err(|_| SkeyStatus::Internal)?;
    file.sync_all().map_err(|_| SkeyStatus::Internal)?;
    drop(file);

    replace_state_file_atomic(&temp_path, &path)
}

fn replace_state_file_atomic(temp_path: &Path, path: &Path) -> Result<(), SkeyStatus> {
    #[cfg(target_os = "windows")]
    {
        replace_state_file_windows(temp_path, path)?;
    }
    #[cfg(not(target_os = "windows"))]
    {
        fs::rename(temp_path, path).map_err(|_| SkeyStatus::Internal)?;
    }
    fsync_parent_dir(path);
    Ok(())
}

#[cfg(target_os = "windows")]
fn replace_state_file_windows(temp_path: &Path, path: &Path) -> Result<(), SkeyStatus> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let temp_wide = temp_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let path_wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    let ok = unsafe { MoveFileExW(temp_wide.as_ptr(), path_wide.as_ptr(), flags) };
    if ok == 0 {
        return Err(SkeyStatus::Internal);
    }
    Ok(())
}

fn fsync_parent_dir(path: &Path) {
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

fn verify_state_hmac(value: &Value, hmac_key: &[u8]) -> Result<(), SkeyStatus> {
    let supplied = value
        .get("hmac")
        .and_then(Value::as_str)
        .ok_or(SkeyStatus::ClockRollback)?;
    let supplied = URL_SAFE_NO_PAD
        .decode(supplied)
        .map_err(|_| SkeyStatus::ClockRollback)?;
    let mut signing_value = value.clone();
    let object = signing_value
        .as_object_mut()
        .ok_or(SkeyStatus::ClockRollback)?;
    object.remove("hmac");
    let bytes = canonical_json_bytes(&signing_value).map_err(|_| SkeyStatus::ClockRollback)?;
    let mut mac = HmacSha256::new_from_slice(hmac_key).map_err(|_| SkeyStatus::ClockRollback)?;
    mac.update(&bytes);
    mac.verify_slice(&supplied)
        .map_err(|_| SkeyStatus::ClockRollback)
}

fn state_hmac(value: &Value, hmac_key: &[u8]) -> Result<Vec<u8>, SkeyStatus> {
    let bytes = canonical_json_bytes(value).map_err(|_| SkeyStatus::ClockRollback)?;
    let mut mac = HmacSha256::new_from_slice(hmac_key).map_err(|_| SkeyStatus::ClockRollback)?;
    mac.update(&bytes);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn state_value(update: &StateUpdate) -> Value {
    json!({
        "schema": STATE_SCHEMA,
        "product_id": update.product_id,
        "package_id": update.package_id,
        "activation_id": update.activation_id,
        "package_hash": update.package_hash,
        "last_seen_utc": fmt_utc(update.last_seen_utc),
        "last_server_utc": update.last_server_utc.map(fmt_utc),
        "last_lease_until": fmt_utc(update.last_lease_until),
        "boot_counter": update.boot_counter,
    })
}

fn fmt_utc(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use tempfile::tempdir;

    use super::{read_state, replace_state_file_atomic, write_state_atomic, StateUpdate};
    use crate::errors::SkeyStatus;

    #[test]
    fn state_round_trips_with_hmac_and_rejects_tamper() {
        let dir = tempdir().unwrap();
        let update = StateUpdate {
            product_id: "prod_x".to_owned(),
            package_id: "pkg_1".to_owned(),
            activation_id: "act_1".to_owned(),
            package_hash: "sha256:abc".to_owned(),
            last_seen_utc: parse("2026-05-25T10:00:00Z"),
            last_server_utc: Some(parse("2026-05-25T09:00:00Z")),
            last_lease_until: parse("2026-05-30T00:00:00Z"),
            boot_counter: 7,
        };
        write_state_atomic(dir.path(), &update, b"state-key").unwrap();

        let state = read_state(dir.path(), b"state-key").unwrap().unwrap();

        assert_eq!(state.product_id, "prod_x");
        assert_eq!(state.boot_counter, 7);

        let path = dir.path().join("state.dat");
        let tampered = std::fs::read_to_string(&path)
            .unwrap()
            .replace("prod_x", "prod_y");
        std::fs::write(&path, tampered).unwrap();

        assert_eq!(
            read_state(dir.path(), b"state-key").unwrap_err(),
            SkeyStatus::ClockRollback
        );
    }

    #[test]
    fn failed_atomic_replace_keeps_existing_state_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.dat");
        let temp_path = dir.path().join("state.dat.new");
        std::fs::write(&path, b"existing-state").unwrap();

        assert_eq!(
            replace_state_file_atomic(&temp_path, &path).unwrap_err(),
            SkeyStatus::Internal
        );

        assert_eq!(std::fs::read(&path).unwrap(), b"existing-state");
    }

    fn parse(value: &str) -> DateTime<Utc> {
        value.parse().unwrap()
    }
}
