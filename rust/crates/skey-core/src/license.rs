use std::fs;
use std::path::Path;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
#[cfg(any(test, not(target_os = "windows")))]
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
#[cfg(target_os = "windows")]
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::errors::SkeyStatus;

#[cfg(any(test, not(target_os = "windows")))]
type HmacSha256 = Hmac<Sha256>;

const CLIENT_KEY_SCHEMA: &str = "skey-client-key-v1";
#[cfg(any(test, not(target_os = "windows")))]
const CLIENT_KEY_PROTECTION: &str = "platform-derived-hmac-sha256-xor-v2";
#[cfg(target_os = "windows")]
const WINDOWS_CLIENT_KEY_PROTECTION: &str = "windows-dpapi-v1";
#[cfg(all(test, target_os = "windows"))]
const LEGACY_CLIENT_KEY_PROTECTION: &str = "platform-derived-hmac-sha256-xor-v1";

#[derive(Clone, Debug, Deserialize)]
pub struct ActivationCert {
    pub product_id: String,
    pub package_id: String,
    pub package_hash: String,
    pub device_hash: String,
    pub device_score_policy: DeviceScorePolicy,
    #[serde(default)]
    pub features: Vec<FeatureClaim>,
    pub not_before: String,
    pub expire_at: String,
    pub lease_until: String,
    pub offline_grace_hours: i64,
    pub wrapped_pkg_key: Value,
    pub kid: String,
    pub signature: String,
}

impl ActivationCert {
    pub fn not_before_utc(&self) -> Result<DateTime<Utc>, SkeyStatus> {
        parse_utc(&self.not_before)
    }

    pub fn expire_at_utc(&self) -> Result<DateTime<Utc>, SkeyStatus> {
        parse_utc(&self.expire_at)
    }

    pub fn lease_until_utc(&self) -> Result<DateTime<Utc>, SkeyStatus> {
        parse_utc(&self.lease_until)
    }

    pub fn enables_feature(&self, code: &str) -> bool {
        self.features
            .iter()
            .any(|feature| feature.enabled && feature.code == code)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeviceScorePolicy {
    pub pass_score: u16,
    pub review_score: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeatureClaim {
    pub code: String,
    pub enabled: bool,
}

pub fn read_activation_cert(
    license_dir: &Path,
    server_public_key: &[u8],
) -> Result<ActivationCert, SkeyStatus> {
    let path = license_dir.join("activation.cert");
    let bytes = fs::read(&path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            SkeyStatus::LicenseMissing
        } else {
            SkeyStatus::LicenseSignature
        }
    })?;
    verify_activation_cert_bytes(&bytes, server_public_key)
}

pub fn verify_activation_cert_bytes(
    bytes: &[u8],
    server_public_key: &[u8],
) -> Result<ActivationCert, SkeyStatus> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| SkeyStatus::LicenseSignature)?;
    let signature_value = value
        .get("signature")
        .and_then(Value::as_str)
        .ok_or(SkeyStatus::LicenseSignature)?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_value)
        .map_err(|_| SkeyStatus::LicenseSignature)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| SkeyStatus::LicenseSignature)?;
    let public_key: [u8; 32] = server_public_key
        .try_into()
        .map_err(|_| SkeyStatus::LicenseSignature)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| SkeyStatus::LicenseSignature)?;
    let signing_bytes = cert_signing_bytes(&value)?;
    verifying_key
        .verify(&signing_bytes, &signature)
        .map_err(|_| SkeyStatus::LicenseSignature)?;
    serde_json::from_value(value).map_err(|_| SkeyStatus::LicenseSignature)
}

pub fn cert_signing_bytes(value: &Value) -> Result<Vec<u8>, SkeyStatus> {
    let mut signing_value = value.clone();
    let object = signing_value
        .as_object_mut()
        .ok_or(SkeyStatus::LicenseSignature)?;
    object.remove("signature");
    canonical_json_bytes(&signing_value).map_err(|_| SkeyStatus::LicenseSignature)
}

pub fn canonical_json_bytes(value: &Value) -> serde_json::Result<Vec<u8>> {
    serde_json::to_vec(value)
}

pub fn package_hash_matches(payload_path: &Path, package_hash: &str) -> Result<bool, SkeyStatus> {
    let payload = fs::read(payload_path).map_err(|_| SkeyStatus::PackageTampered)?;
    let actual = hex_lower(Sha256::digest(payload));
    let expected = package_hash
        .strip_prefix("sha256:")
        .unwrap_or(package_hash)
        .to_ascii_lowercase();
    Ok(actual == expected)
}

pub fn read_client_key(license_dir: &Path) -> Result<Zeroizing<[u8; 32]>, SkeyStatus> {
    let path = license_dir.join("client_key.dat");
    let bytes = fs::read(&path).map_err(|_| SkeyStatus::DecryptFailed)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path)
            .map_err(|_| SkeyStatus::DecryptFailed)?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(SkeyStatus::DecryptFailed);
        }
    }

    let plaintext = decrypt_client_key_envelope(license_dir, &bytes)?;
    to_zeroizing_32(plaintext.as_slice())
}

#[derive(Debug, Deserialize, Serialize)]
struct ClientKeyEnvelope {
    schema: String,
    protection: String,
    #[serde(default)]
    kdf: Option<String>,
    #[serde(default)]
    salt: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
    ciphertext: String,
    #[serde(default)]
    tag: Option<String>,
}

#[cfg(all(test, not(target_os = "windows")))]
fn protect_client_key_for_local_storage(
    license_dir: &Path,
    plaintext: &[u8],
    salt: &[u8],
) -> Vec<u8> {
    protect_client_key_for_local_storage_with_protection(
        license_dir,
        plaintext,
        salt,
        CLIENT_KEY_PROTECTION,
    )
}

#[cfg(all(test, target_os = "windows"))]
fn protect_legacy_client_key_for_local_storage(
    license_dir: &Path,
    plaintext: &[u8],
    salt: &[u8],
) -> Vec<u8> {
    protect_client_key_for_local_storage_with_protection(
        license_dir,
        plaintext,
        salt,
        LEGACY_CLIENT_KEY_PROTECTION,
    )
}

#[cfg(test)]
fn protect_client_key_for_local_storage_with_protection(
    license_dir: &Path,
    plaintext: &[u8],
    salt: &[u8],
    protection: &str,
) -> Vec<u8> {
    let nonce_digest = Sha256::digest([b"nonce:", salt].concat());
    let nonce = nonce_digest[..12].to_vec();
    let enc_key = derive_client_key_material(license_dir, salt, &nonce, b"enc", protection)
        .expect("test platform key material is available");
    let ciphertext = xor_with_derived_stream(plaintext, &enc_key, &nonce);
    let tag = client_key_tag(
        license_dir,
        salt,
        &nonce,
        &ciphertext,
        CLIENT_KEY_SCHEMA,
        protection,
    )
    .expect("static HMAC key material is valid");
    let envelope = serde_json::json!({
        "schema": CLIENT_KEY_SCHEMA,
        "protection": protection,
        "kdf": "sha256-platform-material-v1",
        "salt": URL_SAFE_NO_PAD.encode(salt),
        "nonce": URL_SAFE_NO_PAD.encode(nonce),
        "ciphertext": URL_SAFE_NO_PAD.encode(ciphertext),
        "tag": URL_SAFE_NO_PAD.encode(tag),
    });
    canonical_json_bytes(&envelope).expect("client key envelope serializes")
}

#[cfg(target_os = "windows")]
fn decrypt_client_key_envelope(
    _license_dir: &Path,
    bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SkeyStatus> {
    let envelope: ClientKeyEnvelope =
        serde_json::from_slice(bytes).map_err(|_| SkeyStatus::DecryptFailed)?;
    if envelope.schema != CLIENT_KEY_SCHEMA {
        return Err(SkeyStatus::DecryptFailed);
    }
    decrypt_windows_dpapi_client_key(&envelope)
}

#[cfg(not(target_os = "windows"))]
fn decrypt_client_key_envelope(
    license_dir: &Path,
    bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SkeyStatus> {
    let envelope: ClientKeyEnvelope =
        serde_json::from_slice(bytes).map_err(|_| SkeyStatus::DecryptFailed)?;
    if envelope.schema != CLIENT_KEY_SCHEMA {
        return Err(SkeyStatus::DecryptFailed);
    }
    decrypt_platform_derived_client_key(license_dir, &envelope)
}

#[cfg(target_os = "windows")]
fn decrypt_windows_dpapi_client_key(
    envelope: &ClientKeyEnvelope,
) -> Result<Zeroizing<Vec<u8>>, SkeyStatus> {
    if envelope.protection != WINDOWS_CLIENT_KEY_PROTECTION {
        return Err(SkeyStatus::DecryptFailed);
    }
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&envelope.ciphertext)
        .map_err(|_| SkeyStatus::DecryptFailed)?;
    if ciphertext.is_empty() {
        return Err(SkeyStatus::DecryptFailed);
    }
    let plaintext = windows_dpapi_unprotect(&ciphertext)?;
    if plaintext.is_empty() {
        return Err(SkeyStatus::DecryptFailed);
    }
    Ok(plaintext)
}

#[cfg(target_os = "windows")]
fn windows_dpapi_unprotect(ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, SkeyStatus> {
    use std::ptr;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};

    struct LocalAllocGuard {
        ptr: *mut u8,
        len: usize,
    }

    impl Drop for LocalAllocGuard {
        fn drop(&mut self) {
            if !self.ptr.is_null() {
                unsafe {
                    if self.len != 0 {
                        std::slice::from_raw_parts_mut(self.ptr, self.len).zeroize();
                    }
                    LocalFree(self.ptr.cast());
                }
            }
        }
    }

    let cb_data: u32 = ciphertext
        .len()
        .try_into()
        .map_err(|_| SkeyStatus::DecryptFailed)?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: cb_data,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            0,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(SkeyStatus::DecryptFailed);
    }
    let output_guard = LocalAllocGuard {
        ptr: output.pbData,
        len: output.cbData as usize,
    };
    if output_guard.ptr.is_null() || output_guard.len == 0 {
        return Err(SkeyStatus::DecryptFailed);
    }
    let plaintext = Zeroizing::new(unsafe {
        std::slice::from_raw_parts(output_guard.ptr, output_guard.len).to_vec()
    });
    Ok(plaintext)
}

#[cfg(not(target_os = "windows"))]
fn decrypt_platform_derived_client_key(
    license_dir: &Path,
    envelope: &ClientKeyEnvelope,
) -> Result<Zeroizing<Vec<u8>>, SkeyStatus> {
    if envelope.schema != CLIENT_KEY_SCHEMA
        || envelope.protection != CLIENT_KEY_PROTECTION
        || envelope.kdf.as_deref() != Some("sha256-platform-material-v1")
    {
        return Err(SkeyStatus::DecryptFailed);
    }
    let salt = URL_SAFE_NO_PAD
        .decode(envelope.salt.as_deref().ok_or(SkeyStatus::DecryptFailed)?)
        .map_err(|_| SkeyStatus::DecryptFailed)?;
    let nonce = URL_SAFE_NO_PAD
        .decode(envelope.nonce.as_deref().ok_or(SkeyStatus::DecryptFailed)?)
        .map_err(|_| SkeyStatus::DecryptFailed)?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&envelope.ciphertext)
        .map_err(|_| SkeyStatus::DecryptFailed)?;
    let supplied_tag = URL_SAFE_NO_PAD
        .decode(envelope.tag.as_deref().ok_or(SkeyStatus::DecryptFailed)?)
        .map_err(|_| SkeyStatus::DecryptFailed)?;
    verify_client_key_tag(
        license_dir,
        &salt,
        &nonce,
        &ciphertext,
        &envelope.schema,
        &envelope.protection,
        &supplied_tag,
    )?;
    let enc_key =
        derive_client_key_material(license_dir, &salt, &nonce, b"enc", &envelope.protection)?;
    let plaintext = xor_with_derived_stream(&ciphertext, &enc_key, &nonce);
    if plaintext.is_empty() {
        return Err(SkeyStatus::DecryptFailed);
    }
    Ok(plaintext)
}

#[cfg(any(test, not(target_os = "windows")))]
fn client_key_tag(
    license_dir: &Path,
    salt: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    schema: &str,
    protection: &str,
) -> Result<Vec<u8>, SkeyStatus> {
    let key = derive_client_key_material(license_dir, salt, nonce, b"tag", protection)?;
    let mut mac = HmacSha256::new_from_slice(&key).map_err(|_| SkeyStatus::DecryptFailed)?;
    mac.update(schema.as_bytes());
    mac.update(b"\0");
    mac.update(protection.as_bytes());
    mac.update(b"\0");
    mac.update(salt);
    mac.update(nonce);
    mac.update(ciphertext);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(not(target_os = "windows"))]
fn verify_client_key_tag(
    license_dir: &Path,
    salt: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    schema: &str,
    protection: &str,
    supplied_tag: &[u8],
) -> Result<(), SkeyStatus> {
    let key = derive_client_key_material(license_dir, salt, nonce, b"tag", protection)?;
    let mut mac = HmacSha256::new_from_slice(&key).map_err(|_| SkeyStatus::DecryptFailed)?;
    mac.update(schema.as_bytes());
    mac.update(b"\0");
    mac.update(protection.as_bytes());
    mac.update(b"\0");
    mac.update(salt);
    mac.update(nonce);
    mac.update(ciphertext);
    mac.verify_slice(supplied_tag)
        .map_err(|_| SkeyStatus::DecryptFailed)
}

#[cfg(any(test, not(target_os = "windows")))]
fn derive_client_key_material(
    license_dir: &Path,
    salt: &[u8],
    nonce: &[u8],
    purpose: &[u8],
    protection: &str,
) -> Result<Zeroizing<Vec<u8>>, SkeyStatus> {
    let mut hasher = Sha256::new();
    hasher.update(CLIENT_KEY_SCHEMA.as_bytes());
    hasher.update(b"\0");
    hasher.update(protection.as_bytes());
    hasher.update(b"\0");
    hasher.update(purpose);
    hasher.update(b"\0");
    let platform_material = platform_client_key_material(license_dir)?;
    hasher.update(platform_material.as_slice());
    hasher.update(b"\0");
    hasher.update(salt);
    hasher.update(nonce);
    Ok(Zeroizing::new(hasher.finalize().to_vec()))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_client_key_material(license_dir: &Path) -> Result<Zeroizing<Vec<u8>>, SkeyStatus> {
    use std::os::unix::fs::MetadataExt;

    let uid = fs::metadata(license_dir)
        .or_else(|_| fs::metadata("."))
        .map(|metadata| metadata.uid().to_string())
        .unwrap_or_default();
    let machine_id = fs::read_to_string("/etc/machine-id")
        .or_else(|_| fs::read_to_string("/var/lib/dbus/machine-id"))
        .unwrap_or_else(|_| hostname_fallback());
    Ok(Zeroizing::new(
        [
            CLIENT_KEY_SCHEMA,
            CLIENT_KEY_PROTECTION,
            std::env::consts::OS,
            std::env::consts::ARCH,
            uid.trim(),
            machine_id.trim(),
        ]
        .join("\0")
        .into_bytes(),
    ))
}

#[cfg(target_os = "macos")]
fn platform_client_key_material(_license_dir: &Path) -> Result<Zeroizing<Vec<u8>>, SkeyStatus> {
    const SERVICE: &str = "com.skey.client-key.v1";

    let account = std::env::var("USER").unwrap_or_else(|_| "default".to_owned());
    let secret = read_macos_keychain_secret(SERVICE, &account)
        .or_else(|_| create_macos_keychain_secret(SERVICE, &account))?;
    let mut material = Zeroizing::new(
        [
            CLIENT_KEY_SCHEMA,
            CLIENT_KEY_PROTECTION,
            std::env::consts::OS,
            std::env::consts::ARCH,
            &account,
        ]
        .join("\0")
        .into_bytes(),
    );
    material.push(0);
    material.extend(secret.iter().copied());
    Ok(material)
}

#[cfg(target_os = "macos")]
fn read_macos_keychain_secret(
    service: &str,
    account: &str,
) -> Result<Zeroizing<Vec<u8>>, SkeyStatus> {
    let output = std::process::Command::new("security")
        .args(["find-generic-password", "-w", "-s", service, "-a", account])
        .output()
        .map_err(|_| SkeyStatus::DecryptFailed)?;
    if !output.status.success() {
        return Err(SkeyStatus::DecryptFailed);
    }
    let secret = trim_ascii_line_ending(output.stdout);
    if secret.is_empty() {
        return Err(SkeyStatus::DecryptFailed);
    }
    Ok(Zeroizing::new(secret))
}

#[cfg(target_os = "macos")]
fn create_macos_keychain_secret(
    service: &str,
    account: &str,
) -> Result<Zeroizing<Vec<u8>>, SkeyStatus> {
    let secret = Zeroizing::new(
        std::process::Command::new("uuidgen")
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| trim_ascii_line_ending(output.stdout))
            .filter(|secret| !secret.is_empty())
            .ok_or(SkeyStatus::DecryptFailed)?,
    );
    let secret_arg =
        Zeroizing::new(String::from_utf8(secret.to_vec()).map_err(|_| SkeyStatus::DecryptFailed)?);
    let status = std::process::Command::new("security")
        .args([
            "add-generic-password",
            "-U",
            "-s",
            service,
            "-a",
            account,
            "-w",
            secret_arg.as_str(),
        ])
        .status()
        .map_err(|_| SkeyStatus::DecryptFailed)?;
    if !status.success() {
        return Err(SkeyStatus::DecryptFailed);
    }
    Ok(secret)
}

#[cfg(target_os = "macos")]
fn trim_ascii_line_ending(mut value: Vec<u8>) -> Vec<u8> {
    while matches!(value.last(), Some(b'\n' | b'\r')) {
        value.pop();
    }
    value
}

#[cfg(all(not(unix), any(test, not(target_os = "windows"))))]
fn platform_client_key_material(_license_dir: &Path) -> Result<Zeroizing<Vec<u8>>, SkeyStatus> {
    let user = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default();
    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_default();
    Ok(Zeroizing::new(
        [
            CLIENT_KEY_SCHEMA,
            CLIENT_KEY_PROTECTION,
            std::env::consts::OS,
            std::env::consts::ARCH,
            &user,
            &hostname,
        ]
        .join("\0")
        .into_bytes(),
    ))
}

#[cfg(unix)]
fn hostname_fallback() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| {
        std::process::Command::new("hostname")
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .unwrap_or_default()
    })
}

#[cfg(any(test, not(target_os = "windows")))]
fn xor_with_derived_stream(input: &[u8], key: &[u8], nonce: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut output = Zeroizing::new(Vec::with_capacity(input.len()));
    for (counter, chunk) in input.chunks(32).enumerate() {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(nonce);
        hasher.update((counter as u64).to_be_bytes());
        let stream = hasher.finalize();
        output.extend(
            chunk
                .iter()
                .zip(stream.iter())
                .map(|(byte, mask)| byte ^ mask),
        );
    }
    output
}

fn to_zeroizing_32(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, SkeyStatus> {
    if bytes.len() != 32 {
        return Err(SkeyStatus::DecryptFailed);
    }
    let mut output = Zeroizing::new([0u8; 32]);
    output.copy_from_slice(bytes);
    Ok(output)
}

pub(crate) fn parse_utc(value: &str) -> Result<DateTime<Utc>, SkeyStatus> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| SkeyStatus::LicenseSignature)
}

pub(crate) fn hex_lower(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    use super::{cert_signing_bytes, read_client_key, verify_activation_cert_bytes};

    #[test]
    fn verifies_task_8_style_canonical_certificate_signature() {
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let mut cert = json!({
            "cert_version": 1,
            "product_id": "prod_x",
            "package_id": "pkg_1",
            "package_hash": "sha256:00",
            "device_hash": "device",
            "device_score_policy": {"pass_score": 70, "review_score": 50},
            "features": [{"code": "RUN_MAIN", "enabled": true}],
            "not_before": "2026-05-01T00:00:00Z",
            "expire_at": "2026-06-01T00:00:00Z",
            "lease_until": "2026-05-30T00:00:00Z",
            "offline_grace_hours": 168,
            "wrapped_pkg_key": {"alg": "test"},
            "kid": "test-key"
        });
        let signature = signing_key.sign(&cert_signing_bytes(&cert).unwrap());
        cert["signature"] = json!(URL_SAFE_NO_PAD.encode(signature.to_bytes()));

        let parsed = verify_activation_cert_bytes(
            &serde_json::to_vec(&cert).unwrap(),
            &signing_key.verifying_key().to_bytes(),
        )
        .unwrap();

        assert_eq!(parsed.product_id, "prod_x");
        assert!(parsed.enables_feature("RUN_MAIN"));
    }

    #[test]
    fn rejects_tampered_certificate_claims() {
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let mut cert = json!({
            "product_id": "prod_x",
            "package_id": "pkg_1",
            "package_hash": "sha256:00",
            "device_hash": "device",
            "device_score_policy": {"pass_score": 70, "review_score": 50},
            "features": [],
            "not_before": "2026-05-01T00:00:00Z",
            "expire_at": "2026-06-01T00:00:00Z",
            "lease_until": "2026-05-30T00:00:00Z",
            "offline_grace_hours": 168,
            "wrapped_pkg_key": {"alg": "test"},
            "kid": "test-key"
        });
        let signature = signing_key.sign(&cert_signing_bytes(&cert).unwrap());
        cert["signature"] = json!(URL_SAFE_NO_PAD.encode(signature.to_bytes()));
        cert["product_id"] = json!("tampered");

        assert!(verify_activation_cert_bytes(
            &serde_json::to_vec(&cert).unwrap(),
            &signing_key.verifying_key().to_bytes()
        )
        .is_err());
    }

    #[test]
    fn reads_valid_protected_client_key_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let key = [7u8; 32];
        #[cfg(target_os = "windows")]
        let envelope = protect_client_key_with_dpapi_for_test(&key);
        #[cfg(not(target_os = "windows"))]
        let envelope =
            super::protect_client_key_for_local_storage(dir.path(), key, b"fixed-test-salt");
        let path = dir.path().join("client_key.dat");
        std::fs::write(&path, envelope).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let key_material: zeroize::Zeroizing<[u8; 32]> = read_client_key(dir.path()).unwrap();
        assert_eq!(key_material.as_ref(), &key);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn rejects_legacy_xor_client_key_envelope_on_windows() {
        let dir = tempfile::tempdir().unwrap();
        let envelope = super::protect_legacy_client_key_for_local_storage(
            dir.path(),
            b"client-key-boundary\n",
            b"salt",
        );
        std::fs::write(dir.path().join("client_key.dat"), envelope).unwrap();

        assert_eq!(
            read_client_key(dir.path()).unwrap_err(),
            crate::errors::SkeyStatus::DecryptFailed
        );
    }

    #[test]
    fn rejects_plaintext_or_missing_client_key() {
        let dir = tempfile::tempdir().unwrap();

        assert_eq!(
            read_client_key(dir.path()).unwrap_err(),
            crate::errors::SkeyStatus::DecryptFailed
        );

        std::fs::write(dir.path().join("client_key.dat"), b"client-key-boundary\n").unwrap();
        assert_eq!(
            read_client_key(dir.path()).unwrap_err(),
            crate::errors::SkeyStatus::DecryptFailed
        );
    }

    #[cfg(target_os = "windows")]
    fn protect_client_key_with_dpapi_for_test(plaintext: &[u8]) -> Vec<u8> {
        use std::ptr;

        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB};

        let input = CRYPT_INTEGER_BLOB {
            cbData: plaintext.len().try_into().unwrap(),
            pbData: plaintext.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        let ok = unsafe {
            CryptProtectData(
                &input,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                0,
                &mut output,
            )
        };
        assert_ne!(ok, 0);
        let ciphertext =
            unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
        unsafe {
            LocalFree(output.pbData.cast());
        }
        let envelope = json!({
            "schema": "skey-client-key-v1",
            "protection": "windows-dpapi-v1",
            "ciphertext": URL_SAFE_NO_PAD.encode(ciphertext),
        });
        super::canonical_json_bytes(&envelope).unwrap()
    }
}
