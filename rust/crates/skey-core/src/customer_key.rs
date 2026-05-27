use std::fs;
use std::path::Path;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::errors::SkeyStatus;
use crate::license::{
    canonical_json_bytes, package_hash_matches, parse_utc, ActivationCert, DeviceScorePolicy,
    FeatureClaim,
};
use crate::machine::MachineFingerprint;

const CUSTOMER_KEY_SCHEMA: &str = "skey-customer-key-v1";
const CUSTOMER_KEY_FILE: &str = "skey.key";
const CUSTOMER_KEY_BINDING_SCHEMA: &str = "skey-customer-key-binding-v1";
const CUSTOMER_KEY_BINDING_INFO: &[u8] = b"skey-customer-key-binding-v1";
const PERPETUAL_UTC: &str = "9999-12-31T23:59:59Z";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug)]
pub struct CustomerKeyUnlock {
    pub cert: ActivationCert,
    pub activation_id: String,
    pub package_key: Zeroizing<[u8; 32]>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CustomerKeyFile {
    schema: String,
    license_id: String,
    activation_id: String,
    product_id: String,
    package_id: String,
    package_hash: String,
    device_score_policy: DeviceScorePolicy,
    #[serde(default)]
    features: Vec<FeatureClaim>,
    not_before: String,
    #[serde(default)]
    perpetual: bool,
    #[serde(default)]
    expire_at: Option<String>,
    #[serde(default)]
    lease_until: Option<String>,
    offline_grace_hours: i64,
    package_key_b64: String,
    kid: String,
    #[serde(default)]
    binding: Option<CustomerKeyBinding>,
    signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CustomerKeyBinding {
    schema: String,
    device_hash: String,
    bound_at: String,
    hmac: String,
}

pub fn unlock_with_customer_key(
    app_root: &Path,
    payload_path: &Path,
    server_public_key: &[u8],
    expected_product_id: &str,
    expected_package_id: &str,
    requested_feature: &str,
    machine_fingerprint: &MachineFingerprint,
    now: DateTime<Utc>,
) -> Result<CustomerKeyUnlock, SkeyStatus> {
    let path = app_root.join(CUSTOMER_KEY_FILE);
    let bytes = fs::read(&path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            SkeyStatus::LicenseMissing
        } else {
            SkeyStatus::LicenseSignature
        }
    })?;
    let mut value: Value =
        serde_json::from_slice(&bytes).map_err(|_| SkeyStatus::LicenseSignature)?;
    verify_customer_key_signature(&value, server_public_key)?;
    let mut key_file: CustomerKeyFile =
        serde_json::from_value(value.clone()).map_err(|_| SkeyStatus::LicenseSignature)?;
    validate_customer_key_claims(
        &key_file,
        payload_path,
        expected_product_id,
        expected_package_id,
        requested_feature,
        now,
    )?;
    let package_key = decode_package_key(&key_file.package_key_b64)?;
    let binding = match key_file.binding.clone() {
        Some(binding) => {
            verify_binding_hmac(&binding, &key_file, &package_key)?;
            let machine_match = machine_fingerprint.match_certificate_hash(
                &binding.device_hash,
                key_file.device_score_policy.pass_score,
                key_file.device_score_policy.review_score,
            );
            if !machine_match.passed {
                return Err(SkeyStatus::MachineMismatch);
            }
            binding
        }
        None => {
            let binding = new_binding(machine_fingerprint, &key_file, &package_key, now)?;
            value["binding"] = serde_json::to_value(&binding).map_err(|_| SkeyStatus::Internal)?;
            fs::write(
                &path,
                canonical_json_bytes(&value).map_err(|_| SkeyStatus::Internal)?,
            )
            .map_err(|_| SkeyStatus::Internal)?;
            key_file.binding = Some(binding.clone());
            binding
        }
    };

    Ok(CustomerKeyUnlock {
        cert: synthesize_activation_cert(&key_file, &binding),
        activation_id: key_file.activation_id,
        package_key,
    })
}

fn verify_customer_key_signature(
    value: &Value,
    server_public_key: &[u8],
) -> Result<(), SkeyStatus> {
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
    let signing_bytes = customer_key_signing_bytes(value)?;
    verifying_key
        .verify(&signing_bytes, &signature)
        .map_err(|_| SkeyStatus::LicenseSignature)
}

fn customer_key_signing_bytes(value: &Value) -> Result<Vec<u8>, SkeyStatus> {
    let mut signing_value = value.clone();
    let object = signing_value
        .as_object_mut()
        .ok_or(SkeyStatus::LicenseSignature)?;
    object.remove("signature");
    object.remove("binding");
    canonical_json_bytes(&signing_value).map_err(|_| SkeyStatus::LicenseSignature)
}

fn validate_customer_key_claims(
    key_file: &CustomerKeyFile,
    payload_path: &Path,
    expected_product_id: &str,
    expected_package_id: &str,
    requested_feature: &str,
    now: DateTime<Utc>,
) -> Result<(), SkeyStatus> {
    if key_file.schema != CUSTOMER_KEY_SCHEMA
        || key_file.product_id != expected_product_id
        || key_file.package_id != expected_package_id
    {
        return Err(SkeyStatus::PackageTampered);
    }
    if !package_hash_matches(payload_path, &key_file.package_hash)? {
        return Err(SkeyStatus::PackageTampered);
    }
    if now < parse_utc(&key_file.not_before)? {
        return Err(SkeyStatus::ClockRollback);
    }
    if !key_file.perpetual {
        let expire_at = key_file
            .expire_at
            .as_deref()
            .ok_or(SkeyStatus::LicenseSignature)
            .and_then(parse_utc)?;
        if now >= expire_at {
            return Err(SkeyStatus::LicenseExpired);
        }
        let lease_until = key_file
            .lease_until
            .as_deref()
            .ok_or(SkeyStatus::LicenseSignature)
            .and_then(parse_utc)?;
        if now > lease_until + Duration::hours(key_file.offline_grace_hours) {
            return Err(SkeyStatus::LeaseExpired);
        }
    }
    if !key_file
        .features
        .iter()
        .any(|feature| feature.enabled && feature.code == requested_feature)
    {
        return Err(SkeyStatus::FeatureDenied);
    }
    Ok(())
}

fn decode_package_key(value: &str) -> Result<Zeroizing<[u8; 32]>, SkeyStatus> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| SkeyStatus::DecryptFailed)?;
    if bytes.len() != 32 {
        return Err(SkeyStatus::DecryptFailed);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn new_binding(
    machine_fingerprint: &MachineFingerprint,
    key_file: &CustomerKeyFile,
    package_key: &[u8; 32],
    now: DateTime<Utc>,
) -> Result<CustomerKeyBinding, SkeyStatus> {
    let mut binding = CustomerKeyBinding {
        schema: CUSTOMER_KEY_BINDING_SCHEMA.to_owned(),
        device_hash: machine_fingerprint.device_hash(),
        bound_at: now.to_rfc3339_opts(SecondsFormat::Secs, true),
        hmac: String::new(),
    };
    binding.hmac = URL_SAFE_NO_PAD.encode(binding_hmac(&binding, key_file, package_key)?);
    Ok(binding)
}

fn verify_binding_hmac(
    binding: &CustomerKeyBinding,
    key_file: &CustomerKeyFile,
    package_key: &[u8; 32],
) -> Result<(), SkeyStatus> {
    if binding.schema != CUSTOMER_KEY_BINDING_SCHEMA {
        return Err(SkeyStatus::LicenseSignature);
    }
    let supplied = URL_SAFE_NO_PAD
        .decode(&binding.hmac)
        .map_err(|_| SkeyStatus::LicenseSignature)?;
    let expected = binding_hmac(binding, key_file, package_key)?;
    if supplied != expected {
        return Err(SkeyStatus::LicenseSignature);
    }
    Ok(())
}

fn binding_hmac(
    binding: &CustomerKeyBinding,
    key_file: &CustomerKeyFile,
    package_key: &[u8; 32],
) -> Result<Vec<u8>, SkeyStatus> {
    let value = json!({
        "schema": binding.schema,
        "product_id": key_file.product_id,
        "package_id": key_file.package_id,
        "package_hash": key_file.package_hash,
        "activation_id": key_file.activation_id,
        "device_hash": binding.device_hash,
        "bound_at": binding.bound_at,
    });
    let bytes = canonical_json_bytes(&value).map_err(|_| SkeyStatus::LicenseSignature)?;
    let hmac_key = Sha256::digest([CUSTOMER_KEY_BINDING_INFO, b"\0", package_key].concat());
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(&hmac_key).map_err(|_| SkeyStatus::LicenseSignature)?;
    mac.update(&bytes);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn synthesize_activation_cert(
    key_file: &CustomerKeyFile,
    binding: &CustomerKeyBinding,
) -> ActivationCert {
    ActivationCert {
        product_id: key_file.product_id.clone(),
        package_id: key_file.package_id.clone(),
        package_hash: key_file.package_hash.clone(),
        device_hash: binding.device_hash.clone(),
        device_score_policy: key_file.device_score_policy.clone(),
        features: key_file.features.clone(),
        not_before: key_file.not_before.clone(),
        expire_at: key_file
            .expire_at
            .clone()
            .unwrap_or_else(|| PERPETUAL_UTC.to_owned()),
        lease_until: key_file
            .lease_until
            .clone()
            .unwrap_or_else(|| PERPETUAL_UTC.to_owned()),
        offline_grace_hours: key_file.offline_grace_hours,
        wrapped_pkg_key: Value::Null,
        kid: key_file.kid.clone(),
        signature: key_file.signature.clone(),
    }
}
