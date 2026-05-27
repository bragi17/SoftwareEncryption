use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;

use crate::container::CryptoError;

pub(crate) fn verify_manifest_signature(
    manifest_value: &Value,
    verifying_key: &VerifyingKey,
) -> Result<(), CryptoError> {
    let signature_hex = manifest_value
        .get("signature")
        .and_then(|signature| signature.get("sig"))
        .and_then(Value::as_str)
        .ok_or(CryptoError::MalformedManifest)?;
    let signature_bytes = decode_hex(signature_hex)?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| CryptoError::MalformedManifest)?;
    let signature = Signature::from_bytes(&signature_array);
    verifying_key
        .verify(&manifest_signing_bytes(manifest_value)?, &signature)
        .map_err(|_| CryptoError::Signature)
}

pub(crate) fn manifest_signing_bytes(manifest_value: &Value) -> Result<Vec<u8>, CryptoError> {
    let mut signing_manifest = manifest_value.clone();
    signing_manifest
        .get_mut("signature")
        .and_then(|signature| signature.get_mut("sig"))
        .map(|sig| *sig = Value::String(String::new()))
        .ok_or(CryptoError::MalformedManifest)?;
    serde_json::to_vec(&signing_manifest).map_err(CryptoError::Json)
}

pub(crate) fn decode_hex(value: &str) -> Result<Vec<u8>, CryptoError> {
    if !value.as_bytes().chunks_exact(2).remainder().is_empty() {
        return Err(CryptoError::MalformedManifest);
    }

    let mut decoded = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks_exact(2) {
        let high = hex_value(chunk[0])?;
        let low = hex_value(chunk[1])?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

fn hex_value(value: u8) -> Result<u8, CryptoError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(CryptoError::MalformedManifest),
    }
}
