//! Cryptographic container support for SKP payloads.

mod container;
mod keywrap;
mod manifest;
mod signing;

pub use container::{read_container, Container, CryptoError};
pub use keywrap::derive_file_key;
pub use manifest::{BlobManifest, BlobTableEntry, Manifest};

#[cfg(test)]
mod tests {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use std::fs;

    use crate::{derive_file_key, read_container, CryptoError};

    const PACKAGE_KEY: [u8; 32] = [7; 32];

    #[test]
    fn hkdf_derivation_is_deterministic_and_scoped_by_blob() {
        let first = derive_file_key(&PACKAGE_KEY, "pkg_1", "py:alpha.py", "1.2.0");
        let second = derive_file_key(&PACKAGE_KEY, "pkg_1", "py:alpha.py", "1.2.0");
        let other_blob = derive_file_key(&PACKAGE_KEY, "pkg_1", "py:beta.py", "1.2.0");

        assert_eq!(first, second);
        assert_ne!(first, other_blob);
        assert_eq!(first.len(), 32);
    }

    #[test]
    fn read_container_verifies_manifest_signature_and_decrypts_blob() {
        let signing_key = SigningKey::from_bytes(&[3; 32]);
        let package_path = write_test_package(signing_key.clone(), b"secret module");

        let container = read_container(&package_path, &signing_key.verifying_key()).unwrap();
        let plaintext = container.decrypt_blob("py:alpha.py", &PACKAGE_KEY).unwrap();

        assert_eq!(container.manifest.product_id, "prod_x");
        assert_eq!(plaintext, b"secret module");
    }

    #[test]
    fn read_container_rejects_wrong_manifest_signature() {
        let signing_key = SigningKey::from_bytes(&[3; 32]);
        let other_key = SigningKey::from_bytes(&[4; 32]);
        let package_path = write_test_package(signing_key, b"secret module");

        let err = read_container(&package_path, &other_key.verifying_key()).unwrap_err();

        assert!(matches!(err, CryptoError::Signature));
    }

    #[test]
    fn decrypt_blob_rejects_tampered_ciphertext() {
        let signing_key = SigningKey::from_bytes(&[3; 32]);
        let package_path = write_test_package(signing_key.clone(), b"secret module");
        let mut bytes = fs::read(&package_path).unwrap();
        let last = bytes.last_mut().unwrap();
        *last ^= 0x80;
        fs::write(&package_path, bytes).unwrap();

        let container = read_container(&package_path, &signing_key.verifying_key()).unwrap();
        let err = container
            .decrypt_blob("py:alpha.py", &PACKAGE_KEY)
            .unwrap_err();

        assert!(matches!(err, CryptoError::DecryptFailed));
    }

    #[test]
    fn read_container_rejects_wrong_magic() {
        let signing_key = SigningKey::from_bytes(&[3; 32]);
        let package_path = write_test_package(signing_key.clone(), b"secret module");
        let mut bytes = fs::read(&package_path).unwrap();
        bytes[0] = b'X';
        fs::write(&package_path, bytes).unwrap();

        let err = read_container(&package_path, &signing_key.verifying_key()).unwrap_err();

        assert!(matches!(err, CryptoError::WrongMagic));
    }

    #[test]
    fn read_container_rejects_unsupported_manifest_format() {
        let signing_key = SigningKey::from_bytes(&[3; 32]);
        let package_path = write_custom_test_package(
            signing_key.clone(),
            b"secret module",
            TestPackageOptions {
                format: "BAD1",
                ..TestPackageOptions::default()
            },
        );

        let err = read_container(&package_path, &signing_key.verifying_key()).unwrap_err();

        assert!(matches!(err, CryptoError::UnsupportedFormat));
    }

    #[test]
    fn read_container_rejects_duplicate_nonce_for_same_blob_key() {
        let signing_key = SigningKey::from_bytes(&[3; 32]);
        let package_path = write_custom_test_package(
            signing_key.clone(),
            b"secret module",
            TestPackageOptions {
                duplicate_blob: true,
                ..TestPackageOptions::default()
            },
        );

        let err = read_container(&package_path, &signing_key.verifying_key()).unwrap_err();

        assert!(matches!(err, CryptoError::DuplicateNonce));
    }

    #[test]
    fn read_container_rejects_blob_offsets_outside_file() {
        let signing_key = SigningKey::from_bytes(&[3; 32]);
        let package_path = write_custom_test_package(
            signing_key.clone(),
            b"secret module",
            TestPackageOptions {
                offset: 4096,
                ..TestPackageOptions::default()
            },
        );

        let err = read_container(&package_path, &signing_key.verifying_key()).unwrap_err();

        assert!(matches!(err, CryptoError::BlobOffset));
    }

    #[test]
    fn read_container_rejects_wrong_crypto_contract_metadata() {
        let cases = [
            TestPackageOptions {
                crypto_aead: "AES-128-GCM",
                ..TestPackageOptions::default()
            },
            TestPackageOptions {
                crypto_kdf: "PBKDF2-SHA256",
                ..TestPackageOptions::default()
            },
            TestPackageOptions {
                crypto_signature: "ECDSA-P256",
                ..TestPackageOptions::default()
            },
            TestPackageOptions {
                nonce_policy: "unique-random-96-bit-per-blob-key",
                ..TestPackageOptions::default()
            },
            TestPackageOptions {
                signature_alg: "Ed448",
                ..TestPackageOptions::default()
            },
        ];

        for options in cases {
            let signing_key = SigningKey::from_bytes(&[3; 32]);
            let package_path =
                write_custom_test_package(signing_key.clone(), b"secret module", options);

            let err = read_container(&package_path, &signing_key.verifying_key()).unwrap_err();

            assert!(matches!(err, CryptoError::UnsupportedCrypto));
        }
    }

    #[test]
    fn read_container_rejects_manifest_aad_that_does_not_match_signed_fields() {
        let signing_key = SigningKey::from_bytes(&[3; 32]);
        let package_path = write_custom_test_package(
            signing_key.clone(),
            b"secret module",
            TestPackageOptions {
                aad_override: Some("prod_x|pkg_1|py:alpha.py|1.2.0|bad_hash"),
                ..TestPackageOptions::default()
            },
        );

        let err = read_container(&package_path, &signing_key.verifying_key()).unwrap_err();

        assert!(matches!(err, CryptoError::AadMismatch));
    }

    fn write_test_package(signing_key: SigningKey, plaintext: &[u8]) -> std::path::PathBuf {
        write_custom_test_package(signing_key, plaintext, TestPackageOptions::default())
    }

    #[derive(Clone, Copy)]
    struct TestPackageOptions {
        format: &'static str,
        crypto_aead: &'static str,
        crypto_kdf: &'static str,
        crypto_signature: &'static str,
        nonce_policy: &'static str,
        signature_alg: &'static str,
        duplicate_blob: bool,
        offset: usize,
        aad_override: Option<&'static str>,
    }

    impl Default for TestPackageOptions {
        fn default() -> Self {
            Self {
                format: "SKP1",
                crypto_aead: "AES-256-GCM",
                crypto_kdf: "HKDF-SHA256",
                crypto_signature: "Ed25519",
                nonce_policy: "random_96bit_per_blob",
                signature_alg: "Ed25519",
                duplicate_blob: false,
                offset: 0,
                aad_override: None,
            }
        }
    }

    fn write_custom_test_package(
        signing_key: SigningKey,
        plaintext: &[u8],
        options: TestPackageOptions,
    ) -> std::path::PathBuf {
        let temp_dir = tempfile::tempdir().unwrap().keep();
        let path = temp_dir.join("payload.skp");
        let package_id = "pkg_1";
        let blob_id = "py:alpha.py";
        let version = "1.2.0";
        let plain_hash = sha256_hex(plaintext);
        let encryption_aad = format!("prod_x|{package_id}|{blob_id}|{version}|{plain_hash}");
        let manifest_aad = options.aad_override.unwrap_or(&encryption_aad);
        let nonce = [9u8; 12];
        let key = derive_file_key(&PACKAGE_KEY, package_id, blob_id, version);
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: encryption_aad.as_bytes(),
                },
            )
            .unwrap();
        let blob_entry = json!({
            "blob_id": blob_id,
            "type": "python",
            "original_path": "alpha.py",
            "offset": options.offset,
            "cipher_len": ciphertext.len(),
            "plain_len": plaintext.len(),
            "nonce": hex(&nonce),
            "aad": manifest_aad,
            "sha256_plain": plain_hash,
            "feature": "RUN_MAIN"
        });
        let manifest_blobs = if options.duplicate_blob {
            json!([blob_entry.clone(), blob_entry])
        } else {
            json!([blob_entry])
        };
        let mut manifest = json!({
            "format": options.format,
            "product_id": "prod_x",
            "package_id": package_id,
            "version": version,
            "created_at": "2026-05-25T00:00:00Z",
            "builder_version": "0.1.0",
            "min_runtime_version": "0.1.0",
            "crypto": {
                "aead": options.crypto_aead,
                "kdf": options.crypto_kdf,
                "signature": options.crypto_signature,
                "nonce_policy": options.nonce_policy
            },
            "entrypoints": [],
            "blobs": manifest_blobs,
            "runtime": {"required_dlls": []},
            "signature": {
                "kid": "vendor_sign_2026_01",
                "alg": options.signature_alg,
                "sig": ""
            }
        });
        let signature = signing_key.sign(&manifest_signing_bytes(&manifest));
        manifest["signature"]["sig"] = Value::String(hex(&signature.to_bytes()));

        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let blob_table_bytes = serde_json::to_vec(&json!([{
            "blob_id": blob_id,
            "offset": options.offset,
            "cipher_len": ciphertext.len()
        }]))
        .unwrap();
        let mut package = Vec::new();
        package.extend_from_slice(b"SKP1");
        package.extend_from_slice(&1u16.to_le_bytes());
        package.extend_from_slice(&26u32.to_le_bytes());
        package.extend_from_slice(&(manifest_bytes.len() as u64).to_le_bytes());
        package.extend_from_slice(&(blob_table_bytes.len() as u64).to_le_bytes());
        package.extend_from_slice(&manifest_bytes);
        package.extend_from_slice(&blob_table_bytes);
        package.extend_from_slice(&ciphertext);
        fs::write(&path, package).unwrap();
        path
    }

    fn manifest_signing_bytes(manifest: &Value) -> Vec<u8> {
        let mut signing_manifest = manifest.clone();
        signing_manifest["signature"]["sig"] = Value::String(String::new());
        serde_json::to_vec(&signing_manifest).unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
        encoded
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex(&Sha256::digest(bytes))
    }

}
