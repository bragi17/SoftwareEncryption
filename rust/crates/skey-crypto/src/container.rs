use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ed25519_dalek::VerifyingKey;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::keywrap::derive_file_key;
use crate::manifest::{BlobChunkManifest, BlobManifest, BlobTableEntry, Manifest};
use crate::signing::{decode_hex, verify_manifest_signature};

const MAGIC: &[u8; 4] = b"SKP1";
const HEADER_VERSION: u16 = 1;
const HEADER_LEN: usize = 26;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid SKP header")]
    Header,
    #[error("wrong SKP magic")]
    WrongMagic,
    #[error("unsupported manifest format")]
    UnsupportedFormat,
    #[error("unsupported crypto contract metadata")]
    UnsupportedCrypto,
    #[error("malformed manifest")]
    MalformedManifest,
    #[error("manifest AAD does not match signed blob metadata")]
    AadMismatch,
    #[error("manifest signature verification failed")]
    Signature,
    #[error("duplicate nonce under the same blob key")]
    DuplicateNonce,
    #[error("blob offset outside file")]
    BlobOffset,
    #[error("blob not found")]
    BlobNotFound,
    #[error("blob decryption failed")]
    DecryptFailed,
}

#[derive(Clone, Debug)]
pub struct Container {
    pub manifest: Manifest,
    pub blob_table: Vec<BlobTableEntry>,
    encrypted_blobs: Vec<u8>,
    blob_by_id: HashMap<String, BlobManifest>,
}

pub fn read_container(
    path: impl AsRef<Path>,
    verifying_key: &VerifyingKey,
) -> Result<Container, CryptoError> {
    let package = fs::read(path)?;
    if package.len() < HEADER_LEN {
        return Err(CryptoError::Header);
    }
    if &package[0..4] != MAGIC {
        return Err(CryptoError::WrongMagic);
    }

    let header_version = u16::from_le_bytes(package[4..6].try_into().unwrap());
    let header_len = u32::from_le_bytes(package[6..10].try_into().unwrap()) as usize;
    let manifest_len = usize::try_from(u64::from_le_bytes(package[10..18].try_into().unwrap()))
        .map_err(|_| CryptoError::Header)?;
    let blob_table_len = usize::try_from(u64::from_le_bytes(package[18..26].try_into().unwrap()))
        .map_err(|_| CryptoError::Header)?;
    if header_version != HEADER_VERSION || header_len != HEADER_LEN {
        return Err(CryptoError::Header);
    }

    let manifest_start = header_len;
    let manifest_end = checked_add(manifest_start, manifest_len)?;
    let blob_table_end = checked_add(manifest_end, blob_table_len)?;
    if blob_table_end > package.len() {
        return Err(CryptoError::Header);
    }

    let manifest_bytes = &package[manifest_start..manifest_end];
    let manifest_value: serde_json::Value = serde_json::from_slice(manifest_bytes)?;
    verify_manifest_signature(&manifest_value, verifying_key)?;
    let manifest: Manifest = serde_json::from_value(manifest_value)?;
    if manifest.format != "SKP1" {
        return Err(CryptoError::UnsupportedFormat);
    }
    validate_crypto_contract(&manifest)?;

    let blob_table: Vec<BlobTableEntry> =
        serde_json::from_slice(&package[manifest_end..blob_table_end])?;
    let encrypted_blobs = package[blob_table_end..].to_vec();
    let blob_by_id = validate_blobs(&manifest, &blob_table, encrypted_blobs.len())?;

    Ok(Container {
        manifest,
        blob_table,
        encrypted_blobs,
        blob_by_id,
    })
}

impl Container {
    pub fn decrypt_blob(
        &self,
        blob_id: &str,
        package_key: &[u8; 32],
    ) -> Result<Vec<u8>, CryptoError> {
        let blob = self
            .blob_by_id
            .get(blob_id)
            .ok_or(CryptoError::BlobNotFound)?;
        if is_chunked_blob(blob) {
            return self.decrypt_chunked_blob(blob, package_key);
        }
        let start = blob.offset as usize;
        let end = blob_range_end(start, blob.cipher_len as usize)?;
        let ciphertext = self
            .encrypted_blobs
            .get(start..end)
            .ok_or(CryptoError::BlobOffset)?;
        let nonce = decode_hex(
            blob.nonce
                .as_deref()
                .ok_or(CryptoError::MalformedManifest)?,
        )?;
        if nonce.len() != 12 {
            return Err(CryptoError::MalformedManifest);
        }
        let expected_aad = expected_blob_aad(&self.manifest, blob);
        if blob.aad != expected_aad {
            return Err(CryptoError::AadMismatch);
        }
        let key = Zeroizing::new(derive_file_key(
            package_key,
            &self.manifest.package_id,
            &blob.blob_id,
            &self.manifest.version,
        ));
        let cipher =
            Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| CryptoError::DecryptFailed)?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: blob.aad.as_bytes(),
                },
            )
            .map_err(|_| CryptoError::DecryptFailed)?;

        if plaintext.len() != blob.plain_len as usize || sha256_hex(&plaintext) != blob.sha256_plain
        {
            return Err(CryptoError::DecryptFailed);
        }

        Ok(plaintext)
    }

    pub fn decrypt_blob_range(
        &self,
        blob_id: &str,
        package_key: &[u8; 32],
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        let blob = self
            .blob_by_id
            .get(blob_id)
            .ok_or(CryptoError::BlobNotFound)?;
        if len == 0 || offset >= blob.plain_len {
            return Ok(Vec::new());
        }
        let available = blob.plain_len - offset;
        let requested = u64::try_from(len).map_err(|_| CryptoError::BlobOffset)?;
        let output_len = available.min(requested);

        if !is_chunked_blob(blob) {
            let plaintext = self.decrypt_blob(blob_id, package_key)?;
            let start = usize::try_from(offset).map_err(|_| CryptoError::BlobOffset)?;
            let end = start
                .checked_add(usize::try_from(output_len).map_err(|_| CryptoError::BlobOffset)?)
                .ok_or(CryptoError::BlobOffset)?;
            return Ok(plaintext[start..end].to_vec());
        }

        let chunk_size = blob.chunk_size.ok_or(CryptoError::MalformedManifest)?;
        let start_chunk = offset / chunk_size;
        let end_offset = offset
            .checked_add(output_len)
            .ok_or(CryptoError::BlobOffset)?;
        let end_chunk = (end_offset - 1) / chunk_size;
        let mut output =
            Vec::with_capacity(usize::try_from(output_len).map_err(|_| CryptoError::BlobOffset)?);
        for chunk_index in start_chunk..=end_chunk {
            let chunk = blob
                .chunks
                .get(usize::try_from(chunk_index).map_err(|_| CryptoError::BlobOffset)?)
                .ok_or(CryptoError::MalformedManifest)?;
            let chunk_plaintext =
                self.decrypt_chunk(chunk, blob, package_key, chunk_index as usize)?;
            let chunk_plain_start = chunk_index
                .checked_mul(chunk_size)
                .ok_or(CryptoError::BlobOffset)?;
            let copy_start = offset.saturating_sub(chunk_plain_start);
            let copy_end = end_offset
                .min(chunk_plain_start + chunk.plain_len)
                .saturating_sub(chunk_plain_start);
            let copy_start = usize::try_from(copy_start).map_err(|_| CryptoError::BlobOffset)?;
            let copy_end = usize::try_from(copy_end).map_err(|_| CryptoError::BlobOffset)?;
            output.extend_from_slice(&chunk_plaintext[copy_start..copy_end]);
        }
        Ok(output)
    }

    fn decrypt_chunked_blob(
        &self,
        blob: &BlobManifest,
        package_key: &[u8; 32],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut plaintext = Vec::with_capacity(
            usize::try_from(blob.plain_len).map_err(|_| CryptoError::BlobOffset)?,
        );
        for (chunk_index, chunk) in blob.chunks.iter().enumerate() {
            plaintext.extend(self.decrypt_chunk(chunk, blob, package_key, chunk_index)?);
        }
        if plaintext.len() != blob.plain_len as usize || sha256_hex(&plaintext) != blob.sha256_plain
        {
            return Err(CryptoError::DecryptFailed);
        }
        Ok(plaintext)
    }

    fn decrypt_chunk(
        &self,
        chunk: &BlobChunkManifest,
        blob: &BlobManifest,
        package_key: &[u8; 32],
        chunk_index: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        let start = chunk.offset as usize;
        let end = blob_range_end(start, chunk.cipher_len as usize)?;
        let ciphertext = self
            .encrypted_blobs
            .get(start..end)
            .ok_or(CryptoError::BlobOffset)?;
        let nonce = decode_hex(&chunk.nonce)?;
        if nonce.len() != 12 {
            return Err(CryptoError::MalformedManifest);
        }
        let file_key = Zeroizing::new(derive_file_key(
            package_key,
            &self.manifest.package_id,
            &blob.blob_id,
            &self.manifest.version,
        ));
        let chunk_key = Zeroizing::new(derive_chunk_key(
            file_key.as_ref(),
            &blob.blob_id,
            chunk_index,
        )?);
        let cipher = Aes256Gcm::new_from_slice(chunk_key.as_ref())
            .map_err(|_| CryptoError::DecryptFailed)?;
        let chunk_aad = chunk_aad(&blob.aad, chunk_index);
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: chunk_aad.as_bytes(),
                },
            )
            .map_err(|_| CryptoError::DecryptFailed)?;
        if plaintext.len() != chunk.plain_len as usize {
            return Err(CryptoError::DecryptFailed);
        }
        Ok(plaintext)
    }
}

fn validate_crypto_contract(manifest: &Manifest) -> Result<(), CryptoError> {
    if manifest.crypto.aead != "AES-256-GCM"
        || manifest.crypto.kdf != "HKDF-SHA256"
        || manifest.crypto.signature != "Ed25519"
        || manifest.crypto.nonce_policy != "random_96bit_per_blob"
        || manifest.signature.alg != "Ed25519"
    {
        return Err(CryptoError::UnsupportedCrypto);
    }
    Ok(())
}

fn expected_blob_aad(manifest: &Manifest, blob: &BlobManifest) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        manifest.product_id, manifest.package_id, blob.blob_id, manifest.version, blob.sha256_plain
    )
}

fn validate_blobs(
    manifest: &Manifest,
    blob_table: &[BlobTableEntry],
    encrypted_len: usize,
) -> Result<HashMap<String, BlobManifest>, CryptoError> {
    let mut table_by_id = HashMap::with_capacity(blob_table.len());
    for entry in blob_table {
        if table_by_id.insert(&entry.blob_id, entry).is_some() {
            return Err(CryptoError::MalformedManifest);
        }
        validate_range(entry.offset, entry.cipher_len, encrypted_len)?;
    }

    let mut nonce_by_key = HashSet::new();
    let mut blob_by_id = HashMap::with_capacity(manifest.blobs.len());
    for blob in &manifest.blobs {
        let expected_aad = expected_blob_aad(manifest, blob);
        if blob.aad != expected_aad {
            return Err(CryptoError::AadMismatch);
        }
        validate_range(blob.offset, blob.cipher_len, encrypted_len)?;
        let table_entry = table_by_id
            .get(&blob.blob_id)
            .ok_or(CryptoError::MalformedManifest)?;
        if table_entry.offset != blob.offset || table_entry.cipher_len != blob.cipher_len {
            return Err(CryptoError::MalformedManifest);
        }
        if is_chunked_blob(blob) {
            validate_chunked_blob(manifest, blob, encrypted_len, &mut nonce_by_key)?;
        } else {
            validate_unchunked_blob(manifest, blob, &mut nonce_by_key)?;
        }
        if blob_by_id
            .insert(blob.blob_id.clone(), blob.clone())
            .is_some()
        {
            return Err(CryptoError::MalformedManifest);
        }
    }

    if blob_by_id.len() != table_by_id.len() {
        return Err(CryptoError::MalformedManifest);
    }

    Ok(blob_by_id)
}

fn validate_unchunked_blob(
    manifest: &Manifest,
    blob: &BlobManifest,
    nonce_by_key: &mut HashSet<(String, String, String, Vec<u8>)>,
) -> Result<(), CryptoError> {
    if blob.chunk_size.is_some() || blob.chunk_count.is_some() || !blob.chunks.is_empty() {
        return Err(CryptoError::MalformedManifest);
    }
    let nonce = decode_hex(
        blob.nonce
            .as_deref()
            .ok_or(CryptoError::MalformedManifest)?,
    )?;
    if nonce.len() != 12 {
        return Err(CryptoError::MalformedManifest);
    }
    let key_scope = (
        manifest.package_id.clone(),
        manifest.version.clone(),
        blob.blob_id.clone(),
        nonce,
    );
    if !nonce_by_key.insert(key_scope) {
        return Err(CryptoError::DuplicateNonce);
    }
    Ok(())
}

fn validate_chunked_blob(
    manifest: &Manifest,
    blob: &BlobManifest,
    encrypted_len: usize,
    nonce_by_key: &mut HashSet<(String, String, String, Vec<u8>)>,
) -> Result<(), CryptoError> {
    if blob.nonce.is_some() {
        return Err(CryptoError::MalformedManifest);
    }
    let chunk_size = blob.chunk_size.ok_or(CryptoError::MalformedManifest)?;
    let chunk_count = blob.chunk_count.ok_or(CryptoError::MalformedManifest)?;
    if chunk_size == 0 || chunk_count == 0 || chunk_count as usize != blob.chunks.len() {
        return Err(CryptoError::MalformedManifest);
    }
    let mut expected_plain_offset = 0u64;
    let mut expected_cipher_offset = blob.offset;
    let blob_end = blob
        .offset
        .checked_add(blob.cipher_len)
        .ok_or(CryptoError::BlobOffset)?;
    for (index, chunk) in blob.chunks.iter().enumerate() {
        let nonce = decode_hex(&chunk.nonce)?;
        if nonce.len() != 12 {
            return Err(CryptoError::MalformedManifest);
        }
        let key_scope = (
            manifest.package_id.clone(),
            manifest.version.clone(),
            blob.blob_id.clone(),
            nonce,
        );
        if !nonce_by_key.insert(key_scope) {
            return Err(CryptoError::DuplicateNonce);
        }
        if chunk.plain_len == 0 || chunk.plain_len > chunk_size {
            return Err(CryptoError::MalformedManifest);
        }
        if index + 1 != blob.chunks.len() && chunk.plain_len != chunk_size {
            return Err(CryptoError::MalformedManifest);
        }
        validate_range(chunk.offset, chunk.cipher_len, encrypted_len)?;
        if chunk.offset != expected_cipher_offset
            || chunk.offset < blob.offset
            || chunk
                .offset
                .checked_add(chunk.cipher_len)
                .ok_or(CryptoError::BlobOffset)?
                > blob_end
        {
            return Err(CryptoError::MalformedManifest);
        }
        expected_plain_offset = expected_plain_offset
            .checked_add(chunk.plain_len)
            .ok_or(CryptoError::BlobOffset)?;
        expected_cipher_offset = expected_cipher_offset
            .checked_add(chunk.cipher_len)
            .ok_or(CryptoError::BlobOffset)?;
    }
    if expected_plain_offset != blob.plain_len || expected_cipher_offset != blob_end {
        return Err(CryptoError::MalformedManifest);
    }
    Ok(())
}

fn validate_range(offset: u64, len: u64, encrypted_len: usize) -> Result<(), CryptoError> {
    let start = usize::try_from(offset).map_err(|_| CryptoError::BlobOffset)?;
    let len = usize::try_from(len).map_err(|_| CryptoError::BlobOffset)?;
    let end = blob_range_end(start, len)?;
    if end > encrypted_len {
        return Err(CryptoError::BlobOffset);
    }
    Ok(())
}

fn checked_add(left: usize, right: usize) -> Result<usize, CryptoError> {
    left.checked_add(right).ok_or(CryptoError::Header)
}

fn blob_range_end(start: usize, len: usize) -> Result<usize, CryptoError> {
    start.checked_add(len).ok_or(CryptoError::BlobOffset)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(hex_char(byte >> 4));
        encoded.push(hex_char(byte & 0x0f));
    }
    encoded
}

fn is_chunked_blob(blob: &BlobManifest) -> bool {
    blob.chunk_size.is_some() || blob.chunk_count.is_some() || !blob.chunks.is_empty()
}

fn derive_chunk_key(
    file_key: &[u8],
    blob_id: &str,
    chunk_index: usize,
) -> Result<[u8; 32], CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(blob_id.as_bytes()), file_key);
    let mut output = [0u8; 32];
    hkdf.expand(format!("chunk|{chunk_index}").as_bytes(), &mut output)
        .map_err(|_| CryptoError::DecryptFailed)?;
    Ok(output)
}

fn chunk_aad(blob_aad: &str, chunk_index: usize) -> String {
    format!("{blob_aad}|chunk|{chunk_index}")
}

fn hex_char(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + value - 10) as char,
        _ => unreachable!("nibble is always in range"),
    }
}
