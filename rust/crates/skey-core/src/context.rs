use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use skey_crypto::{read_container, BlobManifest, Container, CryptoError};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::customer_key::unlock_with_customer_key;
use crate::errors::SkeyStatus;
use crate::license::{
    canonical_json_bytes, package_hash_matches, read_activation_cert, read_client_key,
    ActivationCert,
};
use crate::machine::MachineFingerprint;
use crate::session::{activation_claim, evaluate_local_policy, LocalPolicyInput};

const PUBLIC_KEY_SIDECAR: &str = "runtime.manifest.public-key.json";
const RUNTIME_MANIFEST: &str = "runtime.manifest";
const RUNTIME_MANIFEST_SIGNATURE: &str = "runtime.manifest.sig";
const LICENSE_DIR: &str = "license";
const KEY_WRAP_INFO: &[u8] = b"skey-package-key-wrap-v1";
const SESSION_DIR: &str = "sessions";
const SESSION_SCHEMA: &str = "skey-session-v1";
const SESSION_HMAC_INFO: &[u8] = b"skey-session-record-v1";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug)]
pub struct RuntimeInitOptions {
    pub app_root: PathBuf,
    pub payload_path: PathBuf,
    pub entry_id: String,
    pub original_path: String,
    pub argv_json: String,
    pub env_session: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ModuleResolution {
    pub blob_id: String,
    pub virtual_filename: String,
    pub is_package: bool,
}

#[derive(Clone, Debug)]
struct RuntimeManifestVerification {
    status: SkeyStatus,
    schema: Option<String>,
    product_id: Option<String>,
    package_id: Option<String>,
    runtime_version: Option<String>,
    file_count: Option<usize>,
    signature_verified: Option<bool>,
}

impl RuntimeManifestVerification {
    fn verified(manifest: RuntimeManifestFile) -> Self {
        Self {
            status: SkeyStatus::Ok,
            schema: Some(manifest.schema),
            product_id: Some(manifest.product_id),
            package_id: Some(manifest.package_id),
            runtime_version: Some(manifest.runtime_version),
            file_count: Some(manifest.files.len()),
            signature_verified: Some(true),
        }
    }

    fn log_summary(&self) -> String {
        if self.signature_verified == Some(true) {
            format!(
                "verified schema={} product_id={} package_id={} runtime_version={} file_count={}",
                self.schema.as_deref().unwrap_or("unknown"),
                self.product_id.as_deref().unwrap_or("unknown"),
                self.package_id.as_deref().unwrap_or("unknown"),
                self.runtime_version.as_deref().unwrap_or("unknown"),
                self.file_count.unwrap_or_default()
            )
        } else {
            "unavailable".to_owned()
        }
    }
}

#[derive(Debug, Deserialize)]
struct RuntimeManifestFile {
    schema: String,
    product_id: String,
    package_id: String,
    runtime_version: String,
    #[serde(default)]
    files: Vec<RuntimeManifestEntry>,
}

#[derive(Debug, Deserialize)]
struct RuntimeManifestEntry {
    path: String,
    sha256: String,
    role: RuntimeManifestRole,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeManifestRole {
    RuntimeFfi,
    PythonBootstrap,
    PythonStub,
    OnlinePolicy,
    ExeShell,
    JniRuntime,
    JarLoader,
}

#[derive(Debug)]
struct RuntimeLogger {
    path: PathBuf,
    last_status: Option<String>,
}

impl RuntimeLogger {
    fn new(app_root: &Path) -> Self {
        Self {
            path: app_root.join(".secure").join("logs").join("runtime.log"),
            last_status: None,
        }
    }

    fn append_status(&mut self, status: &str) {
        let status = bounded_log_status(status);
        if let Some(parent) = self.path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let line = format!("{} {}\n", Utc::now().to_rfc3339(), status);
        let _ = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut file| file.write_all(line.as_bytes()));
        self.last_status = Some(status);
    }

    fn last_status(&self) -> Option<&str> {
        self.last_status.as_deref()
    }
}

#[derive(Clone, Debug, Default)]
struct ResourceHandles {
    next_handle: u64,
    handles: HashMap<u64, ResourceHandle>,
}

#[derive(Clone, Debug)]
struct ResourceHandle {
    blob_id: String,
}

#[derive(Debug)]
pub struct RuntimeContext {
    app_root: PathBuf,
    payload_path: PathBuf,
    entry_id: String,
    original_path: String,
    argv_json: String,
    container: Container,
    runtime_manifest_verification: RuntimeManifestVerification,
    server_public_key: Vec<u8>,
    license_certificate: Option<ActivationCert>,
    activation_id: Option<String>,
    package_key: Option<Zeroizing<[u8; 32]>>,
    sessions: HashSet<String>,
    resource_handles: ResourceHandles,
    logger: RuntimeLogger,
}

impl RuntimeContext {
    pub fn new(options: RuntimeInitOptions) -> Result<Self, SkeyStatus> {
        if options.app_root.as_os_str().is_empty()
            || options.payload_path.as_os_str().is_empty()
            || options.entry_id.is_empty()
            || options.original_path.is_empty()
            || options.argv_json.is_empty()
        {
            return Err(SkeyStatus::InvalidArgument);
        }

        let server_public_key = read_runtime_public_key(&options.app_root)?;
        // Production runtime builds must embed SKEY_VENDOR_PUBLIC_KEY_SHA256 so
        // the mutable sidecar cannot replace the vendor signing trust root.
        verify_public_key_pin(
            &server_public_key,
            option_env!("SKEY_VENDOR_PUBLIC_KEY_SHA256"),
            cfg!(debug_assertions) || cfg!(test),
        )?;
        let verifying_key =
            VerifyingKey::from_bytes(&to_32(&server_public_key, SkeyStatus::PackageTampered)?)
                .map_err(|_| SkeyStatus::PackageTampered)?;
        let container =
            read_container(&options.payload_path, &verifying_key).map_err(map_container_error)?;
        let runtime_manifest_verification = verify_runtime_manifest(
            &options.app_root,
            &verifying_key,
            &container.manifest.product_id,
            &container.manifest.package_id,
        )?;
        let mut logger = RuntimeLogger::new(&options.app_root);
        logger.append_status(&format!(
            "runtime initialized runtime_manifest={}",
            runtime_manifest_verification.log_summary()
        ));
        let mut context = Self {
            app_root: options.app_root,
            payload_path: options.payload_path,
            entry_id: options.entry_id,
            original_path: options.original_path,
            argv_json: options.argv_json,
            container,
            runtime_manifest_verification,
            server_public_key,
            license_certificate: None,
            activation_id: None,
            package_key: None,
            sessions: HashSet::new(),
            resource_handles: ResourceHandles::default(),
            logger,
        };
        if let Some(session) = &options.env_session {
            if !session.is_empty() {
                context.accept_session(session)?;
            }
        }

        Ok(context)
    }

    pub fn license_check(&mut self, feature_code: &str) -> Result<(), SkeyStatus> {
        if feature_code.is_empty() {
            self.logger.append_status("license status=invalid_argument");
            return Err(SkeyStatus::InvalidArgument);
        }
        let result = self.unlock_feature(feature_code);
        match result {
            Ok(()) => self.logger.append_status("license status=ok"),
            Err(status) => self
                .logger
                .append_status(&format!("license status={}", status.message())),
        }
        result
    }

    pub fn load_entry(&mut self, entry_id: &str) -> Result<Vec<u8>, SkeyStatus> {
        if entry_id.is_empty() {
            return Err(SkeyStatus::InvalidArgument);
        }
        let blob = self.blob_for_entry(entry_id)?;
        self.decrypt_blob(&blob)
    }

    pub fn find_module(&self, module_name: &str) -> Result<Vec<u8>, SkeyStatus> {
        let resolution = self.resolve_module(module_name)?;
        serde_json::to_vec(&json!({
            "blob_id": resolution.blob_id,
            "virtual_filename": resolution.virtual_filename,
            "is_package": resolution.is_package,
        }))
        .map_err(|_| SkeyStatus::Internal)
    }

    pub fn load_module(&mut self, module_name: &str) -> Result<Vec<u8>, SkeyStatus> {
        let resolution = self.resolve_module(module_name)?;
        let blob = self.blob_by_id(&resolution.blob_id)?;
        self.decrypt_blob(&blob)
    }

    pub fn materialize_entry(&mut self, entry_id: &str) -> Result<Vec<u8>, SkeyStatus> {
        if entry_id.is_empty() {
            return Err(SkeyStatus::InvalidArgument);
        }
        self.load_entry(entry_id)
    }

    pub fn create_session(&mut self) -> Result<Vec<u8>, SkeyStatus> {
        let cert = self
            .license_certificate
            .as_ref()
            .ok_or(SkeyStatus::SessionInvalid)?;
        let activation_id = self
            .activation_id
            .clone()
            .map(Ok)
            .unwrap_or_else(|| activation_claim(&self.license_dir(), "activation_id"))?;
        let package_key = self
            .package_key
            .as_ref()
            .ok_or(SkeyStatus::SessionInvalid)?;
        for _ in 0..4 {
            let mut token_bytes = Zeroizing::new([0u8; 32]);
            getrandom::getrandom(token_bytes.as_mut()).map_err(|_| SkeyStatus::Internal)?;
            let token = URL_SAFE_NO_PAD.encode(token_bytes.as_ref());
            if self.sessions.contains(&token) {
                continue;
            }
            let record = session_record_value(
                &token,
                cert,
                &activation_id,
                package_key,
                Utc::now() + Duration::minutes(15),
            )?;
            let path = self.session_path(&token)?;
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|_| SkeyStatus::Internal)?;
            }
            if write_new_private_file(&path, &record).is_ok() {
                self.sessions.insert(token.clone());
                return Ok(token.into_bytes());
            }
        }
        Err(SkeyStatus::Internal)
    }

    pub fn resource_open(&mut self, resource_id: &str) -> Result<u64, SkeyStatus> {
        if resource_id.is_empty() {
            return Err(SkeyStatus::InvalidArgument);
        }
        let blob = self.resource_blob(resource_id)?;
        self.unlock_feature(&blob.feature)?;
        for _ in 0..16 {
            self.resource_handles.next_handle =
                self.resource_handles.next_handle.wrapping_add(1).max(1);
            let handle = self.resource_handles.next_handle;
            if let std::collections::hash_map::Entry::Vacant(entry) =
                self.resource_handles.handles.entry(handle)
            {
                entry.insert(ResourceHandle {
                    blob_id: blob.blob_id,
                });
                return Ok(handle);
            }
        }
        Err(SkeyStatus::Internal)
    }

    pub fn resource_read(
        &mut self,
        handle: u64,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, SkeyStatus> {
        let resource = self
            .resource_handles
            .handles
            .get(&handle)
            .ok_or(SkeyStatus::InvalidArgument)?;
        let blob = self.blob_by_id(&resource.blob_id)?;
        self.unlock_feature(&blob.feature)?;
        let package_key = self.package_key.as_ref().ok_or(SkeyStatus::DecryptFailed)?;
        self.container
            .decrypt_blob_range(&blob.blob_id, package_key, offset, len)
            .map_err(map_decrypt_error)
    }

    pub fn resource_close(&mut self, handle: u64) {
        self.resource_handles.handles.remove(&handle);
    }

    pub fn close_all_resources(&mut self) {
        self.resource_handles.handles.clear();
    }

    pub fn placeholder_state(&self) -> (&str, &str, &str, SkeyStatus, u64, Option<&str>) {
        (
            &self.entry_id,
            &self.original_path,
            &self.argv_json,
            self.runtime_manifest_verification.status,
            self.resource_handles.next_handle,
            self.logger.last_status(),
        )
    }

    fn unlock_feature(&mut self, feature_code: &str) -> Result<(), SkeyStatus> {
        if self
            .license_certificate
            .as_ref()
            .is_some_and(|cert| cert.enables_feature(feature_code))
            && self.package_key.is_some()
        {
            return Ok(());
        }

        let license_dir = self.license_dir();
        let machine_fingerprint = MachineFingerprint::collect();
        let mut trusted_server_utc = None;
        if let Some(policy) = crate::online::read_online_policy(&self.app_root)? {
            match crate::online::apply_runtime_online_policy(
                &policy,
                &license_dir,
                &self.server_public_key,
                &machine_fingerprint,
            ) {
                Ok(server_utc) => trusted_server_utc = Some(server_utc),
                Err(SkeyStatus::Internal)
                | Err(SkeyStatus::ProcessLaunch)
                | Err(SkeyStatus::LicenseMissing) => {}
                Err(status) => return Err(status),
            }
        }
        let policy_input = LocalPolicyInput {
            product_root: &self.app_root,
            payload_path: &self.payload_path,
            license_dir: &license_dir,
            expected_product_id: &self.container.manifest.product_id,
            expected_package_id: &self.container.manifest.package_id,
            requested_feature: feature_code,
            server_public_key: &self.server_public_key,
            machine_fingerprint: &machine_fingerprint,
            state_hmac_key: &[],
            trusted_server_utc,
            local_utc: Utc::now(),
        };
        let decision = evaluate_local_policy(&policy_input);
        if decision.status != SkeyStatus::Ok {
            if decision.status == SkeyStatus::LicenseMissing {
                let unlock = unlock_with_customer_key(
                    &self.app_root,
                    &self.payload_path,
                    &self.server_public_key,
                    &self.container.manifest.product_id,
                    &self.container.manifest.package_id,
                    feature_code,
                    &machine_fingerprint,
                    Utc::now(),
                )?;
                self.activation_id = Some(unlock.activation_id);
                self.license_certificate = Some(unlock.cert);
                self.package_key = Some(unlock.package_key);
                return Ok(());
            }
            return Err(decision.status);
        }

        let cert = read_activation_cert(&license_dir, &self.server_public_key)?;
        let client_key = read_client_key(&license_dir)?;
        let package_key = unwrap_package_key(&cert.wrapped_pkg_key, client_key.as_slice())?;
        let activation_id = activation_claim(&license_dir, "activation_id")?;
        self.activation_id = Some(activation_id);
        self.license_certificate = Some(cert);
        self.package_key = Some(package_key);
        Ok(())
    }

    fn decrypt_blob(&mut self, blob: &BlobManifest) -> Result<Vec<u8>, SkeyStatus> {
        self.unlock_feature(&blob.feature)?;
        let package_key = self.package_key.as_ref().ok_or(SkeyStatus::DecryptFailed)?;
        self.container
            .decrypt_blob(&blob.blob_id, package_key)
            .map_err(map_decrypt_error)
    }

    fn blob_for_entry(&self, entry_id: &str) -> Result<BlobManifest, SkeyStatus> {
        if let Ok(blob) = self.blob_by_id(entry_id) {
            return Ok(blob);
        }
        if let Some(entry) = self
            .container
            .manifest
            .entrypoints
            .iter()
            .find(|entry| entry.id == entry_id)
        {
            let blob_id = format!("py:{}", normalize_manifest_path(&entry.path));
            return self.blob_by_id(&blob_id);
        }
        self.container
            .manifest
            .blobs
            .iter()
            .find(|blob| blob.original_path == entry_id)
            .cloned()
            .ok_or(SkeyStatus::DecryptFailed)
    }

    fn resolve_module(&self, module_name: &str) -> Result<ModuleResolution, SkeyStatus> {
        if module_name.is_empty() {
            return Err(SkeyStatus::InvalidArgument);
        }
        let module_path = module_name.replace('.', "/");
        let package_blob_id = format!("py:{module_path}/__init__.py");
        if let Ok(blob) = self.blob_by_id(&package_blob_id) {
            return Ok(ModuleResolution {
                blob_id: blob.blob_id,
                virtual_filename: blob.original_path,
                is_package: true,
            });
        }
        let module_blob_id = format!("py:{module_path}.py");
        let blob = self.blob_by_id(&module_blob_id)?;
        Ok(ModuleResolution {
            blob_id: blob.blob_id,
            virtual_filename: blob.original_path,
            is_package: false,
        })
    }

    fn blob_by_id(&self, blob_id: &str) -> Result<BlobManifest, SkeyStatus> {
        self.container
            .manifest
            .blobs
            .iter()
            .find(|blob| blob.blob_id == blob_id)
            .cloned()
            .ok_or(SkeyStatus::DecryptFailed)
    }

    fn resource_blob(&self, resource_id: &str) -> Result<BlobManifest, SkeyStatus> {
        let normalized = normalize_manifest_path(resource_id);
        let candidates = if normalized.starts_with("res:") {
            vec![
                normalized.clone(),
                normalized.trim_start_matches("res:").to_owned(),
            ]
        } else {
            vec![format!("res:{normalized}"), normalized.clone()]
        };
        self.container
            .manifest
            .blobs
            .iter()
            .find(|blob| {
                blob.blob_type == "resource"
                    && (candidates
                        .iter()
                        .any(|candidate| candidate == &blob.blob_id)
                        || candidates
                            .iter()
                            .any(|candidate| candidate == &blob.original_path))
            })
            .cloned()
            .ok_or(SkeyStatus::DecryptFailed)
    }

    fn license_dir(&self) -> PathBuf {
        self.app_root.join(".secure").join(LICENSE_DIR)
    }

    fn accept_session(&mut self, token: &str) -> Result<(), SkeyStatus> {
        let license_dir = self.license_dir();
        let (cert, activation_id, package_key) =
            match read_activation_cert(&license_dir, &self.server_public_key) {
                Ok(cert) => {
                    if cert.product_id != self.container.manifest.product_id
                        || cert.package_id != self.container.manifest.package_id
                        || !package_hash_matches(&self.payload_path, &cert.package_hash)?
                    {
                        return Err(SkeyStatus::SessionInvalid);
                    }
                    let client_key = read_client_key(&license_dir)?;
                    let package_key =
                        unwrap_package_key(&cert.wrapped_pkg_key, client_key.as_slice())?;
                    let activation_id = activation_claim(&license_dir, "activation_id")?;
                    (cert, activation_id, package_key)
                }
                Err(SkeyStatus::LicenseMissing) => {
                    let machine_fingerprint = MachineFingerprint::collect();
                    let feature = self.session_customer_key_feature()?;
                    let unlock = unlock_with_customer_key(
                        &self.app_root,
                        &self.payload_path,
                        &self.server_public_key,
                        &self.container.manifest.product_id,
                        &self.container.manifest.package_id,
                        &feature,
                        &machine_fingerprint,
                        Utc::now(),
                    )?;
                    (unlock.cert, unlock.activation_id, unlock.package_key)
                }
                Err(status) => return Err(status),
            };
        verify_session_record(
            &self.session_path(token)?,
            token,
            &cert,
            &activation_id,
            &package_key,
            Utc::now(),
        )?;
        self.activation_id = Some(activation_id);
        self.license_certificate = Some(cert);
        self.package_key = Some(package_key);
        self.sessions.insert(token.to_owned());
        Ok(())
    }

    fn session_customer_key_feature(&self) -> Result<String, SkeyStatus> {
        self.container
            .manifest
            .entrypoints
            .first()
            .map(|entry| entry.feature.clone())
            .or_else(|| {
                self.container
                    .manifest
                    .blobs
                    .first()
                    .map(|blob| blob.feature.clone())
            })
            .filter(|feature| !feature.is_empty())
            .ok_or(SkeyStatus::SessionInvalid)
    }

    fn session_path(&self, token: &str) -> Result<PathBuf, SkeyStatus> {
        if !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(SkeyStatus::SessionInvalid);
        }
        Ok(self
            .app_root
            .join(".secure")
            .join("tmp")
            .join(SESSION_DIR)
            .join(format!("{token}.json")))
    }
}

fn read_runtime_public_key(app_root: &Path) -> Result<Vec<u8>, SkeyStatus> {
    let path = app_root.join(".secure").join(PUBLIC_KEY_SIDECAR);
    let bytes = fs::read(path).map_err(|_| SkeyStatus::PackageTampered)?;
    let sidecar: PublicKeySidecar =
        serde_json::from_slice(&bytes).map_err(|_| SkeyStatus::PackageTampered)?;
    if sidecar.alg != "Ed25519" {
        return Err(SkeyStatus::PackageTampered);
    }
    decode_b64url(&sidecar.public_key, SkeyStatus::PackageTampered)
}

#[derive(Debug, Deserialize, Serialize)]
struct SessionRecord {
    schema: String,
    token_hash: String,
    product_id: String,
    package_id: String,
    activation_id: String,
    package_hash: String,
    features: Vec<String>,
    expires_at: DateTime<Utc>,
    hmac: String,
}

fn session_record_value(
    token: &str,
    cert: &ActivationCert,
    activation_id: &str,
    package_key: &[u8; 32],
    expires_at: DateTime<Utc>,
) -> Result<Vec<u8>, SkeyStatus> {
    let mut record = serde_json::to_value(SessionRecord {
        schema: SESSION_SCHEMA.to_owned(),
        token_hash: sha256_hex(token.as_bytes()),
        product_id: cert.product_id.clone(),
        package_id: cert.package_id.clone(),
        activation_id: activation_id.to_owned(),
        package_hash: cert.package_hash.clone(),
        features: cert
            .features
            .iter()
            .filter(|feature| feature.enabled)
            .map(|feature| feature.code.clone())
            .collect(),
        expires_at,
        hmac: String::new(),
    })
    .map_err(|_| SkeyStatus::Internal)?;
    let mac = session_record_hmac(&record, package_key, activation_id)?;
    record["hmac"] = json!(URL_SAFE_NO_PAD.encode(mac));
    canonical_json_bytes(&record).map_err(|_| SkeyStatus::Internal)
}

fn verify_session_record(
    path: &Path,
    token: &str,
    cert: &ActivationCert,
    activation_id: &str,
    package_key: &[u8; 32],
    now: DateTime<Utc>,
) -> Result<(), SkeyStatus> {
    let bytes = fs::read(path).map_err(|_| SkeyStatus::SessionInvalid)?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| SkeyStatus::SessionInvalid)?;
    let supplied = value
        .get("hmac")
        .and_then(serde_json::Value::as_str)
        .ok_or(SkeyStatus::SessionInvalid)?;
    let supplied = decode_b64url(supplied, SkeyStatus::SessionInvalid)?;
    let expected = session_record_hmac(&value, package_key, activation_id)?;
    if supplied != expected {
        return Err(SkeyStatus::SessionInvalid);
    }
    let record: SessionRecord =
        serde_json::from_value(value).map_err(|_| SkeyStatus::SessionInvalid)?;
    if record.schema != SESSION_SCHEMA
        || record.token_hash != sha256_hex(token.as_bytes())
        || record.product_id != cert.product_id
        || record.package_id != cert.package_id
        || record.activation_id != activation_id
        || record.package_hash != cert.package_hash
        || record.expires_at <= now
    {
        return Err(SkeyStatus::SessionInvalid);
    }
    Ok(())
}

fn session_record_hmac(
    value: &serde_json::Value,
    package_key: &[u8; 32],
    activation_id: &str,
) -> Result<Vec<u8>, SkeyStatus> {
    let mut signing_value = value.clone();
    let object = signing_value
        .as_object_mut()
        .ok_or(SkeyStatus::SessionInvalid)?;
    object.remove("hmac");
    let bytes = canonical_json_bytes(&signing_value).map_err(|_| SkeyStatus::SessionInvalid)?;
    let mut key =
        Vec::with_capacity(package_key.len() + activation_id.len() + SESSION_HMAC_INFO.len());
    key.extend_from_slice(package_key);
    key.extend_from_slice(SESSION_HMAC_INFO);
    key.extend_from_slice(activation_id.as_bytes());
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(&key).map_err(|_| SkeyStatus::SessionInvalid)?;
    mac.update(&bytes);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn write_new_private_file(path: &Path, bytes: &[u8]) -> Result<(), SkeyStatus> {
    #[cfg(target_os = "windows")]
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| SkeyStatus::Internal)?;
        file.write_all(bytes).map_err(|_| SkeyStatus::Internal)?;
        file.sync_all().map_err(|_| SkeyStatus::Internal)?;
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| SkeyStatus::Internal)?;
        file.write_all(bytes).map_err(|_| SkeyStatus::Internal)?;
        file.sync_all().map_err(|_| SkeyStatus::Internal)?;
        Ok(())
    }
}

fn verify_public_key_pin(
    public_key: &[u8],
    expected_pin: Option<&str>,
    allow_unpinned: bool,
) -> Result<(), SkeyStatus> {
    let Some(expected_pin) = expected_pin else {
        return if allow_unpinned {
            Ok(())
        } else {
            Err(SkeyStatus::PackageTampered)
        };
    };
    let expected_pin = expected_pin
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(expected_pin.trim());
    if expected_pin.len() != 64 || !expected_pin.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SkeyStatus::PackageTampered);
    }
    if !expected_pin
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SkeyStatus::PackageTampered);
    }
    if sha256_hex(public_key) == expected_pin {
        Ok(())
    } else {
        Err(SkeyStatus::PackageTampered)
    }
}

#[derive(Debug, Deserialize)]
struct PublicKeySidecar {
    alg: String,
    public_key: String,
}

fn verify_runtime_manifest(
    app_root: &Path,
    verifying_key: &VerifyingKey,
    expected_product_id: &str,
    expected_package_id: &str,
) -> Result<RuntimeManifestVerification, SkeyStatus> {
    let secure_dir = app_root.join(".secure");
    let manifest_path = secure_dir.join(RUNTIME_MANIFEST);
    let signature_path = secure_dir.join(RUNTIME_MANIFEST_SIGNATURE);
    if !manifest_path.exists() || !signature_path.exists() {
        return Err(SkeyStatus::PackageTampered);
    }

    let manifest_bytes = fs::read(&manifest_path).map_err(|_| SkeyStatus::PackageTampered)?;
    let manifest_value: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).map_err(|_| SkeyStatus::PackageTampered)?;
    let manifest: RuntimeManifestFile =
        serde_json::from_value(manifest_value.clone()).map_err(|_| SkeyStatus::PackageTampered)?;
    if manifest.schema != "skey-runtime-manifest-v1"
        || manifest.product_id != expected_product_id
        || manifest.package_id != expected_package_id
    {
        return Err(SkeyStatus::PackageTampered);
    }

    let signature_text =
        fs::read_to_string(&signature_path).map_err(|_| SkeyStatus::PackageTampered)?;
    let signature_bytes = decode_b64url(signature_text.trim(), SkeyStatus::PackageTampered)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| SkeyStatus::PackageTampered)?;
    verifying_key
        .verify(
            &canonical_json_bytes(&manifest_value).map_err(|_| SkeyStatus::PackageTampered)?,
            &signature,
        )
        .map_err(|_| SkeyStatus::PackageTampered)?;
    verify_runtime_manifest_files(app_root, &manifest.files)?;

    Ok(RuntimeManifestVerification::verified(manifest))
}

fn verify_runtime_manifest_files(
    app_root: &Path,
    files: &[RuntimeManifestEntry],
) -> Result<(), SkeyStatus> {
    let canonical_app_root = app_root
        .canonicalize()
        .map_err(|_| SkeyStatus::PackageTampered)?;
    let mut seen_paths = HashSet::new();
    for file in files {
        let relative_path = validate_runtime_manifest_path(&file.path)?;
        match file.role {
            RuntimeManifestRole::RuntimeFfi
            | RuntimeManifestRole::PythonBootstrap
            | RuntimeManifestRole::PythonStub
            | RuntimeManifestRole::OnlinePolicy
            | RuntimeManifestRole::ExeShell
            | RuntimeManifestRole::JniRuntime
            | RuntimeManifestRole::JarLoader => {}
        }
        if !seen_paths.insert(relative_path.clone()) || !is_lower_hex_sha256(&file.sha256) {
            return Err(SkeyStatus::PackageTampered);
        }
        let resolved = canonical_app_root.join(relative_path);
        let canonical_file = resolved
            .canonicalize()
            .map_err(|_| SkeyStatus::PackageTampered)?;
        if !canonical_file.starts_with(&canonical_app_root) {
            return Err(SkeyStatus::PackageTampered);
        }
        let bytes = fs::read(&canonical_file).map_err(|_| SkeyStatus::PackageTampered)?;
        if sha256_hex(&bytes) != file.sha256 {
            return Err(SkeyStatus::PackageTampered);
        }
    }
    Ok(())
}

fn validate_runtime_manifest_path(path: &str) -> Result<PathBuf, SkeyStatus> {
    if path.is_empty() {
        return Err(SkeyStatus::PackageTampered);
    }
    let path = Path::new(path);
    if path.is_absolute() {
        return Err(SkeyStatus::PackageTampered);
    }
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            _ => return Err(SkeyStatus::PackageTampered),
        }
    }
    if clean.as_os_str().is_empty() {
        return Err(SkeyStatus::PackageTampered);
    }
    Ok(clean)
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

fn hex_char(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + value - 10) as char,
        _ => unreachable!("nibble is always in range"),
    }
}

fn unwrap_package_key(
    value: &serde_json::Value,
    client_key: &[u8],
) -> Result<Zeroizing<[u8; 32]>, SkeyStatus> {
    let wrapped: WrappedPackageKey =
        serde_json::from_value(value.clone()).map_err(|_| SkeyStatus::DecryptFailed)?;
    if wrapped.alg != "X25519+HKDF-SHA256+AES-256-GCM" {
        return Err(SkeyStatus::DecryptFailed);
    }
    let client_private_bytes = to_zeroizing_32(client_key, SkeyStatus::DecryptFailed)?;
    let client_private = StaticSecret::from(*client_private_bytes);
    let ephemeral_public = PublicKey::from(to_32(
        &decode_b64url(&wrapped.ephemeral_public, SkeyStatus::DecryptFailed)?,
        SkeyStatus::DecryptFailed,
    )?);
    let shared = client_private.diffie_hellman(&ephemeral_public);
    let hkdf = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut wrapping_key = [0u8; 32];
    hkdf.expand(KEY_WRAP_INFO, &mut wrapping_key)
        .map_err(|_| SkeyStatus::DecryptFailed)?;
    let wrapping_key = Zeroizing::new(wrapping_key);
    let nonce = decode_b64url(&wrapped.nonce, SkeyStatus::DecryptFailed)?;
    if nonce.len() != 12 {
        return Err(SkeyStatus::DecryptFailed);
    }
    let ciphertext = decode_b64url(&wrapped.ciphertext, SkeyStatus::DecryptFailed)?;
    let cipher =
        Aes256Gcm::new_from_slice(wrapping_key.as_ref()).map_err(|_| SkeyStatus::DecryptFailed)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: KEY_WRAP_INFO,
                },
            )
            .map_err(|_| SkeyStatus::DecryptFailed)?,
    );
    to_zeroizing_32(plaintext.as_slice(), SkeyStatus::DecryptFailed)
}

fn bounded_log_status(status: &str) -> String {
    let mut bounded = status.replace(['\r', '\n', '\0'], " ");
    const MAX_STATUS_LEN: usize = 240;
    if bounded.len() > MAX_STATUS_LEN {
        bounded.truncate(MAX_STATUS_LEN);
    }
    bounded
}

fn to_zeroizing_32(bytes: &[u8], status: SkeyStatus) -> Result<Zeroizing<[u8; 32]>, SkeyStatus> {
    if bytes.len() != 32 {
        return Err(status);
    }
    let mut output = Zeroizing::new([0u8; 32]);
    output.copy_from_slice(bytes);
    Ok(output)
}

#[derive(Debug, Deserialize)]
struct WrappedPackageKey {
    alg: String,
    ephemeral_public: String,
    nonce: String,
    ciphertext: String,
}

fn decode_b64url(value: &str, status: SkeyStatus) -> Result<Vec<u8>, SkeyStatus> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .map_err(|_| status)
}

fn to_32(bytes: &[u8], status: SkeyStatus) -> Result<[u8; 32], SkeyStatus> {
    bytes.try_into().map_err(|_| status)
}

fn normalize_manifest_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn map_container_error(error: CryptoError) -> SkeyStatus {
    match error {
        CryptoError::Io(_) => SkeyStatus::PackageTampered,
        CryptoError::Json(_)
        | CryptoError::Header
        | CryptoError::WrongMagic
        | CryptoError::UnsupportedFormat
        | CryptoError::UnsupportedCrypto
        | CryptoError::MalformedManifest
        | CryptoError::AadMismatch
        | CryptoError::Signature
        | CryptoError::DuplicateNonce
        | CryptoError::BlobOffset => SkeyStatus::PackageTampered,
        CryptoError::BlobNotFound | CryptoError::DecryptFailed => SkeyStatus::DecryptFailed,
    }
}

fn map_decrypt_error(error: CryptoError) -> SkeyStatus {
    match error {
        CryptoError::BlobNotFound | CryptoError::DecryptFailed => SkeyStatus::DecryptFailed,
        other => map_container_error(other),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{json, Value};
    use sha2::Digest;

    use super::{session_record_value, verify_session_record, RuntimeContext, RuntimeInitOptions};
    use crate::errors::SkeyStatus;
    use crate::license::canonical_json_bytes;

    const FIXTURE_SIGNING_SEED: [u8; 32] = [
        32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54,
        55, 56, 57, 58, 59, 60, 61, 62, 63,
    ];

    #[test]
    fn init_verifies_runtime_manifest_signature_and_stores_summary() {
        let product = TestProduct::new();
        product.write_runtime_manifest(true);

        let ctx = product.init_context().unwrap();

        assert_eq!(ctx.runtime_manifest_verification.status, SkeyStatus::Ok);
        assert_eq!(
            ctx.runtime_manifest_verification.schema.as_deref(),
            Some("skey-runtime-manifest-v1")
        );
        assert_eq!(
            ctx.runtime_manifest_verification.product_id.as_deref(),
            Some("prod_x")
        );
        assert_eq!(
            ctx.runtime_manifest_verification.package_id.as_deref(),
            Some("pkg_fixture_001")
        );
        assert_eq!(
            ctx.runtime_manifest_verification.runtime_version.as_deref(),
            Some("0.1.0")
        );
        assert_eq!(ctx.runtime_manifest_verification.file_count, Some(1));
        assert_eq!(
            ctx.runtime_manifest_verification.signature_verified,
            Some(true)
        );
    }

    #[test]
    fn init_rejects_missing_runtime_manifest() {
        let product = TestProduct::new();

        assert_eq!(
            product.init_context().unwrap_err(),
            SkeyStatus::PackageTampered
        );
    }

    #[test]
    fn init_rejects_tampered_runtime_manifest_signature() {
        let product = TestProduct::new();
        product.write_runtime_manifest(false);

        assert_eq!(
            product.init_context().unwrap_err(),
            SkeyStatus::PackageTampered
        );
    }

    #[test]
    fn init_rejects_runtime_manifest_hash_mismatch() {
        let product = TestProduct::new();
        product.write_runtime_manifest_with_files(
            true,
            vec![runtime_file(
                ".secure/payload.skp",
                "0".repeat(64),
                "payload",
            )],
        );

        assert_eq!(
            product.init_context().unwrap_err(),
            SkeyStatus::PackageTampered
        );
    }

    #[test]
    fn init_rejects_unknown_runtime_manifest_role() {
        let product = TestProduct::new();
        product.write_runtime_manifest_with_files(
            true,
            vec![runtime_file(
                ".secure/payload.skp",
                sha256_hex(&fs::read(&product.payload_path).unwrap()),
                "runtime_ff1",
            )],
        );

        assert_eq!(
            product.init_context().unwrap_err(),
            SkeyStatus::PackageTampered
        );
    }

    #[test]
    fn init_accepts_signed_python_bootstrap_and_stub_runtime_manifest_roles() {
        let product = TestProduct::new();
        let bootstrap = product.app_root.join("skey_bootstrap.py");
        let stub = product.app_root.join("main.py");
        fs::write(&bootstrap, b"bootstrap").unwrap();
        fs::write(&stub, b"stub").unwrap();
        product.write_runtime_manifest_with_files(
            true,
            vec![
                runtime_file(
                    ".secure/payload.skp",
                    sha256_hex(&fs::read(&product.payload_path).unwrap()),
                    "runtime_ffi",
                ),
                runtime_file(
                    "skey_bootstrap.py",
                    sha256_hex(&fs::read(&bootstrap).unwrap()),
                    "python_bootstrap",
                ),
                runtime_file(
                    "main.py",
                    sha256_hex(&fs::read(&stub).unwrap()),
                    "python_stub",
                ),
            ],
        );

        let ctx = product.init_context().unwrap();

        assert_eq!(ctx.runtime_manifest_verification.file_count, Some(3));
    }

    #[test]
    fn init_rejects_duplicate_runtime_manifest_paths() {
        let product = TestProduct::new();
        let payload_hash = sha256_hex(&fs::read(&product.payload_path).unwrap());
        product.write_runtime_manifest_with_files(
            true,
            vec![
                runtime_file(".secure/payload.skp", payload_hash.clone(), "runtime_ffi"),
                runtime_file(".secure/payload.skp", payload_hash, "runtime_ffi"),
            ],
        );

        assert_eq!(
            product.init_context().unwrap_err(),
            SkeyStatus::PackageTampered
        );
    }

    #[test]
    fn init_rejects_runtime_manifest_path_traversal() {
        let product = TestProduct::new();
        product.write_runtime_manifest_with_files(
            true,
            vec![runtime_file("../escape.txt", "0".repeat(64), "runtime")],
        );

        assert_eq!(
            product.init_context().unwrap_err(),
            SkeyStatus::PackageTampered
        );
    }

    #[test]
    fn public_key_pin_rejects_mismatch() {
        let actual_key = [1u8; 32];
        let mismatched_pin = "00".repeat(32);

        assert_eq!(
            super::verify_public_key_pin(&actual_key, Some(&mismatched_pin), true).unwrap_err(),
            SkeyStatus::PackageTampered
        );
    }

    #[test]
    fn create_session_requires_authorized_package_key() {
        let product = TestProduct::new();
        product.write_runtime_manifest(true);
        let mut ctx = product.init_context().unwrap();

        assert_eq!(
            ctx.create_session().unwrap_err(),
            SkeyStatus::SessionInvalid
        );
    }

    #[test]
    fn session_record_rejects_tamper_cross_package_and_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let token = "session_token";
        let package_key = [7u8; 32];
        let cert = session_cert("pkg_1");
        let path = dir.path().join("session_token.json");
        fs::write(
            &path,
            session_record_value(
                token,
                &cert,
                "ACT-session",
                &package_key,
                "2026-05-25T00:15:00Z".parse().unwrap(),
            )
            .unwrap(),
        )
        .unwrap();

        verify_session_record(
            &path,
            token,
            &cert,
            "ACT-session",
            &package_key,
            "2026-05-25T00:00:00Z".parse().unwrap(),
        )
        .unwrap();

        let mut tampered = fs::read_to_string(&path).unwrap();
        tampered = tampered.replace("pkg_1", "pkg_2");
        fs::write(&path, tampered).unwrap();
        assert_eq!(
            verify_session_record(
                &path,
                token,
                &cert,
                "ACT-session",
                &package_key,
                "2026-05-25T00:00:00Z".parse().unwrap(),
            )
            .unwrap_err(),
            SkeyStatus::SessionInvalid
        );

        fs::write(
            &path,
            session_record_value(
                token,
                &cert,
                "ACT-session",
                &package_key,
                "2026-05-25T00:15:00Z".parse().unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify_session_record(
                &path,
                token,
                &session_cert("pkg_2"),
                "ACT-session",
                &package_key,
                "2026-05-25T00:00:00Z".parse().unwrap(),
            )
            .unwrap_err(),
            SkeyStatus::SessionInvalid
        );
        assert_eq!(
            verify_session_record(
                &path,
                token,
                &cert,
                "ACT-session",
                &package_key,
                "2026-05-25T00:16:00Z".parse().unwrap(),
            )
            .unwrap_err(),
            SkeyStatus::SessionInvalid
        );
    }

    #[test]
    fn init_writes_best_effort_runtime_log_status() {
        let product = TestProduct::new();
        product.write_runtime_manifest(true);

        let _ctx = product.init_context().unwrap();

        let log = fs::read_to_string(product.secure_dir().join("logs").join("runtime.log"))
            .expect("runtime log is written");
        assert!(log.contains("runtime initialized"));
        assert!(log.contains("runtime_manifest=verified"));
    }

    #[test]
    fn license_check_accepts_customer_key_and_binds_current_machine() {
        let product = TestProduct::new();
        product.write_runtime_manifest(true);
        product.write_online_policy();
        product.write_customer_key(true);

        let mut ctx = product.init_context().unwrap();

        ctx.license_check("RUN_MAIN").unwrap();
        let key_file: serde_json::Value =
            serde_json::from_slice(&fs::read(product.app_root.join("skey.key")).unwrap()).unwrap();
        assert!(key_file
            .get("binding")
            .and_then(serde_json::Value::as_object)
            .is_some());
        assert!(key_file["binding"]["device_hash"]
            .as_str()
            .unwrap()
            .starts_with("skey-fp-v1:"));
        assert!(key_file["binding"]["hmac"].as_str().unwrap().len() > 40);
        assert!(!product
            .secure_dir()
            .join("license")
            .join("activation.cert")
            .exists());
    }

    struct TestProduct {
        _temp: tempfile::TempDir,
        app_root: PathBuf,
        payload_path: PathBuf,
    }

    impl TestProduct {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let app_root = temp.path().join("product");
            let secure = app_root.join(".secure");
            fs::create_dir_all(&secure).unwrap();
            let payload_path = secure.join("payload.skp");
            write_fixture_payload(&payload_path);
            write_public_key_sidecar(&secure);
            Self {
                _temp: temp,
                app_root,
                payload_path,
            }
        }

        fn secure_dir(&self) -> PathBuf {
            self.app_root.join(".secure")
        }

        fn write_runtime_manifest(&self, valid_signature: bool) {
            self.write_runtime_manifest_with_files(
                valid_signature,
                vec![runtime_file(
                    ".secure/payload.skp",
                    sha256_hex(&fs::read(&self.payload_path).unwrap()),
                    "runtime_ffi",
                )],
            );
        }

        fn write_runtime_manifest_with_files(
            &self,
            valid_signature: bool,
            files: Vec<serde_json::Value>,
        ) {
            let manifest = json!({
                "schema": "skey-runtime-manifest-v1",
                "product_id": "prod_x",
                "package_id": "pkg_fixture_001",
                "runtime_version": "0.1.0",
                "files": files,
            });
            let manifest_bytes = canonical_json_bytes(&manifest).unwrap();
            fs::write(self.secure_dir().join("runtime.manifest"), &manifest_bytes).unwrap();

            let signing_key = if valid_signature {
                SigningKey::from_bytes(&FIXTURE_SIGNING_SEED)
            } else {
                SigningKey::from_bytes(&[11; 32])
            };
            let signature = signing_key.sign(&manifest_bytes);
            fs::write(
                self.secure_dir().join("runtime.manifest.sig"),
                URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            )
            .unwrap();
        }

        fn write_customer_key(&self, perpetual: bool) {
            let signing_key = SigningKey::from_bytes(&FIXTURE_SIGNING_SEED);
            let now = "2026-05-25T00:00:00Z";
            let mut key_file = json!({
                "schema": "skey-customer-key-v1",
                "license_id": "KEY-prod_x-pkg_fixture_001",
                "activation_id": "KEY-pkg_fixture_001",
                "product_id": "prod_x",
                "package_id": "pkg_fixture_001",
                "package_hash": sha256_hex(&fs::read(&self.payload_path).unwrap()),
                "device_score_policy": {"pass_score": 70, "review_score": 50},
                "features": [{"code": "RUN_MAIN", "enabled": true}],
                "not_before": now,
                "perpetual": perpetual,
                "expire_at": if perpetual { serde_json::Value::Null } else { json!("2026-06-25T00:00:00Z") },
                "lease_until": if perpetual { serde_json::Value::Null } else { json!("2026-06-01T00:00:00Z") },
                "offline_grace_hours": 168,
                "package_key_b64": URL_SAFE_NO_PAD.encode((0u8..32).collect::<Vec<_>>()),
                "kid": "vendor_sign_2026_01",
                "binding": serde_json::Value::Null,
            });
            let mut signing_value = key_file.clone();
            let object = signing_value.as_object_mut().unwrap();
            object.remove("binding");
            object.remove("signature");
            let signature = signing_key.sign(&canonical_json_bytes(&signing_value).unwrap());
            key_file["signature"] = json!(URL_SAFE_NO_PAD.encode(signature.to_bytes()));
            fs::write(
                self.app_root.join("skey.key"),
                canonical_json_bytes(&key_file).unwrap(),
            )
            .unwrap();
        }

        fn write_online_policy(&self) {
            fs::write(
                self.secure_dir().join("online-policy.json"),
                br#"{"server_url":"http://127.0.0.1:9/v1","timeout_ms":1}"#,
            )
            .unwrap();
        }

        fn init_context(&self) -> Result<RuntimeContext, SkeyStatus> {
            RuntimeContext::new(RuntimeInitOptions {
                app_root: self.app_root.clone(),
                payload_path: self.payload_path.clone(),
                entry_id: "py:pkg/alpha.py".to_owned(),
                original_path: "main.py".to_owned(),
                argv_json: "[]".to_owned(),
                env_session: None,
            })
        }
    }

    fn write_public_key_sidecar(secure: &Path) {
        let public_key = SigningKey::from_bytes(&FIXTURE_SIGNING_SEED)
            .verifying_key()
            .to_bytes();
        let value = json!({
            "kid": "vendor_sign_2026_01",
            "alg": "Ed25519",
            "public_key": URL_SAFE_NO_PAD.encode(public_key),
        });
        fs::write(
            secure.join("runtime.manifest.public-key.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
    }

    fn write_fixture_payload(path: &Path) {
        let signing_key = SigningKey::from_bytes(&FIXTURE_SIGNING_SEED);
        let package_key = package_key();
        let blob_id = "py:pkg/alpha.py";
        let package_id = "pkg_fixture_001";
        let version = "0.1.0";
        let plaintext = b"ALPHA = 1\n";
        let plain_hash = sha256_hex(plaintext);
        let encryption_aad = format!("prod_x|{package_id}|{blob_id}|{version}|{plain_hash}");
        let nonce = [9u8; 12];
        let key = skey_crypto::derive_file_key(&package_key, package_id, blob_id, version);
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
        let mut manifest = json!({
            "format": "SKP1",
            "product_id": "prod_x",
            "package_id": package_id,
            "version": version,
            "created_at": "2026-05-25T00:00:00Z",
            "builder_version": "0.1.0",
            "min_runtime_version": "0.1.0",
            "crypto": {
                "aead": "AES-256-GCM",
                "kdf": "HKDF-SHA256",
                "signature": "Ed25519",
                "nonce_policy": "random_96bit_per_blob"
            },
            "entrypoints": [],
            "blobs": [{
                "blob_id": blob_id,
                "type": "python",
                "original_path": "pkg/alpha.py",
                "offset": 0,
                "cipher_len": ciphertext.len(),
                "plain_len": plaintext.len(),
                "nonce": hex(&nonce),
                "aad": encryption_aad,
                "sha256_plain": plain_hash,
                "feature": "RUN_MAIN"
            }],
            "runtime": {"required_dlls": []},
            "signature": {
                "kid": "vendor_sign_2026_01",
                "alg": "Ed25519",
                "sig": ""
            }
        });
        let signature = signing_key.sign(&manifest_signing_bytes(&manifest));
        manifest["signature"]["sig"] = Value::String(hex(&signature.to_bytes()));

        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let blob_table_bytes = serde_json::to_vec(&json!([{
            "blob_id": blob_id,
            "offset": 0,
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
        fs::write(path, package).unwrap();
    }

    fn package_key() -> [u8; 32] {
        std::array::from_fn(|index| index as u8)
    }

    fn manifest_signing_bytes(manifest: &Value) -> Vec<u8> {
        let mut signing_manifest = manifest.clone();
        signing_manifest["signature"]["sig"] = Value::String(String::new());
        serde_json::to_vec(&signing_manifest).unwrap()
    }

    fn runtime_file(path: &str, sha256: String, role: &str) -> serde_json::Value {
        json!({
            "path": path,
            "sha256": sha256,
            "role": role,
        })
    }

    fn session_cert(package_id: &str) -> crate::license::ActivationCert {
        serde_json::from_value(json!({
            "license_id": "LIC-session",
            "activation_id": "ACT-session",
            "product_id": "prod_x",
            "package_id": package_id,
            "package_hash": "sha256:abc",
            "device_hash": "device",
            "device_score_policy": {"pass_score": 0, "review_score": 0},
            "features": [{"code": "RUN_MAIN", "enabled": true}],
            "not_before": "2026-05-01T00:00:00Z",
            "expire_at": "2026-06-01T00:00:00Z",
            "lease_until": "2026-05-30T00:00:00Z",
            "offline_grace_hours": 168,
            "wrapped_pkg_key": {"alg": "test"},
            "kid": "test",
            "signature": "test",
        }))
        .unwrap()
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let digest = sha2::Sha256::digest(bytes);
        hex(&digest)
    }

    fn hex(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push(hex_char(*byte >> 4));
            encoded.push(hex_char(*byte & 0x0f));
        }
        encoded
    }

    fn hex_char(value: u8) -> char {
        match value {
            0..=9 => (b'0' + value) as char,
            10..=15 => (b'a' + value - 10) as char,
            _ => unreachable!("nibble is always in range"),
        }
    }
}
