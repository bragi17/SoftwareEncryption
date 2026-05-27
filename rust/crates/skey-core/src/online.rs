use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::errors::SkeyStatus;
use crate::license::{
    canonical_json_bytes, cert_signing_bytes, read_activation_cert, verify_activation_cert_bytes,
};
use crate::machine::MachineFingerprint;
use crate::session::activation_claim;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OnlinePolicyConfig {
    pub server_url: String,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Clone, Debug)]
pub struct OnlinePolicyClient {
    config: OnlinePolicyConfig,
}

#[derive(Clone, Debug)]
pub struct LeaseRefreshRequest {
    pub product_id: String,
    pub package_id: String,
    pub activation_id: String,
    pub device_hash: String,
}

#[derive(Clone, Debug)]
pub struct LeaseRefresh {
    pub lease_until: String,
}

#[derive(Clone, Debug)]
pub struct RevocationCheck {
    pub product_id: String,
    pub package_id: String,
    pub license_id: String,
    pub activation_id: String,
}

#[derive(Clone, Debug)]
pub struct RevocationStatus {
    pub revoked: bool,
}

impl OnlinePolicyClient {
    pub fn new(config: OnlinePolicyConfig) -> Self {
        Self { config }
    }

    pub fn fetch_signed_time(&self, public_key: &[u8]) -> Result<DateTime<Utc>, SkeyStatus> {
        let response = self.get_json("/time")?;
        let signed = response
            .get("server_time")
            .ok_or(SkeyStatus::LicenseSignature)?;
        verify_signed_json(signed, public_key, "skey-server-time-v1")?;
        let server_time = signed
            .get("server_time")
            .and_then(Value::as_str)
            .ok_or(SkeyStatus::LicenseSignature)?;
        parse_utc(server_time)
    }

    pub fn fetch_revocation_status(
        &self,
        check: &RevocationCheck,
        public_key: &[u8],
    ) -> Result<RevocationStatus, SkeyStatus> {
        let path = format!(
            "/revocations?product_id={}&package_id={}&license_id={}&activation_id={}",
            url_component(&check.product_id),
            url_component(&check.package_id),
            url_component(&check.license_id),
            url_component(&check.activation_id),
        );
        let response = self.get_json(&path)?;
        let signed = response
            .get("revocations")
            .or_else(|| response.get("revocation_list"))
            .ok_or(SkeyStatus::LicenseSignature)?;
        verify_signed_json(signed, public_key, "skey-revocations-v1")?;
        let revoked = signed
            .get("revocations")
            .and_then(Value::as_array)
            .ok_or(SkeyStatus::LicenseSignature)?
            .iter()
            .any(|entry| {
                let license_matches = entry
                    .get("license_id")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value == check.license_id);
                let activation = entry.get("activation_id").and_then(Value::as_str);
                license_matches
                    && (activation.is_none() || activation == Some(check.activation_id.as_str()))
            });
        Ok(RevocationStatus { revoked })
    }

    pub fn refresh_lease_and_persist(
        &self,
        license_dir: &Path,
        request: &LeaseRefreshRequest,
        public_key: &[u8],
    ) -> Result<LeaseRefresh, SkeyStatus> {
        let response = self.post_json(
            "/lease/refresh",
            &json!({
                "product_id": request.product_id,
                "package_id": request.package_id,
                "activation_id": request.activation_id,
                "device_hash": request.device_hash,
            }),
        )?;
        let cert = response
            .get("cert")
            .or_else(|| response.get("activation_cert"))
            .ok_or(SkeyStatus::LicenseSignature)?;
        let cert_bytes = canonical_json_bytes(cert).map_err(|_| SkeyStatus::LicenseSignature)?;
        let parsed = verify_activation_cert_bytes(&cert_bytes, public_key)?;
        fs::create_dir_all(license_dir).map_err(|_| SkeyStatus::Internal)?;
        fs::write(license_dir.join("activation.cert"), cert_bytes)
            .map_err(|_| SkeyStatus::Internal)?;
        Ok(LeaseRefresh {
            lease_until: parsed.lease_until,
        })
    }

    fn get_json(&self, path: &str) -> Result<Value, SkeyStatus> {
        self.request_json("GET", path, None)
    }

    fn post_json(&self, path: &str, body: &Value) -> Result<Value, SkeyStatus> {
        self.request_json("POST", path, Some(body))
    }

    fn request_json(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, SkeyStatus> {
        let url = HttpUrl::parse(&self.config.server_url)?;
        let body_bytes = body
            .map(canonical_json_bytes)
            .transpose()
            .map_err(|_| SkeyStatus::Internal)?
            .unwrap_or_default();
        let request_path = url.join_path(path);
        let mut stream =
            TcpStream::connect((url.host.as_str(), url.port)).map_err(|_| SkeyStatus::Internal)?;
        let timeout = Duration::from_millis(self.config.timeout_ms.max(1));
        stream
            .set_read_timeout(Some(timeout))
            .and_then(|_| stream.set_write_timeout(Some(timeout)))
            .map_err(|_| SkeyStatus::Internal)?;
        write!(
            stream,
            "{method} {request_path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            url.host,
            body_bytes.len(),
        )
        .map_err(|_| SkeyStatus::Internal)?;
        if !body_bytes.is_empty() {
            stream
                .write_all(&body_bytes)
                .map_err(|_| SkeyStatus::Internal)?;
        }
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|_| SkeyStatus::Internal)?;
        parse_http_json(&response)
    }
}

pub fn read_online_policy(app_root: &Path) -> Result<Option<OnlinePolicyConfig>, SkeyStatus> {
    let path = app_root.join(".secure").join("online-policy.json");
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(SkeyStatus::PackageTampered),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| SkeyStatus::PackageTampered)
}

pub fn apply_runtime_online_policy(
    config: &OnlinePolicyConfig,
    license_dir: &Path,
    public_key: &[u8],
    machine_fingerprint: &MachineFingerprint,
) -> Result<DateTime<Utc>, SkeyStatus> {
    let cert = read_activation_cert(license_dir, public_key)?;
    let license_id = activation_claim(license_dir, "license_id")?;
    let activation_id = activation_claim(license_dir, "activation_id")?;
    let client = OnlinePolicyClient::new(config.clone());
    let server_time = client.fetch_signed_time(public_key)?;
    let revocation = client.fetch_revocation_status(
        &RevocationCheck {
            product_id: cert.product_id.clone(),
            package_id: cert.package_id.clone(),
            license_id,
            activation_id: activation_id.clone(),
        },
        public_key,
    )?;
    if revocation.revoked {
        return Err(SkeyStatus::FeatureDenied);
    }
    match client.refresh_lease_and_persist(
        license_dir,
        &LeaseRefreshRequest {
            product_id: cert.product_id,
            package_id: cert.package_id,
            activation_id,
            device_hash: machine_fingerprint.device_hash(),
        },
        public_key,
    ) {
        Ok(_) | Err(SkeyStatus::Internal) | Err(SkeyStatus::ProcessLaunch) => {}
        Err(status) => return Err(status),
    }
    Ok(server_time)
}

fn verify_signed_json(value: &Value, public_key: &[u8], schema: &str) -> Result<(), SkeyStatus> {
    if value.get("schema").and_then(Value::as_str) != Some(schema) {
        return Err(SkeyStatus::LicenseSignature);
    }
    let signature_value = value
        .get("signature")
        .and_then(Value::as_str)
        .ok_or(SkeyStatus::LicenseSignature)?;
    let signature_bytes = decode_b64url(signature_value, SkeyStatus::LicenseSignature)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| SkeyStatus::LicenseSignature)?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| SkeyStatus::LicenseSignature)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| SkeyStatus::LicenseSignature)?;
    verifying_key
        .verify(&cert_signing_bytes(value)?, &signature)
        .map_err(|_| SkeyStatus::LicenseSignature)
}

fn parse_http_json(response: &[u8]) -> Result<Value, SkeyStatus> {
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(SkeyStatus::Internal)?;
    let headers = std::str::from_utf8(&response[..separator]).map_err(|_| SkeyStatus::Internal)?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or(SkeyStatus::Internal)?;
    if !(200..300).contains(&status) {
        return Err(SkeyStatus::ProcessLaunch);
    }
    serde_json::from_slice(&response[separator + 4..]).map_err(|_| SkeyStatus::Internal)
}

fn parse_utc(value: &str) -> Result<DateTime<Utc>, SkeyStatus> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| SkeyStatus::LicenseSignature)
}

fn url_component(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn decode_b64url(value: &str, status: SkeyStatus) -> Result<Vec<u8>, SkeyStatus> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .map_err(|_| status)
}

fn default_timeout_ms() -> u64 {
    1500
}

#[derive(Clone, Debug)]
struct HttpUrl {
    host: String,
    port: u16,
    path: String,
}

impl HttpUrl {
    fn parse(value: &str) -> Result<Self, SkeyStatus> {
        let rest = value
            .strip_prefix("http://")
            .ok_or(SkeyStatus::InvalidArgument)?;
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (
                host.to_owned(),
                port.parse::<u16>()
                    .map_err(|_| SkeyStatus::InvalidArgument)?,
            ),
            None => (authority.to_owned(), 80),
        };
        if host.is_empty() {
            return Err(SkeyStatus::InvalidArgument);
        }
        Ok(Self {
            host,
            port,
            path: format!("/{path}").trim_end_matches('/').to_owned(),
        })
    }

    fn join_path(&self, path: &str) -> String {
        let suffix = path.strip_prefix('/').unwrap_or(path);
        if self.path.is_empty() || self.path == "/" {
            format!("/{suffix}")
        } else {
            format!("{}/{}", self.path, suffix)
        }
    }
}
