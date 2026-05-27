use std::collections::BTreeMap;
use std::env;
use std::process::Command;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::license::{canonical_json_bytes, hex_lower};

const DEVICE_HASH_PREFIX: &str = "skey-fp-v1:";

const FIELD_WEIGHTS: [(&str, u16); 6] = [
    ("machine_id", 40),
    ("volume_id", 20),
    ("mac_set", 15),
    ("cpu_brand", 10),
    ("os_install_id", 10),
    ("hostname", 5),
];

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MachineFingerprint {
    fields: BTreeMap<String, String>,
}

impl MachineFingerprint {
    pub fn from_hashed_fields<const N: usize>(fields: [(&str, &str); N]) -> Self {
        Self {
            fields: fields
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
        }
    }

    pub fn collect() -> Self {
        Self::from_hashed_fields([
            (
                "machine_id",
                &hash_field("machine_id", &machine_id_source()),
            ),
            ("volume_id", &hash_field("volume_id", &volume_id_source())),
            ("mac_set", &hash_field("mac_set", &mac_set_source())),
            ("cpu_brand", &hash_field("cpu_brand", &cpu_brand_source())),
            (
                "os_install_id",
                &hash_field("os_install_id", &os_install_id_source()),
            ),
            ("hostname", &hash_field("hostname", &hostname_source())),
        ])
    }

    pub fn device_hash(&self) -> String {
        let value = serde_json::to_value(&self.fields).expect("BTreeMap serializes");
        let bytes = canonical_json_bytes(&value).expect("BTreeMap serializes");
        format!("{DEVICE_HASH_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn match_certificate_hash(
        &self,
        certificate_device_hash: &str,
        pass_score: u16,
        review_score: u16,
    ) -> MachineMatch {
        let score = if let Some(encoded) = certificate_device_hash.strip_prefix(DEVICE_HASH_PREFIX)
        {
            score_structured_fields(self, encoded)
        } else if certificate_device_hash == self.aggregate_hash()
            || certificate_device_hash == format!("sha256:{}", self.aggregate_hash())
        {
            100
        } else {
            0
        };
        MachineMatch {
            score,
            passed: score >= pass_score,
            review: score >= review_score && score < pass_score,
        }
    }

    fn aggregate_hash(&self) -> String {
        let value = serde_json::to_value(&self.fields).expect("BTreeMap serializes");
        let bytes = canonical_json_bytes(&value).expect("BTreeMap serializes");
        hex_lower(Sha256::digest(bytes))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MachineMatch {
    pub score: u16,
    pub passed: bool,
    pub review: bool,
}

fn score_structured_fields(current: &MachineFingerprint, encoded: &str) -> u16 {
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(encoded) else {
        return 0;
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return 0;
    };
    let Some(expected) = value.as_object() else {
        return 0;
    };
    FIELD_WEIGHTS
        .iter()
        .filter_map(|(name, weight)| {
            let current_value = current.fields.get(*name)?;
            let expected_value = expected.get(*name)?.as_str()?;
            (current_value == expected_value).then_some(*weight)
        })
        .sum()
}

fn hash_field(field: &str, value: &str) -> String {
    let fallback;
    let stable_value = if value.is_empty() {
        fallback = format!("{}:{}:unavailable", env::consts::OS, field);
        &fallback
    } else {
        value
    };
    let mut hasher = Sha256::new();
    hasher.update(field.as_bytes());
    hasher.update(b"\0");
    hasher.update(stable_value.as_bytes());
    hex_lower(hasher.finalize())
}

fn machine_id_source() -> String {
    #[cfg(target_os = "windows")]
    {
        registry_machine_guid()
            .or_else(env_machine_guid)
            .unwrap_or_default()
    }
    #[cfg(target_os = "linux")]
    {
        read_first_existing(["/etc/machine-id", "/var/lib/dbus/machine-id"]).unwrap_or_default()
    }
    #[cfg(target_os = "macos")]
    {
        command_output("ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"])
            .and_then(|output| parse_ioreg_uuid(&output))
            .unwrap_or_default()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        env::consts::OS.to_owned()
    }
}

fn volume_id_source() -> String {
    #[cfg(target_os = "windows")]
    {
        let drive = env::var("SystemDrive").unwrap_or_else(|_| "C:".to_owned());
        command_output("cmd", &["/C", &format!("vol {drive}")])
            .map(|output| output.lines().collect::<Vec<_>>().join(" "))
            .unwrap_or(drive)
    }
    #[cfg(unix)]
    {
        unix_root_device_id().unwrap_or_else(|| "/".to_owned())
    }
    #[cfg(not(any(target_os = "windows", unix)))]
    {
        env::consts::OS.to_owned()
    }
}

fn mac_set_source() -> String {
    let mut candidates = Vec::new();
    #[cfg(target_os = "windows")]
    {
        if let Some(output) = command_output("getmac", &["/fo", "csv", "/nh"]) {
            candidates.extend(extract_mac_addresses(&output));
        }
        if candidates.is_empty() {
            if let Some(output) = command_output("ipconfig", &["/all"]) {
                candidates.extend(extract_mac_addresses(&output));
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Some(output) = command_output("ip", &["link"]) {
            candidates.extend(extract_mac_addresses(&output));
        }
        if candidates.is_empty() {
            if let Some(output) = command_output("ifconfig", &["-a"]) {
                candidates.extend(extract_mac_addresses(&output));
            }
        }
    }
    candidates.sort();
    candidates.dedup();
    candidates.join("|")
}

fn cpu_brand_source() -> String {
    #[cfg(target_os = "windows")]
    {
        env::var("PROCESSOR_IDENTIFIER")
            .ok()
            .filter(|value| !value.is_empty())
            .or_else(|| command_output("wmic", &["cpu", "get", "name"]).map(clean_command_lines))
            .unwrap_or_else(|| env::consts::ARCH.to_owned())
    }
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|contents| {
                contents.lines().find_map(|line| {
                    line.strip_prefix("model name").and_then(|rest| {
                        rest.split_once(':')
                            .map(|(_, value)| value.trim().to_owned())
                    })
                })
            })
            .unwrap_or_else(|| env::consts::ARCH.to_owned())
    }
    #[cfg(target_os = "macos")]
    {
        command_output("sysctl", &["-n", "machdep.cpu.brand_string"])
            .map(|value| value.trim().to_owned())
            .unwrap_or_else(|| env::consts::ARCH.to_owned())
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        env::consts::ARCH.to_owned()
    }
}

fn os_install_id_source() -> String {
    #[cfg(target_os = "windows")]
    {
        registry_machine_guid()
            .or_else(env_machine_guid)
            .unwrap_or_else(|| env::consts::OS.to_owned())
    }
    #[cfg(target_os = "linux")]
    {
        read_first_existing(["/etc/machine-id", "/var/lib/dbus/machine-id"])
            .or_else(|| {
                std::fs::read_to_string("/etc/os-release")
                    .ok()
                    .map(clean_command_lines)
            })
            .unwrap_or_else(|| env::consts::OS.to_owned())
    }
    #[cfg(target_os = "macos")]
    {
        command_output("sw_vers", &["-productVersion"])
            .unwrap_or_else(|| env::consts::OS.to_owned())
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        env::consts::OS.to_owned()
    }
}

fn hostname_source() -> String {
    env::var("COMPUTERNAME")
        .or_else(|_| env::var("HOSTNAME"))
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| command_output("hostname", &[]).map(|value| value.trim().to_owned()))
        .unwrap_or_default()
}

#[cfg(target_os = "windows")]
fn registry_machine_guid() -> Option<String> {
    let output = command_output(
        "reg",
        &[
            "query",
            r"HKLM\SOFTWARE\Microsoft\Cryptography",
            "/v",
            "MachineGuid",
        ],
    )?;
    output
        .lines()
        .find(|line| line.contains("MachineGuid"))
        .and_then(|line| line.split_whitespace().last())
        .map(str::to_owned)
}

#[cfg(target_os = "windows")]
fn env_machine_guid() -> Option<String> {
    env::var("MachineGuid")
        .or_else(|_| env::var("SKEY_MACHINE_GUID"))
        .ok()
        .filter(|value| !value.is_empty())
}

#[cfg(unix)]
fn unix_root_device_id() -> Option<String> {
    use std::os::unix::fs::MetadataExt;

    std::fs::metadata("/").ok().map(|metadata| {
        format!(
            "dev:{}:ino:{}:mode:{}",
            metadata.dev(),
            metadata.ino(),
            metadata.mode()
        )
    })
}

#[cfg(target_os = "linux")]
fn read_first_existing<const N: usize>(paths: [&str; N]) -> Option<String> {
    paths.into_iter().find_map(|path| {
        std::fs::read_to_string(path)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    })
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn clean_command_lines(value: String) -> String {
    value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("|")
}

fn extract_mac_addresses(value: &str) -> Vec<String> {
    value
        .split(|ch: char| !(ch.is_ascii_hexdigit() || ch == ':' || ch == '-'))
        .filter_map(normalize_mac_address)
        .collect()
}

fn normalize_mac_address(value: &str) -> Option<String> {
    let compact: String = value
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .map(|ch| ch.to_ascii_lowercase())
        .collect();
    (compact.len() == 12 && compact != "000000000000").then_some(compact)
}

#[cfg(target_os = "macos")]
fn parse_ioreg_uuid(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        line.split_once("IOPlatformUUID")
            .and_then(|(_, rest)| rest.split('"').nth(2))
            .map(str::to_owned)
    })
}

#[cfg(test)]
mod tests {
    use super::{MachineFingerprint, FIELD_WEIGHTS};

    #[test]
    fn structured_device_hash_scores_weighted_matches() {
        let cert = MachineFingerprint::from_hashed_fields([
            ("machine_id", "a"),
            ("volume_id", "b"),
            ("mac_set", "c"),
            ("cpu_brand", "d"),
            ("os_install_id", "e"),
            ("hostname", "f"),
        ]);
        let current = MachineFingerprint::from_hashed_fields([
            ("machine_id", "a"),
            ("volume_id", "b"),
            ("mac_set", "changed"),
            ("cpu_brand", "d"),
            ("os_install_id", "changed"),
            ("hostname", "f"),
        ]);

        let result = current.match_certificate_hash(&cert.device_hash(), 70, 50);

        assert_eq!(result.score, 75);
        assert!(result.passed);
        assert!(!result.review);
    }

    #[test]
    fn score_between_review_and_pass_marks_review_without_passing() {
        let cert = MachineFingerprint::from_hashed_fields([
            ("machine_id", "a"),
            ("volume_id", "b"),
            ("mac_set", "c"),
            ("cpu_brand", "d"),
            ("os_install_id", "e"),
            ("hostname", "f"),
        ]);
        let current = MachineFingerprint::from_hashed_fields([
            ("machine_id", "a"),
            ("volume_id", "b"),
            ("mac_set", "changed"),
            ("cpu_brand", "changed"),
            ("os_install_id", "changed"),
            ("hostname", "changed"),
        ]);

        let result = current.match_certificate_hash(&cert.device_hash(), 70, 50);

        assert_eq!(result.score, 60);
        assert!(!result.passed);
        assert!(result.review);
    }

    #[test]
    fn collect_returns_all_weighted_fields_as_hashes() {
        let fingerprint = MachineFingerprint::collect();

        for (field, _) in FIELD_WEIGHTS {
            let value = fingerprint
                .fields
                .get(field)
                .expect("weighted field exists");
            assert_eq!(value.len(), 64);
            assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }

        let hostname = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_default();
        if !hostname.is_empty() {
            assert_ne!(fingerprint.fields["hostname"], hostname);
        }
    }
}
