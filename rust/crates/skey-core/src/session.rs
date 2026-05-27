use std::fs;
use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};

use crate::errors::SkeyStatus;
use crate::license::{package_hash_matches, read_activation_cert, read_client_key, ActivationCert};
use crate::machine::MachineFingerprint;
use crate::time_state::{read_state, write_state_atomic, StateUpdate, TrustedTimeState};

#[derive(Debug)]
pub struct LocalPolicyInput<'a> {
    pub product_root: &'a Path,
    pub payload_path: &'a Path,
    pub license_dir: &'a Path,
    pub expected_product_id: &'a str,
    pub expected_package_id: &'a str,
    pub requested_feature: &'a str,
    pub server_public_key: &'a [u8],
    pub machine_fingerprint: &'a MachineFingerprint,
    pub state_hmac_key: &'a [u8],
    pub trusted_server_utc: Option<DateTime<Utc>>,
    pub local_utc: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyDecision {
    pub status: SkeyStatus,
    pub machine_score: Option<u16>,
    pub machine_review: bool,
}

pub fn evaluate_local_policy(input: &LocalPolicyInput<'_>) -> PolicyDecision {
    match evaluate(input) {
        Ok(decision) => decision,
        Err(decision) => decision,
    }
}

fn evaluate(input: &LocalPolicyInput<'_>) -> Result<PolicyDecision, PolicyDecision> {
    let cert = read_activation_cert(input.license_dir, input.server_public_key).map_err(fail)?;

    if cert.product_id != input.expected_product_id || cert.package_id != input.expected_package_id
    {
        return Err(fail(SkeyStatus::PackageTampered));
    }

    if !package_hash_matches(input.payload_path, &cert.package_hash).map_err(fail)? {
        return Err(fail(SkeyStatus::PackageTampered));
    }

    let machine_match = input.machine_fingerprint.match_certificate_hash(
        &cert.device_hash,
        cert.device_score_policy.pass_score,
        cert.device_score_policy.review_score,
    );
    if !machine_match.passed {
        return Err(PolicyDecision {
            status: SkeyStatus::MachineMismatch,
            machine_score: Some(machine_match.score),
            machine_review: machine_match.review,
        });
    }

    let client_key = read_client_key(input.license_dir)
        .map_err(|status| with_machine(status, machine_match.score, machine_match.review))?;
    let activation_id = activation_claim(input.license_dir, "activation_id").map_err(fail)?;
    let state_hmac_key = state_protection_key(&client_key, &cert, &activation_id);
    let state = read_state(input.license_dir, &state_hmac_key).map_err(fail)?;
    if state.is_none() && input.trusted_server_utc.is_none() {
        return Err(with_machine(
            SkeyStatus::ClockRollback,
            machine_match.score,
            machine_match.review,
        ));
    }
    validate_state_binding(
        state.as_ref(),
        input.expected_product_id,
        input.expected_package_id,
        &activation_id,
        &cert.package_hash,
    )
    .map_err(fail)?;
    if is_clock_rollback(input.trusted_server_utc, input.local_utc, state.as_ref()) {
        return Err(PolicyDecision {
            status: SkeyStatus::ClockRollback,
            machine_score: Some(machine_match.score),
            machine_review: machine_match.review,
        });
    }

    let current_utc = trusted_time(input, state.as_ref());
    if current_utc < cert.not_before_utc().map_err(fail)? {
        return Err(with_machine(
            SkeyStatus::ClockRollback,
            machine_match.score,
            machine_match.review,
        ));
    }
    if current_utc >= cert.expire_at_utc().map_err(fail)? {
        return Err(with_machine(
            SkeyStatus::LicenseExpired,
            machine_match.score,
            machine_match.review,
        ));
    }
    let lease_deadline =
        cert.lease_until_utc().map_err(fail)? + Duration::hours(cert.offline_grace_hours);
    if current_utc > lease_deadline {
        return Err(with_machine(
            SkeyStatus::LeaseExpired,
            machine_match.score,
            machine_match.review,
        ));
    }

    if !cert.enables_feature(input.requested_feature) {
        return Err(with_machine(
            SkeyStatus::FeatureDenied,
            machine_match.score,
            machine_match.review,
        ));
    }

    drop(client_key);

    let update = StateUpdate {
        product_id: cert.product_id.clone(),
        package_id: cert.package_id.clone(),
        activation_id,
        package_hash: cert.package_hash.clone(),
        last_seen_utc: state
            .as_ref()
            .map(|cached| cached.last_seen_utc.max(current_utc))
            .unwrap_or(current_utc),
        last_server_utc: input
            .trusted_server_utc
            .or_else(|| state.as_ref().and_then(|cached| cached.last_server_utc)),
        last_lease_until: cert.lease_until_utc().map_err(fail)?,
        boot_counter: state
            .as_ref()
            .map(|cached| cached.boot_counter.saturating_add(1))
            .unwrap_or(1),
    };
    write_state_atomic(input.license_dir, &update, &state_hmac_key).map_err(fail)?;

    Ok(PolicyDecision {
        status: SkeyStatus::Ok,
        machine_score: Some(machine_match.score),
        machine_review: machine_match.review,
    })
}

fn trusted_time(input: &LocalPolicyInput<'_>, state: Option<&TrustedTimeState>) -> DateTime<Utc> {
    if let Some(server_utc) = input.trusted_server_utc {
        return server_utc;
    }

    state
        .map(|cached| {
            cached
                .last_server_utc
                .unwrap_or(cached.last_seen_utc)
                .max(cached.last_seen_utc)
                .max(input.local_utc)
        })
        .unwrap_or(input.local_utc)
}

fn validate_state_binding(
    state: Option<&TrustedTimeState>,
    expected_product_id: &str,
    expected_package_id: &str,
    expected_activation_id: &str,
    expected_package_hash: &str,
) -> Result<(), SkeyStatus> {
    if let Some(state) = state {
        if state.product_id != expected_product_id
            || state.package_id != expected_package_id
            || state.activation_id != expected_activation_id
            || state.package_hash != expected_package_hash
        {
            return Err(SkeyStatus::PackageTampered);
        }
    }
    Ok(())
}

pub fn state_protection_key(
    client_key: &[u8; 32],
    cert: &ActivationCert,
    activation_id: &str,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"skey-state-hmac-v2");
    hasher.update(b"\0");
    hasher.update(client_key);
    hasher.update(b"\0");
    hasher.update(cert.product_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(cert.package_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(activation_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(cert.package_hash.as_bytes());
    hasher.finalize().to_vec()
}

pub fn activation_claim(license_dir: &Path, claim: &str) -> Result<String, SkeyStatus> {
    let bytes = fs::read(license_dir.join("activation.cert")).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            SkeyStatus::LicenseMissing
        } else {
            SkeyStatus::LicenseSignature
        }
    })?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| SkeyStatus::LicenseSignature)?;
    value
        .get(claim)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or(SkeyStatus::LicenseSignature)
}

fn is_clock_rollback(
    trusted_server_utc: Option<DateTime<Utc>>,
    local_utc: DateTime<Utc>,
    state: Option<&TrustedTimeState>,
) -> bool {
    if trusted_server_utc.is_some() {
        return false;
    }
    state
        .map(|cached| local_utc + Duration::minutes(5) < cached.last_seen_utc)
        .unwrap_or(false)
}

fn fail(status: SkeyStatus) -> PolicyDecision {
    PolicyDecision {
        status,
        machine_score: None,
        machine_review: false,
    }
}

fn with_machine(status: SkeyStatus, score: u16, review: bool) -> PolicyDecision {
    PolicyDecision {
        status,
        machine_score: Some(score),
        machine_review: review,
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use super::{is_clock_rollback, trusted_time, validate_state_binding, LocalPolicyInput};
    use crate::machine::MachineFingerprint;
    use crate::time_state::TrustedTimeState;

    #[test]
    fn trusted_time_prefers_server_then_offline_monotonic_time() {
        let machine = MachineFingerprint::default();
        let state = state_with_server(Some(parse("2026-05-25T09:00:00Z")));
        let policy_input = input(
            &machine,
            Some(parse("2026-05-25T10:00:00Z")),
            parse("2026-05-25T08:00:00Z"),
        );

        assert_eq!(
            trusted_time(&policy_input, Some(&state)),
            parse("2026-05-25T10:00:00Z")
        );

        let input_without_server = input(&machine, None, parse("2026-05-25T11:00:00Z"));
        assert_eq!(
            trusted_time(&input_without_server, Some(&state)),
            parse("2026-05-25T11:00:00Z")
        );

        let rollback_input = input(&machine, None, parse("2026-05-25T08:00:00Z"));
        assert_eq!(
            trusted_time(&rollback_input, Some(&state)),
            parse("2026-05-25T10:00:00Z")
        );
        assert_eq!(
            trusted_time(&input_without_server, None),
            parse("2026-05-25T11:00:00Z")
        );
    }

    #[test]
    fn state_binding_must_match_expected_product_and_package() {
        let state = state_with_server(Some(parse("2026-05-25T09:00:00Z")));

        assert!(
            validate_state_binding(Some(&state), "prod_x", "pkg_1", "act_1", "sha256:abc",).is_ok()
        );
        assert_eq!(
            validate_state_binding(Some(&state), "prod_other", "pkg_1", "act_1", "sha256:abc")
                .unwrap_err(),
            crate::errors::SkeyStatus::PackageTampered
        );
        assert_eq!(
            validate_state_binding(Some(&state), "prod_x", "pkg_other", "act_1", "sha256:abc")
                .unwrap_err(),
            crate::errors::SkeyStatus::PackageTampered
        );
        assert_eq!(
            validate_state_binding(Some(&state), "prod_x", "pkg_1", "act_other", "sha256:abc")
                .unwrap_err(),
            crate::errors::SkeyStatus::PackageTampered
        );
        assert_eq!(
            validate_state_binding(Some(&state), "prod_x", "pkg_1", "act_1", "sha256:other")
                .unwrap_err(),
            crate::errors::SkeyStatus::PackageTampered
        );
    }

    #[test]
    fn local_time_more_than_five_minutes_before_last_seen_is_rollback() {
        let state = state_with_server(None);

        assert!(is_clock_rollback(
            None,
            parse("2026-05-25T09:54:59Z"),
            Some(&state)
        ));
        assert!(!is_clock_rollback(
            None,
            parse("2026-05-25T09:55:00Z"),
            Some(&state)
        ));
    }

    #[test]
    fn trusted_server_time_bypasses_local_rollback_check() {
        let state = state_with_server(Some(parse("2026-05-25T10:00:00Z")));

        assert!(!is_clock_rollback(
            Some(parse("2026-05-25T12:00:00Z")),
            parse("2026-05-25T08:00:00Z"),
            Some(&state)
        ));
    }

    fn input<'a>(
        machine: &'a MachineFingerprint,
        trusted_server_utc: Option<DateTime<Utc>>,
        local_utc: DateTime<Utc>,
    ) -> LocalPolicyInput<'a> {
        LocalPolicyInput {
            product_root: std::path::Path::new("."),
            payload_path: std::path::Path::new("payload.skp"),
            license_dir: std::path::Path::new(".secure/license"),
            expected_product_id: "prod_x",
            expected_package_id: "pkg_1",
            requested_feature: "RUN_MAIN",
            server_public_key: &[],
            machine_fingerprint: machine,
            state_hmac_key: b"state-key",
            trusted_server_utc,
            local_utc,
        }
    }

    fn state_with_server(last_server_utc: Option<DateTime<Utc>>) -> TrustedTimeState {
        TrustedTimeState {
            schema: "skey-state-v1".to_owned(),
            product_id: "prod_x".to_owned(),
            package_id: "pkg_1".to_owned(),
            activation_id: "act_1".to_owned(),
            package_hash: "sha256:abc".to_owned(),
            last_seen_utc: parse("2026-05-25T10:00:00Z"),
            last_server_utc,
            last_lease_until: parse("2026-05-30T00:00:00Z"),
            boot_counter: 1,
            hmac: "unused".to_owned(),
        }
    }

    fn parse(value: &str) -> DateTime<Utc> {
        value.parse().unwrap()
    }
}
