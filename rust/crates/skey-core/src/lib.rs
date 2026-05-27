//! Core runtime contracts shared by Rust crates and FFI.

pub mod context;
mod customer_key;
pub mod errors;
pub mod license;
pub mod machine;
pub mod online;
pub mod session;
pub mod time_state;

pub use context::{ModuleResolution, RuntimeContext, RuntimeInitOptions};
pub use errors::SkeyStatus;
pub use machine::{MachineFingerprint, MachineMatch};
pub use session::{evaluate_local_policy, LocalPolicyInput, PolicyDecision};

#[cfg(test)]
mod tests {
    use super::errors::SkeyStatus;

    #[test]
    fn status_codes_are_stable() {
        let cases = [
            (SkeyStatus::Ok, 0),
            (SkeyStatus::LicenseMissing, -1001),
            (SkeyStatus::LicenseSignature, -1002),
            (SkeyStatus::MachineMismatch, -1003),
            (SkeyStatus::LicenseExpired, -1004),
            (SkeyStatus::LeaseExpired, -1005),
            (SkeyStatus::ClockRollback, -1006),
            (SkeyStatus::FeatureDenied, -1007),
            (SkeyStatus::PackageTampered, -1008),
            (SkeyStatus::DecryptFailed, -1009),
            (SkeyStatus::SessionInvalid, -1010),
            (SkeyStatus::ProcessLaunch, -1011),
            (SkeyStatus::InvalidArgument, -1100),
            (SkeyStatus::Internal, -1999),
        ];

        for (status, code) in cases {
            assert_eq!(status.as_i32(), code);
        }
    }

    #[test]
    fn status_messages_are_stable_and_non_empty() {
        assert_eq!(SkeyStatus::Ok.message(), "ok");
        assert_eq!(SkeyStatus::LicenseMissing.message(), "license missing");
        assert_eq!(SkeyStatus::InvalidArgument.message(), "invalid argument");

        for status in SkeyStatus::ALL {
            assert!(!status.message().is_empty());
        }
    }
}
