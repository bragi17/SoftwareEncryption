#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum SkeyStatus {
    Ok = 0,
    LicenseMissing = -1001,
    LicenseSignature = -1002,
    MachineMismatch = -1003,
    LicenseExpired = -1004,
    LeaseExpired = -1005,
    ClockRollback = -1006,
    FeatureDenied = -1007,
    PackageTampered = -1008,
    DecryptFailed = -1009,
    SessionInvalid = -1010,
    ProcessLaunch = -1011,
    InvalidArgument = -1100,
    Internal = -1999,
}

impl SkeyStatus {
    pub const ALL: [Self; 14] = [
        Self::Ok,
        Self::LicenseMissing,
        Self::LicenseSignature,
        Self::MachineMismatch,
        Self::LicenseExpired,
        Self::LeaseExpired,
        Self::ClockRollback,
        Self::FeatureDenied,
        Self::PackageTampered,
        Self::DecryptFailed,
        Self::SessionInvalid,
        Self::ProcessLaunch,
        Self::InvalidArgument,
        Self::Internal,
    ];

    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    pub const fn message(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::LicenseMissing => "license missing",
            Self::LicenseSignature => "license signature invalid",
            Self::MachineMismatch => "machine mismatch",
            Self::LicenseExpired => "license expired",
            Self::LeaseExpired => "lease expired",
            Self::ClockRollback => "clock rollback detected",
            Self::FeatureDenied => "feature denied",
            Self::PackageTampered => "package tampered",
            Self::DecryptFailed => "decrypt failed",
            Self::SessionInvalid => "session invalid",
            Self::ProcessLaunch => "process launch failed",
            Self::InvalidArgument => "invalid argument",
            Self::Internal => "internal error",
        }
    }
}
