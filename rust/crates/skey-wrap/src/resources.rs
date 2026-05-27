//! Resource compatibility helpers for original-path mirroring.

use crate::materialize::{
    cleanup_expired_sessions, cleanup_inactive_sessions, create_session_dir, materialize_blob,
    MaterializedBlobKind,
};
use crate::Result;
use std::path::{Path, PathBuf};

pub fn materialize_resource_mirror(
    tmp_root: &Path,
    original_path: &str,
    bytes: &[u8],
) -> Result<PathBuf> {
    cleanup_inactive_sessions(tmp_root)?;
    cleanup_expired_sessions(tmp_root)?;
    let session_dir = create_session_dir(tmp_root)?;
    materialize_blob(
        &session_dir,
        MaterializedBlobKind::Resource,
        original_path,
        bytes,
    )
}

pub fn cleanup_resource_sessions(tmp_root: &Path) -> Result<()> {
    cleanup_inactive_sessions(tmp_root)?;
    cleanup_expired_sessions(tmp_root)
}
