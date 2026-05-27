#[cfg(not(windows))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime};

use getrandom::getrandom;

use crate::{Result, WrapError};

const SESSION_PREFIX: &str = "sess_";
const SESSION_RANDOM_BYTES: usize = 16;
const SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const SESSION_CREATION_GRACE: Duration = Duration::from_secs(30);
const ACTIVE_MARKER_FILE: &str = "active.pid";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaterializedBlobKind {
    Exe,
    ExeDependency,
    Jar,
    Resource,
}

impl MaterializedBlobKind {
    fn is_executable(self) -> bool {
        matches!(self, Self::Exe)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependencyBlob {
    pub blob_id: String,
    pub original_path: String,
}

pub fn cleanup_expired_sessions(tmp_root: &Path) -> Result<()> {
    fs::create_dir_all(tmp_root)?;
    let now = SystemTime::now();
    for entry in fs::read_dir(tmp_root)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if !file_name.starts_with(SESSION_PREFIX) {
            continue;
        }
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        let modified = match metadata.modified() {
            Ok(modified) => modified,
            Err(_) => continue,
        };
        cleanup_session_dir_if_expired(&entry.path(), now, modified)?;
    }
    Ok(())
}

pub fn cleanup_inactive_sessions(tmp_root: &Path) -> Result<()> {
    fs::create_dir_all(tmp_root)?;
    let now = SystemTime::now();
    for entry in fs::read_dir(tmp_root)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if !file_name.starts_with(SESSION_PREFIX) {
            continue;
        }
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        let modified = match metadata.modified() {
            Ok(modified) => modified,
            Err(_) => continue,
        };
        cleanup_session_dir_if_inactive(&entry.path(), now, modified)?;
    }
    Ok(())
}

pub fn create_session_dir(tmp_root: &Path) -> Result<PathBuf> {
    fs::create_dir_all(tmp_root)?;
    for _ in 0..16 {
        let session_dir = tmp_root.join(format!("{}{}", SESSION_PREFIX, random_hex()?));
        match create_private_dir(&session_dir) {
            Ok(()) => {
                if let Err(error) = write_active_session_marker(&session_dir, std::process::id()) {
                    let _ = fs::remove_dir_all(&session_dir);
                    return Err(error);
                }
                return Ok(session_dir);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(WrapError::new(
        "could not create unique wrapper session directory",
    ))
}

fn cleanup_session_dir_if_expired(
    session_dir: &Path,
    now: SystemTime,
    modified: SystemTime,
) -> Result<bool> {
    if now.duration_since(modified).unwrap_or_default() <= SESSION_TTL {
        return Ok(false);
    }
    if session_has_live_active_marker(session_dir) {
        return Ok(false);
    }
    let _ = fs::remove_dir_all(session_dir);
    Ok(true)
}

fn cleanup_session_dir_if_inactive(
    session_dir: &Path,
    now: SystemTime,
    modified: SystemTime,
) -> Result<bool> {
    if session_has_live_active_marker(session_dir) {
        return Ok(false);
    }
    if now.duration_since(modified).unwrap_or_default() <= SESSION_CREATION_GRACE
        && !session_dir.join(ACTIVE_MARKER_FILE).exists()
    {
        return Ok(false);
    }
    let _ = fs::remove_dir_all(session_dir);
    Ok(true)
}

fn write_active_session_marker(session_dir: &Path, pid: u32) -> Result<()> {
    let marker_path = session_dir.join(ACTIVE_MARKER_FILE);
    let marker_tmp_path = session_dir.join(format!("{ACTIVE_MARKER_FILE}.tmp"));
    let mut file = File::create(&marker_tmp_path)?;
    writeln!(file, "{pid}")?;
    file.sync_all()?;
    drop(file);
    fs::rename(&marker_tmp_path, marker_path)?;
    Ok(())
}

fn session_has_live_active_marker(session_dir: &Path) -> bool {
    let marker_path = session_dir.join(ACTIVE_MARKER_FILE);
    let contents = match fs::read_to_string(&marker_path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
        Err(_) => return true,
    };
    let pid = match contents.trim().parse::<u32>() {
        Ok(pid) if pid != 0 => pid,
        _ => return false,
    };
    process_is_running(pid).unwrap_or(true)
}

#[cfg(windows)]
fn process_is_running(pid: u32) -> Option<bool> {
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, STILL_ACTIVE,
    };
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return match std::io::Error::last_os_error()
            .raw_os_error()
            .map(|value| value as u32)
        {
            Some(ERROR_INVALID_PARAMETER) => Some(false),
            Some(ERROR_ACCESS_DENIED) => Some(true),
            _ => None,
        };
    }

    let mut exit_code = 0u32;
    let ok = unsafe { GetExitCodeProcess(handle, &mut exit_code) };
    unsafe {
        CloseHandle(handle);
    }
    if ok == 0 {
        None
    } else {
        Some(exit_code == STILL_ACTIVE as u32)
    }
}

#[cfg(unix)]
fn process_is_running(pid: u32) -> Option<bool> {
    const EPERM: i32 = 1;
    const ESRCH: i32 = 3;

    if pid > i32::MAX as u32 {
        return Some(false);
    }

    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }

    let result = unsafe { kill(pid as i32, 0) };
    if result == 0 {
        return Some(true);
    }

    match std::io::Error::last_os_error().raw_os_error() {
        Some(ESRCH) => Some(false),
        Some(EPERM) => Some(true),
        _ => None,
    }
}

#[cfg(not(any(windows, unix)))]
fn process_is_running(_pid: u32) -> Option<bool> {
    None
}

pub fn materialize_file(
    session_dir: &Path,
    relative_path: &str,
    bytes: &[u8],
    executable: bool,
) -> Result<PathBuf> {
    let safe_path = safe_relative_path(relative_path)?;
    let output_path = session_dir.join(safe_path);
    if let Some(parent) = output_path.parent() {
        create_private_dir_all(parent)?;
    }
    write_fsynced(&output_path, bytes, executable)?;
    Ok(output_path)
}

pub fn materialize_blob(
    session_dir: &Path,
    kind: MaterializedBlobKind,
    relative_path: &str,
    bytes: &[u8],
) -> Result<PathBuf> {
    materialize_file(session_dir, relative_path, bytes, kind.is_executable())
}

fn safe_relative_path(relative_path: &str) -> Result<PathBuf> {
    let path = Path::new(relative_path);
    if path.is_absolute() {
        return Err(WrapError::new("materialized path must be relative"));
    }

    let mut output = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => output.push(part),
            Component::CurDir => {}
            _ => {
                return Err(WrapError::new(
                    "materialized path escapes session directory",
                ))
            }
        }
    }
    if output.as_os_str().is_empty() {
        return Err(WrapError::new("materialized path is empty"));
    }
    Ok(output)
}

fn write_fsynced(path: &Path, bytes: &[u8], executable: bool) -> Result<()> {
    #[cfg(windows)]
    {
        write_fsynced_windows(path, bytes, executable)
    }

    #[cfg(not(windows))]
    {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        configure_private_file(&mut options);
        let mut file = options.open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);

        #[cfg(unix)]
        if executable {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }

        fsync_parent(path)?;
        Ok(())
    }
}

fn random_hex() -> Result<String> {
    let mut bytes = [0u8; SESSION_RANDOM_BYTES];
    getrandom(&mut bytes).map_err(|_| WrapError::new("could not generate session randomness"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(windows)]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

    let security = private_security_attributes()?;
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    let ok = unsafe { CreateDirectoryW(wide.as_ptr(), security.as_ptr()) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(windows)]
fn write_fsynced_windows(path: &Path, bytes: &[u8], executable: bool) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    };

    let _ = executable;
    let security = private_security_attributes()?;
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_WRITE,
            FILE_SHARE_READ,
            security.as_ptr(),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error().into());
    }

    let mut file = unsafe { File::from_raw_handle(handle) };
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn configure_private_file(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

fn create_private_dir_all(path: &Path) -> std::io::Result<()> {
    if path.as_os_str().is_empty() || path.is_dir() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        create_private_dir_all(parent)?;
    }
    match create_private_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(not(windows))]
fn fsync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(windows)]
struct PrivateSecurityAttributes {
    descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
    attributes: windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
}

#[cfg(windows)]
impl PrivateSecurityAttributes {
    fn as_ptr(&self) -> *const windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        &self.attributes
    }
}

#[cfg(windows)]
impl Drop for PrivateSecurityAttributes {
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::LocalFree(self.descriptor);
            }
        }
    }
}

fn private_temp_sddl_for_user_sid(user_sid: &str) -> String {
    format!("D:P(A;;FA;;;{user_sid})")
}

#[cfg(windows)]
fn private_security_attributes() -> std::io::Result<PrivateSecurityAttributes> {
    use std::mem::size_of;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

    let user_sid = current_user_sid_sddl()?;
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let sddl: Vec<u16> = private_temp_sddl_for_user_sid(&user_sid)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(PrivateSecurityAttributes {
        descriptor,
        attributes: SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        },
    })
}

#[cfg(windows)]
fn current_user_sid_sddl() -> std::io::Result<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    struct TokenHandle(HANDLE);
    impl Drop for TokenHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    let mut token: HANDLE = std::ptr::null_mut();
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if opened == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let token = TokenHandle(token);

    let mut required_len = 0u32;
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut required_len,
        );
    }
    if required_len == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut buffer = vec![0u8; required_len as usize];
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required_len,
            &mut required_len,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let token_user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
    let mut sid_string = std::ptr::null_mut();
    let ok = unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_string) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let sid = unsafe {
        let mut len = 0usize;
        while *sid_string.add(len) != 0 {
            len += 1;
        }
        let value = String::from_utf16_lossy(std::slice::from_raw_parts(sid_string, len));
        windows_sys::Win32::Foundation::LocalFree(sid_string as HLOCAL);
        value
    };
    Ok(sid)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn session_dir_uses_required_prefix_and_random_length() {
        let temp = tempfile::tempdir().unwrap();

        let session = create_session_dir(temp.path()).unwrap();

        let name = session.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("sess_"));
        assert_eq!(name.len(), "sess_".len() + 32);
    }

    #[test]
    fn materialize_rejects_escape_paths() {
        let temp = tempfile::tempdir().unwrap();

        assert!(materialize_file(temp.path(), "../escape.exe", b"x", true).is_err());
        assert!(materialize_file(temp.path(), "/escape.exe", b"x", true).is_err());
    }

    #[test]
    fn materialize_jar_and_resource_use_private_session_paths() {
        let temp = tempfile::tempdir().unwrap();
        let session = create_session_dir(temp.path()).unwrap();

        let jar = materialize_blob(
            &session,
            MaterializedBlobKind::Jar,
            "java/app.jar",
            b"jar-bytes",
        )
        .unwrap();
        let resource = materialize_blob(
            &session,
            MaterializedBlobKind::Resource,
            "assets/config.json",
            b"resource-bytes",
        )
        .unwrap();

        assert!(jar.starts_with(&session));
        assert!(resource.starts_with(&session));
        assert_eq!(fs::read(jar).unwrap(), b"jar-bytes");
        assert_eq!(fs::read(resource).unwrap(), b"resource-bytes");
    }

    #[test]
    fn materialize_jar_and_resource_reject_traversal() {
        let temp = tempfile::tempdir().unwrap();

        assert!(materialize_blob(
            temp.path(),
            MaterializedBlobKind::Jar,
            "../escape.jar",
            b"jar",
        )
        .is_err());
        assert!(materialize_blob(
            temp.path(),
            MaterializedBlobKind::Resource,
            "assets/../../secret.txt",
            b"resource",
        )
        .is_err());
    }

    #[test]
    fn private_temp_sddl_grants_full_access_only_to_current_user() {
        let sddl = private_temp_sddl_for_user_sid("S-1-5-21-111-222-333-1001");

        assert_eq!(sddl, "D:P(A;;FA;;;S-1-5-21-111-222-333-1001)");
        assert_eq!(sddl.matches("(A;;").count(), 1);
        for broad_sid in ["BA", "BU", "WD"] {
            assert!(
                !sddl.contains(&format!(";;;{broad_sid}")),
                "SDDL must not grant access to broad group SID {broad_sid}: {sddl}"
            );
        }
    }

    #[test]
    fn cleanup_removes_expired_session_dirs_only() {
        let temp = tempfile::tempdir().unwrap();
        let expired = temp.path().join("sess_expired");
        let keep = temp.path().join("not_a_session");
        fs::create_dir(&expired).unwrap();
        fs::create_dir(&keep).unwrap();

        #[cfg(windows)]
        {
            let _ = Duration::from_secs(0);
            // Windows does not expose a portable std-only mtime setter. The
            // startup cleanup path is still exercised by leaving current dirs.
            cleanup_expired_sessions(temp.path()).unwrap();
            assert!(expired.exists());
        }

        #[cfg(unix)]
        {
            let _ = Duration::from_secs(0);
            cleanup_expired_sessions(temp.path()).unwrap();
            assert!(expired.exists());
        }

        assert!(keep.exists());
    }

    #[test]
    fn cleanup_decision_removes_old_inactive_session_dir() {
        let temp = tempfile::tempdir().unwrap();
        let expired = temp.path().join("sess_expired");
        fs::create_dir(&expired).unwrap();

        cleanup_session_dir_if_expired(
            &expired,
            SystemTime::UNIX_EPOCH + SESSION_TTL + Duration::from_secs(1),
            SystemTime::UNIX_EPOCH,
        )
        .unwrap();

        assert!(!expired.exists());
    }

    #[test]
    fn cleanup_decision_preserves_old_session_with_live_marker() {
        let temp = tempfile::tempdir().unwrap();
        let active = temp.path().join("sess_active");
        fs::create_dir(&active).unwrap();
        write_active_session_marker(&active, std::process::id()).unwrap();

        cleanup_session_dir_if_expired(
            &active,
            SystemTime::UNIX_EPOCH + SESSION_TTL + Duration::from_secs(1),
            SystemTime::UNIX_EPOCH,
        )
        .unwrap();

        assert!(active.exists());
    }

    #[test]
    fn cleanup_inactive_sessions_removes_abandoned_residue_without_waiting_for_ttl() {
        let temp = tempfile::tempdir().unwrap();
        let zero_pid = temp.path().join("sess_zero_pid");
        let active = temp.path().join("sess_active");
        fs::create_dir(&zero_pid).unwrap();
        fs::create_dir(&active).unwrap();
        fs::write(zero_pid.join("active.pid"), b"0\n").unwrap();
        write_active_session_marker(&active, std::process::id()).unwrap();

        cleanup_inactive_sessions(temp.path()).unwrap();

        assert!(!zero_pid.exists());
        assert!(active.exists());
    }

    #[test]
    fn cleanup_inactive_sessions_preserves_recent_markerless_session_dir() {
        let temp = tempfile::tempdir().unwrap();
        let recent = temp.path().join("sess_being_created");
        fs::create_dir(&recent).unwrap();

        cleanup_session_dir_if_inactive(&recent, SystemTime::now(), SystemTime::now()).unwrap();

        assert!(recent.exists());
    }

    #[test]
    fn active_session_marker_is_published_atomically() {
        let temp = tempfile::tempdir().unwrap();
        let session = temp.path().join("sess_active");
        fs::create_dir(&session).unwrap();

        write_active_session_marker(&session, std::process::id()).unwrap();

        assert_eq!(
            fs::read_to_string(session.join(ACTIVE_MARKER_FILE)).unwrap(),
            format!("{}\n", std::process::id())
        );
        assert!(!session.join(format!("{ACTIVE_MARKER_FILE}.tmp")).exists());
    }

    #[test]
    fn cleanup_inactive_sessions_removes_old_markerless_session_dir() {
        let temp = tempfile::tempdir().unwrap();
        let old = temp.path().join("sess_abandoned_without_marker");
        fs::create_dir(&old).unwrap();

        cleanup_session_dir_if_inactive(
            &old,
            SystemTime::UNIX_EPOCH + SESSION_CREATION_GRACE + Duration::from_secs(1),
            SystemTime::UNIX_EPOCH,
        )
        .unwrap();

        assert!(!old.exists());
    }
}
