//! EXE shell wrapper runtime.

pub mod materialize;
pub mod process;
pub mod resources;

use std::ffi::{c_char, c_int, c_void, CStr, CString, OsString};
use std::fmt;
use std::path::{Path, PathBuf};
use std::{fs, ptr, slice};

use serde_json::Value;

use crate::materialize::{
    cleanup_expired_sessions, cleanup_inactive_sessions, create_session_dir, materialize_blob,
    DependencyBlob, MaterializedBlobKind,
};
use crate::process::run_child;

pub const SESSION_ENV: &str = "APP_SKEY_SESSION";

const PAYLOAD_FILE: &str = "payload.skp";
const RUNTIME_FILE_WINDOWS: &str = "skey_rt.dll";
const RUNTIME_FILE_MACOS: &str = "libskey_rt.dylib";
const RUNTIME_FILE_UNIX: &str = "libskey_rt.so";
const HEADER_LEN: usize = 26;
const RESOURCE_MODE_MATERIALIZE_ON_SESSION: &str = "materialize_on_session";

#[derive(Debug)]
pub struct WrapError {
    message: String,
}

impl WrapError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for WrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for WrapError {}

impl From<std::io::Error> for WrapError {
    fn from(error: std::io::Error) -> Self {
        Self::new(error.to_string())
    }
}

impl From<serde_json::Error> for WrapError {
    fn from(error: serde_json::Error) -> Self {
        Self::new(error.to_string())
    }
}

pub type Result<T> = std::result::Result<T, WrapError>;

#[repr(C)]
struct SkeyInitOptions {
    app_root: *const c_char,
    payload_path: *const c_char,
    entry_id: *const c_char,
    original_path: *const c_char,
    argv_json: *const c_char,
    env_session: *const c_char,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SkeyBuffer {
    data: *mut u8,
    len: usize,
}

type SkeyContext = c_void;
type SkeyStatus = c_int;
type RuntimeInitFn =
    unsafe extern "C" fn(*const SkeyInitOptions, *mut *mut SkeyContext) -> SkeyStatus;
type LoadEntryFn =
    unsafe extern "C" fn(*mut SkeyContext, *const c_char, *mut SkeyBuffer) -> SkeyStatus;
type CreateSessionFn = unsafe extern "C" fn(*mut SkeyContext, *mut SkeyBuffer) -> SkeyStatus;
type LastErrorFn = unsafe extern "C" fn() -> *const c_char;
type BufferFreeFn = unsafe extern "C" fn(SkeyBuffer);
type ContextFreeFn = unsafe extern "C" fn(*mut SkeyContext);

pub fn run_current_exe(raw_args: Vec<OsString>) -> Result<i32> {
    let shell_path = current_process_path()?;
    run_shell(shell_path, raw_args)
}

pub fn run_shell(shell_path: PathBuf, raw_args: Vec<OsString>) -> Result<i32> {
    let child_args = forwarded_args(raw_args);
    let product_root = find_product_root(&shell_path)?;
    let secure_root = product_root.join(".secure");
    let tmp_root = secure_root.join("tmp");
    cleanup_inactive_sessions(&tmp_root)?;
    cleanup_expired_sessions(&tmp_root)?;

    let original_path = relative_posix_path(&product_root, &shell_path)?;
    let entry_id = format!("exe:{original_path}");
    let payload_path = secure_root.join(PAYLOAD_FILE);
    let runtime_path = runtime_library_path(&secure_root);

    let dependency_blobs = dependency_blobs(&payload_path)?;
    let resource_blobs = materialized_resource_blobs(&payload_path)?;
    let runtime = RuntimeLibrary::load(&runtime_path)?;
    let context = runtime.init(RuntimeInitRequest {
        app_root: &product_root,
        payload_path: &payload_path,
        entry_id: &entry_id,
        original_path: &original_path,
        argv_json: &argv_json(&child_args)?,
    })?;
    let session_dir = create_session_dir(&tmp_root)?;

    let exit_code = (|| {
        let exe_bytes = context.load_entry(&entry_id)?;
        let materialized_exe = materialize_blob(
            &session_dir,
            MaterializedBlobKind::Exe,
            &original_path,
            &exe_bytes,
        )?;

        for dependency in dependency_blobs {
            let bytes = context.load_entry(&dependency.blob_id)?;
            materialize_blob(
                &session_dir,
                MaterializedBlobKind::ExeDependency,
                &dependency.original_path,
                &bytes,
            )?;
        }

        for resource in resource_blobs {
            let bytes = context.load_entry(&resource.blob_id)?;
            materialize_blob(
                &session_dir,
                MaterializedBlobKind::Resource,
                &resource.original_path,
                &bytes,
            )?;
        }

        let session_token = context.create_session()?;
        run_child(&materialized_exe, &child_args, &session_token)
    })();

    let _ = fs::remove_dir_all(&session_dir);
    exit_code
}

fn forwarded_args(raw_args: Vec<OsString>) -> Vec<OsString> {
    if raw_args.len() >= 2 && raw_args[0] == "--mode" && raw_args[1] == "run" {
        raw_args.into_iter().skip(2).collect()
    } else {
        raw_args
    }
}

fn argv_json(args: &[OsString]) -> Result<String> {
    let values: Vec<String> = args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    serde_json::to_string(&values).map_err(Into::into)
}

fn runtime_library_path(secure_root: &Path) -> PathBuf {
    let name = if cfg!(windows) {
        RUNTIME_FILE_WINDOWS
    } else if cfg!(target_os = "macos") {
        RUNTIME_FILE_MACOS
    } else {
        RUNTIME_FILE_UNIX
    };
    secure_root.join("rt").join(name)
}

fn find_product_root(shell_path: &Path) -> Result<PathBuf> {
    for candidate in shell_path.ancestors().skip(1) {
        if candidate.join(".secure").join(PAYLOAD_FILE).is_file() {
            return Ok(candidate.to_path_buf());
        }
    }
    Err(WrapError::new("could not locate product .secure payload"))
}

fn relative_posix_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| WrapError::new("shell path is outside product root"))?;
    let value = relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    if value.is_empty() {
        return Err(WrapError::new("shell path has no relative product path"));
    }
    Ok(value)
}

fn dependency_blobs(payload_path: &Path) -> Result<Vec<DependencyBlob>> {
    let blobs = manifest_blobs(payload_path)?;

    let mut dependencies = Vec::new();
    for blob in blobs {
        if blob.get("type").and_then(Value::as_str) != Some("exe-dep") {
            continue;
        }
        let blob_id = blob
            .get("blob_id")
            .and_then(Value::as_str)
            .ok_or_else(|| WrapError::new("dependency blob missing blob_id"))?;
        let original_path = blob
            .get("original_path")
            .and_then(Value::as_str)
            .ok_or_else(|| WrapError::new("dependency blob missing original_path"))?;
        dependencies.push(DependencyBlob {
            blob_id: blob_id.to_owned(),
            original_path: original_path.to_owned(),
        });
    }
    Ok(dependencies)
}

fn materialized_resource_blobs(payload_path: &Path) -> Result<Vec<DependencyBlob>> {
    let blobs = manifest_blobs(payload_path)?;

    let mut resources = Vec::new();
    for blob in blobs {
        if blob.get("type").and_then(Value::as_str) != Some("resource")
            || blob.get("mode").and_then(Value::as_str)
                != Some(RESOURCE_MODE_MATERIALIZE_ON_SESSION)
        {
            continue;
        }
        let blob_id = blob
            .get("blob_id")
            .and_then(Value::as_str)
            .ok_or_else(|| WrapError::new("resource blob missing blob_id"))?;
        let original_path = blob
            .get("original_path")
            .and_then(Value::as_str)
            .ok_or_else(|| WrapError::new("resource blob missing original_path"))?;
        resources.push(DependencyBlob {
            blob_id: blob_id.to_owned(),
            original_path: original_path.to_owned(),
        });
    }
    Ok(resources)
}

fn manifest_blobs(payload_path: &Path) -> Result<Vec<Value>> {
    let package = fs::read(payload_path)?;
    if package.len() < HEADER_LEN || &package[0..4] != b"SKP1" {
        return Err(WrapError::new("payload has invalid SKP header"));
    }

    let header_len = u32::from_le_bytes(package[6..10].try_into().unwrap()) as usize;
    let manifest_len = u64::from_le_bytes(package[10..18].try_into().unwrap()) as usize;
    let manifest_end = header_len
        .checked_add(manifest_len)
        .ok_or_else(|| WrapError::new("payload manifest length overflow"))?;
    if package.len() < manifest_end {
        return Err(WrapError::new("payload manifest is truncated"));
    }

    let manifest: Value = serde_json::from_slice(&package[header_len..manifest_end])?;
    let blobs = manifest
        .get("blobs")
        .and_then(Value::as_array)
        .ok_or_else(|| WrapError::new("payload manifest is missing blobs"))?;
    Ok(blobs.clone())
}

struct RuntimeInitRequest<'a> {
    app_root: &'a Path,
    payload_path: &'a Path,
    entry_id: &'a str,
    original_path: &'a str,
    argv_json: &'a str,
}

struct RuntimeLibrary {
    #[cfg(not(windows))]
    library: *mut c_void,
    #[cfg(windows)]
    module: windows_sys::Win32::Foundation::HMODULE,
    #[cfg(windows)]
    _dll_directory: DllDirectoryGuard,
    runtime_init: RuntimeInitFn,
    load_entry: LoadEntryFn,
    create_session: CreateSessionFn,
    last_error: LastErrorFn,
    buffer_free: BufferFreeFn,
    context_free: ContextFreeFn,
}

impl RuntimeLibrary {
    fn load(runtime_path: &Path) -> Result<Self> {
        if !runtime_path.is_absolute() {
            return Err(WrapError::new("runtime library path must be absolute"));
        }
        #[cfg(windows)]
        let dll_directory = prepare_runtime_library_path(runtime_path)?;
        #[cfg(not(windows))]
        prepare_runtime_library_path(runtime_path)?;
        let library = unsafe { PlatformLibrary::load(runtime_path)? };
        let runtime_init = unsafe { library.symbol(b"skey_runtime_init\0")? };
        let load_entry = unsafe { library.symbol(b"skey_load_entry\0")? };
        let create_session = unsafe { library.symbol(b"skey_create_session\0")? };
        let last_error = unsafe { library.symbol(b"skey_last_error_message\0")? };
        let buffer_free = unsafe { library.symbol(b"skey_buffer_free\0")? };
        let context_free = unsafe { library.symbol(b"skey_context_free\0")? };

        Ok(Self {
            #[cfg(not(windows))]
            library: library.handle,
            #[cfg(windows)]
            module: library.module,
            #[cfg(windows)]
            _dll_directory: dll_directory,
            runtime_init,
            load_entry,
            create_session,
            last_error,
            buffer_free,
            context_free,
        })
    }

    fn init(&self, request: RuntimeInitRequest<'_>) -> Result<RuntimeContext<'_>> {
        let app_root = path_cstring(request.app_root)?;
        let payload_path = path_cstring(request.payload_path)?;
        let entry_id = CString::new(request.entry_id)
            .map_err(|_| WrapError::new("entry id contains NUL byte"))?;
        let original_path = CString::new(request.original_path)
            .map_err(|_| WrapError::new("original path contains NUL byte"))?;
        let argv_json = CString::new(request.argv_json)
            .map_err(|_| WrapError::new("argv json contains NUL byte"))?;
        let options = SkeyInitOptions {
            app_root: app_root.as_ptr(),
            payload_path: payload_path.as_ptr(),
            entry_id: entry_id.as_ptr(),
            original_path: original_path.as_ptr(),
            argv_json: argv_json.as_ptr(),
            env_session: ptr::null(),
        };

        let mut ctx = ptr::null_mut();
        let status = unsafe { (self.runtime_init)(&options, &mut ctx) };
        if status != 0 {
            return Err(self.status_error("runtime init", status));
        }
        if ctx.is_null() {
            return Err(WrapError::new("runtime init returned a null context"));
        }
        Ok(RuntimeContext { runtime: self, ctx })
    }

    fn status_error(&self, operation: &str, status: SkeyStatus) -> WrapError {
        let message = unsafe {
            let ptr = (self.last_error)();
            if ptr.is_null() {
                "unknown runtime error".to_owned()
            } else {
                CStr::from_ptr(ptr).to_string_lossy().into_owned()
            }
        };
        WrapError::new(format!("{operation} failed ({status}): {message}"))
    }
}

#[cfg(not(windows))]
struct PlatformLibrary {
    handle: *mut c_void,
}

#[cfg(not(windows))]
impl PlatformLibrary {
    unsafe fn load(runtime_path: &Path) -> Result<Self> {
        let path = path_cstring(runtime_path)?;
        let handle = dlopen(path.as_ptr(), RTLD_NOW);
        if handle.is_null() {
            return Err(WrapError::new(dl_error()));
        }
        Ok(Self { handle })
    }

    unsafe fn symbol<T: Copy>(&self, name: &[u8]) -> Result<T> {
        use std::mem;

        let pointer = dlsym(self.handle, name.as_ptr().cast());
        if pointer.is_null() {
            return Err(WrapError::new(dl_error()));
        }
        Ok(mem::transmute_copy(&pointer))
    }
}

#[cfg(not(windows))]
impl Drop for RuntimeLibrary {
    fn drop(&mut self) {
        unsafe {
            dlclose(self.library);
        }
    }
}

#[cfg(not(windows))]
const RTLD_NOW: c_int = 2;

#[cfg_attr(target_os = "linux", link(name = "dl"))]
#[cfg(not(windows))]
extern "C" {
    fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> c_int;
    fn dlerror() -> *const c_char;
}

#[cfg(not(windows))]
fn dl_error() -> String {
    unsafe {
        let pointer = dlerror();
        if pointer.is_null() {
            "dynamic library operation failed".to_owned()
        } else {
            CStr::from_ptr(pointer).to_string_lossy().into_owned()
        }
    }
}

#[cfg(windows)]
struct PlatformLibrary {
    module: windows_sys::Win32::Foundation::HMODULE,
}

#[cfg(windows)]
impl PlatformLibrary {
    unsafe fn load(runtime_path: &Path) -> Result<Self> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::System::LibraryLoader::{
            LoadLibraryExW, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
        };

        let mut wide: Vec<u16> = runtime_path.as_os_str().encode_wide().collect();
        wide.push(0);
        let module = LoadLibraryExW(
            wide.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
        );
        if module.is_null() {
            return Err(WrapError::new("LoadLibraryExW failed"));
        }
        Ok(Self { module })
    }

    unsafe fn symbol<T: Copy>(&self, name: &[u8]) -> Result<T> {
        use std::mem;
        use windows_sys::Win32::System::LibraryLoader::GetProcAddress;

        let proc = GetProcAddress(self.module, name.as_ptr());
        let proc = proc.ok_or_else(|| WrapError::new("runtime symbol was not found"))?;
        Ok(mem::transmute_copy(&proc))
    }
}

#[cfg(windows)]
impl Drop for RuntimeLibrary {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::FreeLibrary(self.module);
        }
    }
}

struct RuntimeContext<'a> {
    runtime: &'a RuntimeLibrary,
    ctx: *mut SkeyContext,
}

impl RuntimeContext<'_> {
    fn load_entry(&self, entry_id: &str) -> Result<Vec<u8>> {
        let entry_id =
            CString::new(entry_id).map_err(|_| WrapError::new("entry id contains NUL byte"))?;
        let mut out = empty_buffer();
        let status = unsafe { (self.runtime.load_entry)(self.ctx, entry_id.as_ptr(), &mut out) };
        self.take_buffer("load entry", status, out)
    }

    fn create_session(&self) -> Result<String> {
        let mut out = empty_buffer();
        let status = unsafe { (self.runtime.create_session)(self.ctx, &mut out) };
        let bytes = self.take_buffer("create session", status, out)?;
        String::from_utf8(bytes).map_err(|_| WrapError::new("runtime returned non-UTF8 session"))
    }

    fn take_buffer(&self, operation: &str, status: SkeyStatus, out: SkeyBuffer) -> Result<Vec<u8>> {
        if status != 0 {
            return Err(self.runtime.status_error(operation, status));
        }
        if out.data.is_null() || out.len == 0 {
            unsafe { (self.runtime.buffer_free)(out) };
            return Ok(Vec::new());
        }
        let bytes = unsafe { slice::from_raw_parts(out.data, out.len).to_vec() };
        unsafe { (self.runtime.buffer_free)(out) };
        Ok(bytes)
    }
}

impl Drop for RuntimeContext<'_> {
    fn drop(&mut self) {
        unsafe { (self.runtime.context_free)(self.ctx) };
    }
}

fn empty_buffer() -> SkeyBuffer {
    SkeyBuffer {
        data: ptr::null_mut(),
        len: 0,
    }
}

fn path_cstring(path: &Path) -> Result<CString> {
    CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| WrapError::new("path contains NUL byte"))
}

#[cfg(windows)]
fn current_process_path() -> Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;

    let mut capacity = 260usize;
    loop {
        let mut buffer = vec![0u16; capacity];
        let len = unsafe {
            GetModuleFileNameW(
                std::ptr::null_mut(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
            )
        };
        if len == 0 {
            return Err(WrapError::new("GetModuleFileNameW failed"));
        }
        let len = len as usize;
        if len < buffer.len() - 1 {
            buffer.truncate(len);
            return Ok(PathBuf::from(OsString::from_wide(&buffer)));
        }
        capacity *= 2;
    }
}

#[cfg(not(windows))]
fn current_process_path() -> Result<PathBuf> {
    std::env::current_exe().map_err(Into::into)
}

#[cfg(windows)]
struct DllDirectoryGuard(*mut c_void);

#[cfg(windows)]
impl Drop for DllDirectoryGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                windows_sys::Win32::System::LibraryLoader::RemoveDllDirectory(
                    self.0 as *const c_void,
                );
            }
        }
    }
}

#[cfg(windows)]
fn prepare_runtime_library_path(runtime_path: &Path) -> Result<DllDirectoryGuard> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::LibraryLoader::{
        AddDllDirectory, SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
    };

    // Process-global DLL search defaults are intentional: Task 12 requires
    // SetDefaultDllDirectories before AddDllDirectory and LoadLibraryExW.
    unsafe {
        if SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS) == 0 {
            return Err(WrapError::new("SetDefaultDllDirectories failed"));
        }
    }

    let runtime_dir = runtime_path
        .parent()
        .ok_or_else(|| WrapError::new("runtime library has no parent directory"))?;
    let mut wide: Vec<u16> = runtime_dir.as_os_str().encode_wide().collect();
    wide.push(0);
    let cookie = unsafe { AddDllDirectory(wide.as_ptr()) };
    if cookie.is_null() {
        return Err(WrapError::new("AddDllDirectory failed"));
    }
    Ok(DllDirectoryGuard(cookie))
}

#[cfg(not(windows))]
fn prepare_runtime_library_path(_runtime_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_mode_prefix_is_stripped_from_child_args() {
        let args = forwarded_args(vec![
            OsString::from("--mode"),
            OsString::from("run"),
            OsString::from("--flag"),
        ]);

        assert_eq!(args, vec![OsString::from("--flag")]);
    }

    #[test]
    fn dependency_parser_reads_exe_dep_blobs() {
        let temp = tempfile::tempdir().unwrap();
        let payload = temp.path().join("payload.skp");
        let manifest = br#"{"blobs":[{"blob_id":"exe:tools/helper.exe","type":"exe","original_path":"tools/helper.exe"},{"blob_id":"exe-dep:tools/helper.dll","type":"exe-dep","original_path":"tools/helper.dll"}]}"#;
        let header_len = HEADER_LEN as u32;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"SKP1");
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&header_len.to_le_bytes());
        bytes.extend_from_slice(&(manifest.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(manifest);
        fs::write(&payload, bytes).unwrap();

        let dependencies = dependency_blobs(&payload).unwrap();

        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0].blob_id, "exe-dep:tools/helper.dll");
        assert_eq!(dependencies[0].original_path, "tools/helper.dll");
    }

    #[test]
    fn resource_parser_selects_only_materialize_on_session_blobs() {
        let temp = tempfile::tempdir().unwrap();
        let payload = temp.path().join("payload.skp");
        let manifest = br#"{"blobs":[{"blob_id":"res:data/model.dat","type":"resource","original_path":"data/model.dat","mode":"stream_api"},{"blob_id":"res:data/license_template.dat","type":"resource","original_path":"data/license_template.dat","mode":"materialize_on_session"}]}"#;
        let header_len = HEADER_LEN as u32;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"SKP1");
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&header_len.to_le_bytes());
        bytes.extend_from_slice(&(manifest.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(manifest);
        fs::write(&payload, bytes).unwrap();

        let resources = materialized_resource_blobs(&payload).unwrap();

        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].blob_id, "res:data/license_template.dat");
        assert_eq!(resources[0].original_path, "data/license_template.dat");
    }
}
