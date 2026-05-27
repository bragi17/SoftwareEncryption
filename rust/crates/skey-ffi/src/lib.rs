//! Public C ABI exports for the SKey runtime.

#![allow(non_camel_case_types)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{c_char, c_int, CStr};
use std::ops::{Deref, DerefMut};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::sync::{Mutex, MutexGuard};

use skey_core::context::{RuntimeContext, RuntimeInitOptions};
use skey_core::errors::SkeyStatus;
use zeroize::Zeroize;

pub type skey_status = c_int;

#[repr(C)]
pub struct skey_context {
    inner: Mutex<RuntimeContext>,
}

#[repr(C)]
pub struct skey_init_options {
    pub app_root: *const c_char,
    pub payload_path: *const c_char,
    pub entry_id: *const c_char,
    pub original_path: *const c_char,
    pub argv_json: *const c_char,
    pub env_session: *const c_char,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct skey_buffer {
    pub data: *mut u8,
    pub len: usize,
}

impl skey_init_options {
    fn has_required_fields(&self) -> bool {
        !self.app_root.is_null()
            && !self.payload_path.is_null()
            && !self.entry_id.is_null()
            && !self.original_path.is_null()
            && !self.argv_json.is_null()
    }
}

thread_local! {
    // Keep Rust 1.78+ plausible; Clippy on newer toolchains prefers `const { ... }`.
    #[allow(clippy::missing_const_for_thread_local)]
    static LAST_ERROR: RefCell<LastErrorMessage> = RefCell::new(LastErrorMessage::new(SkeyStatus::Ok.message()));
}

#[derive(Clone, Copy, Debug)]
struct RegisteredResourceHandle {
    ctx: usize,
    local_handle: u64,
}

#[derive(Debug, Default)]
struct ResourceRegistry {
    handles: HashMap<u64, RegisteredResourceHandle>,
}

static RESOURCE_REGISTRY: OnceLock<Mutex<ResourceRegistry>> = OnceLock::new();
static NEXT_RESOURCE_HANDLE: AtomicU64 = AtomicU64::new(1);
static CONTEXT_LIFECYCLE: OnceLock<Mutex<()>> = OnceLock::new();

fn set_status(status: SkeyStatus) -> skey_status {
    set_last_error_message(status.message());
    status.as_i32()
}

#[derive(Debug)]
struct LastErrorMessage {
    message: Vec<u8>,
}

impl LastErrorMessage {
    fn new(message: &str) -> Self {
        let mut last_error = Self {
            message: Vec::new(),
        };
        last_error.set(message);
        last_error
    }

    fn set(&mut self, message: &str) {
        self.message.clear();
        self.message.extend(
            message
                .as_bytes()
                .iter()
                .map(|byte| if *byte == 0 { b' ' } else { *byte }),
        );
        self.message.push(0);
    }

    fn as_ptr(&self) -> *const c_char {
        self.message.as_ptr().cast()
    }
}

fn set_last_error_message(message: &str) {
    LAST_ERROR.with(|last_error| last_error.borrow_mut().set(message));
}

fn last_error_message_ptr() -> *const c_char {
    LAST_ERROR.with(|last_error| last_error.borrow().as_ptr())
}

fn ffi_status<F, C>(operation: F, on_panic: C) -> skey_status
where
    F: FnOnce() -> skey_status,
    C: FnOnce(),
{
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(status) => status,
        Err(_) => {
            let _ = catch_unwind(AssertUnwindSafe(on_panic));
            set_status(SkeyStatus::Internal)
        }
    }
}

fn ffi_void<F>(operation: F)
where
    F: FnOnce(),
{
    if catch_unwind(AssertUnwindSafe(operation)).is_err() {
        let _ = set_status(SkeyStatus::Internal);
    }
}

fn ffi_const_char_ptr<F>(operation: F) -> *const c_char
where
    F: FnOnce() -> *const c_char,
{
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(ptr) => ptr,
        Err(_) => {
            let _ = set_status(SkeyStatus::Internal);
            last_error_message_ptr()
        }
    }
}

fn clear_buffer(buffer: *mut skey_buffer) {
    if !buffer.is_null() {
        unsafe {
            (*buffer).data = ptr::null_mut();
            (*buffer).len = 0;
        }
    }
}

fn clear_context_out(out_ctx: *mut *mut skey_context) {
    if !out_ctx.is_null() {
        unsafe {
            *out_ctx = ptr::null_mut();
        }
    }
}

fn clear_handle_out(out_handle: *mut u64) {
    if !out_handle.is_null() {
        unsafe {
            *out_handle = 0;
        }
    }
}

fn resource_registry() -> &'static Mutex<ResourceRegistry> {
    RESOURCE_REGISTRY.get_or_init(|| Mutex::new(ResourceRegistry::default()))
}

fn context_lifecycle() -> &'static Mutex<()> {
    CONTEXT_LIFECYCLE.get_or_init(|| Mutex::new(()))
}

fn context_lifecycle_lock() -> Result<MutexGuard<'static, ()>, SkeyStatus> {
    Ok(context_lifecycle()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()))
}

fn register_resource_handle(ctx: *mut skey_context, local_handle: u64) -> Result<u64, SkeyStatus> {
    let mut registry = resource_registry()
        .lock()
        .map_err(|_| SkeyStatus::Internal)?;
    for _ in 0..16 {
        let handle = NEXT_RESOURCE_HANDLE.fetch_add(1, Ordering::Relaxed).max(1);
        if let std::collections::hash_map::Entry::Vacant(entry) = registry.handles.entry(handle) {
            entry.insert(RegisteredResourceHandle {
                ctx: ctx as usize,
                local_handle,
            });
            return Ok(handle);
        }
    }
    Err(SkeyStatus::Internal)
}

fn lookup_resource_handle(handle: u64) -> Result<RegisteredResourceHandle, SkeyStatus> {
    let registry = resource_registry()
        .lock()
        .map_err(|_| SkeyStatus::Internal)?;
    registry
        .handles
        .get(&handle)
        .copied()
        .ok_or(SkeyStatus::InvalidArgument)
}

fn unregister_resource_handle(handle: u64) -> Option<RegisteredResourceHandle> {
    resource_registry()
        .lock()
        .ok()
        .and_then(|mut registry| registry.handles.remove(&handle))
}

fn unregister_context_handles(ctx: *mut skey_context) {
    if let Ok(mut registry) = resource_registry().lock() {
        let ctx = ctx as usize;
        registry
            .handles
            .retain(|_, registered| registered.ctx != ctx);
    }
}

// All buffers returned through the C ABI must be allocated by this helper.
// skey_buffer_free reconstructs the same Box<[u8]> allocation shape.
#[allow(dead_code)]
fn buffer_from_vec_for_ffi(bytes: Vec<u8>) -> skey_buffer {
    if bytes.is_empty() {
        return skey_buffer {
            data: ptr::null_mut(),
            len: 0,
        };
    }

    let len = bytes.len();
    let boxed = bytes.into_boxed_slice();
    let data = Box::into_raw(boxed) as *mut u8;
    skey_buffer { data, len }
}

fn validate_ctx(ctx: *mut skey_context) -> Result<(), SkeyStatus> {
    if ctx.is_null() {
        Err(SkeyStatus::InvalidArgument)
    } else {
        Ok(())
    }
}

fn validate_c_string(value: *const c_char) -> Result<(), SkeyStatus> {
    if value.is_null() {
        Err(SkeyStatus::InvalidArgument)
    } else {
        Ok(())
    }
}

unsafe fn c_string(value: *const c_char) -> Result<String, SkeyStatus> {
    if value.is_null() {
        return Err(SkeyStatus::InvalidArgument);
    }
    CStr::from_ptr(value)
        .to_str()
        .map(str::to_owned)
        .map_err(|_| SkeyStatus::InvalidArgument)
}

unsafe fn init_options_from_ffi(
    options: *const skey_init_options,
) -> Result<RuntimeInitOptions, SkeyStatus> {
    if options.is_null() {
        return Err(SkeyStatus::InvalidArgument);
    }
    let options = &*options;
    if !options.has_required_fields() {
        return Err(SkeyStatus::InvalidArgument);
    }
    Ok(RuntimeInitOptions {
        app_root: PathBuf::from(c_string(options.app_root)?),
        payload_path: PathBuf::from(c_string(options.payload_path)?),
        entry_id: c_string(options.entry_id)?,
        original_path: c_string(options.original_path)?,
        argv_json: c_string(options.argv_json)?,
        env_session: if options.env_session.is_null() {
            None
        } else {
            Some(c_string(options.env_session)?)
        },
    })
}

struct ContextGuard<'a> {
    _lifecycle: MutexGuard<'static, ()>,
    inner: MutexGuard<'a, RuntimeContext>,
}

impl Deref for ContextGuard<'_> {
    type Target = RuntimeContext;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ContextGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

unsafe fn ctx_lock<'a>(ctx: *mut skey_context) -> Result<ContextGuard<'a>, SkeyStatus> {
    let lifecycle = context_lifecycle_lock()?;
    let inner = ctx_lock_after_lifecycle(ctx)?;
    Ok(ContextGuard {
        _lifecycle: lifecycle,
        inner,
    })
}

unsafe fn ctx_lock_after_lifecycle<'a>(
    ctx: *mut skey_context,
) -> Result<MutexGuard<'a, RuntimeContext>, SkeyStatus> {
    if ctx.is_null() {
        return Err(SkeyStatus::InvalidArgument);
    }
    (*ctx).inner.lock().map_err(|_| SkeyStatus::Internal)
}

fn set_result(result: Result<(), SkeyStatus>) -> skey_status {
    match result {
        Ok(()) => set_status(SkeyStatus::Ok),
        Err(status) => set_status(status),
    }
}

unsafe fn write_buffer_result(
    out_buffer: *mut skey_buffer,
    result: Result<Vec<u8>, SkeyStatus>,
) -> skey_status {
    clear_buffer(out_buffer);
    if out_buffer.is_null() {
        return set_status(SkeyStatus::InvalidArgument);
    }
    match result {
        Ok(bytes) => {
            *out_buffer = buffer_from_vec_for_ffi(bytes);
            set_status(SkeyStatus::Ok)
        }
        Err(status) => set_status(status),
    }
}

#[no_mangle]
/// # Safety
///
/// `options` and `out_ctx` must follow the pointer rules in `include/skey_runtime.h`.
/// On success, the returned context must be released with `skey_context_free`.
pub unsafe extern "C" fn skey_runtime_init(
    options: *const skey_init_options,
    out_ctx: *mut *mut skey_context,
) -> skey_status {
    ffi_status(
        || {
            clear_context_out(out_ctx);

            if options.is_null() || out_ctx.is_null() {
                return set_status(SkeyStatus::InvalidArgument);
            }

            let init_options = match init_options_from_ffi(options) {
                Ok(options) => options,
                Err(status) => return set_status(status),
            };
            match RuntimeContext::new(init_options) {
                Ok(inner) => {
                    *out_ctx = Box::into_raw(Box::new(skey_context {
                        inner: Mutex::new(inner),
                    }));
                    set_status(SkeyStatus::Ok)
                }
                Err(status) => set_status(status),
            }
        },
        || clear_context_out(out_ctx),
    )
}

#[no_mangle]
/// # Safety
///
/// `ctx` and `feature_code` must follow the pointer rules in `include/skey_runtime.h`.
pub unsafe extern "C" fn skey_license_check(
    ctx: *mut skey_context,
    feature_code: *const c_char,
) -> skey_status {
    ffi_status(
        || {
            if ctx.is_null() || feature_code.is_null() {
                return set_status(SkeyStatus::InvalidArgument);
            }

            let feature_code = match c_string(feature_code) {
                Ok(value) => value,
                Err(status) => return set_status(status),
            };
            set_result(ctx_lock(ctx).and_then(|mut ctx| ctx.license_check(&feature_code)))
        },
        || {},
    )
}

#[no_mangle]
/// # Safety
///
/// `ctx`, `entry_id`, and `out_source` must follow the pointer and buffer ownership
/// rules in `include/skey_runtime.h`.
pub unsafe extern "C" fn skey_load_entry(
    ctx: *mut skey_context,
    entry_id: *const c_char,
    out_source: *mut skey_buffer,
) -> skey_status {
    ffi_status(
        || {
            clear_buffer(out_source);
            if ctx.is_null() || entry_id.is_null() || out_source.is_null() {
                return set_status(SkeyStatus::InvalidArgument);
            }
            let entry_id = match c_string(entry_id) {
                Ok(value) => value,
                Err(status) => return set_status(status),
            };
            let result = ctx_lock(ctx).and_then(|mut ctx| ctx.load_entry(&entry_id));
            write_buffer_result(out_source, result)
        },
        || clear_buffer(out_source),
    )
}

#[no_mangle]
/// # Safety
///
/// `ctx`, `module_name`, and `out_json` must follow the pointer and buffer ownership
/// rules in `include/skey_runtime.h`.
pub unsafe extern "C" fn skey_find_module(
    ctx: *mut skey_context,
    module_name: *const c_char,
    out_json: *mut skey_buffer,
) -> skey_status {
    ffi_status(
        || {
            clear_buffer(out_json);
            if ctx.is_null() || module_name.is_null() || out_json.is_null() {
                return set_status(SkeyStatus::InvalidArgument);
            }
            let module_name = match c_string(module_name) {
                Ok(value) => value,
                Err(status) => return set_status(status),
            };
            let result = ctx_lock(ctx).and_then(|ctx| ctx.find_module(&module_name));
            write_buffer_result(out_json, result)
        },
        || clear_buffer(out_json),
    )
}

#[no_mangle]
/// # Safety
///
/// `ctx`, `module_name`, and `out_source` must follow the pointer and buffer ownership
/// rules in `include/skey_runtime.h`.
pub unsafe extern "C" fn skey_load_module(
    ctx: *mut skey_context,
    module_name: *const c_char,
    out_source: *mut skey_buffer,
) -> skey_status {
    ffi_status(
        || {
            clear_buffer(out_source);
            if ctx.is_null() || module_name.is_null() || out_source.is_null() {
                return set_status(SkeyStatus::InvalidArgument);
            }
            let module_name = match c_string(module_name) {
                Ok(value) => value,
                Err(status) => return set_status(status),
            };
            let result = ctx_lock(ctx).and_then(|mut ctx| ctx.load_module(&module_name));
            write_buffer_result(out_source, result)
        },
        || clear_buffer(out_source),
    )
}

#[no_mangle]
/// # Safety
///
/// `ctx`, `entry_id`, and `out_bytes` must follow the pointer and buffer ownership
/// rules in `include/skey_runtime.h`.
pub unsafe extern "C" fn skey_materialize_entry(
    ctx: *mut skey_context,
    entry_id: *const c_char,
    out_bytes: *mut skey_buffer,
) -> skey_status {
    ffi_status(
        || {
            clear_buffer(out_bytes);
            if ctx.is_null() || entry_id.is_null() || out_bytes.is_null() {
                return set_status(SkeyStatus::InvalidArgument);
            }
            let entry_id = match c_string(entry_id) {
                Ok(value) => value,
                Err(status) => return set_status(status),
            };
            let result = ctx_lock(ctx).and_then(|mut ctx| ctx.materialize_entry(&entry_id));
            write_buffer_result(out_bytes, result)
        },
        || clear_buffer(out_bytes),
    )
}

#[no_mangle]
/// # Safety
///
/// `ctx` and `out_token` must follow the pointer and buffer ownership rules in
/// `include/skey_runtime.h`.
pub unsafe extern "C" fn skey_create_session(
    ctx: *mut skey_context,
    out_token: *mut skey_buffer,
) -> skey_status {
    ffi_status(
        || {
            clear_buffer(out_token);

            if ctx.is_null() || out_token.is_null() {
                return set_status(SkeyStatus::InvalidArgument);
            }

            let result = ctx_lock(ctx).and_then(|mut ctx| ctx.create_session());
            write_buffer_result(out_token, result)
        },
        || clear_buffer(out_token),
    )
}

#[no_mangle]
/// # Safety
///
/// `ctx`, `resource_id`, and `out_handle` must follow the pointer rules in
/// `include/skey_runtime.h`.
pub unsafe extern "C" fn skey_resource_open(
    ctx: *mut skey_context,
    resource_id: *const c_char,
    out_handle: *mut u64,
) -> skey_status {
    ffi_status(
        || {
            clear_handle_out(out_handle);

            if validate_ctx(ctx).is_err()
                || validate_c_string(resource_id).is_err()
                || out_handle.is_null()
            {
                return set_status(SkeyStatus::InvalidArgument);
            }

            let resource_id = match c_string(resource_id) {
                Ok(value) => value,
                Err(status) => return set_status(status),
            };
            let _lifecycle = match context_lifecycle_lock() {
                Ok(guard) => guard,
                Err(status) => return set_status(status),
            };
            let mut guard = match ctx_lock_after_lifecycle(ctx) {
                Ok(guard) => guard,
                Err(status) => return set_status(status),
            };
            let local_handle = match guard.resource_open(&resource_id) {
                Ok(handle) => handle,
                Err(status) => return set_status(status),
            };
            match register_resource_handle(ctx, local_handle) {
                Ok(handle) => {
                    *out_handle = handle;
                    set_status(SkeyStatus::Ok)
                }
                Err(status) => {
                    guard.resource_close(local_handle);
                    set_status(status)
                }
            }
        },
        || clear_handle_out(out_handle),
    )
}

#[no_mangle]
/// # Safety
///
/// `out_bytes` must follow the pointer and buffer ownership rules in
/// `include/skey_runtime.h`.
pub unsafe extern "C" fn skey_resource_read(
    handle: u64,
    offset: u64,
    len: usize,
    out_bytes: *mut skey_buffer,
) -> skey_status {
    ffi_status(
        || {
            clear_buffer(out_bytes);

            if handle == 0 || out_bytes.is_null() {
                return set_status(SkeyStatus::InvalidArgument);
            }

            let _lifecycle = match context_lifecycle_lock() {
                Ok(guard) => guard,
                Err(status) => return set_status(status),
            };
            let registered = match lookup_resource_handle(handle) {
                Ok(registered) => registered,
                Err(status) => return set_status(status),
            };
            let ctx = registered.ctx as *mut skey_context;
            let result = ctx_lock_after_lifecycle(ctx)
                .and_then(|mut ctx| ctx.resource_read(registered.local_handle, offset, len));
            write_buffer_result(out_bytes, result)
        },
        || clear_buffer(out_bytes),
    )
}

#[no_mangle]
pub extern "C" fn skey_resource_close(handle: u64) {
    ffi_void(|| {
        let Ok(_lifecycle) = context_lifecycle_lock() else {
            return;
        };
        if let Some(registered) = unregister_resource_handle(handle) {
            let ctx = registered.ctx as *mut skey_context;
            if let Ok(mut ctx) = unsafe { ctx_lock_after_lifecycle(ctx) } {
                ctx.resource_close(registered.local_handle);
            }
        }
    });
}

#[no_mangle]
pub extern "C" fn skey_last_error_message() -> *const c_char {
    ffi_const_char_ptr(last_error_message_ptr)
}

#[no_mangle]
/// # Safety
///
/// `buffer` must be either null/zero or a buffer returned by SKey. Non-empty buffers
/// must be released exactly once and must not be passed to `free`; see
/// `include/skey_runtime.h`.
pub unsafe extern "C" fn skey_buffer_free(buffer: skey_buffer) {
    ffi_void(|| {
        if buffer.data.is_null() || buffer.len == 0 {
            return;
        }

        let slice = ptr::slice_from_raw_parts_mut(buffer.data, buffer.len);
        let mut boxed = Box::from_raw(slice);
        wipe_buffer_contents_for_free(&mut boxed);
        drop(boxed);
    });
}

fn wipe_buffer_contents_for_free(buffer: &mut [u8]) {
    buffer.zeroize();
}

#[no_mangle]
/// # Safety
///
/// `ctx` must be null or a context returned by `skey_runtime_init`. Non-null contexts
/// must be released at most once; see `include/skey_runtime.h`.
pub unsafe extern "C" fn skey_context_free(ctx: *mut skey_context) {
    ffi_void(|| {
        if ctx.is_null() {
            return;
        }

        let Ok(_lifecycle) = context_lifecycle_lock() else {
            return;
        };
        unregister_context_handles(ctx);
        if let Ok(mut guard) = (*ctx).inner.lock() {
            guard.close_all_resources();
        }
        drop(Box::from_raw(ctx));
    });
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;
    use std::ptr;

    use skey_core::errors::SkeyStatus;

    use super::*;

    fn c_ptr(bytes: &'static [u8]) -> *const c_char {
        bytes.as_ptr().cast()
    }

    #[allow(clippy::manual_dangling_ptr)]
    fn invalid_context_ptr() -> *mut skey_context {
        // Keep this test helper compatible with Rust 1.78 instead of using
        // `ptr::dangling_mut`, which newer Clippy suggests.
        1usize as *mut skey_context
    }

    #[allow(clippy::manual_dangling_ptr)]
    fn invalid_u8_ptr() -> *mut u8 {
        // Keep this test helper compatible with Rust 1.78 instead of using
        // `ptr::dangling_mut`, which newer Clippy suggests.
        1usize as *mut u8
    }

    fn test_options() -> skey_init_options {
        skey_init_options {
            app_root: c_ptr(b"app\0"),
            payload_path: c_ptr(b"payload\0"),
            entry_id: c_ptr(b"main\0"),
            original_path: c_ptr(b"original\0"),
            argv_json: c_ptr(b"[]\0"),
            env_session: ptr::null(),
        }
    }

    #[test]
    fn runtime_init_rejects_null_inputs() {
        let mut ctx: *mut skey_context = ptr::null_mut();

        assert_eq!(
            unsafe { skey_runtime_init(ptr::null(), &mut ctx) },
            SkeyStatus::InvalidArgument.as_i32()
        );

        let options = test_options();

        assert_eq!(
            unsafe { skey_runtime_init(&options, ptr::null_mut()) },
            SkeyStatus::InvalidArgument.as_i32()
        );
    }

    #[test]
    fn runtime_init_rejects_unreadable_payload_without_context() {
        let options = test_options();
        let mut ctx: *mut skey_context = ptr::null_mut();

        assert_eq!(
            unsafe { skey_runtime_init(&options, &mut ctx) },
            SkeyStatus::PackageTampered.as_i32()
        );
        assert!(ctx.is_null());
    }

    #[test]
    fn runtime_init_rejects_null_required_option_fields() {
        let options = skey_init_options {
            app_root: ptr::null(),
            payload_path: c_ptr(b"payload\0"),
            entry_id: c_ptr(b"main\0"),
            original_path: c_ptr(b"original\0"),
            argv_json: c_ptr(b"[]\0"),
            env_session: ptr::null(),
        };
        let mut ctx: *mut skey_context = ptr::null_mut();

        assert_eq!(
            unsafe { skey_runtime_init(&options, &mut ctx) },
            SkeyStatus::InvalidArgument.as_i32()
        );
        assert!(ctx.is_null());
    }

    #[test]
    fn context_and_string_arguments_are_validated() {
        let mut buffer = skey_buffer {
            data: ptr::null_mut(),
            len: 42,
        };

        assert_eq!(
            unsafe { skey_license_check(ptr::null_mut(), c_ptr(b"feature\0")) },
            SkeyStatus::InvalidArgument.as_i32()
        );
        assert_eq!(
            unsafe { skey_license_check(invalid_context_ptr(), ptr::null()) },
            SkeyStatus::InvalidArgument.as_i32()
        );
        assert_eq!(
            unsafe { skey_load_entry(ptr::null_mut(), c_ptr(b"main\0"), &mut buffer) },
            SkeyStatus::InvalidArgument.as_i32()
        );
    }

    #[test]
    fn buffer_outputs_are_cleared_before_argument_validation() {
        let mut buffer = skey_buffer {
            data: invalid_u8_ptr(),
            len: 99,
        };

        assert_eq!(
            unsafe { skey_load_module(ptr::null_mut(), c_ptr(b"module\0"), &mut buffer) },
            SkeyStatus::InvalidArgument.as_i32()
        );
        assert!(buffer.data.is_null());
        assert_eq!(buffer.len, 0);

        unsafe { skey_buffer_free(buffer) };
    }

    #[test]
    fn last_error_message_tracks_thread_local_status() {
        let mut ctx: *mut skey_context = ptr::null_mut();
        assert_eq!(
            unsafe { skey_runtime_init(ptr::null(), &mut ctx) },
            SkeyStatus::InvalidArgument.as_i32()
        );

        let message = unsafe { CStr::from_ptr(skey_last_error_message()) }
            .to_str()
            .unwrap();
        assert_eq!(message, SkeyStatus::InvalidArgument.message());
    }

    #[test]
    fn last_error_message_pointer_remains_valid_until_next_update() {
        assert_eq!(
            set_status(SkeyStatus::LicenseMissing),
            SkeyStatus::LicenseMissing.as_i32()
        );
        let message = skey_last_error_message();

        assert_eq!(
            unsafe { CStr::from_ptr(message) }.to_str().unwrap(),
            SkeyStatus::LicenseMissing.message()
        );
        assert_eq!(
            unsafe { CStr::from_ptr(message) }.to_str().unwrap(),
            SkeyStatus::LicenseMissing.message()
        );

        assert_eq!(
            set_status(SkeyStatus::InvalidArgument),
            SkeyStatus::InvalidArgument.as_i32()
        );
        assert_eq!(
            unsafe { CStr::from_ptr(skey_last_error_message()) }
                .to_str()
                .unwrap(),
            SkeyStatus::InvalidArgument.message()
        );
    }

    #[test]
    fn invalid_arguments_clear_prefilled_outputs() {
        let mut ctx = invalid_context_ptr();
        assert_eq!(
            unsafe { skey_runtime_init(ptr::null(), &mut ctx) },
            SkeyStatus::InvalidArgument.as_i32()
        );
        assert!(ctx.is_null());

        let mut buffer = skey_buffer {
            data: invalid_u8_ptr(),
            len: 99,
        };
        assert_eq!(
            unsafe { skey_load_entry(ptr::null_mut(), c_ptr(b"main\0"), &mut buffer) },
            SkeyStatus::InvalidArgument.as_i32()
        );
        assert!(buffer.data.is_null());
        assert_eq!(buffer.len, 0);

        let mut handle = 42;
        assert_eq!(
            unsafe { skey_resource_open(ptr::null_mut(), c_ptr(b"resource\0"), &mut handle) },
            SkeyStatus::InvalidArgument.as_i32()
        );
        assert_eq!(handle, 0);
    }

    #[test]
    fn panic_boundary_converts_status_panics_to_internal() {
        let status = ffi_status(|| panic!("boom"), || {});

        assert_eq!(status, SkeyStatus::Internal.as_i32());
        let message = unsafe { CStr::from_ptr(skey_last_error_message()) }
            .to_str()
            .unwrap();
        assert_eq!(message, SkeyStatus::Internal.message());
    }

    #[test]
    fn buffer_free_accepts_helper_allocated_owned_empty_and_null_context() {
        let empty = skey_buffer {
            data: ptr::null_mut(),
            len: 0,
        };
        unsafe { skey_buffer_free(empty) };
        unsafe { skey_context_free(ptr::null_mut()) };

        let buffer = buffer_from_vec_for_ffi(b"owned".to_vec());
        assert!(!buffer.data.is_null());
        assert_eq!(buffer.len, 5);
        unsafe { skey_buffer_free(buffer) };
    }

    #[test]
    fn buffer_free_wipe_helper_zeroizes_plaintext_before_drop() {
        let mut plaintext = b"secret plaintext".to_vec();

        wipe_buffer_contents_for_free(&mut plaintext);

        assert!(plaintext.iter().all(|byte| *byte == 0));
    }
}
