//! JNI bridge for the SKey Java loader.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::ptr;
use std::sync::{Mutex, MutexGuard};

use jni::objects::{JClass, JObject, JObjectArray, JString, JThrowable, JValue};
use jni::sys::{jbyteArray, jlong, jobjectArray, jstring};
use jni::JNIEnv;
use skey_core::context::{RuntimeContext, RuntimeInitOptions};
use skey_core::errors::SkeyStatus;

const SKEY_EXCEPTION_CLASS: &str = "com/vendor/skey/NativeBridge$SKeyException";
const RUNTIME_EXCEPTION_CLASS: &str = "java/lang/RuntimeException";

type JniResult<T> = Result<T, SkeyStatus>;
type NativeHandle = Mutex<RuntimeContext>;

fn safe_jni<T, F>(mut env: JNIEnv<'_>, default: T, operation: F) -> T
where
    F: FnOnce(&mut JNIEnv<'_>) -> T,
{
    match catch_unwind(AssertUnwindSafe(|| operation(&mut env))) {
        Ok(value) => value,
        Err(_) => {
            throw_skey_exception(&mut env, SkeyStatus::Internal);
            default
        }
    }
}

fn throw_skey_exception(env: &mut JNIEnv<'_>, status: SkeyStatus) {
    if throw_native_bridge_exception(env, status).is_err() {
        let _ = env.exception_clear();
        let _ = env.throw_new(
            RUNTIME_EXCEPTION_CLASS,
            format!("SKEY[{}]: {}", status.as_i32(), status.message()),
        );
    }
}

fn throw_native_bridge_exception(
    env: &mut JNIEnv<'_>,
    status: SkeyStatus,
) -> jni::errors::Result<()> {
    let class = env.find_class(SKEY_EXCEPTION_CLASS)?;
    let message = env.new_string(status.message())?;
    let message_obj = JObject::from(message);
    let exception = env.new_object(
        class,
        "(ILjava/lang/String;)V",
        &[JValue::Int(status.as_i32()), JValue::Object(&message_obj)],
    )?;
    env.throw(JThrowable::from(exception))
}

fn java_string_ref(env: &mut JNIEnv<'_>, value: &JString<'_>) -> JniResult<String> {
    if value.is_null() {
        return Err(SkeyStatus::InvalidArgument);
    }
    env.get_string(value)
        .map(|value| value.into())
        .map_err(|_| SkeyStatus::InvalidArgument)
}

fn java_string(env: &mut JNIEnv<'_>, value: JString<'_>) -> JniResult<String> {
    java_string_ref(env, &value)
}

fn optional_java_string(env: &mut JNIEnv<'_>, value: JString<'_>) -> JniResult<Option<String>> {
    if value.is_null() {
        Ok(None)
    } else {
        java_string(env, value).map(Some)
    }
}

fn java_args_json(env: &mut JNIEnv<'_>, args: jobjectArray) -> JniResult<String> {
    if args.is_null() {
        return Err(SkeyStatus::InvalidArgument);
    }
    let args = unsafe { JObjectArray::from_raw(args) };
    let len = env
        .get_array_length(&args)
        .map_err(|_| SkeyStatus::InvalidArgument)?;
    let mut values = Vec::with_capacity(len as usize);
    for index in 0..len {
        let item = env
            .get_object_array_element(&args, index)
            .map_err(|_| SkeyStatus::InvalidArgument)?;
        if item.is_null() {
            return Err(SkeyStatus::InvalidArgument);
        }
        let item = env.auto_local(item);
        let item: &JString<'_> = (&*item).into();
        values.push(java_string_ref(env, item)?);
    }
    serde_json::to_string(&values).map_err(|_| SkeyStatus::InvalidArgument)
}

fn init_options(
    env: &mut JNIEnv<'_>,
    app_root: JString<'_>,
    payload_path: JString<'_>,
    entry_id: JString<'_>,
    original_path: JString<'_>,
    args: jobjectArray,
    env_session: JString<'_>,
) -> JniResult<RuntimeInitOptions> {
    Ok(RuntimeInitOptions {
        app_root: PathBuf::from(java_string(env, app_root)?),
        payload_path: PathBuf::from(java_string(env, payload_path)?),
        entry_id: java_string(env, entry_id)?,
        original_path: java_string(env, original_path)?,
        argv_json: java_args_json(env, args)?,
        env_session: optional_java_string(env, env_session)?,
    })
}

fn context_from_handle<'a>(handle: jlong) -> JniResult<MutexGuard<'a, RuntimeContext>> {
    if handle == 0 {
        return Err(SkeyStatus::InvalidArgument);
    }
    let context = handle as *mut NativeHandle;
    if context.is_null() {
        return Err(SkeyStatus::InvalidArgument);
    }
    unsafe { (*context).lock().map_err(|_| SkeyStatus::Internal) }
}

fn return_or_throw<T>(env: &mut JNIEnv<'_>, result: JniResult<T>, default: T) -> T {
    match result {
        Ok(value) => value,
        Err(status) => {
            throw_skey_exception(env, status);
            default
        }
    }
}

fn byte_array(env: &mut JNIEnv<'_>, bytes: Vec<u8>) -> JniResult<jbyteArray> {
    env.byte_array_from_slice(&bytes)
        .map(|array| array.into_raw())
        .map_err(|_| SkeyStatus::Internal)
}

fn string(env: &mut JNIEnv<'_>, bytes: Vec<u8>) -> JniResult<jstring> {
    let token = String::from_utf8(bytes).map_err(|_| SkeyStatus::Internal)?;
    env.new_string(token)
        .map(|value| value.into_raw())
        .map_err(|_| SkeyStatus::Internal)
}

#[no_mangle]
pub extern "system" fn Java_com_vendor_skey_NativeBridge_initNative(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    app_root: JString<'_>,
    payload_path: JString<'_>,
    entry_id: JString<'_>,
    original_path: JString<'_>,
    args: jobjectArray,
    env_session: JString<'_>,
) -> jlong {
    safe_jni(env, 0, |env| {
        let result = init_options(
            env,
            app_root,
            payload_path,
            entry_id,
            original_path,
            args,
            env_session,
        )
        .and_then(RuntimeContext::new)
        .map(|context| Box::into_raw(Box::new(Mutex::new(context))) as jlong);
        return_or_throw(env, result, 0)
    })
}

#[no_mangle]
pub extern "system" fn Java_com_vendor_skey_NativeBridge_checkNative(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    feature: JString<'_>,
) {
    safe_jni(env, (), |env| {
        let result = java_string(env, feature).and_then(|feature| {
            let mut context = context_from_handle(handle)?;
            context.license_check(&feature)
        });
        if let Err(status) = result {
            throw_skey_exception(env, status);
        }
    });
}

#[no_mangle]
pub extern "system" fn Java_com_vendor_skey_NativeBridge_materializeNative(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    entry_id: JString<'_>,
) -> jbyteArray {
    safe_jni(env, ptr::null_mut(), |env| {
        let result = java_string(env, entry_id).and_then(|entry_id| {
            let mut context = context_from_handle(handle)?;
            let bytes = context.materialize_entry(&entry_id)?;
            byte_array(env, bytes)
        });
        match result {
            Ok(array) => array,
            Err(status) => {
                throw_skey_exception(env, status);
                ptr::null_mut()
            }
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_com_vendor_skey_NativeBridge_createSessionNative(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jstring {
    safe_jni(env, ptr::null_mut(), |env| {
        let result = context_from_handle(handle)
            .and_then(|mut context| context.create_session())
            .and_then(|token| string(env, token));
        match result {
            Ok(token) => token,
            Err(status) => {
                throw_skey_exception(env, status);
                ptr::null_mut()
            }
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_com_vendor_skey_NativeBridge_freeNative(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    safe_jni(env, (), |env| {
        if handle == 0 {
            throw_skey_exception(env, SkeyStatus::InvalidArgument);
            return;
        }
        unsafe {
            drop(Box::from_raw(handle as *mut NativeHandle));
        }
    });
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn args_json_uses_stable_json_array_shape() {
        let args = vec!["--config".to_owned(), "config.yaml".to_owned()];

        let json = serde_json::to_string(&args).expect("args json");

        assert_eq!(json, json!(["--config", "config.yaml"]).to_string());
    }

    #[test]
    fn context_from_handle_rejects_zero_handle() {
        assert!(matches!(
            context_from_handle(0),
            Err(SkeyStatus::InvalidArgument)
        ));
    }
}
