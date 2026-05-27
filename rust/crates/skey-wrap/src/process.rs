use std::ffi::OsString;
use std::path::Path;

use crate::{Result, WrapError, SESSION_ENV};

#[cfg(not(windows))]
pub fn run_child(executable: &Path, args: &[OsString], session_token: &str) -> Result<i32> {
    use std::process::Command;

    let status = Command::new(executable)
        .args(args)
        .env(SESSION_ENV, session_token)
        .status()
        .map_err(|error| WrapError::new(format!("process launch failed: {error}")))?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(windows)]
pub fn run_child(executable: &Path, args: &[OsString], session_token: &str) -> Result<i32> {
    use std::env;
    use std::mem::{size_of, zeroed};
    use std::ptr;
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW,
    };

    let previous_session = env::var_os(SESSION_ENV);
    env::set_var(SESSION_ENV, session_token);
    let launch_result = (|| {
        let mut command_line = windows_command_line(executable, args);
        let mut startup_info: STARTUPINFOW = unsafe { zeroed() };
        startup_info.cb = size_of::<STARTUPINFOW>() as u32;
        let mut process_info: PROCESS_INFORMATION = unsafe { zeroed() };

        let success = unsafe {
            CreateProcessW(
                ptr::null(),
                command_line.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                1,
                0,
                ptr::null(),
                ptr::null(),
                &startup_info,
                &mut process_info,
            )
        };
        if success == 0 {
            return Err(WrapError::new("CreateProcessW failed"));
        }

        let exit_code = wait_for_child(process_info);
        close_handle(process_info.hThread);
        close_handle(process_info.hProcess);
        exit_code
    })();
    match previous_session {
        Some(value) => env::set_var(SESSION_ENV, value),
        None => env::remove_var(SESSION_ENV),
    }
    launch_result
}

#[cfg(windows)]
fn wait_for_child(
    process_info: windows_sys::Win32::System::Threading::PROCESS_INFORMATION,
) -> Result<i32> {
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, WaitForSingleObject, INFINITE,
    };

    let wait_result = unsafe { WaitForSingleObject(process_info.hProcess, INFINITE) };
    if wait_result == u32::MAX {
        return Err(WrapError::new("WaitForSingleObject failed"));
    }
    let mut exit_code = 0u32;
    if unsafe { GetExitCodeProcess(process_info.hProcess, &mut exit_code) } == 0 {
        return Err(WrapError::new("GetExitCodeProcess failed"));
    }
    Ok(exit_code as i32)
}

#[cfg(windows)]
fn close_handle(handle: windows_sys::Win32::Foundation::HANDLE) {
    use windows_sys::Win32::Foundation::CloseHandle;

    if !handle.is_null() {
        unsafe {
            CloseHandle(handle);
        }
    }
}

#[cfg(windows)]
fn windows_command_line(executable: &Path, args: &[OsString]) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    let mut command = quote_windows_arg(&executable.as_os_str().encode_wide().collect::<Vec<_>>());
    for arg in args {
        command.push(' ');
        command.push_str(&quote_windows_arg(&arg.encode_wide().collect::<Vec<_>>()));
    }
    command.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn quote_windows_arg(wide: &[u16]) -> String {
    let raw = String::from_utf16_lossy(wide);
    if raw.is_empty() {
        return "\"\"".to_owned();
    }
    if !raw.bytes().any(|byte| matches!(byte, b' ' | b'\t' | b'"')) {
        return raw;
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0usize;
    for ch in raw.chars() {
        if ch == '\\' {
            backslashes += 1;
            continue;
        }
        if ch == '"' {
            quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
            quoted.push('"');
            backslashes = 0;
            continue;
        }
        quoted.push_str(&"\\".repeat(backslashes));
        backslashes = 0;
        quoted.push(ch);
    }
    quoted.push_str(&"\\".repeat(backslashes * 2));
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use std::ffi::OsString;

    #[cfg(windows)]
    #[test]
    fn windows_command_line_quotes_spaces_and_quotes() {
        let command = super::windows_command_line(
            std::path::Path::new(r"C:\Program Files\tool.exe"),
            &[OsString::from(r#"a "quoted" value"#)],
        );
        let rendered = String::from_utf16(&command[..command.len() - 1]).unwrap();

        assert_eq!(
            rendered,
            r#""C:\Program Files\tool.exe" "a \"quoted\" value""#,
        );
    }
}
