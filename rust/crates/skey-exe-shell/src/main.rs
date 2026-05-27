use std::env;
use std::process;

fn main() {
    match skey_wrap::run_current_exe(env::args_os().skip(1).collect()) {
        Ok(code) => process::exit(code),
        Err(error) => {
            eprintln!("skey exe shell: {error}");
            process::exit(1);
        }
    }
}
