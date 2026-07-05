//! C ABI (`extern "C"`) bindings for the Quipu core. Stateless, panic-safe,
//! caller-frees-output. See docs/superpowers/specs/2026-07-05-c-abi-bindings-design.md.
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Status codes returned by every fallible export. `0` = success, negative =
/// error. Coarse by design: no failure oracle finer than the Rust API's.
#[allow(non_camel_case_types)]
#[repr(i32)]
pub enum quipu_status {
    QUIPU_OK = 0,
    QUIPU_ERR_NULL_ARG = -1,
    QUIPU_ERR_AUTH = -2,
    QUIPU_ERR_KEY = -3,
    QUIPU_ERR_CHUNK = -4,
    QUIPU_ERR_INTERNAL = -5,
}
use quipu_status::*;

/// Runs `f`, converting any panic into `QUIPU_ERR_INTERNAL`. A panic must never
/// unwind across the FFI boundary (that is undefined behavior).
fn guard(f: impl FnOnce() -> i32) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(code) => code,
        Err(_) => QUIPU_ERR_INTERNAL as i32,
    }
}

/// Returns a static, NUL-terminated version string. DO NOT free.
#[no_mangle]
pub extern "C" fn quipu_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn version_is_nonempty_cstr() {
        let ptr = quipu_version();
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert!(!s.is_empty());
        assert!(s.chars().next().unwrap().is_ascii_digit());
    }

    #[test]
    fn guard_swallows_panic() {
        let code = guard(|| panic!("boom"));
        assert_eq!(code, QUIPU_ERR_INTERNAL as i32);
    }
}
