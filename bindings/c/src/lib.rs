//! C ABI (`extern "C"`) bindings for the Quipu core. Stateless, panic-safe,
//! caller-frees-output. See docs/superpowers/specs/2026-07-05-c-abi-bindings-design.md.
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::{c_char, CStr};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

use quipu::stream::{
    decrypt_stream_bytes as core_decrypt_stream, encrypt_stream as core_encrypt_stream,
    StreamError, StreamOptions,
};

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

// --- internal helpers (non-`extern`, so cbindgen ignores them) ---

/// Borrows `len` bytes at `ptr`. A NULL pointer is valid only when `len == 0`
/// (an empty input), yielding an empty slice.
///
/// SAFETY: if `ptr` is non-null it must point to `len` readable bytes valid for
/// the returned borrow's lifetime.
unsafe fn as_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return if len == 0 { Some(&[]) } else { None };
    }
    Some(unsafe { slice::from_raw_parts(ptr, len) })
}

/// Borrows a NUL-terminated UTF-8 C string. NULL or invalid UTF-8 -> None.
///
/// SAFETY: if non-null, `ptr` must be a valid NUL-terminated C string.
unsafe fn as_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

/// Hands ownership of `v` to the caller via `out`/`out_len`. The exact-sized
/// boxed slice means the free path needs only (ptr, len).
///
/// SAFETY: `out` and `out_len` must be valid, writable pointers.
unsafe fn write_bytes(v: Vec<u8>, out: *mut *mut u8, out_len: *mut usize) {
    let boxed = v.into_boxed_slice();
    let len = boxed.len();
    let ptr = Box::into_raw(boxed) as *mut u8;
    unsafe {
        *out = ptr;
        *out_len = len;
    }
}

fn map_stream_err(e: StreamError) -> i32 {
    let s = match e {
        StreamError::BadChunkSize => QUIPU_ERR_CHUNK,
        StreamError::Decrypt | StreamError::Truncated => QUIPU_ERR_AUTH,
        StreamError::Header | StreamError::UnsupportedVersion(_) | StreamError::InsaneKdf => {
            QUIPU_ERR_KEY
        }
        StreamError::Io(_) => QUIPU_ERR_INTERNAL,
    };
    s as i32
}

// --- exports ---

/// Frees a byte buffer returned by any `quipu_*` function. No-op on NULL.
///
/// # Safety
/// `ptr`/`len` must come unmodified from a Quipu byte output, freed once.
#[no_mangle]
pub unsafe extern "C" fn quipu_bytes_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let s = slice::from_raw_parts_mut(ptr, len);
        drop(Box::from_raw(s as *mut [u8]));
    }
}

/// Encrypts `data` into the streaming AEAD container (`QST1`). `chunk_size == 0`
/// uses the format default; otherwise it must be in 4 KiB..=16 MiB. `pepper`
/// may be `(NULL, 0)`.
///
/// # Safety
/// Pointers must satisfy the documented borrow/out-pointer contracts.
#[no_mangle]
pub unsafe extern "C" fn quipu_encrypt_stream(
    data: *const u8,
    data_len: usize,
    passphrase: *const c_char,
    pepper: *const u8,
    pepper_len: usize,
    chunk_size: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    guard(|| {
        if out.is_null() || out_len.is_null() {
            return QUIPU_ERR_NULL_ARG as i32;
        }
        let data = match unsafe { as_slice(data, data_len) } {
            Some(s) => s,
            None => return QUIPU_ERR_NULL_ARG as i32,
        };
        let pepper = match unsafe { as_slice(pepper, pepper_len) } {
            Some(s) => s,
            None => return QUIPU_ERR_NULL_ARG as i32,
        };
        let passphrase = match unsafe { as_str(passphrase) } {
            Some(s) => s,
            None => return QUIPU_ERR_NULL_ARG as i32,
        };
        let mut opts = StreamOptions {
            pepper,
            ..StreamOptions::default()
        };
        if chunk_size != 0 {
            opts.chunk_size = chunk_size;
        }
        // Fallible variant: a bad chunk_size returns an error instead of the
        // panicking `encrypt_stream_bytes`.
        let mut blob = Vec::new();
        match core_encrypt_stream(data, &mut blob, passphrase, &opts) {
            Ok(()) => {
                unsafe { write_bytes(blob, out, out_len) };
                QUIPU_OK as i32
            }
            Err(e) => map_stream_err(e),
        }
    })
}

/// Decrypts a `QST1` container produced by `quipu_encrypt_stream` (same
/// `pepper`). `chunk_size` is read from the header.
///
/// # Safety
/// Pointers must satisfy the documented borrow/out-pointer contracts.
#[no_mangle]
pub unsafe extern "C" fn quipu_decrypt_stream(
    blob: *const u8,
    blob_len: usize,
    passphrase: *const c_char,
    pepper: *const u8,
    pepper_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    guard(|| {
        if out.is_null() || out_len.is_null() {
            return QUIPU_ERR_NULL_ARG as i32;
        }
        let blob = match unsafe { as_slice(blob, blob_len) } {
            Some(s) => s,
            None => return QUIPU_ERR_NULL_ARG as i32,
        };
        let pepper = match unsafe { as_slice(pepper, pepper_len) } {
            Some(s) => s,
            None => return QUIPU_ERR_NULL_ARG as i32,
        };
        let passphrase = match unsafe { as_str(passphrase) } {
            Some(s) => s,
            None => return QUIPU_ERR_NULL_ARG as i32,
        };
        match core_decrypt_stream(blob, passphrase, pepper) {
            Ok(bytes) => {
                unsafe { write_bytes(bytes, out, out_len) };
                QUIPU_OK as i32
            }
            Err(e) => map_stream_err(e),
        }
    })
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

    #[test]
    fn stream_roundtrip() {
        let msg = b"attack at dawn";
        let pass = c"correct horse".as_ptr();
        let (mut blob, mut blob_len) = (std::ptr::null_mut(), 0usize);
        let rc = unsafe {
            quipu_encrypt_stream(
                msg.as_ptr(),
                msg.len(),
                pass,
                std::ptr::null(),
                0,
                0,
                &mut blob,
                &mut blob_len,
            )
        };
        assert_eq!(rc, QUIPU_OK as i32);
        assert!(!blob.is_null() && blob_len > 0);

        let (mut out, mut out_len) = (std::ptr::null_mut(), 0usize);
        let rc = unsafe {
            quipu_decrypt_stream(
                blob,
                blob_len,
                pass,
                std::ptr::null(),
                0,
                &mut out,
                &mut out_len,
            )
        };
        assert_eq!(rc, QUIPU_OK as i32);
        let got = unsafe { std::slice::from_raw_parts(out, out_len) };
        assert_eq!(got, msg);

        unsafe {
            quipu_bytes_free(blob, blob_len);
            quipu_bytes_free(out, out_len);
            quipu_bytes_free(std::ptr::null_mut(), 0); // no-op
        }
    }

    #[test]
    fn stream_wrong_passphrase_is_auth_error() {
        let msg = b"secret";
        let (mut blob, mut blob_len) = (std::ptr::null_mut(), 0usize);
        unsafe {
            quipu_encrypt_stream(
                msg.as_ptr(),
                msg.len(),
                c"right".as_ptr(),
                std::ptr::null(),
                0,
                0,
                &mut blob,
                &mut blob_len,
            );
        }
        let (mut out, mut out_len) = (std::ptr::null_mut(), 0usize);
        let rc = unsafe {
            quipu_decrypt_stream(
                blob,
                blob_len,
                c"wrong".as_ptr(),
                std::ptr::null(),
                0,
                &mut out,
                &mut out_len,
            )
        };
        assert_eq!(rc, QUIPU_ERR_AUTH as i32);
        assert!(out.is_null());
        unsafe {
            quipu_bytes_free(blob, blob_len);
        }
    }

    #[test]
    fn stream_bad_chunk_size_is_chunk_error() {
        let msg = b"x";
        let (mut blob, mut blob_len) = (std::ptr::null_mut(), 0usize);
        let rc = unsafe {
            quipu_encrypt_stream(
                msg.as_ptr(),
                msg.len(),
                c"p".as_ptr(),
                std::ptr::null(),
                0,
                64, // 64 < 4 KiB
                &mut blob,
                &mut blob_len,
            )
        };
        assert_eq!(rc, QUIPU_ERR_CHUNK as i32);
    }

    #[test]
    fn stream_null_out_is_null_arg() {
        let msg = b"x";
        let rc = unsafe {
            quipu_encrypt_stream(
                msg.as_ptr(),
                msg.len(),
                c"p".as_ptr(),
                std::ptr::null(),
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, QUIPU_ERR_NULL_ARG as i32);
    }
}
