// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! C ABI (`extern "C"`) bindings for the Quipu core. Stateless, panic-safe,
//! caller-frees-output. See docs/superpowers/specs/2026-07-05-c-abi-bindings-design.md.
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

use zeroize::Zeroize;

use quipu::api::{
    decode as core_decode, decode_as_recipient as core_decode_pq,
    decode_verified as core_decode_verified, encode as core_encode,
    encode_signed as core_encode_signed, encode_to_recipient as core_encode_pq, DecodeError,
    Options,
};
use quipu::dictionary::Dictionary;
use quipu::kdf::KdfParams;
use quipu::{pqhybrid, pqsign};
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

/// The default 94-symbol printable-ASCII dictionary (matches the Python layer).
fn default_dict() -> Dictionary {
    Dictionary::new((0x21u8..=0x7e).map(|b| b as char).collect())
        .expect("el alfabeto ASCII por defecto es válido")
}

/// Hands ownership of a glyph string to the caller as a NUL-terminated C string.
///
/// SAFETY: `out` must be a valid, writable pointer.
unsafe fn write_string(s: String, out: *mut *mut c_char) -> i32 {
    match CString::new(s) {
        Ok(cs) => {
            unsafe { *out = cs.into_raw() };
            QUIPU_OK as i32
        }
        // Glyph symbols are 0x21..=0x7e, so an interior NUL is impossible; keep
        // the arm defensive rather than panicking.
        Err(_) => QUIPU_ERR_INTERNAL as i32,
    }
}

fn map_decode_err(e: DecodeError) -> i32 {
    let s = match e {
        DecodeError::Decrypt | DecodeError::BadSignature => QUIPU_ERR_AUTH,
        DecodeError::Symbol(_) | DecodeError::Container(_) | DecodeError::CodebookMismatch => {
            QUIPU_ERR_KEY
        }
    };
    s as i32
}

// --- exports ---

/// Frees a byte buffer returned by any `quipu_*` function. The buffer is wiped
/// before release, so secret keys and decrypted plaintext leave no residue. No-op
/// on NULL.
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
        s.zeroize();
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

/// Frees a string returned by any `quipu_*` function. No-op on NULL.
///
/// # Safety
/// `ptr` must come unmodified from a Quipu string output, freed once.
#[no_mangle]
pub unsafe extern "C" fn quipu_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe { drop(CString::from_raw(ptr)) };
}

/// Encodes `data` protected by `passphrase` into glyph symbols. `pepper` may be
/// `(NULL, 0)`. On success writes a NUL-terminated string to `*out`.
///
/// # Safety
/// Pointers must satisfy the documented borrow/out-pointer contracts.
#[no_mangle]
pub unsafe extern "C" fn quipu_encode(
    data: *const u8,
    data_len: usize,
    passphrase: *const c_char,
    pepper: *const u8,
    pepper_len: usize,
    out: *mut *mut c_char,
) -> i32 {
    guard(|| {
        if out.is_null() {
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
        let opts = Options {
            pepper,
            kdf_params: KdfParams::default(),
            codebook_id: 0,
        };
        let s = core_encode(data, passphrase, &default_dict(), &opts);
        unsafe { write_string(s, out) }
    })
}

/// Decodes glyph `symbols` with `passphrase` (and optional `pepper`). On success
/// writes plaintext bytes to `*out`/`*out_len`.
///
/// # Safety
/// Pointers must satisfy the documented borrow/out-pointer contracts.
#[no_mangle]
pub unsafe extern "C" fn quipu_decode(
    symbols: *const c_char,
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
        let symbols = match unsafe { as_str(symbols) } {
            Some(s) => s,
            None => return QUIPU_ERR_NULL_ARG as i32,
        };
        let passphrase = match unsafe { as_str(passphrase) } {
            Some(s) => s,
            None => return QUIPU_ERR_NULL_ARG as i32,
        };
        let pepper = match unsafe { as_slice(pepper, pepper_len) } {
            Some(s) => s,
            None => return QUIPU_ERR_NULL_ARG as i32,
        };
        match core_decode(symbols, passphrase, &default_dict(), pepper) {
            Ok(bytes) => {
                unsafe { write_bytes(bytes, out, out_len) };
                QUIPU_OK as i32
            }
            Err(e) => map_decode_err(e),
        }
    })
}

/// Generates a hybrid post-quantum keypair (X25519 + ML-KEM-1024). Writes the
/// public key (1600 B) and secret key (3200 B) as freshly allocated buffers.
///
/// # Safety
/// All four out-pointers must be valid, writable pointers.
#[no_mangle]
pub unsafe extern "C" fn quipu_generate_keypair(
    pk: *mut *mut u8,
    pk_len: *mut usize,
    sk: *mut *mut u8,
    sk_len: *mut usize,
) -> i32 {
    guard(|| {
        if pk.is_null() || pk_len.is_null() || sk.is_null() || sk_len.is_null() {
            return QUIPU_ERR_NULL_ARG as i32;
        }
        let (public, secret) = pqhybrid::generate_keypair();
        unsafe {
            write_bytes(public.to_bytes(), pk, pk_len);
            // to_bytes() ahora devuelve Zeroizing<Vec<u8>> (higiene, capa 2);
            // write_bytes toma posesión de un Vec, así que .to_vec() — igual que
            // en los casos de pqsign (líneas de vk/state). El secreto se entrega
            // al llamador C a propósito; su custodia/liberación es del lado C (N7).
            write_bytes(secret.to_bytes().to_vec(), sk, sk_len);
        }
        QUIPU_OK as i32
    })
}

/// Encrypts `data` to a recipient's hybrid public key (`pk`, 1600 B). On success
/// writes glyph symbols to `*out`.
///
/// # Safety
/// Pointers must satisfy the documented borrow/out-pointer contracts.
#[no_mangle]
pub unsafe extern "C" fn quipu_encrypt_to_recipient(
    data: *const u8,
    data_len: usize,
    pk: *const u8,
    pk_len: usize,
    out: *mut *mut c_char,
) -> i32 {
    guard(|| {
        if out.is_null() {
            return QUIPU_ERR_NULL_ARG as i32;
        }
        let data = match unsafe { as_slice(data, data_len) } {
            Some(s) => s,
            None => return QUIPU_ERR_NULL_ARG as i32,
        };
        let pk_bytes = match unsafe { as_slice(pk, pk_len) } {
            Some(s) => s,
            None => return QUIPU_ERR_NULL_ARG as i32,
        };
        let public = match pqhybrid::PublicKey::from_bytes(pk_bytes) {
            Some(k) => k,
            None => return QUIPU_ERR_KEY as i32,
        };
        let s = core_encode_pq(data, &public, &default_dict());
        unsafe { write_string(s, out) }
    })
}

/// Decrypts recipient symbols with the hybrid secret key (`sk`, 3200 B). On
/// success writes plaintext to `*out`/`*out_len`.
///
/// # Safety
/// Pointers must satisfy the documented borrow/out-pointer contracts.
#[no_mangle]
pub unsafe extern "C" fn quipu_decrypt_as_recipient(
    symbols: *const c_char,
    sk: *const u8,
    sk_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    guard(|| {
        if out.is_null() || out_len.is_null() {
            return QUIPU_ERR_NULL_ARG as i32;
        }
        let symbols = match unsafe { as_str(symbols) } {
            Some(s) => s,
            None => return QUIPU_ERR_NULL_ARG as i32,
        };
        let sk_bytes = match unsafe { as_slice(sk, sk_len) } {
            Some(s) => s,
            None => return QUIPU_ERR_NULL_ARG as i32,
        };
        let secret = match pqhybrid::SecretKey::from_bytes(sk_bytes) {
            Some(k) => k,
            None => return QUIPU_ERR_KEY as i32,
        };
        match core_decode_pq(symbols, &secret, &default_dict()) {
            Ok(bytes) => {
                unsafe { write_bytes(bytes, out, out_len) };
                QUIPU_OK as i32
            }
            Err(e) => map_decode_err(e),
        }
    })
}

/// Generates a hybrid signing keypair (Ed25519 + ML-DSA-87). Writes the
/// verifying key (2624 B) and the sensitive signing key (64 B).
///
/// # Safety
/// All four out-pointers must be valid, writable pointers.
#[no_mangle]
pub unsafe extern "C" fn quipu_generate_signing_keypair(
    vk: *mut *mut u8,
    vk_len: *mut usize,
    sk: *mut *mut u8,
    sk_len: *mut usize,
) -> i32 {
    guard(|| {
        if vk.is_null() || vk_len.is_null() || sk.is_null() || sk_len.is_null() {
            return QUIPU_ERR_NULL_ARG as i32;
        }
        let (verifying, signing) = pqsign::generate_keypair();
        unsafe {
            write_bytes(verifying.to_bytes(), vk, vk_len);
            write_bytes(signing.to_bytes().to_vec(), sk, sk_len);
        }
        QUIPU_OK as i32
    })
}

/// Signs `data` with the hybrid signing key (`sk`, 64 B). The output is a
/// self-contained, SIGNED-BUT-CLEARTEXT artifact (authenticity, not secrecy).
/// On success writes glyph symbols to `*out`.
///
/// # Safety
/// Pointers must satisfy the documented borrow/out-pointer contracts.
#[no_mangle]
pub unsafe extern "C" fn quipu_sign(
    data: *const u8,
    data_len: usize,
    sk: *const u8,
    sk_len: usize,
    out: *mut *mut c_char,
) -> i32 {
    guard(|| {
        if out.is_null() {
            return QUIPU_ERR_NULL_ARG as i32;
        }
        let data = match unsafe { as_slice(data, data_len) } {
            Some(s) => s,
            None => return QUIPU_ERR_NULL_ARG as i32,
        };
        let sk_bytes = match unsafe { as_slice(sk, sk_len) } {
            Some(s) => s,
            None => return QUIPU_ERR_NULL_ARG as i32,
        };
        let signing = match pqsign::SigningKey::from_bytes(sk_bytes) {
            Some(k) => k,
            None => return QUIPU_ERR_KEY as i32,
        };
        let s = core_encode_signed(data, &signing, &default_dict());
        unsafe { write_string(s, out) }
    })
}

/// Verifies a signed artifact against the PINNED verifying key (`vk`, 2624 B)
/// and, only if it validates, writes the message to `*out`/`*out_len`.
///
/// # Safety
/// Pointers must satisfy the documented borrow/out-pointer contracts.
#[no_mangle]
pub unsafe extern "C" fn quipu_verify(
    symbols: *const c_char,
    vk: *const u8,
    vk_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    guard(|| {
        if out.is_null() || out_len.is_null() {
            return QUIPU_ERR_NULL_ARG as i32;
        }
        let symbols = match unsafe { as_str(symbols) } {
            Some(s) => s,
            None => return QUIPU_ERR_NULL_ARG as i32,
        };
        let vk_bytes = match unsafe { as_slice(vk, vk_len) } {
            Some(s) => s,
            None => return QUIPU_ERR_NULL_ARG as i32,
        };
        let verifying = match pqsign::VerifyingKey::from_bytes(vk_bytes) {
            Some(k) => k,
            None => return QUIPU_ERR_KEY as i32,
        };
        match core_decode_verified(symbols, &verifying, &default_dict()) {
            Ok(bytes) => {
                unsafe { write_bytes(bytes, out, out_len) };
                QUIPU_OK as i32
            }
            Err(e) => map_decode_err(e),
        }
    })
}

// --- VOPRF client hardening (talks to a quipu-oprf-server) ---

/// Client-side VOPRF blinding. Writes the ephemeral blind state (64 B, KEEP for
/// finalize) and the blinded point (32 B, SEND to the server). Both buffers are
/// freshly allocated; free with `quipu_bytes_free`.
///
/// # Safety
/// All four out-pointers must be valid, writable pointers.
#[no_mangle]
pub unsafe extern "C" fn quipu_voprf_blind(
    password: *const u8,
    password_len: usize,
    state: *mut *mut u8,
    state_len: *mut usize,
    blinded: *mut *mut u8,
    blinded_len: *mut usize,
) -> i32 {
    guard(|| {
        if state.is_null() || state_len.is_null() || blinded.is_null() || blinded_len.is_null() {
            return QUIPU_ERR_NULL_ARG as i32;
        }
        let pw = match unsafe { as_slice(password, password_len) } {
            Some(s) => s,
            None => return QUIPU_ERR_NULL_ARG as i32,
        };
        // RFC 9497 §3.3.2: `blind` falla si la entrada mapea a la identidad.
        let (st, b) = match quipu::voprf::blind(pw) {
            Some(v) => v,
            None => return QUIPU_ERR_KEY as i32,
        };
        unsafe {
            write_bytes(st.to_bytes().to_vec(), state, state_len);
            write_bytes(b.to_vec(), blinded, blinded_len);
        }
        QUIPU_OK as i32
    })
}

/// Client-side VOPRF finalize. VERIFIES the DLEQ `proof` (64 B) against the
/// PINNED `server_pub` (32 B) and, only if it validates, writes the 64 B
/// hardened secret to `*out`/`*out_len` (free with `quipu_bytes_free`).
/// NOTE: 64 B, not 32 — RFC 9497's output is the full SHA-512 hash. This
/// changed when the custom construction was replaced by the conformant one.
/// `state` (64 B) is from `quipu_voprf_blind`; `evaluated` (32 B) and `proof`
/// come from the server. Returns `QUIPU_ERR_AUTH` if the proof is invalid
/// (dishonest server or wrong pinned key).
///
/// # Safety
/// Pointers must satisfy the documented borrow/out-pointer contracts.
#[no_mangle]
pub unsafe extern "C" fn quipu_voprf_finalize(
    password: *const u8,
    password_len: usize,
    state: *const u8,
    state_len: usize,
    evaluated: *const u8,
    evaluated_len: usize,
    proof: *const u8,
    proof_len: usize,
    server_pub: *const u8,
    server_pub_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    guard(|| {
        if out.is_null() || out_len.is_null() {
            return QUIPU_ERR_NULL_ARG as i32;
        }
        let pw = match unsafe { as_slice(password, password_len) } {
            Some(s) => s,
            None => return QUIPU_ERR_NULL_ARG as i32,
        };
        let st_bytes = match unsafe { as_slice(state, state_len) } {
            Some(s) => s,
            None => return QUIPU_ERR_NULL_ARG as i32,
        };
        let ev = match unsafe { as_slice(evaluated, evaluated_len) } {
            Some(s) => s,
            None => return QUIPU_ERR_NULL_ARG as i32,
        };
        let pf = match unsafe { as_slice(proof, proof_len) } {
            Some(s) => s,
            None => return QUIPU_ERR_NULL_ARG as i32,
        };
        let sp = match unsafe { as_slice(server_pub, server_pub_len) } {
            Some(s) => s,
            None => return QUIPU_ERR_NULL_ARG as i32,
        };

        let st_arr: [u8; 64] = match st_bytes.try_into() {
            Ok(a) => a,
            Err(_) => return QUIPU_ERR_KEY as i32,
        };
        let ev_arr: [u8; 32] = match ev.try_into() {
            Ok(a) => a,
            Err(_) => return QUIPU_ERR_KEY as i32,
        };
        let pf_arr: [u8; 64] = match pf.try_into() {
            Ok(a) => a,
            Err(_) => return QUIPU_ERR_KEY as i32,
        };
        let sp_arr: [u8; 32] = match sp.try_into() {
            Ok(a) => a,
            Err(_) => return QUIPU_ERR_KEY as i32,
        };

        let state = match quipu::voprf::BlindState::from_bytes(&st_arr) {
            Some(s) => s,
            None => return QUIPU_ERR_KEY as i32,
        };
        match quipu::voprf::finalize(pw, &state, &ev_arr, &pf_arr, &sp_arr) {
            Some(key) => {
                unsafe { write_bytes(key.to_vec(), out, out_len) };
                QUIPU_OK as i32
            }
            None => QUIPU_ERR_AUTH as i32,
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

    #[test]
    fn codec_roundtrip() {
        let msg = b"hello glyphs";
        let mut sym: *mut c_char = std::ptr::null_mut();
        let rc = unsafe {
            quipu_encode(
                msg.as_ptr(),
                msg.len(),
                c"pw".as_ptr(),
                std::ptr::null(),
                0,
                &mut sym,
            )
        };
        assert_eq!(rc, QUIPU_OK as i32);
        assert!(!sym.is_null());

        let (mut out, mut out_len) = (std::ptr::null_mut(), 0usize);
        let rc =
            unsafe { quipu_decode(sym, c"pw".as_ptr(), std::ptr::null(), 0, &mut out, &mut out_len) };
        assert_eq!(rc, QUIPU_OK as i32);
        let got = unsafe { std::slice::from_raw_parts(out, out_len) };
        assert_eq!(got, msg);

        unsafe {
            quipu_string_free(sym);
            quipu_string_free(std::ptr::null_mut()); // no-op
            quipu_bytes_free(out, out_len);
        }
    }

    #[test]
    fn codec_wrong_passphrase_is_auth_error() {
        let msg = b"data";
        let mut sym: *mut c_char = std::ptr::null_mut();
        unsafe {
            quipu_encode(
                msg.as_ptr(),
                msg.len(),
                c"right".as_ptr(),
                std::ptr::null(),
                0,
                &mut sym,
            );
        }
        let (mut out, mut out_len) = (std::ptr::null_mut(), 0usize);
        let rc = unsafe {
            quipu_decode(sym, c"wrong".as_ptr(), std::ptr::null(), 0, &mut out, &mut out_len)
        };
        assert_eq!(rc, QUIPU_ERR_AUTH as i32);
        unsafe {
            quipu_string_free(sym);
        }
    }

    #[test]
    fn recipient_roundtrip_and_bad_key() {
        let (mut pk, mut pk_len) = (std::ptr::null_mut(), 0usize);
        let (mut sk, mut sk_len) = (std::ptr::null_mut(), 0usize);
        let rc = unsafe { quipu_generate_keypair(&mut pk, &mut pk_len, &mut sk, &mut sk_len) };
        assert_eq!(rc, QUIPU_OK as i32);
        assert_eq!(pk_len, 1600);
        assert_eq!(sk_len, 3200);

        let msg = b"for your eyes only";
        let mut sym: *mut c_char = std::ptr::null_mut();
        let rc =
            unsafe { quipu_encrypt_to_recipient(msg.as_ptr(), msg.len(), pk, pk_len, &mut sym) };
        assert_eq!(rc, QUIPU_OK as i32);

        let (mut out, mut out_len) = (std::ptr::null_mut(), 0usize);
        let rc = unsafe { quipu_decrypt_as_recipient(sym, sk, sk_len, &mut out, &mut out_len) };
        assert_eq!(rc, QUIPU_OK as i32);
        let got = unsafe { std::slice::from_raw_parts(out, out_len) };
        assert_eq!(got, msg);

        // Wrong-length public key -> KEY error.
        let short = [0u8; 10];
        let mut sym2: *mut c_char = std::ptr::null_mut();
        let rc = unsafe {
            quipu_encrypt_to_recipient(msg.as_ptr(), msg.len(), short.as_ptr(), short.len(), &mut sym2)
        };
        assert_eq!(rc, QUIPU_ERR_KEY as i32);

        unsafe {
            quipu_string_free(sym);
            quipu_bytes_free(out, out_len);
            quipu_bytes_free(pk, pk_len);
            quipu_bytes_free(sk, sk_len);
        }
    }

    #[test]
    fn signature_roundtrip_and_tamper() {
        let (mut vk, mut vk_len) = (std::ptr::null_mut(), 0usize);
        let (mut sk, mut sk_len) = (std::ptr::null_mut(), 0usize);
        let rc =
            unsafe { quipu_generate_signing_keypair(&mut vk, &mut vk_len, &mut sk, &mut sk_len) };
        assert_eq!(rc, QUIPU_OK as i32);
        assert_eq!(vk_len, 2624);
        assert_eq!(sk_len, 64);

        let msg = b"signed statement";
        let mut sym: *mut c_char = std::ptr::null_mut();
        let rc = unsafe { quipu_sign(msg.as_ptr(), msg.len(), sk, sk_len, &mut sym) };
        assert_eq!(rc, QUIPU_OK as i32);

        let (mut out, mut out_len) = (std::ptr::null_mut(), 0usize);
        let rc = unsafe { quipu_verify(sym, vk, vk_len, &mut out, &mut out_len) };
        assert_eq!(rc, QUIPU_OK as i32);
        let got = unsafe { std::slice::from_raw_parts(out, out_len) };
        assert_eq!(got, msg);

        // Verify against a different key -> AUTH error.
        let (mut vk2, mut vk2_len) = (std::ptr::null_mut(), 0usize);
        let (mut sk2, mut sk2_len) = (std::ptr::null_mut(), 0usize);
        unsafe {
            quipu_generate_signing_keypair(&mut vk2, &mut vk2_len, &mut sk2, &mut sk2_len);
        }
        let (mut out2, mut out2_len) = (std::ptr::null_mut(), 0usize);
        let rc = unsafe { quipu_verify(sym, vk2, vk2_len, &mut out2, &mut out2_len) };
        assert_eq!(rc, QUIPU_ERR_AUTH as i32);

        unsafe {
            quipu_string_free(sym);
            quipu_bytes_free(out, out_len);
            quipu_bytes_free(vk, vk_len);
            quipu_bytes_free(sk, sk_len);
            quipu_bytes_free(vk2, vk2_len);
            quipu_bytes_free(sk2, sk2_len);
        }
    }
}
