# Quipu C ABI Bindings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose Quipu's data-at-rest crypto surface through a stable, stateless, panic-safe `extern "C"` interface with a cbindgen-generated `quipu.h` header and a C-level test suite.

**Architecture:** A new Cargo workspace member `quipu-capi` at `bindings/c/` depends on the `quipu` core crate (rlib) and produces `cdylib` + `staticlib`. Every export is `#[no_mangle] extern "C"`, wrapped in `catch_unwind`, NULL-checked, returning an `i32` status code with outputs via caller-freed out-pointers. The header is generated from the source and verified in CI.

**Tech Stack:** Rust (edition 2021 for the capi crate), cbindgen for header generation, system `cc` for the C integration test, GitHub Actions CI.

## Global Constraints

- The capi crate MUST NOT break the existing `quipu` package build, the `maturin`/PyO3 build, `cargo vet`, or the release pipeline.
- The capi crate is a workspace member but is **NOT** published to crates.io in this iteration.
- Every `extern "C"` function body MUST run inside `std::panic::catch_unwind` and return `QUIPU_ERR_INTERNAL` (`-5`) on a caught panic. No panic may cross the FFI boundary.
- Every required pointer MUST be NULL-checked before deref; a NULL required pointer returns `QUIPU_ERR_NULL_ARG` (`-1`).
- The library allocates all variable-length outputs; the caller frees them via `quipu_bytes_free` / `quipu_string_free`. Free functions are no-ops on NULL.
- Error codes are coarse and non-oracular: decrypt failure, bad signature, and truncation all collapse to `QUIPU_ERR_AUTH` (`-2`).
- Status enum values (exact): `QUIPU_OK=0`, `QUIPU_ERR_NULL_ARG=-1`, `QUIPU_ERR_AUTH=-2`, `QUIPU_ERR_KEY=-3`, `QUIPU_ERR_CHUNK=-4`, `QUIPU_ERR_INTERNAL=-5`.
- Fixed key/blob byte lengths from the core: `pqhybrid::PUBLIC_KEY_LEN=1600`, `SECRET_KEY_LEN=3200`; `pqsign::VERIFYING_KEY_LEN=2624`, `SIGNING_KEY_LEN=64`.
- `chunk_size = 0` means "use the format default"; non-zero values must be within 4 KiB–16 MiB or the call returns `QUIPU_ERR_CHUNK`.

---

## File Structure

- Modify: `Cargo.toml` — add `[workspace]` table.
- Create: `bindings/c/Cargo.toml` — package `quipu-capi`, `crate-type = ["cdylib", "staticlib"]`.
- Create: `bindings/c/src/lib.rs` — status enum, internal helpers, 10 crypto fns + `quipu_version` + 2 free fns, plus `#[cfg(test)]` Rust ABI tests.
- Create: `bindings/c/cbindgen.toml` — header generation config.
- Create: `bindings/c/include/quipu.h` — generated header (checked in).
- Create: `bindings/c/tests/roundtrip.c` — C program linking the real lib + header.
- Create: `bindings/c/README.md` — build & link usage.
- Modify: `.github/workflows/ci.yml` — add `capi` job.
- Modify: `supply-chain/config.toml` — `[policy.quipu-capi]`.
- Modify: `CHANGELOG.md`, `README.md` — note the C ABI.

---

## Task 1: Workspace + crate skeleton + `quipu_version`

**Files:**
- Modify: `Cargo.toml` (add `[workspace]` table)
- Create: `bindings/c/Cargo.toml`
- Create: `bindings/c/src/lib.rs`

**Interfaces:**
- Produces: the `quipu-capi` crate; the `quipu_status` enum (values in Global Constraints); `guard(f: impl FnOnce() -> i32) -> i32` helper; `quipu_version() -> *const c_char`.

- [ ] **Step 1: Add the workspace table to the root `Cargo.toml`**

Add this block at the very top of `Cargo.toml` (before `[package]`):

```toml
[workspace]
members = [".", "bindings/c"]
resolver = "2"
```

- [ ] **Step 2: Create `bindings/c/Cargo.toml`**

```toml
[package]
name = "quipu-capi"
version = "0.6.0"
edition = "2021"
description = "C ABI (extern \"C\") bindings for the Quipu post-quantum crypto core."
license = "AGPL-3.0-or-later"
repository = "https://github.com/isazajuancarlos/quipu"
publish = false

[lib]
name = "quipu_capi"
crate-type = ["cdylib", "staticlib"]

[dependencies]
quipu = { path = "../.." }
```

- [ ] **Step 3: Write the failing test in `bindings/c/src/lib.rs`**

Create the file with the status enum, the `guard` helper, `quipu_version`, and the first test:

```rust
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p quipu-capi`
Expected: PASS (`version_is_nonempty_cstr`, `guard_swallows_panic`). Also confirms the workspace resolves and the core `quipu` build still works.

- [ ] **Step 5: Verify the existing build is intact**

Run: `cargo build -p quipu && cargo build -p quipu-capi`
Expected: both succeed; `target/debug/libquipu_capi.so` exists.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock bindings/c/Cargo.toml bindings/c/src/lib.rs
git commit -m "feat(capi): workspace skeleton, status codes, quipu_version"
```

---

## Task 2: Streaming AEAD + memory helpers + `quipu_bytes_free`

**Files:**
- Modify: `bindings/c/src/lib.rs`

**Interfaces:**
- Consumes: `guard`, `quipu_status` from Task 1.
- Produces: `quipu_encrypt_stream`, `quipu_decrypt_stream`, `quipu_bytes_free`; internal helpers `as_slice`, `as_str`, `write_bytes`, `map_stream_err` used by later tasks.

- [ ] **Step 1: Write the failing tests**

Append to the `tests` module in `bindings/c/src/lib.rs`:

```rust
    #[test]
    fn stream_roundtrip() {
        let msg = b"attack at dawn";
        let pass = c"correct horse".as_ptr();
        let (mut blob, mut blob_len) = (std::ptr::null_mut(), 0usize);
        let rc = unsafe {
            quipu_encrypt_stream(msg.as_ptr(), msg.len(), pass,
                std::ptr::null(), 0, 0, &mut blob, &mut blob_len)
        };
        assert_eq!(rc, QUIPU_OK as i32);
        assert!(!blob.is_null() && blob_len > 0);

        let (mut out, mut out_len) = (std::ptr::null_mut(), 0usize);
        let rc = unsafe {
            quipu_decrypt_stream(blob, blob_len, pass,
                std::ptr::null(), 0, &mut out, &mut out_len)
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
            quipu_encrypt_stream(msg.as_ptr(), msg.len(), c"right".as_ptr(),
                std::ptr::null(), 0, 0, &mut blob, &mut blob_len);
        }
        let (mut out, mut out_len) = (std::ptr::null_mut(), 0usize);
        let rc = unsafe {
            quipu_decrypt_stream(blob, blob_len, c"wrong".as_ptr(),
                std::ptr::null(), 0, &mut out, &mut out_len)
        };
        assert_eq!(rc, QUIPU_ERR_AUTH as i32);
        assert!(out.is_null());
        unsafe { quipu_bytes_free(blob, blob_len); }
    }

    #[test]
    fn stream_bad_chunk_size_is_chunk_error() {
        let msg = b"x";
        let (mut blob, mut blob_len) = (std::ptr::null_mut(), 0usize);
        let rc = unsafe {
            quipu_encrypt_stream(msg.as_ptr(), msg.len(), c"p".as_ptr(),
                std::ptr::null(), 0, 64, &mut blob, &mut blob_len) // 64 < 4 KiB
        };
        assert_eq!(rc, QUIPU_ERR_CHUNK as i32);
    }

    #[test]
    fn stream_null_out_is_null_arg() {
        let msg = b"x";
        let rc = unsafe {
            quipu_encrypt_stream(msg.as_ptr(), msg.len(), c"p".as_ptr(),
                std::ptr::null(), 0, 0, std::ptr::null_mut(), std::ptr::null_mut())
        };
        assert_eq!(rc, QUIPU_ERR_NULL_ARG as i32);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p quipu-capi stream_`
Expected: FAIL — `quipu_encrypt_stream` / `quipu_decrypt_stream` / `quipu_bytes_free` not defined.

- [ ] **Step 3: Add the helpers and functions**

Add these imports at the top of `bindings/c/src/lib.rs` (after the existing `use` lines):

```rust
use std::ffi::{CStr, CString};
use std::slice;

use quipu::stream::{
    decrypt_stream_bytes as core_decrypt_stream, encrypt_stream as core_encrypt_stream,
    StreamError, StreamOptions,
};
```

Add the internal helpers (non-`extern`, so cbindgen ignores them):

```rust
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
```

Add the exports:

```rust
/// Frees a byte buffer returned by any `quipu_*` function. No-op on NULL.
///
/// SAFETY: `ptr`/`len` must come unmodified from a Quipu byte output, freed once.
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
/// SAFETY: pointers must satisfy the documented borrow/out-pointer contracts.
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
        let mut opts = StreamOptions::default();
        opts.pepper = pepper;
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
/// SAFETY: pointers must satisfy the documented borrow/out-pointer contracts.
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
```

Note: `CString` is imported here even though it is first *used* in Task 3, to keep the import block stable — if Task 3 is implemented separately, add `use std::ffi::CString;` only if it is not already present. If clippy warns `unused_imports` after this task, drop `CString` from the `use` line and re-add it in Task 3.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p quipu-capi`
Expected: PASS (all `stream_*` tests plus Task 1's).

- [ ] **Step 5: Lint**

Run: `cargo clippy -p quipu-capi --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add bindings/c/src/lib.rs
git commit -m "feat(capi): streaming encrypt/decrypt + bytes_free + mem/err helpers"
```

---

## Task 3: Symmetric glyph codec (`quipu_encode` / `quipu_decode`) + `quipu_string_free`

**Files:**
- Modify: `bindings/c/src/lib.rs`

**Interfaces:**
- Consumes: `guard`, `as_slice`, `as_str`, `write_bytes` from Task 2.
- Produces: `quipu_encode`, `quipu_decode`, `quipu_string_free`; helpers `default_dict`, `write_string`, `map_decode_err`.

- [ ] **Step 1: Write the failing tests**

Append to the `tests` module:

```rust
    #[test]
    fn codec_roundtrip() {
        let msg = b"hello glyphs";
        let mut sym: *mut c_char = std::ptr::null_mut();
        let rc = unsafe {
            quipu_encode(msg.as_ptr(), msg.len(), c"pw".as_ptr(),
                std::ptr::null(), 0, &mut sym)
        };
        assert_eq!(rc, QUIPU_OK as i32);
        assert!(!sym.is_null());

        let (mut out, mut out_len) = (std::ptr::null_mut(), 0usize);
        let rc = unsafe {
            quipu_decode(sym, c"pw".as_ptr(), std::ptr::null(), 0, &mut out, &mut out_len)
        };
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
        unsafe { quipu_encode(msg.as_ptr(), msg.len(), c"right".as_ptr(), std::ptr::null(), 0, &mut sym); }
        let (mut out, mut out_len) = (std::ptr::null_mut(), 0usize);
        let rc = unsafe {
            quipu_decode(sym, c"wrong".as_ptr(), std::ptr::null(), 0, &mut out, &mut out_len)
        };
        assert_eq!(rc, QUIPU_ERR_AUTH as i32);
        unsafe { quipu_string_free(sym); }
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p quipu-capi codec_`
Expected: FAIL — `quipu_encode` / `quipu_decode` / `quipu_string_free` not defined.

- [ ] **Step 3: Add imports, helpers, and functions**

Add to the imports block:

```rust
use quipu::api::{
    decode as core_decode, encode as core_encode, DecodeError, Options,
};
use quipu::dictionary::Dictionary;
use quipu::kdf::KdfParams;
```

Ensure `use std::ffi::CString;` is present (from Task 2's note). Add helpers:

```rust
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
```

Add the exports:

```rust
/// Frees a string returned by any `quipu_*` function. No-op on NULL.
///
/// SAFETY: `ptr` must come unmodified from a Quipu string output, freed once.
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
/// SAFETY: pointers must satisfy the documented borrow/out-pointer contracts.
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
/// SAFETY: pointers must satisfy the documented borrow/out-pointer contracts.
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p quipu-capi`
Expected: PASS (all `codec_*` plus prior tests).

- [ ] **Step 5: Lint**

Run: `cargo clippy -p quipu-capi --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add bindings/c/src/lib.rs
git commit -m "feat(capi): symmetric glyph codec encode/decode + string_free"
```

---

## Task 4: Post-quantum recipient (keypair / encrypt / decrypt)

**Files:**
- Modify: `bindings/c/src/lib.rs`

**Interfaces:**
- Consumes: `guard`, `as_slice`, `as_str`, `write_bytes`, `write_string`, `default_dict`, `map_decode_err` from Tasks 2–3.
- Produces: `quipu_generate_keypair`, `quipu_encrypt_to_recipient`, `quipu_decrypt_as_recipient`.

- [ ] **Step 1: Write the failing tests**

Append to the `tests` module:

```rust
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
        let rc = unsafe {
            quipu_encrypt_to_recipient(msg.as_ptr(), msg.len(), pk, pk_len, &mut sym)
        };
        assert_eq!(rc, QUIPU_OK as i32);

        let (mut out, mut out_len) = (std::ptr::null_mut(), 0usize);
        let rc = unsafe {
            quipu_decrypt_as_recipient(sym, sk, sk_len, &mut out, &mut out_len)
        };
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p quipu-capi recipient_`
Expected: FAIL — recipient functions not defined.

- [ ] **Step 3: Add imports and functions**

Extend the `quipu::api` import to add the recipient functions, and add the `pqhybrid` import:

```rust
use quipu::api::{
    decode as core_decode, decode_as_recipient as core_decode_pq, encode as core_encode,
    encode_to_recipient as core_encode_pq, DecodeError, Options,
};
use quipu::pqhybrid;
```

Add the exports:

```rust
/// Generates a hybrid post-quantum keypair (X25519 + ML-KEM-1024). Writes the
/// public key (1600 B) and secret key (3200 B) as freshly allocated buffers.
///
/// SAFETY: all four out-pointers must be valid, writable pointers.
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
            write_bytes(secret.to_bytes(), sk, sk_len);
        }
        QUIPU_OK as i32
    })
}

/// Encrypts `data` to a recipient's hybrid public key (`pk`, 1600 B). On success
/// writes glyph symbols to `*out`.
///
/// SAFETY: pointers must satisfy the documented borrow/out-pointer contracts.
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
/// SAFETY: pointers must satisfy the documented borrow/out-pointer contracts.
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p quipu-capi`
Expected: PASS (`recipient_roundtrip_and_bad_key` plus prior).

- [ ] **Step 5: Lint**

Run: `cargo clippy -p quipu-capi --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add bindings/c/src/lib.rs
git commit -m "feat(capi): post-quantum recipient keypair/encrypt/decrypt"
```

---

## Task 5: Hybrid signature (keypair / sign / verify)

**Files:**
- Modify: `bindings/c/src/lib.rs`

**Interfaces:**
- Consumes: `guard`, `as_slice`, `as_str`, `write_bytes`, `write_string`, `default_dict`, `map_decode_err` from Tasks 2–3.
- Produces: `quipu_generate_signing_keypair`, `quipu_sign`, `quipu_verify`.

- [ ] **Step 1: Write the failing tests**

Append to the `tests` module:

```rust
    #[test]
    fn signature_roundtrip_and_tamper() {
        let (mut vk, mut vk_len) = (std::ptr::null_mut(), 0usize);
        let (mut sk, mut sk_len) = (std::ptr::null_mut(), 0usize);
        let rc = unsafe { quipu_generate_signing_keypair(&mut vk, &mut vk_len, &mut sk, &mut sk_len) };
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
        unsafe { quipu_generate_signing_keypair(&mut vk2, &mut vk2_len, &mut sk2, &mut sk2_len); }
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p quipu-capi signature_`
Expected: FAIL — signing functions not defined.

- [ ] **Step 3: Add imports and functions**

Extend the `quipu::api` import to add the signing functions, and add the `pqsign` import (combine with the existing `quipu::pqhybrid;` line as `use quipu::{pqhybrid, pqsign};`):

```rust
use quipu::api::{
    decode as core_decode, decode_as_recipient as core_decode_pq,
    decode_verified as core_decode_verified, encode as core_encode,
    encode_signed as core_encode_signed, encode_to_recipient as core_encode_pq,
    DecodeError, Options,
};
use quipu::{pqhybrid, pqsign};
```

Add the exports:

```rust
/// Generates a hybrid signing keypair (Ed25519 + ML-DSA-87). Writes the
/// verifying key (2624 B) and the sensitive signing key (64 B).
///
/// SAFETY: all four out-pointers must be valid, writable pointers.
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
/// SAFETY: pointers must satisfy the documented borrow/out-pointer contracts.
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
/// SAFETY: pointers must satisfy the documented borrow/out-pointer contracts.
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p quipu-capi`
Expected: PASS (`signature_roundtrip_and_tamper` plus all prior).

- [ ] **Step 5: Lint**

Run: `cargo clippy -p quipu-capi --all-targets -- -D warnings`
Expected: clean. (If a clippy `field_reassign_with_default` fires on the `StreamOptions` block from Task 2, leave it — it is intentional for clarity; add `#[allow(clippy::field_reassign_with_default)]` on that function if `-D warnings` rejects it.)

- [ ] **Step 6: Commit**

```bash
git add bindings/c/src/lib.rs
git commit -m "feat(capi): hybrid signature keypair/sign/verify"
```

---

## Task 6: cbindgen config + generated `quipu.h`

**Files:**
- Create: `bindings/c/cbindgen.toml`
- Create: `bindings/c/include/quipu.h`

**Interfaces:**
- Consumes: all `#[no_mangle] extern "C"` functions and the `quipu_status` enum from Tasks 1–5.
- Produces: `bindings/c/include/quipu.h` (checked in).

- [ ] **Step 1: Install cbindgen**

Run: `cargo install cbindgen --locked`
Expected: `cbindgen` on PATH (`cbindgen --version`).

- [ ] **Step 2: Create `bindings/c/cbindgen.toml`**

```toml
language = "C"
include_guard = "QUIPU_H"
pragma_once = false
tab_width = 4
cpp_compat = true
documentation = true
documentation_style = "c99"
no_includes = true
sys_includes = ["stdint.h", "stddef.h"]
autogen_warning = "/* Generated by cbindgen from quipu-capi. Do not edit by hand. Regenerate: cd bindings/c && cbindgen --config cbindgen.toml --crate quipu-capi --output include/quipu.h */"

[enum]
prefix_with_name = false
```

- [ ] **Step 3: Generate the header**

Run:
```bash
cd bindings/c && cbindgen --config cbindgen.toml --crate quipu-capi --output include/quipu.h
```
Expected: `bindings/c/include/quipu.h` created.

- [ ] **Step 4: Verify the header content**

Run: `grep -c "quipu_" bindings/c/include/quipu.h`
Expected: at least 13 (10 crypto fns + `quipu_version` + 2 free fns). Also confirm the enum is present:
```bash
grep -E "QUIPU_OK|QUIPU_ERR_AUTH|quipu_status" bindings/c/include/quipu.h
```
Expected: the enum and its variants appear.

- [ ] **Step 5: Confirm it compiles as C**

Run: `cc -fsyntax-only -x c bindings/c/include/quipu.h`
Expected: no errors (header is self-contained via `stdint.h`/`stddef.h`).

- [ ] **Step 6: Commit**

```bash
git add bindings/c/cbindgen.toml bindings/c/include/quipu.h
git commit -m "build(capi): cbindgen config + generated quipu.h"
```

---

## Task 7: C integration test

**Files:**
- Create: `bindings/c/tests/roundtrip.c`

**Interfaces:**
- Consumes: `quipu.h` (Task 6), `libquipu_capi` (Tasks 1–5).

- [ ] **Step 1: Write `bindings/c/tests/roundtrip.c`**

```c
/* Links the real libquipu_capi + the generated header and exercises the ABI:
 * a streaming encrypt->decrypt roundtrip and a wrong-passphrase error path. */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "quipu.h"

int main(void) {
    const char *pass = "correct horse battery staple";
    const uint8_t msg[] = "attack at dawn";
    const size_t msg_len = sizeof(msg) - 1; /* drop the trailing NUL */

    uint8_t *blob = NULL;
    size_t blob_len = 0;
    int rc = quipu_encrypt_stream(msg, msg_len, pass, NULL, 0, 0, &blob, &blob_len);
    assert(rc == QUIPU_OK);
    assert(blob != NULL && blob_len > 0);

    uint8_t *out = NULL;
    size_t out_len = 0;
    rc = quipu_decrypt_stream(blob, blob_len, pass, NULL, 0, &out, &out_len);
    assert(rc == QUIPU_OK);
    assert(out_len == msg_len);
    assert(memcmp(out, msg, msg_len) == 0);

    uint8_t *bad = NULL;
    size_t bad_len = 0;
    rc = quipu_decrypt_stream(blob, blob_len, "wrong", NULL, 0, &bad, &bad_len);
    assert(rc == QUIPU_ERR_AUTH);
    assert(bad == NULL);

    quipu_bytes_free(blob, blob_len);
    quipu_bytes_free(out, out_len);
    quipu_bytes_free(NULL, 0); /* no-op */

    printf("C ABI roundtrip OK (%zu bytes, version %s)\n", out_len, quipu_version());
    return 0;
}
```

- [ ] **Step 2: Build the shared library**

Run: `cargo build -p quipu-capi`
Expected: `target/debug/libquipu_capi.so` exists.

- [ ] **Step 3: Compile and link the C test**

Run:
```bash
cc -I bindings/c/include bindings/c/tests/roundtrip.c \
   -L target/debug -lquipu_capi -o target/debug/capi_roundtrip
```
Expected: compiles and links with no errors.

- [ ] **Step 4: Run the C test**

Run: `LD_LIBRARY_PATH=target/debug target/debug/capi_roundtrip`
Expected: prints `C ABI roundtrip OK (14 bytes, version 0.6.0)` and exits 0.

- [ ] **Step 5: Commit**

```bash
git add bindings/c/tests/roundtrip.c
git commit -m "test(capi): C integration roundtrip linking the real ABI"
```

---

## Task 8: CI job, cargo-vet policy, and docs

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `supply-chain/config.toml`
- Modify: `CHANGELOG.md`, `README.md`
- Create: `bindings/c/README.md`

**Interfaces:**
- Consumes: everything from Tasks 1–7.

- [ ] **Step 1: Add the `capi` job to `.github/workflows/ci.yml`**

Append this job under the `jobs:` map (match the two-space indentation of the existing `test:`/`vet:` jobs):

```yaml
  capi:
    name: C ABI (bindings/c)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - name: Install cbindgen
        run: cargo install cbindgen --locked
      - name: Build cdylib + staticlib
        run: cargo build -p quipu-capi
      - name: Verify quipu.h is up to date
        run: |
          cd bindings/c
          cbindgen --config cbindgen.toml --crate quipu-capi --output /tmp/quipu.gen.h
          diff -u include/quipu.h /tmp/quipu.gen.h
      - name: Rust ABI unit tests
        run: cargo test -p quipu-capi
      - name: Compile and run the C integration test
        run: |
          cc -I bindings/c/include bindings/c/tests/roundtrip.c \
             -L target/debug -lquipu_capi -o /tmp/capi_roundtrip
          LD_LIBRARY_PATH=target/debug /tmp/capi_roundtrip
```

- [ ] **Step 2: Verify the workflow YAML is valid**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))" && echo OK`
Expected: `OK` (no YAML parse error).

- [ ] **Step 3: Add the cargo-vet policy for `quipu-capi`**

In `supply-chain/config.toml`, directly after the existing `[policy.quipu]` block (lines with `audit-as-crates-io = true`), add:

```toml
[policy.quipu-capi]
# Local, unpublished workspace member: no crates.io-style audit needed. It adds
# no new third-party crates (depends only on the already-vetted `quipu`).
audit-as-crates-io = false
```

- [ ] **Step 4: Verify cargo-vet still passes**

Run: `cargo vet --locked || cargo vet`
Expected: passes (no new unvetted crates; `quipu-capi` is policy-excused). If it reports a missing exemption for a *new* transitive crate, add the suggested `[[exemptions.<crate>]]` block exactly as cargo-vet prints it, then re-run.

- [ ] **Step 5: Create `bindings/c/README.md`**

```markdown
# Quipu C ABI (`quipu-capi`)

Stable, stateless `extern "C"` bindings over the Quipu core. Foundation for
language bindings (Node, Go, …). See
`../../docs/superpowers/specs/2026-07-05-c-abi-bindings-design.md`.

## Build

```sh
cargo build -p quipu-capi --release   # target/release/libquipu_capi.{so,a}
```

Produces a `cdylib` (`libquipu_capi.so`) and a `staticlib` (`libquipu_capi.a`).

## Header

`include/quipu.h` is generated by cbindgen and checked in. Regenerate after
changing the ABI:

```sh
cd bindings/c
cbindgen --config cbindgen.toml --crate quipu-capi --output include/quipu.h
```

CI fails if the checked-in header drifts from the source.

## Link (example)

```sh
cc -I bindings/c/include my_app.c -L target/release -lquipu_capi -o my_app
LD_LIBRARY_PATH=target/release ./my_app
```

## Contract

- Every fallible function returns `int32_t`: `QUIPU_OK` (0) or a negative
  `quipu_status`. Outputs are written only on success.
- The library allocates outputs; free them with `quipu_bytes_free(ptr, len)` or
  `quipu_string_free(ptr)`. Both are no-ops on `NULL`. Free each output once.
- `pepper` is optional: pass `(NULL, 0)`.
- No global state; safe to call from any thread.
```

- [ ] **Step 6: Note the C ABI in `CHANGELOG.md`**

Under the `[Unreleased]` section's `### Added` list (create the heading if absent), add:

```markdown
- **C ABI bindings** (`bindings/c`, crate `quipu-capi`): stable `extern "C"`
  surface (parity with the Python bindings) with a cbindgen-generated
  `quipu.h`, a `cdylib`/`staticlib`, and a C integration test in CI. Foundation
  for future Node/Go bindings.
```

- [ ] **Step 7: Note the C ABI in `README.md`**

Add a short subsection near the existing bindings/usage documentation (place it after the Python usage section; match the surrounding heading level):

```markdown
### C / other languages (C ABI)

A stable C ABI lives in [`bindings/c`](bindings/c) (crate `quipu-capi`). It builds
a shared/static library and a generated `quipu.h`, so any language with a C FFI
(Node, Go, Ruby, …) can consume Quipu. See [`bindings/c/README.md`](bindings/c/README.md).
```

- [ ] **Step 8: Full workspace check**

Run:
```bash
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings
```
Expected: all tests pass, clippy clean across both crates.

- [ ] **Step 9: Commit**

```bash
git add .github/workflows/ci.yml supply-chain/config.toml CHANGELOG.md README.md bindings/c/README.md
git commit -m "ci(capi): C ABI job, cargo-vet policy, and docs"
```

---

## Self-Review Notes

- **Spec coverage:** §2 crate layout → Task 1; §3.1 error codes → Tasks 1–5 (`map_stream_err`/`map_decode_err` + per-fn returns); §3.2 memory ownership → Task 2 (`write_bytes`/`quipu_bytes_free`) + Task 3 (`write_string`/`quipu_string_free`); §3.3 panic safety → Task 1 (`guard`) applied in every export; §4 function surface (10 fns + version + 2 frees) → Tasks 1–5; §5 header generation → Task 6; §6 testing (Rust + C) → Tasks 2–5 (Rust) + Task 7 (C); §7 CI + vet → Task 8. All spec sections map to a task.
- **Panic safety** is enforced uniformly by wrapping every export body in `guard(...)`.
- **cbindgen is install-only** (`cargo install`), so it does not enter the audited dependency graph — no `cargo vet` exemption for cbindgen is required (correcting the tentative note in spec §7).
- **Types are consistent** across tasks: helper signatures (`as_slice`, `as_str`, `write_bytes`, `write_string`, `map_stream_err`, `map_decode_err`, `default_dict`) are defined once (Tasks 2–3) and only consumed thereafter; the `quipu::api` import is progressively extended (Tasks 3→4→5) with the final form shown in Task 5.
```
