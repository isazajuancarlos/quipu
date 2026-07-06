# Quipu C ABI Bindings — Design

**Date:** 2026-07-05
**Status:** Approved (design), pending implementation plan
**Scope:** A stable C ABI over the Quipu core, plus a generated `quipu.h` header
and a C-level test suite. Foundation for future Node (N-API/ffi) and Go (cgo)
bindings — each of which is a separate spec/PR that consumes this ABI.

## 1 · Goal & non-goals

**Goal.** Expose Quipu's data-at-rest cryptographic surface through a stable,
portable, `extern "C"` interface that any language with a C FFI can consume.
The ABI must be:

- **Stateless** — no global state, no thread-local last-error. Every call is
  self-contained. This makes it trivial to drive from Go/cgo, Node, Python
  `ctypes`, Ruby FFI, etc.
- **Panic-safe** — no Rust panic may cross the FFI boundary (that is UB).
- **Memory-explicit** — the library allocates outputs; the caller frees them
  with a matching free function. No ambiguity about ownership.
- **Verifiable** — the header is generated from the Rust source and checked in
  CI, so it can never drift from the implementation.

**Non-goals (v1).**

- No Node/Go/Ruby bindings in this iteration (separate specs).
- No `pkg-config`/`.pc` file, no install target, no SONAME versioning policy —
  noted as follow-ups.
- No glyph-optimization helpers (`glyph_min_distance`, `select_separable`) —
  not cryptographic core, no value to a C consumer.
- No lab/red-team, OPRF-network, or image/glyph rendering surface.
- Linux is the CI target for v1; macOS/Windows builds are a follow-up.

## 2 · Crate layout

Introduce a Cargo **workspace**. The repository root stays the `quipu` package
(still independently publishable to crates.io exactly as today). Add one member:

```
quipu/                     # root: package `quipu` (lib + PyO3), unchanged
├── Cargo.toml             # gains [workspace] members = [".", "bindings/c"]
└── bindings/
    └── c/                 # package `quipu-capi`
        ├── Cargo.toml     # crate-type = ["cdylib", "staticlib"]; depends on quipu (path)
        ├── cbindgen.toml  # header-generation config (no build.rs; header generated in CI/make)
        ├── src/lib.rs     # all `#[no_mangle] extern "C"` fns; the only `unsafe` surface
        ├── include/
        │   └── quipu.h    # cbindgen output, checked in, CI-verified
        └── tests/
            └── roundtrip.c # C program linking the real lib + header
```

Rationale: isolating every `no_mangle`/`unsafe`/`catch_unwind` in its own crate
keeps the core clean and keeps the PyO3 `cdylib` (module-init symbols) from
colliding with the C `cdylib`. The core `quipu` crate is a plain `rlib`
dependency here.

The workspace addition must not break the existing `quipu` package build,
`maturin` (PyO3) build, `cargo vet`, or the release pipeline. A `[patch]`/
feature audit and a `cargo vet` re-exemption for the new package will be part of
implementation (see §7).

## 3 · ABI conventions

### 3.1 Return values & error codes

Every fallible function returns `int32_t`. `0` = success. Negative = error.
Outputs are written through caller-supplied out-pointers only on success.

```c
typedef enum {
    QUIPU_OK            =  0,
    QUIPU_ERR_NULL_ARG  = -1,  // a required pointer was NULL / bad length
    QUIPU_ERR_AUTH      = -2,  // decrypt/verify failed (wrong key/pass or tampered)
    QUIPU_ERR_KEY       = -3,  // a key/blob had the wrong length or was malformed
    QUIPU_ERR_CHUNK     = -4,  // chunk_size out of range (streaming)
    QUIPU_ERR_INTERNAL  = -5,  // caught panic or unexpected internal failure
} quipu_status;
```

Mapping from core error enums:

| Core error | Code |
|---|---|
| `DecodeError::Decrypt`, `::BadSignature`, `StreamError::Decrypt`, `::Truncated` | `QUIPU_ERR_AUTH` |
| `DecodeError::Symbol/Container/CodebookMismatch`, `StreamError::Header/UnsupportedVersion/InsaneKdf` | `QUIPU_ERR_KEY` |
| `StreamError::BadChunkSize` | `QUIPU_ERR_CHUNK` |
| invalid key length (`from_bytes` → `None`) | `QUIPU_ERR_KEY` |
| any `NULL` required pointer, or length overflow | `QUIPU_ERR_NULL_ARG` |
| `StreamError::Io`, caught `panic` | `QUIPU_ERR_INTERNAL` |

Note: error codes are **coarse and non-oracular by design.** `Decrypt`,
`BadSignature`, and `Truncated` all collapse to `QUIPU_ERR_AUTH` — the C ABI
does not hand an attacker a finer failure oracle than the Rust API already
exposes.

### 3.2 Memory ownership

The library allocates all variable-length outputs; the caller frees them.

- Byte outputs: `uint8_t** out, size_t* out_len`. Freed with
  `quipu_bytes_free(uint8_t* ptr, size_t len)`.
- String outputs (glyph symbols; NUL-terminated ASCII): `char** out`. Freed with
  `quipu_string_free(char* ptr)`.

Implementation: outputs are built as `Box<[u8]>` (or `CString`), released with
`Box::into_raw` / `CString::into_raw`; the free functions reconstruct and drop
them. Using a boxed slice means the allocation's size is exact, so the free path
needs only `(ptr, len)` and never loses `capacity`. `quipu_bytes_free(NULL, _)`
and `quipu_string_free(NULL)` are no-ops (double-free-safe against NULL).

Inputs are always borrowed (`const uint8_t*, size_t`); the library never frees
or retains caller memory past the call.

### 3.3 Panic safety

Every `extern "C"` function body runs inside `std::panic::catch_unwind`. A
caught panic returns `QUIPU_ERR_INTERNAL` and writes nothing to out-pointers.
The crate sets `#![deny(unsafe_op_in_unsafe_fn)]`; each pointer deref is
justified with a `// SAFETY:` note. NULL checks on every required pointer occur
before any deref.

## 4 · Function surface (parity with the Python bindings)

Ten cryptographic functions, mirroring `src/python.rs` one-for-one (minus the
two glyph helpers), plus `quipu_version` and the two free functions. `pepper`
is optional: pass `(NULL, 0)` for none.

```c
// --- meta ---
const char* quipu_version(void);   // static string, DO NOT free

// --- symmetric codec (glyph-string output) ---
int32_t quipu_encode(const uint8_t* data, size_t data_len,
                     const char* passphrase,
                     const uint8_t* pepper, size_t pepper_len,
                     char** out);                              // -> QUIPU_OK
int32_t quipu_decode(const char* symbols,
                     const char* passphrase,
                     const uint8_t* pepper, size_t pepper_len,
                     uint8_t** out, size_t* out_len);

// --- post-quantum recipient (X25519 + ML-KEM-1024) ---
int32_t quipu_generate_keypair(uint8_t** pk, size_t* pk_len,
                               uint8_t** sk, size_t* sk_len);  // 1600 / 3200 B
int32_t quipu_encrypt_to_recipient(const uint8_t* data, size_t data_len,
                                   const uint8_t* pk, size_t pk_len,
                                   char** out);
int32_t quipu_decrypt_as_recipient(const char* symbols,
                                   const uint8_t* sk, size_t sk_len,
                                   uint8_t** out, size_t* out_len);

// --- hybrid signature (Ed25519 + ML-DSA-87) ---
int32_t quipu_generate_signing_keypair(uint8_t** vk, size_t* vk_len,
                                        uint8_t** sk, size_t* sk_len); // 2624 / 64 B
int32_t quipu_sign(const uint8_t* data, size_t data_len,
                   const uint8_t* sk, size_t sk_len,
                   char** out);
int32_t quipu_verify(const char* symbols,
                     const uint8_t* vk, size_t vk_len,
                     uint8_t** out, size_t* out_len);

// --- streaming AEAD (QST1; binary in/out) ---
int32_t quipu_encrypt_stream(const uint8_t* data, size_t data_len,
                             const char* passphrase,
                             const uint8_t* pepper, size_t pepper_len,
                             size_t chunk_size,   // 0 = format default
                             uint8_t** out, size_t* out_len);
int32_t quipu_decrypt_stream(const uint8_t* blob, size_t blob_len,
                             const char* passphrase,
                             const uint8_t* pepper, size_t pepper_len,
                             uint8_t** out, size_t* out_len);

// --- memory ---
void quipu_bytes_free(uint8_t* ptr, size_t len);
void quipu_string_free(char* ptr);
```

Notes.

- `quipu_encrypt_stream` uses the **fallible** `stream::encrypt_stream` into a
  `Vec` (never the panicking `_bytes` variant), matching the fix already applied
  in the Python layer, so a bad `chunk_size` returns `QUIPU_ERR_CHUNK` instead of
  aborting the caller.
- `chunk_size = 0` means "use the format default" (same convention as Python's
  `None`). Any non-zero value outside 4 KiB–16 MiB returns `QUIPU_ERR_CHUNK`.
- `passphrase`/`symbols` are borrowed C strings validated as UTF-8; invalid
  UTF-8 → `QUIPU_ERR_NULL_ARG`.
- Key/blob byte lengths are fixed by the core constants
  (`pqhybrid::PUBLIC_KEY_LEN=1600`, `SECRET_KEY_LEN=3200`;
  `pqsign::VERIFYING_KEY_LEN=2624`, `SIGNING_KEY_LEN=64`) and documented in the
  header comments.

## 5 · Header generation

`quipu.h` is generated by **cbindgen** from `bindings/c/src/lib.rs`, configured
via `cbindgen.toml` (C output, `QUIPU_H` include guard, `#include <stdint.h>`/
`<stddef.h>`, documentation comments preserved, the `quipu_status` enum emitted).
The generated header is **checked in** at `bindings/c/include/quipu.h`.

CI regenerates the header and `git diff --exit-code`s it: a stale header fails
the build. This makes the header a verified artifact, not hand-maintained prose.

## 6 · Testing

Two layers, because Rust `#[test]`s alone do not exercise the real linked ABI.

1. **Rust unit tests** (`bindings/c/src/lib.rs` `#[cfg(test)]`): call each
   `extern "C"` fn directly. Cover: encrypt→decrypt roundtrip for all three
   modes; wrong-passphrase → `QUIPU_ERR_AUTH`; tampered blob → `QUIPU_ERR_AUTH`;
   wrong-length key → `QUIPU_ERR_KEY`; out-of-range `chunk_size` →
   `QUIPU_ERR_CHUNK`; NULL required arg → `QUIPU_ERR_NULL_ARG`; free of NULL is a
   no-op; free of a real output does not leak/crash (run under valgrind/ASan in
   CI where available).

2. **C integration test** (`bindings/c/tests/roundtrip.c`): compiled with the
   system `cc` against the built `libquipu_capi` + the checked-in header. Does a
   streaming encrypt→decrypt roundtrip, asserts plaintext equality, asserts a
   wrong-passphrase decrypt returns `QUIPU_ERR_AUTH`, and frees every output.
   This is the test that proves the ABI + header are real and correct.

## 7 · CI & supply chain

- New **`capi`** job in `.github/workflows/ci.yml` (Linux): `cargo build -p
  quipu-capi` (cdylib+staticlib) → cbindgen regenerate + `git diff --exit-code`
  → `cargo test -p quipu-capi` → compile & run `tests/roundtrip.c` linked
  against the built lib. Optionally under ASan.
- `cargo vet`: the new `quipu-capi` package needs its own self-exemption entry
  (`audit-as-crates-io` mirrors the existing `quipu` gotcha — see the release
  checklist). cbindgen becomes a dev/build tool; if it enters the audited
  graph it needs vetting/exemption too.
- The existing PyO3 wheel build and the `quipu` crates.io publish are unaffected:
  `quipu-capi` is a workspace member that is **not** published to crates.io in
  this iteration (it can be later).

## 8 · Risks & mitigations

- **Panic across FFI (UB).** → `catch_unwind` wrapper on every export; unit test
  asserts a forced-error path returns a code, never aborts.
- **Header drift.** → CI regenerate-and-diff gate.
- **Double free / use-after-free by caller.** → single documented ownership
  rule; NULL-safe frees; ASan in CI on the C test.
- **Workspace change breaks release/PyO3/vet.** → verify `maturin` build,
  `cargo vet`, and the release workflow still pass before merge; add the vet
  exemption in the same PR.
- **Symbol collision with PyO3 cdylib.** → separate crate; distinct lib name
  (`quipu_capi`).

## 9 · Deliverables checklist

- [ ] Workspace `Cargo.toml` + `bindings/c/Cargo.toml` (`quipu-capi`).
- [ ] `bindings/c/src/lib.rs`: 10 crypto fns + `quipu_version` + 2 free fns, all
      panic-guarded and NULL-checked.
- [ ] `cbindgen.toml` + generated `bindings/c/include/quipu.h` (checked in).
- [ ] Rust unit tests (all modes, all error codes, free safety).
- [ ] `bindings/c/tests/roundtrip.c` + a way to build/run it.
- [ ] `capi` CI job (build + header-diff + rust tests + C test).
- [ ] `cargo vet` exemption for `quipu-capi` (+ cbindgen if needed).
- [ ] README/CHANGELOG note; short `bindings/c/README.md` (build & link usage).
- [ ] Update `quipu-roadmap-status` memory (C ABI: done → Node/Go next).

## 10 · Follow-ups (explicitly out of scope here)

Node (N-API/ffi) binding; Go (cgo) binding; macOS/Windows CI matrix;
`pkg-config` `.pc` + install target + SONAME policy; publishing `quipu-capi` to
crates.io; prebuilt shared libraries in GitHub Releases.
