# Quipu Node.js Bindings — Design

**Date:** 2026-07-05
**Status:** Design for review (implementation deferred)
**Scope:** A Node.js package that consumes the Quipu **C ABI** (`quipu-capi` /
`bindings/c/include/quipu.h`) via runtime FFI, exposing an idiomatic
Promise-based TypeScript API. Builds on the C ABI shipped in PR #20.

## 1 · Goal & non-goals

**Goal.** Let Node.js applications use Quipu's data-at-rest crypto through an
idiomatic, type-safe, non-blocking API — implemented as a thin binding *over the
C ABI* (not by re-linking the Rust core, not by reimplementing crypto). The
binding must be:

- **Idiomatic** — `Buffer` in / `Buffer` out, `Promise`-based, errors thrown
  (not returned codes), `camelCase`, shipped `.d.ts` types.
- **Non-blocking** — every operation runs Argon2id (~tens of ms at 64 MiB), so
  calls execute off the main event loop.
- **Thin & auditable** — the only new "unsafe" surface is one small pointer/free
  helper; everything else is declarative FFI signatures + a typed wrapper.
- **Interoperable** — proven to decrypt a container produced by the Rust core,
  using the shared interop vectors.

**Non-goals (v1).**

- No synchronous API (follow-up; the async path is correct-by-default for Node).
- No N-API/C++ native addon (considered — see §3; follow-up for single-file
  prebuilt distribution).
- No macOS/Windows prebuilds in CI (Linux only in v1, mirroring the C ABI's own
  CI; the code stays platform-neutral).
- No publish to npm in this iteration.
- No KDF-cost tuning knobs (mirrors the Python bindings; the C ABI uses the
  format defaults).

## 2 · FFI mechanism: Koffi (runtime FFI)

Three viable ways for Node to call `libquipu_capi`:

| Option | What | Verdict |
|---|---|---|
| **Koffi** | Modern runtime FFI: declare the `quipu.h` signatures in TS, load the shared library. No C++. | **Chosen** |
| N-API addon (C++) | A C++ shim that `#include`s `quipu.h`, statically links `libquipu_capi.a`, produces a self-contained `.node`. | Follow-up |
| `ffi-napi` | The legacy Node FFI. | Rejected: unmaintained, slow, fragile pointer handling |

**Rationale for Koffi.** It is the most literal expression of "a binding *over
the C ABI*" — it declares the exact C signatures and nothing else. It introduces
zero C++/node-gyp/cmake/Rust-staticlib-linking risk, so the new surface is
TypeScript + config, the most auditable option for a security library. Koffi is
actively maintained and fast, and supports **async calls** that run the native
call on libuv's threadpool — which matches the stateless, thread-safe C ABI and
gives non-blocking Argon2id for free. The N-API C++ addon yields a
self-contained `.node` (better distribution) but reintroduces the very C++ layer
the C ABI exists to avoid; it is recorded as the upgrade path once prebuilt
single-file distribution becomes the priority.

## 3 · Package layout

```
quipu/
└── bindings/
    └── node/                     # npm package `quipu-crypto`
        ├── package.json          # name, type: module, node:test script, koffi dep
        ├── tsconfig.json
        ├── scripts/
        │   └── build-native.mjs  # cargo build -p quipu-capi --release; copy artifact
        ├── src/
        │   ├── native.ts         # koffi: load lib + declare the 13 C signatures
        │   ├── memory.ts         # the out-pointer/copy/free helper (only unsafe surface)
        │   ├── errors.ts         # QuipuError + status-code -> code mapping
        │   └── index.ts          # the public typed async API
        ├── prebuilds/
        │   └── <platform>-<arch>/libquipu_capi.<ext>   # populated by build-native.mjs
        ├── test/
        │   ├── roundtrip.test.mjs
        │   ├── errors.test.mjs
        │   └── interop.test.mjs  # decrypts a Rust-made QST1 vector via the C ABI
        └── README.md
```

Files split by responsibility: signature declarations (`native`), the raw
pointer dance (`memory`), error translation (`errors`), and the ergonomic API
(`index`). Each is small and independently testable.

## 4 · Native library loading

`native.ts` resolves the shared library for the current platform/arch:

1. `prebuilds/${process.platform}-${process.arch}/libquipu_capi.<ext>`
   (`.so` on linux, `.dylib` on darwin, `.dll` on win32).
2. Dev fallback: `../../target/release/libquipu_capi.<ext>` relative to the repo,
   so a plain `cargo build -p quipu-capi --release` + `npm test` works in-tree.
3. Override: `QUIPU_CAPI_LIB` env var pointing at an explicit path.

If none resolves, throw a clear error naming the search paths and the
`build-native.mjs` command. `scripts/build-native.mjs` runs
`cargo build -p quipu-capi --release` and copies the artifact into
`prebuilds/<platform>-<arch>/`; it runs on `npm run build`.

## 5 · FFI signatures (Koffi)

`native.ts` declares each export from `quipu.h`. All fallible functions return
`int32_t`; outputs use koffi output-pointer parameters. Example shapes:

```ts
// koffi types: pointers to a pointer cell and a size cell for outputs.
const OutBytes = koffi.out(koffi.pointer('uint8_t*'));   // uint8_t**
const OutLen   = koffi.out(koffi.pointer('size_t'));     // size_t*
const OutStr   = koffi.out(koffi.pointer('char*'));      // char**

lib.func('int32_t quipu_encrypt_stream(const uint8_t*, size_t, const char*, ' +
         'const uint8_t*, size_t, size_t, _Out_ uint8_t**, _Out_ size_t*)');
lib.func('int32_t quipu_decrypt_stream(const uint8_t*, size_t, const char*, ' +
         'const uint8_t*, size_t, _Out_ uint8_t**, _Out_ size_t*)');
lib.func('void quipu_bytes_free(uint8_t*, size_t)');
lib.func('void quipu_string_free(char*)');
lib.func('const char* quipu_version()');
// …encode/decode, generate_keypair, encrypt_to_recipient/decrypt_as_recipient,
//   generate_signing_keypair, sign, verify — same pattern.
```

Async execution uses koffi's `.async()` call form so the native work runs on the
libuv threadpool; the wrapper returns a `Promise`. (Exact koffi API names are
settled during implementation against the installed koffi version.)

## 6 · Memory ownership (`memory.ts`)

The library allocates outputs; the wrapper copies them into JS and frees the
native buffer. Callers never see a pointer. One helper per output kind:

```
readBytesAndFree(outPtrCell, outLenCell):
    ptr = deref(outPtrCell); len = deref(outLenCell)
    buf = koffi.decode(ptr, 'uint8_t', len)   // copies native -> JS Buffer
    quipu_bytes_free(ptr, len)                 // C ABI wipes on free
    return buf

readStringAndFree(outStrCell):
    ptr = deref(outStrCell)
    s = koffi.decode(ptr, 'string')            // copies to a JS string
    quipu_string_free(ptr)
    return s
```

Because `quipu_bytes_free` zeroizes before releasing, secret keys and decrypted
plaintext leave no native residue once copied out. On any non-`QUIPU_OK` status,
no output pointer was written, so nothing is read or freed (the C ABI guarantees
this) — the wrapper throws instead (§7).

## 7 · Error handling (`errors.ts`)

The `int32_t` status becomes a thrown `QuipuError`:

```ts
class QuipuError extends Error { code: QuipuErrorCode }
type QuipuErrorCode = 'AUTH' | 'KEY' | 'CHUNK' | 'NULL_ARG' | 'INTERNAL';
```

| C status | thrown `code` | meaning |
|---|---|---|
| `QUIPU_OK` (0) | — (resolves) | success |
| `QUIPU_ERR_NULL_ARG` (-1) | `NULL_ARG` | bad/absent argument (should not happen from the typed API) |
| `QUIPU_ERR_AUTH` (-2) | `AUTH` | decrypt/verify failed (wrong key/pass, tampered, truncated) |
| `QUIPU_ERR_KEY` (-3) | `KEY` | malformed key/blob (e.g. wrong length) |
| `QUIPU_ERR_CHUNK` (-4) | `CHUNK` | `chunkSize` out of range |
| `QUIPU_ERR_INTERNAL` (-5) | `INTERNAL` | caught panic / unexpected |

`code` stays coarse and non-oracular, matching the C ABI: `AUTH` deliberately
merges decrypt failure, bad signature, and truncation.

## 8 · Public API (`index.ts`)

```ts
export function version(): string;

// symmetric glyph codec
export function encode(data: Buffer, passphrase: string, pepper?: Buffer): Promise<string>;
export function decode(symbols: string, passphrase: string, pepper?: Buffer): Promise<Buffer>;

// streaming AEAD (binary)
export interface StreamOptions { pepper?: Buffer; chunkSize?: number; }
export function encryptStream(data: Buffer, passphrase: string, opts?: StreamOptions): Promise<Buffer>;
export function decryptStream(blob: Buffer, passphrase: string, opts?: { pepper?: Buffer }): Promise<Buffer>;

// post-quantum recipient (X25519 + ML-KEM-1024)
export interface KeyPair { publicKey: Buffer; secretKey: Buffer; }
export function generateKeypair(): Promise<KeyPair>;
export function encryptToRecipient(data: Buffer, publicKey: Buffer): Promise<string>;
export function decryptAsRecipient(symbols: string, secretKey: Buffer): Promise<Buffer>;

// hybrid signature (Ed25519 + ML-DSA-87)
export interface SigningKeyPair { verifyingKey: Buffer; signingKey: Buffer; }
export function generateSigningKeypair(): Promise<SigningKeyPair>;
export function sign(data: Buffer, signingKey: Buffer): Promise<string>;
export function verify(symbols: string, verifyingKey: Buffer): Promise<Buffer>;
```

Notes: `pepper` optional (omitted → `(NULL, 0)` at the boundary); `chunkSize`
omitted or `0` → format default; `version()` is a cheap sync call (no KDF, static
string). Secret-bearing `Buffer`s are the caller's to manage after return; the
docs note `.fill(0)` when done.

## 9 · Testing (`node:test`, zero extra deps)

- **`roundtrip.test.mjs`** — encrypt→decrypt for all four modes (symmetric,
  streaming, recipient, signature); assert plaintext equality and that
  `version()` is a non-empty semver-ish string.
- **`errors.test.mjs`** — wrong passphrase → `QuipuError` with `code==='AUTH'`;
  wrong-length key → `code==='KEY'`; `chunkSize: 64` → `code==='CHUNK'`.
- **`interop.test.mjs`** — the distinctive one: load
  `../../tests/vectors/quipu_vectors.json`, take `frozen.streaming_decode[i]`
  (a QST1 container produced by the Rust core), call
  `decryptStream(Buffer.from(blob_hex,'hex'), passphrase, { pepper })`, and assert
  the result equals `Buffer.from(plaintext_hex,'hex')`. This proves the format
  contract holds across languages through the C ABI.

## 10 · CI

New **`node`** job in `.github/workflows/ci.yml` (Linux):
`cargo build -p quipu-capi --release` → `node scripts/build-native.mjs` (copy
artifact) → `npm ci` (in `bindings/node`) → `npm test`. Uses `actions/setup-node`
(LTS) + the existing Rust toolchain. macOS/Windows matrix is a follow-up.

## 11 · Risks & mitigations

- **Pointer/free correctness in JS.** → Confined to `memory.ts`; every mode's
  roundtrip test exercises the copy-then-free path; the C ABI's NULL-safe,
  write-only-on-success contract means error paths never touch pointers.
- **Blocking the event loop.** → Async via koffi threadpool calls; no sync API in
  v1.
- **Native lib not found.** → Three-tier resolution (prebuilds → `target/release`
  → `QUIPU_CAPI_LIB`) with an actionable error message.
- **koffi API drift.** → Pin a koffi version in `package.json`; the FFI surface is
  small and centralized in `native.ts`.
- **Interop drift.** → `interop.test.mjs` fails if the Node path and the Rust
  vectors disagree, catching any accidental ABI/format skew.

## 12 · Deliverables checklist (for the future implementation plan)

- [ ] `bindings/node` package skeleton (`package.json`, `tsconfig.json`).
- [ ] `scripts/build-native.mjs` (cargo build + copy artifact).
- [ ] `native.ts` (load + 13 signatures) with three-tier lib resolution.
- [ ] `memory.ts` (bytes/string read-and-free helpers).
- [ ] `errors.ts` (`QuipuError` + status mapping).
- [ ] `index.ts` (typed async API) + shipped types.
- [ ] `node:test` suites: roundtrip, errors, interop-vectors.
- [ ] `node` CI job (Linux).
- [ ] `bindings/node/README.md`; CHANGELOG note.
- [ ] Update `quipu-roadmap-status` memory (Node done → Go next).

## 13 · Follow-ups (explicitly out of scope here)

Synchronous API; N-API single-file addon for prebuilt distribution;
macOS/Windows prebuilds + CI matrix; publish `quipu-crypto` to npm; Go (cgo)
binding (separate spec).
