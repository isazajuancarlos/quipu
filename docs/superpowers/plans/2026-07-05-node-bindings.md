# Quipu Node.js Bindings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An npm package (`bindings/node`) that consumes the Quipu C ABI via Koffi runtime FFI, exposing an idiomatic Promise-based `Buffer` API with thrown `QuipuError`s, verified by roundtrip, error, and cross-language interop tests.

**Architecture:** ESM JavaScript modules load `libquipu_capi` with Koffi and declare the `quipu.h` signatures. A tiny memory module reads native outputs into JS (copy-then-free), a call module wraps each function's async form (libuv threadpool → non-blocking) into a Promise, and `index.js` is the typed public API. Types ship as a hand-written `index.d.ts`.

**Tech Stack:** Node.js ≥ 18 (developed on 22), Koffi ^3.1.0, `node:test`, the `quipu-capi` cdylib.

## Global Constraints

- **Consumes the C ABI only** — loads `libquipu_capi`; never re-links the Rust core or reimplements crypto.
- **Async, non-blocking** — every crypto function uses Koffi's `.async` form (libuv threadpool) and returns a `Promise`. Only `version()` is sync.
- **`Buffer` in / `Buffer` out**; glyph outputs are `string`. `pepper` optional → `(null, 0)` at the boundary. `chunkSize` omitted/`0` → format default.
- **Errors thrown, not returned** — non-`QUIPU_OK` status → `throw`/reject a `QuipuError` with `code ∈ {'AUTH','KEY','CHUNK','NULL_ARG','INTERNAL'}`. `AUTH` is coarse (decrypt/verify/truncation).
- **Memory** — the wrapper copies each native output into JS then frees it (`quipu_bytes_free` / `quipu_string_free`). String outputs are declared as `uint8_t **` (NOT `char **`, which auto-copies and leaks the native pointer) and read via a NUL-safe view scan. `size_t` values arrive as `bigint` → `Number()`.
- **Fixed key lengths** (asserted in tests): recipient public 1600 / secret 3200; verifying 2624 / signing 64.
- **Language refinement of the spec:** the spec named `.ts` files; implementation authors ESM `.js` + a hand-written `index.d.ts` (full consumer types, zero build step). Same outcome, smaller surface.

## File Structure

- Create: `bindings/node/package.json` — package metadata, `type: module`, scripts, koffi dep.
- Create: `bindings/node/.gitignore` — `node_modules/`, `prebuilds/`.
- Create: `bindings/node/scripts/build-native.mjs` — `cargo build -p quipu-capi --release` + copy artifact.
- Create: `bindings/node/src/native.js` — Koffi load (3-tier resolution) + all 13 signatures.
- Create: `bindings/node/src/memory.js` — `decodeBytes`, `decodeCString`.
- Create: `bindings/node/src/errors.js` — `QuipuError`, `errorFor`.
- Create: `bindings/node/src/call.js` — `callBytes`, `callString`, `callKeypair`.
- Create: `bindings/node/src/index.js` — public async API.
- Create: `bindings/node/index.d.ts` — consumer types.
- Create: `bindings/node/test/{roundtrip,errors,interop}.test.mjs`.
- Create: `bindings/node/README.md`.
- Modify: `.github/workflows/ci.yml` — add `node` job.
- Modify: `CHANGELOG.md` — note the Node bindings.

All commands below run with the repo's toolchain; in this environment prefix Node commands with the portable Node on PATH:
`export PATH="$PWD/../../<scratch>/node/bin:$PATH"` is already set for the executor — use `node`/`npm` directly.

---

## Task 1: Package skeleton, native loader, all FFI signatures, `version()`

**Files:**
- Create: `bindings/node/package.json`, `bindings/node/.gitignore`,
  `bindings/node/scripts/build-native.mjs`, `bindings/node/src/native.js`,
  `bindings/node/test/roundtrip.test.mjs`

**Interfaces:**
- Produces: `native.js` exporting `koffi`, `lib`, and `versionFn`, `encodeFn`,
  `decodeFn`, `encryptStreamFn`, `decryptStreamFn`, `generateKeypairFn`,
  `encryptToRecipientFn`, `decryptAsRecipientFn`, `generateSigningKeypairFn`,
  `signFn`, `verifyFn`, `bytesFreeFn`, `stringFreeFn`.

- [ ] **Step 1: Create `bindings/node/package.json`**

```json
{
  "name": "quipu-crypto",
  "version": "0.6.0",
  "description": "Node.js bindings for Quipu — hybrid post-quantum crypto for data at rest (over the C ABI).",
  "type": "module",
  "main": "src/index.js",
  "types": "index.d.ts",
  "license": "AGPL-3.0-or-later",
  "engines": { "node": ">=18" },
  "scripts": {
    "build": "node scripts/build-native.mjs",
    "test": "node --test test/"
  },
  "dependencies": { "koffi": "^3.1.0" },
  "files": ["src/", "index.d.ts", "prebuilds/", "README.md"]
}
```

- [ ] **Step 2: Create `bindings/node/.gitignore`**

```gitignore
node_modules/
prebuilds/
```

- [ ] **Step 3: Create `bindings/node/scripts/build-native.mjs`**

```js
// Builds libquipu_capi in release and copies it into prebuilds/<platform>-<arch>/.
import { execFileSync } from 'node:child_process';
import { mkdirSync, copyFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..', '..');
const ext = process.platform === 'darwin' ? 'dylib' : process.platform === 'win32' ? 'dll' : 'so';
const libFile = process.platform === 'win32' ? `quipu_capi.${ext}` : `libquipu_capi.${ext}`;

execFileSync('cargo', ['build', '-p', 'quipu-capi', '--release'], { cwd: repoRoot, stdio: 'inherit' });

const src = join(repoRoot, 'target', 'release', libFile);
const destDir = join(here, '..', 'prebuilds', `${process.platform}-${process.arch}`);
mkdirSync(destDir, { recursive: true });
copyFileSync(src, join(destDir, libFile));
console.log(`copied ${libFile} -> ${destDir}`);
```

- [ ] **Step 4: Create `bindings/node/src/native.js`**

```js
import koffi from 'koffi';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const ext = process.platform === 'darwin' ? 'dylib' : process.platform === 'win32' ? 'dll' : 'so';
const libFile = process.platform === 'win32' ? `quipu_capi.${ext}` : `libquipu_capi.${ext}`;

function resolveLib() {
  const candidates = [
    process.env.QUIPU_CAPI_LIB,
    join(here, '..', 'prebuilds', `${process.platform}-${process.arch}`, libFile),
    join(here, '..', '..', '..', 'target', 'release', libFile),
  ].filter(Boolean);
  for (const p of candidates) if (existsSync(p)) return p;
  throw new Error(
    `quipu-capi native library not found. Looked in:\n  ${candidates.join('\n  ')}\n` +
    `Build it with: npm run build`,
  );
}

export { koffi };
export const lib = koffi.load(resolveLib());

// String outputs are declared as `uint8_t **` (not `char **`): koffi auto-copies
// a `char **` to a JS string and discards the pointer, which would leak the
// native allocation. As `uint8_t **` we get the raw pointer, read it safely, and
// free it via quipu_string_free.
export const versionFn = lib.func('const char* quipu_version()');
export const encodeFn = lib.func('int32_t quipu_encode(const uint8_t *data, size_t data_len, const char *passphrase, const uint8_t *pepper, size_t pepper_len, _Out_ uint8_t **out)');
export const decodeFn = lib.func('int32_t quipu_decode(const char *symbols, const char *passphrase, const uint8_t *pepper, size_t pepper_len, _Out_ uint8_t **out, _Out_ size_t *out_len)');
export const encryptStreamFn = lib.func('int32_t quipu_encrypt_stream(const uint8_t *data, size_t data_len, const char *passphrase, const uint8_t *pepper, size_t pepper_len, size_t chunk_size, _Out_ uint8_t **out, _Out_ size_t *out_len)');
export const decryptStreamFn = lib.func('int32_t quipu_decrypt_stream(const uint8_t *blob, size_t blob_len, const char *passphrase, const uint8_t *pepper, size_t pepper_len, _Out_ uint8_t **out, _Out_ size_t *out_len)');
export const generateKeypairFn = lib.func('int32_t quipu_generate_keypair(_Out_ uint8_t **pk, _Out_ size_t *pk_len, _Out_ uint8_t **sk, _Out_ size_t *sk_len)');
export const encryptToRecipientFn = lib.func('int32_t quipu_encrypt_to_recipient(const uint8_t *data, size_t data_len, const uint8_t *pk, size_t pk_len, _Out_ uint8_t **out)');
export const decryptAsRecipientFn = lib.func('int32_t quipu_decrypt_as_recipient(const char *symbols, const uint8_t *sk, size_t sk_len, _Out_ uint8_t **out, _Out_ size_t *out_len)');
export const generateSigningKeypairFn = lib.func('int32_t quipu_generate_signing_keypair(_Out_ uint8_t **vk, _Out_ size_t *vk_len, _Out_ uint8_t **sk, _Out_ size_t *sk_len)');
export const signFn = lib.func('int32_t quipu_sign(const uint8_t *data, size_t data_len, const uint8_t *sk, size_t sk_len, _Out_ uint8_t **out)');
export const verifyFn = lib.func('int32_t quipu_verify(const char *symbols, const uint8_t *vk, size_t vk_len, _Out_ uint8_t **out, _Out_ size_t *out_len)');
export const bytesFreeFn = lib.func('void quipu_bytes_free(uint8_t *ptr, size_t len)');
export const stringFreeFn = lib.func('void quipu_string_free(uint8_t *ptr)');
```

- [ ] **Step 5: Install koffi and write the failing version test**

Run: `cd bindings/node && npm install`
Then create `bindings/node/test/roundtrip.test.mjs`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { versionFn } from '../src/native.js';

test('version() returns a semver-ish string', () => {
  const v = versionFn();
  assert.equal(typeof v, 'string');
  assert.match(v, /^\d+\.\d+\.\d+/);
});
```

- [ ] **Step 6: Build the native lib, run the test**

Run:
```bash
cd bindings/node && node scripts/build-native.mjs && npm test
```
Expected: build copies `libquipu_capi.so` into `prebuilds/linux-x64/`; the test passes (`version() returns a semver-ish string`). The dev-fallback path also works without the copy since the loader finds `target/release`.

- [ ] **Step 7: Commit**

```bash
git add bindings/node/package.json bindings/node/package-lock.json bindings/node/.gitignore \
        bindings/node/scripts/build-native.mjs bindings/node/src/native.js \
        bindings/node/test/roundtrip.test.mjs
git commit -m "feat(node): package skeleton, koffi loader + signatures, version()"
```

---

## Task 2: Memory + errors + call helpers + streaming API

**Files:**
- Create: `bindings/node/src/memory.js`, `bindings/node/src/errors.js`,
  `bindings/node/src/call.js`, `bindings/node/src/index.js`
- Modify: `bindings/node/test/roundtrip.test.mjs`
- Create: `bindings/node/test/errors.test.mjs`

**Interfaces:**
- Consumes: `native.js` exports (Task 1).
- Produces: `decodeBytes(ptr,len)→Buffer`, `decodeCString(ptr)→string`;
  `QuipuError`, `errorFor(rc)→QuipuError|null`; `callBytes(fn,args)→Promise<Buffer>`,
  `callString(fn,args)→Promise<string>`, `callKeypair(fn)→Promise<[Buffer,Buffer]>`;
  `index.js` exporting `version`, `encryptStream`, `decryptStream` (and, in later
  tasks, the rest).

- [ ] **Step 1: Create `bindings/node/src/memory.js`**

```js
import { koffi } from './native.js';

// Copy `len` native bytes at `ptr` into a JS Buffer.
export function decodeBytes(ptr, len) {
  return Buffer.from(koffi.decode(ptr, koffi.array('uint8_t', len)));
}

// Read a NUL-terminated C string at `ptr`. A lazy zero-copy view is scanned only
// up to the terminating NUL, which is the last allocated byte — so this never
// reads past the allocation. Quipu glyph strings are always >= 115 bytes, so the
// first 256-byte window is always in-bounds; the loop covers longer outputs.
export function decodeCString(ptr) {
  const CHUNK = 256;
  let size = CHUNK;
  for (;;) {
    const view = Buffer.from(koffi.view(ptr, size));
    const nul = view.indexOf(0);
    if (nul !== -1) return view.toString('latin1', 0, nul);
    size += CHUNK;
  }
}
```

- [ ] **Step 2: Create `bindings/node/src/errors.js`**

```js
const CODE_FOR_STATUS = {
  '-1': 'NULL_ARG',
  '-2': 'AUTH',
  '-3': 'KEY',
  '-4': 'CHUNK',
  '-5': 'INTERNAL',
};
const MESSAGE = {
  NULL_ARG: 'invalid argument',
  AUTH: 'authentication failed',
  KEY: 'malformed key or container',
  CHUNK: 'chunk size out of range',
  INTERNAL: 'internal error',
};

export class QuipuError extends Error {
  constructor(code) {
    super(`quipu: ${MESSAGE[code] ?? 'unknown error'}`);
    this.name = 'QuipuError';
    this.code = code;
  }
}

// A QuipuError for a non-zero status, or null for QUIPU_OK (0).
export function errorFor(rc) {
  if (rc === 0) return null;
  return new QuipuError(CODE_FOR_STATUS[String(rc)] ?? 'INTERNAL');
}
```

- [ ] **Step 3: Create `bindings/node/src/call.js`**

```js
import { errorFor } from './errors.js';
import { decodeBytes, decodeCString } from './memory.js';
import { bytesFreeFn, stringFreeFn } from './native.js';

// Async call whose success writes (uint8_t** out, size_t* out_len).
export function callBytes(fn, args) {
  return new Promise((resolve, reject) => {
    const out = [null];
    const outLen = [0n];
    fn.async(...args, out, outLen, (err, rc) => {
      if (err) return reject(err);
      const e = errorFor(rc);
      if (e) return reject(e);
      const len = Number(outLen[0]);
      const buf = decodeBytes(out[0], len);
      bytesFreeFn(out[0], len);
      resolve(buf);
    });
  });
}

// Async call whose success writes (uint8_t** out) holding a C string.
export function callString(fn, args) {
  return new Promise((resolve, reject) => {
    const out = [null];
    fn.async(...args, out, (err, rc) => {
      if (err) return reject(err);
      const e = errorFor(rc);
      if (e) return reject(e);
      const s = decodeCString(out[0]);
      stringFreeFn(out[0]);
      resolve(s);
    });
  });
}

// Async keypair generator: (uint8_t** a, size_t* aLen, uint8_t** b, size_t* bLen).
export function callKeypair(fn) {
  return new Promise((resolve, reject) => {
    const a = [null];
    const aLen = [0n];
    const b = [null];
    const bLen = [0n];
    fn.async(a, aLen, b, bLen, (err, rc) => {
      if (err) return reject(err);
      const e = errorFor(rc);
      if (e) return reject(e);
      const al = Number(aLen[0]);
      const bl = Number(bLen[0]);
      const aBuf = decodeBytes(a[0], al);
      bytesFreeFn(a[0], al);
      const bBuf = decodeBytes(b[0], bl);
      bytesFreeFn(b[0], bl);
      resolve([aBuf, bBuf]);
    });
  });
}
```

- [ ] **Step 4: Create `bindings/node/src/index.js`** (streaming + version now; rest added in later tasks)

```js
import * as native from './native.js';
import { callBytes, callString, callKeypair } from './call.js';
export { QuipuError } from './errors.js';

const pepperArgs = (pepper) => (pepper ? [pepper, pepper.length] : [null, 0]);

export function version() {
  return native.versionFn();
}

export function encryptStream(data, passphrase, opts = {}) {
  const { pepper, chunkSize = 0 } = opts;
  return callBytes(native.encryptStreamFn, [data, data.length, passphrase, ...pepperArgs(pepper), chunkSize]);
}

export function decryptStream(blob, passphrase, opts = {}) {
  const { pepper } = opts;
  return callBytes(native.decryptStreamFn, [blob, blob.length, passphrase, ...pepperArgs(pepper)]);
}
```

Note: `callString`/`callKeypair` are imported now so the module is complete; they
are used by Tasks 3–5. (No unused-import lint runs on the runtime `.js`.)

- [ ] **Step 5: Replace `test/roundtrip.test.mjs` to test through the public API**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as quipu from '../src/index.js';

test('version() returns a semver-ish string', () => {
  assert.match(quipu.version(), /^\d+\.\d+\.\d+/);
});

test('streaming roundtrip', async () => {
  const msg = Buffer.from('streaming payload for node');
  const blob = await quipu.encryptStream(msg, 'pw');
  assert.ok(Buffer.isBuffer(blob) && blob.length > 0);
  const back = await quipu.decryptStream(blob, 'pw');
  assert.deepEqual(back, msg);
});

test('streaming with pepper roundtrip', async () => {
  const msg = Buffer.from('peppered');
  const pepper = Buffer.from('spice');
  const blob = await quipu.encryptStream(msg, 'pw', { pepper });
  assert.deepEqual(await quipu.decryptStream(blob, 'pw', { pepper }), msg);
});
```

- [ ] **Step 6: Create `bindings/node/test/errors.test.mjs`**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as quipu from '../src/index.js';

test('wrong passphrase -> QuipuError code AUTH', async () => {
  const blob = await quipu.encryptStream(Buffer.from('x'), 'right');
  await assert.rejects(quipu.decryptStream(blob, 'wrong'), (e) => {
    assert.ok(e instanceof quipu.QuipuError);
    assert.equal(e.code, 'AUTH');
    return true;
  });
});

test('out-of-range chunkSize -> code CHUNK', async () => {
  await assert.rejects(quipu.encryptStream(Buffer.from('x'), 'pw', { chunkSize: 64 }), (e) => {
    assert.equal(e.code, 'CHUNK');
    return true;
  });
});
```

- [ ] **Step 7: Run the tests**

Run: `cd bindings/node && npm test`
Expected: all pass (version, streaming roundtrip, streaming+pepper, AUTH error, CHUNK error).

- [ ] **Step 8: Commit**

```bash
git add bindings/node/src/memory.js bindings/node/src/errors.js bindings/node/src/call.js \
        bindings/node/src/index.js bindings/node/test/roundtrip.test.mjs bindings/node/test/errors.test.mjs
git commit -m "feat(node): memory/errors/call helpers + streaming API"
```

---

## Task 3: Symmetric glyph codec (`encode` / `decode`)

**Files:**
- Modify: `bindings/node/src/index.js`, `bindings/node/test/roundtrip.test.mjs`,
  `bindings/node/test/errors.test.mjs`

**Interfaces:**
- Consumes: `callString`, `callBytes`, `native.encodeFn`, `native.decodeFn`.
- Produces: `encode(data, passphrase, pepper?) → Promise<string>`,
  `decode(symbols, passphrase, pepper?) → Promise<Buffer>`.

- [ ] **Step 1: Add to `src/index.js`** (after `decryptStream`)

```js
export function encode(data, passphrase, pepper) {
  return callString(native.encodeFn, [data, data.length, passphrase, ...pepperArgs(pepper)]);
}

export function decode(symbols, passphrase, pepper) {
  return callBytes(native.decodeFn, [symbols, passphrase, ...pepperArgs(pepper)]);
}
```

- [ ] **Step 2: Add roundtrip test to `test/roundtrip.test.mjs`**

```js
test('symmetric codec roundtrip (string symbols)', async () => {
  const msg = Buffer.from('hello glyphs');
  const sym = await quipu.encode(msg, 'pw');
  assert.equal(typeof sym, 'string');
  assert.ok(sym.length >= 115);
  assert.deepEqual(await quipu.decode(sym, 'pw'), msg);
});
```

- [ ] **Step 3: Add error test to `test/errors.test.mjs`**

```js
test('decode with wrong passphrase -> AUTH', async () => {
  const sym = await quipu.encode(Buffer.from('data'), 'right');
  await assert.rejects(quipu.decode(sym, 'wrong'), (e) => {
    assert.equal(e.code, 'AUTH');
    return true;
  });
});
```

- [ ] **Step 4: Run the tests**

Run: `cd bindings/node && npm test`
Expected: all pass, including the new codec roundtrip and decode-AUTH.

- [ ] **Step 5: Commit**

```bash
git add bindings/node/src/index.js bindings/node/test/roundtrip.test.mjs bindings/node/test/errors.test.mjs
git commit -m "feat(node): symmetric glyph codec encode/decode"
```

---

## Task 4: Post-quantum recipient

**Files:**
- Modify: `bindings/node/src/index.js`, `bindings/node/test/roundtrip.test.mjs`,
  `bindings/node/test/errors.test.mjs`

**Interfaces:**
- Consumes: `callKeypair`, `callString`, `callBytes`, `native.generateKeypairFn`,
  `native.encryptToRecipientFn`, `native.decryptAsRecipientFn`.
- Produces: `generateKeypair() → Promise<{publicKey:Buffer, secretKey:Buffer}>`,
  `encryptToRecipient(data, publicKey) → Promise<string>`,
  `decryptAsRecipient(symbols, secretKey) → Promise<Buffer>`.

- [ ] **Step 1: Add to `src/index.js`**

```js
export async function generateKeypair() {
  const [publicKey, secretKey] = await callKeypair(native.generateKeypairFn);
  return { publicKey, secretKey };
}

export function encryptToRecipient(data, publicKey) {
  return callString(native.encryptToRecipientFn, [data, data.length, publicKey, publicKey.length]);
}

export function decryptAsRecipient(symbols, secretKey) {
  return callBytes(native.decryptAsRecipientFn, [symbols, secretKey, secretKey.length]);
}
```

- [ ] **Step 2: Add roundtrip test to `test/roundtrip.test.mjs`**

```js
test('post-quantum recipient roundtrip', async () => {
  const { publicKey, secretKey } = await quipu.generateKeypair();
  assert.equal(publicKey.length, 1600);
  assert.equal(secretKey.length, 3200);
  const msg = Buffer.from('for your eyes only');
  const sym = await quipu.encryptToRecipient(msg, publicKey);
  assert.deepEqual(await quipu.decryptAsRecipient(sym, secretKey), msg);
});
```

- [ ] **Step 3: Add error test to `test/errors.test.mjs`**

```js
test('wrong-length recipient key -> KEY', async () => {
  await assert.rejects(quipu.encryptToRecipient(Buffer.from('x'), Buffer.alloc(10)), (e) => {
    assert.equal(e.code, 'KEY');
    return true;
  });
});
```

- [ ] **Step 4: Run the tests**

Run: `cd bindings/node && npm test`
Expected: all pass, including the recipient roundtrip (key sizes 1600/3200) and KEY error.

- [ ] **Step 5: Commit**

```bash
git add bindings/node/src/index.js bindings/node/test/roundtrip.test.mjs bindings/node/test/errors.test.mjs
git commit -m "feat(node): post-quantum recipient keypair/encrypt/decrypt"
```

---

## Task 5: Hybrid signature

**Files:**
- Modify: `bindings/node/src/index.js`, `bindings/node/test/roundtrip.test.mjs`,
  `bindings/node/test/errors.test.mjs`

**Interfaces:**
- Consumes: `callKeypair`, `callString`, `callBytes`,
  `native.generateSigningKeypairFn`, `native.signFn`, `native.verifyFn`.
- Produces: `generateSigningKeypair() → Promise<{verifyingKey:Buffer, signingKey:Buffer}>`,
  `sign(data, signingKey) → Promise<string>`,
  `verify(symbols, verifyingKey) → Promise<Buffer>`.

- [ ] **Step 1: Add to `src/index.js`**

```js
export async function generateSigningKeypair() {
  const [verifyingKey, signingKey] = await callKeypair(native.generateSigningKeypairFn);
  return { verifyingKey, signingKey };
}

export function sign(data, signingKey) {
  return callString(native.signFn, [data, data.length, signingKey, signingKey.length]);
}

export function verify(symbols, verifyingKey) {
  return callBytes(native.verifyFn, [symbols, verifyingKey, verifyingKey.length]);
}
```

- [ ] **Step 2: Add roundtrip test to `test/roundtrip.test.mjs`**

```js
test('hybrid signature roundtrip', async () => {
  const { verifyingKey, signingKey } = await quipu.generateSigningKeypair();
  assert.equal(verifyingKey.length, 2624);
  assert.equal(signingKey.length, 64);
  const msg = Buffer.from('acta oficial');
  const signed = await quipu.sign(msg, signingKey);
  assert.deepEqual(await quipu.verify(signed, verifyingKey), msg);
});
```

- [ ] **Step 3: Add error test to `test/errors.test.mjs`**

```js
test('verify with a different key -> AUTH', async () => {
  const a = await quipu.generateSigningKeypair();
  const b = await quipu.generateSigningKeypair();
  const signed = await quipu.sign(Buffer.from('m'), a.signingKey);
  await assert.rejects(quipu.verify(signed, b.verifyingKey), (e) => {
    assert.equal(e.code, 'AUTH');
    return true;
  });
});
```

- [ ] **Step 4: Run the tests**

Run: `cd bindings/node && npm test`
Expected: all pass (signature roundtrip with sizes 2624/64, verify-AUTH).

- [ ] **Step 5: Commit**

```bash
git add bindings/node/src/index.js bindings/node/test/roundtrip.test.mjs bindings/node/test/errors.test.mjs
git commit -m "feat(node): hybrid signature keypair/sign/verify"
```

---

## Task 6: Cross-language interop test, types, README

**Files:**
- Create: `bindings/node/test/interop.test.mjs`, `bindings/node/index.d.ts`,
  `bindings/node/README.md`

**Interfaces:**
- Consumes: the full public API; `../../../tests/vectors/quipu_vectors.json`.

- [ ] **Step 1: Create `bindings/node/test/interop.test.mjs`**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import * as quipu from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, '..', '..', '..', 'tests', 'vectors', 'quipu_vectors.json');
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8'));

test('decrypts Rust-produced QST1 streaming vectors (cross-language interop)', async () => {
  const cases = vectors.frozen.streaming_decode;
  assert.ok(Array.isArray(cases) && cases.length > 0);
  for (const v of cases) {
    const blob = Buffer.from(v.blob_hex, 'hex');
    const pepper = v.pepper_hex ? Buffer.from(v.pepper_hex, 'hex') : undefined;
    const plain = await quipu.decryptStream(blob, v.passphrase, { pepper });
    assert.deepEqual(plain, Buffer.from(v.plaintext_hex, 'hex'), v.desc);
  }
});
```

- [ ] **Step 2: Create `bindings/node/index.d.ts`**

```ts
export declare function version(): string;

export declare function encode(data: Buffer, passphrase: string, pepper?: Buffer): Promise<string>;
export declare function decode(symbols: string, passphrase: string, pepper?: Buffer): Promise<Buffer>;

export interface StreamOptions { pepper?: Buffer; chunkSize?: number; }
export declare function encryptStream(data: Buffer, passphrase: string, opts?: StreamOptions): Promise<Buffer>;
export declare function decryptStream(blob: Buffer, passphrase: string, opts?: { pepper?: Buffer }): Promise<Buffer>;

export interface KeyPair { publicKey: Buffer; secretKey: Buffer; }
export declare function generateKeypair(): Promise<KeyPair>;
export declare function encryptToRecipient(data: Buffer, publicKey: Buffer): Promise<string>;
export declare function decryptAsRecipient(symbols: string, secretKey: Buffer): Promise<Buffer>;

export interface SigningKeyPair { verifyingKey: Buffer; signingKey: Buffer; }
export declare function generateSigningKeypair(): Promise<SigningKeyPair>;
export declare function sign(data: Buffer, signingKey: Buffer): Promise<string>;
export declare function verify(symbols: string, verifyingKey: Buffer): Promise<Buffer>;

export type QuipuErrorCode = 'AUTH' | 'KEY' | 'CHUNK' | 'NULL_ARG' | 'INTERNAL';
export declare class QuipuError extends Error { code: QuipuErrorCode; }
```

- [ ] **Step 3: Create `bindings/node/README.md`**

```markdown
# quipu-crypto (Node.js)

Node.js bindings for [Quipu](../../README.md) — hybrid post-quantum crypto for
data at rest — implemented over the stable [C ABI](../c) via Koffi runtime FFI.

## Build

```sh
cd bindings/node
npm install
npm run build   # cargo build -p quipu-capi --release + copy the native lib
npm test
```

`npm run build` compiles `libquipu_capi` and copies it into
`prebuilds/<platform>-<arch>/`. In a dev checkout the loader also falls back to
`target/release`, and `QUIPU_CAPI_LIB` can point at an explicit path.

## Usage

```js
import * as quipu from 'quipu-crypto';

console.log(quipu.version());

// symmetric (glyph symbols)
const sym = await quipu.encode(Buffer.from('secret'), 'passphrase');
const back = await quipu.decode(sym, 'passphrase');

// streaming AEAD (binary)
const blob = await quipu.encryptStream(Buffer.from('big data'), 'passphrase');
const plain = await quipu.decryptStream(blob, 'passphrase');

// post-quantum recipient
const { publicKey, secretKey } = await quipu.generateKeypair();
const c = await quipu.encryptToRecipient(Buffer.from('m'), publicKey);
await quipu.decryptAsRecipient(c, secretKey);

// hybrid signature
const { verifyingKey, signingKey } = await quipu.generateSigningKeypair();
const signed = await quipu.sign(Buffer.from('acta'), signingKey);
await quipu.verify(signed, verifyingKey); // rejects if tampered
```

## Contract

- All crypto functions are **async** and run off the event loop (Koffi threadpool).
- Failures reject with a `QuipuError` whose `code` is one of `AUTH`, `KEY`,
  `CHUNK`, `NULL_ARG`, `INTERNAL` (coarse and non-oracular, like the C ABI).
- Secret-bearing `Buffer`s are yours to manage; call `.fill(0)` when done. The
  native side already wipes its own output buffers on free.
```

- [ ] **Step 4: Run the full suite**

Run: `cd bindings/node && npm test`
Expected: every test passes, including the interop test decrypting the
Rust-produced `frozen.streaming_decode` vectors.

- [ ] **Step 5: Commit**

```bash
git add bindings/node/test/interop.test.mjs bindings/node/index.d.ts bindings/node/README.md
git commit -m "test(node): cross-language interop vectors + types + README"
```

---

## Task 7: CI job and CHANGELOG

**Files:**
- Modify: `.github/workflows/ci.yml`, `CHANGELOG.md`

**Interfaces:**
- Consumes: everything from Tasks 1–6.

- [ ] **Step 1: Add the `node` job to `.github/workflows/ci.yml`**

Append under the `jobs:` map (two-space indentation, matching the existing jobs):

```yaml
  node:
    name: Node.js bindings (bindings/node)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - name: Build native lib + copy prebuild
        working-directory: bindings/node
        run: node scripts/build-native.mjs
      - name: Install dependencies
        working-directory: bindings/node
        run: npm ci
      - name: Test
        working-directory: bindings/node
        run: npm test
```

- [ ] **Step 2: Validate the workflow YAML**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('OK')"`
Expected: `OK`.

- [ ] **Step 3: Note the Node bindings in `CHANGELOG.md`**

Under `[Unreleased]` → `### Added`, append:

```markdown
- **Node.js bindings** (`bindings/node`, npm package `quipu-crypto`): an idiomatic
  Promise-based API (`Buffer` in/out, thrown `QuipuError`) over the C ABI via
  Koffi runtime FFI — symmetric codec, streaming AEAD, post-quantum recipient,
  and hybrid signature. Every operation runs off the event loop. Ships hand-written
  TypeScript types and a `node:test` suite including a **cross-language interop**
  test that decrypts Rust-produced QST1 vectors. New `node` CI job.
```

And update the `### Planned` bindings line:

```markdown
- Higher-language bindings over the C ABI: **Go (cgo)** (Node.js shipped).
```

- [ ] **Step 4: Full workspace + node check**

Run:
```bash
cargo build -p quipu-capi --release
cd bindings/node && npm test
```
Expected: native lib builds; all Node tests pass.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml CHANGELOG.md
git commit -m "ci(node): Node.js bindings job + changelog"
```

---

## Self-Review Notes

- **Spec coverage:** §2 Koffi → Tasks 1–5 (all calls via koffi); §3 layout →
  Tasks 1–6 (refined to `.js` + `index.d.ts`, noted in Global Constraints); §4
  loader (3-tier) → Task 1 `native.js` + `build-native.mjs`; §5 signatures → Task
  1; §6 memory (copy+free, `uint8_t**` for strings, NUL-safe scan) → Task 2
  `memory.js`/`call.js`; §7 errors → Task 2 `errors.js`; §8 public API → Tasks
  2–5; §9 tests (roundtrip/errors/interop) → Tasks 2–6; §10 CI → Task 7. All spec
  sections map to a task.
- **Verified mechanics:** every koffi call form in this plan (output pointers,
  `size_t`→`bigint`, byte decode, NUL-safe string decode, `.async` threadpool
  wrapping, `quipu_bytes_free`/`quipu_string_free`) was validated against the real
  `libquipu_capi.so` before writing the plan.
- **Type consistency:** helper names (`decodeBytes`, `decodeCString`, `errorFor`,
  `QuipuError`, `callBytes`, `callString`, `callKeypair`, `pepperArgs`) and the
  `native.*Fn` exports are defined once and consumed unchanged across tasks; the
  public API names match `index.d.ts` exactly.
- **Distribution note:** `prebuilds/` is git-ignored and rebuilt in CI; publishing
  to npm and macOS/Windows prebuilds are explicit spec follow-ups, not in this plan.
```
