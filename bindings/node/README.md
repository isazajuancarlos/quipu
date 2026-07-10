# quipu-crypto (Node.js)

Node.js bindings for [Quipu](../../README.md) — hybrid post-quantum crypto for
data at rest — implemented over the stable [C ABI](../c) via [Koffi](https://koffi.dev)
runtime FFI.

## Install

```sh
npm install quipu-crypto
```

Prebuilt native libraries ship for **linux-x64, darwin-x64, darwin-arm64 and
win32-x64**, so no Rust toolchain is needed at install time.

## Build from source (contributors)

If you're hacking on the bindings or your platform has no prebuild:

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

quipu.version();

// symmetric (glyph symbols)
const sym = quipu.encode(Buffer.from('secret'), 'passphrase');
const back = quipu.decode(sym, 'passphrase');

// streaming AEAD (binary)
const blob = quipu.encryptStream(Buffer.from('big data'), 'passphrase');
const plain = quipu.decryptStream(blob, 'passphrase');

// post-quantum recipient
const { publicKey, secretKey } = quipu.generateKeypair();
const c = quipu.encryptToRecipient(Buffer.from('m'), publicKey);
quipu.decryptAsRecipient(c, secretKey);

// hybrid signature
const { verifyingKey, signingKey } = quipu.generateSigningKeypair();
const signed = quipu.sign(Buffer.from('acta'), signingKey);
quipu.verify(signed, verifyingKey); // throws QuipuError if tampered

// VOPRF online hardening (talks to a quipu-oprf-server)
const secret = await quipu.oprfHarden({
  baseUrl: 'https://oprf.tudominio.com',
  apiKey: 'quipu_live_...',
  password: Buffer.from('user password'),
  // serverPublicKey: Buffer.from('<64hex>', 'hex'),  // PIN in production
});
// `secret` is a rate-limited, quantum-safe hardened key. Throws QuipuError('AUTH')
// if the server's DLEQ proof does not verify (dishonest/impersonated server).
```

See [`examples/oprf-client.mjs`](examples/oprf-client.mjs) for the full flow, and
[the server](../../crates/quipu-oprf-server) for how to run one. `voprfBlind` /
`voprfFinalize` expose the low-level primitives if you use your own HTTP client.

## Contract

- The API is **synchronous**. It is intentionally not `Promise`-based in v1:
  koffi's async path runs on a libuv threadpool worker whose stack is too small
  for the core's ML-DSA-87 operations (they SIGSEGV there), so calls run on the
  main thread. **These calls run Argon2id (tens of ms) and block the event loop**
  — for a server, call them from a `worker_thread` (a non-blocking async wrapper
  is a planned follow-up).
- Failures throw a `QuipuError` whose `code` is one of `AUTH`, `KEY`, `CHUNK`,
  `NULL_ARG`, `INTERNAL` (coarse and non-oracular, like the C ABI). `AUTH` merges
  decrypt failure, bad signature, and truncation.
- Secret-bearing `Buffer`s are yours to manage; call `.fill(0)` when done. The
  native side already wipes its own output buffers on free.
```

