# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Independent security audit and public remediation of findings.
- A non-blocking `worker_threads` wrapper for the Node.js bindings.
- Reference deployment of the online VOPRF hardening server.

## [0.9.0] — 2026-07-20

### Added
- **Key custody in a PKCS#11 device (feature `hsm`).** The signing private key
  can live in an HSM, token or smartcard and **never leave it**: both halves of
  the hybrid signature (Ed25519 + ML-DSA-87) are generated and used *inside* the
  device. The `firmante::Custodio` trait separates *who holds the key* from *how
  the signature is assembled* — it asks for operations, never for the key
  material. A signature made in a device and one made in memory are byte-for-byte
  identical and verify with the same verifier. Exposed to Python as
  `quipu.CustodioHsm`, shipped in the wheel. Tested end-to-end against a real
  PKCS#11 token (128 concurrent signatures under a timeout).
- **Threshold signing (`firmante::firmar_con_comparticiones`, feature `escrow`).**
  Reconstructs a signing key from Shamir shares, signs, and drops it in a single
  Rust call, so the key never crosses the FFI boundary into a binding.

### Changed
- **BREAKING — the RNG boundary is fallible.** When the OS cannot provide
  randomness, Quipu no longer substitutes a weaker source and no longer panics:
  it reports an actionable error, with a bounded retry for the one transient
  cause. No key is ever born from a dead RNG (the Debian OpenSSL 2008 failure
  mode, prevented by construction), and `Drop`/zeroize still runs on the failure
  path. The functions that acquire randomness now return `Result`.
- **BREAKING — hybrid secret-key serialization.** `ml-kem` 0.3 serializes the
  decapsulation key as its 64-byte **seed** rather than the 3168-byte expanded
  form, so the hybrid secret key is now **96 bytes** instead of 3200. **Both
  formats are read; the new one is written** — keys created by 0.8.0 still
  decrypt. Public keys and on-wire ciphertext are unchanged, so a 0.8.0 sender
  can still encrypt to a 0.9.0 recipient. Verified across versions.
- **Coupled primitives migration:** `ml-kem` 0.3, `x25519-dalek` 3,
  `rand_core` 0.10, `getrandom` 0.4, `rand_chacha` 0.10. An API migration that
  had to land as one block, not four separate bumps.

### Security
- **A trained adversary as evidence of indistinguishability (feature `lab`).**
  `SPEC.md` claimed the ciphertext is indistinguishable from random by citing
  XChaCha20-Poly1305; it is now measured against the implementation. A logistic
  regression over twelve statistical features (not a neural net, so an auditor
  can read it) finds no distinguisher: over 100 rounds the sigma is a standard
  Gaussian. The lab never ships in a released build.
- **Export-control notification** filed under EAR §742.15(b) (`docs/EXPORT.md`).

### Fixed
- **`quipu-voprf` moved from `getrandom` 0.2 to 0.4** — the last old version left
  in the normal dependency tree. `cargo tree` now shows a single `getrandom`.

## [0.8.0] — 2026-07-18

### Added
- **Documented side-channel posture (`docs/SPEC.md` §15)** and **dudect coverage
  of the post-quantum path**. Two findings worth stating plainly:

  **XChaCha20-Poly1305 is constant-time without a hardware dependency.** It is an
  ARX construction with no lookup tables, so the guarantee holds *unconditionally*
  — every architecture, with or without cryptographic hardware. AES has the same
  property only where the hardware provides it; without AES instructions it falls
  back to S-box tables indexed by secret bytes, the classic cache-timing channel.
  On a modern server with AES-NI the two are equivalent; below that line they are
  not, and **the fallback is silent** — no warning, no test, no API change. In an
  air-gapped on-premise deployment the hardware belongs to the client and is often
  unknown to the vendor, so a property that must be verified per machine is not one
  a specification can promise. §15.2 states this as a table across targets rather
  than as a blanket claim: a CNSA-conformant profile would be a compliance
  decision, and on hardware without AES acceleration a regression on this axis.

  **KyberSlash does not apply.** The attack recovered Kyber keys in minutes by
  exploiting a secret-dependent division; verified in the vendored source that
  `ml-kem` replaces it with a multiply-and-shift and that its only division is a
  compile-time constant. `RUSTSEC-2023-0079` is filed against `pqc_kyber`, not
  used here.

  The bench now measures what the analysis claims: dudect probes over ML-KEM
  decapsulation, with classes *valid vs corrupted encapsulation* (implicit
  rejection must be indistinguishable, or a chosen-ciphertext attack opens up)
  and *two different secret keys* (key-dependent timing). Both report
  constant-time. Signature verification is deliberately **not** a target — key,
  message and signature are all public, so its timing reveals no secret — and
  ML-DSA *signing* is excluded because rejection sampling makes its time vary by
  specification, which would read as a leak that is not one.

  Also recorded: deep-learning side-channel analysis reports breaking an AES
  implementation in ~350 traces where a classical template attack needs ~52,000.
  "The leak is too small to matter" is no longer a defensible position, which is
  precisely why the defence here is absence of leakage by construction rather
  than obfuscation of it.
- **Shamir secret sharing (`quipu::shamir`, opt-in feature `escrow`)** — split a
  secret into `n` shares of which any `k` reconstruct it, over GF(2^8) with
  constant-time field arithmetic (no lookup tables, which would leak through the
  cache). Exposed to Python as `split_secret` / `combine_secret`; the PyPI wheel
  and CI enable the feature explicitly.

  It sits behind a non-default gate on principle, not out of caution: a tool
  should be **contained to its single purpose**. Whoever encrypts data does not
  need to split keys, and code that is not compiled exposes no API, cannot be
  invoked by mistake and cannot interfere with anything else.

  This closes residual risk **R2** of the threat model, whose documented
  mitigation was "offline backup": splitting the OPRF server key into k-of-n
  shares held separately *is* that backup, done with discipline. It equally
  covers custody of an integrator's ML-DSA signing key and contractual escrow,
  and it needs neither network nor HSM — the condition of air-gapped
  deployments.

  **The integrity tag travels inside what is split, not in the header** —
  `secret ‖ SHA-256(domain ‖ secret)[0..8]`. That single placement decision is
  what makes the design hold: with `k-1` shares perfect secrecy covers the whole
  payload, tag included, so **there is no guessing oracle** — whoever can verify
  a guess already holds `k` shares, and therefore already holds the secret. A
  corrupted share, or one from a different split, is still detected: the
  reconstruction is not the payload and the tag does not match.

  It also makes shares **unlinkable**. The header carries only
  `magic ‖ threshold ‖ index ‖ length`, so two shares of the same split look no
  more related than two of different splits. This matters wherever shares for
  several secrets are stored together: a shared field would partition them into
  equivalence classes and hand a reader a map of which shares are worth
  combining.

  An earlier draft put the verifier in the header. That opened an oracle and
  required four patches to contain it — a minimum length floor, Argon2id
  hardening, a documented "high-entropy only" caveat, and per-share salts for
  unlinkability. Moving eight bytes removed all four. Not threshold signing: the
  secret is reassembled in memory to be used.

  Cross-validated against an independent implementation using a different
  approach (log/antilog tables), and against the AES field's known vectors.
- **Power-on self-tests (`quipu::selftest`)** — known-answer tests run against
  the binary actually executing, not the CI build. A wheel compiled with an odd
  flag, a broken SIMD backend or a faulty CPU would otherwise go unnoticed:
  the vectors in `tests/` only ever prove the build that ran them. Certified
  cryptographic modules — FIPS 140-3 and the Chinese GM/T alike — require this
  for that reason, and the module **refuses to operate** if a check fails
  rather than returning silently wrong results.

  Three ways it goes beyond what those standards ask:
  1. **Published vectors, not vendor-chosen ones.** HKDF-SHA256 is checked
     against **RFC 5869 test case 1**. A certified module may use vectors of the
     vendor's own making, which only prove self-consistency; an RFC vector
     proves conformance to the standard.
  2. **Negative tests.** It is not enough that the correct path works — tampered
     ciphertexts, wrong AAD, forged signatures and wrong-key decapsulation must
     all *fail*. A module that always validated would pass conventional
     self-tests, which are purely positive.
  3. **Continuous RNG health.** Two consecutive draws must differ and must not
     be all zeros — a dead generator is the quietest and most catastrophic
     failure mode there is.

  14 checks in total, wired into **every entry point that uses the crypto core**
  — `api::encode`/`decode`, `stream::encrypt`/`decrypt_stream` and both keypair
  generators. The first call costs ~9 ms (median over 200 runs); every call after
  it costs **8.7 ns**, which is nothing next to the Argon2id the same function is
  about to run at 64 MiB.

  **The failure path is treated as a feature, not an afterthought.** A failing
  self-test is almost never the caller's fault — it means a build compiled for a
  different CPU, a corrupted or substituted library file, or failing hardware. So
  the message says that in plain language, states what did *not* happen ("nothing
  was encrypted, decrypted or saved; your files are intact"), lists probable
  causes in order, and gives a reporting path. A technical dump would leave a
  person unsure whether their data was at risk.

  It is also **exercised rather than assumed**: a non-default `selftest-fault`
  feature forces a check to fail so the whole error path runs in CI, and each
  check is proven to *discriminate* — flip a bit of the expected vector and it
  must reject it. A check that always returned `true` would pass a conventional
  self-test suite exactly like a correct one.

  Backed by `examples/selftest_soak.rs`: 200 sequential passes + 100 concurrent
  threads + 1000 repeated calls = **1300 simulated operations**, wired into CI.


## [0.7.0] — 2026-07-06

### Added
- **Multi-language bindings over a stable C ABI.** Quipu's post-quantum core is
  now reachable from C, Node.js and Go, all through one `extern "C"` surface,
  each with a cross-language interop test that decrypts Rust-produced `QST1`
  vectors. Distribution: the Python package (`quipu-crypto`) and signed source
  ship to PyPI + the GitHub Release on tag; the Go module is consumable at
  `github.com/isazajuancarlos/quipu/bindings/go@v0.7.0`; the npm package
  (`quipu-crypto`) publishes via a prebuild matrix (Linux/macOS/Windows).
- **Written specification + machine-readable interoperability test vectors.**
  `docs/SPEC.md` now documents every container format byte-by-byte through v0.6.0
  (adds the streaming `QST1`, honey `QHNY`, and triple-signature `QSG3` formats to
  the existing symmetric/PQ/VOPRF/signature spec). New
  `tests/vectors/quipu_vectors.json` holds known-answer vectors — deterministic
  entries (KDF, HKDF, XChaCha20-Poly1305, Padmé, `QUIP`, `QHNY`) freeze the format
  byte-for-byte; frozen entries pin the decode/verify direction for streaming, PQ
  and signatures. Generated by `examples/gen_vectors.rs`, checked on every
  `cargo test` by `tests/vectors.rs`. Closes a roadmap item and is a prerequisite
  for an external audit and for multi-language bindings.
- **C ABI bindings** (`bindings/c`, crate `quipu-capi`): a stable, stateless,
  panic-safe `extern "C"` surface with parity to the Python bindings (symmetric
  codec, streaming AEAD, post-quantum recipient, hybrid signature). Ships a
  cbindgen-generated `quipu.h`, a `cdylib`/`staticlib`, and a C integration test
  wired into CI (build + header-drift gate + Rust ABI tests + linked C test).
  Output buffers are wiped on free, so no secret-key or plaintext residue
  remains. Foundation for future Node.js/Go bindings.
- **Node.js bindings** (`bindings/node`, npm package `quipu-crypto`): an idiomatic
  `Buffer`-in/out API over the C ABI via Koffi runtime FFI — symmetric codec,
  streaming AEAD, post-quantum recipient, and hybrid signature — with thrown
  `QuipuError`s, hand-written TypeScript types, and a `node:test` suite including
  a **cross-language interop** test that decrypts Rust-produced QST1 vectors. New
  `node` CI job. The API is synchronous in v1: koffi's async path runs on a libuv
  worker whose stack is too small for the core's ML-DSA-87 operations; a
  non-blocking `worker_threads` wrapper is a planned follow-up.
- **Go bindings** (`bindings/go`, module `github.com/isazajuancarlos/quipu/bindings/go`):
  an idiomatic `(result, error)` API over the C ABI via cgo, static-linking
  `libquipu_capi.a` — symmetric codec, streaming AEAD, post-quantum recipient, and
  hybrid signature. Errors are `*quipu.Error` sentinels (`errors.Is`-matchable). A
  `testing` suite includes a **cross-language interop** test that decrypts
  Rust-produced QST1 vectors. Unlike the Node bindings, no async workaround is
  needed: cgo runs on the goroutine system stack, so ML-DSA-87 has room and calls
  are concurrency-safe. New `go` CI job.

### Security Lab
- **Coverage-guided fuzzing wired into CI**: the `fuzz/` libFuzzer harness gains a
  `honey_decrypt` target (the newest untrusted parser) and a nightly `fuzz (smoke)`
  CI job that runs every target (`honey_decrypt`, `parse_container`, `unpad`,
  `codec_roundtrip`) on each push. Local verification found no crashes across
  ~53M executions.

## [0.6.0] — 2026-07-04

### Added
- **Honey Encryption — decoy mode for low-entropy secrets (opt-in `honey`
  feature)**: `honey::encrypt`/`decrypt` (and `encrypt_pin`/`decrypt_pin`) protect
  a secret modelled as a uniform fixed-alphabet sequence (a PIN, a mnemonic
  phrase) so that **any wrong passphrase decrypts to a different but plausible
  secret**, not an error. An offline brute-force attacker never gets a
  "correct-key" signal — the success oracle that makes guessing a weak passphrase
  viable is removed (Juels & Ristenpart, 2014). Construction is a base-`A`
  one-time-pad keyed by Argon2id + HKDF; no new dependencies. **By design this
  mode carries no authentication tag** (a tag would itself be a success oracle),
  so it does not detect tampering and is a specialised companion to — never a
  replacement for — the authenticated AEAD core. Only sound for uniform,
  low-entropy secrets, not arbitrary data. Covered by a "success-oracle" attack
  in the Security Lab.
- **Streaming AEAD exposed in the Python bindings**: `quipu.encrypt_stream` /
  `quipu.decrypt_stream` (optional `pepper` and `chunk_size`) wrap the STREAM
  construction. Output is raw `bytes` (a binary container), not symbols; a
  `chunk_size` outside the 4 KiB–16 MiB range or a failed authentication raises
  `ValueError` instead of aborting the interpreter.

### Security Lab
- **Consolidated red-team runner** (`examples/redteam.rs`): launches every
  adversarial surface at once — adaptive (leak, symmetric/streaming/triple-hybrid
  forgery, honey success-oracle) and deterministic (tamper, truncation,
  salt/nonce uniqueness, signature forgery) — with a single verdict, an
  antihacker-defense latch, and a `QUIPU_REDTEAM_SCALE` soak knob.
- **Honey parser fuzzer** (`lab::honey_fuzz`): feeds adversarial byte strings to
  `honey::decrypt` and proves it never panics (caught via `catch_unwind`) nor
  allocates unbounded — only a decoy or a structural error.

## [0.5.0] — 2026-07-04

### Added
- **Triple-hybrid signature mode (opt-in `slh` feature)**: Ed25519 + ML-DSA-87 +
  **SLH-DSA-SHA2-256s** (FIPS-205, stateless hash-based, via the `fips205` crate)
  combined with an **AND 3-of-3** combiner — a signature is valid only if all three
  verify, so it stays unforgeable as long as at least one of three independent
  families (elliptic curve, lattice, hash) survives. New `QSG3` container and
  `api::encode_signed_triple` / `decode_verified_triple`. High-assurance mode:
  signatures are ~34 KB and signing is slow, so it is opt-in, not the default. The
  double-hybrid mode and v0.4.x artifacts are unchanged. Covered by an adaptive
  3-of-3 forgery attack in the Security Lab.
- **Streaming AEAD for large data-at-rest**: `api::encrypt_stream` /
  `decrypt_stream` (and byte-slice `*_bytes` helpers) encrypt an `io::Read` to an
  `io::Write` in bounded memory using the STREAM construction (Tink-inspired) —
  fixed-size chunks under XChaCha20-Poly1305 with a per-file Argon2id+HKDF key and
  a `QST1` header bound as AAD. Resistant to truncation (final-chunk flag),
  reordering and duplication (per-chunk counter in the nonce), cross-file splicing
  (per-file key) and tampering. Covered by an adaptive forgery surface in the
  Security Lab. No new dependencies.

## [0.4.1] — 2026-07-02

### Security
- **Internal security audit remediation** (availability/robustness hardening;
  no confidentiality/integrity issue was found). Online OPRF server: per-connection
  read/write timeouts (anti-slowloris), a bounded worker-thread pool, and a
  rate limiter that expires entries and caps tracked IPs (bounded memory).
  Offline library: untrusted PNG decoding now enforces `image` size/allocation
  limits (anti decompression-bomb); `ecc::recover` rejects a degenerate parity
  byte; `decode_verified` uses checked arithmetic (no 32-bit length overflow);
  the unverified OPRF path is hidden from docs in favour of the verifiable VOPRF.

### Changed
- **`KdfParams` maximum memory lowered from 1 GiB to 256 MiB.** Decrypting an
  untrusted container runs Argon2 with the container's own parameters before the
  AEAD tag is checked, so the ceiling bounds a cost-amplification DoS. 256 MiB is
  4× the interactive default. **Compatibility:** artifacts encoded with
  `mem_kib > 256 MiB` (very unusual) can no longer be decoded.

## [0.4.0] — 2026-07-02

### Added
- **Supply-chain & side-channel credibility (Security Lab Fase 0)**: a dudect-style
  constant-time gate (Welch's t-test) in the offline timing bench; a CycloneDX SBOM
  and a `cargo-vet` dependency-review gate in CI; and sigstore/cosign keyless
  signatures for release artifacts, documented in `docs/RELEASES.md`.
- **Signed release**: the wheels, sdist and their `.sigstore` bundles are attached
  to the [v0.4.0 GitHub Release](https://github.com/isazajuancarlos/quipu/releases/tag/v0.4.0),
  verifiable with `cosign verify-blob --bundle` (keyless, GitHub OIDC identity);
  the PyPI wheels additionally carry PEP 740 provenance attestations. Verification
  steps are in [`docs/RELEASES.md`](docs/RELEASES.md).

### Changed (BREAKING — wire format)
- **Post-quantum primitives raised to NIST security category 5 (CNSA 2.0)**:
  the hybrid KEM now uses **ML-KEM-1024** (was ML-KEM-768) and the hybrid
  signature uses **ML-DSA-87** (was ML-DSA-65). This aligns Quipu with the NSA
  Commercial National Security Algorithm Suite 2.0 parameter levels. The classical
  halves (X25519, Ed25519), the X-Wing-style transcript binding, the AND signature
  combiner and the domain-separation labels are unchanged.
- **Consequence**: hybrid public/secret keys, encapsulations, verifying/signing
  keys and signatures are larger, and artifacts/keys produced by 0.3.x are **not
  interoperable** with 0.4.0. Sizes: ML-KEM ek/ct 1184/1088 → 1568/1568 B, dk
  2400 → 3168 B; ML-DSA vk 1952 → 2592 B, signature 3309 → 4627 B (hybrid
  signature 3373 → 4691 B). No security downgrade is possible: the recipient/signer
  key fixes the parameter level and cross-level bytes fail length validation.

## [0.3.0] — 2026-07-01

### Added
- **Quipu Security Lab — Etapa B (offline bench)**: timing / side-channel harness
  (surface 2: constant-time `ct_eq` and passphrase-independent `decode` timing)
  and an AI-accelerated password-guessing cost model (surface 3: verifies the
  Argon2id per-guess cost floor holds and that a ranked wordlist never cracks).
  Gated behind a new non-default `lab-offline` feature (implies `lab`, not run by
  CI) and shipped with an isolated `quipu-lab` OCI container (`--network none`,
  non-root, read-only, no real keys). Rust-only and reproducible; the container is
  documented as "ML-ready". Run with `bash lab/run.sh` or
  `cargo run --release --example securitylab_offline --features lab-offline`.
- **Python bindings for the hybrid signature mode**: `generate_signing_keypair`,
  `encode_signed` and `decode_verified` are now exposed to Python, reaching
  Rust/Python parity for the signature API. `quickstart.py` and the Python test
  suite cover the signed round-trip and rejection of wrong/tampered artifacts.
- **Quipu Security Lab (Etapa A)**: a self-hosted *adaptive* red-team behind a
  non-default `lab` Cargo feature (never compiled into the published crate or the
  PyPI wheel — "the weapon does not ship with the product"). A deterministic,
  seed-reproducible engine drives breach-guided attacks over two surfaces:
  ciphertext/format length-leak distinguishing (surface 1) and adaptive signature
  forgery — frankensignatures, key-substitution and region tampering (surface 4).
  Ships three anti-abuse locks: compile-time isolation, a tamper-evidence guard
  that fails CI if the antihacker defenses (`ct_eq`, KDF-param validation, `wipe`)
  are weakened, and a hash-chained findings corpus. Run with
  `cargo run --example securitylab --features lab`.

## [0.2.0] — 2026-07-01

### Added
- **Hybrid signature mode** (asymmetric authenticity): Ed25519 + ML-DSA-65
  (FIPS-204) combined with an **AND** verification combiner — a signature is valid
  only if *both* verify, so it stays unforgeable as long as at least one primitive
  survives. Signatures bind the signer's full verifying key and a
  `quipu/v3/sign` domain label into the signed preimage to prevent key
  substitution and cross-component mixing. New `pqsign` module and
  `api::encode_signed` / `api::decode_verified` (a signed-but-plaintext `QSG1`
  container: authenticity + non-repudiation, not confidentiality).
- **Red-team coverage**: hackerbot `forgery_attack` (tamper each symbol of a
  signed artifact; every mutation must fail verification).

### Security
- Signing keys are stored as 32-byte seeds and zeroized on drop; Ed25519 uses
  strict verification (rejects small-order keys and malleable signatures).
- Signature primitives are vetted third-party crates (`ed25519-dalek`, `ml-dsa`);
  zero `unsafe` in first-party code preserved.

## [0.1.0] — 2026-07-01

First public release. Published to crates.io (`quipu`) and PyPI
(`quipu-crypto`).

### Added
- **Symmetric mode** (passphrase): Argon2id + HKDF-SHA256 key derivation with
  NFKC normalization and optional pepper; XChaCha20-Poly1305 AEAD; 68-byte
  authenticated container header bound as AAD.
- **Hybrid post-quantum mode** (asymmetric): X25519 + ML-KEM-768 (FIPS-203)
  combined via HKDF with X-Wing-style transcript binding (recipient's full public
  key + encapsulation).
- **Verifiable online hardening mode**: VOPRF over ristretto255 with
  non-interactive DLEQ proofs (RFC 9497 style); the client cryptographically
  detects a dishonest hardening server. Includes a dependency-free TCP server.
- **Visual channels**: lossless PNG output, a native glyph alphabet, and a robust
  print channel with Reed-Solomon error correction.
- **Length hiding** via Padmé padding.
- **Defensive layers**: key zeroization (`zeroize`), constant-time comparison
  (`subtle`), KDF-parameter validation against malicious headers.
- **Internal tooling**: a red-team component ("hackerbot") and a test platform.
- **Bindings**: Python via PyO3 (abi3, CPython 3.9+); Rust `rlib` + C-ABI
  `cdylib`.
- **Docs**: internal pre-audit, threat model, licensing (dual AGPL + commercial),
  runnable Rust and Python quickstart examples.

### Security
- All cryptographic primitives are vetted third-party crates; zero `unsafe` in
  first-party code.
- Verified against Google Wycheproof AEAD vectors; Miri (no UB) and `cargo-fuzz`
  (no crashes) on the pure-logic and parsing modules; `cargo-audit` in CI.
- **Not yet independently audited** — see [`SECURITY.md`](SECURITY.md).

[Unreleased]: https://github.com/isazajuancarlos/quipu/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/isazajuancarlos/quipu/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/isazajuancarlos/quipu/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/isazajuancarlos/quipu/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/isazajuancarlos/quipu/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/isazajuancarlos/quipu/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/isazajuancarlos/quipu/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/isazajuancarlos/quipu/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/isazajuancarlos/quipu/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/isazajuancarlos/quipu/releases/tag/v0.1.0
