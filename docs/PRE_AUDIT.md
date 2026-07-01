# Quipu — Internal Pre-Audit Report

**Stage 0, self-audit · 2026-06-30 (F1/F2 updates 2026-07-01)**

> 🇪🇸 Original en español: [`../INFORME_PREAUDITORIA.txt`](../INFORME_PREAUDITORIA.txt)
>
> **Scope:** the library core (symmetric encryption, post-quantum hybrid, OPRF,
> visual channel, ECC, container format) + dependencies.
> **NOTE:** this does NOT replace an independent audit. It is preparation to
> reduce the cost and scope of a later paid/independent audit.

## Executive summary

Automated checks and a manual analysis of the protocols were run. Result: 2
dependency vulnerabilities (pyo3) FIXED; 2 medium/low-severity design findings
(non-verifiable OPRF; hybrid combiner binding), both since corrected; the rest
positive. The library uses vetted primitives and contains no first-party `unsafe`
code, so the focus of an audit would be the COMPOSITION.

## 1. Automated checks (results)

- **cargo-audit** (deps vs RustSec): BEFORE — 2 vulnerabilities in pyo3 0.23.5
  (RUSTSEC-2025-0020, RUSTSEC-2026-0177); neither affected function is used by
  Quipu, but pyo3 was upgraded to 0.29. AFTER — clean (0 vulnerabilities).
- **Wycheproof** (Google KAT vectors for XChaCha20-Poly1305 vs `quipu::cipher`):
  PASS. Encryption reproduces ct‖tag; all invalid vectors are REJECTED
  (manipulated tags/nonces/ct). Interoperable, no known failures.
- **unsafe** (first-party `src/`): 0 uses of `unsafe`. Memory safety rests only on
  vetted crates.
- **Miri** (undefined-behavior detector on pure-logic modules — codec, prelayers,
  ecc, glyphopt): 13/13 tests with no UB detected.
- **Fuzzing** (`cargo-fuzz`: parse_container, unpad, codec_roundtrip): no crashes
  (~25M+ executions across sessions).

## 2. Findings (manual composition analysis)

### [F1] Non-verifiable OPRF — Severity: MEDIUM — FIXED
The online mode used a simple multiplicative OPRF (2HashDH) with no verifiability:
the client could not detect a dishonest server.
**Fix:** implemented a VOPRF (`src/voprf.rs`) with a DLEQ proof (non-interactive
Chaum-Pedersen, RFC 9497 style): the server publishes `Y = k·G`; each evaluation
carries a DLEQ proof that it used the same `k`; the client VERIFIES it against the
pinned public key. Wired into `oprf_net`, `api::encode_online/decode_online` (new
`server_pub` parameter), and the server binary. Tests: forged proof / wrong key /
tampered evaluation → all REJECTED; a dishonest server is detected
(`OnlineError::Verification`).
**Residual:** the non-verifiable primitive (`src/oprf.rs`) remains as a building
block, but the online mode no longer uses it.

### [F2] Hybrid combiner binding — Severity: LOW — FIXED
The hybrid combiner (`src/pqhybrid.rs::combine`) derived the key with `info =
LABEL ‖ eph_x_pub ‖ mlkem_ct`, without the recipient's public key.
**Fix:** the transcript now binds the recipient's FULL public key (X25519 pub +
ML-KEM ek) and the encapsulation (X-Wing style). The recipient recomputes the ek
from its dk (`dk.encapsulation_key()`); a test verifies the recomputed ek matches
the original. Round-trip verified.

### [F3] Untrusted KDF parameters — Severity: MEDIUM — FIXED
Found by the hackerbot: Argon2 params from a tampered header caused
overflow/DoS. Fixed with `KdfParams::is_sane()` before deriving + a regression
test.

## 3. Observations (informational)

- **[O1]** "Representation ≠ security" boundary: the codebook/symbology is public
  and versioned; no security property depends on its secrecy (Kerckhoffs).
- **[O2]** Online-mode availability: if the OPRF server is down, online decryption
  fails. The server key is a critical secret; its loss makes all hardened secrets
  unrecoverable. Offline backup + planned rotation.
- **[O3]** Domain separation: distinct HKDF/hash labels are used (cipher, codebook,
  hybrid, oprf-server-key). VERIFIED — all labels are unique.
- **[O4]** Nonces: XChaCha20 with a random 192-bit nonce per operation → negligible
  collision risk. Correct.
- **[O5]** Zeroization: derived keys (master, cipher_key) and plaintext buffers are
  wiped. ENHANCED: the normalized passphrase + pepper (kdf) and the combined shared
  secret material (pqhybrid) are now also wiped. Residual R3: best-effort in Rust.

## 4. Prioritized recommendations (status)

1. **[DONE]** VOPRF implemented and wired into the online mode (F1).
2. **[DONE]** Recipient public key bound to the hybrid transcript (F2), now
   including the ML-KEM ek (full X-Wing hardening).
3. **[DONE]** O3 domain separation verified; O5 zeroization enhanced.
4. **[DONE]** cargo-audit in CI (with a scheduled weekly run) + local mirror
   `scripts/audit.sh`.
5. **[DONE]** Threat model written (see [`THREAT_MODEL.md`](THREAT_MODEL.md)).

## 5. Suggested scope for the independent audit

Since the primitives are vetted and there is no first-party `unsafe`, the auditor
should concentrate on:
- The hybrid KEM combiner (F2) and the construction of the asymmetric mode.
- The VOPRF and the online protocol (rate-limit, replay).
- Container and image/PNG parsing (untrusted input; expand fuzzing).
- Domain separation and key management/zeroization.
- The threat model vs. the real guarantees of each mode.

## 6. Tools used

cargo-audit 0.22, wycheproof 0.6 (XChaCha20-Poly1305 vectors), Miri (nightly),
`unsafe` grep, cargo-fuzz, clippy. Pending (requires Go / other environment):
formal modeling with Verifpal/ProVerif/Tamarin — NOTE: Verifpal does not model
ML-KEM or OPRF blinding natively; for those, follow the reference constructions
(X-Wing, RFC 9497).
