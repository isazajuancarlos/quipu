# Quipu — Threat Model

**Version 1.0 · 2026-07-01**

> 🇪🇸 Original en español: [`../MODELO_DE_AMENAZA.txt`](../MODELO_DE_AMENAZA.txt)

This is a living document. It should be revised on every design change and is an
input for the independent cryptographic audit.

## 0. Purpose

To define **what** Quipu protects, **from whom**, and **under which
assumptions**. Without this frame, "this is secure" has no verifiable meaning.
This document bounds the real guarantees of each mode and makes explicit what is
out of scope.

Guiding principle (Kerckhoffs): security lives in the **keys** and the vetted
primitives, **never** in the secrecy of the representation (codebook, symbology,
glyphs, format). All symbology is public and versioned. If anything depends on
hiding the format, it is a design defect.

## 1. Assets to protect

- **A1.** Confidentiality of the plaintext (the encoded data).
- **A2.** Integrity/authenticity of the container (tamper detection).
- **A3.** The user's passphrase and the keys derived from it.
- **A4.** The recipient's asymmetric secret keys (hybrid PQ mode).
- **A5.** The OPRF server key (online mode). Its loss makes all secrets hardened
  with it **unrecoverable**; its theft enables offline dictionary attacks on
  those secrets.
- **A6.** The pepper (a secret kept outside the data).

## 2. Adversaries and capabilities

- **T1. Observer of data at rest / in transit:** has the full encrypted container
  (bytes, PNG image, or glyphs) and the public codebook. Does **not** have the
  passphrase, pepper, or secret keys. Goal: read the plaintext or distinguish it
  from random.
- **T2. Active tamperer:** can alter, truncate, or forge containers and hand them
  to the victim to decrypt. Goal: cause acceptance of false data, panic/DoS, or
  leakage.
- **T3. Offline attacker with compute:** brute-force / dictionary attack on the
  passphrase, holding the container.
- **T4. Dishonest or compromised OPRF server** (online mode): responds with the
  wrong key or tries to deflect the derivation.
- **T5. "Harvest now, decrypt later" adversary** with a future quantum computer:
  stores today's asymmetric traffic to decrypt it once the classical part
  (X25519) can be broken.
- **T6. Attacker with access to process memory AFTER an operation** (dump, swap,
  partial cold-boot): looks for residual keys.

Out of the adversary model (see §5): an attacker with access to memory **during**
the operation, a local physical side channel, or control of the binary/OS.

## 3. Trust assumptions

- **S1.** The vetted primitives are secure: XChaCha20-Poly1305, Argon2id,
  HKDF-SHA256, X25519, ML-KEM-768 (FIPS-203), ristretto255.
- **S2.** The system RNG (getrandom/OsRng) is cryptographically secure.
- **S3.** The passphrase has sufficient entropy AND/OR a high Argon2id cost is
  used; a weak passphrase is breakable by T3 regardless (see R1).
- **S4.** The pepper and secret keys are stored beyond T1/T2's reach.
- **S5.** In online mode, the client PINS the correct OPRF server public key via a
  prior trusted channel.
- **S6.** The OPRF network channel runs over TLS in production (the custom
  protocol does not provide transport confidentiality by itself).
- **S7.** The machine running Quipu is not compromised during the operation.

## 4. Security guarantees per mode

**Symmetric mode (passphrase):**
- Confidentiality and integrity of the plaintext (AEAD) against T1 and T2, under
  S1–S3. The header is authenticated as AAD: any altered bit → decryption
  REJECTED.
- Brute-force resistance proportional to the Argon2id cost + passphrase entropy
  (against T3). The pepper adds a secret T3 does not have.
- KDF parameters from a tampered header are VALIDATED (`is_sane`) before deriving
  → no panic/DoS from memory exhaustion (closes the hackerbot finding, F3).

**Asymmetric hybrid PQ mode (encrypt to a public key):**
- Confidentiality against T1 and T5: the content key combines an X25519 secret
  and an ML-KEM-768 secret via HKDF; breaking it requires breaking BOTH.
- The transcript binds the recipient's FULL public key (X25519 pub + ML-KEM ek)
  and the encapsulation (X-Wing style) → resistant to re-encapsulation /
  public-key-substitution attacks (closes F2).
- ML-KEM uses implicit rejection: a wrong secret key does NOT fail but yields a
  different content key (the subsequent AEAD detects it).

**Online mode (OPRF server-assisted hardening):**
- The server participates in deriving the key without seeing the passphrase or the
  result (ristretto255 blinding). It turns an offline dictionary attack into an
  ONLINE one, subject to the server's rate limiting.
- VERIFIABILITY (VOPRF + DLEQ proof): the client checks the server used the pinned
  key; a dishonest server (T4) is DETECTED and the operation aborts (closes F1).

**Visual channel (glyphs / PNG) and ECC:**
- Purely representation: adds/subtracts no security. The PNG/glyph carries exactly
  the encrypted container. Reed-Solomon corrects channel errors; it is not a
  cryptographic defense. Parsing treats input as UNtrusted (fuzzing + anti-DoS
  guards).

## 5. Non-goals (out of scope)

- **N1.** Hiding the EXISTENCE or exact SIZE of the message. Size is mitigated with
  Padmé padding (approximate length hiding), not full steganography.
- **N2.** Protecting against an adversary controlling the machine DURING the
  operation (malware with live RAM access, keylogger, trojaned binary).
- **N3.** Local physical side channels (fine timing, power, EM). Constant-time
  comparison is used where applicable, but it is not the goal.
- **N4.** Low-entropy passphrases without a high KDF cost (see R1).
- **N5.** Availability of the online mode if the OPRF server is down (see R2).
- **N6.** Secrecy of the representation/codebook (public by design).
- **N7.** Key management/rotation and secure storage (operator's responsibility;
  Quipu provides primitives, not custody).

## 6. Attack surface (for the auditor)

- Container parsing (`container::parse`) and image/PNG/glyph parsing: untrusted
  input. Covered by fuzzing (`parse_container`, `unpad`, `codec_roundtrip`).
- The hybrid KEM combiner and the construction of the asymmetric mode.
- The VOPRF: DLEQ proof, network protocol (replay, rate limiting, denial).
- Domain separation: each derivation uses a unique label (`quipu/v1/cipher`,
  `quipu/v2/hybrid-kem`, `quipu/v2/voprf[-dleq|-server-key]`,
  `quipu/v2/oprf[-server-key]`). Verified.
- In-memory key management: zeroization of intermediate material (normalized
  passphrase, combined shared secrets, subkeys, padded plaintext).

## 7. Residual risks

- **R1. Weak passphrase:** no KDF saves a guessable password. Mitigate with a high
  Argon2id cost + pepper + (optionally) the rate-limited online mode.
- **R2. The OPRF server is a single point:** its downtime blocks online decryption;
  losing its key makes secrets unrecoverable. Offline backup + planned rotation +
  high availability.
- **R3. Zeroization in Rust is best-effort:** copies moved by the optimizer or
  spilled to swap may persist. `zeroize` is used on key buffers, but there is no
  absolute guarantee against T6.
- **R4. Trust in third-party crates** for the primitives (S1). Mitigated with
  `cargo-audit` in CI, but a 0-day in a dependency remains possible.
- **R5.** The model does not cover a compromised endpoint (N2): if the user's
  machine is owned, the passphrase and plaintext leak in the clear.

## 8. Traceability to mitigations (summary)

| Adversary | Mitigation |
|-----------|-----------|
| T1 | AEAD (XChaCha20-Poly1305); public representation with no secret value. |
| T2 | Header as AAD; `is_sane` validation of KDF params; parsing guards. |
| T3 | Argon2id (memory-hard) + pepper; online mode with rate limiting. |
| T4 | VOPRF with DLEQ proof verified against a pinned public key (F1). |
| T5 | Hybrid KEM X25519 + ML-KEM-768 (F2, transcript with bound ek). |
| T6 | Best-effort zeroization of sensitive material (partial; see R3). |

---

Construction references: RFC 9497 (OPRF/VOPRF), X-Wing (hybrid KEM), FIPS-203
(ML-KEM), RFC 8439 (ChaCha20-Poly1305), RFC 9106 (Argon2).
