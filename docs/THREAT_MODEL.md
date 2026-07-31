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
format). All symbology is public and versioned. If anything depends on
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
  (bytes or PNG image) and the public codebook. Does **not** have the
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
- **T7. Attacker of the operator, not the cryptography** (2026-07-26): reaches the
  plaintext through the surrounding system — the deployed service, an
  administrative credential, a supplier. Does not attack a primitive because it
  does not need to. This is the adversary that every real incident we studied
  actually was; see §10.
- **T8. Attacker of the human in the loop:** pretexting, phishing, coercion,
  shoulder-surfing. The concrete surface is **support for the OPRF service**: the
  `/admin/*` operations are run by a person, and "we got revoked by mistake,
  please reactivate us" is an email anyone can write. Whoever answers cannot tell
  the customer from whoever is impersonating them.

  MITIGATED BY ASYMMETRY, not by getting the judgement right. Closing (revoke,
  deactivate) may be done for anyone who asks: being wrong there is a reversible
  nuisance. Reopening what was deliberately closed is **not available at all** —
  `activate` will not resurrect a revoked key and `verify` rejects it even if its
  `active` flag is raised by some other route. Issuing a new key stays deliberate
  and is checked against the payment record, never against the requester's word.
  See `crates/quipu-oprf-server/README.md`.

  This entry originally justified itself on **paper custody** — someone reading
  words aloud or photographing a sheet. That channel was removed in PR #93, so
  the scenario was rewritten to match the operation that actually exists. An
  invariant defended over a use case we no longer have defends nothing.
- **T9. Attacker of availability with a security consequence:** takes down the
  distribution or update path so fixes do not arrive. Not a breach, and still a
  degradation of everyone downstream.

Out of the adversary model (see §5): an attacker with access to memory **during**
the operation, a local physical side channel, or control of the binary/OS.

## 3. Trust assumptions

- **S1.** The vetted primitives are secure: XChaCha20-Poly1305, Argon2id,
  HKDF-SHA256, X25519, ML-KEM-1024 (FIPS-203), ristretto255.
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
  and an ML-KEM-1024 secret via HKDF; breaking it requires breaking BOTH.
- The transcript binds the recipient's FULL public key (X25519 pub + ML-KEM ek)
  and the encapsulation (X-Wing *style*, not wire-compatible: ML-KEM-1024 +
  HKDF-SHA256, vs X-Wing's ML-KEM-768 + SHA3-256) → resistant to re-encapsulation /
  public-key-substitution attacks (closes F2).
- ML-KEM uses implicit rejection: a wrong secret key does NOT fail but yields a
  different content key (the subsequent AEAD detects it).

**Online mode (OPRF server-assisted hardening):**
- The server participates in deriving the key without seeing the passphrase or the
  result (ristretto255 blinding). It turns an offline dictionary attack into an
  ONLINE one, subject to the server's rate limiting.
- VERIFIABILITY (VOPRF + DLEQ proof): the client checks the server used the pinned
  key; a dishonest server (T4) is DETECTED and the operation aborts (closes F1).

**Visual channel (PNG) and ECC:**
- Purely representation: adds/subtracts no security. The PNG carries exactly
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
  Quipu provides primitives, not custody). `quipu::shamir` is precisely such a
  primitive — `split`/`combine` and nothing else: there is no keystore, no
  service, no rotation. Where and how the shares are held stays with the
  operator.

## 6. Attack surface (for the auditor)

- Container parsing (`container::parse`) and image/PNG parsing: untrusted
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
  high availability. The offline backup now has a primitive in the library:
  `quipu::shamir` splits the key into k-of-n shares held separately, so no single
  custodian can recover it and no single loss destroys it.
- **R3. Zeroization in Rust is best-effort:** copies moved by the optimizer or
  spilled to swap may persist. `zeroize` is used on key buffers, but there is no
  absolute guarantee against T6.

  **What the library does, and where it stops (audited 2026-07-31).** The
  reconstructed-material path is clean and was checked, not assumed:
  `shamir::combine` returns `Zeroizing<Vec<u8>>` and wipes its intermediates,
  `SigningKey` wipes its seeds on drop, and `firmar_con_comparticiones` confines
  the secret's life to one call from which only the signature survives.

  What the library will **not** ship is `mlock`. RAM can leak through five paths —
  swap, a process core dump, cold boot, `ptrace` from another process of the same
  user, and the hibernation image — and `mlock` closes one of them (and half of
  hibernation) in exchange for pulling `libc` in as a direct dependency. Its
  siblings (`mlockall`, `PR_SET_DUMPABLE`, `MADV_DONTDUMP`) each patch one more
  path at the same cost. Five partial patches do not add up to one whole defence,
  and they would leave a README claiming memory is protected when it is protected
  against one path in five.

  **And "best-effort" now has a number** (`tests/residuo_memoria.rs`). Rejecting
  `mlock` left the real question unanswered — *does anything actually survive?* —
  and that question was never measured, only asserted. It is measured now, and
  measuring it is what closes the gap rather than patching around it.

  How: a child process performs the real operation and parks; the parent reads
  `/proc/<child>/mem` and counts occurrences of a canary secret. Two processes,
  not one — a scanner reading its own heap copies the very bytes it searches for
  into its own read buffer, and the same situation measured 0, 17 or 33 depending
  on scan order. Pure `std`: on Linux a process's memory is a file, so this needs
  neither `libc` nor explicit ptrace. And it searches an *interior* slice of the
  canary, because the allocator writes its own pointers over the first 16 bytes of
  a freed chunk — demanding a whole-secret match reported "no residue" with 240 of
  256 bytes of the secret still sitting in freed memory.

  Measured, in debug and in release: **zero residue** on all three paths —
  the Shamir-reconstructed signing seed, the derived master key, and the
  passphrase itself. Each result has a control that deliberately leaks a copy and
  requires the scanner to see it; without those, a zero would be indistinguishable
  from a scanner looking in the wrong place.

  So, precisely:

  - **T6 (memory read AFTER the operation) is closed and measured ON THE THREE
    PATHS THAT WERE MEASURED**: the Shamir-reconstructed signing seed, the derived
    master key, and the passphrase. On those, a dump, a swap image, a hibernation
    image or a cold boot find nothing.

    **On the paths not yet measured, nothing is claimed** — which is not the same
    as claiming they are fine. Still to measure: `decode_as_recipient` (the
    post-quantum hybrid, with the recipient key and the content key that comes out
    of decapsulation), the **plaintext** returned by `decode` — the user's own
    secret, the one that affects the most people — `stream` (`QST1`), and `honey`.
    Each needs its own deliberate-leak control; a control for one scenario does
    not validate another.
  - **An adversary with root on the machine WHILE the process runs is R5**, a
    compromised endpoint, and is already out of scope by declaration. Conflating
    it with T6 is what makes this gap look unclosable; they are different threats.
  - **With an HSM:** closed by construction too — the private key never leaves the
    device.
  - **Defence in depth for the deployment**, not a substitute for the above:
    encrypted or disabled swap, hibernation off, core dumps off (`ulimit -c 0` /
    `kernel.core_pattern`), full-disk encryption.
- **R4. Trust in third-party crates** for the primitives (S1). Mitigated with
  `cargo-audit` in CI, but a 0-day in a dependency remains possible.
- **R5.** The model does not cover a compromised endpoint (N2): if the user's
  machine is owned, the passphrase and plaintext leak in the clear.
- **R6. We are somebody's supplier.** `oprf.xiliux.com` is a deployed service that
  other people's products depend on. Supersalud and MIPRES did not fail through
  their own fault: their supplier IFX Networks failed. In that story the seat
  Xiliux occupies is IFX's. This is the operational risk of the product, well
  above any attack on the primitives, and R2 only covered its availability half —
  not the cascade to clients.
- **R7. Degraded mode.** If the system is unavailable, the client must not be left
  in breach before a third party (the patient, the payer, the regulator). Medellín
  logged emergencies on paper for a reason. Recovery that needs no machine —
  a word list rather than a camera — is not nostalgia: it is what an emergency
  service actually did.
- **R8. Encryption at rest is what makes exfiltration worthless.** Against double
  extortion — encrypt and leak — backups solve the first half only. The leak is
  neutralised solely if the data was already encrypted with keys the attacker did
  not obtain. This is Quipu's exact scope and the strongest argument to a client
  in the health sector.

## 8. Traceability to mitigations (summary)

| Adversary | Mitigation |
|-----------|-----------|
| T1 | AEAD (XChaCha20-Poly1305); public representation with no secret value. |
| T2 | Header as AAD; `is_sane` validation of KDF params; parsing guards. |
| T3 | Argon2id (memory-hard) + pepper; online mode with rate limiting. |
| T4 | VOPRF with DLEQ proof verified against a pinned public key (F1). |
| T5 | Hybrid KEM X25519 + ML-KEM-1024 (F2, transcript with bound ek). |
| T6 | Best-effort zeroization of sensitive material (partial; see R3). |

## 9. Continuous self-attack (Security Lab)

Attackers keep learning, adapt, and increasingly train their own local AI models
for offensive work. A fixed test battery ages; the countermeasure is a system
that **attacks itself and corrects** ("antivirus with a lab included"). Quipu
ships a self-hosted *adaptive* red-team, the **Security Lab**.

Design principle — **the weapon does not ship with the product**: the whole lab
lives behind non-default Cargo features (`lab`, and `lab-offline` for the heavy
bench). It is never compiled into the published crate or the PyPI wheel, so it
cannot be invoked at runtime against a deployed instance.

Two speeds, two cages:

- **CI core (`--features lab`)** — deterministic, seed-reproducible:
  - *Surface 1 — format leak* (`src/lab/leak.rs`): checks that output length
    depends only on plaintext length, never on content (guards T1).
  - *Surface 4 — adaptive forgery* (`src/lab/forge.rs`): frankensignatures,
    key-substitution, region tampering against `decode_verified` (guards the
    signature mode).
  - *Anti-abuse locks*: compile-time isolation (CI check that no non-lab module
    references `crate::lab`); a **tamper-evidence guard** (`src/lab/guard.rs`)
    that fails CI if the antihacker defenses — `ct_eq`, KDF-param validation,
    `wipe` — are weakened; and a **hash-chained findings corpus**
    (`src/lab/corpus.rs`) so results cannot be silently poisoned.
- **Offline bench (`--features lab-offline`, run inside the `quipu-lab`
  container)** — machine-dependent, isolated (`--network none`, non-root,
  read-only, no real keys):
  - *Surface 2 — timing* (`src/lab/timing.rs`): looks for secret-dependent
    timing in `ct_eq` and `decode` (relates to T6 / side channels).
  - *Surface 3 — AI-accelerated guessing* (`src/lab/guessing.rs`): confirms the
    Argon2id per-guess cost floor holds and that a ranked wordlist never cracks
    (relates to T3 / R1).

On AI-assisted attacks: the lab treats the *attacker* as AI-capable but does not
require AI to *defend*. A trained model only amplifies leaks that already exist;
if there is no timing difference there is no trace to learn, and no ranking
(however smart) beats a memory-hard per-guess cost. The offline bench is
therefore Rust-only, deterministic and reproducible (audit-friendly), while the
container is documented as "ML-ready" for optional heavy experiments.

---

Construction references: RFC 9497 (OPRF/VOPRF), X-Wing (hybrid KEM), FIPS-203
(ML-KEM), RFC 8439 (ChaCha20-Poly1305), RFC 9106 (Argon2).

## 10. Empirical evidence: what actually happens (2026-07)

The model above was built from the cryptographic literature. This section records
what real incidents show, because the weight of the model should follow the
evidence and not the elegance of the categories.

**None of the incidents studied attacked the cryptography.** Not one. They were
denial of service, ransomware through a supplier, and compromised access. The
five invariants of `ATAQUES_TAXONOMIA.md` would not have changed any outcome —
that document is an excellent map of attacks *on the cipher*, and its conclusion
reads as universal when its scope is not.

| Incident | What it was | What it teaches |
|---|---|---|
| Canonical, Apr–May 2026 | **DDoS, not a breach.** `archive.ubuntu.com` and `security.ubuntu.com` down | An availability attack delayed **patching for everyone downstream**. → T9 |
| Medellín 123 / SIESM, Feb 2023 | LockBit ransomware; emergencies logged **with pencil and paper**; personal data of dispatchers leaked | The degraded mode is not hypothetical: an emergency service fell back to paper. → R7 |
| Supersalud + MIPRES | Fell because **IFX Networks**, their supplier, fell | The vector was the supplier, not the entity. → R6 |
| Salud Total, Jan 2024 | 4.6 M members affected | Colombian health is a preferred target |

Reported but **denied by the entity** and therefore not treated as fact: an
alleged attack on the Medellín city portal in March 2026.

Deliberately absent from this section: the exploitation vector of any named
entity. Several may still be exposed. What is useful here is the pattern —
supplier, availability, exfiltration — not anyone's concrete hole.
