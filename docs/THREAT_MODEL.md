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
  **Operational gap, found 2026-08-01: the container header carries NO pepper
  identifier.** Verified — `container.rs` has no such field. The consequence is
  not cryptographic but it bites at exactly the wrong moment: if a pepper is
  compromised and has to be replaced, **there is no way to tell which containers
  were made with the old one**. No inventory, no way to prove a given file has
  been re-encrypted, no way to stop halfway and know where you are.
  This is deliberate in one sense — a pepper id would be a linkable field across
  every container of the same owner (see the linkability discussion) — so it is a
  real trade-off and not an oversight to "fix". What was missing is that it was
  never written down, so nobody could weigh it. Whoever deploys a pepper needs to
  keep that inventory **outside** the containers, from day one.

## 2. Adversaries and capabilities

- **T1. Observer of data at rest / in transit:** has the full encrypted container
  (bytes; the "or PNG image" this used to say was removed 2026-08-01 — **that
  channel no longer exists**, deleted in PR #93/#99, and neither does the glyph
  renderer) and the public codebook. Does **not** have the
  passphrase, pepper, or secret keys. Goal: read the plaintext or distinguish it
  from random.
- **T1b. Observer who sees the container MORE THAN ONCE** (added 2026-08-01).
  Distinguished from T1 because the temporal dimension changes what is
  achievable, and for one mode it is decisive: **`negacion` loses deniability
  entirely** against it — comparing two snapshots reveals which region changed,
  and therefore that a hidden volume exists.
  This adversary is not exotic. He is *the default* in ordinary deployments:
  a versioned backup, a cloud sync folder, a filesystem journal, a VM snapshot,
  and — hardest to reason about — an **SSD**, where overwriting a file leaves the
  previous version in unmapped-but-present flash that wear levelling declines to
  erase.
  The `negacion` module doc states this limit; it was missing here, which is the
  wrong place for it to be missing: an auditor reads the threat model.
- **T2. Active tamperer:** can alter, truncate, or forge containers and hand them
  to the victim to decrypt. Goal: cause acceptance of false data, panic/DoS, or
  leakage.
- **T3. Offline attacker with compute:** brute-force / dictionary attack on the
  passphrase, holding the container.
- **T4. Dishonest or compromised OPRF server** (online mode): responds with the
  wrong key or tries to deflect the derivation.
- **T5. Adversary with a future quantum computer (CRQC).** Rewritten 2026-08-01:
  the previous wording said "stores today's asymmetric traffic to decrypt it once
  the classical part **(X25519)** can be broken", and that parenthesis quietly
  narrowed the adversary to the one place the design already handles. A category
  closed around what somebody thought of is the failure mode this document exists
  to avoid.
  T5 breaks **every elliptic-curve construction in the tree**, and the tree has
  three: X25519, Ed25519 and **ristretto255**. The first two are covered by
  construction — the hybrid KEM and the AND signature keep working while ML-KEM
  and ML-DSA stand. The third is not, and it is the one that matters:
  - **The VOPRF hardening (`api::encode_online`) is ristretto255 and is not
    post-quantum.** Its public key `Y = k·G` is *published by design*: the server
    serves it at `/v1/public-key` and S5 **requires** clients to pin it out of
    band. So this is not theft of `k` — it is **arithmetic on a value the design
    obliges us to publish**. Shor recovers `k` with nothing captured and nobody
    breached.
  - With `k`, the adversary evaluates the OPRF locally and the **rate limit
    disappears**. That rate limit is the whole of what the online mode adds (see
    §8, T3): Argon2id prices each guess, only the VOPRF caps how many there are.
    The victim is back to T3 with no signal anywhere.
  - **It is the FIRST link to fall, not the last.** 256-bit ECDLP needs roughly
    2 330 logical qubits against ~4 100 for RSA-2048 (Roetteler et al., 2017), so
    this breaks *before* the RSA everyone quotes as the deadline — and long before
    ML-KEM-1024 or ML-DSA-87 are in the conversation.
  - **And it is retroactive with no recovery.** Every container hardened online,
    and every password table hardened through `quipu-oprf-django`, that an
    attacker holds *today* becomes offline-guessable the day a CRQC exists. `k`
    and the domain never rotate, by project rule. This is the most concrete
    harvest-now case in the whole tree.
  - What survives, and it is not nothing: **obliviousness is perfect and holds
    even against a CRQC** — `B = r·H(pw)` with uniform `r` means every candidate
    is explained by some `r`, so the server never sees the passphrase. And the
    DLEQ proof stays sound (Chaum-Pedersen with Fiat-Shamir is statistical in the
    ROM, not reducible to DL) — but the guarantee goes **vacuous**, because an
    adversary holding `k` *is* the server and produces honest proofs.
  - **There is no fix to apply.** No practical, standardised post-quantum OPRF
    exists. The honest response is that this is written here, in §4, in §8 and in
    the README next to where the guarantee is sold — and that clients with a long
    horizon use **pepper AND VOPRF**, because the pepper is the only factor in
    that table that survives T5.
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

- **T10. Supply-chain attacker** (added 2026-08-01): does not attack the
  mathematics but the path the code takes to the user. Compromises a transitive
  dependency, the build machine, or the published artifact, so that the binary
  the victim runs is not the one the source describes. Goal: weaken the RNG, leak
  keys, or make a check pass that should fail.
  **This was the most conspicuous gap in the model, and the odd part is that the
  defences already existed while the adversary did not.** R4 named third-party
  crates as a residual risk — a *passive* framing ("a 0-day remains possible") —
  even though the countermeasures in the tree are all aimed at a *deliberate*
  attacker: reproducible builds (I5, byte-for-byte, enforced in CI),
  `cargo-vet` provenance gating, signed releases, and the boot self-test whose
  KATs a substituted primitive cannot pass. After xz/liblzma (2024), treating
  this as bad luck rather than as an adversary is not defensible.
  What it does **not** cover: an attacker who compromises the source repository
  itself with the maintainer's consent, and a subverted-but-statistically-sound
  RNG (see S2 — no output test can detect that; provenance is the only defence).

  **T10a. The concrete payload, and why testing can never find it (2026-08-01).**
  The natural weapon for T10 is not a backdoor in the mathematics — it is an
  **Algorithm Substitution Attack**: a build that computes everything correctly
  and hides the key in the fields that are *supposed* to look random.

  Quipu writes **40 bytes of pure randomness in clear into every container** —
  a 16-byte salt and a 24-byte nonce (`api::encode_to_blob`). A substituted
  implementation can set

      salt ‖ nonce  :=  Encrypt(attacker's public key, master key)

  and the result is **indistinguishable from randomness by construction**: a
  ciphertext is what randomness is supposed to look like. 320 bits of channel is
  more than enough for a 256-bit key, so **one container exfiltrates everything**,
  and every self-test, KAT, statistical battery and `dudect` measurement in this
  repository still passes, because the implementation *is* correct in every
  respect they measure.

  **Can it be closed?** Not without losing something Quipu needs. Deriving the
  salt deterministically from the passphrase would destroy its purpose (equal
  passwords would share a salt, reopening multi-target attacks). Hedged
  derivation still carries fresh randomness, so the channel survives. Squeezing
  it out entirely means deterministic encryption (SIV-style), which costs the
  randomised-encryption properties the rest of the design rests on.

  So this is stated as an **irreducible consequence, not a to-do**: any format
  with public random fields has this channel, and the defence is not a test but
  the **provenance of the binary** — reproducible builds byte-for-byte, signed
  releases, `cargo-vet`. It is the same reason the S2 note says a subverted RNG
  is undetectable: these are one attack wearing two hats.

Out of the adversary model (see §5): an attacker with access to memory **during**
the operation, a local physical side channel, or control of the binary/OS.

## 3. Trust assumptions

- **S1.** The vetted primitives are secure: XChaCha20-Poly1305, Argon2id,
  HKDF-SHA256, X25519, ML-KEM-1024 (FIPS-203), ristretto255.
- **S2.** The system RNG (getrandom/OsRng) is cryptographically secure.
  - **Partially VERIFIED since 2026-08-01, and the split matters.** Every draw
    goes through `aleatorio::llenar`, the single choke point, and is subjected to
    **continuous health tests** — not a one-off check at startup, because a
    source can degrade *after* boot (a `seccomp` filter that tightens, a VM
    migration). Output that fails is **wiped, reported, and NOT retried**: the
    same broken source may hand back something that *looks* fine next time.
  - **What that catches:** sources that are broken and look like they work — a
    `seccomp` filter returning success without touching the buffer, a badly
    emulated `chroot` without `/dev/urandom`, an embedded target or WASM shim
    returning constants. Deterministic deployment failures, so they show up every
    time. Verified by poisoning the source: 4 red tests in `aleatorio`, 5 in
    `selftest`.
  - **What it does NOT catch, and this is the honest half:** a *subverted but
    statistically sound* generator passes every one of these tests — and would
    pass monobit, runs, and any battery added later. That is the definition of a
    good PRNG seeded by somebody else. No output test can detect it; the defence
    is **provenance of the binary** (reproducible build, signed release), not a
    test on the bytes. Claiming otherwise would manufacture the same false sense
    of coverage as antivirus software pointed at the wrong layer.
  - So S2 remains an assumption **about the source's honesty**, and is now a
    verified property **about the source's function**.
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

**Visual channel (PNG) and ECC — REMOVED, kept here as a tombstone:**
- **This channel no longer exists.** The PNG carrier and the native glyph
  renderer were deleted in PR #93/#99; there is no module for either in `src/`
  or `crates/`. Whatever this section guaranteed, it guarantees about nothing.
- Kept as a marker rather than deleted because a security document that silently
  loses a section leaves an auditor unable to tell "removed" from "never
  reviewed". What replaced it is the **paper carrier**: standard symbology (QR)
  plus a typeable layer, with the payload in `quipu_nucleo::papel`. Its
  guarantees are availability, not confidentiality — the payload is ciphertext,
  so a broken encoder can only produce an unreadable sheet, never leak a key.
- The `ecc` module survives, and the reason is in its own header: it is what the
  paper carrier needs. Its hostile-input limits are documented at
  `ecc::PARIDAD_MAXIMA`.

## 5. Non-goals (out of scope)

- **N1a. Which modes actually apply Padmé — measured 2026-08-01, because N1's
  wording was wider than the code.** N1 states length hiding as a library-wide
  mitigation. It is not: `prelayers::pad` is applied by the symmetric and hybrid
  container paths only. **`QST1` (streaming), `QSG1` and `QSG3` (signed) never
  call it**, and for `QST1` the leak is not approximate but *exact* — an
  independent review reconstructed the original size to the byte, 10 out of 10,
  from the file size and the `chunk_size` that travels in clear in the header.
  That is the mode used for large data at rest, which is where size matters most.
  And where Padmé *is* applied, the honest number: it pins the true length inside
  a **±0.8 % window** across the whole range, leaving only **422 observable file
  sizes between 0 and 16 MiB**. At the small end it degenerates — a payload of
  1–24 B shares its file size with just **2** lengths, 25–56 B with 4. The small
  end is Quipu's showcase (a key, a PIN, a mnemonic), so a 12-word phrase and a
  24-word one are told apart by the file size alone.
  None of this contradicts N1 — hiding size is a declared non-goal. What was
  wrong is that N1 named a mitigation without its scope or its magnitude, and a
  reader concluded coverage that is not there.
- **N1.** Hiding the EXISTENCE or exact SIZE of the message. Size is mitigated with
  Padmé padding (approximate length hiding), not full steganography.
- **N2.** Protecting against an adversary controlling the machine DURING the
  operation (malware with live RAM access, keylogger, trojaned binary).
- **N3.** Local **physical** side channels (power, EM, probing). Constant-time
  comparison is used where applicable, but it is not the goal.
- **N3b. Microarchitectural side channels from a CO-TENANT** — and this was a
  HOLE, not a limit (found 2026-08-01). N3 used to read "local *physical* side
  channels (fine timing, power, EM)", which quietly excluded the case that
  actually applies: a process or VM sharing hardware, mounting a cache-timing
  attack. That adversary is neither physical nor a network observer, so it fell
  between the categories — covered by nothing, declared by nothing.
  It is not hypothetical here. **Argon2id is deliberately data-dependent in its
  second half** (that is the `id` trade-off: resistance to GPU/TMTO at the cost of
  some cache-timing exposure), and `quipu-oprf-server` runs on a VPS, which is
  shared hardware by definition.
  Status: **out of scope, but now by DECISION rather than by omission.** Closing
  it would mean Argon2**i** (weaker against the attacker who matters more here,
  T3 with compute) or dedicated hardware. The honest mitigation is deployment-side
  — dedicated instances for anything deriving keys from a passphrase — and it is
  named here so that whoever deploys can weigh it.
- **N10. Traffic analysis of the online mode** (added 2026-08-01). The VOPRF
  exchange is **32 bytes out, 97 bytes in, always** (`SPEC.md` §8.2), and
  `decode_online` performs it exactly as `encode_online` does. A passive network
  observer therefore learns, per host and in real time, **when a file is
  encrypted and when a file is OPENED** — not which file, not its content, but
  the timeline. TLS hides the content and not the record sizes.
  Out of scope. **And padding is not the answer**: the sizes are already
  constant and published, so padding to a different constant is still a
  constant. What betrays is the pattern and its timing; hiding that needs cover
  traffic or batching, which is a different product. Offering padding would be
  the appearance of a fix — the exact defect this document keeps finding
  elsewhere.
  §4 says the server "participates without seeing the passphrase or the result",
  which is true and says nothing about who else sees **that it participated**.
  Anyone whose threat model includes when-you-opened-a-file uses the offline mode
  with a pepper.
- **N9. Linkability of containers by their CONFIGURATION** (added 2026-08-01,
  after an independent review; measured independently before writing this).
  A Quipu container announces itself as one — the `QUIP` magic is deliberate, and
  Kerckhoffs governs this project: the format is public. Asking the symmetric
  mode for indistinguishability would be asking for a property only `negacion`
  promises, and `negacion` pays for it with a price the normal modes must not pay
  (no magic, no version, KDF parameters outside the file).
  So this is a **non-goal — but one that was neither promised nor ruled out, and
  that is the dangerous category.** With its magnitude, so nobody has to guess:
  - **The key links NOTHING.** Measured over 1 000 containers under one
    passphrase: 1 000 distinct salts, 1 000 distinct nonces. This is a *security*
    property and it must never regress. Pinned by
    `la_clave_no_enlaza_y_la_configuracion_enlaza_exactamente_lo_declarado`.
  - **The configuration links 28 bytes**, identical across every container the
    same author writes: `[0..16)` = magic(4) ‖ version(1) ‖ flags(1) ‖
    `codebook_id`(2) ‖ codebook fingerprint(8), and `[56..68)` = the three KDF
    parameters.
  - **For the common case those 28 bytes are a world constant.** `ascii94`,
    `KdfParams::default()`, `codebook_id: 0` — what the Python wheel does — is
    byte-identical for every Quipu user on earth. It says "a Quipu file", not
    "your Quipu file".
  - **Customising is where it turns into a pseudonym, and the alphabet
    fingerprint is INVERTIBLE.** Measured: the exact alphabet was recovered by
    brute force from its 8-byte fingerprint in **46.8 ms** over 5 120 candidates,
    sweeping `dictionaries::from_range`, the constructor the library itself
    offers. Not a weakness of the hash — the *space* of alphabets is small and
    enumerable. Pinned by `la_huella_del_alfabeto_se_invierte_por_fuerza_bruta`.
  - **Who this matters to:** whoever customises is precisely the security-minded
    user, and the API invites it — `kdf_params` is documented as "adjustable
    difficulty", `codebook_id` as a public "informational" field. Anyone whose
    threat model includes a seized or leaked corpus of mixed provenance should
    stay on the defaults, where the fields are a world constant.
  - **If this ever becomes a goal**, the path is not encryption — the symmetric
    mode needs the KDF parameters *before* it can derive the key that would
    decrypt them. It is (a) **canonical KDF profiles**: one byte selecting from a
    public ladder instead of 12 bytes of arbitrary configuration, the same shape
    as `negacion::tamano_canonico`; and (b) a **keyed codebook fingerprint**
    (`HMAC(master_key, alphabet)` instead of truncated SHA-256), which kills both
    the invertibility and the linkability of those 8 bytes at the cost of paying
    one Argon2id before "wrong alphabet" can be reported. Both break the format,
    so they belong to the next format break, together.
- **N8. Key commitment / partitioning oracles** (added 2026-08-01, after an
  independent review). XChaCha20-Poly1305 is **not key-committing**: a ciphertext
  that validates under two distinct keys is constructible (Len–Grubbs–Ristenpart,
  2021). Out of scope, for two different reasons that must not be merged:
  - **In the core modes**, because a partitioning oracle requires repeated,
    adaptive decryption of attacker-supplied input with the victim's secret,
    leaking whether it worked. Quipu has no such surface, and the failure of
    `decode` collapses "wrong passphrase" and "tampered container" into one error
    with no timing difference that depends on the passphrase.
  - **In `negacion`, because the absence of commitment is a REQUIREMENT, not a
    defect.** A key-committing AEAD would be precisely the field that says "this
    region opened with THIS key" — the field the whole format exists not to have.
    Hardening it there would break deniability. The operational invariant that
    keeps this true is written next to the code: **`negacion::abrir` must never
    be exposed as a service that decrypts other people's containers.** That day
    the oracle is born.
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
- **R2. The OPRF server is a single point**, and it has two halves that must not
  be confused. Corrected 2026-08-01: only the first was written down, and the
  mitigation named for it did not exist.
  - **Availability half:** downtime blocks online decryption; **losing** the key
    makes those secrets unrecoverable for ever. Mitigated by `quipu::shamir`,
    which splits the key into k-of-n shares held separately, so no single
    custodian can recover it and no single loss destroys it.
  - **Confidentiality half — named in A5, absent HERE, and the worse one.** The
    distinction matters and is the lesson of this correction: A5 already said
    that theft of the key "enables offline dictionary attacks", but A5 is the
    asset list. **R2 is where the mitigation is prescribed**, and R2 spoke only
    of loss. A consequence listed among the assets and missing from the residual
    risk is a consequence nobody plans for. Concretely: an attacker
    who **steals** `k` can evaluate the OPRF offline, without ever talking to the
    server, for **every container ever hardened — past and future**. That removes
    the rate limit, and the rate limit is the entire reason the online mode
    exists (see the README: Argon2id makes each guess expensive, only the VOPRF
    caps how many there are). The victim is returned to T3, offline guessing,
    with no signal that it happened.
  - **AND THE STATED MITIGATION WAS FICTION.** This entry used to prescribe
    "planned rotation". The project rule forbids it in as many words — `CLAUDE.md`
    and the README both say the domain and key `k` **never rotate**, because
    rotating invalidates everything derived from them. So there is no recovery
    from theft of `k`: it is permanent and retroactive by construction. Naming a
    mitigation that cannot be performed is worse than naming none, because it
    closes the question.
  - What this actually demands is **prevention, not recovery**: the key in an HSM
    (feature `hsm`), custody split (`escrow`), and treating any suspicion of
    compromise as the end of life of that OPRF domain — a new domain, and every
    container hardened under the old one re-encrypted.
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

**This table had drifted**: it stopped at T6 while the adversary list has run to
T9 since 2026-07-26. A traceability table that does not track the list it traces
is worse than none — it reads as coverage. Completed 2026-08-01.

| Adversary | Mitigation |
|-----------|-----------|
| T1 | AEAD (XChaCha20-Poly1305); public representation with no secret value. |
| T1b | **None for `negacion`** — deniability does not survive a second look at the same container. The other modes are unaffected: their guarantee never depended on the adversary seeing the file once. Deployment-side only: no versioned backup, no cloud sync, and be aware that an SSD keeps the old copy whatever you do. |
| T2 | Header as AAD; `is_sane` validation of KDF params; parsing guards. |
| T3 | Argon2id (memory-hard) + pepper; online mode with rate limiting. **Argon2id raises the price of each guess; only the VOPRF caps how many there are — and that cap is classical: see T5.** |
| T4 | VOPRF with DLEQ proof verified against a pinned public key (F1). |
| T5 | Hybrid KEM X25519 + ML-KEM-1024 (F2, transcript with bound ek), hybrid signature Ed25519 + ML-DSA-87 — both hold. **NONE for the VOPRF hardening**: ristretto255 is classical, its public key is published by design, and Shor on it removes the rate limit retroactively for every container ever hardened. No practical PQ OPRF exists to swap in. Mitigate by *also* using a pepper, the only factor that survives T5. |
| T6 | Best-effort zeroization of sensitive material (partial; see R3), plus `limpiar_pila` for reconstructed material, measured in `tests/residuo_memoria.rs` in both debug and release. |
| T7 | Not cryptographic and not solvable here: least privilege, encryption at rest so exfiltration is worthless (R8), and the operational hardening of `quipu-oprf-server`. This is the adversary every real incident studied in §10 actually was. |
| T8 | Asymmetry of the admin operations: closing is cheap and reversible, reopening is **not available at all**. Never the requester's word; always the payment record. |
| T9 | Reproducible builds and signed releases so a fix can be verified when it does arrive; no mitigation for the takedown itself. |
| T10 | Reproducible build byte-for-byte enforced in CI (I5), `cargo-vet` provenance gating, signed releases, and boot self-test KATs that a substituted primitive cannot pass. **No mitigation** against a subverted-but-statistically-sound RNG — provenance is the only defence (S2). |

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
