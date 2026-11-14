# Quipu — Technical Specification

**Covers the container formats as of v0.15.1 (unchanged since v0.15.0) · updated 2026-11-06**

> The banner said *«through v0.6.0»* until 2026-08-05, while the crate was at
> 0.11.0 and §§7–11 of this very document already covered the hybrid PQ mode, the
> VOPRF, hybrid signatures, streaming and honey encryption. What was stale was the
> banner, never the body — but a reader arriving from docs.rs reads the banner
> first, so it was the one line able to make the whole spec look abandoned.
>
> **Scope, stated so it can be checked**: the **six** wire formats specified here
> are `QUIP` (§3.2), `QPQ1` (§7.3), `QSG1` (§9.3), `QSG3` (§9.4), `QST1` (§10)
> and `QHNY` (§11). The deniable mode (opt-in feature `negacion`) introduces
> **no new format** — it reuses the `QUIP` container, and its threat model and
> design live in [`DISENO_NEGACION.md`](DISENO_NEGACION.md).

> ⚠️ This spec is **descriptive of the current implementation**, not a frozen wire
> standard. Formats may change before v1.0. It is intended for auditors and for
> anyone reimplementing or interoperating with Quipu. Where this document and the
> source disagree, the source is authoritative — please file an issue.
>
> **Machine-readable known-answer vectors:** [`tests/vectors/quipu_vectors.json`](../tests/vectors/quipu_vectors.json)
> (regenerate with `cargo run --example gen_vectors --features honey`; checked by
> [`tests/vectors.rs`](../tests/vectors.rs)). See §14.

All multi-byte integers are **big-endian** unless stated otherwise.

## 1. Overview

Quipu protects data with an authenticated encryption pipeline and then renders the
resulting bytes in a chosen representation (dense text over a public
alphabet). Security
lives in the keys and the vetted primitives; the representation is public
(Kerckhoffs).

```
plaintext
  → Padmé padding                      (§4)
  → AEAD encrypt (XChaCha20-Poly1305)  (§3), AAD = header
  → container = header ‖ ciphertext    (§2)
  → base-N codec → symbol indices      (§5)
  → dictionary rendering (§6)
```

## 2. Primitives

| Role | Primitive | Crate |
|------|-----------|-------|
| AEAD | XChaCha20-Poly1305 (256-bit key, 192-bit nonce, 128-bit tag) | `chacha20poly1305` |
| Password hashing | Argon2id (v0x13) | `argon2` |
| KDF | HKDF-SHA256 | `hkdf` |
| Hash | SHA-256, SHA-512 | `sha2` |
| Classical KEM/DH | X25519 | `x25519-dalek` |
| Post-quantum KEM | ML-KEM-1024 (FIPS-203) | `ml-kem` |
| Classical signature | Ed25519 (EdDSA) | `ed25519-dalek` |
| Post-quantum signature | ML-DSA-87 (FIPS-204) | `ml-dsa` |
| OPRF group | ristretto255 | `curve25519-dalek` |
| Normalization | Unicode NFKC | `unicode-normalization` |

**CNSA 2.0.** The post-quantum choices above (ML-KEM-1024, ML-DSA-87) match the
CNSA 2.0 suite; the symmetric ones deliberately do not — CNSA 2.0 mandates
AES-256 and SHA-384/512. The reasoning, the cost of a compliant profile, and the
conditions under which it would be built are in [CNSA.md](CNSA.md). Short
version: ChaCha20 is constant-time by construction on any CPU, AES is not
without hardware acceleration, and algorithm alignment is not the same thing as
FIPS validation.

## 3. Symmetric mode

### 3.1 Key derivation

```
normalized = NFKC(passphrase)                       # Unicode normalization
secret     = utf8(normalized) ‖ pepper              # pepper may be empty
master(32) = Argon2id(password = secret,
                      salt = salt(16),
                      m = kdf_mem_kib, t = kdf_iterations, p = kdf_parallelism,
                      out_len = 32, version = 0x13)
cipher_key(32) = HKDF-SHA256(ikm = master, salt = none,
                             info = "quipu/v1/cipher")
```

`master` and the intermediate `secret` are zeroized after use.

**KDF parameter bounds** (rejected before deriving, to prevent DoS from a tampered
header): `1 ≤ parallelism ≤ 16`, `1 ≤ iterations ≤ 16`, `8·parallelism ≤ mem_kib ≤
262 144` (**256 MiB**). Corrected 2026-08-01: this said 1 048 576 (1 GiB), the
old bound. The code has held 256 MiB since the anti-amplification work — the
reasoning is at `kdf.rs`, `MAX_MEM_KIB` — and a spec quoting the looser bound
would have an implementer accept headers the reference rejects.
Defaults: `mem_kib = 65536` (64 MiB), `iterations = 3`,
`parallelism = 1`.

### 3.2 Container format

Fixed 68-byte header, followed by the AEAD output (ciphertext ‖ 16-byte tag):

| Offset | Size | Field |
|-------:|-----:|-------|
| 0  | 4  | magic = `"QUIP"` (0x51 0x55 0x49 0x50) |
| 4  | 1  | version = `1` |
| 5  | 1  | flags (bit 0 = `blindaje`; all other bits MUST be 0) |
| 6  | 2  | codebook_id (**RESERVED, deprecated — write 0**) |
| 8  | 8  | codebook_hash_prefix (first 8 bytes of the dictionary fingerprint) |
| 16 | 16 | salt |
| 32 | 24 | nonce (XChaCha20) |
| 56 | 4  | kdf_mem_kib |
| 60 | 4  | kdf_iterations |
| 64 | 4  | kdf_parallelism |
| 68 | …  | AEAD ciphertext ‖ tag |

The **entire 68-byte header is the AEAD Associated Data (AAD)**. Any alteration of
version, codebook_id, salt, nonce, or KDF parameters causes decryption to fail.

> **`flags` and `codebook_id` — reserved fields, and they are handled
> differently on purpose (2026-08-01).**
>
> **`flags` (offset 5) is VALIDATED: any UNKNOWN bit is REJECTED**
> (`ContainerError::FlagsDesconocidos`).
>
> *Updated 2026-08-17.* This paragraph said "a non-zero value is rejected", and
> that stopped being true on 2026-08-16: **bit 0 means `blindaje`**, the blind
> split, and a decoder built with that feature accepts it. It is the first bit of
> `flags` ever used. A decoder without the feature returns
> `DecodeError::ModoNoCompilado` — it refuses, it does not guess, which is what
> the rest of this note is about. **The body format of a container with bit 0 set
> (`QBL2`) is NOT specified in this document**, so this specification is not yet
> sufficient to write an interoperable decoder for that mode; see
> `src/blindaje.rs`. This is not tidiness — it closes a
> **silent downgrade**. The header travels as AAD, so a future container with
> `flags = 1` authenticates perfectly against an old decoder; if that decoder
> *ignored* the field it would interpret the payload under the old rules and
> return misread data **with the AEAD green**, which is the worst possible
> outcome: a failure nobody notices. Same reason TLS is strict about unknown
> extensions. An old decoder must refuse, not guess.
>
> **`codebook_id` (offset 6) is NOT rejected**, and the asymmetry is deliberate.
> It has been public and settable through `Options` since 0.10.0, so refusing a
> non-zero value would render **permanently unreadable** any container somebody
> already built with it — orphaned data, no recovery, in exchange for tidiness.
> It is marked deprecated with its reason and removed at the next format break,
> once nothing writes it any more.
>
> This entry used to call the field *"informational"*, and that word is what
> turned a format reservation into an invitation to store a tenant, user or
> document identifier there — 16 bits of cleartext metadata, chosen by the
> encryptor and stable across every container they write (see N9 in the threat
> model).

### 3.3 Encryption

```
padded     = Padme_pad(plaintext)                   # §4
ciphertext = XChaCha20Poly1305_Seal(key = cipher_key,
                                    nonce = nonce,
                                    aad = header_bytes(68),
                                    plaintext = padded)
blob       = header_bytes ‖ ciphertext
```

Decryption reverses this: parse header (validate magic + version), re-derive
`cipher_key`, AEAD-open with the header as AAD, then `Padme_unpad`.

## 4. Padmé padding (length hiding)

Reversible padding that quantizes length so ciphertext size leaks minimally
(Nikitin et al., PURBs; overhead < ~13%).

Block layout: `[ len : u64 big-endian (8 bytes) | data | zero bytes up to
padme(8 + len(data)) ]`.

```
padme(l):
    if l < 2: return l
    e = floor(log2(l))                 # position of the top set bit
    s = bit_length(e)
    last_bits = e - s                  # saturating (>= 0)
    mask = (1 << last_bits) - 1
    return (l + mask) & ~mask          # round up, clearing low bits
```

## 5. Base-N codec

Maps the container bytes to a sequence of symbol indices in `[0, N)`.

```
encode(data, N):
    buf    = 0x01 ‖ data               # leading marker preserves leading zeros / empty
    value  = big-endian integer of buf
    digits = base-N representation of value, most-significant digit first
    return digits                      # each digit is a symbol index

decode(indices, N):
    value = Σ indices[i] · N^(len-1-i)
    bytes = big-endian bytes of value
    return bytes[1:]                   # strip the 0x01 marker
```

The index **is** the symbol's binary value (positional encoding); the dictionary
only maps index → symbol identity.

## 6. Representation layer

- **Dictionary:** an ordered set of `N` symbols. `ascii94()` (N = 94),
  `flagship()` (N = 4096 CJK glyphs, ~12 bits/symbol), or `from_range(start,
  count)`. The dictionary "fingerprint" is the first 8 bytes of SHA-256 over its
  symbols, stored in the header for mismatch detection.
> **Removed 2026-08-01.** This section also listed **PNG**, **Robust PNG** and
> **Native glyphs** as representation layers. All three were deleted in PR
> #93/#99 and no module for them exists in the tree. A specification that
> describes carriers the software does not have is the exact defect that made
> the README announce Node/Go/C-ABI bindings months after they were removed.
>
> What exists instead is the **paper carrier** (`quipu_nucleo::papel`): standard
> symbology — QR, so any phone reads it — plus a typeable layer with three
> framings (bare Base32, Base32 + Reed-Solomon, and BIP-39 words). The reason it
> is standard symbology and not our own alphabet is custody, not aesthetics:
> what decides at twenty years is that the decoder exists in 2050.

## 7. Hybrid post-quantum mode (asymmetric)

Encrypts to a recipient's hybrid public key. No passphrase; the content key comes
from the KEM.

### 7.1 Keys and sizes

| Item | Size (bytes) |
|------|-------------:|
| X25519 public | 32 |
| ML-KEM-1024 encapsulation key (ek) | 1568 |
| ML-KEM-1024 ciphertext (ct) | 1568 |
| Hybrid public key (X25519 pub ‖ ek) | 1600 |
| Encapsulation (eph X25519 pub ‖ ct) | 1600 |
| ML-KEM-1024 decapsulation key **seed** | 64 |
| Hybrid secret key (X25519 secret ‖ dk seed) | **96** |

> **Secret-key serialization changed in 0.9.0.** Up to and including 0.8.0 the
> decapsulation key was stored in its *expanded* form (3168 bytes), making the
> hybrid secret key 3200 bytes. `ml-kem` 0.3 stores the 64-byte **seed** it is
> derived from and deprecated the expanded form, so the hybrid secret key is now
> 96 bytes.
>
> **Both are read; only the new one is written.** `SecretKey::from_bytes`
> accepts either length — 96 or 3200 — and `to_bytes` always emits 96, so any
> key that passes through is migrated. A secret key is the one thing a user
> cannot regenerate: losing it loses everything encrypted to it, so breaking it
> silently was not an option. Public keys, ciphertexts and the symmetric
> container are **unchanged** (`tests/vectors.rs` still passes byte-for-byte).

### 7.2 Encapsulation and key combination

```
eph            = X25519 ephemeral secret;  eph_pub = X25519(eph)
x_ss(32)       = X25519(eph, recipient_x_pub)
(ml_ct, ml_ss) = MLKEM1024.Encaps(recipient_ek)         # ml_ss is 32 bytes
encapsulation  = eph_pub(32) ‖ ml_ct(1568)

transcript     = recipient_x_pub(32) ‖ recipient_ek(1568) ‖ encapsulation(1600)
content_key(32)= HKDF-SHA256(ikm = x_ss ‖ ml_ss, salt = none,
                             info = "quipu/v2/hybrid-kem" ‖ transcript)
```

Binding the recipient's **full** public key (X25519 + ek) is X-Wing style and
prevents public-key-substitution / re-encapsulation attacks. On decapsulation the
recipient recomputes `ek` from its decapsulation key. Breaking `content_key`
requires breaking **both** X25519 and ML-KEM-1024.

> **X-Wing *style*, not interoperable X-Wing.** This follows the X-Wing design
> principle (bind both shared secrets and the public material through a KDF), but
> it is NOT wire-compatible with `draft-connolly-cfrg-xwing-kem` (checked against
> **draft-10**, 2026-03-02, *Informational* — no IETF standards standing). X-Wing
> is defined over ML-KEM-**768** with a single SHA3-256 combiner:
>
> ```
> X-Wing:  ss = SHA3-256( ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ 5c2e2f2f5e5c )   # 32-byte label "\.//^\"
> Quipu :  content_key = HKDF-SHA256( ikm = x_ss ‖ ml_ss,
>                                     info = "quipu/v2/hybrid-kem" ‖ transcript )
> ```
>
> Quipu uses ML-KEM-**1024** (CNSA 2.0, NIST level 5) and `HKDF-SHA256`, and
> additionally binds the ML-KEM `ek`/`ct` in the transcript. Deliberate: the
> parameter set is driven by CNSA 2.0, not interop. A wire-compatible
> **X-Wing-768** profile is tracked separately (see `docs/ESTANDARES-2026-08.md`).

### 7.3 Container

```
header = "QPQ1"(4) ‖ version=1 (1) ‖ flags=0 (1) ‖ nonce(24) ‖ encapsulation(1600)
blob   = header ‖ XChaCha20Poly1305_Seal(content_key, nonce, aad = header, padded_plaintext)
```

`blob` is then base-N encoded and rendered like the symmetric mode.

## 8. Verifiable OPRF (online hardening)

A verifiable OPRF lets a server help harden a passphrase without seeing it, and
lets the client verify the server used the expected key. Quipu implements
**RFC 9497** with the **`ristretto255-SHA512`** ciphersuite in **VOPRF mode**
(`crates/quipu-voprf/src/rfc9497.rs`). The RFC is the normative reference; this
section records the choices Quipu pins and how the mode wires into the rest of
the product. Conformance is checked against the RFC's own Appendix A.1.2 vectors
in `crates/quipu-voprf/tests/rfc9497_vectors.rs`. `G` is the ristretto255
basepoint and ℓ its prime order.

> **This replaced a proprietary construction (removed 2026-08-17).** The earlier
> mode used a private domain string, a `hash_to_curve` without
> `expand_message_xmd`, a home-grown DLEQ transcript and a 32-byte truncated
> output. It was *inspired by* the RFC but not conformant: it interoperated with
> nothing and inherited none of the RFC's security analysis. The switch **breaks
> the wire format** — the ciphersuite is baked into every hardened secret and,
> like the key `k`, never rotates — and was done while there were zero clients,
> the only possible window.

Everything below is domain-separated by one context string (RFC §3.1):

```
mode          = 0x01                      # VOPRF (verifiable)
contextString = "OPRFV1-" ‖ I2OSP(0x01, 1) ‖ "-ristretto255-SHA512"
              = "OPRFV1-\x01-ristretto255-SHA512"
```

Each hash below carries its own DST built from that string, so no two uses of
SHA-512 collide (RFC §3.1, §4.1). `expand_message_xmd` is RFC 9380 §5.3.1 over
SHA-512 with `len_in_bytes = 64`:

| Primitive | DST | Construction |
|---|---|---|
| `HashToGroup` | `"HashToGroup-" ‖ contextString` | `hash_to_ristretto255` over `expand_message_xmd` (64 uniform bytes → `from_uniform_bytes`) |
| `HashToScalar` | `"HashToScalar-" ‖ contextString` | 64 uniform bytes read little-endian, reduced mod ℓ |
| `DeriveKeyPair` | `"DeriveKeyPair" ‖ contextString` | **no trailing hyphen** — the RFC spells this one without it; getting it wrong derives a different key silently |
| composites seed | `"Seed-" ‖ contextString` | seeds the batched-proof composite scalars (§8.1) |

Server key and public key (RFC §3.2, `DeriveKeyPair`):

```
DeriveKeyPair(seed, info):
    for counter in 0..=255:
        k = HashToScalar( seed ‖ I2OSP(len(info),2) ‖ info ‖ I2OSP(counter,1),
                          DST = "DeriveKeyPair" ‖ contextString )
        if k ≠ 0: return k                 # else DeriveKeyPairError
pkS = k · G                                # public key; pin on client
```

Protocol (RFC §3.3.2), batch size 1:

```
Blind(pw):        P = HashToGroup(pw);  abort if P = identity   (InvalidInputError)
                  r ← random scalar;  B = r · P;  send B (32B compressed)

BlindEvaluate(B): abort if B decodes to identity                (server rejects it)
                  Z = k · B
                  proof = GenerateProof(k, G, pkS, B, Z)         # DLEQ, §8.1
                  send Z(32) ‖ proof(64)

Finalize(pw,r,Z,proof):
                  verify proof against the pinned pkS; abort on failure
                  N = r⁻¹ · Z                                    # = k · HashToGroup(pw)
                  output = SHA-512( I2OSP(len(pw),2) ‖ pw ‖ I2OSP(32,2) ‖ N ‖ "Finalize" )
                  # 64 bytes, NOT truncated
```

`output` (64 bytes) is then used as, or mixed into, the pepper / hardening input
of the symmetric mode.

### 8.1 DLEQ proof (RFC §2.2)

`GenerateProof`/`VerifyProof` prove `log_G(pkS) = log_B(Z) = k` without revealing
`k`. Quipu uses the batched form (§2.2.1) with a single element, so the composite
collapses to one pair: `A = G`, `B = pkS`, `C =` the blinded element, `D = Z`.

```
ComputeComposites(pkS, [C], [D]):                                # §2.2.1
    seed = SHA-512( I2OSP(32,2) ‖ pkS ‖ I2OSP(len,2) ‖ "Seed-"‖contextString )
    d_0  = HashToScalar( I2OSP(64,2) ‖ seed ‖ I2OSP(0,2)
                         ‖ I2OSP(32,2) ‖ C ‖ I2OSP(32,2) ‖ D ‖ "Composite" )
    M = d_0 · C ;  Z = d_0 · D            # server's Fast variant instead sets Z = k · M

GenerateProof(k, …):                                             # §2.2.1
    r ← random scalar
    t2 = r · G ;  t3 = r · M
    c  = challenge(pkS, M, Z, t2, t3)
    s  = r − c · k
    return c(32) ‖ s(32)                  # 64 bytes

VerifyProof(pkS, C, D, c ‖ s):                                   # §2.2.2
    (M, Z) = ComputeComposites(pkS, [C], [D])
    t2 = s · G + c · pkS
    t3 = s · M + c · Z
    return challenge(pkS, M, Z, t2, t3) == c

challenge(pkS, M, Z, t2, t3) =                                   # challengeTranscript, §2.2.1
    HashToScalar( I2OSP(32,2)‖pkS ‖ I2OSP(32,2)‖M ‖ I2OSP(32,2)‖Z
                  ‖ I2OSP(32,2)‖t2 ‖ I2OSP(32,2)‖t3 ‖ "Challenge" )
```

The trailing `"Composite"`, `"Challenge"` and `"Finalize"` labels carry **no
length prefix** — that is what the RFC specifies (§2.2.1, §3.3.2), and adding one
would change the scalar. All points are 32-byte compressed ristretto255
encodings; both scalars in a proof must be canonical little-endian, or
verification fails.

### 8.2 Online wire protocol

Minimal TCP protocol (put behind TLS in production):

> **TLS hides the content, not the sizes — and here the sizes are a signature
> (2026-08-01).** The exchange below is **32 bytes out, 97 bytes in, always**,
> and `decode_online` performs it exactly like `encode_online` does. So a passive
> network observer — an ISP, a corporate proxy, anyone on the same network —
> learns, per host and in real time, **when a file is encrypted and when a file
> is OPENED**. Not which file, not its content: the timeline.
>
> **Padding is not the answer, and saying so matters.** The sizes are *already*
> constant, and published right here; padding to a different constant is still a
> constant. What betrays is the pattern and its timing, so hiding it would take
> cover traffic or batching — a different product, not a bigger buffer. Offering
> padding would be the appearance of a fix.
>
> This is declared, not mitigated. §4 of the threat model says the server
> "participates without seeing the passphrase or the result", and that is true —
> it says nothing about who else sees **that it participated**. Anyone whose
> threat model includes when-you-opened-a-file should use the offline mode with
> a pepper.

```
client → server:  B                       (32 bytes, blinded point)
server → client:  status(1) ‖ Z(32) ‖ proof(64)   (97 bytes; status 1 = ok, 0 = denied)
```

Rate limiting (e.g. per-IP) is the caller's responsibility.

## 9. Hybrid signature mode (asymmetric authenticity)

Signs a message with a hybrid key so that anyone holding the verifying key can
check authorship and integrity. This mode provides **authenticity, integrity and
non-repudiation**, publicly verifiable — but **not confidentiality** (the signed
container is plaintext). It fits data-at-rest artifacts: signed documents,
backups, releases.

### 9.1 Keys and sizes

| Item | Primitive | Size (bytes) |
|------|-----------|-------------:|
| Ed25519 verifying key | Ed25519 | 32 |
| ML-DSA-87 verifying key | ML-DSA-87 (FIPS-204) | 2592 |
| Hybrid verifying key (Ed25519 ‖ ML-DSA vk) | — | 2624 |
| Ed25519 seed / ML-DSA seed | — | 32 / 32 |
| Hybrid signing key (Ed25519 seed ‖ ML-DSA seed) | — | 64 |
| Ed25519 signature | Ed25519 | 64 |
| ML-DSA-87 signature | ML-DSA-87 | 4627 |
| Hybrid signature (Ed25519 ‖ ML-DSA) | — | 4691 |

Both signing keys are stored as their 32-byte seeds and re-expanded on use; the
seed material is zeroized on drop.

### 9.2 Signing and verification

> **Corrected 2026-08-01.** This section specified **ML-DSA-65** — NIST level 3 —
> with its sizes (1984 / 3309 / 3373), while §9.1 fourteen lines above, the code,
> and the entire product claim say **ML-DSA-87**, level 5, the one CNSA 2.0
> requires. Leftovers from an earlier version that were never migrated.
>
> This document says the source wins where they disagree, and that clause only
> helps whoever *notices* the disagreement: §9.1 (table) and §9.2 (pseudocode)
> read as complementary, not contradictory, so nobody goes looking. Anyone
> reimplementing a verifier from the normative section would have built one at
> level 3 — and it would not interoperate either, because the preimage binds a
> verifying key of a different length.

```
preimage = "quipu/v3/sign" ‖ verifying_key(2624) ‖ message
σ_ed     = Ed25519.Sign(sk_ed, preimage)            # 64 B, deterministic
σ_ml     = MLDSA87.Sign(sk_ml, preimage)            # 4627 B, deterministic (empty ctx)
signature = σ_ed(64) ‖ σ_ml(4627)                   # 4691 B

verify(vk, message, signature):
    preimage = "quipu/v3/sign" ‖ vk ‖ message
    return Ed25519.VerifyStrict(vk_ed, preimage, σ_ed)   # rejects small-order / malleable
           AND MLDSA87.Verify(vk_ml, preimage, σ_ml)     # AND-combiner
```

Binding the **full** verifying key (both components) and a domain label into the
signed preimage prevents weak key-substitution and cross-component mixing (a
component signature cannot be reused under a different keypair). The **AND**
combiner (both must verify) makes the hybrid signature unforgeable as long as **at
least one** of Ed25519 / ML-DSA-87 remains unforgeable.

### 9.3 Signed container

```
blob = "QSG1"(4) ‖ version=1 (1) ‖ flags=0 (1) ‖ msg_len(u32 BE, 4)
       ‖ message(msg_len) ‖ signature(4691)
```

`blob` is base-N encoded and rendered like the other modes. On decode the message
is returned **only** if the signature verifies against the caller-pinned verifying
key.

### 9.4 Triple-hybrid variant (`QSG3`, opt-in feature `slh`)

A high-assurance variant adds a third family: **SLH-DSA-SHA2-256s** (FIPS-205,
stateless hash-based) with an **AND 3-of-3** combiner — the signature verifies
only if Ed25519 **and** ML-DSA-87 **and** SLH-DSA all verify, so it stays
unforgeable as long as ≥1 of {elliptic-curve, lattice, hash} survives. The
container magic is `"QSG3"`. SLH-DSA signatures are large (~29 KB), so the mode
is opt-in; the double-hybrid `QSG1` artifacts are unchanged.

## 10. Streaming AEAD (`QST1`)

STREAM construction (Tink-inspired) for large data-at-rest in bounded memory. A
57-byte header, then a sequence of AEAD chunks:

| Offset | Size | Field |
|-------:|-----:|-------|
| 0  | 4  | magic = `"QST1"` (0x51 0x53 0x54 0x31) |
| 4  | 1  | version = `1` |
| 5  | 1  | flags (`0`) |
| 6  | 4  | kdf_mem_kib |
| 10 | 4  | kdf_iterations |
| 14 | 4  | kdf_parallelism |
| 18 | 16 | salt |
| 34 | 19 | nonce_prefix |
| 53 | 4  | chunk_size (4 KiB … 16 MiB) |
| 57 | …  | chunks |

The per-file key is derived like the symmetric mode and then run through an
**HKDF-SHA256** expansion: `master = Argon2id(passphrase ‖ pepper, salt, params)`,
then `key = HKDF-SHA256-Expand(master, info = "quipu/stream/v1" ‖ nonce_prefix)`
(see `derive_stream_key` in `src/stream.rs`). That single per-file `key` encrypts
every chunk — only the nonce varies per chunk. Each chunk is
`XChaCha20Poly1305_Seal(key, nonce_i, aad = header(57), chunk_plaintext)` followed
by its 16-byte tag. The 24-byte nonce of chunk *i* is:

```
nonce_i = nonce_prefix(19) ‖ be_u32(counter) ‖ final_flag(1)
```

`final_flag = 1` only on the last chunk. This gives resistance to **truncation**
(missing final chunk), **reordering / duplication** (counter in the nonce) and
**cross-file splicing** (per-file salt ⇒ per-file key).

## 11. Honey Encryption (`QHNY`, opt-in feature `honey`)

Decoy mode for low-entropy secrets modelled as a uniform sequence of `L` tokens
from an alphabet of size `A` (a PIN: `A=10`; a mnemonic: `A=`wordlist size). A
39-byte header, then the encrypted tokens:

| Offset | Size | Field |
|-------:|-----:|-------|
| 0  | 4  | magic = `"QHNY"` (0x51 0x48 0x4e 0x59) |
| 4  | 1  | version = `1` |
| 5  | 16 | salt |
| 21 | 4  | kdf_mem_kib |
| 25 | 4  | kdf_iterations |
| 29 | 4  | kdf_parallelism |
| 33 | 2  | alphabet A (≥ 2) |
| 35 | 4  | length L (≤ 1000) |
| 39 | 2·L | encrypted tokens `c_i` (each big-endian u16) |

A base-`A` one-time-pad keyed by the KDF:

```
master = Argon2id(NFKC(pw) ‖ pepper, salt, params)
buf    = HKDF-SHA256-Expand(master, info = "quipu-honey-v1/pad", 8·L)   # 8 bytes/token
k_i    = be_u64(buf[8i .. 8i+8])  mod A
c_i    = (t_i + k_i)  mod A        # encrypt
t_i    = (c_i - k_i)  mod A        # decrypt
```

**No authentication tag, by design** — a tag would be a success oracle. Every
passphrase decrypts to a valid token sequence, so a wrong guess yields a
plausible *decoy* and an offline brute-forcer gets no "correct-key" signal. Only
sound for uniform, fixed-alphabet secrets; it does **not** detect tampering and
is a specialised companion to, never a replacement for, the authenticated AEAD
core.

## 12. Domain-separation labels

Every key derivation / hash uses a unique label:

| Label | Use |
|-------|-----|
| `quipu/v1/cipher` | HKDF: symmetric content-cipher subkey |
| `quipu/v2/hybrid-kem` | HKDF: hybrid KEM content key (prefix of `info`) |
| `"…-ristretto255-SHA512"` (contextString, §8) | VOPRF (RFC 9497): every hash is DST-separated from this one string — `HashToGroup-`, `HashToScalar-`, `DeriveKeyPair`, `Seed-` |
| `quipu/v3/sign` | Hybrid signature preimage (Ed25519 + ML-DSA [+ SLH-DSA for QSG3]) |
| `quipu/stream/v1` | HKDF: streaming AEAD per-file key (§10), `info` suffixed with `nonce_prefix` |
| `quipu-honey-v1/pad` | HKDF: honey per-token keystream (§11) |
| `quipu/v4/sign-triple` | Triple-signature preimage context (`slh`), distinct from `quipu/v3/sign` so a triple can never be verified as a double |
| `quipu/v1/blindaje` | HKDF: blind-split subkey (`blindaje`); `quipu blindaje v1 :: {clave,nonce} capa {AES-256-GCM,XChaCha20-Poly1305}` derive each layer's key/nonce, and `quipu blindaje v2 :: mascara …` the plaintext-dependent mask (`src/blindaje.rs`) |
| `quipu/v1/shamir-tag` | HKDF: authentication tag over a Shamir share set (`escrow`, `src/shamir.rs`) |
| `quipu/negacion/v1/senuelo`, `quipu/negacion/v1/oculto` | Deniability decoy vs. hidden volume (`negacion`); two labels so the same passphrase never derives the same material for both (`src/negacion.rs`) |
| `quipu/v1/perforable/ggm/izq`, `…/ggm/der` | HKDF-Expand PRG of the GGM puncturable tree — left/right child, distinct so siblings are independent (`perforable`, `src/perforable.rs`, §16) |
| `quipu/v1/perforable/tag->ruta!!!` | 32-byte HKDF **IKM** (not `info`) that maps an arbitrary tag to its 128-bit tree path; a public domain constant, secrecy lives in the random root (`perforable`) |
| `quipu/v2/oprf`, `quipu/v2/oprf-server-key` | Legacy non-verifiable OPRF (`#[deprecated]`, no consumers; the online mode uses §8) |

The CNSA-alignment profile derives with its own labels (`quipu-cnsa/…`), stated in
[`docs/CNSA.md`](CNSA.md). Internal-only derivations that never touch a stored
format — the VOPRF ephemeral keypair (`quipu-voprf-ephemeral`, per RFC 9497
`DeriveKeyPair`) and the `lab` timing harness — are not container constants and
are documented at their call sites.

## 13. Constants

Every value below is either **mandated** by a named standard (the only honest
value is the one the standard fixes) or a **decision** whose reasoning is
recorded — inline in the source module, or in the threat model. There is no bare
number: a constant that cannot be traced to one of these is itself a finding.

| Name | Value | Source / provenance |
|------|-------|---------------------|
| Symmetric magic / version | `"QUIP"` / `1` | format decision (§3.2) |
| Symmetric header size | 68 bytes | derived — sum of §3.2 fields |
| Hybrid magic / version | `"QPQ1"` / `1` | format decision (§7.3) |
| Signed magic / version | `"QSG1"` (double) · `"QSG3"` (triple) / `1` | format decision (§9.3, §9.4) |
| Streaming magic / version / header | `"QST1"` / `1` / 57 bytes | format decision (§10); header size derived from its fields |
| Streaming nonce prefix / chunk size range | 19 bytes / 4 KiB – 16 MiB | decision (§10): 19-byte per-file prefix leaves room in the 24-byte XChaCha nonce for a counter; bounds are memory/DoS scoping (`src/stream.rs`) |
| Honey magic / version / header | `"QHNY"` / `1` / 39 bytes | format decision (§11) |
| Honey alphabet / max length | u16 (≥ 2) / 1000 tokens | decision (§11), `src/honey.rs` |
| AEAD key / nonce / tag | 32 / 24 / 16 bytes | XChaCha20-Poly1305: RFC 8439 (256-bit key, 128-bit tag) + the XChaCha 192-bit extended-nonce construction |
| salt | 16 bytes | Argon2id salt, RFC 9106 (recommended salt length) |
| KDF cost — canonical ladder | LIGERO 16 MiB · EQUILIBRADO **(default)** 64 MiB · FUERTE 256 MiB; iterations 3/3/4; parallelism 1 | measured decision, `src/kdf.rs` + `THREAT_MODEL` N9 (the ladder collapses the header's KDF-parameter fingerprint) |
| KDF bounds (rejected before deriving) | mem ≤ 256 MiB (`MAX_MEM_KIB` 262 144), 1 ≤ t ≤ 16, 1 ≤ p ≤ 16 | anti-amplification decision, `src/kdf.rs` `MAX_MEM_KIB` (§3.1) |
| DLEQ proof | 64 bytes | RFC 9497, `ristretto255-SHA512` (two 32-byte scalars) |
| VOPRF verified response | 97 bytes | derived — 1 (tag) + 32 (evaluated element) + 64 (proof) |
| Hybrid verifying key / signing key / signature | 2624 / 64 / 4691 bytes | derived: Ed25519 (RFC 8032: 32 / 32 seed / 64) ‖ ML-DSA-87 (FIPS-204: 2592 / 32 seed / 4627) |
| Triple verifying key / signing key / signature (`slh`) | 2688 / 192 / 34483 bytes | derived: adds SLH-DSA-SHA2-256s (FIPS-205: pk 64 / sk 128 / sig 29792) to the hybrid above (§9.4) |
| Blind-split magic / version (`blindaje`) | `"QBL1"` (v1) · `"QBL2"` (v2, current) / — | format decision, `src/blindaje.rs`; the magic bump is load-bearing — a `QBL1` opened as `QBL2` (or vice-versa) is rejected, not silently mis-parsed |
| Shamir custody magic (`escrow`) | `"QSS2"` | format decision, `src/shamir.rs` |
| Puncturable state magic / version (`perforable`) | `"QPF1"` / `1` | format decision, `src/perforable.rs` (§16) |
| Puncturable state entry size (`perforable`) | 49 bytes | derived — 1 (depth) + 16 (path prefix) + 32 (subtree key) |
| Puncturable seal magic (`perforable`) | `"QPS1"` | format decision, `src/api.rs`; layout `magic(4) ‖ nonce(24) ‖ ciphertext‖tag` |
| Puncturable tree depth (`perforable`) | `DEPTH` = 128 bits | decision, `src/perforable.rs`: tag→path width; a chance collision needs ~2⁶⁴ tags, a targeted one ~2¹²⁸ work (§16) |
| Puncturable node size (`perforable`) | 32 bytes | mandated by the PRG — HKDF-SHA256 output, reused as the AEAD key length |

The feature-gated modes above (`blindaje`, `escrow`, `negacion`, `perforable`)
ship their format constants here and the deeper reasoning in their module headers
and design notes; `quipu-cnsa` states its own in [`docs/CNSA.md`](CNSA.md).

## 14. Interoperability test vectors

[`tests/vectors/quipu_vectors.json`](../tests/vectors/quipu_vectors.json) holds
known-answer vectors in two classes:

- **`deterministic.*`** — with fixed salt/nonce the output is byte-for-byte
  reproducible (KDF master key, HKDF subkey, XChaCha20-Poly1305, Padmé, the
  `QUIP` symmetric container, the `QHNY` honey container). These **freeze the
  format**: any accidental change breaks the test.
- **`frozen.*`** — modes with internal randomness (streaming, hybrid PQ, hybrid
  signature) pin a captured artifact and verify the **decode / verify** direction.

The Argon2id cost in the vectors is intentionally cheap so tests run fast; a KAT
pins the algorithm, not the cost. [`tests/vectors.rs`](../tests/vectors.rs)
recomputes the deterministic vectors and checks the frozen ones on every
`cargo test`. Regenerate after an intentional format change with
`cargo run --example gen_vectors --features honey`.

## 15. Side-channel posture

The threat model puts local physical side channels out of scope (N3): Quipu is
software protecting data at rest, and an attacker with an oscilloscope on the
CPU is not the adversary it is built against. That is a scoping decision, not an
excuse to be careless — the primitives are chosen so that the leakage an
attacker *could* reach is absent by construction rather than merely small.

### 15.1 Why "the leak is small" is no longer a defence

Machine learning does not break the mathematics, but it has collapsed the safety
margin on implementation leaks. Deep-learning side-channel analysis reports
compromising an AES implementation in **~350 traces where a classical template
attack needs ~52,000** — five orders of magnitude, at greater distance. The 2025
literature further reports that deep-learning attacks break **masked**
implementations in a black-box setting, without preprocessing to combine
leakages.

Two consequences shape this section. First, a leak that is "too small to be
practical" should be assumed practical. Second, masking is not the silver bullet
it is often taken for: it is provable in the *d*-probing model, but real
implementations leak through channels that model does not capture.

The conclusion is the one already stated in `THREAT_MODEL` §9 — a trained model
*amplifies* leaks that exist; it cannot learn a trace that was never emitted.
The defence is therefore absence of leakage by construction, not obfuscation of
it.

### 15.2 Symmetric core: constant-time without a hardware dependency

**XChaCha20-Poly1305 is an ARX construction** — additions, rotations and XORs
only. It has **no lookup tables**, so no memory access depends on secret data.
The property that matters is not that it is fast, but that it holds
**unconditionally**: on every architecture, with or without cryptographic
hardware, in every build configuration.

AES has the same property **only where the hardware provides it**. Where AES
instructions are absent, a software implementation falls back to S-box lookup
tables indexed by secret-dependent bytes — the classic cache-timing side channel,
a practical and published attack rather than a theoretical one.

| Target | AES-256 | XChaCha20-Poly1305 |
|---|---|---|
| x86-64 with AES-NI (Westmere, 2010, and later) | constant-time (hardware) | constant-time |
| x86-64 predating AES-NI | **table-based** | constant-time |
| ARMv8 with crypto extensions | constant-time (hardware) | constant-time |
| ARMv7, ARMv8 without extensions, low-cost SBCs | **table-based** | constant-time |
| RISC-V without the scalar-crypto extension | **table-based** | constant-time |
| WebAssembly, portable/`no_std` builds | **table-based** | constant-time |

> The table compares **choices, not code paths that ship**. Quipu contains no AES
> implementation: the AES column describes what a CNSA-conformant profile (§15.5)
> would inherit if it were built, and is the reason such a profile is not an
> automatic improvement.

So the honest claim is narrower and stronger than "more resistant than AES". It
is this: **the guarantee does not depend on the machine the operator happens to
own.** On a modern server with AES-NI the two are equivalent on this axis; below
that line they are not, and the difference is silent.

That silence is the point. A build that falls back to table-based AES emits no
warning, appears in no test, and changes no API. The operator would have to know
to check — and in an air-gapped on-premise deployment nobody is checking, because
the hardware belongs to the client, is chosen by the client, and is frequently
not even known to the vendor. **A property that must be verified per machine is
not a property a specification can promise.** One that holds unconditionally is.

That is why the divergence from CNSA 2.0 on the symmetric side is deliberate and
not a gap. A CNSA-conformant profile remains possible (§15.5), but it would be a
compliance decision, and on hardware without AES acceleration it would be a
**regression** on this axis, not an improvement.

The same reasoning covers the KDF. HKDF-SHA256 rather than SHA-384/512 is a
divergence in the *named algorithm*, not in the security level: HKDF's security
as a PRF does not rest on the collision resistance that separates SHA-256 from
SHA-384. SHA-2 is table-free in every implementation, so it carries no equivalent
hardware dependency.

### 15.3 Post-quantum: KyberSlash does not apply

**KyberSlash** (2024) recovered Kyber secret keys — in minutes on a Cortex-A7 —
by exploiting a **secret-dependent division** present in several implementations,
including the reference code. A direct implementation divides a secret value by
the constant `q`, and division is not constant-time on most platforms.

Quipu uses the `ml-kem` crate (RustCrypto), which **avoids this by
construction**, verified in the vendored source:

- `compress.rs` replaces the division with a multiply-and-shift
  (`a / q ≈ (a * x) >> s`), the standard constant-time substitution.
- The only division in the crate is `DIV_MUL`, a **compile-time constant**, never
  evaluated at runtime on secret data.

`RUSTSEC-2023-0079` (KyberSlash) is filed against `pqc_kyber`, which Quipu does
not use.

### 15.4 What is actively verified

- **`antihacker::ct_eq`** — constant-time comparison (`subtle`) for every tag and
  signature check. A meta-test in the Security Lab fails CI if this defence is
  weakened.
- **dudect harness** (`lab::timing`, offline bench) — measures Welch's *t*
  between two input classes sampled *interleaved*, so system drift cancels.
  It covers `ct_eq`, container `decode`, and the two post-quantum classes where
  a secret is actually involved:
  - **valid vs corrupted encapsulation** — ML-KEM's implicit rejection must be
    indistinguishable in time, or an attacker who can submit ciphertexts and
    measure gains a validity oracle, which is the way into a chosen-ciphertext
    attack against the KEM;
  - **two different secret keys over the same encapsulation** — detects timing
    correlated with key material itself.

  Both report *constant-time* against the `DUDECT_T_THRESHOLD` of 10, with |*t*|
  well under 1 on the reference machine. This is the empirical counterpart to the
  static argument in §15.3: the analysis says the KyberSlash division is absent,
  and the bench measures no distinguishable timing. Absolute *t* values are
  machine-dependent and are not part of this specification; the verdict is.

  **Signature verification is deliberately not a dudect target.** The verifying
  key, the message and the signature are all public, so a timing difference there
  reveals no secret — measuring it would produce a number and no information.
- The power-on self-tests (`quipu::selftest`) confirm on the executing binary
  that `ct_eq` still discriminates — a comparison that always returned `true`
  would make every tag check decorative.

**ML-DSA *signing* is deliberately not dudect-tested.** ML-DSA uses rejection
sampling: the number of loop iterations legitimately varies with the sampled
randomness, so signing time is variable *by specification*. A dudect verdict
there would report leakage that is a documented property of the algorithm, not a
defect of this implementation. Verification, which has no rejection loop, is
tested.

### 15.5 What Quipu does not do, and what to use instead

**Masking / threshold implementations are not implemented.** They are the
software counterpart of dual-rail precharge logic and cost 2–10× in performance
and a large increase in complexity, to defend against an adversary the threat
model excludes (N2, N3) — while §15.1 shows they are not unconditionally
effective either. The leakage they would close is already closed by primitive
choice, which is cheaper and auditable.

**Noise, dummy operations and random delays are deliberately absent.** Such
*hiding* multiplies an attacker's trace count by a constant; more samples average
the noise away. It costs performance and auditability and changes nothing
asymptotically.

**For an adversary with physical access, the correct answer is hardware.** A
software library cannot defend the silicon it runs on. The supported path is to
keep the private key inside a certified module (PKCS#11 / HSM) so the sensitive
operation never happens in Quipu's address space — planned as the `Signer` /
`KeyStore` abstraction with a PKCS#11 reference backend.

## 16. Puncturable encryption (`QPF1` / `QPS1`, opt-in feature `perforable`)

Forward secrecy for **data at rest**: opening a seal destroys the key that opens
it, so an attacker who later steals the whole key state, the ciphertext and the
passphrase still cannot re-read what was already read. It is not a session mode —
Quipu has no messaging or ratcheting, and this adds none.

### 16.1 Construction

A [GGM](https://eprint.iacr.org/2014/838) **puncturable PRF**. From a random
32-byte root, a PRG derives two independent children per node —
`HKDF-Expand(PRK = node, info = GGM_izq)` and `… info = GGM_der` (§12) — defining
a binary tree of depth `DEPTH` (128). Each leaf is the key of one
seal. A tag maps to its 128-bit leaf path with `HKDF(IKM = quipu/v1/perforable/tag->ruta!!!, info = tag)`
— a public map (secrecy is in the root, not the mapping). The key of a tag is the
leaf at the end of its path.

**Puncturing** a tag replaces the stored node covering its path with the *sibling*
subtree roots along that path (the co-path): from those siblings every other leaf
is still derivable, but the punctured leaf is not — recovering it would require
inverting HMAC-SHA256. The stored key is a set of `(depth, prefix, node)`
coverages that partition all non-punctured leaves.

The root is **random and never derived from a passphrase**: if it could be
regenerated there would be nothing to destroy. Consequently the serialized state
is the only copy and is mutated in place; a surviving older snapshot re-opens what
it held, and "overwriting the file" does not erase it on copy-on-write
filesystems or SSDs (secure erasure must happen where it is real — TPM/`fscrypt`
/RAM). What has **not** been read stays readable to whoever steals the state.
The full threat model, including the T6 (post-operation memory) handling, is in
the `src/perforable.rs` module header.

### 16.2 Formats

**Seal (`QPS1`)** — the "lacre" that carries the data:

```
magic "QPS1" (4) | nonce (24) | ciphertext‖tag       (XChaCha20-Poly1305, aad = tag)
```

The tag travels as AEAD `aad` and the per-seal key is derived from the same tag,
so a ciphertext cannot be re-labelled. `abrir` decrypts and **only then** punctures
the tag; a failed authentication never burns the key.

**State (`QPF1`)** — the puncturable key, sensitive (it holds the live subtree
keys); serialize it with `a_bytes`, protect it at rest with Quipu's normal
encryption, and destroy old copies:

```
magic "QPF1" (4) | version (1) | depth (1) | punctured_count (8, LE) | n (4, LE)
  then n × [ depth (1) | prefix (16) | key (32) ]          (entry = 49 bytes)
```

Constants and their provenance are in §13; the domain labels in §12.
