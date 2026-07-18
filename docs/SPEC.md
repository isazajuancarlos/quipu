# Quipu — Technical Specification

**Covers the container formats through v0.6.0 · updated 2026-07-04**

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
resulting bytes in a chosen representation (dense text, PNG, or glyphs). Security
lives in the keys and the vetted primitives; the representation is public
(Kerckhoffs).

```
plaintext
  → Padmé padding                      (§4)
  → AEAD encrypt (XChaCha20-Poly1305)  (§3), AAD = header
  → container = header ‖ ciphertext    (§2)
  → base-N codec → symbol indices      (§5)
  → dictionary / PNG / glyph rendering (§6)
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
1 048 576` (1 GiB). Defaults: `mem_kib = 65536` (64 MiB), `iterations = 3`,
`parallelism = 1`.

### 3.2 Container format

Fixed 68-byte header, followed by the AEAD output (ciphertext ‖ 16-byte tag):

| Offset | Size | Field |
|-------:|-----:|-------|
| 0  | 4  | magic = `"QUIP"` (0x51 0x55 0x49 0x50) |
| 4  | 1  | version = `1` |
| 5  | 1  | flags (currently `0`) |
| 6  | 2  | codebook_id (informational) |
| 8  | 8  | codebook_hash_prefix (first 8 bytes of the dictionary fingerprint) |
| 16 | 16 | salt |
| 32 | 24 | nonce (XChaCha20) |
| 56 | 4  | kdf_mem_kib |
| 60 | 4  | kdf_iterations |
| 64 | 4  | kdf_parallelism |
| 68 | …  | AEAD ciphertext ‖ tag |

The **entire 68-byte header is the AEAD Associated Data (AAD)**. Any alteration of
version, codebook_id, salt, nonce, or KDF parameters causes decryption to fail.

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
- **PNG:** the container bytes are rendered as a lossless grayscale PNG.
- **Robust PNG:** as above but wrapped with Reed-Solomon ECC (`parity`
  bytes/block) to tolerate print/photo channel noise. ECC is error correction,
  not a security layer.
- **Native glyphs:** the bytes are base-N encoded over a deterministic native
  glyph font and rendered as a strip; recognition maps glyphs back to indices by
  nearest fingerprint.

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
> it is NOT wire-compatible with `draft-connolly-cfrg-xwing-kem`: X-Wing uses
> ML-KEM-**768** and a single `SHA3-256` combiner, whereas Quipu uses
> ML-KEM-**1024** (CNSA 2.0, NIST level 5) and `HKDF-SHA256`, and additionally
> binds the ML-KEM `ek`/`ct`. Deliberate: the parameter set is driven by CNSA 2.0,
> not interop.

### 7.3 Container

```
header = "QPQ1"(4) ‖ version=1 (1) ‖ flags=0 (1) ‖ nonce(24) ‖ encapsulation(1600)
blob   = header ‖ XChaCha20Poly1305_Seal(content_key, nonce, aad = header, padded_plaintext)
```

`blob` is then base-N encoded and rendered like the symmetric mode.

## 8. Verifiable OPRF (online hardening)

A verifiable OPRF over ristretto255 lets a server participate in hardening a
passphrase without seeing it, and lets the client verify the server used the
expected key (RFC 9497 style). `G` is the ristretto255 basepoint.

```
Server key:  k = SHA-512("quipu/v2/voprf-server-key" ‖ seed) mod ℓ   (wide reduce)
Public key:  Y = k · G                                                (pin on client)

hash_to_curve(pw) = Ristretto.hash_from_bytes<SHA-512>("quipu/v2/voprf" ‖ pw)

Client blind:   r ← random scalar;  B = r · H(pw);  send B (32B compressed)
Server eval:    Z = k · B;  proof = DLEQ(k, Y, B, Z);  send Z(32) ‖ proof(64)
Client final:   verify DLEQ(Y, B, Z, proof) against the pinned Y; abort on failure
                U = r⁻¹ · Z            # = k · H(pw)
                output(32) = SHA-512("quipu/v2/voprf" ‖ len(pw):u64 ‖ pw ‖ U)[0..32]
```

`output` is then used as (or mixed into) the pepper/hardening input of the
symmetric mode.

### 8.1 DLEQ proof (Chaum-Pedersen, non-interactive)

Proves `log_G(Y) = log_B(Z) = k` without revealing `k`.

```
prove(k, Y, B, Z):
    t ← random scalar
    A1 = t · G;  A2 = t · B
    c  = challenge(Y, B, Z, A1, A2)
    s  = t + c · k
    return c(32) ‖ s(32)                # 64 bytes

verify(Y, B, Z, proof = c ‖ s):
    A1 = s · G − c · Y
    A2 = s · B − c · Z
    return challenge(Y, B, Z, A1, A2) == c

challenge(Y, B, Z, A1, A2) =
    SHA-512("quipu/v2/voprf-dleq" ‖ G ‖ Y ‖ B ‖ Z ‖ A1 ‖ A2) mod ℓ   (wide reduce)
```

All points are 32-byte compressed ristretto255 encodings.

### 8.2 Online wire protocol

Minimal TCP protocol (put behind TLS in production):

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

```
preimage = "quipu/v3/sign" ‖ verifying_key(1984) ‖ message
σ_ed     = Ed25519.Sign(sk_ed, preimage)            # 64 B, deterministic
σ_ml     = MLDSA65.Sign(sk_ml, preimage)            # 3309 B, deterministic (empty ctx)
signature = σ_ed(64) ‖ σ_ml(3309)                   # 3373 B

verify(vk, message, signature):
    preimage = "quipu/v3/sign" ‖ vk ‖ message
    return Ed25519.VerifyStrict(vk_ed, preimage, σ_ed)   # rejects small-order / malleable
           AND MLDSA65.Verify(vk_ml, preimage, σ_ml)     # AND-combiner
```

Binding the **full** verifying key (both components) and a domain label into the
signed preimage prevents weak key-substitution and cross-component mixing (a
component signature cannot be reused under a different keypair). The **AND**
combiner (both must verify) makes the hybrid signature unforgeable as long as **at
least one** of Ed25519 / ML-DSA-87 remains unforgeable.

### 9.3 Signed container

```
blob = "QSG1"(4) ‖ version=1 (1) ‖ flags=0 (1) ‖ msg_len(u32 BE, 4)
       ‖ message(msg_len) ‖ signature(3373)
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

The per-file key is derived like the symmetric mode (`Argon2id` → the file key is
used directly per chunk). Each chunk is `XChaCha20Poly1305_Seal(key, nonce_i,
aad = header(57), chunk_plaintext)` followed by its 16-byte tag. The 24-byte
nonce of chunk *i* is:

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
| `quipu/v2/voprf` | VOPRF hash-to-curve and final output |
| `quipu/v2/voprf-dleq` | DLEQ challenge |
| `quipu/v2/voprf-server-key` | Deterministic VOPRF server key from seed |
| `quipu/v3/sign` | Hybrid signature preimage (Ed25519 + ML-DSA [+ SLH-DSA for QSG3]) |
| `quipu-honey-v1/pad` | HKDF: honey per-token keystream (§11) |
| `quipu/v2/oprf`, `quipu/v2/oprf-server-key` | Legacy non-verifiable OPRF (building block; unused by the online mode) |

## 13. Constants

| Name | Value |
|------|-------|
| Symmetric magic / version | `"QUIP"` / `1` |
| Symmetric header size | 68 bytes |
| Hybrid magic / version | `"QPQ1"` / `1` |
| Signed magic / version | `"QSG1"` (double) · `"QSG3"` (triple) / `1` |
| Streaming magic / version / header | `"QST1"` / `1` / 57 bytes |
| Streaming nonce prefix / chunk size range | 19 bytes / 4 KiB – 16 MiB |
| Honey magic / version / header | `"QHNY"` / `1` / 39 bytes |
| Honey alphabet / max length | u16 (≥ 2) / 1000 tokens |
| AEAD key / nonce / tag | 32 / 24 / 16 bytes |
| salt | 16 bytes |
| DLEQ proof | 64 bytes |
| VOPRF verified response | 97 bytes |
| Hybrid verifying key / signing key / signature | 1984 / 64 / 3373 bytes |

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
