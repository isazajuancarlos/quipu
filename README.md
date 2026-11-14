# Quipu

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![crates.io](https://img.shields.io/crates/v/quipu.svg)](https://crates.io/crates/quipu)
[![docs.rs](https://img.shields.io/docsrs/quipu)](https://docs.rs/quipu)
[![CI](https://github.com/isazajuancarlos/quipu/actions/workflows/ci.yml/badge.svg)](https://github.com/isazajuancarlos/quipu/actions/workflows/ci.yml)
[![post-quantum](https://img.shields.io/badge/post--quantum-ML--KEM--1024-purple.svg)](#modes)

> 🇪🇸 **[Léeme en español →](README.es.md)** — the Spanish version is the
> original and both are kept in sync.

An encoding library with **cryptographic protection** and a **pluggable symbol
alphabet**.

> "Wheel and caterpillar track" philosophy: where good cryptography already
> exists we **reuse** it (XChaCha20-Poly1305, Argon2id, HKDF, ML-KEM, X25519);
> where the ground is new (representation, symbols, format) we **innovate**. We
> never invent cryptographic primitives: security lives in the key and the AEAD,
> never in the representation.

## What it does

Protects data and renders it as **symbols** — dense text or an image —
reversibly and with authentication.

```
data → KDF(passphrase+pepper) → AEAD → container → base-N codec → dictionary → symbols
```

## Modes

| Mode | API (Rust) | Description |
|---|---|---|
| Symmetric (passphrase) | `api::encode` / `api::decode` | Argon2id + XChaCha20-Poly1305 |
| Post-quantum (public key) | `api::encode_to_recipient` / `decode_as_recipient` | Hybrid **X25519 + ML-KEM-1024** (X-Wing-style bound transcript) |
| Online (hardening) | `api::encode_online` / `decode_online` | **VOPRF per [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497.html)** (ristretto255-SHA512, DLEQ proof): the client detects a dishonest server |
| Signed (authenticity) | `api::encode_signed` / `decode_verified` | Hybrid signature **Ed25519 + ML-DSA-87** (AND combiner). Verifiable authenticity and non-repudiation; **not** confidentiality |
| Triple-signed (high assurance, feature `slh`) | `api::encode_signed_triple` / `decode_verified_triple` | Triple-hybrid **Ed25519 + ML-DSA-87 + SLH-DSA-256s** (AND 3-of-3): unforgeable as long as ≥1 of {curve, lattice, hash} survives. Opt-in; ~34 KB signature |
| Streaming (large files) | `api::encrypt_stream` / `decrypt_stream` | Chunked encryption (bounded memory) for large data at rest; resistant to truncation, reordering and splicing. `QST1` container |
| Decoys / Honey (feature `honey`) | `honey::encrypt_pin` / `decrypt_pin` (and generic `encrypt`/`decrypt`) | **Honey Encryption** for low-entropy secrets (a PIN, a mnemonic phrase): any wrong passphrase decrypts to **another plausible secret**, not to an error → no brute-force oracle. Opt-in. **Unauthenticated by design** (a tag would itself be an oracle); it does not replace the AEAD core, and only suits uniform sequences |
| Deniability (feature `negacion`) | `negacion::crear` / `abrir` | One file, **two passphrases**: one opens the decoy you hand over under coercion, the other the real volume. **Nothing inside the container says whether the second exists**, and the remainder is filled with randomness whether it does or not. Opt-in. See the limit in bold below |
| Blind split (feature `blindaje`) | `api::encode_blindado` / `api::decode` | Two AEADs from **two different crates** (AES-256-GCM + XChaCha20-Poly1305), and **neither one ever receives the plaintext**: the payload is XOR-split and each half goes to one layer. Defends against a *compromised library*, which ordinary encryption does not. Opt-in: output is **2×** the payload and encryption is ~**17×** at 256 KiB and 52× on 1 KiB messages (measured 2026-08-17; the 5.2× published here was `QBL1`, before the mask) |
| Discreet / PURB (feature `discreto`) | `api::encode_discreto` / `api::decode_discreto` | A container with **no cleartext header** — no magic, version, or KDF parameters — with fixed parameters and Padmé-padded length (Nikitin et al. 2019): without the key the blob is **indistinguishable from uniform random** and cannot be fingerprinted as Quipu. Opt-in. Cost: no cost ladder, and a wrong passphrase is indistinguishable from "not a container" (that distinction would be the fingerprint it avoids) |
| Threshold custody of the document (feature `escrow`) | `api::encode_con_custodia` / `api::decode_con_custodia` | The document is encrypted under a **random content key**, and that key is **Shamir-split into k-of-n shares**: decrypting requires at least **k** custodians. Shamir applied to the *document*, not just to the OPRF server seed. The key is never derived from a passphrase and lives only split. Opt-in. `QCU1` container |
| Puncturable / destroy-on-open (feature `perforable`) | `api::sellar` / `api::abrir` | Reading a seal **destroys the key that opens it**: an attacker who later steals the whole key state, the ciphertext and the passphrase still cannot re-open what was already read. *Forward secrecy for data at rest* via a GGM puncturable PRF over HKDF-SHA256 (**no new dependency**). Opt-in. The key root is **random, not derived from a passphrase**, and a stale snapshot of the state defeats it — see the section below |

### A scope limit: there is no PUBLIC-KEY streaming

The table above has both modes and **they do not cross**:

- `encrypt_stream` / `decrypt_stream` (`QST1`) encrypts in chunks with bounded
  memory — but it is **symmetric**: it derives from a passphrase.
- `encode_to_recipient` encrypts to a post-quantum public key — but it takes a
  `&[u8]` and returns a `String`: it **loads the whole file into memory** and
  runs it through the base-N codec.

So **"encrypt a large file to someone else's public key" has no bounded-memory
path today**. This is not a bug; it is scope nobody has asked for yet, and it is
written down here so that nobody discovers it halfway through an integration.

**The TIME cost of the symbolic path, which was undocumented until 2026-08-16
and was the limit that bit first.** The base-N codec converts the whole message
as a single number, and it used to do that with a loop of divisions: it was
**quadratic**. 512 KiB took 50.7 s and 10 MiB would have taken about 5.6 hours —
so the real limit was never memory (10 MiB is nothing), it was the clock.
Rewritten with **divide-and-conquer** radix conversion, the order drops to
`O(M(m)·log m)`: **512 KiB went from 50.7 s to 0.46 s (111×) and 10 MiB from
~5.6 h to 41.4 s**, both measured. Guarded by
`crates/quipu-nucleo/tests/escala_del_codec.rs`, which turns red if it ever
becomes quadratic again.

It is still superlinear, so the symbolic path is not for arbitrarily large
files: that is what `encrypt_stream` is for, and it does not go through the
codec. The memory ceiling did not move — this is a time improvement, not a space
one, and the power table it uses adds roughly another message-sized allocation.

What it would cost, so it need not be re-derived: a `QST1` whose header carries
the ML-KEM encapsulation instead of the salt and the Argon2id parameters. The
content key already comes out of decapsulation, so the rest of the chunk format
— per-chunk AAD, resistance to truncation and reordering — carries over
unchanged. It is a container variant, not new cryptography.

## What actually protects your secret: the three factors, and which to pick

The table above says what each mode **does**. This one says what it depends on
for somebody to be able to open it, which is the question to answer first.

**The axis is not "key or file".** What decides security is *how many attempts
the attacker gets, and whether he can make them without asking anyone's
permission*.

| Factor | What it is | Strong against | Weak against |
|---|---|---|---|
| **Passphrase** (always) | what you KNOW. Argon2id turns it into a key | theft of the file: there is nothing stored to copy | **offline, parallel, unlimited** guessing — and coercion |
| **`pepper`** (`Options::pepper`) | what you HAVE: an environment variable, code, an HSM. Mixed in before the KDF | whoever gets the container but not the pepper **cannot even begin** to guess | being copied without your noticing; if you lose it, the data goes with it |
| **Online VOPRF** (`encode_online`) | what a **server grants**, with a DLEQ proof verified against a pinned key | it is the only one that **BOUNDS THE NUMBER OF ATTEMPTS**: each one requires a query the server can refuse | availability — if the server is down, nothing decrypts ([R2/N5](docs/THREAT_MODEL.md)) |

**Argon2id makes each attempt expensive; it does not limit how many there are.**
That sentence orders the table: against somebody holding your container, with
time and machines, per-attempt cost only multiplies his bill. The only thing that
puts a ceiling on the number of attempts is the VOPRF, and that is why it is the
paid service and not an ornament.

### Which to use

- **Passphrase alone**: if it is long and random (a six-word-plus diceware
  phrase, not one you made up). No infrastructure, and it is the default.
  `Options::pepper` ships empty: **by default there is no second factor**, and
  that is worth knowing.
- **Passphrase + `pepper`**: as soon as there is somewhere to keep it that is not
  the same disk as the container. It is the cheapest improvement available.
- **Passphrase + VOPRF**: when the adversary may walk off with the container and
  has patience. In exchange you accept a dependency on a service — which is why
  its domain and its key `k` **never rotate**: rotating would invalidate
  everything ever derived.
- **Public-key mode** (`encode_to_recipient`): when whoever encrypts is **not**
  who decrypts, or when no human types anything at all (a server encrypting its
  own database). There *is* a secret to keep there, and that is what the
  [HSM](#device-held-signing-hsmpkcs11-feature-hsm) and
  [k-of-n custody](#key-custody-k-of-n-feature-escrow) are for.

### Why Quipu has no plain "key file"

It would be a single object whose **copying leaves no trace** and whose **loss
has no recourse**, and it moves the problem to exactly where an attacker with
filesystem access is strongest. The `pepper` is the strictly better version of
"something you have": it is not required to be a file — it can live in the
environment or in an HSM — and it **adds to** the passphrase instead of replacing
it. Adding a key file on top would look like more protection while introducing a
single point of failure.

## Blind split: the threat ordinary encryption does not cover (feature `blindaje`)

Every mode above protects against whoever **intercepts** the container. None of
them protects against one of the **libraries** we depend on being compromised —
which is where the attacks have moved — because the malicious crate runs in the
same process and sees the plaintext and the key before anybody else.

The obvious idea is to chain two ciphers, `AES(XChaCha(P))`. **That does not help
here**: the inner layer receives the whole plaintext. It helps against a
cryptanalytic break of one of the two, which is a different threat.

This mode **splits instead of chaining**:

```text
    S1 = random(|P|)                 S2 = P xor S1
    C1 = AES-256-GCM(K1, S1)         C2 = XChaCha20-Poly1305(K2, S2)
```

`S1` is uniform by construction and `S2` is uniform because it is `P` masked with
`S1`, so **each algorithm implementation receives noise**: on its own, neither
holds a single bit of information about the message. And you still have to break
both to read, exactly as with a cascade — the split has both properties, it does
not trade one for the other.

**How far that "AND" reaches, and how it was closed.** The 2026-08-16 review
found the split was blind per algorithm implementation and **not per glue**:
neither `aes-gcm` nor `chacha20poly1305` implements the `encrypt` that receives
the message — both inherit the blanket one from the `aead` crate — so `aead` saw
`S1` on one call and `S2` on the next, and `S1 xor S2 = P`.

It was closed on 2026-08-17 with the **`QBL2`** format, and without pulling in
any new ecosystem: the XChaCha layer no longer receives `S2` but `S2 xor M`, where
`M` is derived by HKDF-SHA256 from the master key and the message id. Whoever
sees both calls gets `P xor M`, which without `M` is nothing. This rests on a
supply-chain fact, measured and guarded by a test: **the 14 packages exclusive to
the AEAD path — `aead`, `cipher` and `inout` among them — are not in the
dependency closure of `hkdf`/`sha2`**, so none of them can see `M`.

What the split gives, precisely: a cryptanalytic break or a backdoor **in `aes`
or in `chacha20`** yields nothing, and since `QBL2` neither does the glue shared
by those two paths. **What it still does not give is immunity to two packages**:
`block-buffer`, which sits on both routes, and `zeroize`, which the module hands
both halves in the clear because it is what wipes them. There were 22; two
remain. Closing those too would require one of the layers from outside
RustCrypto — a dependency decision with its own price, still untaken, written
down in the module so it need not be re-derived.

**This is not invented cryptography.** `P = S1 xor S2` with uniform `S1` is the
one-time pad, and the `k = n = 2` case of Shamir's scheme, which already lives in
this repository. The secrecy of each half on its own is perfect, not
computational. *(The property `QBL2` adds — that joining both calls does not
yield the plaintext — is computational: it rests on HKDF-SHA256 being a PRF.
Two distinct claims, worth not conflating.)* What is ours here is
the COMPOSITION — what each layer receives, how its material is derived, what
binds them — and that is not a primitive.

**The price, measured 2026-08-16:** output is exactly `2·|P| + 56` bytes and
encryption costs **17×** at 256 KiB and **52×** at 1 KiB, where the four HKDF derivations
dominate). The size doubling **cannot be optimised away**: any size-preserving
construction necessarily has one component that touches the plaintext first, and
that component sees it. Keeping every component blind costs double. Hence opt-in
rather than default — on the symbolic path, twice the bytes is twice the glyphs.

**How to use it, and what happens to those who don't have it.** Encrypt with
`api::encode_blindado` and open with `api::decode` — **the same one as always**:
the mode travels in bit 0 of the header's `flags`, so a stored artifact declares
how it was written and whoever opens it two years from now does not have to
remember. The container is the same — same version, same header, same header as
AAD — so flipping the bit on an already-written container **breaks
authentication** rather than silently downgrading it.

A default-build binary — without the feature — returns
`DecodeError::ModoNoCompilado`; one older than 2026-08-16 returns
`FlagsDesconocidos`. Both refuse out loud, which is what that second error
existed for all along: this is the first `flags` bit ever used since the format
was born.

**What it does NOT protect against**, which matters as much: both crates
compromised; a compromised HKDF or Argon2id, which see the master key; and a
compromised random generator — if `S1` is predictable the split falls apart. That
is why the random half `S1` comes from `aleatorio::llenar`, i.e. the operating system, and
**never** from `aleatorio::generador()`, which is a ChaCha20 DRBG: using the
ChaCha crate to generate the mask *and* to encrypt the other share would hand
both halves to a single compromised crate. That is the subtle way to implement
this mode wrongly, and it is part of that cost.

## Deniability: what it promises and what it does NOT (feature `negacion`)

**It protects against PROOF, not against the SUSPICION of somebody who has
already decided to suspect.** Under physical coercion that distinction may be
worth nothing. This is **not** "undetectable encryption", and whoever uses it may
be someone whose freedom depends on understanding the difference.

The threat model assumes the adversary sees the container **once**. Anyone who
keeps successive versions of the same file in a backup — or syncs it to the
cloud — **loses deniability**: comparing two snapshots reveals which region
changed.

What *is* measured, with red cases that turn the bench red: the container is
indistinguishable from randomness, no byte position is predictable, one with a
hidden volume is indistinguishable from one without, and opening the decoy costs
the same as opening the hidden volume (`t = 0.73`, threshold 10). The design, the
deviations and the measurements are in
[`docs/DISENO_NEGACION.md`](docs/DISENO_NEGACION.md).

It does not ship in the Python wheels in this version: a misused API here does
not produce an error, it produces a false sense of deniability.

## Puncturable encryption: destroy the key on opening (feature `perforable`)

**Reading a seal destroys the ability to read it again.** Each item is sealed
under a *tag* with a per-tag key drawn from a puncturable PRF — a GGM tree over
HKDF-SHA256, so **no new dependency**. `api::abrir` decrypts and then *punctures*
the tag: the tree leaf that produced its key is overwritten, so that seal can
never be opened again, while every other seal stays openable. This is **forward
secrecy for data at rest**, not for a session — Quipu has no messaging or
ratcheting, and this adds none.

It buys the one thing ordinary encryption cannot: a key stolen **after** a seal
was read does not recover that plaintext. Three rules make that true, and they
are **not optional**:

- **The root is random and is never derived from a passphrase.** If it could be
  regenerated from a secret, there would be nothing to destroy. The serialized
  state is the only copy.
- **The state is mutated in place; an old snapshot undoes it.** Keep a copy of
  the state from *before* you opened a seal and whoever holds it re-opens the
  seal. `Perforable` is deliberately **not `Clone`**. And destroying the previous
  state is harder than it looks: on copy-on-write filesystems (APFS, ZFS, Btrfs),
  on any SSD with an FTL, and with snapshots or backups, *overwriting the file
  does not erase the old blocks*. The precise guarantee is: against a copy taken
  **after** opening, **assuming secure erasure of the prior state** — which
  consumer storage does not give by default. Put the state behind a wrapping key
  in a TPM/secure element or `fscrypt` (and destroy that key), or keep it in RAM.
- **What has not been read is still readable by whoever steals the state.**
  Puncturing kills what was read, not what is pending — you must be able to open
  those. This is inherent.

Protect the state at rest with Quipu's normal encryption: that is *the seal the
puncturable layer sits on top of*. The full threat model is at the top of
[`src/perforable.rs`](src/perforable.rs). Runnable demo:
`cargo run --example perforable --features perforable`.

## Key custody (k-of-n, feature `escrow`)

`quipu::shamir` splits a secret into `n` shares of which any **k** reconstruct it
and **k-1 reveal nothing**. It sits behind an **opt-in feature gate**: it is an
escrow tool, not part of the encryption core, and whoever does not need it does
not compile it in. It serves to back up the OPRF server key, to hold an
integrator's signing key, or to set up a contractual escrow — **without network
and without an HSM**, which is the condition of an air-gapped deployment.

```rust
let shares = quipu::shamir::split(&key, 3, 5)?;   // 3 of 5
let key = quipu::shamir::combine(&shares[..3])?;
```

Each share carries a verifier, so a corrupt one — or one from a different split —
**is detected** instead of returning garbage. That verifier would allow checking
guesses at a guessable secret, so the module **rejects secrets shorter than the
smallest key material the architecture itself produces** (`kdf::KEY_LEN`, 32
bytes): it is for keys, and for guessable things there is `honey`. It is not
threshold signing — the secret is reconstructed in memory in order to be used.

## Device-held signing (HSM/PKCS#11, feature `hsm`)

The private signing key can live **inside an HSM, token or PKCS#11 card and never
leave it**. This is the answer to a security committee's first question, and it
works with the full hybrid signature: **both halves** — Ed25519 and ML-DSA-87 —
are generated and used **inside** the device; only signatures and the public key
come out of the library.

The `firmante::Custodio` trait separates *who holds the key* from *how the
signature is assembled*. It asks for operations, never for material: there is no
way to extract the key, because that is the entire point. A signature made in an
HSM and one made in memory **are verified by the same verifier, which cannot tell
them apart**.

> **Corrected on 2026-08-01.** This sentence used to say they were **identical
> byte for byte**, and that is false: PKCS#11 is asked for `HedgeType::Preferred`,
> i.e. **randomized** ML-DSA if the device supports it, while the in-memory path
> signs deterministically. The bytes differ; what does not change is that both
> verify under the same key with the same verifier, which is all a caller needs.
> Hedging is moreover what FIPS-204 recommends against fault injection, so the
> difference works in our favour.
>
> An independent review found it, and the test that backed the claim —
> `firmar_por_el_trait_da_lo_mismo_que_el_camino_directo` — **only exercises the
> in-memory custodian**, where the equality holds trivially because both paths
> call the same code. It was passing for the wrong reason.

```rust
// The usual in-memory custodian (default, no feature):
let sig = firmante::firmar(&firmante::EnMemoria::nuevo(sk), message)?;

// Or against a PKCS#11 device, key held inside (feature `hsm`):
let custodian = CustodioPkcs11::por_etiqueta(session, "firma-ed", "firma-ml")?;
let sig = firmante::firmar(&custodian, message)?;  // the key never crosses here
```

With `escrow`, `firmar_con_comparticiones` reconstructs from Shamir, signs and
wipes in a single Rust call, without the key crossing into the bindings. Tested
end to end — 128 concurrent signatures against a real token, each one verified —
and in the Python binding (`quipu.CustodioHsm`), which ships in the wheel.

## Dictionaries (pluggable symbol alphabets)

- `dictionaries::ascii94()` — 94 ASCII symbols (universal copy-paste).
- `dictionaries::flagship()` — 4096 glyphs (12 bits/symbol, ~2× denser).
- `dictionaries::from_range(start, count)` — a custom alphabet.

## Security and hardening

- **Pre-layers**: NFKC normalization, pepper, Padmé padding (hides length),
  context binding (AAD), HKDF (subkey separation).
- **Antihacker**: key wiping in memory (`zeroize`), constant-time comparison, KDF
  parameter validation, uniform errors.
- **Entropy failure, never a silent substitution**: when the operating system
  cannot provide randomness, Quipu **does not fall back to a weaker source** — no
  key is ever born from a dead RNG. The failure is reported as an actionable
  error (do I retry, or do I fix the deployment?) with a bounded retry for the
  one transient case, rather than a `panic`: that way memory cleanup
  (`Drop`/zeroize) still runs, which is exactly when it matters most. This is the
  Debian OpenSSL 2008 failure mode — predictable keys that *look* correct —
  prevented by construction, and there is a self-test that warns at start-up
  instead of killing the process.
- **Start-up self-tests** (`quipu::selftest`): 14 known-answer vectors run
  against **the binary that is actually executing**, not against the CI build.
  They run once per process on entry through any core path, and if one fails the
  module **refuses to operate** rather than silently producing wrong results.

  A failing self-test **does not mean Quipu is broken**: it means the machine is
  not executing the cryptography correctly — a wheel compiled for another
  processor, a damaged or substituted file, faulty memory. They introduce no
  failure modes; they make visible the ones that were already there.

  They go beyond what FIPS 140-3 and the Chinese GM/T standards require in three
  ways: they use **published vectors** where these exist (HKDF against RFC 5869,
  not home-made vectors that only prove self-consistency), they include
  **negative tests** (tampered input must *fail*), and they monitor **RNG health**
  continuously. Every check is itself proved to **discriminate**: one that always
  returned `true` would pass a conventional battery exactly like a correct one.

  Verified with 1300 simulated operations — 200 passes, 100 concurrent threads,
  1000 repeated calls — and with fault injection to exercise the error path, both
  in CI.
- **Hackerbot**: internal red team (tamper/truncation/uniqueness). It found, and
  we fixed, a DoS via malicious Argon2 parameters.
- **Security Lab** (features `lab` / `lab-offline`, absent from the published
  build): an **adaptive** red team that attacks itself. Core in CI (format
  leakage + signature forgery) with a chained corpus and meta-tests that fail if
  an antihacker defence is weakened; plus an **isolated offline bench** (network-
  less container) for timing and AI-accelerated guessing cost.
  `cargo run --example securitylab --features lab` · `bash lab/run.sh`. See
  [`lab/README.md`](lab/README.md) and `THREAT_MODEL.md` §9.

## Usage (Rust)

```rust
use quipu::api::{encode, decode, Options};
use quipu::dictionaries;

let dict = dictionaries::ascii94();
let sym = encode(b"secret", "passphrase", &dict, &Options::default());
let data = decode(&sym, "passphrase", &dict, b"").unwrap();
```

Hybrid signature (third-party-verifiable authenticity, post-quantum):

```rust
use quipu::api::{encode_signed, decode_verified};
use quipu::{dictionaries, pqsign};

let dict = dictionaries::ascii94();
let (vk, sk) = pqsign::generate_keypair();
let signed = encode_signed(b"official record", &sk, &dict);
let msg = decode_verified(&signed, &vk, &dict).unwrap(); // fails if tampered with
```

## Usage (Python)

**The native Python wheel was retired on 2026-08-14.** quipu is now pure Rust
with **no bindings at all**: `src/python.rs`, `pyproject.toml` and the PyO3
dependency are gone. `pip install quipu-crypto` no longer corresponds to any
source in this repository, and those PyPI releases are yanked.

Why: the PyO3 chain cost 120,551 lines of dependency tree, 8 crates and — what
actually mattered — **5 of the crates that execute code at build time**, which is
the vector the npm and AUR worms used.

**What still works from Python**, and it is not the same thing: the OPRF service
client. It speaks HTTP, links nothing, and is unaffected — see «Password
hardening» below.

**If a native binding is needed again**, the decision is already taken and it is
*not* PyO3 nor a hand-written C ABI: a pure-Python wrapper talking to the quipu
binary over a pipe. Zero FFI, zero `unsafe`, and it serves any language, not just
Python.

## Runnable examples

Round-trip of every mode, ready to run:

```bash
cargo run --example quickstart          # Rust   (examples/quickstart.rs)
python examples/quickstart.py           # Python (examples/quickstart.py)
```

## Build and test

```bash
cargo test                      # unit + property tests
cargo clippy --all-targets      # lint
cargo run --example demo        # symmetric demo
cargo run --example v2demo      # post-quantum + OPRF + image
cargo run --example hackerbot --features lab   # red team
cargo run --example testplatform --features lab --release   # full battery
cargo run --example securitylab --features lab   # security lab (adaptive red team)
cargo run --example redteam --features "lab slh honey" --release   # consolidated red team (all surfaces)
bash lab/run.sh   # isolated offline bench (timing + guessing) — Stage B

# Coverage-guided fuzzing (libFuzzer, nightly). Targets: parse_container,
# honey_decrypt, unpad, codec_roundtrip.
cargo +nightly fuzz run honey_decrypt

# (the Python bindings were retired on 2026-08-14: quipu is pure Rust)
```

## Status

v1 + v1.1 + v2 + streaming AEAD (`QST1`) + honey (`QHNY`) + signatures (hybrid
Ed25519+ML-DSA-87 and triple with SLH-DSA), all implemented under strict TDD.
**380 Rust tests across 38 binaries** plus Wycheproof and 15 Python tests, all
green; clippy clean, fuzzing without crashes, Miri without UB. **Pure Rust**: the C ABI, Node, Go **and the Python wheel** are all gone — as of
2026-08-14 there is **no binding at all**. Post-quantum parameters at **NIST security
category 5 (CNSA 2.0)**: **ML-KEM-1024** and **ML-DSA-87**. Online mode with
**RFC 9497-conformant VOPRF** (ristretto255-SHA512), verified against the
**official Appendix A.1.2 vectors**, hybrid KEM with an X-Wing-style bound
transcript, **hybrid Ed25519 + ML-DSA-87 signature** (AND combiner), and an
internal **pre-audit** (see `INFORME_PREAUDITORIA.txt` and
`MODELO_DE_AMENAZA.txt`). **Security Lab** (self-hosted adaptive red team): 14
attacks in CI (`--features lab`) plus an offline timing/guessing bench
(`--features lab-offline`).

> ⚠️ Project under development. The internal pre-audit does **not** substitute for
> an **independent** cryptographic audit: do not use this to protect real
> critical data until that external seal exists.

## The family: one core, two profiles

Quipu is not a single crate: it is a **primitive-agnostic core** with thin
profiles on top that declare which cryptography they commit to.

| Crate | What it is |
|---|---|
| [`crates/padme-frame`](crates/padme-frame) | **Padmé** padding with its length frame, in a separate crate under **`MIT OR Apache-2.0`**: `no_std`, zero dependencies, usable without dragging in everything else's AGPL. It is the only piece here that is useful outside Quipu, and that is why it is the only permissively licensed one. |
| [`crates/quipu-nucleo`](crates/quipu-nucleo) | Everything that is **not** cryptography: container format, base-N codec, Reed-Solomon, the paper-carrier payload. **Zero primitives.** Padmé padding is re-exported into it from `padme-frame` — `prelayers::pad`/`unpad` stay where they were, with the same signature. |
| `quipu` (this crate) | The default profile: **XChaCha20-Poly1305**, HKDF-SHA-256, 192-bit extended nonce. |
| [`crates/quipu-cnsa`](crates/quipu-cnsa) | The **CNSA 2.0**-aligned profile: AES-256-GCM, HKDF-SHA-384, 96-bit nonce. **NOT FIPS 140-3 validated.** And its recipient channel abandons hybridization: it is **PURE ML-KEM-1024, with no classical partner**. Stronger against a quantum adversary than `quipu` and weaker against a classical lattice break — whoever picks this profile for a regulatory mandate is also accepting that change of posture, and this is where it gets chosen, so this is where it is said. |

The relationship is Devuan's to Debian: not a maintenance fork, but a **declared
commitment** that shares almost everything. The format, the codec and the visual
channel live exactly once, in the core, so **a bug is fixed once** — not two
branches diverging until one gets the patch and the other does not.

**If you can choose, use `quipu`.** The CNSA profile exists for those under a
regulatory mandate: on hardware without AES acceleration, AES-GCM is a
*regression* — slower and harder to write in constant time, because of its
substitution tables. ChaCha20 has no tables and is constant-time by construction.

## Password hardening (OPRF service)

```
Argon2 alone:  steal the DB -> offline brute force, at your GPU's speed.
With VOPRF:    steal the DB -> you derive nothing without the server key. Every
               attempt needs a request the operator sees, throttles and cuts off.
```

There is a managed instance at **`https://oprf.xiliux.com`** (beta). The client
is a separate crate and **Apache-2.0**: it does not drag this core's AGPL into
your authentication server.

```bash
pip install quipu-oprf-django   # Django: only touches PASSWORD_HASHERS
pip install quipu-voprf         # the primitives, for any other stack
```

The password leaves **blinded** (the server never sees it) and the server cannot
lie: it attaches a DLEQ proof the client verifies against a public key **pinned
out of band**. It fails closed: if the service does not answer or the proof does
not validate, it does not degrade to "unhardened".

- [`crates/quipu-voprf`](crates/quipu-voprf) — VOPRF primitives (RFC 9497), Apache-2.0
- [`crates/quipu-oprf-server`](crates/quipu-oprf-server) — the server, self-hostable
- [`integrations/`](integrations) — Django (published)

## Documentation

- [`docs/HOJA_DE_RUTA.md`](docs/HOJA_DE_RUTA.md) — **what is missing and in what
  order**, with measured status and the decisions already taken, so they are not
  reopened.
- [`docs/RAMAS.md`](docs/RAMAS.md) — the branch model (estable, testing,
  desarrollo) and why promotion is not done by hand.
- [`docs/SPEC.md`](docs/SPEC.md) — **technical specification** (container format,
  KDF, hybrid mode, VOPRF/DLEQ, domain separation).
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — threat model (EN) · original
  [`MODELO_DE_AMENAZA.txt`](MODELO_DE_AMENAZA.txt) (ES).
- [`docs/PRE_AUDIT.md`](docs/PRE_AUDIT.md) — internal pre-audit (EN) · original
  [`INFORME_PREAUDITORIA.txt`](INFORME_PREAUDITORIA.txt) (ES).
- [`SECURITY.md`](SECURITY.md) — security policy and vulnerability reporting.
- [`docs/RELEASES.md`](docs/RELEASES.md) — how to verify a release's authenticity
  (**retired 2026-08-10** — the wheels are yanked and there is no CI to sign
  anything; the source is delivered as a hybrid-signed package instead, see
  `docs/RELEASES.md`).
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to contribute ·
  [`CHANGELOG.md`](CHANGELOG.md).
- [`LICENSING.md`](LICENSING.md) — the dual licensing model.
- [`docs/announcement.md`](docs/announcement.md) — design article (EN/ES).
- [`docs/superpowers/specs/2026-07-01-quipu-security-lab-design.md`](https://github.com/isazajuancarlos/quipu/blob/estable/docs/superpowers/specs/2026-07-01-quipu-security-lab-design.md)
  — **Security Lab** design (adaptive red team, feature `lab`). Absolute link on
  purpose: that directory is excluded from the published `.crate`, so a relative
  path would 404 for anyone reading this from crates.io or docs.rs.

Most documents are in Spanish; the threat model and the pre-audit have English
versions, linked above.

> ⚠️ The internal pre-audit is preparation; it does **not** substitute for an
> independent audit. That external seal is the project's next step (an
> application has been submitted to the OTF Security Lab).

## License

A **dual licensing** (open-core) model. **Not the whole repository is AGPL**:
what a client of the OPRF service links into its own server is permissive.

| Component | License |
|---|---|
| `quipu` (core) and its bindings | `AGPL-3.0-or-later` (see `LICENSE`) |
| `crates/quipu-nucleo` (format, codec, paper carrier) | `AGPL-3.0-or-later` / commercial |
| `crates/padme-frame` (Padmé padding, `no_std`) | **`MIT OR Apache-2.0`** |
| `crates/quipu-cnsa` (CNSA 2.0 profile) | `AGPL-3.0-or-later` / commercial |
| `crates/quipu-voprf` → [`quipu-voprf`](https://pypi.org/project/quipu-voprf/) | **`Apache-2.0`** |
| `crates/quipu-oprf-server` | `AGPL-3.0-or-later` / commercial |

### What exactly is being charged for

**Quipu is free/libre and always will be.** You can use it today without paying
anything. The only condition is publishing the source of what you build on top.
If that does not work for you, we sell you an exemption from that obligation.

Put differently: **we do not charge for use, we charge for the right not to
publish.** Copyleft does not forbid charging — the GPL says literally that you
may charge any price or none; what it restricts is **secrecy**, not price.

- **Commercial license** — for closed proprietary products or SaaS without
  opening source. Terms in [`LICENSE-COMMERCIAL`](LICENSE-COMMERCIAL). It is an
  **additional and parallel** grant to the AGPL, not a replacement: with or
  without a contract you keep everything the AGPL grants anyone — use, study,
  modify, redistribute, sell, fork and even compete. All it adds is exemption
  from the network copyleft.
- **Managed OPRF server** — a different and complementary business: what is sold
  there is not an exemption but not having to operate the infrastructure or hold
  the key.

**If you can comply with the copyleft, you need not buy anything from us.** A
free-software project, an academic one, or an organization with an open-source
policy uses Quipu for free, and we want them to.

**Why AGPL and not GPL:** under plain GPL, whoever runs the software as a network
service never *distributes* it, so the copyleft never triggers. AGPL section 13
closes that gap. It was not an ideological choice.

It is the same structure as **Qt** or **MySQL**: a free license for those who
comply, a commercial license for those who need proprietary terms.

Copyright (c) 2024-2026 Juan Carlos Isaza — sole holder; see
[`COPYRIGHT`](COPYRIGHT). Use of the name "Quipu" is governed by
[`TRADEMARK.md`](TRADEMARK.md).

The VOPRF primitives live in a **separate** crate (not merely under a different
label): a wrapper's license does not relicense its dependency. Details and the
reasoning in [`LICENSING.md`](LICENSING.md) §0. Contact:
isazajuancarlos@gmail.com
