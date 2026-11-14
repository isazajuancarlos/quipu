# Introducing Quipu: reuse the wheel, innovate the track

> 🇪🇸 Versión en español: [`announcement.es.md`](announcement.es.md)

*A small Rust library for encrypting and encoding data — hybrid post-quantum,
verifiable online hardening, and an optional visual glyph channel. Built on
vetted primitives only.*

> **Status & honesty up front.** Quipu is `v0.1.0`. It is **not** audited by an
> independent third party yet, and it's my first substantial Rust project. Please
> do **not** use it to protect real secrets until it has an external audit. I'm
> publishing it now to invite review, not to claim it's production-ready. If
> you're a cryptographer or a Rust security person, tearing it apart is the most
> useful thing you can do — issues and PRs welcome.

## The one rule: never invent primitives

Most "I built my own crypto" projects fail for the same reason — they invent the
dangerous part. Quipu's guiding rule is the opposite, which I think of as
*"reuse the wheel, innovate the track"*: where good cryptography exists, reuse it
untouched; only innovate in **representation, format, and protocol composition**.

So the security-critical pieces are all standard, vetted crates:

- **AEAD:** XChaCha20-Poly1305
- **KDF:** Argon2id + HKDF-SHA256 (+ NFKC normalization, optional pepper)
- **Post-quantum KEM:** ML-KEM-1024 (FIPS-203) via the `ml-kem` crate
- **Classical KEM/DH:** X25519 (`x25519-dalek`)
- **OPRF group:** ristretto255 (`curve25519-dalek`)

There is **zero `unsafe`** in Quipu's own code. The security of memory rests on
audited dependencies; the thing worth reviewing in Quipu is the **composition**.

## What it does

```
data → KDF(passphrase + pepper) → AEAD → container → base-N codec → symbols
```

The output can be dense text, a lossless PNG, or a strip of custom **glyphs**.
The representation is public and versioned — nothing about security depends on
hiding it (Kerckhoffs). It's a *track*, not a lock.

## What's actually new (the composition)

Standard primitives, combined in ways that a hand-rolled `encrypt-then-encode`
usually doesn't bother with:

### 1. Hybrid post-quantum mode
Encrypting to a recipient's public key derives the content key from **both** an
X25519 shared secret **and** an ML-KEM-1024 shared secret, combined through HKDF
with an X-Wing-style transcript binding (the recipient's full public key —
X25519 + ML-KEM encapsulation key — is bound into the KDF). An attacker has to
break **both** to recover the key, which is the point of "harvest now, decrypt
later" resistance.

### 2. Verifiable online hardening (VOPRF)
Server-assisted password hardening usually forces the client to *trust* the
server. Quipu uses a **verifiable** OPRF over ristretto255 with a non-interactive
**DLEQ proof** (RFC 9497 style): the server publishes a public key, and every
evaluation carries a proof that it used that same key. The client verifies the
proof against a pinned public key — so a **dishonest or compromised server is
detected** and the operation aborts, instead of silently producing the wrong key.

### 3. A visual channel that isn't security theater
The same ciphertext can be rendered as a custom glyph alphabet or a PNG, with
Reed-Solomon error correction for print/photo channels. This is explicitly
**representation, not protection** — it corrects channel noise, it doesn't add
secrecy. Being loud about that distinction is part of the design.

## Engineering rigor (because "trust me" isn't enough)

I can't offer you a track record, so I'll offer discipline instead:

- **Test-driven throughout:** 89 Rust tests + Python tests, all green.
- **Google Wycheproof** known-answer vectors for the AEAD.
- **Miri** — no undefined behavior in the pure-logic modules.
- **Fuzzing** (`cargo-fuzz`) on the container/codec parsers — no crashes.
- **`cargo-audit`** in CI, on every push and weekly.
- An internal **red-team component** ("hackerbot") that already found and fixed a
  real denial-of-service bug (malicious Argon2 parameters in a tampered header).
- A written **internal pre-audit** and a **threat model** (assets, adversaries,
  per-mode guarantees, residual risks) in the repo.

None of this replaces an independent audit. It's meant to lower the cost of one.

## Try it

**Rust:**
```rust
use quipu::api::{encode, decode, Options};
use quipu::dictionaries;

let dict = dictionaries::ascii94();
let sym = encode(b"secret", "correct-horse-battery-staple", &dict, &Options::default());
let back = decode(&sym, "correct-horse-battery-staple", &dict, b"").unwrap();
assert_eq!(back, b"secret");
```
`cargo add quipu` · <https://crates.io/crates/quipu> · <https://docs.rs/quipu>

**Python:**
```python
import quipu
s = quipu.encode(b"secret", "correct-horse-battery-staple")
assert quipu.decode(s, "correct-horse-battery-staple") == b"secret"

pub, sec = quipu.generate_keypair()          # hybrid post-quantum
assert quipu.decode_as_recipient(quipu.encode_to_recipient(b"pq", pub), sec) == b"pq"
```
`pip install quipu-crypto` (imports as `quipu`) · <https://pypi.org/project/quipu-crypto/>

Runnable end-to-end examples: [`examples/quickstart.rs`](../examples/quickstart.rs)
and [`examples/quickstart.py`](../examples/quickstart.py).

## Where it's going

- Independent security audit (the gating step before recommending it for real use).
- A written spec + interoperability test vectors so others can reimplement it.
- Multi-language bindings over the C ABI (C / Node / Go).
- A reference deployment of the online VOPRF hardening server.

## Feedback wanted

If you spot a composition mistake, a domain-separation gap, a transcript that
isn't bound tightly enough, or anything that smells off — please open an issue.
For a crypto library, "many eyes" is the whole point of being open.

**Repo (AGPL-3.0):** <https://github.com/isazajuancarlos/quipu>
