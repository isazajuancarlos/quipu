# Security Policy

## Status: not yet independently audited

Quipu is `v0.15.1`. It composes only vetted cryptographic primitives and never
invents its own, but the **composition has not yet been reviewed by an
independent third party**. An external audit is the project's top priority: a
free audit was requested through the Open Technology Fund's Security Lab in
**June 2026** (request #22572), and is currently in their queue.

**Do not use Quipu to protect real, high-value secrets until it has an
independent security audit.** Until then, treat it as pre-release software for
review and experimentation.

## Reporting a vulnerability

If you believe you have found a security vulnerability, please report it
**privately**. Do **not** open a public issue for security problems.

- Email: **isazajuancarlos@gmail.com** with the subject line `SECURITY: quipu`.
- If possible, use GitHub's private vulnerability reporting:
  <https://github.com/isazajuancarlos/quipu/security/advisories/new>

Please include:
- A description of the issue and its impact.
- Steps to reproduce or a proof of concept.
- The affected version/commit.

You will get an acknowledgement as quickly as possible. Coordinated disclosure is
appreciated: please give a reasonable window to fix before public disclosure.

## What is in scope

Because the primitives are vetted crates and there is no `unsafe` in first-party
code, the meaningful attack surface is the **composition**:

- The hybrid post-quantum KEM combiner (X25519 + ML-KEM-1024) and its transcript
  binding.
- The verifiable OPRF (VOPRF) and its DLEQ proof, and the online protocol.
- Parsing of untrusted input (container header, PNG/glyph decoders).
- Key derivation, domain separation, and key zeroization.
- AEAD/KDF usage (nonce handling, AAD binding, KDF-parameter validation).

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ (pre-release; security fixes) |

## Cryptographic design principle

Security lives in the keys and the vetted primitives, **never** in hiding the
format or the symbol representation (Kerckhoffs's principle). A report that relies
on the representation being secret is not a vulnerability by design.

The corollary is that **every byte of the format is public and every
cryptographic constant is stated with where it comes from** — there is nothing to
hide, so there is no excuse for a magic number without a citation.

## Every constant with its provenance

A constant in a cryptographic codec is one of two things, never a third:

1. **Dictated by a named standard.** The primitive fixes it, and the only honest
   value is the one the standard mandates. These are cited to their RFC or FIPS
   publication.
2. **A measured or scoped decision.** No standard fixes it; we chose it, and the
   reasoning is recorded next to the choice — never a bare number.

There is no "constant we just picked": if a value cannot be traced to a standard
or to a written decision, that is itself a security finding worth reporting.

The single source of truth for the values and their origin is the technical
specification. It is not restated from memory here; the format it fixes is in
turn frozen by the deterministic known-answer vectors, which are **recomputed
against the code on every `cargo test`** (§14), so a number that drifts from the
implementation breaks the build:

- [`docs/SPEC.md` §2 — Primitives](docs/SPEC.md): each primitive with its crate
  and its RFC/FIPS reference (Argon2id/RFC 9106, HKDF/RFC 5869, XChaCha20-Poly1305
  from RFC 8439 + the XChaCha extended-nonce construction, ML-KEM-1024/FIPS-203,
  ML-DSA-87/FIPS-204, SLH-DSA/FIPS-205, Ed25519/RFC 8032, VOPRF/RFC 9497).
- [`docs/SPEC.md` §12 — Domain-separation labels](docs/SPEC.md): every HKDF/hash
  `info`/context string and what separates it from the others.
- [`docs/SPEC.md` §13 — Constants](docs/SPEC.md): sizes, magics, versions and KDF
  cost values, each with the standard or the decision it derives from.
- The **source modules** carry the reasoning inline where a value is a decision
  rather than a mandate — e.g. `src/kdf.rs` (`MAX_MEM_KIB` = 256 MiB, the
  anti-amplification bound, and the canonical cost ladder 16/64/256 MiB, both
  argued against `docs/THREAT_MODEL.md` N9) and `crates/quipu-cnsa/src/kdf.rs`
  (why HKDF-**SHA-384** and not SHA-512, per CNSA 2.0).

The CNSA-alignment profile (`quipu-cnsa`) states its own constants and their
CNSA 2.0 provenance in [`docs/CNSA.md`](docs/CNSA.md); the deniability, streaming
and honey-encryption modes state theirs in their own design notes.

See [`docs/SPEC.md`](docs/SPEC.md) for the full technical specification,
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full threat model, and
[`docs/PRE_AUDIT.md`](docs/PRE_AUDIT.md) for the internal pre-audit.

## Export control

Quipu is publicly available encryption source code, ECCN 5D002, excluded from
the EAR under 15 CFR §742.15(b). The classification, the reasoning — including
why the case is arguable rather than obvious — and the notification itself are
in [`docs/EXPORT.md`](docs/EXPORT.md).
