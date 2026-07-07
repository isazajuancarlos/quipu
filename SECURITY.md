# Security Policy

## Status: not yet independently audited

Quipu is `v0.7.0`. It composes only vetted cryptographic primitives and never
invents its own, but the **composition has not yet been reviewed by an
independent third party**. An external audit is the project's top priority (a
free audit has been requested through OTF's Security Lab).

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

- The hybrid post-quantum KEM combiner (X25519 + ML-KEM-768) and its transcript
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

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full threat model and
[`docs/PRE_AUDIT.md`](docs/PRE_AUDIT.md) for the internal pre-audit.
