# Contributing to Quipu

Thanks for your interest. Quipu is a cryptography library, so contributions are
held to a deliberately strict bar — but review, testing, and design feedback are
especially welcome.

## The one non-negotiable rule

**Never invent cryptographic primitives.** Quipu's entire design philosophy is
"reuse the wheel, innovate the track": reuse vetted primitives untouched, and
only innovate in representation, format, and protocol composition. A PR that adds
a hand-rolled cipher, hash, KDF, or curve operation will be declined. New
cryptographic constructions must follow a published standard or reference
construction (e.g. RFC 9497, FIPS-203, X-Wing) and cite it.

## What is most valuable

- **Security review** of the composition (transcript binding, domain separation,
  the VOPRF/DLEQ protocol, parsing of untrusted input).
- **Additional test vectors** and interoperability tests.
- **New fuzz targets** for untrusted-input surfaces.
- **Bindings** to other languages over the C ABI.
- **Documentation** and examples.

## Development setup

```bash
# Rust toolchain via rustup; then:
cargo test                     # unit + property tests
cargo clippy --all-targets -- -D warnings
cargo run --example quickstart # end-to-end demo

# Fuzzing (nightly)
cargo +nightly fuzz run parse_container

# Python bindings
python -m venv venv && source venv/bin/activate
pip install maturin
maturin develop --features python
python tests/python/test_quipu.py

# Full local check (mirror of CI)
./scripts/audit.sh
```

## Standards for a PR

- **Test-driven.** New behavior comes with tests. Bug fixes come with a
  regression test that fails before the fix.
- **`cargo clippy --all-targets -- -D warnings` must pass** (zero warnings).
- **No `unsafe`** in first-party code.
- **Domain separation:** any new key derivation must use a unique, documented
  label.
- **Match the surrounding style** (naming, comment density, idioms).
- Keep the public API small and documented.

## Reporting security issues

Do **not** open a public issue for vulnerabilities. See
[`SECURITY.md`](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the project
license (**AGPL-3.0-or-later**). See [`LICENSING.md`](LICENSING.md) for the dual
(AGPL + commercial) model.

## Code of conduct

Be respectful and constructive. Assume good faith. Harassment or abuse is not
tolerated; maintainers may remove contributions or block accounts that violate
this.
