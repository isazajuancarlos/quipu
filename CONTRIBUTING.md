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
# Los bindings de Python se retiraron el 2026-08-14: quipu es Rust puro y ya
# no hay nada que construir con maturin.

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

## Mutation testing before a crypto merge (`cargo-mutants`)

The test suite being green says the tests **ran**, not that they **discriminate**.
For changes to `src/blindaje.rs`, `src/pqsign.rs`, `src/kdf.rs` or `src/cipher.rs`
— the files where a silently-weakened guard costs the most — run the mutants:

    cargo mutants --features=blindaje --file src/<archivo>.rs -j 4

**What counts as passing.** Not "zero survivors": a survivor can be genuinely
equivalent (a guard the algebra makes unreachable). What counts is that **every
survivor has a written argument next to the code**, and that the argument is a
demonstration, not a reading.

**And "equivalent" is a conclusion, not a first impression.** Measured on
2026-08-17: of seven survivors in `blindaje.rs` classified as "6 equivalent + 1
cosmetic", **five were not** — they were untested behaviour, and one of them was
a reachable panic on network input. The rule that came out of it:

> Before writing "equivalent", ask **what input would tell the two versions
> apart, and why it cannot exist**. If the answer takes more than a minute,
> writing the test is cheaper than the proof.

It is not part of the local gate: it takes ~16 minutes on a single file, and a
guard that gets in the way is one somebody eventually removes. Run it by hand
before the merge, and put the numbers in the commit message.

## What a red case has to do

A test that goes red is not enough — it has to go red **for the reason it
claims**. Two real examples from this repository, both found by audit:

- A negative control used 64 zero hex bytes as a "wrong public key". Those are
  the canonical encoding of the ristretto255 **identity**, rejected by a guard
  that runs *before* the DLEQ verification. With the verification hardwired to
  `true` — switched off entirely — the control still passed.
- `header_tamper_fails` claimed to prove the stream header is bound as AAD. Its
  mutation made the KDF parameters *insane*, so it exited through range
  validation before touching the AEAD. Deleting the AAD binding altogether left
  **all eleven** tamper tests green.

So: ask which **line** makes it fail, not whether it fails. And prove it by
switching the mechanism off and requiring the test to notice.
