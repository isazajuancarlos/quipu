# Posts cortos para difusión

Versiones listas para pegar. Tono honesto (la comunidad cripto castiga el
overclaiming; la franqueza sobre "no auditado / primer proyecto / revísenlo"
juega a favor). Dónde publicar: r/rust, Hacker News (Show HN), lobste.rs,
Mastodon/Bluesky, y enlazar el artículo largo (`docs/announcement.md`).

---

## Show HN (título + primer comentario)

**Título:**
> Show HN: Quipu – a post-quantum encoding library in Rust (reuse the wheel, innovate the track)

**Primer comentario (contexto honesto):**
> I built Quipu, a small Rust library (also on PyPI) for encrypt-then-encode.
> The rule I set myself: never invent primitives — it only uses vetted crates
> (XChaCha20-Poly1305, Argon2id, HKDF, X25519, ML-KEM-768, ristretto255). The
> parts I think are interesting are the *composition*: a hybrid post-quantum mode
> (X25519 + ML-KEM-768, X-Wing-style transcript binding), a *verifiable* online
> password-hardening mode (VOPRF + DLEQ, so the client can detect a dishonest
> server), and an optional visual glyph channel (representation, not security).
>
> Honesty first: it's v0.1.0, my first substantial Rust project, and NOT audited
> by a third party yet — please don't protect real secrets with it. I'm posting
> to get review, not to claim it's production-ready. There's an internal pre-audit
> and threat model in the repo, plus Wycheproof vectors, Miri, fuzzing, and zero
> unsafe in my own code. If you do crypto or Rust security, tearing the
> composition apart is the most useful thing you could do.
>
> Repo: https://github.com/isazajuancarlos/quipu

---

## r/rust

**Título:**
> Quipu: post-quantum encrypt-then-encode library — vetted primitives only, looking for review

**Cuerpo:**
> `cargo add quipu` / `pip install quipu-crypto`
>
> A library for protecting and encoding data that composes only vetted primitives
> (never rolls its own crypto). Highlights:
> - Hybrid post-quantum KEM (X25519 + ML-KEM-768, FIPS-203), X-Wing-style binding
> - Verifiable OPRF online hardening (DLEQ proofs — client detects a dishonest server)
> - Optional visual/glyph + PNG channel (Kerckhoffs: representation ≠ security)
> - 0 `unsafe`, TDD (89 tests), Wycheproof, Miri, fuzzing, internal pre-audit + threat model
>
> Caveats, said plainly: v0.1.0, first serious Rust project, **not externally
> audited** — not for real secrets yet. I'd genuinely value review of the
> composition (transcript binding, domain separation, the VOPRF protocol).
>
> Repo: https://github.com/isazajuancarlos/quipu · docs.rs/quipu

---

## Mastodon / Bluesky (corto)

> Quipu v0.1.0: a Rust library for post-quantum encrypt-then-encode. Vetted
> primitives only (ML-KEM-768 + X25519, XChaCha20-Poly1305, verifiable OPRF).
> First project, not audited yet — review very welcome.
> 🦀 crates.io/crates/quipu · 🐍 pip install quipu-crypto
> https://github.com/isazajuancarlos/quipu

---

## Nota de estrategia
- No lo publiques todo el mismo día; empieza por r/rust (feedback técnico amable),
  ajusta según respuestas, y luego Show HN.
- Responde a TODO comentario técnico con humildad; un buen hilo de discusión vale
  más que los upvotes para la reputación.
- Enlaza siempre el pre-audit y el threat model: demuestran seriedad.
