<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas
-->

# Export control notice — Quipu

**Status: notification SENT on 2026-07-20**, from the copyright holder's own
address, to both `crypt@bis.doc.gov` and `enc@nsa.gov`.

The §742.15(b) exclusion is therefore perfected. It must be **re-sent when the
cryptographic functionality changes** — §3 says what does and does not trigger
that.

Quipu is published on GitHub, crates.io, PyPI and npm — all US infrastructure —
so the US Export Administration Regulations (EAR) are the relevant regime,
regardless of the author being Colombian and the code being written in Colombia.

---

## 1. Classification

| | |
|---|---|
| ECCN | **5D002** — "Information Security" software |
| Basis for exclusion | **§742.15(b)** — publicly available encryption source code |
| Licence exception used | None required once the notification is filed |
| Object code | Compiled artefacts from publicly available source (wheels, npm packages, crates) fall under the same exclusion |

Publicly available encryption **source code** is not subject to the EAR under
§742.15(b), but only **once the notification has been sent**. Until then, the
exclusion has not been perfected.

---

## 2. Why this is genuinely ambiguous, and why we file anyway

Since the 2021 revision, the notification is required only for source code
implementing **"non-standard cryptography"** — defined as cryptography using
"an unpublished algorithm or an algorithm not adopted by an international
standards body".

**Quipu's primitives are all standard**, without exception:

| Role | Primitive | Standard |
|---|---|---|
| AEAD | XChaCha20-Poly1305 | RFC 8439 (+ XChaCha extension) |
| Post-quantum KEM | ML-KEM-1024 | FIPS 203 |
| Post-quantum signature | ML-DSA-87 | FIPS 204 |
| Hash-based signature (`slh`) | SLH-DSA-SHA2-256s | FIPS 205 |
| Classical KEM/DH | X25519 | RFC 7748 |
| Classical signature | Ed25519 | RFC 8032 |
| Password hashing | Argon2id | RFC 9106 |
| KDF | HKDF-SHA256 | RFC 5869 |
| OPRF | ristretto255 | RFC 9497 |
| Secret sharing (`escrow`) | Shamir over GF(2⁸) | Shamir 1979 |

**But two constructions are our own composition**, and that is what makes the
classification arguable rather than obvious:

1. **The hybrid KEM combiner.** `SPEC.md` §7.2 documents it as *"X-Wing style,
   not interoperable X-Wing"*: it follows the X-Wing design principle but is
   **not** wire-compatible with `draft-connolly-cfrg-xwing-kem` — Quipu uses
   ML-KEM-1024 instead of 768 and HKDF-SHA256 instead of a single SHA3-256
   combiner. A composition of standard primitives that no standards body has
   adopted **as that composition**.

2. **The container format** (`SPEC.md` §3.2), the Padmé padding layer, the
   base-N codec and the glyph channel. All published and documented here, none
   adopted by a standards body.

A reasonable person can argue either way: *"every primitive is standard, so this
is standard cryptography"* against *"the combiner is an unpublished construction,
so it is non-standard"*.

**We file the notification.** It costs one email, it is harmless if unnecessary,
and it removes the ambiguity whichever way the classification would resolve.
Arguing the point after the fact costs incomparably more than sending it in
advance.

---

## 3. What the notification must contain

Per §742.15(b)(1), the notification must give the **internet location** of the
source code (URL), or the code itself, and it must be sent to **both** addresses
below.

It must be **re-sent when the cryptographic functionality changes** — not for
every release, but whenever a primitive is added, removed or replaced.

Changes that would trigger a re-notification, given the current roadmap:

- adding AES-256-GCM and SHA-384 (a CNSA 2.0 profile — see `CNSA.md`);
- adding LMS or XMSS for software signing;
- any change to the hybrid combiner in `SPEC.md` §7.2.

Changes that would **not**: version bumps, the fallible-RNG refactor, glyph
recognition, anything in the `lab` feature (which is never shipped).

---

## 4. Draft notification

> **To:** `crypt@bis.doc.gov`, `enc@nsa.gov`
> **Subject:** Notification of publicly available encryption source code — 15 CFR §742.15(b) — Quipu
>
> To whom it may concern,
>
> Pursuant to 15 CFR §742.15(b), this is notification of publicly available
> encryption source code.
>
> **Product name:** Quipu — a hybrid post-quantum cryptographic codec
> **ECCN:** 5D002
> **Author / copyright holder:** Juan Carlos Isaza Arenas (Medellín, Colombia)
> **Licence:** GNU AGPL-3.0-or-later, with a commercial licence available
>
> **Internet location of the source code:**
> `https://github.com/isazajuancarlos/quipu`
>
> The same source code is distributed in package form at:
> - crates.io — `quipu` and `quipu-voprf`
> - PyPI — `quipu-crypto`
> - npm — `quipu-crypto`
>
> **Cryptographic functionality.** The software implements standard,
> published algorithms: ML-KEM-1024 (FIPS 203), ML-DSA-87 (FIPS 204),
> SLH-DSA-SHA2-256s (FIPS 205), X25519 (RFC 7748), Ed25519 (RFC 8032),
> XChaCha20-Poly1305 (RFC 8439 with the XChaCha extension), Argon2id
> (RFC 9106), HKDF-SHA256 (RFC 5869), a verifiable OPRF over ristretto255
> (RFC 9497) and Shamir secret sharing.
>
> It additionally defines a hybrid KEM combiner which follows the X-Wing design
> principle but is not wire-compatible with `draft-connolly-cfrg-xwing-kem`, and
> a container format of its own. Both are fully documented in the public
> specification at `docs/SPEC.md` in the repository above. This notification is
> submitted irrespective of whether those compositions are considered
> "non-standard cryptography".
>
> No encryption functionality is withheld from the published source.
>
> Please direct any questions to the address below.
>
> Juan Carlos Isaza Arenas
> `isazajuancarlos@gmail.com`

---

## 5. What was settled before sending

Sending was irreversible and outward-facing: a filing with a US government
agency under the author's own name. These points were decided first, and are
recorded because any re-notification has to hold to the same choices:

1. **The name and address.** The notification is filed as Isaza Arenas, the
   natural person — Xiliux is not a legal entity and must not appear as filer.
   Confirm the contact email is the one you want on a government record.
2. **The repository is public and will stay public.** The exclusion rests on
   public availability; taking the repo private later would undo its basis.
3. **Whether to mention the commercial licence at all.** It is included above
   because dual licensing does not affect public availability of the source, and
   omitting it could look like a material omission. It can be removed if you
   prefer a narrower filing.
4. **Keep the sent copy.** Archive the email with its date. The filing is the
   evidence; there is no acknowledgement to rely on.

Sent 2026-07-20. Cross-referenced from `SECURITY.md`.

**Keep the sent copy archived.** Neither agency acknowledges receipt: the filing
itself is the evidence.
