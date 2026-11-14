# SLH-DSA Triple-Hybrid Signature — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in `Ed25519 + ML-DSA-87 + SLH-DSA-SHA2-256s` triple-hybrid signature mode (AND 3-of-3) in a new `QSG3` container, behind a non-default `slh` Cargo feature, without touching the existing double-hybrid mode or v0.4.x artifacts.

**Architecture:** A parallel API and parallel key types (`TripleVerifyingKey` / `TripleSigningKey`) live in `src/pqsign.rs` under `#[cfg(feature = "slh")]`, mirroring the existing double-hybrid types. `src/api.rs` gains `encode_signed_triple` / `decode_verified_triple` over a new `QSG3` container that reuses the hardened (checked-arithmetic) parsing of `decode_verified`. The Security Lab (`src/lab/forge.rs`) gains 3-of-3 forgery coverage. The suite is determined by the key *type* — there is no in-band suite negotiation and thus no downgrade surface.

**Tech Stack:** Rust (edition 2024), `fips205` v0.4.1 (integritychain, pure-Rust FIPS-205; chosen over RustCrypto `slh-dsa` v0.1.0 because the latter pulls a `signature` prerelease that conflicts with `ed25519-dalek`/`ml-dsa`), `ed25519-dalek`, `ml-dsa`, `zeroize`.

## Global Constraints

- Edition 2024; **zero `unsafe`** in first-party code.
- **Compose vetted crates only** — never invent or reimplement a primitive.
- New mode is **strictly additive**: `pqsign::{SigningKey, VerifyingKey}`, `api::{encode_signed, decode_verified}` and the `QSG1` container are unchanged; v0.4.x artifacts still verify.
- All new code is gated behind `#[cfg(feature = "slh")]`; the default build and the PyPI wheel must not compile it.
- Domain-separation label for the triple mode is exactly `b"quipu/v4/sign-triple"`.
- Parameter set is exactly **SLH-DSA-SHA2-256s** (`slh_dsa::Sha2_256s`, NIST level 5).
- Fixed sizes (FIPS-205): `SLH_PUB_LEN = 64`, `SLH_SECRET_LEN = 128`, `SLH_SIG_LEN = 29_792`, `TRIPLE_VERIFYING_KEY_LEN = 2_688`, `TRIPLE_SIGNING_KEY_LEN = 192`, `TRIPLE_SIGNATURE_LEN = 34_483`.
- Every `cargo` invocation in this environment must be prefixed with `export PATH="$HOME/.cargo/bin:$PATH";`.
- Branch: `feat/phase1-slh-triple` (already created). Do **not** tag or publish — release is a separate, gated step.
- **Run all `slh` tests in `--release`.** SLH-DSA-256s signing takes ~40 s in a debug build and ~2 s optimized; every `cargo test --features slh …` command below must add `--release`.
- **`fips205` serialization:** `into_bytes()` consumes the key and returns a fixed `[u8; N]`; parse back with `PublicKey::try_from_bytes(&[u8; PK_LEN])` / `PrivateKey::try_from_bytes(&[u8; SK_LEN])`. `verify(msg, sig, ctx)` takes `sig: &[u8; SIG_LEN]` — convert a slice with `slice.try_into()` (yields `&[u8; N]`). The stored lengths (64/128/29_792) are fixed by the `PK_LEN`/`SK_LEN`/`SIG_LEN` consts.

---

### Task 1: Wire up the `slh` feature and lock the SLH-DSA-256s API + sizes

**Files:**
- Modify: `Cargo.toml` (dependencies + `[features]`)
- Modify: `src/pqsign.rs` (append a `#[cfg(feature = "slh")]` block with constants + a spike test)

**Interfaces:**
- Produces: constants `SLH_PUB_LEN`, `SLH_SECRET_LEN`, `SLH_SIG_LEN`, `TRIPLE_VERIFYING_KEY_LEN`, `TRIPLE_SIGNING_KEY_LEN`, `TRIPLE_SIGNATURE_LEN`; establishes the exact `slh-dsa` call sites (keygen via `OsRng`, `sign`, `verify`, `to_bytes`/`try_from`) that later tasks reuse.

- [ ] **Step 1: Add the optional dependency and feature**

In `Cargo.toml`, under `[dependencies]` add:
```toml
slh-dsa = { version = "0.1.0", optional = true }
```
Under `[features]` add (keep the existing `lab` / `lab-offline` lines):
```toml
# Firma triple-híbrida de alta garantía (Ed25519 + ML-DSA-87 + SLH-DSA).
# NO-default: la firma pesa ~34 KB y no debe compilarse siempre.
slh = ["dep:slh-dsa"]
```

- [ ] **Step 2: Add the SLH/triple size constants and a spike test to `src/pqsign.rs`**

Append at the end of `src/pqsign.rs` (outside the existing `#[cfg(test)] mod tests`):
```rust
// ---------------------------------------------------------------------------
// Fase 1: firma triple-híbrida (Ed25519 + ML-DSA-87 + SLH-DSA-SHA2-256s).
// Opt-in tras la feature `slh`. Aditivo: el modo doble de arriba no cambia.
// ---------------------------------------------------------------------------
#[cfg(feature = "slh")]
use slh_dsa::{
    Sha2_256s, Signature as SlhSignature, SigningKey as SlhSigningKey,
    VerifyingKey as SlhVerifyingKey,
};
#[cfg(feature = "slh")]
use slh_dsa::signature::{Keypair as _, Signer as _, Verifier as _};

/// Longitud de la clave pública SLH-DSA-SHA2-256s.
#[cfg(feature = "slh")]
pub const SLH_PUB_LEN: usize = 64;
/// Longitud de la clave secreta SLH-DSA-SHA2-256s (serializada).
#[cfg(feature = "slh")]
pub const SLH_SECRET_LEN: usize = 128;
/// Longitud de la firma SLH-DSA-SHA2-256s.
#[cfg(feature = "slh")]
pub const SLH_SIG_LEN: usize = 29_792;

/// Clave de verificación triple serializada (Ed25519 || ML-DSA || SLH-DSA).
#[cfg(feature = "slh")]
pub const TRIPLE_VERIFYING_KEY_LEN: usize = ED25519_PUB_LEN + MLDSA_VK_LEN + SLH_PUB_LEN; // 2688
/// Clave de firma triple serializada (Ed25519 seed || ML-DSA seed || SLH sk). ¡Sensible!
#[cfg(feature = "slh")]
pub const TRIPLE_SIGNING_KEY_LEN: usize = ED25519_SEED_LEN + MLDSA_SEED_LEN + SLH_SECRET_LEN; // 192
/// Firma triple (Ed25519 || ML-DSA || SLH-DSA).
#[cfg(feature = "slh")]
pub const TRIPLE_SIGNATURE_LEN: usize = ED25519_SIG_LEN + MLDSA_SIG_LEN + SLH_SIG_LEN; // 34483

/// Etiqueta de dominio del modo triple. Distinta de `quipu/v3/sign`.
#[cfg(feature = "slh")]
const SIGN_TRIPLE_CONTEXT: &[u8] = b"quipu/v4/sign-triple";

#[cfg(all(test, feature = "slh"))]
mod triple_spike {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn slh_dsa_256s_sizes_and_roundtrip() {
        // Bloquea la API y los tamaños del param set antes de componer.
        let sk = SlhSigningKey::<Sha2_256s>::new(&mut OsRng);
        let vk = sk.verifying_key();

        let vk_bytes = vk.to_bytes();
        assert_eq!(vk_bytes.as_slice().len(), SLH_PUB_LEN, "SLH vk len");

        let sk_bytes = sk.to_bytes();
        assert_eq!(sk_bytes.as_slice().len(), SLH_SECRET_LEN, "SLH sk len");

        let sig = sk.sign(b"spike");
        let sig_bytes = sig.to_bytes();
        assert_eq!(sig_bytes.as_slice().len(), SLH_SIG_LEN, "SLH sig len");

        // Round-trip de serialización y verificación.
        let vk2 = SlhVerifyingKey::<Sha2_256s>::try_from(vk_bytes.as_slice()).unwrap();
        let sig2 = SlhSignature::<Sha2_256s>::try_from(sig_bytes.as_slice()).unwrap();
        assert!(vk2.verify(b"spike", &sig2).is_ok());
        assert!(vk2.verify(b"otro", &sig2).is_err());
    }
}
```

- [ ] **Step 3: Run the spike test and let the compiler pin the exact API**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --features slh triple_spike -- --nocapture`
Expected: PASS. If a `to_bytes()`/`try_from` call does not compile, adjust the slice conversion (`.as_slice()` vs `.as_ref()` vs `&x[..]`) to satisfy the compiler — the asserted **lengths must stay** `64 / 128 / 29_792`. If a length assert fails, STOP: the param set or crate version is wrong.

- [ ] **Step 4: Verify the default build is unaffected**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo build && cargo test --lib pqsign`
Expected: PASS — the default build does not compile any `slh` code.

- [ ] **Step 5: Commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
git add Cargo.toml Cargo.lock src/pqsign.rs
git commit -m "feat(pqsign): add slh feature + SLH-DSA-256s size constants (spike)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Triple key types, keygen, serialization, and sign/verify round-trip

**Files:**
- Modify: `src/pqsign.rs` (append triple types + impls, still under `#[cfg(feature = "slh")]`)

**Interfaces:**
- Consumes: constants and `slh-dsa` imports from Task 1.
- Produces:
  - `pub struct TripleVerifyingKey` with `verify(&self, message: &[u8], signature: &[u8]) -> bool`, `to_bytes(&self) -> Vec<u8>`, `from_bytes(b: &[u8]) -> Option<Self>`.
  - `pub struct TripleSigningKey` with `verifying_key(&self) -> TripleVerifyingKey`, `sign(&self, message: &[u8]) -> Vec<u8>`, `to_bytes(&self) -> Zeroizing<Vec<u8>>`, `from_bytes(b: &[u8]) -> Option<Self>`.
  - `pub fn generate_triple_keypair() -> (TripleVerifyingKey, TripleSigningKey)`.
  - `fn build_triple_preimage(vk_bytes: &[u8], message: &[u8]) -> Vec<u8>`.

- [ ] **Step 1: Write the failing round-trip test**

Append inside a new test module at the end of `src/pqsign.rs`:
```rust
#[cfg(all(test, feature = "slh"))]
mod triple_tests {
    use super::*;

    #[test]
    fn triple_sign_verify_round_trips() {
        let (vk, sk) = generate_triple_keypair();
        let msg = b"documento de altisimo valor";
        let sig = sk.sign(msg);
        assert_eq!(sig.len(), TRIPLE_SIGNATURE_LEN);
        assert!(vk.verify(msg, &sig));
    }

    #[test]
    fn triple_parameters_are_level5() {
        assert_eq!(SLH_SIG_LEN, 29_792);
        assert_eq!(TRIPLE_VERIFYING_KEY_LEN, 2_688);
        assert_eq!(TRIPLE_SIGNING_KEY_LEN, 192);
        assert_eq!(TRIPLE_SIGNATURE_LEN, 34_483);
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --features slh triple_sign_verify_round_trips`
Expected: FAIL — `generate_triple_keypair`, `TripleVerifyingKey`, `TripleSigningKey` not found.

- [ ] **Step 3: Implement the triple types and operations**

Append to `src/pqsign.rs` (before the test modules), under the same `#[cfg(feature = "slh")]` gate:
```rust
/// Clave de verificación triple-híbrida (pública).
#[cfg(feature = "slh")]
pub struct TripleVerifyingKey {
    ed: EdVerifyingKey,
    ml: MlVerifyingKey<MlDsa87>,
    slh: SlhVerifyingKey<Sha2_256s>,
}

/// Clave de firma triple-híbrida (secreta). Ed25519/ML-DSA como semillas de 32 B;
/// SLH-DSA como sus bytes de clave secreta (la API no expone keygen desde semilla).
/// Todo el material se borra al soltarse.
#[cfg(feature = "slh")]
pub struct TripleSigningKey {
    ed_seed: Zeroizing<[u8; ED25519_SEED_LEN]>,
    ml_seed: Zeroizing<[u8; MLDSA_SEED_LEN]>,
    slh_sk: Zeroizing<[u8; SLH_SECRET_LEN]>,
}

/// Genera un par de claves triple-híbrido.
#[cfg(feature = "slh")]
pub fn generate_triple_keypair() -> (TripleVerifyingKey, TripleSigningKey) {
    use rand_core::OsRng;
    let mut ed_seed = [0u8; ED25519_SEED_LEN];
    let mut ml_seed = [0u8; MLDSA_SEED_LEN];
    getrandom::getrandom(&mut ed_seed).expect("RNG del sistema");
    getrandom::getrandom(&mut ml_seed).expect("RNG del sistema");

    let slh_signing = SlhSigningKey::<Sha2_256s>::new(&mut OsRng);
    let mut slh_sk = [0u8; SLH_SECRET_LEN];
    slh_sk.copy_from_slice(slh_signing.to_bytes().as_slice());

    let sk = TripleSigningKey {
        ed_seed: Zeroizing::new(ed_seed),
        ml_seed: Zeroizing::new(ml_seed),
        slh_sk: Zeroizing::new(slh_sk),
    };
    let vk = sk.verifying_key();
    (vk, sk)
}

#[cfg(feature = "slh")]
fn slh_signing_key(sk_bytes: &[u8; SLH_SECRET_LEN]) -> SlhSigningKey<Sha2_256s> {
    SlhSigningKey::<Sha2_256s>::try_from(&sk_bytes[..]).expect("clave secreta SLH de 128 bytes")
}

#[cfg(feature = "slh")]
impl TripleSigningKey {
    /// Deriva la clave de verificación (pública) correspondiente.
    pub fn verifying_key(&self) -> TripleVerifyingKey {
        let ed = EdSigningKey::from_bytes(&self.ed_seed).verifying_key();
        let ml = ml_signing_key(&self.ml_seed).verifying_key();
        let slh = slh_signing_key(&self.slh_sk).verifying_key();
        TripleVerifyingKey { ed, ml, slh }
    }

    /// Firma `message` con las tres primitivas sobre la misma preimagen.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let vk = self.verifying_key();
        let preimage = build_triple_preimage(&vk.to_bytes(), message);

        let ed_sig = EdSigningKey::from_bytes(&self.ed_seed).sign(&preimage);
        let ml_sig = ml_signing_key(&self.ml_seed).sign(&preimage);
        let slh_sig = slh_signing_key(&self.slh_sk).sign(&preimage);

        let mut out = Vec::with_capacity(TRIPLE_SIGNATURE_LEN);
        out.extend_from_slice(&ed_sig.to_bytes());
        out.extend_from_slice(ml_sig.encode().as_slice());
        out.extend_from_slice(slh_sig.to_bytes().as_slice());
        out
    }

    /// Serializa la clave de firma (ed seed || ml seed || slh sk). ¡Sensible!
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Vec::with_capacity(TRIPLE_SIGNING_KEY_LEN);
        v.extend_from_slice(self.ed_seed.as_ref());
        v.extend_from_slice(self.ml_seed.as_ref());
        v.extend_from_slice(self.slh_sk.as_ref());
        Zeroizing::new(v)
    }

    /// Reconstruye la clave de firma desde bytes.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != TRIPLE_SIGNING_KEY_LEN {
            return None;
        }
        let ed_seed: [u8; ED25519_SEED_LEN] = b[0..ED25519_SEED_LEN].try_into().ok()?;
        let ml_start = ED25519_SEED_LEN;
        let ml_seed: [u8; MLDSA_SEED_LEN] =
            b[ml_start..ml_start + MLDSA_SEED_LEN].try_into().ok()?;
        let slh_start = ml_start + MLDSA_SEED_LEN;
        let slh_sk: [u8; SLH_SECRET_LEN] = b[slh_start..].try_into().ok()?;
        Some(TripleSigningKey {
            ed_seed: Zeroizing::new(ed_seed),
            ml_seed: Zeroizing::new(ml_seed),
            slh_sk: Zeroizing::new(slh_sk),
        })
    }
}

#[cfg(feature = "slh")]
impl TripleVerifyingKey {
    /// Verifica una firma triple. `true` sólo si las TRES validan (AND 3-de-3).
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        if signature.len() != TRIPLE_SIGNATURE_LEN {
            return false;
        }
        let preimage = build_triple_preimage(&self.to_bytes(), message);

        let (ed_sig_bytes, rest) = signature.split_at(ED25519_SIG_LEN);
        let (ml_sig_bytes, slh_sig_bytes) = rest.split_at(MLDSA_SIG_LEN);

        // Ed25519 (verify_strict rechaza orden pequeño y maleabilidad).
        let ed_arr: [u8; ED25519_SIG_LEN] = match ed_sig_bytes.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let ed_ok = self
            .ed
            .verify_strict(&preimage, &EdSignature::from_bytes(&ed_arr))
            .is_ok();

        // ML-DSA-87.
        let ml_ok = match EncodedSignature::<MlDsa87>::try_from(ml_sig_bytes) {
            Ok(enc) => match MlSignature::<MlDsa87>::decode(&enc) {
                Some(sig) => self.ml.verify(&preimage, &sig).is_ok(),
                None => false,
            },
            Err(_) => false,
        };

        // SLH-DSA-256s.
        let slh_ok = match SlhSignature::<Sha2_256s>::try_from(slh_sig_bytes) {
            Ok(sig) => self.slh.verify(&preimage, &sig).is_ok(),
            Err(_) => false,
        };

        ed_ok && ml_ok && slh_ok
    }

    /// Serializa la clave de verificación (Ed25519 pub || ML-DSA vk || SLH vk).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(TRIPLE_VERIFYING_KEY_LEN);
        v.extend_from_slice(self.ed.as_bytes());
        v.extend_from_slice(self.ml.encode().as_slice());
        v.extend_from_slice(self.slh.to_bytes().as_slice());
        v
    }

    /// Reconstruye la clave de verificación desde bytes.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != TRIPLE_VERIFYING_KEY_LEN {
            return None;
        }
        let ed_bytes: [u8; ED25519_PUB_LEN] = b[0..ED25519_PUB_LEN].try_into().ok()?;
        let ed = EdVerifyingKey::from_bytes(&ed_bytes).ok()?;
        let ml_start = ED25519_PUB_LEN;
        let ml_enc =
            EncodedVerifyingKey::<MlDsa87>::try_from(&b[ml_start..ml_start + MLDSA_VK_LEN]).ok()?;
        let ml = MlVerifyingKey::<MlDsa87>::decode(&ml_enc);
        let slh_start = ml_start + MLDSA_VK_LEN;
        let slh = SlhVerifyingKey::<Sha2_256s>::try_from(&b[slh_start..]).ok()?;
        Some(TripleVerifyingKey { ed, ml, slh })
    }
}

/// Preimagen triple: etiqueta de dominio || clave pública triple completa || mensaje.
#[cfg(feature = "slh")]
fn build_triple_preimage(vk_bytes: &[u8], message: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(SIGN_TRIPLE_CONTEXT.len() + vk_bytes.len() + message.len());
    p.extend_from_slice(SIGN_TRIPLE_CONTEXT);
    p.extend_from_slice(vk_bytes);
    p.extend_from_slice(message);
    p
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --features slh triple_`
Expected: PASS (`triple_sign_verify_round_trips`, `triple_parameters_are_level5`, and the Task 1 spike).

- [ ] **Step 5: Clippy clean under the feature**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo clippy --features slh --all-targets -- -D warnings`
Expected: no warnings.

- [ ] **Step 6: Commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
git add src/pqsign.rs
git commit -m "feat(pqsign): triple-hybrid keys, keygen, sign/verify round-trip

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Negative & AND-combiner security tests

**Files:**
- Modify: `src/pqsign.rs` (extend `mod triple_tests`)

**Interfaces:**
- Consumes: all public triple API from Task 2. Adds no new production API; these tests must pass against the Task 2 implementation as written (if any fails, the bug is in Task 2 — fix it there).

- [ ] **Step 1: Write the failing security tests**

Add inside `mod triple_tests`:
```rust
    #[test]
    fn triple_tampered_message_fails() {
        let (vk, sk) = generate_triple_keypair();
        let sig = sk.sign(b"pagar 100");
        assert!(!vk.verify(b"pagar 900", &sig));
    }

    #[test]
    fn triple_tampered_signature_fails() {
        let (vk, sk) = generate_triple_keypair();
        let msg = b"mensaje";
        // Voltear un bit en CADA uno de los tres componentes por separado.
        for pos in [0, ED25519_SIG_LEN + 10, ED25519_SIG_LEN + MLDSA_SIG_LEN + 10] {
            let mut sig = sk.sign(msg);
            sig[pos] ^= 0x01;
            assert!(!vk.verify(msg, &sig), "flip en offset {pos} debio fallar");
        }
    }

    #[test]
    fn triple_wrong_key_fails() {
        let (_vk, sk) = generate_triple_keypair();
        let (vk2, _sk2) = generate_triple_keypair();
        let sig = sk.sign(b"mensaje");
        assert!(!vk2.verify(b"mensaje", &sig));
    }

    #[test]
    fn triple_and_combiner_rejects_swapped_component() {
        // Sustituir CADA componente por el de otra firma (misma msg, otra clave)
        // debe fallar: el AND 3-de-3 exige que los tres validen bajo la MISMA vk.
        let (vk, sk) = generate_triple_keypair();
        let (_vk2, sk2) = generate_triple_keypair();
        let msg = b"mensaje";
        let sig = sk.sign(msg);
        let other = sk2.sign(msg);

        let ed_end = ED25519_SIG_LEN;
        let ml_end = ED25519_SIG_LEN + MLDSA_SIG_LEN;

        // (a) Ed25519 de sk2, resto de sk.
        let mut a = other[..ed_end].to_vec();
        a.extend_from_slice(&sig[ed_end..]);
        assert!(!vk.verify(msg, &a), "swap Ed25519");

        // (b) ML-DSA de sk2, resto de sk.
        let mut b = sig[..ed_end].to_vec();
        b.extend_from_slice(&other[ed_end..ml_end]);
        b.extend_from_slice(&sig[ml_end..]);
        assert!(!vk.verify(msg, &b), "swap ML-DSA");

        // (c) SLH-DSA de sk2, resto de sk.
        let mut c = sig[..ml_end].to_vec();
        c.extend_from_slice(&other[ml_end..]);
        assert!(!vk.verify(msg, &c), "swap SLH-DSA");
    }

    #[test]
    fn triple_signing_key_serialization_round_trips() {
        let (vk, sk) = generate_triple_keypair();
        let bytes = sk.to_bytes();
        assert_eq!(bytes.len(), TRIPLE_SIGNING_KEY_LEN);
        let sk2 = TripleSigningKey::from_bytes(&bytes).unwrap();
        assert!(vk.verify(b"m", &sk2.sign(b"m")));
    }

    #[test]
    fn triple_verifying_key_serialization_round_trips() {
        let (vk, sk) = generate_triple_keypair();
        let bytes = vk.to_bytes();
        assert_eq!(bytes.len(), TRIPLE_VERIFYING_KEY_LEN);
        let vk2 = TripleVerifyingKey::from_bytes(&bytes).unwrap();
        assert!(vk2.verify(b"m", &sk.sign(b"m")));
    }

    #[test]
    fn triple_wrong_length_signature_rejected() {
        let (vk, sk) = generate_triple_keypair();
        let mut sig = sk.sign(b"m");
        sig.truncate(TRIPLE_SIGNATURE_LEN - 1);
        assert!(!vk.verify(b"m", &sig));
    }

    #[test]
    fn triple_signatures_are_deterministic_but_bind_message() {
        let (_vk, sk) = generate_triple_keypair();
        assert_eq!(sk.sign(b"a"), sk.sign(b"a"));
        assert_ne!(sk.sign(b"a"), sk.sign(b"b"));
    }
```

- [ ] **Step 2: Run the tests**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --features slh triple_`
Expected: PASS. If `triple_signatures_are_deterministic_but_bind_message` fails, the `slh-dsa` default `sign` is randomized — switch `TripleSigningKey::sign` to the deterministic path or drop the determinism assert (document the choice); prefer deterministic to mirror the double mode.

- [ ] **Step 3: Commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
git add src/pqsign.rs
git commit -m "test(pqsign): triple-hybrid tamper, wrong-key, AND 3-of-3 rejection

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: QSG3 container — `encode_signed_triple` / `decode_verified_triple`

**Files:**
- Modify: `src/api.rs` (add QSG3 constants, the two functions, and tests) under `#[cfg(feature = "slh")]`

**Interfaces:**
- Consumes: `pqsign::{TripleSigningKey, TripleVerifyingKey, TRIPLE_SIGNATURE_LEN}`, existing `codec`, `Dictionary`, `DecodeError`, `ContainerError`.
- Produces:
  - `pub fn encode_signed_triple(data: &[u8], signer: &pqsign::TripleSigningKey, dict: &Dictionary) -> String`
  - `pub fn decode_verified_triple(symbols: &str, verifier: &pqsign::TripleVerifyingKey, dict: &Dictionary) -> Result<Vec<u8>, DecodeError>`

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` in `src/api.rs`, wrapped so they only build with the feature:
```rust
    #[cfg(feature = "slh")]
    #[test]
    fn triple_signed_round_trips() {
        let dict = crate::dictionaries::ascii94();
        let (vk, sk) = pqsign::generate_triple_keypair();
        let data = b"artefacto de altisimo valor";
        let symbols = encode_signed_triple(data, &sk, &dict);
        assert_eq!(decode_verified_triple(&symbols, &vk, &dict).unwrap(), data);
    }

    #[cfg(feature = "slh")]
    #[test]
    fn triple_wrong_key_rejected() {
        let dict = crate::dictionaries::ascii94();
        let (_vk, sk) = pqsign::generate_triple_keypair();
        let (vk2, _sk2) = pqsign::generate_triple_keypair();
        let symbols = encode_signed_triple(b"datos", &sk, &dict);
        assert!(matches!(
            decode_verified_triple(&symbols, &vk2, &dict),
            Err(DecodeError::BadSignature)
        ));
    }

    #[cfg(feature = "slh")]
    #[test]
    fn triple_region_tamper_rejected() {
        let dict = crate::dictionaries::ascii94();
        let (vk, sk) = pqsign::generate_triple_keypair();
        let symbols = encode_signed_triple(b"transferir 100", &sk, &dict);
        let mut chars: Vec<char> = symbols.chars().collect();
        chars[SIGNED_TRIPLE_PREFIX] = if chars[SIGNED_TRIPLE_PREFIX] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert!(decode_verified_triple(&tampered, &vk, &dict).is_err());
    }

    #[cfg(feature = "slh")]
    #[test]
    fn triple_empty_message_round_trips() {
        let dict = crate::dictionaries::ascii94();
        let (vk, sk) = pqsign::generate_triple_keypair();
        let symbols = encode_signed_triple(b"", &sk, &dict);
        assert_eq!(decode_verified_triple(&symbols, &vk, &dict).unwrap(), b"");
    }

    #[cfg(feature = "slh")]
    #[test]
    fn triple_rejects_overflowing_msg_len_without_panic() {
        let dict = crate::dictionaries::ascii94();
        let (vk, _sk) = pqsign::generate_triple_keypair();
        let mut blob = Vec::new();
        blob.extend_from_slice(b"QSG3");
        blob.push(1); // version
        blob.push(0); // flags
        blob.extend_from_slice(&u32::MAX.to_be_bytes()); // msg_len enorme
        let indices = codec::encode_base_n(&blob, dict.base());
        let symbols = dict.encode(&indices).unwrap();
        assert!(decode_verified_triple(&symbols, &vk, &dict).is_err());
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --features slh --lib api::tests::triple_`
Expected: FAIL — `encode_signed_triple` / `decode_verified_triple` / `SIGNED_TRIPLE_PREFIX` not found.

- [ ] **Step 3: Implement the QSG3 functions**

Add to `src/api.rs`, near the existing `SIGNED_MAGIC` block:
```rust
#[cfg(feature = "slh")]
const SIGNED_TRIPLE_MAGIC: [u8; 4] = *b"QSG3";
#[cfg(feature = "slh")]
const SIGNED_TRIPLE_VERSION: u8 = 1;
/// Cabecera QSG3: magic+version+flags+msg_len (idéntico layout que QSG1).
#[cfg(feature = "slh")]
const SIGNED_TRIPLE_PREFIX: usize = 4 + 1 + 1 + 4;

/// Firma `data` con la clave triple-híbrida y lo representa con `dict` (contenedor
/// QSG3). Autosuficiente, FIRMADO PERO EN CLARO: autenticidad/integridad/no-repudio,
/// no confidencialidad. Modo de alta garantía (firma ~34 KB).
#[cfg(feature = "slh")]
pub fn encode_signed_triple(
    data: &[u8],
    signer: &pqsign::TripleSigningKey,
    dict: &Dictionary,
) -> String {
    let signature = signer.sign(data);
    let mut blob = Vec::with_capacity(SIGNED_TRIPLE_PREFIX + data.len() + signature.len());
    blob.extend_from_slice(&SIGNED_TRIPLE_MAGIC);
    blob.push(SIGNED_TRIPLE_VERSION);
    blob.push(0u8); // flags
    blob.extend_from_slice(&(data.len() as u32).to_be_bytes());
    blob.extend_from_slice(data);
    blob.extend_from_slice(&signature);

    let indices = codec::encode_base_n(&blob, dict.base());
    dict.encode(&indices)
        .expect("los índices del codec están en [0, base)")
}

/// Verifica un artefacto QSG3 contra la clave triple FIJADA y, sólo si valida,
/// devuelve el mensaje. Un artefacto QSG1 aquí da `BadMagic` (sin downgrade).
#[cfg(feature = "slh")]
pub fn decode_verified_triple(
    symbols: &str,
    verifier: &pqsign::TripleVerifyingKey,
    dict: &Dictionary,
) -> Result<Vec<u8>, DecodeError> {
    let indices = dict.decode(symbols).map_err(DecodeError::Symbol)?;
    let blob = codec::decode_base_n(&indices, dict.base());

    if blob.len() < SIGNED_TRIPLE_PREFIX + pqsign::TRIPLE_SIGNATURE_LEN {
        return Err(DecodeError::Container(ContainerError::TooShort));
    }
    if blob[0..4] != SIGNED_TRIPLE_MAGIC {
        return Err(DecodeError::Container(ContainerError::BadMagic));
    }
    if blob[4] != SIGNED_TRIPLE_VERSION {
        return Err(DecodeError::Container(ContainerError::UnsupportedVersion(
            blob[4],
        )));
    }
    let msg_len = u32::from_be_bytes(blob[6..10].try_into().expect("4 bytes")) as usize;

    // Aritmética verificada (misma defensa F4 que decode_verified).
    let Some(msg_end) = SIGNED_TRIPLE_PREFIX.checked_add(msg_len) else {
        return Err(DecodeError::Container(ContainerError::TooShort));
    };
    let Some(expected_len) = msg_end.checked_add(pqsign::TRIPLE_SIGNATURE_LEN) else {
        return Err(DecodeError::Container(ContainerError::TooShort));
    };
    if blob.len() != expected_len {
        return Err(DecodeError::Container(ContainerError::TooShort));
    }
    let message = &blob[SIGNED_TRIPLE_PREFIX..msg_end];
    let signature = &blob[msg_end..];

    if !verifier.verify(message, signature) {
        return Err(DecodeError::BadSignature);
    }
    Ok(message.to_vec())
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --features slh --lib api::tests::triple_`
Expected: PASS (all five).

- [ ] **Step 5: Commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
git add src/api.rs
git commit -m "feat(api): QSG3 container — encode_signed_triple / decode_verified_triple

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Security Lab — 3-of-3 adaptive forgery coverage

**Files:**
- Create: `src/lab/forge_triple.rs`
- Modify: `src/lab/mod.rs` (register the module) — gated so it only builds with both `lab` and `slh`.

**Interfaces:**
- Consumes: `crate::api::{encode_signed_triple, decode_verified_triple}`, `crate::pqsign` triple API, `crate::lab::engine::{Attack, AttackOutcome, Rng}`, `crate::dictionaries`.
- Produces: `pub struct ForgeTripleAttack` implementing `Attack` (`name()` → `"forge/triple"`).

- [ ] **Step 1: Inspect how `forge.rs` is registered**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; grep -n "mod forge\|pub mod\|mod " src/lab/mod.rs`
Expected: shows the `mod forge;` (or `pub mod forge;`) line to mirror.

- [ ] **Step 2: Write the failing test module `src/lab/forge_triple.rs`**

Create `src/lab/forge_triple.rs`:
```rust
//! Superficie 4 (triple): falsificación adaptativa contra el modo QSG3.
//!
//! Refleja `forge.rs` para el AND 3-de-3: frankensignature sobre cada uno de los
//! tres componentes, key-substitution y manipulación de región. Cualquier
//! `decode_verified_triple` que devuelva Ok sobre algo forjado es una brecha.

use crate::api::{decode_verified_triple, encode_signed_triple};
use crate::dictionaries;
use crate::lab::engine::{Attack, AttackOutcome, Rng};
use crate::pqsign;

/// Falsificador triple adaptativo.
pub struct ForgeTripleAttack;

impl ForgeTripleAttack {
    /// Nuevo ataque de falsificación triple.
    pub fn new() -> Self {
        Self
    }
}

impl Default for ForgeTripleAttack {
    fn default() -> Self {
        Self::new()
    }
}

impl Attack for ForgeTripleAttack {
    fn name(&self) -> &'static str {
        "forge/triple"
    }

    fn step(&mut self, rng: &mut Rng) -> AttackOutcome {
        let dict = dictionaries::ascii94();
        let (vk1, sk1) = pqsign::generate_triple_keypair();
        let (vk2, sk2) = pqsign::generate_triple_keypair();
        let message = b"orden triple del laboratorio";

        let ed_end = pqsign::ED25519_SIG_LEN;
        let ml_end = pqsign::ED25519_SIG_LEN + pqsign::MLDSA_SIG_LEN;

        match rng.below(3) {
            // Frankensignature: intercambia un componente (ed/ml/slh) de sk2.
            0 => {
                let sig1 = sk1.sign(message);
                let sig2 = sk2.sign(message);
                let which = rng.below(3);
                let spliced = match which {
                    0 => {
                        let mut s = sig2[..ed_end].to_vec();
                        s.extend_from_slice(&sig1[ed_end..]);
                        s
                    }
                    1 => {
                        let mut s = sig1[..ed_end].to_vec();
                        s.extend_from_slice(&sig2[ed_end..ml_end]);
                        s.extend_from_slice(&sig1[ml_end..]);
                        s
                    }
                    _ => {
                        let mut s = sig1[..ml_end].to_vec();
                        s.extend_from_slice(&sig2[ml_end..]);
                        s
                    }
                };
                // Reconstruye el artefacto QSG3 público a mano (Kerckhoffs).
                let mut blob = Vec::new();
                blob.extend_from_slice(b"QSG3");
                blob.push(1);
                blob.push(0);
                blob.extend_from_slice(&(message.len() as u32).to_be_bytes());
                blob.extend_from_slice(message);
                blob.extend_from_slice(&spliced);
                let indices = crate::codec::encode_base_n(&blob, dict.base());
                let artifact = dict.encode(&indices).expect("índices en rango");
                if decode_verified_triple(&artifact, &vk1, &dict).is_ok()
                    || decode_verified_triple(&artifact, &vk2, &dict).is_ok()
                {
                    return AttackOutcome::Breach(format!("frankensig triple (comp {which}) verificó"));
                }
                AttackOutcome::Advanced
            }
            // Key-substitution.
            1 => {
                let artifact = encode_signed_triple(message, &sk1, &dict);
                if decode_verified_triple(&artifact, &vk2, &dict).is_ok() {
                    return AttackOutcome::Breach("firma triple verificó con clave equivocada".into());
                }
                AttackOutcome::Advanced
            }
            // Manipulación de región.
            _ => {
                let artifact = encode_signed_triple(message, &sk1, &dict);
                let mut chars: Vec<char> = artifact.chars().collect();
                if chars.is_empty() {
                    return AttackOutcome::NoProgress;
                }
                let pos = rng.below(chars.len());
                let idx = dict.symbol_to_index(chars[pos]).expect("símbolo propio");
                let new = dict
                    .index_to_symbol((idx + 1) % dict.base())
                    .expect("índice válido");
                if new == chars[pos] {
                    return AttackOutcome::NoProgress;
                }
                chars[pos] = new;
                let mutated: String = chars.into_iter().collect();
                if decode_verified_triple(&mutated, &vk1, &dict).is_ok() {
                    return AttackOutcome::Breach(format!("mutación triple en pos {pos} verificó"));
                }
                AttackOutcome::Advanced
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::engine::run;

    #[test]
    fn adaptive_triple_forgery_never_verifies() {
        let mut attack = ForgeTripleAttack::new();
        let report = run(&mut attack, 1337, 30);
        assert!(report.attempts > 0);
        assert!(
            report.is_clean(),
            "ninguna falsificación triple debe verificar: {:?}",
            report.breaches
        );
    }
}
```

- [ ] **Step 3: Register the module in `src/lab/mod.rs`**

Add, mirroring the `forge` registration but gated on `slh` too:
```rust
#[cfg(feature = "slh")]
pub mod forge_triple;
```

- [ ] **Step 4: Run the Lab test**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --features "lab slh" forge_triple`
Expected: PASS (`adaptive_triple_forgery_never_verifies`). Note: 30 iterations because SLH-DSA signing is slow; keep it modest.

- [ ] **Step 5: Clippy clean**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo clippy --features "lab slh" --all-targets -- -D warnings`
Expected: no warnings.

- [ ] **Step 6: Commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
git add src/lab/forge_triple.rs src/lab/mod.rs
git commit -m "test(lab): 3-of-3 adaptive forgery coverage for triple-hybrid mode

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: CI matrix + feature-isolation check

**Files:**
- Modify: `.github/workflows/*.yml` (the test/clippy job and the `security-lab` job)

**Interfaces:**
- Consumes: nothing new. Ensures `slh` builds/tests in CI and that the default build stays lean.

- [ ] **Step 1: Find the workflow and jobs**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; ls .github/workflows && grep -rn "cargo test\|features lab\|security-lab" .github/workflows`
Expected: shows the test job and the `security-lab` job invocation to mirror.

- [ ] **Step 2: Add an `slh` test/clippy step to the main test job**

In the test job (after the existing default `cargo test`), add steps:
```yaml
      - name: Test (slh feature)
        run: cargo test --features slh
      - name: Clippy (slh feature)
        run: cargo clippy --features slh --all-targets -- -D warnings
```

- [ ] **Step 3: Add `slh` to the Security Lab job**

In the `security-lab` job, add after the existing `--features lab` run:
```yaml
      - name: Security Lab (triple)
        run: cargo test --features "lab slh" forge_triple
```

- [ ] **Step 4: Sanity-check locally that the default build has no `slh` symbols**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo build 2>&1 | tail -5 && nm -D target/debug/libquipu.so 2>/dev/null | grep -i triple | head` (the `grep` should print nothing).
Expected: default build succeeds; no `triple` symbols exported.

- [ ] **Step 5: Commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
git add .github/workflows
git commit -m "ci: build/test/lint the slh feature and run triple forgery in CI

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: Docs, rustdoc, and CHANGELOG (no release)

**Files:**
- Modify: `src/pqsign.rs` (module-level rustdoc note on the triple mode)
- Modify: `CHANGELOG.md` (`[Unreleased]` → new `### Added` entry)
- Modify: `README.md` if it enumerates signature modes (grep first)

**Interfaces:**
- Consumes: nothing. Documentation only.

- [ ] **Step 1: Add a rustdoc note to `src/pqsign.rs`**

Just above the `#[cfg(feature = "slh")]` triple block, add:
```rust
/// # Modo triple-híbrido (feature `slh`, opt-in)
///
/// Añade **SLH-DSA-SHA2-256s** (FIPS-205, hash-based *stateless*) a la firma,
/// combinando Ed25519 + ML-DSA-87 + SLH-DSA con **AND 3-de-3**: infalsificable
/// mientras sobreviva al menos una de tres familias (curva, retículo, hash). La
/// firma pesa ~34 KB y firmar es lento: es un modo de **alta garantía** para
/// artefactos de altísimo valor, no el por defecto. Contenedor `QSG3` vía
/// `api::encode_signed_triple` / `decode_verified_triple`.
```

- [ ] **Step 2: Add the CHANGELOG entry**

Under `## [Unreleased]`, add an `### Added` section:
```markdown
### Added
- **Triple-hybrid signature mode (opt-in `slh` feature)**: Ed25519 + ML-DSA-87 +
  **SLH-DSA-SHA2-256s** (FIPS-205, stateless hash-based) combined with an **AND
  3-of-3** combiner — a signature is valid only if all three verify, so it stays
  unforgeable as long as at least one of three independent families (elliptic
  curve, lattice, hash) survives. New `QSG3` container and
  `api::encode_signed_triple` / `decode_verified_triple`. High-assurance mode:
  signatures are ~34 KB and signing is slow, so it is opt-in, not the default.
  The double-hybrid mode and v0.4.x artifacts are unchanged.
```

- [ ] **Step 3: Check README for a signature-modes list**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; grep -n "Ed25519\|ML-DSA\|signature mode\|firma" README.md | head`
If a modes list exists, add one line for the triple mode mirroring the existing style. If not, skip.

- [ ] **Step 4: Verify docs build**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo doc --features slh --no-deps 2>&1 | tail -5`
Expected: builds without warnings on the new items.

- [ ] **Step 5: Commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
git add src/pqsign.rs CHANGELOG.md README.md
git commit -m "docs: document the opt-in triple-hybrid signature mode

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Final verification (before opening the PR)

- [ ] `export PATH="$HOME/.cargo/bin:$PATH"; cargo test` (default build green — nothing broke).
- [ ] `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --features slh` (all triple unit/api tests green).
- [ ] `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --features "lab slh" forge_triple` (Lab finds no breach).
- [ ] `export PATH="$HOME/.cargo/bin:$PATH"; cargo clippy --features slh --all-targets -- -D warnings` (clean).
- [ ] Run `superpowers:verification-before-completion` before declaring done.
- [ ] Open a PR from `feat/phase1-slh-triple` into `main`. **Do not tag/publish** — the v0.5.0 release (Cargo.toml/pyproject.toml/Cargo.lock/`supply-chain/config.toml` exemption bump, tag, PyPI, crates.io) is a separate, explicitly-gated step.

## Notes carried from the spec

- `supply-chain/config.toml`: when the release happens, bump the `[[exemptions.quipu]]` version and add an entry (safe-to-deploy) for the new `slh-dsa` dependency, or `cargo-vet` in CI will fail.
- The sandbox cannot `bind` sockets, but this phase has no network component, so all tests run locally.
