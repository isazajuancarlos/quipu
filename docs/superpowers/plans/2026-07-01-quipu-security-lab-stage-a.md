# Quipu Security Lab — Etapa A — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Etapa A núcleo of the Quipu Security Lab — an adaptive, self-hosted red-team that attacks Quipu's own ciphertext/format (surface 1) and signature verification (surface 4), with three anti-abuse locks (compile isolation, tamper-evident defenses, hash-chained corpus).

**Architecture:** New `src/lab/` module gated behind a non-default Cargo feature `lab`, so it never ships in the published crate or the PyPI wheel (maturin builds only `features = ["python"]`). A deterministic seeded PRNG drives a breach-guided attack loop over a common `Attack` trait; each surface is a self-contained unit. A hash-chained corpus makes findings tamper-evident, and a `guard` module asserts the antihacker defenses are still present and effective.

**Tech Stack:** Rust (edition 2024), existing crates only — `sha2` (corpus hashing, already a dependency), `crate::api`, `crate::pqsign`, `crate::antihacker`, `crate::kdf`, `crate::dictionaries`. No new dependencies (matches Quipu's "reuse vetted primitives, never invent" philosophy; the PRNG is a plain SplitMix64, not cryptographic).

## Global Constraints

- Rust edition: 2024 (copied from `Cargo.toml`).
- Everything under `src/lab/` MUST be gated with `#[cfg(feature = "lab")]`; the `lab` feature MUST NOT be enabled by default nor by maturin (`[tool.maturin] features = ["python"]` stays unchanged).
- No new third-party dependencies. The lab PRNG is non-cryptographic and used ONLY to make attacks reproducible.
- Never invent or substitute a cryptographic primitive. The lab only composes existing ones and attacks Quipu; it never targets third parties.
- All new tests must pass under `cargo test --features lab`; the default `cargo test --all-targets` must stay green and must NOT compile the lab.
- The published QSG1 signed-container format is public (Kerckhoffs): the lab may reconstruct it byte-for-byte to craft malicious artifacts.

---

### Task 1: `lab` feature + deterministic PRNG

**Files:**
- Modify: `Cargo.toml` (add `lab = []` feature)
- Modify: `src/lib.rs:24` (gated `pub mod lab;`)
- Create: `src/lab/mod.rs`
- Create: `src/lab/engine.rs`

**Interfaces:**
- Produces: `crate::lab::engine::Rng` with `Rng::seeded(seed: u64) -> Rng`, `next_u64(&mut self) -> u64`, `below(&mut self, n: usize) -> usize`, `byte(&mut self) -> u8`.

- [ ] **Step 1: Add the feature and module wiring**

In `Cargo.toml`, change the `[features]` block from:

```toml
[features]
python = ["dep:pyo3"]
```

to:

```toml
[features]
python = ["dep:pyo3"]
# Laboratorio de seguridad (red-team adaptativo). NUNCA se activa en release ni
# en la rueda de PyPI: el arma no viaja con el producto.
lab = []
```

In `src/lib.rs`, after the line `pub mod voprf;` (line 27) add:

```rust
#[cfg(feature = "lab")]
pub mod lab;
```

Create `src/lab/mod.rs`:

```rust
//! Quipu Security Lab: red-team adaptativo AUTO-HOSPEDADO (Etapa A, núcleo CI).
//!
//! Se ataca a sí mismo, aprende de cada corrida y convierte cada brecha en un
//! test de regresión. Todo el módulo está tras `#[cfg(feature = "lab")]`: NO se
//! compila en release ni en la rueda de PyPI (el arma no viaja con el producto).
//!
//! Nunca inventa ni sustituye primitivas: compone las existentes y ataca a Quipu.

pub mod engine;
```

- [ ] **Step 2: Write the failing test for the PRNG**

Create `src/lab/engine.rs` with only the test module first:

```rust
//! Motor del laboratorio: PRNG determinista + bucle de ataque guiado por brechas.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prng_is_deterministic_for_a_seed() {
        let mut a = Rng::seeded(42);
        let mut b = Rng::seeded(42);
        let seq_a: Vec<u64> = (0..8).map(|_| a.next_u64()).collect();
        let seq_b: Vec<u64> = (0..8).map(|_| b.next_u64()).collect();
        assert_eq!(seq_a, seq_b, "misma semilla debe dar misma secuencia");
    }

    #[test]
    fn prng_differs_across_seeds() {
        let mut a = Rng::seeded(1);
        let mut b = Rng::seeded(2);
        assert_ne!(a.next_u64(), b.next_u64(), "semillas distintas divergen");
    }

    #[test]
    fn below_stays_in_range() {
        let mut r = Rng::seeded(7);
        for _ in 0..1000 {
            assert!(r.below(10) < 10);
        }
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `export PATH="$HOME/.cargo/bin:$PATH" && cargo test --features lab --lib lab::engine 2>&1 | tail -20`
Expected: FAIL — `cannot find type Rng in this scope`.

- [ ] **Step 4: Implement the PRNG**

At the TOP of `src/lab/engine.rs` (above the `#[cfg(test)]` module) add:

```rust
/// PRNG determinista (SplitMix64). NO es criptográfico: sirve SOLO para hacer los
/// ataques reproducibles con una semilla fija (CI verde y auditable).
pub struct Rng {
    state: u64,
}

impl Rng {
    /// Crea un generador con semilla fija.
    pub fn seeded(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Siguiente valor de 64 bits (SplitMix64).
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Entero uniforme en `[0, n)`. Devuelve 0 si `n == 0`.
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.next_u64() % n as u64) as usize
    }

    /// Un byte pseudoaleatorio.
    pub fn byte(&mut self) -> u8 {
        self.next_u64() as u8
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH" && cargo test --features lab --lib lab::engine 2>&1 | tail -20`
Expected: PASS (3 tests). Also confirm the default build ignores the lab:
Run: `export PATH="$HOME/.cargo/bin:$PATH" && cargo build 2>&1 | tail -5`
Expected: builds with no reference to `lab`.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml src/lib.rs src/lab/mod.rs src/lab/engine.rs
git commit -m "feat(lab): gated lab feature + deterministic SplitMix64 PRNG"
```

---

### Task 2: `Attack` trait + breach-guided run loop

**Files:**
- Modify: `src/lab/engine.rs`

**Interfaces:**
- Consumes: `Rng` from Task 1.
- Produces:
  - `enum AttackOutcome { Advanced, Breach(String), NoProgress }`
  - `trait Attack { fn name(&self) -> &'static str; fn step(&mut self, rng: &mut Rng) -> AttackOutcome; }`
  - `struct LabReport { pub name: &'static str, pub attempts: usize, pub advances: usize, pub breaches: Vec<String> }` with `fn is_clean(&self) -> bool`
  - `fn run(attack: &mut dyn Attack, seed: u64, budget: usize) -> LabReport`

- [ ] **Step 1: Write the failing test**

In `src/lab/engine.rs`, inside the existing `#[cfg(test)] mod tests`, add:

```rust
    struct BreachOnThird {
        count: usize,
    }
    impl Attack for BreachOnThird {
        fn name(&self) -> &'static str {
            "breach-on-third"
        }
        fn step(&mut self, _rng: &mut Rng) -> AttackOutcome {
            self.count += 1;
            if self.count == 3 {
                AttackOutcome::Breach("simulada".into())
            } else {
                AttackOutcome::Advanced
            }
        }
    }

    #[test]
    fn run_collects_breaches_and_is_reproducible() {
        let mut a = BreachOnThird { count: 0 };
        let report = run(&mut a, 99, 5);
        assert_eq!(report.attempts, 5);
        assert_eq!(report.advances, 4);
        assert_eq!(report.breaches, vec!["simulada".to_string()]);
        assert!(!report.is_clean());
    }

    #[test]
    fn clean_report_has_no_breaches() {
        struct Always(AttackOutcome);
        impl Attack for Always {
            fn name(&self) -> &'static str {
                "always"
            }
            fn step(&mut self, _rng: &mut Rng) -> AttackOutcome {
                match self.0 {
                    AttackOutcome::NoProgress => AttackOutcome::NoProgress,
                    _ => AttackOutcome::Advanced,
                }
            }
        }
        let mut a = Always(AttackOutcome::NoProgress);
        let report = run(&mut a, 1, 10);
        assert!(report.is_clean());
        assert_eq!(report.advances, 0);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `export PATH="$HOME/.cargo/bin:$PATH" && cargo test --features lab --lib lab::engine 2>&1 | tail -20`
Expected: FAIL — `cannot find type Attack` / `cannot find function run`.

- [ ] **Step 3: Implement the trait, report and loop**

In `src/lab/engine.rs`, above the `#[cfg(test)]` module (below the `Rng` impl), add:

```rust
/// Resultado de un paso de ataque.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttackOutcome {
    /// El paso se acercó a una brecha (guía la búsqueda), sin romper nada.
    Advanced,
    /// ¡Brecha! La librería aceptó indebidamente algo forjado/alterado.
    Breach(String),
    /// El paso no aportó información nueva.
    NoProgress,
}

/// Un ataque adaptativo contra Quipu. Cada superficie implementa este trait como
/// una unidad aislada y testeable.
pub trait Attack {
    /// Nombre estable del ataque (aparece en el reporte).
    fn name(&self) -> &'static str;
    /// Ejecuta un intento. `rng` es determinista: el ataque debe ser reproducible.
    fn step(&mut self, rng: &mut Rng) -> AttackOutcome;
}

/// Reporte de una corrida de ataque.
#[derive(Debug, Clone)]
pub struct LabReport {
    /// Nombre del ataque.
    pub name: &'static str,
    /// Intentos realizados.
    pub attempts: usize,
    /// Pasos que se "acercaron" (guía; no son brechas).
    pub advances: usize,
    /// Brechas: cada una es un fallo real que hay que convertir en regresión.
    pub breaches: Vec<String>,
}

impl LabReport {
    /// `true` si no hubo ninguna brecha.
    pub fn is_clean(&self) -> bool {
        self.breaches.is_empty()
    }
}

/// Corre `attack` durante `budget` pasos con una semilla fija (reproducible) y
/// acumula las brechas encontradas.
pub fn run(attack: &mut dyn Attack, seed: u64, budget: usize) -> LabReport {
    let mut rng = Rng::seeded(seed);
    let mut report = LabReport {
        name: attack.name(),
        attempts: 0,
        advances: 0,
        breaches: Vec::new(),
    };
    for _ in 0..budget {
        report.attempts += 1;
        match attack.step(&mut rng) {
            AttackOutcome::Advanced => report.advances += 1,
            AttackOutcome::Breach(detail) => report.breaches.push(detail),
            AttackOutcome::NoProgress => {}
        }
    }
    report
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH" && cargo test --features lab --lib lab::engine 2>&1 | tail -20`
Expected: PASS (5 tests total in `lab::engine`).

- [ ] **Step 5: Commit**

```bash
git add src/lab/engine.rs
git commit -m "feat(lab): Attack trait, LabReport and breach-guided run loop"
```

---

### Task 3: Hash-chained corpus (integrity lock)

**Files:**
- Modify: `src/lab/mod.rs` (add `pub mod corpus;`)
- Create: `src/lab/corpus.rs`

**Interfaces:**
- Produces:
  - `struct Corpus { /* private */ }` with `Corpus::new() -> Corpus`, `append(&mut self, kind: &str, data: &[u8])`, `head(&self) -> [u8; 32]`, `len(&self) -> usize`, `is_empty(&self) -> bool`, `verify(&self) -> bool`, and a test-only `corrupt_last(&mut self)`.
  - `const ROOT: [u8; 32]` (all zeros).

- [ ] **Step 1: Declare the module**

In `src/lab/mod.rs`, add below `pub mod engine;`:

```rust
pub mod corpus;
```

- [ ] **Step 2: Write the failing test**

Create `src/lab/corpus.rs`:

```rust
//! Corpus de hallazgos encadenado por hash (candado de INTEGRIDAD).
//!
//! Append-only: cada entrada liga el hash de la anterior. Envenenar el historial
//! (inyectar "todo verde" para ocultar una brecha real) rompe la cadena y
//! `verify()` lo detecta. El laboratorio no confía ciegamente en su memoria.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_corpus_verifies() {
        let c = Corpus::new();
        assert!(c.is_empty());
        assert_eq!(c.head(), ROOT);
        assert!(c.verify());
    }

    #[test]
    fn appended_chain_verifies_and_advances_head() {
        let mut c = Corpus::new();
        c.append("seed", b"hola");
        let h1 = c.head();
        c.append("breach", b"forgery-x");
        assert_eq!(c.len(), 2);
        assert_ne!(c.head(), ROOT);
        assert_ne!(c.head(), h1, "cada entrada mueve la cabeza");
        assert!(c.verify());
    }

    #[test]
    fn poisoning_breaks_the_chain() {
        let mut c = Corpus::new();
        c.append("seed", b"hola");
        c.append("breach", b"forgery-x");
        c.corrupt_last();
        assert!(!c.verify(), "una entrada alterada debe romper la verificación");
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `export PATH="$HOME/.cargo/bin:$PATH" && cargo test --features lab --lib lab::corpus 2>&1 | tail -20`
Expected: FAIL — `cannot find type Corpus`.

- [ ] **Step 4: Implement the corpus**

At the TOP of `src/lab/corpus.rs` (above the tests) add:

```rust
use sha2::{Digest, Sha256};

/// Hash raíz de la cadena (cabeza de un corpus vacío).
pub const ROOT: [u8; 32] = [0u8; 32];

/// Una entrada del corpus: tipo + datos + hash encadenado.
#[derive(Clone)]
struct Entry {
    kind: String,
    data: Vec<u8>,
    hash: [u8; 32],
}

/// Corpus append-only encadenado por hash.
pub struct Corpus {
    entries: Vec<Entry>,
}

impl Corpus {
    /// Corpus vacío (cabeza = `ROOT`).
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Hash encadenado de una entrada: `sha256(prev || kind || 0x00 || data)`.
    fn link(prev: &[u8; 32], kind: &str, data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(prev);
        h.update(kind.as_bytes());
        h.update([0u8]); // separador dominio kind/data
        h.update(data);
        h.finalize().into()
    }

    /// Añade una entrada, ligándola a la cabeza actual.
    pub fn append(&mut self, kind: &str, data: &[u8]) {
        let prev = self.head();
        let hash = Self::link(&prev, kind, data);
        self.entries.push(Entry {
            kind: kind.to_string(),
            data: data.to_vec(),
            hash,
        });
    }

    /// Cabeza actual de la cadena (hash de la última entrada, o `ROOT` si vacío).
    pub fn head(&self) -> [u8; 32] {
        self.entries.last().map(|e| e.hash).unwrap_or(ROOT)
    }

    /// Número de entradas.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` si no hay entradas.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Recalcula la cadena desde `ROOT`; `false` si alguna entrada fue alterada.
    pub fn verify(&self) -> bool {
        let mut prev = ROOT;
        for e in &self.entries {
            let expected = Self::link(&prev, &e.kind, &e.data);
            if expected != e.hash {
                return false;
            }
            prev = e.hash;
        }
        true
    }

    /// SOLO test: simula envenenamiento alterando los datos de la última entrada
    /// sin recalcular su hash.
    #[cfg(test)]
    fn corrupt_last(&mut self) {
        if let Some(e) = self.entries.last_mut() {
            e.data.push(0xFF);
        }
    }
}

impl Default for Corpus {
    fn default() -> Self {
        Self::new()
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH" && cargo test --features lab --lib lab::corpus 2>&1 | tail -20`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add src/lab/mod.rs src/lab/corpus.rs
git commit -m "feat(lab): hash-chained tamper-evident findings corpus"
```

---

### Task 4: Surface 1 — ciphertext/format leak distinguisher

**Files:**
- Modify: `src/lab/mod.rs` (add `pub mod leak;`)
- Create: `src/lab/leak.rs`

**Interfaces:**
- Consumes: `Attack`, `AttackOutcome`, `Rng` from `crate::lab::engine`; `crate::api::{encode, Options}`; `crate::dictionaries`.
- Produces: `struct LeakAttack` with `LeakAttack::new() -> LeakAttack` implementing `Attack`.

**Rationale (why this is a valid breach test):** Quipu applies Padmé padding over the container, whose length depends only on the plaintext length (AEAD ciphertext length = plaintext length + fixed tag, independent of content). So two plaintexts of the **same length** but different content MUST encode to the **same number of symbols**. If they don't, output length leaks content — a breach.

- [ ] **Step 1: Declare the module**

In `src/lab/mod.rs`, add:

```rust
pub mod leak;
```

- [ ] **Step 2: Write the failing test**

Create `src/lab/leak.rs`:

```rust
//! Superficie 1: distinguidor de fuga en ciphertext/formato.
//!
//! ¿El contenedor / Padmé / codec base-N filtran estructura del plaintext? Como
//! el AEAD no depende del contenido en longitud y Padmé rellena por longitud, dos
//! plaintexts del MISMO tamaño deben producir la MISMA cantidad de símbolos. Si no,
//! la longitud de salida filtra el contenido: brecha.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::engine::run;

    #[test]
    fn length_does_not_leak_plaintext_content() {
        let mut attack = LeakAttack::new();
        let report = run(&mut attack, 20260701, 64);
        assert!(report.attempts > 0);
        assert!(
            report.is_clean(),
            "la longitud de salida no debe depender del contenido: {:?}",
            report.breaches
        );
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `export PATH="$HOME/.cargo/bin:$PATH" && cargo test --features lab --lib lab::leak 2>&1 | tail -20`
Expected: FAIL — `cannot find type LeakAttack`.

- [ ] **Step 4: Implement the leak attack**

At the TOP of `src/lab/leak.rs` add:

```rust
use crate::api::{encode, Options};
use crate::dictionaries;
use crate::kdf::KdfParams;
use crate::lab::engine::{Attack, AttackOutcome, Rng};

/// Ataca la confidencialidad estructural: busca que la LONGITUD de salida dependa
/// del CONTENIDO (no solo del tamaño) del plaintext.
pub struct LeakAttack;

impl LeakAttack {
    /// Nuevo ataque de fuga.
    pub fn new() -> Self {
        Self
    }
}

impl Default for LeakAttack {
    fn default() -> Self {
        Self::new()
    }
}

impl Attack for LeakAttack {
    fn name(&self) -> &'static str {
        "leak/length"
    }

    fn step(&mut self, rng: &mut Rng) -> AttackOutcome {
        let dict = dictionaries::ascii94();
        // Coste KDF barato para que el barrido sea ágil (no afecta la longitud).
        let opts = Options {
            pepper: b"",
            kdf_params: KdfParams {
                mem_kib: 64,
                iterations: 1,
                parallelism: 1,
            },
            codebook_id: 0,
        };

        // Longitud común, contenidos distintos: uno estructurado, uno aleatorio.
        let len = 1 + rng.below(256);
        let structured = vec![0xABu8; len];
        let random: Vec<u8> = (0..len).map(|_| rng.byte()).collect();

        let a = encode(&structured, "clave-lab", &dict, &opts);
        let b = encode(&random, "clave-lab", &dict, &opts);

        if a.chars().count() != b.chars().count() {
            AttackOutcome::Breach(format!(
                "longitud de salida depende del contenido (len={len}): {} vs {}",
                a.chars().count(),
                b.chars().count()
            ))
        } else {
            AttackOutcome::Advanced
        }
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH" && cargo test --features lab --lib lab::leak 2>&1 | tail -20`
Expected: PASS (1 test).

- [ ] **Step 6: Commit**

```bash
git add src/lab/mod.rs src/lab/leak.rs
git commit -m "feat(lab): surface 1 ciphertext/format length-leak distinguisher"
```

---

### Task 5: Surface 4 — adaptive signature forgery

**Files:**
- Modify: `src/lab/mod.rs` (add `pub mod forge;`)
- Create: `src/lab/forge.rs`

**Interfaces:**
- Consumes: `Attack`, `AttackOutcome`, `Rng` from `crate::lab::engine`; `crate::api::{encode_signed, decode_verified}`; `crate::pqsign`; `crate::dictionaries`.
- Produces: `struct ForgeAttack` with `ForgeAttack::new() -> ForgeAttack` implementing `Attack`.

**Note:** The QSG1 format is public. The lab reconstructs it byte-for-byte to craft spliced signatures — exactly what a Kerckhoffs-aware attacker would do. Layout: `b"QSG1"` (4) ‖ version `1` (1) ‖ flags `0` (1) ‖ `msg_len` u32 BE (4) ‖ message ‖ signature (`pqsign::SIGNATURE_LEN`). Signature layout: Ed25519 (`pqsign::ED25519_SIG_LEN` = 64) ‖ ML-DSA (`pqsign::MLDSA_SIG_LEN` = 3309).

- [ ] **Step 1: Declare the module**

In `src/lab/mod.rs`, add:

```rust
pub mod forge;
```

- [ ] **Step 2: Write the failing test**

Create `src/lab/forge.rs`:

```rust
//! Superficie 4: falsificación adaptativa contra el modo firmado (QSG1).
//!
//! Tres estrategias que un atacante consciente de Kerckhoffs intentaría:
//!   1. Frankensignature: mezclar el componente Ed25519 de una firma con el
//!      componente ML-DSA de otra (el combinador AND debe rechazar).
//!   2. Key-substitution: firmar con una clave y verificar con otra.
//!   3. Manipulación de región: mutar un símbolo del artefacto válido.
//! Cualquier `decode_verified` que devuelva Ok sobre algo forjado es una brecha.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::engine::run;

    #[test]
    fn adaptive_forgery_never_verifies() {
        let mut attack = ForgeAttack::new();
        let report = run(&mut attack, 1337, 90);
        assert!(report.attempts > 0);
        assert!(
            report.is_clean(),
            "ninguna falsificación debe verificar: {:?}",
            report.breaches
        );
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `export PATH="$HOME/.cargo/bin:$PATH" && cargo test --features lab --lib lab::forge 2>&1 | tail -20`
Expected: FAIL — `cannot find type ForgeAttack`.

- [ ] **Step 4: Implement the forge attack**

At the TOP of `src/lab/forge.rs` add:

```rust
use crate::api::{decode_verified, encode_signed};
use crate::dictionaries;
use crate::lab::engine::{Attack, AttackOutcome, Rng};
use crate::pqsign;

/// Cabecera pública QSG1 antes del mensaje (magic+version+flags+len).
const QSG1_PREFIX_LEN: usize = 4 + 1 + 1 + 4;

/// Ensambla un artefacto QSG1 crudo (formato público) y lo representa con `dict`.
/// El atacante conoce el formato: reconstruirlo es legítimo (Kerckhoffs).
fn build_qsg1(message: &[u8], signature: &[u8], dict: &crate::dictionary::Dictionary) -> String {
    let mut blob = Vec::with_capacity(QSG1_PREFIX_LEN + message.len() + signature.len());
    blob.extend_from_slice(b"QSG1");
    blob.push(1u8); // version
    blob.push(0u8); // flags
    blob.extend_from_slice(&(message.len() as u32).to_be_bytes());
    blob.extend_from_slice(message);
    blob.extend_from_slice(signature);
    let indices = crate::codec::encode_base_n(&blob, dict.base());
    dict.encode(&indices).expect("índices en rango")
}

/// Falsificador adaptativo: rota entre estrategias según el PRNG.
pub struct ForgeAttack;

impl ForgeAttack {
    /// Nuevo ataque de falsificación.
    pub fn new() -> Self {
        Self
    }
}

impl Default for ForgeAttack {
    fn default() -> Self {
        Self::new()
    }
}

impl Attack for ForgeAttack {
    fn name(&self) -> &'static str {
        "forge/adaptive"
    }

    fn step(&mut self, rng: &mut Rng) -> AttackOutcome {
        let dict = dictionaries::ascii94();
        let (vk1, sk1) = pqsign::generate_keypair();
        let (vk2, sk2) = pqsign::generate_keypair();
        let message = b"orden firmada del laboratorio";

        match rng.below(3) {
            // 1) Frankensignature: Ed25519 de sk1 + ML-DSA de sk2.
            0 => {
                let sig1 = sk1.sign(message);
                let sig2 = sk2.sign(message);
                let mut spliced = Vec::with_capacity(pqsign::SIGNATURE_LEN);
                spliced.extend_from_slice(&sig1[..pqsign::ED25519_SIG_LEN]);
                spliced.extend_from_slice(&sig2[pqsign::ED25519_SIG_LEN..]);
                let artifact = build_qsg1(message, &spliced, &dict);
                if decode_verified(&artifact, &vk1, &dict).is_ok() {
                    return AttackOutcome::Breach("frankensignature verificó bajo vk1".into());
                }
                if decode_verified(&artifact, &vk2, &dict).is_ok() {
                    return AttackOutcome::Breach("frankensignature verificó bajo vk2".into());
                }
                AttackOutcome::Advanced
            }
            // 2) Key-substitution: firma de sk1 verificada con vk2.
            1 => {
                let artifact = encode_signed(message, &sk1, &dict);
                if decode_verified(&artifact, &vk2, &dict).is_ok() {
                    return AttackOutcome::Breach("firma verificó con clave equivocada".into());
                }
                AttackOutcome::Advanced
            }
            // 3) Manipulación de región: mutar un símbolo del artefacto válido.
            _ => {
                let artifact = encode_signed(message, &sk1, &dict);
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
                if decode_verified(&mutated, &vk1, &dict).is_ok() {
                    return AttackOutcome::Breach(format!("mutación en pos {pos} verificó"));
                }
                AttackOutcome::Advanced
            }
        }
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH" && cargo test --features lab --lib lab::forge 2>&1 | tail -20`
Expected: PASS (1 test). Note: this exercises full hybrid verification per step; ~90 steps may take a few seconds in debug.

- [ ] **Step 6: Commit**

```bash
git add src/lab/mod.rs src/lab/forge.rs
git commit -m "feat(lab): surface 4 adaptive signature forgery (franken/key-sub/tamper)"
```

---

### Task 6: Tamper-evidence guard (defenses-still-alive lock)

**Files:**
- Modify: `src/lab/mod.rs` (add `pub mod guard;`)
- Create: `src/lab/guard.rs`

**Interfaces:**
- Consumes: `crate::antihacker::{ct_eq, wipe}`; `crate::kdf::KdfParams`.
- Produces: `fn all_defenses_intact() -> bool`.

- [ ] **Step 1: Declare the module**

In `src/lab/mod.rs`, add:

```rust
pub mod guard;
```

- [ ] **Step 2: Write the failing test**

Create `src/lab/guard.rs`:

```rust
//! Candado de TAMPER-EVIDENCE: verifica que las defensas antihacker siguen
//! PRESENTES y EFECTIVAS. Si alguien borra o debilita `ct_eq`, la validación de
//! parámetros KDF o `wipe`, estos meta-tests fallan (CI en rojo). Las defensas no
//! se pueden apagar en silencio.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_still_discriminates() {
        assert!(guard_ct_eq());
    }

    #[test]
    fn kdf_validation_still_rejects_malicious_params() {
        assert!(guard_kdf_validation());
    }

    #[test]
    fn wipe_still_zeroes_memory() {
        assert!(guard_wipe());
    }

    #[test]
    fn all_defenses_report_intact() {
        assert!(all_defenses_intact());
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `export PATH="$HOME/.cargo/bin:$PATH" && cargo test --features lab --lib lab::guard 2>&1 | tail -20`
Expected: FAIL — `cannot find function guard_ct_eq`.

- [ ] **Step 4: Implement the guards**

At the TOP of `src/lab/guard.rs` add:

```rust
use crate::antihacker::{ct_eq, wipe};
use crate::kdf::KdfParams;

/// La comparación en tiempo constante sigue distinguiendo iguales de distintos y
/// no acepta longitudes distintas.
pub fn guard_ct_eq() -> bool {
    ct_eq(b"clave-secreta", b"clave-secreta")
        && !ct_eq(b"clave-secreta", b"clave-secretX")
        && !ct_eq(b"corta", b"mas-larga")
}

/// La validación de parámetros KDF sigue bloqueando parámetros maliciosos
/// (regresión del DoS por agotamiento de memoria de Argon2) y admite los sanos.
pub fn guard_kdf_validation() -> bool {
    let sane = KdfParams::default().is_sane();
    let malicious = KdfParams {
        mem_kib: u32::MAX,
        iterations: u32::MAX,
        parallelism: u32::MAX,
    };
    sane && !malicious.is_sane()
}

/// El borrado de memoria sigue dejando el buffer en ceros.
pub fn guard_wipe() -> bool {
    let mut buf = [0xAAu8; 32];
    wipe(&mut buf);
    buf.iter().all(|&b| b == 0)
}

/// `true` si TODAS las defensas siguen intactas y efectivas.
pub fn all_defenses_intact() -> bool {
    guard_ct_eq() && guard_kdf_validation() && guard_wipe()
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH" && cargo test --features lab --lib lab::guard 2>&1 | tail -20`
Expected: PASS (4 tests).

- [ ] **Step 6: Commit**

```bash
git add src/lab/mod.rs src/lab/guard.rs
git commit -m "feat(lab): tamper-evidence guard for antihacker defenses"
```

---

### Task 7: Runnable example `securitylab`

**Files:**
- Modify: `Cargo.toml` (add `[[example]]` with `required-features`)
- Create: `examples/securitylab.rs`

**Interfaces:**
- Consumes: `crate::lab::engine::run`; `crate::lab::leak::LeakAttack`; `crate::lab::forge::ForgeAttack`; `crate::lab::guard::all_defenses_intact`; `crate::lab::corpus::Corpus`.

- [ ] **Step 1: Register the example (feature-gated)**

In `Cargo.toml`, after the `[dev-dependencies]` block, add:

```toml
[[example]]
name = "securitylab"
required-features = ["lab"]
```

- [ ] **Step 2: Write the example**

Create `examples/securitylab.rs`:

```rust
//! Quipu Security Lab (Etapa A). Corre los ataques adaptativos con semilla fija,
//! sella los hallazgos en un corpus encadenado y sale con código != 0 si hay
//! brecha o si alguna defensa antihacker fue debilitada.
//!
//! Ejecutar: `cargo run --example securitylab --features lab`

use quipu::lab::corpus::Corpus;
use quipu::lab::engine::{run, LabReport};
use quipu::lab::forge::ForgeAttack;
use quipu::lab::guard::all_defenses_intact;
use quipu::lab::leak::LeakAttack;

fn record(corpus: &mut Corpus, report: &LabReport) -> bool {
    println!(
        "  {:<16} intentos={:<4} avances={:<4} brechas={}",
        report.name,
        report.attempts,
        report.advances,
        report.breaches.len()
    );
    for b in &report.breaches {
        println!("    !! BRECHA: {b}");
        corpus.append("breach", b.as_bytes());
    }
    corpus.append("run", report.name.as_bytes());
    report.is_clean()
}

fn main() {
    println!("== Quipu Security Lab — Etapa A ==");
    let mut corpus = Corpus::new();
    let mut clean = true;

    print!("Defensas antihacker intactas... ");
    if all_defenses_intact() {
        println!("OK");
    } else {
        println!("¡DEBILITADAS!");
        clean = false;
    }

    let leak = run(&mut LeakAttack::new(), 20260701, 128);
    clean &= record(&mut corpus, &leak);

    let forge = run(&mut ForgeAttack::new(), 1337, 120);
    clean &= record(&mut corpus, &forge);

    let corpus_ok = corpus.verify();
    println!(
        "Corpus: {} entradas, cadena {}",
        corpus.len(),
        if corpus_ok { "íntegra" } else { "ROTA" }
    );
    clean &= corpus_ok;

    if clean {
        println!("Resultado: LIMPIO (0 brechas).");
    } else {
        eprintln!("Resultado: FALLO — revisar brechas/defensas.");
        std::process::exit(1);
    }
}
```

- [ ] **Step 3: Build and run the example**

Run: `export PATH="$HOME/.cargo/bin:$PATH" && cargo run --example securitylab --features lab 2>&1 | tail -20`
Expected: prints the report, ends with `Resultado: LIMPIO (0 brechas).` and exit code 0.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml examples/securitylab.rs
git commit -m "feat(lab): runnable securitylab example (feature-gated)"
```

---

### Task 8: CI job, isolation check, clippy and CHANGELOG

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Add the security-lab CI job**

In `.github/workflows/ci.yml`, after the `audit:` job (end of file), add a new job under `jobs:` (same indentation as `test:` and `audit:`):

```yaml
  security-lab:
    name: security lab (feature-gated)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy
      - uses: Swatinem/rust-cache@v2
      - name: Isolation — el arma no viaja en el build por defecto
        run: |
          # Ningún módulo NO-lab debe referenciar crate::lab.
          if grep -rn "crate::lab" src --include='*.rs' | grep -v '^src/lab/' | grep -v 'cfg(feature = "lab")'; then
            echo "FALLO: referencia a crate::lab fuera del laboratorio" && exit 1
          fi
          # El build por defecto (el que se publica) no debe compilar el laboratorio.
          cargo build
      - name: Lab tests
        run: cargo test --features lab --lib lab
      - name: Lab example
        run: cargo run --example securitylab --features lab
      - name: Clippy (lab, deny warnings)
        run: cargo clippy --features lab --all-targets -- -D warnings
```

- [ ] **Step 2: Run the isolation check and clippy locally**

Run:
```bash
export PATH="$HOME/.cargo/bin:$PATH"
grep -rn "crate::lab" src --include='*.rs' | grep -v '^src/lab/' | grep -v 'cfg(feature = "lab")' || echo "AISLAMIENTO OK"
cargo clippy --features lab --all-targets -- -D warnings 2>&1 | tail -15
```
Expected: prints `AISLAMIENTO OK` and clippy finishes with no warnings.

- [ ] **Step 3: Update the CHANGELOG**

In `CHANGELOG.md`, under `## [Unreleased]`, replace the `### Planned` section header line by inserting an `### Added` block ABOVE it:

```markdown
## [Unreleased]

### Added
- **Quipu Security Lab (Etapa A)**: a self-hosted *adaptive* red-team behind a
  non-default `lab` Cargo feature (never compiled into the published crate or the
  PyPI wheel — "the weapon does not ship with the product"). A deterministic,
  seed-reproducible engine drives breach-guided attacks over two surfaces:
  ciphertext/format length-leak distinguishing (surface 1) and adaptive signature
  forgery — frankensignatures, key-substitution and region tampering (surface 4).
  Ships three anti-abuse locks: compile-time isolation, a tamper-evidence guard
  that fails CI if the antihacker defenses (`ct_eq`, KDF-param validation, `wipe`)
  are weakened, and a hash-chained findings corpus. Run with
  `cargo run --example securitylab --features lab`.

### Planned
```

- [ ] **Step 4: Full verification sweep**

Run:
```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo test --all-targets 2>&1 | tail -5          # default suite still green, no lab
cargo test --features lab --lib lab 2>&1 | tail -5
```
Expected: both pass; the default suite does not mention `lab`.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml CHANGELOG.md
git commit -m "ci(lab): security-lab job + isolation check; changelog"
```

---

## Notes for Etapa B (out of scope here, specified only)

Etapa B adds the offline heavy bench inside an isolated `quipu-lab` OCI container
(`--network none`, non-root, read-only FS, no real keys): surface 2 (timing /
side-channel harness) and surface 3 (AI-accelerated password-guessing cost model).
It is documented in the design spec and intentionally NOT implemented in this plan.
