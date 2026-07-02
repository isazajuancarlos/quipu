# Quipu Security Lab — Etapa B — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Etapa B offline bench of the Quipu Security Lab — a timing/side-channel harness (surface 2) and an AI-accelerated password-guessing cost model (surface 3), plus the isolated `quipu-lab` container that runs them without network or real keys.

**Architecture:** A second, non-default feature `lab-offline` (implies `lab`) gates the heavy/noisy bench so the CI `security-lab` job (which runs `--features lab`) stays deterministic and never compiles it. The bench is pure Rust — deterministic in *what* it exercises, statistical in *what it measures* — and is intended to run inside the `quipu-lab` OCI container with `--network none`, non-root, read-only FS, and no access to real keys. No ML model is shipped: the container is documented as "ML-ready" (a place to plug heavy models later), matching the project's no-heavy-deps, reproducible, audit-friendly ethos.

**Tech Stack:** Rust (edition 2024), std only (`std::time::Instant`, `std::hint::black_box`), existing crates (`crate::api`, `crate::antihacker`, `crate::pqsign`, `crate::dictionaries`, `crate::kdf`, `crate::lab::engine`). Docker/OCI for the isolation cage. No new third-party dependencies.

## Global Constraints

- Rust edition: 2024.
- New feature `lab-offline = ["lab"]`; NOT default, NOT enabled by maturin, NOT run by the CI `security-lab` job (which uses `--features lab`).
- Everything new under `src/lab/timing.rs` and `src/lab/guessing.rs` is gated `#[cfg(feature = "lab-offline")]`.
- No new dependencies. No ML model bundled (container stays "ML-ready").
- The bench only attacks Quipu; never third parties. Never invent/substitute primitives.
- Timing/guessing assertions use generous tolerances (offline, machine-dependent): the HARD assertions are functional (no breach, all guesses rejected); timing ratios are reported and only gross deviations flagged.

---

### Task 1: `lab-offline` feature + timing measurement core

**Files:**
- Modify: `Cargo.toml` (add `lab-offline` feature)
- Modify: `src/lab/mod.rs` (gated `pub mod timing;`)
- Create: `src/lab/timing.rs`

**Interfaces:**
- Produces:
  - `fn median_time(samples: usize, op: impl FnMut()) -> std::time::Duration`
  - `struct TimingReport { pub name: &'static str, pub a: std::time::Duration, pub b: std::time::Duration }` with `fn ratio(&self) -> f64` and `fn within(&self, lo: f64, hi: f64) -> bool`.

- [ ] **Step 1: Add the feature and module wiring**

In `Cargo.toml`, under `[features]`, after the `lab = []` line add:

```toml
# Banco OFFLINE pesado/ruidoso (timing, guessing). Implica `lab`. NO lo corre el
# job de CI (que usa --features lab); vive dentro del contenedor quipu-lab.
lab-offline = ["lab"]
```

In `src/lab/mod.rs`, after `pub mod leak;` add:

```rust
#[cfg(feature = "lab-offline")]
pub mod timing;
```

- [ ] **Step 2: Write the failing test**

Create `src/lab/timing.rs`:

```rust
//! Superficie 2 (banco offline): harness de timing / canales laterales.
//!
//! Mide tiempos de operaciones sensibles y compara distribuciones para detectar
//! variación dependiente del secreto. La IA del atacante solo AMPLIFICA fugas que
//! ya existan; si no hay diferencia de tiempo, no hay traza que aprender. Ruidoso
//! y dependiente de la máquina: vive fuera del CI, dentro del contenedor.

use std::time::{Duration, Instant};

/// Mediana del tiempo de `op` sobre `samples` repeticiones.
pub fn median_time(samples: usize, mut op: impl FnMut()) -> Duration {
    let mut times = Vec::with_capacity(samples.max(1));
    for _ in 0..samples.max(1) {
        let t = Instant::now();
        op();
        times.push(t.elapsed());
    }
    times.sort_unstable();
    times[times.len() / 2]
}

/// Comparación de tiempos entre dos clases de entrada.
pub struct TimingReport {
    /// Nombre de la comparación.
    pub name: &'static str,
    /// Mediana de la clase A.
    pub a: Duration,
    /// Mediana de la clase B.
    pub b: Duration,
}

impl TimingReport {
    /// Razón b/a (1.0 = idénticos). Evita división por cero.
    pub fn ratio(&self) -> f64 {
        let a = self.a.as_secs_f64().max(1e-12);
        self.b.as_secs_f64() / a
    }

    /// `true` si la razón está dentro de `[lo, hi]` (sin fuga gruesa de timing).
    pub fn within(&self, lo: f64, hi: f64) -> bool {
        let r = self.ratio();
        r >= lo && r <= hi
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn median_time_measures_something() {
        let d = median_time(16, || {
            std::hint::black_box((0..100).sum::<u64>());
        });
        assert!(d >= Duration::ZERO);
    }

    #[test]
    fn ratio_and_within_work() {
        let r = TimingReport {
            name: "t",
            a: Duration::from_micros(100),
            b: Duration::from_micros(110),
        };
        assert!(r.within(0.5, 2.0));
        assert!((r.ratio() - 1.1).abs() < 0.01);
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `export PATH="$HOME/.cargo/bin:$PATH" && cargo test --features lab-offline --lib lab::timing 2>&1 | tail -20`
Expected: FAIL first because the module/feature isn't wired, then PASS once Step 1+2 applied. If Step 1+2 are done, this compiles and PASSES (2 tests). (This task's "failing" state is the pre-wiring compile error.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH" && cargo test --features lab-offline --lib lab::timing 2>&1 | tail -20`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml src/lab/mod.rs src/lab/timing.rs
git commit -m "feat(lab): lab-offline feature + timing measurement core"
```

---

### Task 2: Surface 2 — constant-time / timing-leak checks

**Files:**
- Modify: `src/lab/timing.rs`

**Interfaces:**
- Consumes: `median_time`, `TimingReport`; `crate::antihacker::ct_eq`; `crate::api::{encode, decode, Options}`; `crate::kdf::KdfParams`; `crate::dictionaries`.
- Produces:
  - `fn ct_eq_timing(samples: usize) -> TimingReport`
  - `fn decode_timing(samples: usize) -> TimingReport`

- [ ] **Step 1: Write the failing test**

In `src/lab/timing.rs`, inside `#[cfg(test)] mod tests`, add:

```rust
    #[test]
    fn ct_eq_shows_no_gross_timing_leak() {
        let report = ct_eq_timing(2000);
        // Tolerancia amplia (ruido de máquina); solo detecta fugas GRUESAS.
        assert!(
            report.within(0.5, 2.0),
            "ct_eq no debería depender de dónde difieren los bytes: ratio={}",
            report.ratio()
        );
    }

    #[test]
    fn decode_time_independent_of_passphrase_correctness() {
        let report = decode_timing(24);
        assert!(
            report.within(0.5, 2.0),
            "decode con pass correcta vs incorrecta debe costar ~lo mismo (Argon2 domina): ratio={}",
            report.ratio()
        );
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `export PATH="$HOME/.cargo/bin:$PATH" && cargo test --features lab-offline --lib lab::timing 2>&1 | tail -20`
Expected: FAIL — `cannot find function ct_eq_timing`.

- [ ] **Step 3: Implement the checks**

In `src/lab/timing.rs`, below the `TimingReport` impl (above the tests), add:

```rust
use crate::antihacker::ct_eq;
use crate::api::{decode, encode, Options};
use crate::dictionaries;
use crate::kdf::KdfParams;

/// Compara el tiempo de `ct_eq` cuando los buffers difieren en el PRIMER byte vs
/// en el ÚLTIMO. Una comparación en tiempo constante no debe distinguirlos.
pub fn ct_eq_timing(samples: usize) -> TimingReport {
    let base = [0x5Au8; 64];
    let mut diff_first = base;
    diff_first[0] ^= 0xFF;
    let mut diff_last = base;
    diff_last[63] ^= 0xFF;

    let a = median_time(samples, || {
        std::hint::black_box(ct_eq(&base, std::hint::black_box(&diff_first)));
    });
    let b = median_time(samples, || {
        std::hint::black_box(ct_eq(&base, std::hint::black_box(&diff_last)));
    });
    TimingReport {
        name: "ct_eq/first-vs-last-diff",
        a,
        b,
    }
}

/// Compara el tiempo de `decode` con la passphrase CORRECTA vs una INCORRECTA.
/// Ambas ejecutan la derivación Argon2id completa, que domina el coste, así que
/// no debe filtrarse por timing si la passphrase acertó.
pub fn decode_timing(samples: usize) -> TimingReport {
    let dict = dictionaries::ascii94();
    // Coste moderado: suficiente para que Argon2 domine, ágil para el banco.
    let opts = Options {
        pepper: b"",
        kdf_params: KdfParams {
            mem_kib: 8 * 1024,
            iterations: 2,
            parallelism: 1,
        },
        codebook_id: 0,
    };
    let secret = b"contenido protegido para el banco de timing";
    let sym = encode(secret, "passphrase-correcta", &dict, &opts);

    let a = median_time(samples, || {
        std::hint::black_box(decode(&sym, "passphrase-correcta", &dict, b"").is_ok());
    });
    let b = median_time(samples, || {
        std::hint::black_box(decode(&sym, "passphrase-incorrecta", &dict, b"").is_ok());
    });
    TimingReport {
        name: "decode/correct-vs-wrong-pass",
        a,
        b,
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH" && cargo test --features lab-offline --lib lab::timing 2>&1 | tail -20`
Expected: PASS (4 tests). Note: timing tests are inherently noisy; the tolerance band `[0.5, 2.0]` is deliberately wide. If a run is flaky on a loaded machine, re-run.

- [ ] **Step 5: Commit**

```bash
git add src/lab/timing.rs
git commit -m "feat(lab): surface 2 constant-time / timing-leak checks"
```

---

### Task 3: Surface 3 — AI-accelerated guessing cost model

**Files:**
- Modify: `src/lab/mod.rs` (gated `pub mod guessing;`)
- Create: `src/lab/guessing.rs`

**Interfaces:**
- Consumes: `crate::api::{encode, decode, Options}`; `crate::kdf::KdfParams`; `crate::dictionaries`; `crate::lab::engine::Rng`.
- Produces:
  - `struct GuessReport { pub attempts: usize, pub cracked: usize, pub total: std::time::Duration, pub per_guess: std::time::Duration }` with `fn cost_years(&self, keyspace_bits: u32) -> f64`.
  - `fn guessing_cost(guesses: usize, seed: u64) -> GuessReport`

- [ ] **Step 1: Declare the module**

In `src/lab/mod.rs`, after the gated `pub mod timing;` add:

```rust
#[cfg(feature = "lab-offline")]
pub mod guessing;
```

- [ ] **Step 2: Write the failing test**

Create `src/lab/guessing.rs`:

```rust
//! Superficie 3 (banco offline): modelo de coste de guessing acelerado por IA.
//!
//! Un atacante prioriza contraseñas con un modelo local (aquí, una lista "rankeada"
//! simulada). Lo que protege a Quipu NO es ocultar el ranking: es que CADA intento
//! cuesta una derivación Argon2id memory-hard. Este banco verifica que ningún
//! intento del ranking descifra y estima el coste por intento (el piso que arruina
//! el guessing masivo, con o sin IA).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranked_guesses_never_crack_and_cost_holds() {
        let report = guessing_cost(64, 2026);
        assert_eq!(report.attempts, 64);
        assert_eq!(report.cracked, 0, "ningún intento del ranking debe descifrar");
        assert!(
            report.per_guess > std::time::Duration::ZERO,
            "cada intento debe costar una derivación real"
        );
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `export PATH="$HOME/.cargo/bin:$PATH" && cargo test --features lab-offline --lib lab::guessing 2>&1 | tail -20`
Expected: FAIL — `cannot find function guessing_cost`.

- [ ] **Step 4: Implement the cost model**

At the TOP of `src/lab/guessing.rs` add:

```rust
use crate::api::{decode, encode, Options};
use crate::dictionaries;
use crate::kdf::KdfParams;
use crate::lab::engine::Rng;
use std::time::{Duration, Instant};

/// Resultado del modelo de coste de guessing.
pub struct GuessReport {
    /// Intentos del ranking probados.
    pub attempts: usize,
    /// Cuántos descifraron (debe ser 0).
    pub cracked: usize,
    /// Tiempo total del barrido.
    pub total: Duration,
    /// Coste medio por intento.
    pub per_guess: Duration,
}

impl GuessReport {
    /// Estima los años para recorrer un espacio de `keyspace_bits` bits al coste
    /// medido por intento (una sola máquina, un solo hilo).
    pub fn cost_years(&self, keyspace_bits: u32) -> f64 {
        let secs_per = self.per_guess.as_secs_f64();
        let guesses = 2f64.powi(keyspace_bits as i32);
        secs_per * guesses / (365.25 * 24.0 * 3600.0)
    }
}

/// Cifra un secreto con una passphrase real y luego prueba `guesses` candidatos
/// "rankeados" (deterministas vía `seed`), ninguno igual al real. Mide el coste.
pub fn guessing_cost(guesses: usize, seed: u64) -> GuessReport {
    let dict = dictionaries::ascii94();
    // Coste moderado y realista para el banco (Argon2id memory-hard).
    let opts = Options {
        pepper: b"",
        kdf_params: KdfParams {
            mem_kib: 16 * 1024,
            iterations: 2,
            parallelism: 1,
        },
        codebook_id: 0,
    };
    let real_pass = "correcta-y-fuera-del-ranking-2026";
    let secret = b"tesoro";
    let sym = encode(secret, real_pass, &dict, &opts);

    // Lista "rankeada por IA": candidatos prioritarios simulados, deterministas.
    let mut rng = Rng::seeded(seed);
    let mut cracked = 0usize;
    let start = Instant::now();
    for i in 0..guesses {
        let guess = format!("guess-{}-{}", i, rng.next_u64());
        // El pepper vacío es el mismo del cifrado; el guess es la única variable.
        if decode(&sym, &guess, &dict, b"").is_ok() {
            cracked += 1;
        }
    }
    let total = start.elapsed();
    let per_guess = if guesses == 0 {
        Duration::ZERO
    } else {
        total / guesses as u32
    };

    GuessReport {
        attempts: guesses,
        cracked,
        total,
        per_guess,
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH" && cargo test --features lab-offline --lib lab::guessing 2>&1 | tail -20`
Expected: PASS (1 test). Takes a few seconds (64 real Argon2 derivations).

- [ ] **Step 6: Commit**

```bash
git add src/lab/mod.rs src/lab/guessing.rs
git commit -m "feat(lab): surface 3 AI-accelerated guessing cost model"
```

---

### Task 4: Offline bench example `securitylab_offline`

**Files:**
- Modify: `Cargo.toml` (add `[[example]]`)
- Create: `examples/securitylab_offline.rs`

**Interfaces:**
- Consumes: `crate::lab::timing::{ct_eq_timing, decode_timing}`; `crate::lab::guessing::guessing_cost`.

- [ ] **Step 1: Register the example**

In `Cargo.toml`, after the existing `[[example]]` block for `securitylab`, add:

```toml
[[example]]
name = "securitylab_offline"
required-features = ["lab-offline"]
```

- [ ] **Step 2: Write the example**

Create `examples/securitylab_offline.rs`:

```rust
//! Quipu Security Lab — banco OFFLINE (Etapa B). Timing (superficie 2) y coste de
//! guessing (superficie 3). Pensado para correr AISLADO dentro del contenedor
//! `quipu-lab` (--network none, sin claves reales).
//!
//! Ejecutar: `cargo run --release --example securitylab_offline --features lab-offline`

use quipu::lab::guessing::guessing_cost;
use quipu::lab::timing::{ct_eq_timing, decode_timing};

fn main() {
    println!("== Quipu Security Lab — banco offline (Etapa B) ==");

    // Superficie 2: timing.
    let ct = ct_eq_timing(4000);
    println!(
        "[timing] {:<28} a={:?} b={:?} ratio={:.3}",
        ct.name,
        ct.a,
        ct.b,
        ct.ratio()
    );
    let dt = decode_timing(32);
    println!(
        "[timing] {:<28} a={:?} b={:?} ratio={:.3}",
        dt.name,
        dt.a,
        dt.b,
        dt.ratio()
    );

    // Superficie 3: coste de guessing.
    let g = guessing_cost(128, 2026);
    println!(
        "[guessing] intentos={} descifrados={} coste/intento={:?}",
        g.attempts, g.cracked, g.per_guess
    );
    println!(
        "[guessing] extrapolación a 2^40 intentos: {:.1} años (1 hilo)",
        g.cost_years(40)
    );

    let clean = ct.within(0.5, 2.0) && dt.within(0.5, 2.0) && g.cracked == 0;
    if clean {
        println!("Resultado: sin fuga gruesa de timing y 0 descifrados.");
    } else {
        eprintln!("Resultado: revisar — posible fuga de timing o descifrado.");
        std::process::exit(1);
    }
}
```

- [ ] **Step 3: Build and run the example**

Run: `export PATH="$HOME/.cargo/bin:$PATH" && cargo run --release --example securitylab_offline --features lab-offline 2>&1 | tail -12`
Expected: prints timing + guessing lines, ends with `Resultado: sin fuga gruesa de timing y 0 descifrados.` and exit 0.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml examples/securitylab_offline.rs
git commit -m "feat(lab): offline bench example (timing + guessing)"
```

---

### Task 5: `quipu-lab` container + runner + docs

**Files:**
- Create: `lab/Dockerfile`
- Create: `lab/run.sh`
- Create: `lab/README.md`
- Modify: `CHANGELOG.md`
- Modify: `README.md`

**Interfaces:** none (packaging + docs).

- [ ] **Step 1: Write the Dockerfile (isolation cage)**

Create `lab/Dockerfile`:

```dockerfile
# Contenedor del banco offline del Quipu Security Lab.
# Aislamiento: se EJECUTA con `--network none`, usuario no-root y FS de solo
# lectura (ver lab/run.sh). El arma no viaja con el producto: esta imagen es
# solo para investigación local, nunca se publica ni entra en el crate/rueda.
# Base fijada por versión (para reproducibilidad, se puede fijar por @sha256).
FROM rust:1.90-slim-bookworm

# Usuario no-root.
RUN useradd --create-home --uid 1000 labrunner
WORKDIR /work

# Copia el código (solo lo necesario para compilar el banco).
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY examples ./examples

# Compila el banco offline en release.
RUN cargo build --release --example securitylab_offline --features lab-offline

USER labrunner
# Corre el banco. Sin red, sin claves reales (montadas fuera).
ENTRYPOINT ["/work/target/release/examples/securitylab_offline"]
```

- [ ] **Step 2: Write the runner**

Create `lab/run.sh`:

```bash
#!/usr/bin/env bash
# Construye y ejecuta el banco offline del Quipu Security Lab dentro de una jaula:
#   - sin red         (--network none): no puede exfiltrar ni descargar payloads
#   - solo lectura     (--read-only): no puede modificar la imagen
#   - usuario no-root  (definido en el Dockerfile)
#   - sin claves reales: NO se monta oprf_seed.bin ni ningún secreto
set -euo pipefail
cd "$(dirname "$0")/.."

docker build -t quipu-lab -f lab/Dockerfile .
docker run --rm \
  --network none \
  --read-only \
  --tmpfs /tmp \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  quipu-lab
```

- [ ] **Step 3: Write the lab README and syntax-check the runner**

Create `lab/README.md`:

```markdown
# Quipu Security Lab — banco offline (Etapa B)

Mesa de laboratorio PESADA y AISLADA. No corre en CI ni viaja en el producto.

## Qué contiene
- **Superficie 2 — timing** (`src/lab/timing.rs`): busca variación de tiempo
  dependiente del secreto en `ct_eq` y en `decode`.
- **Superficie 3 — guessing** (`src/lab/guessing.rs`): modela un atacante que
  prioriza contraseñas con IA y verifica que el coste Argon2id por intento
  arruina el guessing masivo.

## Cómo correrlo

Local (rápido, para desarrollo):
```
cargo run --release --example securitylab_offline --features lab-offline
```

Aislado en contenedor (recomendado; sin red, sin claves, solo lectura):
```
bash lab/run.sh
```

## ML-ready
El banco es Rust determinista (reproducible, apto para auditoría). El contenedor
queda PREPARADO para enchufar modelos ML pesados (distinguidores de timing,
ranking de contraseñas) si algún día se quiere; no se empaqueta ninguno hoy para
no añadir dependencias pesadas ni no-determinismo.
```

Then run: `bash -n lab/run.sh && echo "run.sh OK"`
Expected: `run.sh OK` (syntax valid).

- [ ] **Step 4: Update CHANGELOG and README**

In `CHANGELOG.md`, under `## [Unreleased]` → `### Added`, add a new bullet at the top:

```markdown
- **Quipu Security Lab — Etapa B (offline bench)**: timing / side-channel harness
  (surface 2: constant-time `ct_eq` and passphrase-independent `decode` timing)
  and an AI-accelerated password-guessing cost model (surface 3: verifies the
  Argon2id per-guess cost floor holds and that a ranked wordlist never cracks).
  Gated behind a new non-default `lab-offline` feature (implies `lab`, not run by
  CI) and shipped with an isolated `quipu-lab` OCI container (`--network none`,
  non-root, read-only, no real keys). Rust-only and reproducible; the container is
  documented as "ML-ready". Run with `bash lab/run.sh` or
  `cargo run --release --example securitylab_offline --features lab-offline`.
```

In `README.md`, in the "## Construir y probar" block, after the `securitylab` line add:

```bash
bash lab/run.sh   # banco offline aislado (timing + guessing) — Etapa B
```

- [ ] **Step 5: Commit**

```bash
git add lab/Dockerfile lab/run.sh lab/README.md CHANGELOG.md README.md
git commit -m "feat(lab): quipu-lab isolation container + runner + docs (Etapa B)"
```

---

## Self-review notes

- Spec §5 (Etapa B) coverage: surface 2 → Task 2; surface 3 → Task 3; container
  `quipu-lab` (--network none, non-root, read-only, no keys) → Task 5; "ML-ready"
  documented → Task 5. Two-speeds/two-cages preserved via the `lab-offline`
  feature (CI runs `--features lab`, never the offline bench).
- No new dependencies; std-only timing.
- Hard assertions are functional (no crack, measurable per-guess cost); timing
  uses wide tolerances because it is offline and machine-dependent.
- Docker build is NOT executed in the dev sandbox (no Docker); the payload is
  verified by running the example locally, and `run.sh` is syntax-checked.
