# Quipu Fase 0 — Credibilidad barata (quick wins) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Añadir señales de rigor de alto valor y bajo coste — un gate de timing estadístico (dudect) en el banco offline, SBOM en CI, revisión de dependencias con `cargo-vet`, y releases firmados con sigstore — sin tocar el core criptográfico ni las dependencias por defecto.

**Architecture:** El gate dudect extiende el módulo de timing del Security Lab (`src/lab/timing.rs`, feature `lab-offline`) con la t de Welch y un veredicto constant-time, ejecutado en el ejemplo offline (no en CI, para no ser flaky). El resto son tooling/CI: nuevos jobs en `.github/workflows/ci.yml` (SBOM, cargo-vet) y firmas keyless en `.github/workflows/release.yml`, más una guía de verificación en `docs/RELEASES.md`.

**Tech Stack:** Rust (edition 2024), GitHub Actions, `cargo-cyclonedx` (SBOM CycloneDX), `cargo-vet` (Mozilla, revisión de deps), `sigstore/cosign` (firma keyless OIDC).

## Global Constraints

- Edition 2024; crate `quipu` (cdylib + rlib). Ejecutar cargo con `export PATH="$HOME/.cargo/bin:$PATH"` en cada shell.
- **Cero dependencias nuevas de runtime.** El gate dudect usa solo `std`. Las herramientas (`cargo-cyclonedx`, `cargo-vet`, `cosign`) son tooling de CI, no dependencias del crate.
- El código dudect vive **detrás de `lab-offline`** (`#[cfg(feature = "lab-offline")]` vía el módulo `src/lab/timing.rs`, que ya está gated). **NUNCA** en el build por defecto ni en la rueda de PyPI. El chequeo de aislamiento de CI (ningún módulo no-lab referencia `crate::lab`) debe seguir pasando.
- El gate dudect **no se ejecuta como test bloqueante en CI** (el timing es ruidoso); corre en el ejemplo `securitylab_offline` dentro del contenedor `quipu-lab`. Los tests unitarios de la Fase 0 que SÍ corren en CI son **deterministas** (matemática sobre datos sintéticos), no medidas de tiempo.
- No commitear secretos ni artefactos generados (SBOM) al repo salvo la config de `cargo-vet` (`supply-chain/`).
- Umbral dudect: `|t| > 10` indica fuga dependiente del secreto (criterio dudect estándar).

---

## Task 1: t de Welch (estadístico determinista)

Función pura para comparar dos muestras de tiempos. Es la base del veredicto dudect y es **testeable de forma determinista** (sin medir tiempo).

**Files:**
- Modify: `src/lab/timing.rs` (añadir `welch_t`, `mean_var`, y la constante `DUDECT_T_THRESHOLD` tras la función `median_time`, antes de `pub struct TimingReport`)
- Test: `src/lab/timing.rs` (módulo `#[cfg(test)] mod tests`)

**Interfaces:**
- Produces:
  - `pub const DUDECT_T_THRESHOLD: f64 = 10.0;`
  - `pub fn welch_t(a: &[f64], b: &[f64]) -> f64` — t de Welch; `0.0` si alguna muestra tiene < 2 elementos; `±INFINITY` si la varianza combinada es 0 pero las medias difieren.

- [ ] **Step 1: Write the failing test**

Añade dentro de `mod tests` en `src/lab/timing.rs`:

```rust
    #[test]
    fn welch_t_is_zero_for_identical_samples() {
        assert_eq!(welch_t(&[1.0, 2.0, 3.0, 4.0], &[1.0, 2.0, 3.0, 4.0]), 0.0);
    }

    #[test]
    fn welch_t_is_antisymmetric() {
        let a = [2.0, 4.0, 6.0];
        let b = [1.0, 2.0, 3.0];
        assert!((welch_t(&a, &b) + welch_t(&b, &a)).abs() < 1e-12);
    }

    #[test]
    fn welch_t_known_value() {
        // a: mean 6, var 10 (n-1); b: mean 3, var 2.5; denom = sqrt(2 + 0.5).
        let a = [2.0, 4.0, 6.0, 8.0, 10.0];
        let b = [1.0, 2.0, 3.0, 4.0, 5.0];
        assert!((welch_t(&a, &b) - 1.897366).abs() < 1e-4);
    }

    #[test]
    fn welch_t_handles_too_small_samples() {
        assert_eq!(welch_t(&[1.0], &[1.0, 2.0]), 0.0);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --features lab-offline --lib lab::timing::tests::welch_t 2>&1 | tail -15`
Expected: FAIL — `cannot find function welch_t in this scope`.

- [ ] **Step 3: Write minimal implementation**

Inserta en `src/lab/timing.rs` justo después de la función `median_time` (línea ~25) y antes de `pub struct TimingReport`:

```rust
/// Umbral dudect: `|t|` por encima de esto indica variación de tiempo dependiente
/// del secreto (criterio del test dudect de Reparaz et al.).
pub const DUDECT_T_THRESHOLD: f64 = 10.0;

/// Media y varianza muestral (denominador n-1) de `x`.
fn mean_var(x: &[f64]) -> (f64, f64) {
    let n = x.len() as f64;
    let mean = x.iter().sum::<f64>() / n;
    let var = x.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1.0);
    (mean, var)
}

/// t de Welch entre dos muestras de tiempos. Devuelve `0.0` si alguna muestra
/// tiene menos de 2 elementos; `±INFINITY` si la varianza combinada es 0 pero
/// las medias difieren (fuga determinista).
pub fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    if a.len() < 2 || b.len() < 2 {
        return 0.0;
    }
    let (ma, va) = mean_var(a);
    let (mb, vb) = mean_var(b);
    let denom = (va / a.len() as f64 + vb / b.len() as f64).sqrt();
    let diff = ma - mb;
    if denom == 0.0 {
        return if diff == 0.0 { 0.0 } else { f64::INFINITY * diff.signum() };
    }
    diff / denom
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --features lab-offline --lib lab::timing::tests::welch_t 2>&1 | tail -8`
Expected: PASS — `test result: ok. 4 passed`.

- [ ] **Step 5: Commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
git add src/lab/timing.rs
git commit -m "feat(lab): add Welch's t-test for the dudect timing gate"
```

---

## Task 2: Veredicto dudect (constant-time)

Un reporte que envuelve la `t` y decide constant-time vs fuga. Se separa la parte pura (`from_classes`, testeable) de la que mide tiempo (`dudect_ct_eq`).

**Files:**
- Modify: `src/lab/timing.rs` (añadir `sample_times_ns`, `DudectReport` y `dudect_ct_eq` tras la función `decode_timing`, antes de `#[cfg(test)]`)
- Test: `src/lab/timing.rs` (módulo `tests`)

**Interfaces:**
- Consumes: `welch_t`, `DUDECT_T_THRESHOLD` (Task 1); `ct_eq` (ya importado en el módulo).
- Produces:
  - `pub struct DudectReport { pub name: &'static str, pub t: f64, pub n: usize }`
  - `impl DudectReport { pub fn from_classes(name: &'static str, a: &[f64], b: &[f64]) -> Self; pub fn is_constant_time(&self, threshold: f64) -> bool }`
  - `pub fn dudect_ct_eq(samples: usize) -> DudectReport`

- [ ] **Step 1: Write the failing test**

Añade dentro de `mod tests` en `src/lab/timing.rs`:

```rust
    #[test]
    fn dudect_verdict_constant_time_for_similar_classes() {
        // Dos clases con misma distribución (media 10, varianza pequeña) -> t≈0.
        let a: Vec<f64> = (0..100).map(|i| if i % 2 == 0 { 9.0 } else { 11.0 }).collect();
        let b = a.clone();
        let r = DudectReport::from_classes("t", &a, &b);
        assert!(r.is_constant_time(DUDECT_T_THRESHOLD), "t={}", r.t);
    }

    #[test]
    fn dudect_verdict_flags_leaky_classes() {
        // Clases con medias muy separadas (10 vs 30) -> |t| enorme -> fuga.
        let a: Vec<f64> = (0..100).map(|i| if i % 2 == 0 { 9.0 } else { 11.0 }).collect();
        let b: Vec<f64> = (0..100).map(|i| if i % 2 == 0 { 29.0 } else { 31.0 }).collect();
        let r = DudectReport::from_classes("t", &a, &b);
        assert!(!r.is_constant_time(DUDECT_T_THRESHOLD), "t={}", r.t);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --features lab-offline --lib lab::timing::tests::dudect 2>&1 | tail -15`
Expected: FAIL — `cannot find type DudectReport in this scope` (o similar).

- [ ] **Step 3: Write minimal implementation**

Inserta en `src/lab/timing.rs` justo después de la función `decode_timing` y antes de `#[cfg(test)]`:

```rust
/// Tiempos crudos (nanosegundos) de `op` sobre `samples` repeticiones.
fn sample_times_ns(samples: usize, mut op: impl FnMut()) -> Vec<f64> {
    let n = samples.max(2);
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        let t = Instant::now();
        op();
        v.push(t.elapsed().as_nanos() as f64);
    }
    v
}

/// Veredicto dudect: t de Welch entre dos clases de tiempos y decisión
/// constant-time.
pub struct DudectReport {
    /// Nombre de la operación evaluada.
    pub name: &'static str,
    /// t de Welch entre las dos clases.
    pub t: f64,
    /// Nº de muestras por clase (la menor de las dos).
    pub n: usize,
}

impl DudectReport {
    /// Construye el reporte a partir de dos muestras de tiempos ya recogidas.
    pub fn from_classes(name: &'static str, a: &[f64], b: &[f64]) -> Self {
        DudectReport {
            name,
            t: welch_t(a, b),
            n: a.len().min(b.len()),
        }
    }

    /// `true` si `|t|` no supera `threshold` (sin fuga detectable).
    pub fn is_constant_time(&self, threshold: f64) -> bool {
        self.t.abs() <= threshold
    }
}

/// dudect sobre `ct_eq`: la clase A difiere en el PRIMER byte, la B en el ÚLTIMO.
/// Una comparación en tiempo constante no debe distinguir ambas clases.
pub fn dudect_ct_eq(samples: usize) -> DudectReport {
    let base = [0x5Au8; 64];
    let mut diff_first = base;
    diff_first[0] ^= 0xFF;
    let mut diff_last = base;
    diff_last[63] ^= 0xFF;

    let a = sample_times_ns(samples, || {
        std::hint::black_box(ct_eq(&base, std::hint::black_box(&diff_first)));
    });
    let b = sample_times_ns(samples, || {
        std::hint::black_box(ct_eq(&base, std::hint::black_box(&diff_last)));
    });
    DudectReport::from_classes("dudect/ct_eq", &a, &b)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --features lab-offline --lib lab::timing::tests::dudect 2>&1 | tail -8`
Expected: PASS — `test result: ok. 2 passed`.

- [ ] **Step 5: Verify clippy stays clean under lab-offline**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo clippy --features lab-offline --all-targets -- -D warnings 2>&1 | tail -5`
Expected: sin warnings (exit 0).

- [ ] **Step 6: Commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
git add src/lab/timing.rs
git commit -m "feat(lab): dudect constant-time verdict for ct_eq (offline gate)"
```

---

## Task 3: Cablear el gate dudect en el ejemplo offline

Mostrar la `t` dudect y sumarla al veredicto "limpio" del banco offline (dentro del contenedor).

**Files:**
- Modify: `examples/securitylab_offline.rs` (import + bloque de impresión + condición `clean`)

**Interfaces:**
- Consumes: `dudect_ct_eq`, `DudectReport`, `DUDECT_T_THRESHOLD` (Task 2).

- [ ] **Step 1: Update imports**

En `examples/securitylab_offline.rs`, reemplaza la línea:

```rust
use quipu::lab::timing::{ct_eq_timing, decode_timing};
```

por:

```rust
use quipu::lab::timing::{ct_eq_timing, decode_timing, dudect_ct_eq, DUDECT_T_THRESHOLD};
```

- [ ] **Step 2: Print the dudect verdict**

En `examples/securitylab_offline.rs`, justo DESPUÉS del bloque que imprime `dt` (la línea que termina el `println!` de `decode/correct-vs-wrong-pass`, alrededor de la línea 29) y ANTES del comentario `// Superficie 3: coste de guessing.`, inserta:

```rust
    // Superficie 2 (dudect): t de Welch sobre ct_eq. |t| > umbral = posible fuga.
    let dud = dudect_ct_eq(10_000);
    let verdict = if dud.is_constant_time(DUDECT_T_THRESHOLD) {
        "constant-time"
    } else {
        "POSIBLE FUGA"
    };
    println!(
        "[dudect]   {:<27} t={:.2} (n={}, umbral={:.0}) -> {}",
        dud.name, dud.t, dud.n, DUDECT_T_THRESHOLD, verdict
    );
```

- [ ] **Step 3: Fold dudect into the clean verdict**

En `examples/securitylab_offline.rs`, reemplaza la línea:

```rust
    let clean = ct.within(0.5, 2.0) && dt.within(0.5, 2.0) && g.cracked == 0;
```

por:

```rust
    let clean = ct.within(0.5, 2.0)
        && dt.within(0.5, 2.0)
        && g.cracked == 0
        && dud.is_constant_time(DUDECT_T_THRESHOLD);
```

- [ ] **Step 4: Run the offline example end-to-end**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo run --release --example securitylab_offline --features lab-offline 2>&1 | tail -8`
Expected: imprime una línea `[dudect]   dudect/ct_eq ... -> constant-time`, y termina con `Resultado: sin fuga gruesa de timing y 0 descifrados.` (exit 0). Nota: la `t` empírica varía por máquina; si diera `POSIBLE FUGA` de forma reproducible, es hallazgo real que se investiga (no se relaja el umbral sin justificar).

- [ ] **Step 5: Commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
git add examples/securitylab_offline.rs
git commit -m "feat(lab): surface the dudect timing verdict in the offline bench"
```

---

## Task 4: SBOM (CycloneDX) en CI

Generar un SBOM en cada corrida de CI y subirlo como artefacto. No se commitea (es un artefacto de build).

**Files:**
- Modify: `.gitignore` (ignorar SBOM generado localmente)
- Modify: `.github/workflows/ci.yml` (nuevo job `sbom`)

**Interfaces:** ninguna (tooling).

- [ ] **Step 1: Verify SBOM generation locally**

Run:
```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo install cargo-cyclonedx --locked
cargo cyclonedx --format json
ls -1 *.cdx.json bom.json 2>/dev/null
```
Expected: se instala la herramienta y aparece un fichero SBOM (`quipu.cdx.json` o `bom.json`) que contiene un objeto JSON con `"bomFormat": "CycloneDX"`. Verifícalo:
```bash
grep -m1 'CycloneDX' quipu.cdx.json bom.json 2>/dev/null
```
Expected: una línea que contiene `CycloneDX`.

- [ ] **Step 2: Ignore the generated SBOM**

Añade al final de `.gitignore`:

```gitignore
# SBOM generado (artefacto de build; se produce en CI, no se versiona)
*.cdx.json
bom.json
bom.xml
```

- [ ] **Step 3: Add the CI job**

En `.github/workflows/ci.yml`, añade este job al final (después del job `security-lab`, mismo nivel de indentación que los demás jobs):

```yaml
  sbom:
    name: SBOM (CycloneDX)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - name: Install cargo-cyclonedx
        run: cargo install cargo-cyclonedx --locked
      - name: Generate SBOM (JSON)
        run: cargo cyclonedx --format json
      - name: Upload SBOM artifact
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: |
            *.cdx.json
            bom.json
          if-no-files-found: error
```

- [ ] **Step 4: Lint the workflow YAML locally**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('ci.yml OK')"`
Expected: `ci.yml OK` (sin excepción de parseo).

- [ ] **Step 5: Clean the local SBOM and commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
rm -f *.cdx.json bom.json bom.xml
git add .gitignore .github/workflows/ci.yml
git commit -m "ci: generate and upload a CycloneDX SBOM"
```

---

## Task 5: Revisión de dependencias con cargo-vet

Inicializar `cargo-vet` (registra las deps actuales) y añadir un gate en CI.

**Files:**
- Create: `supply-chain/config.toml`, `supply-chain/audits.toml`, `supply-chain/imports.lock` (los genera `cargo vet init`)
- Modify: `.github/workflows/ci.yml` (nuevo job `vet`)

**Interfaces:** ninguna (tooling).

- [ ] **Step 1: Initialize cargo-vet locally**

Run:
```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo install cargo-vet --locked
cargo vet init
cargo vet --locked
```
Expected: se crea el directorio `supply-chain/` con `config.toml`, `audits.toml` e `imports.lock`; `cargo vet init` marca las dependencias actuales como *exemptions*, y `cargo vet` termina con `Vetting succeeded` (exit 0).

- [ ] **Step 2: Add the CI job**

En `.github/workflows/ci.yml`, añade este job al final (después de `sbom`):

```yaml
  vet:
    name: cargo-vet (supply chain)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - name: Install cargo-vet
        run: cargo install cargo-vet --locked
      - name: Vet dependencies
        run: cargo vet --locked
```

- [ ] **Step 3: Lint the workflow YAML locally**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('ci.yml OK')"`
Expected: `ci.yml OK`.

- [ ] **Step 4: Commit**

```bash
git add supply-chain/ .github/workflows/ci.yml
git commit -m "ci: add cargo-vet supply-chain review gate"
```

---

## Task 6: Releases firmados (sigstore) + guía de verificación

Firmar los artefactos del release de forma keyless (OIDC de GitHub) con cosign, y documentar cómo verificar la cadena de confianza.

**Files:**
- Modify: `.github/workflows/release.yml` (nuevo job `sign` + permiso `id-token`)
- Create: `docs/RELEASES.md`

**Interfaces:** ninguna (tooling/docs).

- [ ] **Step 1: Add the signing job to release.yml**

En `.github/workflows/release.yml`, añade este job al final del fichero (mismo nivel que `wheels`, `sdist`, `publish`):

```yaml
  sign:
    name: sign artifacts (sigstore)
    needs: [wheels, sdist]
    runs-on: ubuntu-latest
    if: startsWith(github.ref, 'refs/tags/v')
    permissions:
      id-token: write   # cosign keyless (OIDC), sin claves en secretos
      contents: read
    steps:
      - uses: actions/download-artifact@v4
        with:
          path: dist
          merge-multiple: true
      - name: Install cosign
        uses: sigstore/cosign-installer@v3
      - name: Sign each artifact (keyless)
        run: |
          for f in dist/*; do
            cosign sign-blob --yes --bundle "${f}.sigstore" "${f}"
          done
      - uses: actions/upload-artifact@v4
        with:
          name: signatures
          path: dist/*.sigstore
          if-no-files-found: error
```

- [ ] **Step 2: Lint the workflow YAML locally**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/release.yml')); print('release.yml OK')"`
Expected: `release.yml OK`.

- [ ] **Step 3: Write the verification guide**

Crea `docs/RELEASES.md` con este contenido:

```markdown
# Verificar la autenticidad de un release de Quipu

Cada release publicado desde un tag `v*` produce dos capas de procedencia
verificable, ambas **keyless** (sin claves privadas de larga vida): la identidad
del firmante es el propio workflow de GitHub Actions, atada vía OIDC a sigstore.

## 1. Wheels de PyPI — attestations PEP 740

`pypa/gh-action-pypi-publish` adjunta attestations de procedencia (PEP 740) a cada
rueda y al sdist. `pip`/`uv` las verifican automáticamente cuando están disponibles;
también puedes inspeccionarlas en la página del proyecto en PyPI.

## 2. Artefactos firmados con cosign (sigstore)

El job `sign` firma cada artefacto de `dist/` y sube un *bundle* `<archivo>.sigstore`.
Para verificar un artefacto descargado junto a su bundle:

```bash
cosign verify-blob \
  --bundle quipu_crypto-<versión>-<plataforma>.whl.sigstore \
  --certificate-identity-regexp 'https://github.com/isazajuancarlos/quipu/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  quipu_crypto-<versión>-<plataforma>.whl
```

Una verificación correcta imprime `Verified OK`. Si el archivo fue alterado o no
proviene del workflow de este repositorio, la verificación falla.

## 3. crates.io

El crate `quipu` se publica manualmente con `cargo publish`. Su integridad la
respalda el checksum del índice de crates.io. La procedencia reproducible del
código es el tag firmado del repositorio y este documento.
```

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/release.yml docs/RELEASES.md
git commit -m "ci,docs: sign release artifacts with sigstore + verification guide"
```

---

## Task 7: Enlazar la nueva documentación y cerrar la fase

Referenciar `docs/RELEASES.md` desde el README y registrar la Fase 0 en el CHANGELOG.

**Files:**
- Modify: `README.md` (sección "Documentación")
- Modify: `CHANGELOG.md` (bajo `[Unreleased]`)

- [ ] **Step 1: Link RELEASES.md from the README**

En `README.md`, en la lista de la sección `## Documentación`, añade tras la línea de `SECURITY.md`:

```markdown
- [`docs/RELEASES.md`](docs/RELEASES.md) — cómo verificar la autenticidad de un
  release (attestations PEP 740 + firmas sigstore/cosign).
```

- [ ] **Step 2: Record Phase 0 under [Unreleased] in the CHANGELOG**

En `CHANGELOG.md`, bajo `## [Unreleased]`, añade una subsección `### Added` (antes de `### Planned`):

```markdown
### Added
- **Supply-chain & side-channel credibility (Security Lab Fase 0)**: a dudect-style
  constant-time gate (Welch's t-test) in the offline timing bench; a CycloneDX SBOM
  and a `cargo-vet` dependency-review gate in CI; and sigstore/cosign keyless
  signatures for release artifacts, documented in `docs/RELEASES.md`.
```

- [ ] **Step 3: Full verification sweep**

Run:
```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo test --features lab-offline --lib lab::timing 2>&1 | grep 'test result'
cargo clippy --features lab-offline --all-targets -- -D warnings 2>&1 | tail -2
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); yaml.safe_load(open('.github/workflows/release.yml')); print('workflows OK')"
```
Expected: los tests de `lab::timing` pasan; clippy sin warnings; `workflows OK`.

- [ ] **Step 4: Commit**

```bash
git add README.md CHANGELOG.md
git commit -m "docs: link RELEASES.md and record Phase 0 in the changelog"
```

---

## Notas de ejecución y verificación

- Los jobs de CI (`sbom`, `vet`) y el de firma (`sign`) **solo se verifican de
  verdad al correr en GitHub Actions**. En local se valida: (a) que las herramientas
  producen la salida esperada (Steps de "verify locally"), y (b) que el YAML parsea.
  No se puede ejecutar el runner de Actions desde el sandbox.
- El gate dudect es **offline por diseño**: corre en el ejemplo/contenedor, no como
  test bloqueante de CI, para no introducir un test flaky por ruido de timing. Los
  tests que sí gatean CI son los deterministas de `welch_t` y `from_classes`.
- Al terminar la fase, el estado natural es abrir PR/merge y decidir si entra en el
  próximo release. La Fase 1 (SLH-DSA / triple-híbrido) es el siguiente ciclo
  spec → plan → implementación.
```
