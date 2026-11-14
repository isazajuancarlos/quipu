# Quipu — Roadmap para igualar y superar a las librerías de clase militar

**Fecha:** 2026-07-02
**Estado:** diseño aprobado (estructura), pendiente de specs por fase
**Tipo:** spec-paraguas (programa multi-fase). Cada fase tendrá su propio spec →
plan → implementación.

## 1. Objetivo

Llevar a Quipu de "criptografía correcta y moderna" a "criptografía **acreditable
y, en varios ejes, superior** a una librería de clase militar/gubernamental",
persiguiendo simultáneamente —por fases— los tres sentidos de "superar":

1. **Superioridad técnica demostrable** — que Quipu sea objetivamente más
   conservador/moderno (triple-híbrido de firma, KDF memory-hard, red-team
   propio) y poder probarlo con evidencia pública.
2. **Credibilidad / listo para auditoría** — señales que un evaluador externo
   (OTF, Cure53) y la comunidad reconocen: SBOM, releases firmados, `cargo-vet`,
   gate de timing, claims verificables.
3. **Venta a gobierno / cumplimiento** — poder entrar en compras públicas: modo
   FIPS, backend HSM/KMS, gestión de claves.

Punto de partida (ya conseguido, v0.4.0): parámetros post-cuánticos en
**categoría de seguridad NIST 5 (CNSA 2.0)** — **ML-KEM-1024** + **ML-DSA-87** —,
firma híbrida con combinador AND, KEM híbrido con binding X-Wing, Security Lab
auto-atacante (Etapas A+B), pre-auditoría interna y VOPRF verificable.

## 2. Principios rectores (invariantes de todo el programa)

- **No inventar primitivas.** Solo se componen primitivas vetadas y estandarizadas
  (FIPS-203/204/205, RFCs). Lo propio es el formato, el binding de dominio y la
  composición.
- **Core lean, capacidades opcionales.** Toda capacidad pesada va **detrás de una
  feature Cargo** (como `lab`, `python`, `fips`, `hsm`, `slh`). El build por
  defecto y la rueda de PyPI se mantienen ligeros.
- **Alcance: datos en reposo.** No mensajería/sesiones/ratcheting. (Ver
  `[[quipu-scope-data-at-rest]]`.)
- **Construible vs. financiado.** Se separan explícitamente:
  - *Construible ahora* (lo implementa el proyecto en el repo): Fases 0–4.
  - *Gated por fondos/terceros* (se prepara y documenta, no bloquea el resto):
    auditoría independiente y validación FIPS 140-3 CMVP.
- **Compatibilidad de formato versionada.** Cualquier cambio de wire-format sube
  versión y, cuando aporte, un identificador de esquema/suite en el contenedor.
- **Cada capacidad se auto-ataca.** Toda fase que toque cripto añade cobertura en
  el Security Lab (`[[quipu-security-lab]]`) antes de considerarse hecha.

## 3. Análisis de brecha (tras v0.4.0)

| Aspecto | Clase militar | Quipu hoy | Fase que lo cierra |
|---|---|---|---|
| Nivel de seguridad PQ | Categoría 5 | ✅ Categoría 5 (1024/87) | — (hecho en v0.4.0) |
| Firmas hash-based | LMS/XMSS (firmware) | ❌ | **Fase 1** (SLH-DSA, mejor: stateless) |
| Conformidad FIPS | Módulo validado | ❌ (ChaCha/Argon2 no aprobados) | **Fase 2** (modo FIPS) |
| Canales laterales | Impl. constant-time verificada | Parcial (`subtle`, Lab mide) | **Fase 0** (gate dudect) |
| Almacenamiento HW de claves | HSM anti-tamper | ❌ (memoria + `zeroize`) | **Fase 3** (KeyStore/HSM) |
| Gestión de claves | PKI, rotación, escrow | Mínima | **Fase 4** (rotación + Shamir) |
| Cadena de suministro | SBOM, firma, provenance | Parcial (attestations PyPI) | **Fase 0** (SBOM, vet, firmar) |
| Auditoría independiente | Sí (acreditación) | ❌ (enviada a OTF) | Milestone externo |

## 4. Roadmap por fases

Cada fase es un sub-proyecto con su propio spec y plan. Aquí se fija el **objetivo,
alcance, entregables, criterio de éxito, feature gate y riesgos**; el detalle de
implementación vive en el spec de cada fase.

### Fase 0 — Credibilidad barata (quick wins)

- **Objetivo:** máxima señal de rigor por mínimo esfuerzo; desbloquea confianza de
  auditores y comunidad.
- **Alcance / entregables:**
  - **SBOM** generado en CI (`cargo cyclonedx` o equivalente), publicado como
    artefacto del release.
  - **`cargo-vet`** (o `cargo-crev`) para revisión/auditoría de dependencias, con
    umbral en CI. `cargo-audit` ya está.
  - **Releases firmados** con **sigstore/`gitsign`** o firma del tag; documentar
    verificación. (Las wheels de PyPI ya llevan attestations SLSA.)
  - **Gate de timing "dudect"**: elevar `src/lab/timing.rs` a una prueba estadística
    (t-test de Welch sobre dos clases de entrada) con umbral, ejecutada de forma
    robusta (muestreo alto / entorno controlado) para no romper por ruido de CI.
- **Criterio de éxito:** CI produce SBOM + verificación de deps; un tag firmado y
  verificable; el gate de timing corre y documenta sus márgenes.
- **Feature gate:** ninguno (es tooling/CI); el gate dudect extiende `lab-offline`.
- **Riesgos:** ruido de timing en CI → mitigar con muestreo y ejecución offline;
  no convertirlo en un test flaky que bloquee merges.

### Fase 1 — El diferenciador: firma triple-híbrida (SLH-DSA)

- **Objetivo:** superar el estándar militar en firma. CNSA 2.0 usa LMS/XMSS
  (hash-based **con estado**, peligroso si se reutiliza estado); Quipu añade
  **SLH-DSA (FIPS-205 / SPHINCS+)**, hash-based **stateless**, y ofrece un modo
  **triple-híbrido Ed25519 + ML-DSA-87 + SLH-DSA** con combinador **AND (3-de-3)**:
  infalsificable mientras sobreviva *al menos una* de tres familias
  criptográficas independientes (curva elíptica, retículos, funciones hash).
- **Alcance / entregables:**
  - Integrar el crate vetado `slh-dsa` (RustCrypto), param set alineado a nivel 5
    (p. ej. `SLH-DSA-SHA2-256s`).
  - Nuevo modo de firma opcional que extiende `pqsign`: preimagen liga las **tres**
    claves de verificación + etiqueta de dominio nueva; verificación 3-de-3.
  - Cobertura en el Security Lab: extender `forge.rs` (frankensignature sobre tres
    componentes, sustitución de clave).
- **Criterio de éxito:** round-trip, rechazo de manipulación por componente, y el
  Lab no encuentra brecha. Documentado el **trade-off de tamaño** (las firmas
  SLH-DSA son grandes: ~30 KB para 256s), por eso es un modo **opcional de alta
  garantía**, no el por defecto.
- **Feature gate:** `slh` (o `sign-hashbased`).
- **Riesgos:** tamaño de firma; rendimiento de firma SLH-DSA. Mitigación: opt-in,
  documentar cuándo conviene (firmar artefactos/firmware de altísimo valor).

### Fase 2 — Puerta gubernamental: modo FIPS

- **Objetivo:** ofrecer un perfil con **algoritmos aprobados FIPS** sobre un
  **backend validado**, sin (todavía) validación CMVP propia.
- **Alcance / entregables:**
  - Feature `fips` que conmuta las primitivas al perfil aprobado usando
    **`aws-lc-rs`** (módulo FIPS 140-3 de AWS): **AES-256-GCM** en vez de
    XChaCha20-Poly1305, **HKDF/PBKDF2-HMAC-SHA-512** en vez de Argon2id para clave
    por contraseña, SHA-2. ML-KEM/ML-DSA se mantienen (ya FIPS).
  - Identificador de suite en el contenedor para no confundir perfiles.
  - Documentar límites (p. ej. nonce de GCM; Quipu deriva clave fresca por mensaje,
    lo que evita el límite de reutilización).
- **Criterio de éxito:** round-trip completo en modo FIPS; el core no-FIPS intacto;
  tests que verifican que el perfil FIPS no usa primitivas no aprobadas.
- **Feature gate:** `fips`.
- **Riesgos:** `aws-lc-rs` es una dependencia pesada con toolchain C/asm →
  estrictamente opcional; documentar que Argon2 (mejor cripto) sigue siendo el
  por defecto no-FIPS.

### Fase 3 — Nivel enterprise/gov: KeyStore + HSM

- **Objetivo:** que las claves privadas puedan **vivir en hardware** (HSM/TPM/KMS)
  y nunca salir en claro.
- **Alcance / entregables:**
  - Abstracción **`Signer` / `KeyStore`** (trait) para las operaciones que usan
    clave privada (firmar, decapsular), con backend por defecto en memoria (actual).
  - **Un backend de referencia**: **PKCS#11** (`cryptoki`) probado contra SoftHSM,
    o Cloud-KMS. TPM/otros quedan como extensiones futuras.
- **Criterio de éxito:** firmar/decapsular con la clave en el HSM de referencia,
  sin exponer material privado al proceso; el path en memoria sigue funcionando.
- **Feature gate:** `hsm` (y/o `pkcs11`).
- **Riesgos:** complejidad de integración/tests HW → usar SoftHSM en CI; mantener
  la abstracción mínima y bien acotada.

### Fase 4 — Ciclo de vida de claves

- **Objetivo:** rotación y recuperación sin construir una PKI propia.
- **Alcance / entregables:**
  - **Versionado/ID de clave** y metadatos de rotación en el formato del
    contenedor (permite re-cifrado/roll-over ordenado).
  - ~~**Shamir Secret Sharing** (crate vetado, p. ej. `vsss-rs`) para escrow/respaldo
    de claves con umbral k-de-n.~~ **HECHO** (`src/shamir.rs`), con dos
    desviaciones deliberadas de este plan, ambas justificadas en el PR:
    1. **Implementado en el propio repo, no con `vsss-rs`.** Ese crate está
       construido sobre `elliptic-curve` y reparte escalares de curva; para
       partir BYTES arrastraba dos subárboles nuevos (`elliptic-curve`, `sha3`)
       al presupuesto de `cargo-vet`, y su línea 6.0 está en RC. Shamir sobre
       GF(2^8) son ~200 líneas de algoritmo especificado desde 1979 — está más
       cerca de implementar HKDF desde su RFC que de inventar cripto.
    2. ~~**No va tras un feature gate.**~~ **REVERTIDO**: sí va tras `escrow`,
       como decía este plan. Mi argumento era que un gate lo dejaría fuera de la
       rueda de PyPI que consume `informes`; el argumento era flojo, porque eso
       se arregla añadiendo `escrow` a los args de maturin, que es lo que se
       hizo. El principio que manda es que **una herramienta debe estar contenida
       a su único fin**: quien cifra datos no necesita repartir claves, y código
       que no se compila no expone API ni puede interferir con nada. Directiva de
       Juan, 2026-07-18.
  - Helpers de rotación; integración documentada con KMS/PKI existentes (no se
    construye PKI).
- **Criterio de éxito:** roll-over de clave con artefactos versionados; recuperar
  una clave desde k comparticiones Shamir.
- **Feature gate:** parte en core (metadatos), Shamir tras `escrow`/`sharing`.
- **Riesgos:** creep de alcance hacia "gestión de claves" completa → YAGNI estricto,
  solo rotación + escrow por umbral.

### Milestones externos (en paralelo, no bloquean)

- **Auditoría independiente** — solicitud a OTF ya enviada; alternativas
  Cure53 / Radically Open Security vía grant NLnet; abrir programa de divulgación
  responsable / bug bounty. Es el **mayor sello de credibilidad**.
- **Validación FIPS 140-3 (CMVP)** — costosa y con laboratorio; solo si un cliente
  gubernamental la financia. La Fase 2 (modo FIPS) es el prerrequisito técnico.

## 5. Dónde Quipu *supera*, no solo iguala

- **Firma triple-híbrida** sobre tres familias (curva/retículos/hash) — más
  conservador que el LMS/XMSS militar y **stateless** (sin el riesgo de estado).
- **Ya híbrido clásico+PQ** en cifrado y firma, cuando muchos despliegues gov
  apenas migran.
- **Argon2id memory-hard** > PBKDF2 para claves por contraseña (en el perfil
  no-FIPS por defecto).
- **Security Lab auto-atacante** de serie — poco habitual en librerías.
- **OPRF verificable (DLEQ)** y **transparencia total** (AGPL, Kerckhoffs).

## 6. Secuenciación y justificación

Orden por **señal/coste**: primero lo barato que desbloquea confianza (Fase 0),
luego el diferenciador de portada (Fase 1), después las puertas de mercado gov
(Fases 2–3) y el ciclo de vida (Fase 4). Los milestones externos corren en
paralelo porque dependen de terceros/fondos, no del código.

Cada fase entrega valor independiente y observable; ninguna bloquea a la siguiente
salvo la dependencia natural Fase 2 → CMVP.

## 7. Fuera de alcance (YAGNI)

- PKI/CA propia, gestión de identidades, revocación online.
- Mensajería, sesiones, forward secrecy/ratcheting (fuera del alcance de Quipu).
- Protecciones de canal lateral **de hardware** (potencia/EM/TEMPEST): requieren
  hardware, no una librería de software.
- LMS/XMSS con estado (se prefiere SLH-DSA stateless).
- Validación CMVP como trabajo de ingeniería (es proceso/dinero, no código).

## 8. Cómo continúa

Tras aprobar este spec-paraguas, se escribe el **spec detallado de la Fase 0** y su
plan de implementación (skill `writing-plans`), y se ejecuta. Cada fase siguiente
repite el ciclo spec → plan → implementación, siempre con cobertura del Security
Lab y verificación (`superpowers:verification-before-completion`) antes de dar por
cerrada.
