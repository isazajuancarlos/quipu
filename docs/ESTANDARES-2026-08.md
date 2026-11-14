# Estándares nuevos para quipu — investigación 2026-08-29

> Investigación de qué estándares criptográficos nuevos (2025–2026) son
> relevantes para quipu, qué encaja con su tesis y qué NO. Cierra en
> determinaciones, no en recomendaciones sueltas (directiva 27). Todo cambio de
> primitiva a quipu es repo sensible → propuesta + `security-review` + decisión
> de Juan (directiva 25); aquí NADA se implementa, se decide.
>
> **Este documento es el RASTREADOR vivo de estos estándares** (versionado desde
> 2026-09-02). El análisis de las §§1–4 es del 2026-08-29; la §5 lleva el estado
> **verificado en vivo** en cada revisita, con fecha y fuente (directiva 30/31: un
> estado sin fecha caduca sin avisar).

## 1. Lo que quipu YA cubre (para no reproponerlo)

| Estándar | Dónde | Estado |
|---|---|---|
| **FIPS 203 (ML-KEM-1024)** | `pqhybrid.rs` (híbrido), `quipu-cnsa` (puro) | implementado, vectores A.1.2 |
| **FIPS 204 (ML-DSA-87)** | firma híbrida Ed25519+ML-DSA | implementado |
| **FIPS 205 (SLH-DSA-256s)** | firma triple, feature `slh` | implementado, opt-in |
| **RFC 9497 (VOPRF)** | modo online, `quipu-voprf` | implementado, ristretto255-SHA512 + DLEQ |
| **RFC 9106 (Argon2id), RFC 8439 (ChaCha20-Poly1305), HKDF** | núcleo | implementado |
| **CNSA 2.0 categoría 5** | perfil `quipu-cnsa` (AES-256-GCM, HKDF-SHA-384) | alineado (NO validado FIPS 140-3, y lo dice) |

quipu está **al día con todo lo finalizado**. Lo que sigue es lo que aún no
estaba cuando se construyó.

## 2. Estándares nuevos — determinación

| Estándar | Qué es | Encaje con quipu | Prioridad | Determinación |
|---|---|---|---|---|
| **X-Wing** (IETF `draft-connolly-cfrg-xwing-kem-10`, mar-2026, Informational) | KEM híbrido PQ/T formal: **X25519 + ML-KEM-768**, transcript-bound | quipu ya hace transcript binding "X-Wing-**style**" pero con **ML-KEM-1024** → NO es conformante (ver §3) | **ALTA** | **Precisar la doc ya** (inerte) y **evaluar un perfil X-Wing-768 conformante** como opción de interop/credibilidad. Barato, alto valor NLnet/portafolio |
| **HQC** (5.º KEM NIST, draft 2026, final **2027**) | KEM **basado en códigos**, NO-reticular | Es el estándar MÁS on-brand: la tesis de quipu es "sobrevive si ≥1 familia matemática aguanta", pero su KEM es lattice-**only**. HQC lleva esa diversificación a la CONFIDENCIALIDAD, como ya la tiene en las firmas | **MEDIA-ALTA** (estratégica) | **Rastrear + prototipo experimental feature-gated**. NO producción: draft no final hasta 2027 y sin impl Rust auditada madura. Candidato natural a un milestone NLnet |
| **FIPS 206 / FN-DSA (Falcon)** (en camino 2026) | Firma reticular **compacta** (~0,7–1,3 KB vs 4,6 KB de ML-DSA-87) | Optimiza TAMAÑO dentro de la familia lattice; **no añade familia matemática nueva** (sigue siendo reticular, como ML-DSA) → no refuerza la diversificación | **BAJA-MEDIA** | **Esperar**. Implementar solo con FIPS 206 final + impl Rust auditada. **Riesgo a señalar**: el constant-time de Falcon (punto flotante) es notoriamente difícil de hacer bien — no es un "añadir dependencia" trivial |
| **draft-ietf-hpke-pq** (HPKE PQ/híbrido) | Sobre estándar para cifrado a destinatario con KEM PQ | quipu tiene formato de contenedor PROPIO; HPKE-PQ es la vía si se quiere INTEROPERAR con otras herramientas | **MEDIA** (según posicionamiento) | **Decisión de producto**: si quipu quiere ser interoperable, un perfil HPKE-PQ es milestone NLnet; si su valor es el contenedor autónomo, es opcional. Proponer a Juan |
| **COSE/JOSE PQC, CMS composite** (firmas verificables por tooling estándar) | Envoltorios estándar de firma | Sus firmas híbridas hoy solo las verifica quipu | **BAJA** | Opcional, ligado a la decisión HPKE. Solo si un cliente pide verificación con tooling estándar |
| **NIST IR 8547** (transición a PQC), **RFC 9958** (PQC for Engineers) | Guía de transición, no primitivas | Refuerza el relato de cumplimiento | **BAJA** (doc) | **Citarlos** en el README/portafolio. Esfuerzo casi nulo, valor de venta |

## 3. Hallazgo verificado: X-Wing 768 vs ML-KEM-1024 (inconsistencia interna)

Verificado en el código (`src/pqhybrid.rs:22,99`): el canal a destinatario usa
**`MlKem1024`**. Entonces:

- **README** dice "X25519 + ML-KEM-**1024** (X-Wing-style)" → **correcto**.
- **`GRANT_NLNET.md`** dice "X25519 + ML-KEM-**768**, FIPS-203, X-Wing-style" →
  **INCORRECTO**: no describe lo que quipu hace. Y ese documento **va a la
  solicitud NLnet del 3-sep** — un auditor europeo puede cazar que la memoria
  técnica dice 768 y el código hace 1024. Hay que **corregirlo antes de enviar**.
- **X-Wing formal** es X25519 + ML-KEM-**768**. quipu usa 1024 a propósito
  (categoría 5 / CNSA 2.0). Por tanto quipu es **X-Wing-INSPIRADO, no
  conformante**, y decir "X-Wing-style" es honesto siempre que no se afirme
  conformidad. La doc no debe decir "X-Wing" a secas.

**Determinación:** (a) corregir `GRANT_NLNET.md` a ML-KEM-1024 antes del envío
NLnet (inerte, se hace ya); (b) decidir si se añade un perfil X-Wing-768
conformante como opción de interop, o se deja solo el 1024 category-5 con la
redacción precisa "X-Wing-style, not the 768 standard".

> **(a) HECHO — 2026-09-02.** `GRANT_NLNET.md` ya no dice 768 en ninguna parte
> (verificado con `grep`); se precisó además la línea de *Standards alignment* y
> la *AI disclosure* para que "X-Wing" no aparezca nunca como estándar/alineación
> a secas, y `docs/SPEC.md` recoge ahora el combinador exacto del draft-10 frente
> al de quipu. La doc entera es honesta: **X-Wing-style, no wire-compatible**.
> **(b) es el ítem 2** (perfil X-Wing-768), abajo en §5.

## 4. Recomendación de fondo

El estándar nuevo con más valor para quipu **no es el más nuevo ni el más
grande: es HQC**, porque es el único que extiende su tesis central
(diversificación de familias matemáticas) al eslabón que hoy la tiene en
lattice-only: la confidencialidad. Falcon es más llamativo (firmas pequeñas)
pero no aporta familia nueva. X-Wing es el más urgente pero es sobre todo
**precisión documental + una opción de interop**, no una capacidad que falte.

Orden sugerido: **(1)** corregir la doc X-Wing/768 [ya, inerte] → **(2)** perfil
X-Wing-768 conformante [milestone] → **(3)** prototipo HQC experimental
[milestone, la apuesta estratégica] → **(4)** rastrear FIPS 206 sin implementar.

## 5. Seguimiento — estado verificado en vivo (2026-09-02)

Verificado por búsqueda/fetch web ese día (no de memoria). Fuentes abajo.

| # | Ítem | Estado 2026-09-02 | Acción |
|---|---|---|---|
| 1 | **Precisar doc X-Wing** | **HECHO.** `GRANT_NLNET.md` (0 menciones "768"), `SPEC.md` (combinador exacto draft-10) y demás doc quedan como *X-Wing-style, no wire-compatible*. Inerte | cerrado |
| 2 | **Perfil X-Wing-768 conformante** | **Factible offline**: `sha3` (SHA3-256) y `ml-kem` (`MlKem768`) ya están vendorizados → combinador y KEM sin dependencias nuevas. Combinador del draft-10 verificado: `SHA3-256(ss_M‖ss_X‖ct_X‖pk_X‖5c2e2f2f5e5c)`, tamaños pk 1216 / ct 1120 / ss 32 | implementar feature `xwing`, probar round-trip + KAT del Apéndice C, `security-review` (D25), merge = decisión de Juan |
| 3 | **Prototipo HQC** | El bloqueo "no hay Rust puro" **cayó**: existen `hqcr` (3 param sets) y RustCrypto `hqc-kem`, ambos **Rust puro** — pero **sin auditoría independiente ni revisión de canal lateral** (uno declarado *AI-assisted*). También `pqcrypto-hqc` (bindings a C de PQClean, rompería `forbid(unsafe_code)` + Rust-puro + build offline) | **DECIDIDO 2026-09-02 (Juan): ESPERAR y solo rastrear.** NO se vendoriza cripto no auditada al árbol endurecido de quipu —incoherente con la postura solo-local/vendored/ignore-scripts que define al repo de base—. Revisitar cuando exista impl Rust-puro **AUDITADA** (con revisión de canal lateral) o HQC llegue a FIPS final (~2027) |
| 4 | **Rastrear FIPS 206 (FN-DSA/Falcon)** | **Sigue en BORRADOR**: draft enviado a aprobación 2025-08-28; final esperado **finales 2026 / principios 2027**. Riesgo confirmado: el muestreo gaussiano en **punto flotante** hace el constant-time notoriamente difícil | **ESPERAR** (sin cambio). Revisar cuando salga FIPS 206 final + impl Rust auditada |

**Determinación de fondo, sin cambios respecto a §4**: el de más valor sigue
siendo **HQC** (única familia matemática nueva en la confidencialidad, hoy
lattice-only), y ahora está desbloqueado técnicamente pero pendiente de una
decisión de riesgo de cadena de suministro. X-Wing-768 es la ganancia más barata
y sin dependencias nuevas. FIPS 206 se espera.

## Fuentes

- NIST PQC standardization — https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization
- HQC 5.º algoritmo (draft 2026 / final 2027) — https://utimaco.com/news/blog-posts/pqc-news-nist-announces-hqc-fifth-algorithm-be-standardized
- X-Wing draft-10 (mar-2026) — https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/
- FIPS 206 / FN-DSA en camino 2026 — https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards
- HPKE PQ (draft-ietf-hpke-pq-05) — https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/
- RFC 9958 PQC for Engineers — https://datatracker.ietf.org/doc/rfc9958/

Verificación en vivo 2026-09-02:
- FIPS 206 / FN-DSA — https://csrc.nist.gov/presentations/2025/fips-206-fn-dsa-falcon (borrador a aprobación 2025-08-28; final ~2027; constant-time de punto flotante difícil)
- X-Wing draft-10 (2026-03-02, Informational) — https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/ ; combinador y KAT en el Apéndice C de https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-09.html
- HQC Rust puro (sin auditar): `hqcr` — https://docs.rs/hqcr/ ; RustCrypto `hqc-kem` — https://github.com/RustCrypto/KEMs ; bindings a C: `pqcrypto-hqc` — https://crates.io/crates/pqcrypto-hqc
