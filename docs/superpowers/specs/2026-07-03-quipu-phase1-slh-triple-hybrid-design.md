# Quipu — Fase 1: firma triple-híbrida (SLH-DSA)

**Fecha:** 2026-07-03
**Estado:** diseño aprobado (delegado por el usuario: "elige lo mejor para quipu").
**Programa:** sub-proyecto de `[[2026-07-02-quipu-surpass-military-roadmap-design]]`.
**Feature gate:** `slh` (no-default).
**Entrega prevista:** v0.5.0 (cambio aditivo, sin romper wire-format).

## 1. Objetivo

Superar el estándar de firma de clase militar. CNSA 2.0 usa firmas hash-based
**con estado** (LMS/XMSS), peligrosas si se reutiliza el estado. Quipu añade un
modo **triple-híbrido** de firma:

**Ed25519 (curva) + ML-DSA-87 (retículo) + SLH-DSA (hash, *stateless*)**

combinados con **AND 3-de-3**: la firma es válida sólo si las **tres** verifican.
Queda infalsificable mientras sobreviva **al menos una** de tres familias
criptográficas independientes. Es un modo **opcional de alta garantía**, no el por
defecto: la firma pesa ~34 KB.

## 2. Invariantes respetadas

- **No inventar primitivas.** Sólo se compone el crate vetado `slh-dsa`
  (RustCrypto, Rust puro). Lo propio es el formato, el binding de dominio y la
  composición.
- **Core lean.** Todo el modo triple va tras `#[cfg(feature = "slh")]`; el build
  por defecto y la rueda de PyPI no lo compilan.
- **Aditivo.** El modo doble-híbrido (`pqsign::{SigningKey, VerifyingKey}`,
  `api::{encode_signed, decode_verified}`, contenedor QSG1) **no cambia**. Los
  artefactos v0.4.x siguen verificando.
- **Cada capacidad se auto-ataca.** El Security Lab cubre el modo triple antes de
  darse por hecho.
- **Alcance: datos en reposo.** Firmar documentos/artefactos de altísimo valor.

## 3. Decisiones de diseño

| # | Decisión | Elección | Justificación |
|---|---|---|---|
| 1 | Arquitectura | API paralela + tipos propios | Aditivo; la suite la fija el TIPO de clave → cero superficie de downgrade; doble-híbrido intacto. |
| 2 | Feature gate | `slh` (no-default) | Firma grande/lenta no debe compilarse siempre; wheel ligera. |
| 3 | Param set | **SLH-DSA-SHA2-256s** (`Sha2_256s`, nivel 5) | Firma pequeña (~29 KB) vs 256f (~49 KB); SHA-2 ya es dependencia del crate. |
| 4 | Combinador | AND 3-de-3 | Infalsificable mientras sobreviva ≥1 de {curva, retículo, hash}. |
| 5 | Determinismo | Firma determinista (`sk.sign(msg)`) | Coherente con el modo doble (Ed25519/ML-DSA deterministas). |
| 6 | Clave secreta SLH | Guardar los **bytes completos** de la PrivateKey (128 B), no una semilla | La API expone `into_bytes`/`try_from_bytes`, no keygen desde semilla de 32 B. |
| 7 | Bindings Python | **Fuera de alcance** esta fase (Rust-first) | Mantiene la wheel por defecto ligera; se añade luego si hay demanda. |
| 8 | Tests `slh` | Correr en **`--release`** | La firma SLH-DSA-256s en build *debug* tarda ~40 s; en release ~2 s. |

## 4. Dependencia

**Nota (cambio respecto al diseño inicial):** el crate `slh-dsa` v0.1.0 de
RustCrypto depende de un *prerelease* de la crate `signature` (`2.3.0-pre`) que
**choca** con `ed25519-dalek`/`ml-dsa` (que fijan `signature ^2` estable). Se usa en
su lugar **`fips205`** (integritychain), implementación FIPS-205 pura en Rust con
API propia (traits `SerDes`/`Signer`/`Verifier`), que **no** depende de `signature`
y por tanto no genera conflicto.

Añadir a `Cargo.toml`, **opcional**, activada por la feature `slh`:

```toml
[dependencies]
fips205 = { version = "0.4.1", optional = true, default-features = false, features = ["slh_dsa_sha2_256s", "default-rng"] }

[features]
slh = ["dep:fips205"]
```

- Rust puro, sin toolchain C (a diferencia de `aws-lc-rs` de la Fase 2).
- `default-features = false` + sólo el param set 256s → no compila los otros 11.
- API usada: `fips205::slh_dsa_sha2_256s::{try_keygen, PublicKey, PrivateKey,
  PK_LEN, SK_LEN, SIG_LEN}` y `fips205::traits::{SerDes, Signer, Verifier}`.
  Firma determinista con `try_sign(msg, ctx, /*hedged=*/false)`; contexto FIPS-205
  vacío (todo el binding va en la preimagen).
- Actualizar SBOM CycloneDX y `cargo-vet` para el nuevo crate cuando se integre.

## 5. Cambios en `src/pqsign.rs`

Todo bajo `#[cfg(feature = "slh")]`, junto (no en vez) de los tipos actuales.

### Constantes (SLH-DSA-SHA2-256s, FIPS-205)
```
SLH_PUB_LEN            = 64
SLH_SECRET_LEN         = 128
SLH_SIG_LEN            = 29_792
TRIPLE_VERIFYING_KEY_LEN = ED25519_PUB_LEN + MLDSA_VK_LEN + SLH_PUB_LEN   = 2_688
TRIPLE_SIGNING_KEY_LEN   = ED25519_SEED_LEN + MLDSA_SEED_LEN + SLH_SECRET_LEN = 192
TRIPLE_SIGNATURE_LEN     = ED25519_SIG_LEN + MLDSA_SIG_LEN + SLH_SIG_LEN  = 34_483
```
(Los tres tamaños SLH se fijan como constantes y se verifican contra
`SignatureLen`/`VerifyingKeyLen`/`SigningKeyLen` del crate en un test de regresión.)

### Etiqueta de dominio
```rust
const SIGN_TRIPLE_CONTEXT: &[u8] = b"quipu/v4/sign-triple";
```
Distinta de `quipu/v3/sign` → imposible confundir un artefacto doble con uno triple
aunque compartan mensaje.

### Tipos
```rust
pub struct TripleVerifyingKey { ed: EdVerifyingKey, ml: MlVerifyingKey<MlDsa87>, slh: SlhVerifyingKey<Sha2_256s> }
pub struct TripleSigningKey    { ed_seed: Zeroizing<[u8;32]>, ml_seed: Zeroizing<[u8;32]>, slh_sk_bytes: Zeroizing<[u8;128]> }
```

### Operaciones
- `generate_triple_keypair() -> (TripleVerifyingKey, TripleSigningKey)`
- `TripleSigningKey::verifying_key()`, `::sign(&self, msg) -> Vec<u8>`,
  `::to_bytes() -> Zeroizing<Vec<u8>>` (192 B, sensible), `::from_bytes()`
- `TripleVerifyingKey::verify(&self, msg, sig) -> bool`,
  `::to_bytes() -> Vec<u8>` (2688 B), `::from_bytes()`

### Preimagen y verificación
```
preimage = SIGN_TRIPLE_CONTEXT ‖ (ed_pub ‖ ml_vk ‖ slh_vk) ‖ message
```
Las tres primitivas firman **la misma** preimagen. `verify` decodifica los tres
componentes de longitud fija (offsets `ED25519_SIG_LEN`, `+MLDSA_SIG_LEN`,
`+SLH_SIG_LEN`), rechaza cualquier longitud distinta de `TRIPLE_SIGNATURE_LEN`, y
devuelve `ed_ok && ml_ok && slh_ok` (Ed25519 con `verify_strict`).

## 6. Formato de contenedor — QSG3

Nuevo magic, espejo estructural de QSG1:
```
"QSG3" (4) │ version=1 (1) │ flags=0 (1) │ msg_len u32 BE (4) │ message │ triple-signature (34_483)
```
En `src/api.rs`, bajo `#[cfg(feature = "slh")]`:
- `SIGNED_TRIPLE_MAGIC = *b"QSG3"`, `SIGNED_TRIPLE_VERSION = 1`,
  `SIGNED_TRIPLE_PREFIX = 10` (reusa la misma constante de layout).
- `pub fn encode_signed_triple(data, signer: &TripleSigningKey, dict) -> String`
- `pub fn decode_verified_triple(symbols, verifier: &TripleVerifyingKey, dict) -> Result<Vec<u8>, DecodeError>`

Reutiliza el parsing endurecido de `decode_verified`: aritmética `checked_add`
(corrección F4 de v0.4.1), mismas variantes `DecodeError` (`TooShort`, `BadMagic`,
`UnsupportedVersion`, `BadSignature`). Un `TripleVerifyingKey` **sólo** acepta
QSG3; un artefacto QSG1 presentado a `decode_verified_triple` da `BadMagic`. No hay
negociación de suite → sin superficie de downgrade.

## 7. Auto-ataque (Security Lab) — requisito de "hecho"

Extender `src/lab/forge.rs` con cobertura del modo triple (o un `ForgeTripleAttack`
paralelo), reutilizando el motor determinista:
- **Frankensignature 3-de-3:** intercambiar *cada uno* de los tres componentes
  (ed / ml / slh) tomándolo de una firma de otra clave → las tres variantes deben
  fallar bajo ambas `vk`.
- **Key-substitution:** firmar con `sk1`, verificar con `vk2` → falla.
- **Manipulación de región:** mutar un símbolo del QSG3 válido → falla.
Cualquier `decode_verified_triple` que devuelva `Ok` sobre algo forjado es brecha.
El job de CI del Lab corre esta cobertura (`--features lab,slh`).

## 8. Pruebas (todas bajo `--features slh`)

Espejo de la suite de `pqsign`:
1. `triple_parameters_are_level5` — fija `SLH_SIG_LEN`, `TRIPLE_VERIFYING_KEY_LEN`,
   `TRIPLE_SIGNATURE_LEN` y los casa con los tamaños del crate.
2. `triple_sign_verify_round_trips`
3. `triple_tampered_message_fails`
4. `triple_tampered_signature_fails` — voltear un bit en *cada* uno de los tres
   componentes por separado.
5. `triple_wrong_key_fails`
6. `triple_and_combiner_rejects_swapped_component` — franken en cada uno de los 3.
7. `triple_signing_key_serialization_round_trips` (192 B)
8. `triple_verifying_key_serialization_round_trips` (2688 B)
9. `triple_wrong_length_signature_rejected`
10. `triple_signatures_are_deterministic_but_bind_message`
11. En `api.rs`: round-trip `encode_signed_triple`/`decode_verified_triple`, rechazo
    de clave equivocada, manipulación de región, mensaje vacío, y rechazo de
    `msg_len` que desborda (espejo de `decode_verified_rejects_overflowing_msg_len`).

## 9. CI

- Job existente de test/clippy: añadir una corrida `--features slh` (y
  `--no-default-features`/combinaciones clave para verificar aislamiento).
- Job del Security Lab: correr también `--features lab,slh`.
- El check de aislamiento del Lab (ningún módulo no-lab referencia `crate::lab`)
  sigue vigente.

## 10. Versionado y documentación

- **v0.5.0** (aditivo). Actualizar `Cargo.toml`, `pyproject.toml`, `Cargo.lock`,
  `supply-chain/config.toml` (exención `quipu` por versión exacta — tarea de release
  recurrente) y `CHANGELOG.md`.
- Documentar el trade-off: firma ~34 KB, firma SLH lenta; modo de **alta garantía**
  para artefactos de altísimo valor, no el por defecto. `docs/` y rustdoc del módulo.

## 11. Fuera de alcance (YAGNI)

- Bindings Python del modo triple.
- Byte de "suite" auto-descriptivo en el contenedor (eso es Fase 2, donde el cifrado
  FIPS lo necesita de verdad).
- Backends HSM para SLH-DSA (los HSM apenas soportan PQC — ver Fase 3).
- Param sets SLH-DSA distintos de `Sha2_256s` (256f/SHAKE): opt-in futuro si hay
  demanda; el diseño fija los tamaños del param set elegido.

## 12. Riesgos

| Riesgo | Mitigación |
|---|---|
| Firma SLH-DSA grande (~34 KB triple) | Modo opt-in documentado; no es el por defecto. |
| Firma SLH-DSA lenta | Aceptable para datos en reposo de alto valor; documentar. |
| `slh-dsa` v0.1.0 (joven) | El AND 3-de-3 lo cubre: aunque SLH falle, Ed25519+ML-DSA sostienen. |
| Uso de stack alto (el crate asigna en stack) | Documentar; los tests corren en release. |
| Olvidar la exención `cargo-vet` al liberar | Checklist de release lo recoge. |

## 13. Criterio de "hecho"

Round-trip triple correcto; rechazo por manipulación de *cada* componente; el
Security Lab no encuentra brecha (`--features lab,slh`); CI verde en las
combinaciones de features; doble-híbrido y artefactos v0.4.x intactos;
`superpowers:verification-before-completion` antes de cerrar.
