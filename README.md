# Quipu

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![crates.io](https://img.shields.io/crates/v/quipu.svg)](https://crates.io/crates/quipu)
[![docs.rs](https://img.shields.io/docsrs/quipu)](https://docs.rs/quipu)
[![CI](https://github.com/isazajuancarlos/quipu/actions/workflows/ci.yml/badge.svg)](https://github.com/isazajuancarlos/quipu/actions/workflows/ci.yml)
[![post-quantum](https://img.shields.io/badge/post--quantum-ML--KEM--768-purple.svg)](#modos)

Librería de codificación con **protección criptográfica** y **simbología propia**.

> 🇬🇧 *Quipu is a free/libre (AGPL-3.0) library that encrypts and encodes data
> using only vetted cryptographic primitives (XChaCha20-Poly1305, Argon2id,
> HKDF), with a hybrid post-quantum mode (X25519 + ML-KEM-768) and a verifiable
> online hardening mode (VOPRF + DLEQ). It never invents primitives — security
> lives in the keys, not in hiding the format.*

> Filosofía "rueda y oruga": donde existe buena criptografía, la **reutilizamos**
> (XChaCha20-Poly1305, Argon2id, HKDF, ML-KEM, X25519); donde hay terreno nuevo
> (representación, simbología, formato), **innovamos**. Nunca inventamos primitivas
> criptográficas: la seguridad vive en la clave + el AEAD, no en la representación.

## Qué hace

Protege datos y los representa como **símbolos** (texto denso, glifos, o una imagen),
de forma reversible y autenticada.

```
datos → KDF(passphrase+pepper) → AEAD → contenedor → codec base-N → diccionario → símbolos
```

## Modos

| Modo | API (Rust) | Descripción |
|---|---|---|
| Simétrico (passphrase) | `api::encode` / `api::decode` | Argon2id + XChaCha20-Poly1305 |
| Post-cuántico (clave pública) | `api::encode_to_recipient` / `decode_as_recipient` | Híbrido **X25519 + ML-KEM-768** (transcript ligado estilo X-Wing) |
| Canal visual | `api::encode_to_image` / `decode_from_image` | Salida **PNG** lossless |
| Canal robusto (impreso) | `api::encode_to_robust_image` / `decode_from_robust_image` | + **Reed-Solomon** (corrige errores de canal) |
| Glifos nativos | `api::encode_to_glyph_image` / `decode_from_glyph_image` | Alfabeto de glifos propio, reconocible |
| Online (endurecimiento) | `api::encode_online` / `decode_online` | **VOPRF verificable** (prueba DLEQ): el cliente detecta un servidor deshonesto |

## Diccionarios (simbología enchufable)

- `dictionaries::ascii94()` — 94 símbolos ASCII (copy-paste universal).
- `dictionaries::flagship()` — 4096 glifos (12 bits/símbolo, ~2× más denso).
- `dictionaries::from_range(start, count)` — alfabeto a medida.
- `glyphopt` — selección de glifos por máxima separabilidad (base para glifos por IA).

## Galería de glifos

La misma carga cifrada puede representarse como texto denso, como una imagen PNG,
o con un **alfabeto de glifos propio** (geométrico o generado orgánicamente).
La simbología es **pública** (Kerckhoffs): no aporta ni resta seguridad, solo
representación.

| Alfabeto de glifos | Secreto en glifos | Glifos nativos | Glifos generativos |
|---|---|---|---|
| ![alfabeto](glyph_alphabet.png) | ![secreto](secreto_en_glifos.png) | ![nativos](glifos_nativos.png) | ![generativos](glyph_generative.png) |

## Seguridad y endurecimiento

- **Precapas**: normalización NFKC, pepper, padding Padmé (oculta longitud),
  binding de contexto (AAD), HKDF (separación de subclaves).
- **Antihacker**: borrado de claves en memoria (`zeroize`), comparación en tiempo
  constante, validación de parámetros KDF, errores uniformes.
- **Hackerbot**: red-team interno (tamper/truncation/uniqueness). Encontró y se
  corrigió un DoS por parámetros Argon2 maliciosos.

## Uso (Rust)

```rust
use quipu::api::{encode, decode, Options};
use quipu::dictionaries;

let dict = dictionaries::ascii94();
let sym = encode(b"secreto", "passphrase", &dict, &Options::default());
let data = decode(&sym, "passphrase", &dict, b"").unwrap();
```

## Uso (Python)

```bash
pip install quipu-crypto   # se instala como "quipu-crypto", se importa como "quipu"
```

```python
import quipu
s = quipu.encode(b"secreto", "passphrase")
assert quipu.decode(s, "passphrase") == b"secreto"

# Post-cuántico
pub, sec = quipu.generate_keypair()
s = quipu.encode_to_recipient(b"secreto", pub)
assert quipu.decode_as_recipient(s, sec) == b"secreto"
```

## Ejemplos funcionales

Round-trip de todos los modos, listo para correr:

```bash
cargo run --example quickstart          # Rust  (examples/quickstart.rs)
python examples/quickstart.py           # Python (examples/quickstart.py)
```

## Construir y probar

```bash
cargo test                      # tests unit + property
cargo clippy --all-targets      # lint
cargo run --example demo        # demo simétrico + glifos
cargo run --example v2demo      # post-cuántico + OPRF + imagen
cargo run --example hackerbot   # red-team
cargo run --example testplatform --release   # batería completa

# Fuzzing (nightly)
cargo +nightly fuzz run parse_container

# Bindings Python
source venv/bin/activate
maturin develop --features python
python tests/python/test_quipu.py
```

## Estado

v1 + v1.1 + v2 implementados con TDD estricto. **89 tests Rust + Wycheproof + 5
Python** verdes, clippy limpio, fuzzing sin crashes, Miri sin UB. Modo online con
**VOPRF verificable** (prueba DLEQ), KEM híbrido con transcript ligado estilo
X-Wing, y **pre-auditoría** propia (ver `INFORME_PREAUDITORIA.txt` y
`MODELO_DE_AMENAZA.txt`).

> ⚠️ Proyecto en desarrollo. La pre-auditoría interna NO sustituye una auditoría
> criptográfica **independiente**: no usar para proteger datos críticos reales
> hasta ese sello externo.

## Documentación y auditoría

- [`INFORME_PREAUDITORIA.txt`](INFORME_PREAUDITORIA.txt) — pre-auditoría interna
  (cargo-audit, Wycheproof, Miri, fuzzing, análisis de composición).
- [`MODELO_DE_AMENAZA.txt`](MODELO_DE_AMENAZA.txt) — modelo de amenaza (activos,
  adversarios, supuestos, garantías por modo, riesgos residuales).
- [`LICENSING.md`](LICENSING.md) — modelo de licenciamiento dual.

> La pre-auditoría interna es preparación, **no** sustituye una auditoría
> independiente. Ese sello externo es el siguiente paso del proyecto.

## Licencia

Modelo de **licencia dual** (open-core):

- **AGPL-3.0-or-later** para uso abierto (ver `LICENSE`).
- **Licencia comercial** para producto propietario cerrado o SaaS sin abrir código.
- El **servidor OPRF** se ofrece además como **servicio gestionado** de pago.

Detalles en [`LICENSING.md`](LICENSING.md). Contacto: isazajuancarlos@gmail.com
