# Quipu — Streaming AEAD para datos en reposo grandes (construcción STREAM)

**Fecha:** 2026-07-04
**Estado:** diseño aprobado por delegación ("planea como gustes e implementa con libertad").
**Inspiración:** Google Tink `StreamingAEAD` (AES-GCM-HKDF-Streaming) + la construcción
**STREAM** (Hoang–Reyhanitabar–Rogaway–Vizár, "Online AE"). Se compone con las
primitivas ya vetadas de Quipu; no se inventa ninguna.
**Entrega prevista:** v0.5.0 (aditivo; se puede batchear con la Fase 1 ya en `main`).

## 1. Objetivo y motivación

Hoy todo el pipeline de Quipu cifra un **blob entero en memoria** (`api::encode`/
`decode`). Eso impide cifrar datos en reposo **grandes** (backups, imágenes de disco,
archivos de varios GB) sin agotar memoria, y no hay resistencia estructural a
truncación/reordenamiento a nivel de archivo.

Este subsistema añade **cifrado por streaming**: un `Read` → `Write` procesado por
*chunks* de tamaño fijo, con **memoria acotada** (independiente del tamaño del
archivo) y garantías de integridad de todo el flujo:

- **Anti-truncación:** no se puede recortar el final del archivo sin detección.
- **Anti-reordenamiento:** no se pueden permutar chunks.
- **Anti-splice entre archivos:** un chunk de otro archivo/clave no valida.
- **Anti-manipulación:** cualquier bit alterado en cabecera o cuerpo falla.

## 2. Invariantes respetadas

- **No inventar primitivas.** STREAM es una construcción publicada y analizada; se
  compone `chacha20poly1305` (XChaCha20-Poly1305, ya en `cipher.rs`) + `hkdf` +
  `argon2` (ya en `kdf.rs`). **Cero dependencias nuevas.**
- **Alcance: datos en reposo.** Cifrado de archivos/respaldos. No mensajería.
- **Aditivo.** No toca `encode`/`decode` ni los contenedores existentes.
- **Core lean.** Sin deps nuevas ni feature pesada → va en el core (sin gate). El
  ataque del Security Lab va tras `lab` como el resto.
- **Cada capacidad se auto-ataca.** Cobertura en el Security Lab antes de "hecho".

## 3. Construcción criptográfica (STREAM sobre XChaCha20-Poly1305)

Sea `P` el passphrase y `pepper` opcional.

1. **Derivación de clave por archivo.** Salt aleatorio de 16 B →
   `master = kdf::derive_master_key(P, salt, pepper, kdf_params)` (Argon2id, ya
   existente). Luego un `nonce_prefix` aleatorio de 19 B y
   `stream_key = kdf::derive_subkey(master, INFO)` donde
   `INFO = b"quipu/stream/v1" ‖ nonce_prefix` (HKDF, ya existente). Ligar el
   `nonce_prefix` en el `info` de HKDF garantiza que dos archivos con el mismo
   passphrase pero distinto prefix deriven claves distintas.
2. **Nonce por chunk (24 B):** `nonce_i = nonce_prefix(19) ‖ counter_be(4) ‖ final(1)`.
   `counter` empieza en 0 y crece de uno en uno. `final = 1` sólo en el último chunk,
   `0` en el resto. (19+4+1 = 24 = `cipher::NONCE_LEN`.)
3. **Cifrado por chunk:** `ct_i = cipher::encrypt(stream_key, nonce_i, pt_i, aad=header_bytes)`
   (XChaCha20-Poly1305, tag de 16 B incluido). `aad` = los bytes exactos de la
   cabecera (§4), así todo el flujo queda ligado a los parámetros.
4. **Chunking:** el plaintext se parte en chunks de `chunk_size` bytes (default
   **262 144 = 256 KiB**). El último chunk puede ser más corto (incluido tamaño 0
   sólo si el archivo está vacío → un único chunk final vacío). Todos los chunks
   salvo el último tienen exactamente `chunk_size` bytes de plaintext.

**Garantías que dan las piezas:**
- `final_flag` → recortar el último chunk hace que el chunk previo (con `final=0`) sea
  el último leído; el decodificador exige `final=1` en el último → falla.
- `counter` en el nonce → permutar/duplicar chunks cambia el nonce esperado → el tag
  falla.
- `stream_key` por archivo (salt+prefix) → un chunk de otro archivo no valida.
- `aad = header` → alterar params/cabecera invalida todos los tags.

## 4. Contenedor `QST1` (cabecera, ligada como AAD)

```
magic     "QST1"        4 B
version   0x01          1 B
flags     0x00          1 B
mem_kib   u32 BE        4 B   ┐
iters     u32 BE        4 B   ├ KdfParams (Argon2id)
par       u32 BE        4 B   ┘
salt                    16 B  (Argon2 salt)
nonce_prefix            19 B  (prefijo de nonce por archivo)
chunk_size u32 BE       4 B
------------------------------- total cabecera = 57 B
[ct_0 ‖ tag]  (chunk_size + 16 B)   (final=0)
[ct_1 ‖ tag]  ...
[ct_N ‖ tag]  (<= chunk_size + 16 B) (final=1)
```

La cabecera se escribe tal cual al inicio del `Write` y se usa como AAD en cada
chunk. El decodificador la lee, valida magic/version, reconstruye `KdfParams`
(pasando por `KdfParams::is_sane` — defensa F2 existente), deriva la clave y procesa
los chunks.

## 5. Módulo `src/stream.rs` y API

Módulo nuevo `src/stream.rs`, reexpuesto por `api`.

```rust
pub struct StreamOptions<'a> {
    pub pepper: &'a [u8],
    pub kdf_params: KdfParams,
    pub chunk_size: usize, // default 262_144; validado en [4 KiB, 16 MiB]
}
impl Default for StreamOptions<'_> { /* pepper=b"", kdf_params=interactivo, 256 KiB */ }

pub enum StreamError { Io(std::io::Error), Header, UnsupportedVersion(u8),
                       BadChunkSize, InsaneKdf, Decrypt, Truncated }

/// Cifra `reader` → `writer` por streaming. Memoria acotada por `chunk_size`.
pub fn encrypt_stream<R: Read, W: Write>(reader: R, writer: W, passphrase: &str,
                                         opts: &StreamOptions) -> Result<(), StreamError>;

/// Descifra `reader` → `writer`. Falla si hay truncación/reordenamiento/manipulación.
/// El `pepper` es secreto y NO viaja en el contenedor: se pasa explícito (simétrico
/// con `api::decode`).
pub fn decrypt_stream<R: Read, W: Write>(reader: R, writer: W, passphrase: &str, pepper: &[u8])
                                         -> Result<(), StreamError>;

/// Conveniencia bytes↔bytes (para uso simple y tests).
pub fn encrypt_stream_bytes(data: &[u8], passphrase: &str, opts: &StreamOptions) -> Vec<u8>;
pub fn decrypt_stream_bytes(blob: &[u8], passphrase: &str, pepper: &[u8]) -> Result<Vec<u8>, StreamError>;
```

`api.rs` reexporta: `pub use crate::stream::{encrypt_stream, decrypt_stream,
encrypt_stream_bytes, decrypt_stream_bytes, StreamOptions, StreamError};`

**Lectura con "un chunk de adelanto":** para saber si un chunk es el último, el
decodificador lee el siguiente antes de decidir el `final_flag` esperado; mantiene a
lo sumo dos buffers de `chunk_size` → memoria acotada.

## 6. Auto-ataque (Security Lab) — requisito de "hecho"

Nuevo `src/lab/stream_attack.rs` (gated `lab`), un `Attack` adaptativo que sobre un
cifrado válido de varios chunks intenta y **debe fallar** en:
- **Truncar** el último chunk (dropear el bloque final).
- **Truncar** un chunk intermedio.
- **Append** de un chunk extra (repetir el último).
- **Reordenar** dos chunks (swap).
- **Splice**: sustituir un chunk por el de OTRO archivo (otra clave/salt).
- **Tamper** de un byte de la cabecera y del cuerpo.
Cualquier `decrypt_stream` que devuelva `Ok` con datos ≠ originales, o que acepte un
flujo forjado, es brecha.

## 7. Pruebas (core, sin feature)

1. `round_trips_small` (< 1 chunk), `round_trips_empty`, `round_trips_one_byte`.
2. `round_trips_multichunk` (varios chunks, con último parcial).
3. `round_trips_exact_multiple` (tamaño múltiplo exacto de `chunk_size`).
4. `wrong_passphrase_fails`.
5. `truncated_last_chunk_fails`, `truncated_middle_fails`, `appended_chunk_fails`.
6. `reordered_chunks_fail`, `cross_file_chunk_fails`.
7. `header_tamper_fails`, `body_tamper_fails`.
8. `rejects_insane_kdf_params` y `rejects_out_of_range_chunk_size`.
9. `deterministic_with_injected_salt_and_prefix` (helper de test que inyecta salt+prefix
   para comparar bytes).
10. `bounded_memory_smoke`: cifrar 4 MiB con chunk 256 KiB sin cargar todo (usa
    `Cursor`/`Read` perezoso; comprobación funcional, no de RSS).

## 8. CI y docs

- El core ya se testea en el job por defecto; estas pruebas entran ahí.
- El ataque de streaming corre en el job `security-lab` (`--features lab`).
- CHANGELOG (`[Unreleased] Added`), rustdoc del módulo, fila en el README (tabla de
  modos): "Streaming (archivos grandes)".

## 9. Fuera de alcance (YAGNI)

- Salida por símbolos/glifos/impreso para streaming (es byte-oriented; los canales
  visuales siguen para artefactos pequeños).
- Modo asimétrico/firmado por streaming (este subsistema es simétrico por passphrase;
  se puede extender luego).
- Paralelización multihilo del cifrado por chunks (optimización posterior; STREAM lo
  permite, pero YAGNI ahora).
- Compresión (ortogonal; el usuario puede comprimir antes de cifrar).

## 10. Riesgos

| Riesgo | Mitigación |
|---|---|
| Reutilización de (clave, nonce) entre archivos | `stream_key` deriva de salt+prefix por archivo; prefix aleatorio de 19 B. |
| Amplificación de coste al descifrar entrada ajena | `KdfParams::is_sane` (F2) antes de derivar; `chunk_size` acotado. |
| Chunk gigante declarado en cabecera → OOM | `chunk_size` validado en [4 KiB, 16 MiB] antes de asignar. |
| Confusión con el contenedor simétrico existente | Magic propio `QST1`; API separada. |

## 11. Criterio de "hecho"

Round-trip por streaming (pequeño y multi-chunk) correcto; los seis ataques del Lab
fallan; memoria acotada verificada funcionalmente; `encode`/`decode` y contenedores
existentes intactos; `superpowers:verification-before-completion` antes de cerrar.
