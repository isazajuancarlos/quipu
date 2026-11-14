# Streaming AEAD (STREAM construction) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add chunked streaming AEAD (`Read` → `Write`, bounded memory) for large data-at-rest, resistant to truncation/reordering/splicing, composing Quipu's existing XChaCha20-Poly1305 + Argon2id/HKDF.

**Architecture:** A new `src/stream.rs` module implements the STREAM construction: per-file Argon2id+HKDF key derivation, fixed-size chunks each AEAD-encrypted under a nonce `prefix ‖ counter ‖ final_flag`, framed after a `QST1` header that is bound as AAD. `encrypt_stream`/`decrypt_stream` operate over `io::Read`/`io::Write` with one-chunk look-ahead so at most two chunk buffers live at once. Re-exported through `api`.

**Tech Stack:** Rust (edition 2024), existing crates only — `chacha20poly1305` (via `crate::cipher`), `argon2`/`hkdf` (via `crate::kdf`), `getrandom`, `zeroize`. No new dependencies.

## Global Constraints

- Edition 2024; **zero `unsafe`** in first-party code.
- **Compose vetted primitives only** — STREAM is a published construction; reuse `crate::cipher::{encrypt, decrypt}` and `crate::kdf::{derive_master_key, derive_subkey, KdfParams, SALT_LEN}`. **No new crates.**
- **Strictly additive**: do not touch `api::encode`/`decode`, `container`, or existing wire formats.
- In **core** (no Cargo feature) — no new deps, central to the data-at-rest mission. The Security Lab attack is gated behind `lab` like the rest.
- Container magic is exactly `b"QST1"`, version `1`. Header is exactly **57 bytes** and is the AAD for every chunk.
- Nonce (24 B) = `nonce_prefix(19) ‖ counter_be(4) ‖ final_flag(1)`. `NONCE_PREFIX_LEN = 19`, `cipher::NONCE_LEN = 24`, `cipher::KEY_LEN = 32`, `kdf::SALT_LEN = 16`, tag = 16 B.
- Default chunk size `262_144` (256 KiB); valid range `[4096, 16_777_216]`.
- HKDF info = `b"quipu/stream/v1" ‖ nonce_prefix`.
- Every `cargo` invocation must be prefixed with `export PATH="$HOME/.cargo/bin:$PATH";`.
- Branch: `feat/streaming-aead` (already created). Do **not** tag or publish.

---

### Task 1: Module scaffold — types, `QST1` header, helpers

**Files:**
- Create: `src/stream.rs`
- Modify: `src/lib.rs` (add `pub mod stream;`)

**Interfaces:**
- Produces:
  - `pub struct StreamOptions<'a> { pub pepper: &'a [u8], pub kdf_params: KdfParams, pub chunk_size: usize }` + `Default`.
  - `pub enum StreamError { Io(std::io::Error), Header, UnsupportedVersion(u8), BadChunkSize, InsaneKdf, Decrypt, Truncated }` (+ `Debug`, `Display`, `std::error::Error`, `From<std::io::Error>`).
  - `pub const DEFAULT_CHUNK_SIZE: usize = 262_144;`
  - Internal: `const MAGIC`, `VERSION`, `NONCE_PREFIX_LEN`, `MIN_CHUNK_SIZE`, `MAX_CHUNK_SIZE`, `HEADER_LEN`, `TAG_LEN`, `STREAM_INFO_PREFIX`; `struct StreamHeader`; `fn chunk_nonce`, `fn derive_stream_key`, `fn read_chunk`.

- [ ] **Step 1: Wire the module into `src/lib.rs`**

Find the block of `pub mod ...;` declarations in `src/lib.rs` and add (alphabetical-ish, near `pub mod prelayers;` / `pub mod pqsign;`):
```rust
pub mod stream;
```

- [ ] **Step 2: Write `src/stream.rs` with types, constants, header, and helpers**

Create `src/stream.rs`:
```rust
//! Cifrado por STREAMING para datos en reposo grandes (construcción STREAM).
//!
//! Procesa un `Read` → `Write` por chunks de tamaño fijo con memoria acotada
//! (independiente del tamaño del archivo). Cada chunk se cifra con
//! XChaCha20-Poly1305 bajo un nonce `prefix ‖ counter ‖ final_flag`; la cabecera
//! `QST1` se liga como AAD. Da resistencia a truncación (flag final),
//! reordenamiento (counter en el nonce), splice entre archivos (clave por archivo)
//! y manipulación (AAD).
//!
//! No inventa primitivas: compone `cipher` (XChaCha20-Poly1305) + `kdf`
//! (Argon2id + HKDF), ya vetados. Inspirado en Google Tink `StreamingAEAD`.

use std::io::{Read, Write};

use zeroize::Zeroizing;

use crate::cipher::{self, KEY_LEN, NONCE_LEN};
use crate::kdf::{self, KdfParams, SALT_LEN};

const MAGIC: [u8; 4] = *b"QST1";
const VERSION: u8 = 1;
const NONCE_PREFIX_LEN: usize = 19;
const TAG_LEN: usize = 16;
/// Cabecera QST1: magic+version+flags + KdfParams(3×u32) + salt + prefix + chunk_size.
const HEADER_LEN: usize = 4 + 1 + 1 + (4 * 3) + SALT_LEN + NONCE_PREFIX_LEN + 4; // 57
const STREAM_INFO_PREFIX: &[u8] = b"quipu/stream/v1";

/// Tamaño de chunk por defecto (256 KiB).
pub const DEFAULT_CHUNK_SIZE: usize = 262_144;
const MIN_CHUNK_SIZE: usize = 4096;
const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;

/// Opciones de cifrado por streaming.
pub struct StreamOptions<'a> {
    pub pepper: &'a [u8],
    pub kdf_params: KdfParams,
    pub chunk_size: usize,
}

impl Default for StreamOptions<'_> {
    fn default() -> Self {
        StreamOptions {
            pepper: b"",
            kdf_params: KdfParams {
                mem_kib: 65_536, // 64 MiB, interactivo
                iterations: 3,
                parallelism: 1,
            },
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }
}

/// Errores del subsistema de streaming.
#[derive(Debug)]
pub enum StreamError {
    Io(std::io::Error),
    Header,
    UnsupportedVersion(u8),
    BadChunkSize,
    InsaneKdf,
    Decrypt,
    Truncated,
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::Io(e) => write!(f, "io: {e}"),
            StreamError::Header => write!(f, "cabecera QST1 inválida"),
            StreamError::UnsupportedVersion(v) => write!(f, "versión no soportada: {v}"),
            StreamError::BadChunkSize => write!(f, "chunk_size fuera de rango"),
            StreamError::InsaneKdf => write!(f, "parámetros KDF fuera de límites"),
            StreamError::Decrypt => write!(f, "fallo de descifrado/autenticación"),
            StreamError::Truncated => write!(f, "flujo truncado o incompleto"),
        }
    }
}

impl std::error::Error for StreamError {}

impl From<std::io::Error> for StreamError {
    fn from(e: std::io::Error) -> Self {
        StreamError::Io(e)
    }
}

/// Cabecera QST1 (se liga como AAD en cada chunk).
struct StreamHeader {
    kdf_params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    chunk_size: u32,
}

impl StreamHeader {
    fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        let mut i = 0;
        b[i..i + 4].copy_from_slice(&MAGIC);
        i += 4;
        b[i] = VERSION;
        i += 1;
        b[i] = 0u8; // flags
        i += 1;
        b[i..i + 4].copy_from_slice(&self.kdf_params.mem_kib.to_be_bytes());
        i += 4;
        b[i..i + 4].copy_from_slice(&self.kdf_params.iterations.to_be_bytes());
        i += 4;
        b[i..i + 4].copy_from_slice(&self.kdf_params.parallelism.to_be_bytes());
        i += 4;
        b[i..i + SALT_LEN].copy_from_slice(&self.salt);
        i += SALT_LEN;
        b[i..i + NONCE_PREFIX_LEN].copy_from_slice(&self.nonce_prefix);
        i += NONCE_PREFIX_LEN;
        b[i..i + 4].copy_from_slice(&self.chunk_size.to_be_bytes());
        b
    }

    fn from_bytes(b: &[u8]) -> Result<Self, StreamError> {
        if b.len() < HEADER_LEN {
            return Err(StreamError::Header);
        }
        if b[0..4] != MAGIC {
            return Err(StreamError::Header);
        }
        if b[4] != VERSION {
            return Err(StreamError::UnsupportedVersion(b[4]));
        }
        let rd = |o: usize| u32::from_be_bytes(b[o..o + 4].try_into().expect("4 bytes"));
        let kdf_params = KdfParams {
            mem_kib: rd(6),
            iterations: rd(10),
            parallelism: rd(14),
        };
        if !kdf_params.is_sane() {
            return Err(StreamError::InsaneKdf);
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&b[18..18 + SALT_LEN]); // 18..34
        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        nonce_prefix.copy_from_slice(&b[34..34 + NONCE_PREFIX_LEN]); // 34..53
        let chunk_size = rd(53); // 53..57
        if (chunk_size as usize) < MIN_CHUNK_SIZE || (chunk_size as usize) > MAX_CHUNK_SIZE {
            return Err(StreamError::BadChunkSize);
        }
        Ok(StreamHeader {
            kdf_params,
            salt,
            nonce_prefix,
            chunk_size,
        })
    }
}

/// Nonce de 24 B para el chunk `counter`. `final_flag` = último chunk.
fn chunk_nonce(prefix: &[u8; NONCE_PREFIX_LEN], counter: u32, final_flag: bool) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    n[NONCE_PREFIX_LEN..NONCE_PREFIX_LEN + 4].copy_from_slice(&counter.to_be_bytes());
    n[NONCE_PREFIX_LEN + 4] = final_flag as u8;
    n
}

/// Deriva la clave de streaming por archivo: Argon2id + HKDF(info ‖ prefix).
fn derive_stream_key(
    passphrase: &str,
    pepper: &[u8],
    params: &KdfParams,
    salt: &[u8; SALT_LEN],
    prefix: &[u8; NONCE_PREFIX_LEN],
) -> Zeroizing<[u8; KEY_LEN]> {
    let master = Zeroizing::new(kdf::derive_master_key(passphrase, salt, pepper, params));
    let mut info = Vec::with_capacity(STREAM_INFO_PREFIX.len() + NONCE_PREFIX_LEN);
    info.extend_from_slice(STREAM_INFO_PREFIX);
    info.extend_from_slice(prefix);
    Zeroizing::new(kdf::derive_subkey(&master, &info))
}

/// Lee hasta llenar `buf` o EOF; devuelve cuántos bytes se leyeron.
fn read_chunk<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> StreamHeader {
        StreamHeader {
            kdf_params: KdfParams { mem_kib: 64, iterations: 1, parallelism: 1 },
            salt: [3u8; SALT_LEN],
            nonce_prefix: [7u8; NONCE_PREFIX_LEN],
            chunk_size: DEFAULT_CHUNK_SIZE as u32,
        }
    }

    #[test]
    fn header_len_is_57() {
        assert_eq!(HEADER_LEN, 57);
        assert_eq!(sample_header().to_bytes().len(), 57);
    }

    #[test]
    fn header_round_trips() {
        let h = sample_header();
        let bytes = h.to_bytes();
        let back = StreamHeader::from_bytes(&bytes).unwrap();
        assert_eq!(back.kdf_params.mem_kib, 64);
        assert_eq!(back.salt, [3u8; SALT_LEN]);
        assert_eq!(back.nonce_prefix, [7u8; NONCE_PREFIX_LEN]);
        assert_eq!(back.chunk_size, DEFAULT_CHUNK_SIZE as u32);
    }

    #[test]
    fn header_rejects_bad_magic() {
        let mut bytes = sample_header().to_bytes();
        bytes[0] = b'X';
        assert!(matches!(StreamHeader::from_bytes(&bytes), Err(StreamError::Header)));
    }

    #[test]
    fn header_rejects_bad_version() {
        let mut bytes = sample_header().to_bytes();
        bytes[4] = 2;
        assert!(matches!(
            StreamHeader::from_bytes(&bytes),
            Err(StreamError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn header_rejects_insane_kdf() {
        let mut h = sample_header();
        h.kdf_params.mem_kib = KdfParams::MAX_MEM_KIB + 1;
        let bytes = h.to_bytes();
        assert!(matches!(StreamHeader::from_bytes(&bytes), Err(StreamError::InsaneKdf)));
    }

    #[test]
    fn header_rejects_out_of_range_chunk_size() {
        let mut h = sample_header();
        h.chunk_size = 100; // < MIN_CHUNK_SIZE
        let bytes = h.to_bytes();
        assert!(matches!(StreamHeader::from_bytes(&bytes), Err(StreamError::BadChunkSize)));
    }

    #[test]
    fn nonce_layout_is_prefix_counter_final() {
        let prefix = [9u8; NONCE_PREFIX_LEN];
        let n = chunk_nonce(&prefix, 0x01020304, true);
        assert_eq!(&n[..NONCE_PREFIX_LEN], &prefix);
        assert_eq!(&n[NONCE_PREFIX_LEN..NONCE_PREFIX_LEN + 4], &[1, 2, 3, 4]);
        assert_eq!(n[23], 1);
        let n0 = chunk_nonce(&prefix, 0, false);
        assert_eq!(n0[23], 0);
    }
}
```

- [ ] **Step 3: Run the scaffold tests**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --lib stream::tests`
Expected: PASS (7 tests: header len, round-trip, bad magic/version/kdf/chunk, nonce layout).

- [ ] **Step 4: Clippy clean**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo clippy --lib --all-targets -- -D warnings`
Expected: no warnings.

- [ ] **Step 5: Commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
git add src/stream.rs src/lib.rs
git commit -m "feat(stream): QST1 header, types, nonce/key helpers (scaffold)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: `encrypt_stream` / `decrypt_stream` + bytes convenience + api reexports

**Files:**
- Modify: `src/stream.rs` (add the four public functions + tests)
- Modify: `src/api.rs` (re-export the streaming API)

**Interfaces:**
- Consumes: everything from Task 1.
- Produces:
  - `pub fn encrypt_stream<R: Read, W: Write>(reader: R, writer: W, passphrase: &str, opts: &StreamOptions) -> Result<(), StreamError>`
  - `pub fn decrypt_stream<R: Read, W: Write>(reader: R, writer: W, passphrase: &str, pepper: &[u8]) -> Result<(), StreamError>`
  - `pub fn encrypt_stream_bytes(data: &[u8], passphrase: &str, opts: &StreamOptions) -> Vec<u8>`
  - `pub fn decrypt_stream_bytes(blob: &[u8], passphrase: &str, pepper: &[u8]) -> Result<Vec<u8>, StreamError>`

  The pepper is a secret and is **not** stored in the `QST1` container, so `decrypt_stream` takes it as an explicit argument (symmetric with `api::decode`). All other parameters come from the header.

- [ ] **Step 1: Write the failing round-trip tests**

Add to `mod tests` in `src/stream.rs`:
```rust
    fn fast_opts() -> StreamOptions<'static> {
        StreamOptions {
            pepper: b"",
            kdf_params: KdfParams { mem_kib: 64, iterations: 1, parallelism: 1 },
            chunk_size: MIN_CHUNK_SIZE, // 4096, para forzar multi-chunk barato
        }
    }

    fn roundtrip(data: &[u8]) {
        let blob = encrypt_stream_bytes(data, "clave-correcta", &fast_opts());
        let back = decrypt_stream_bytes(&blob, "clave-correcta", b"").unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn round_trips_with_pepper() {
        let opts = StreamOptions {
            pepper: b"pimienta",
            kdf_params: KdfParams { mem_kib: 64, iterations: 1, parallelism: 1 },
            chunk_size: MIN_CHUNK_SIZE,
        };
        let blob = encrypt_stream_bytes(b"con pepper", "k", &opts);
        assert_eq!(decrypt_stream_bytes(&blob, "k", b"pimienta").unwrap(), b"con pepper");
        // Pepper equivocado => falla.
        assert!(decrypt_stream_bytes(&blob, "k", b"otra").is_err());
    }

    #[test]
    fn round_trips_empty() {
        roundtrip(b"");
    }

    #[test]
    fn round_trips_one_byte() {
        roundtrip(b"x");
    }

    #[test]
    fn round_trips_small() {
        roundtrip(b"un mensaje corto en reposo");
    }

    #[test]
    fn round_trips_multichunk() {
        let data: Vec<u8> = (0..MIN_CHUNK_SIZE * 3 + 123).map(|i| (i % 251) as u8).collect();
        roundtrip(&data);
    }

    #[test]
    fn round_trips_exact_multiple() {
        let data: Vec<u8> = (0..MIN_CHUNK_SIZE * 2).map(|i| (i % 251) as u8).collect();
        roundtrip(&data);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let blob = encrypt_stream_bytes(b"secreto", "clave-a", &fast_opts());
        assert!(matches!(
            decrypt_stream_bytes(&blob, "clave-b", b""),
            Err(StreamError::Decrypt)
        ));
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --lib stream::tests::round_trips_small`
Expected: FAIL — `encrypt_stream_bytes` not found.

- [ ] **Step 3: Implement the four functions**

Add to `src/stream.rs` (before `#[cfg(test)]`):
```rust
/// Cifra `reader` → `writer` por streaming. Memoria acotada por `chunk_size`.
pub fn encrypt_stream<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    passphrase: &str,
    opts: &StreamOptions,
) -> Result<(), StreamError> {
    if !opts.kdf_params.is_sane() {
        return Err(StreamError::InsaneKdf);
    }
    if opts.chunk_size < MIN_CHUNK_SIZE || opts.chunk_size > MAX_CHUNK_SIZE {
        return Err(StreamError::BadChunkSize);
    }
    let mut salt = [0u8; SALT_LEN];
    let mut prefix = [0u8; NONCE_PREFIX_LEN];
    getrandom::getrandom(&mut salt).expect("RNG del sistema");
    getrandom::getrandom(&mut prefix).expect("RNG del sistema");

    let header = StreamHeader {
        kdf_params: opts.kdf_params.clone(),
        salt,
        nonce_prefix: prefix,
        chunk_size: opts.chunk_size as u32,
    };
    let header_bytes = header.to_bytes();
    writer.write_all(&header_bytes)?;

    let key = derive_stream_key(passphrase, opts.pepper, &opts.kdf_params, &salt, &prefix);

    let chunk = opts.chunk_size;
    let mut counter: u32 = 0;
    let mut cur = vec![0u8; chunk];
    let mut nxt = vec![0u8; chunk];
    let mut n_cur = read_chunk(&mut reader, &mut cur)?;

    loop {
        let is_last = if n_cur < chunk {
            true
        } else {
            let n_nxt = read_chunk(&mut reader, &mut nxt)?;
            if n_nxt == 0 {
                true
            } else {
                let nonce = chunk_nonce(&prefix, counter, false);
                let ct = cipher::encrypt(&key, &nonce, &cur[..n_cur], &header_bytes);
                writer.write_all(&ct)?;
                counter = counter.checked_add(1).ok_or(StreamError::Truncated)?;
                std::mem::swap(&mut cur, &mut nxt);
                n_cur = n_nxt;
                continue;
            }
        };
        let nonce = chunk_nonce(&prefix, counter, true);
        let ct = cipher::encrypt(&key, &nonce, &cur[..n_cur], &header_bytes);
        writer.write_all(&ct)?;
        break;
    }
    Ok(())
}

/// Descifra `reader` → `writer`. Falla ante truncación/reordenamiento/manipulación.
pub fn decrypt_stream<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    passphrase: &str,
    pepper: &[u8],
) -> Result<(), StreamError> {
    let mut header_bytes = [0u8; HEADER_LEN];
    read_exact_or_header_err(&mut reader, &mut header_bytes)?;
    let header = StreamHeader::from_bytes(&header_bytes)?;
    let key = derive_stream_key(
        passphrase,
        pepper, // el pepper NO viaja en el contenedor; se pasa explícito.
        &header.kdf_params,
        &header.salt,
        &header.nonce_prefix,
    );

    let block = header.chunk_size as usize + TAG_LEN;
    let mut counter: u32 = 0;
    let mut cur = vec![0u8; block];
    let mut nxt = vec![0u8; block];
    let mut n_cur = read_chunk(&mut reader, &mut cur)?;
    if n_cur < TAG_LEN {
        return Err(StreamError::Truncated);
    }

    loop {
        let is_last = if n_cur < block {
            true
        } else {
            let n_nxt = read_chunk(&mut reader, &mut nxt)?;
            if n_nxt == 0 {
                true
            } else {
                if n_nxt < TAG_LEN {
                    return Err(StreamError::Truncated);
                }
                let nonce = chunk_nonce(&header.nonce_prefix, counter, false);
                let pt = cipher::decrypt(&key, &nonce, &cur[..n_cur], &header_bytes)
                    .map_err(|_| StreamError::Decrypt)?;
                writer.write_all(&pt)?;
                counter = counter.checked_add(1).ok_or(StreamError::Truncated)?;
                std::mem::swap(&mut cur, &mut nxt);
                n_cur = n_nxt;
                continue;
            }
        };
        let nonce = chunk_nonce(&header.nonce_prefix, counter, true);
        let pt = cipher::decrypt(&key, &nonce, &cur[..n_cur], &header_bytes)
            .map_err(|_| StreamError::Decrypt)?;
        writer.write_all(&pt)?;
        break;
    }
    Ok(())
}

/// Lee exactamente `buf.len()` bytes o devuelve `Header` si el flujo se acaba antes.
fn read_exact_or_header_err<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<(), StreamError> {
    let n = read_chunk(reader, buf)?;
    if n != buf.len() {
        return Err(StreamError::Header);
    }
    Ok(())
}

/// Conveniencia: cifra un slice completo en memoria y devuelve el contenedor.
pub fn encrypt_stream_bytes(data: &[u8], passphrase: &str, opts: &StreamOptions) -> Vec<u8> {
    let mut out = Vec::new();
    encrypt_stream(data, &mut out, passphrase, opts)
        .expect("cifrado en memoria no debe fallar de I/O");
    out
}

/// Conveniencia: descifra un contenedor completo en memoria.
pub fn decrypt_stream_bytes(
    blob: &[u8],
    passphrase: &str,
    pepper: &[u8],
) -> Result<Vec<u8>, StreamError> {
    let mut out = Vec::new();
    decrypt_stream(blob, &mut out, passphrase, pepper)?;
    Ok(out)
}
```

Note: `encrypt_stream(data, &mut out, ...)` uses `&[u8]: Read` and `&mut Vec<u8>: Write` from std.

- [ ] **Step 4: Re-export from `src/api.rs`**

Add near the other `pub use` / module facade lines in `src/api.rs` (after the `use crate::stream;`-style imports if present; otherwise add both):
```rust
pub use crate::stream::{
    decrypt_stream, decrypt_stream_bytes, encrypt_stream, encrypt_stream_bytes, StreamError,
    StreamOptions,
};
```

- [ ] **Step 5: Run the round-trip tests**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --lib stream::tests`
Expected: PASS (scaffold + `round_trips_empty/one_byte/small/multichunk/exact_multiple`, `wrong_passphrase_fails`).

- [ ] **Step 6: Clippy + commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo clippy --all-targets -- -D warnings
git add src/stream.rs src/api.rs
git commit -m "feat(stream): encrypt_stream/decrypt_stream over Read/Write + bytes helpers

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Integrity tests — truncation, reorder, splice, tamper

**Files:**
- Modify: `src/stream.rs` (extend `mod tests`)

**Interfaces:**
- Consumes: the public API from Task 2 and internal `HEADER_LEN`, `TAG_LEN`, `MIN_CHUNK_SIZE` (tests are in-module, so they see privates). No new production API; if any test fails, the defect is in Task 2 — fix it there.

- [ ] **Step 1: Write the failing integrity tests**

Add to `mod tests` in `src/stream.rs`:
```rust
    // Un cifrado de 2 chunks completos + 1 final parcial => 3 bloques de ct.
    fn three_block_blob() -> Vec<u8> {
        let data: Vec<u8> = (0..MIN_CHUNK_SIZE * 2 + 10).map(|i| (i % 251) as u8).collect();
        encrypt_stream_bytes(&data, "k", &fast_opts())
    }

    // Tamaño en bytes de un bloque de ciphertext no-final (chunk + tag).
    const CT_BLOCK: usize = MIN_CHUNK_SIZE + TAG_LEN;

    #[test]
    fn truncated_last_chunk_fails() {
        let blob = three_block_blob();
        // Quita el último bloque (final).
        let cut = blob.len() - (blob.len() - HEADER_LEN - 2 * CT_BLOCK);
        let truncated = &blob[..cut];
        assert!(decrypt_stream_bytes(truncated, "k", b"").is_err());
    }

    #[test]
    fn truncated_middle_fails() {
        let blob = three_block_blob();
        // Elimina el segundo bloque de ct (bytes HEADER..+CT_BLOCK del cuerpo).
        let mut spliced = blob[..HEADER_LEN + CT_BLOCK].to_vec();
        spliced.extend_from_slice(&blob[HEADER_LEN + 2 * CT_BLOCK..]);
        assert!(decrypt_stream_bytes(&spliced, "k", b"").is_err());
    }

    #[test]
    fn appended_chunk_fails() {
        let blob = three_block_blob();
        // Duplica el primer bloque de ct al final.
        let mut extended = blob.clone();
        extended.extend_from_slice(&blob[HEADER_LEN..HEADER_LEN + CT_BLOCK]);
        assert!(decrypt_stream_bytes(&extended, "k", b"").is_err());
    }

    #[test]
    fn reordered_chunks_fail() {
        let blob = three_block_blob();
        // Intercambia los dos primeros bloques de ct (mismo tamaño).
        let mut reordered = blob[..HEADER_LEN].to_vec();
        reordered.extend_from_slice(&blob[HEADER_LEN + CT_BLOCK..HEADER_LEN + 2 * CT_BLOCK]);
        reordered.extend_from_slice(&blob[HEADER_LEN..HEADER_LEN + CT_BLOCK]);
        reordered.extend_from_slice(&blob[HEADER_LEN + 2 * CT_BLOCK..]);
        assert!(decrypt_stream_bytes(&reordered, "k", b"").is_err());
    }

    #[test]
    fn cross_file_chunk_fails() {
        let blob_a = three_block_blob();
        let blob_b = three_block_blob(); // otra sal/prefix aleatorios => otra clave
        // Sustituye el primer bloque de ct de A por el de B.
        let mut spliced = blob_a[..HEADER_LEN].to_vec();
        spliced.extend_from_slice(&blob_b[HEADER_LEN..HEADER_LEN + CT_BLOCK]);
        spliced.extend_from_slice(&blob_a[HEADER_LEN + CT_BLOCK..]);
        assert!(decrypt_stream_bytes(&spliced, "k", b"").is_err());
    }

    #[test]
    fn header_tamper_fails() {
        let mut blob = three_block_blob();
        blob[6] ^= 0x01; // altera un byte de KdfParams en la cabecera (es AAD)
        // Puede fallar como InsaneKdf o Decrypt; en todo caso NO devuelve Ok.
        assert!(decrypt_stream_bytes(&blob, "k", b"").is_err());
    }

    #[test]
    fn body_tamper_fails() {
        let mut blob = three_block_blob();
        let p = HEADER_LEN + 5;
        blob[p] ^= 0x01;
        assert!(matches!(decrypt_stream_bytes(&blob, "k", b""), Err(StreamError::Decrypt)));
    }

    #[test]
    fn rejects_out_of_range_chunk_size_on_encrypt() {
        let mut opts = fast_opts();
        opts.chunk_size = 10; // < MIN
        let mut out = Vec::new();
        assert!(matches!(
            encrypt_stream(&b"x"[..], &mut out, "k", &opts),
            Err(StreamError::BadChunkSize)
        ));
    }

    #[test]
    fn rejects_insane_kdf_on_encrypt() {
        let mut opts = fast_opts();
        opts.kdf_params.mem_kib = KdfParams::MAX_MEM_KIB + 1;
        let mut out = Vec::new();
        assert!(matches!(
            encrypt_stream(&b"x"[..], &mut out, "k", &opts),
            Err(StreamError::InsaneKdf)
        ));
    }
```

- [ ] **Step 2: Run the integrity tests**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --lib stream::tests`
Expected: PASS. If `truncated_last_chunk_fails` or `appended_chunk_fails` do NOT fail-to-decrypt, the `final_flag` logic in Task 2 is wrong — fix `encrypt_stream`/`decrypt_stream`, not the test.

- [ ] **Step 3: Commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
git add src/stream.rs
git commit -m "test(stream): truncation, reorder, splice, tamper all rejected

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Security Lab — adaptive streaming-forgery surface

**Files:**
- Create: `src/lab/stream_attack.rs`
- Modify: `src/lab/mod.rs` (register the module)
- Modify: `.github/workflows/ci.yml` (run it in the security-lab job)

**Interfaces:**
- Consumes: `crate::api::{encrypt_stream_bytes, decrypt_stream_bytes, StreamOptions}`, `crate::kdf::KdfParams`, `crate::lab::engine::{Attack, AttackOutcome, Rng}`.
- Produces: `pub struct StreamAttack` implementing `Attack` (`name()` → `"stream/forge"`).

- [ ] **Step 1: Check how `forge` is registered in `src/lab/mod.rs`**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; grep -n "pub mod" src/lab/mod.rs`
Expected: shows `pub mod forge;` etc. to mirror.

- [ ] **Step 2: Create `src/lab/stream_attack.rs`**

```rust
//! Superficie de streaming: manipulación adaptativa de contenedores QST1.
//!
//! Sobre un cifrado válido de varios chunks, intenta truncar, reordenar, hacer
//! splice desde otro archivo y manipular bytes. Cualquier `decrypt_stream_bytes`
//! que devuelva Ok con datos ≠ originales (o acepte un flujo forjado) es brecha.

use crate::api::{decrypt_stream_bytes, encrypt_stream_bytes, StreamOptions};
use crate::kdf::KdfParams;
use crate::lab::engine::{Attack, AttackOutcome, Rng};

const HEADER_LEN: usize = 57;
const CHUNK: usize = 4096;
const TAG: usize = 16;
const CT_BLOCK: usize = CHUNK + TAG;

fn opts() -> StreamOptions<'static> {
    StreamOptions {
        pepper: b"",
        kdf_params: KdfParams { mem_kib: 64, iterations: 1, parallelism: 1 },
        chunk_size: CHUNK,
    }
}

/// Atacante adaptativo contra el modo streaming.
pub struct StreamAttack;

impl StreamAttack {
    /// Nuevo ataque de streaming.
    pub fn new() -> Self {
        Self
    }
}

impl Default for StreamAttack {
    fn default() -> Self {
        Self::new()
    }
}

impl Attack for StreamAttack {
    fn name(&self) -> &'static str {
        "stream/forge"
    }

    fn step(&mut self, rng: &mut Rng) -> AttackOutcome {
        let data: Vec<u8> = (0..CHUNK * 2 + 7).map(|i| (i % 251) as u8).collect();
        let blob = encrypt_stream_bytes(&data, "clave-lab", &opts());

        let forged: Vec<u8> = match rng.below(5) {
            // Truncar el último bloque.
            0 => blob[..HEADER_LEN + 2 * CT_BLOCK].to_vec(),
            // Truncar el bloque intermedio.
            1 => {
                let mut v = blob[..HEADER_LEN + CT_BLOCK].to_vec();
                v.extend_from_slice(&blob[HEADER_LEN + 2 * CT_BLOCK..]);
                v
            }
            // Append (duplicar primer bloque).
            2 => {
                let mut v = blob.clone();
                v.extend_from_slice(&blob[HEADER_LEN..HEADER_LEN + CT_BLOCK]);
                v
            }
            // Reordenar los dos primeros bloques.
            3 => {
                let mut v = blob[..HEADER_LEN].to_vec();
                v.extend_from_slice(&blob[HEADER_LEN + CT_BLOCK..HEADER_LEN + 2 * CT_BLOCK]);
                v.extend_from_slice(&blob[HEADER_LEN..HEADER_LEN + CT_BLOCK]);
                v.extend_from_slice(&blob[HEADER_LEN + 2 * CT_BLOCK..]);
                v
            }
            // Splice desde OTRO archivo (otra clave por archivo).
            _ => {
                let other = encrypt_stream_bytes(&data, "clave-lab", &opts());
                let mut v = blob[..HEADER_LEN].to_vec();
                v.extend_from_slice(&other[HEADER_LEN..HEADER_LEN + CT_BLOCK]);
                v.extend_from_slice(&blob[HEADER_LEN + CT_BLOCK..]);
                v
            }
        };

        match decrypt_stream_bytes(&forged, "clave-lab", b"") {
            Ok(out) if out == data => {
                AttackOutcome::Breach("forjado descifró a los datos originales".into())
            }
            Ok(_) => AttackOutcome::Breach("forjado descifró (datos distintos, pero Ok)".into()),
            Err(_) => AttackOutcome::Advanced,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::engine::run;

    #[test]
    fn adaptive_stream_forgery_never_verifies() {
        let mut attack = StreamAttack::new();
        let report = run(&mut attack, 4242, 40);
        assert!(report.attempts > 0);
        assert!(
            report.is_clean(),
            "ninguna manipulación de streaming debe descifrar: {:?}",
            report.breaches
        );
    }
}
```

- [ ] **Step 3: Register in `src/lab/mod.rs`**

Add alongside the other `pub mod` lines:
```rust
pub mod stream_attack;
```

- [ ] **Step 4: Run the Lab test**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --features lab stream_attack`
Expected: PASS (`adaptive_stream_forgery_never_verifies`).

- [ ] **Step 5: Add the CI step to the security-lab job**

In `.github/workflows/ci.yml`, in the `security-lab` job after the existing `Lab tests` step, add:
```yaml
      - name: Lab tests (streaming forgery)
        run: cargo test --features lab stream_attack
```

- [ ] **Step 6: Clippy + commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo clippy --features lab --all-targets -- -D warnings
git add src/lab/stream_attack.rs src/lab/mod.rs .github/workflows/ci.yml
git commit -m "test(lab): adaptive streaming-forgery surface (truncate/reorder/splice)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Docs — rustdoc, CHANGELOG, README

**Files:**
- Modify: `CHANGELOG.md` (`[Unreleased]` → `### Added`)
- Modify: `README.md` (modes table)

**Interfaces:**
- Consumes: nothing. Documentation only. (Module rustdoc was written in Task 1.)

- [ ] **Step 1: Add the CHANGELOG entry**

Under the existing `## [Unreleased]` / `### Added` list (add a new bullet; keep the triple-hybrid bullet from Phase 1):
```markdown
- **Streaming AEAD for large data-at-rest**: `api::encrypt_stream` /
  `decrypt_stream` (and byte-slice `*_bytes` helpers) encrypt an `io::Read` to an
  `io::Write` in bounded memory using the STREAM construction (Tink-inspired) —
  fixed-size chunks under XChaCha20-Poly1305 with a per-file Argon2id+HKDF key and
  a `QST1` header bound as AAD. Resistant to truncation (final-chunk flag),
  reordering and duplication (per-chunk counter in the nonce), cross-file splicing
  (per-file key) and tampering. Covered by an adaptive forgery surface in the
  Security Lab. No new dependencies.
```

- [ ] **Step 2: Add a README modes-table row**

In the modes table in `README.md`, after the streaming-relevant rows, add:
```markdown
| Streaming (archivos grandes) | `api::encrypt_stream` / `decrypt_stream` | Cifrado por chunks (memoria acotada) para datos en reposo grandes; resistente a truncación/reordenamiento/splice. Contenedor `QST1` |
```

- [ ] **Step 3: Verify docs build**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo doc --no-deps 2>&1 | tail -5`
Expected: builds without warnings on the new module.

- [ ] **Step 4: Commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
git add CHANGELOG.md README.md
git commit -m "docs: document the streaming AEAD mode

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Final verification (before opening the PR)

- [ ] `export PATH="$HOME/.cargo/bin:$PATH"; cargo test` (full default suite green — includes all stream tests).
- [ ] `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --features lab stream_attack` (Lab finds no breach).
- [ ] `export PATH="$HOME/.cargo/bin:$PATH"; cargo clippy --all-targets -- -D warnings` (clean).
- [ ] Run `superpowers:verification-before-completion` before declaring done.
- [ ] Open a PR from `feat/streaming-aead` into `main`. **Do not tag/publish.**

## Notes carried from the spec

- The pepper is a secret and is **not** stored in the `QST1` container. `encrypt_stream` takes it via `StreamOptions.pepper`; `decrypt_stream`/`decrypt_stream_bytes` take it as an explicit `pepper: &[u8]` argument (symmetric with `api::decode`). Round-trip tests cover both `b""` and a real pepper.
- One-chunk look-ahead keeps at most two `chunk_size` (encrypt) / `chunk_size + 16` (decrypt) buffers alive → memory is bounded regardless of file size.
