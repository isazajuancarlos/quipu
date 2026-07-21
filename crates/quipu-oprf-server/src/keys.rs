// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Generación, parseo y hashing de API keys.
//!
//! Formato: `quipu_live_<64 hex>` (32 bytes aleatorios). El secreto completo se
//! muestra UNA sola vez al emitirla; el almacén guarda solo:
//!   - `prefix`  = `quipu_live_<primeros 12 hex>` — búsqueda O(1), no sensible.
//!   - `hash`    = SHA-256(secreto completo) — robar la BD no da keys usables.
//!
//! Las keys son aleatorias de alta entropía (256 bits), así que SHA-256 basta;
//! no hace falta un hash lento tipo Argon2 (no hay contraseña que proteger).

use sha2::{Digest, Sha256};

use crate::hexutil::to_hex;

const KEY_TAG: &str = "quipu_live_";
const HEX_LEN: usize = 64; // 32 bytes
const PREFIX_HEX_LEN: usize = 12;

/// Una API key recién emitida. `secret` se entrega al cliente una única vez.
pub struct GeneratedKey {
    pub secret: String,
    pub prefix: String,
    pub hash: [u8; 32],
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Un identificador aleatorio de 128 bits en hex (para customer/key ids).
pub fn random_id() -> String {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).expect("RNG del sistema");
    to_hex(&raw)
}

/// Genera una API key nueva.
pub fn generate() -> GeneratedKey {
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).expect("RNG del sistema");
    let hex = to_hex(&raw);
    let secret = format!("{KEY_TAG}{hex}");
    let prefix = format!("{KEY_TAG}{}", &hex[..PREFIX_HEX_LEN]);
    let hash = sha256(secret.as_bytes());
    GeneratedKey {
        secret,
        prefix,
        hash,
    }
}

/// Extrae `(prefix, hash)` de una key presentada, validando el formato.
/// Devuelve `None` si no encaja con `quipu_live_<64 hex>`.
pub fn parse(presented: &str) -> Option<(String, [u8; 32])> {
    let rest = presented.strip_prefix(KEY_TAG)?;
    if rest.len() != HEX_LEN || !rest.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let prefix = format!("{KEY_TAG}{}", &rest[..PREFIX_HEX_LEN]);
    Some((prefix, sha256(presented.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_roundtrips_through_parse() {
        let k = generate();
        assert!(k.secret.starts_with("quipu_live_"));
        assert_eq!(k.secret.len(), KEY_TAG.len() + HEX_LEN);
        let (prefix, hash) = parse(&k.secret).expect("key válida");
        assert_eq!(prefix, k.prefix);
        assert_eq!(hash, k.hash);
    }

    #[test]
    fn parse_rejects_malformed() {
        assert!(parse("nope").is_none());
        assert!(parse("quipu_live_xyz").is_none()); // corto
        assert!(parse("quipu_live_ZZ").is_none()); // no hex
        let mut bad = generate().secret;
        bad.push('0'); // demasiado largo
        assert!(parse(&bad).is_none());
    }

    #[test]
    fn distinct_keys_are_unique() {
        let a = generate();
        let b = generate();
        assert_ne!(a.secret, b.secret);
        assert_ne!(a.hash, b.hash);
    }
}
