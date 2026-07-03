//! Derivación de clave. Precapas del lado de la CLAVE:
//!   passphrase -> NFKC -> (+ pepper) -> Argon2id -> clave maestra
//!   clave maestra -> HKDF-SHA256 (etiqueta `info`) -> subclaves independientes.
//!
//! Argon2id (memory-hard) es el "antibot offline": encarece cada intento.
//! El pepper es un secreto que vive FUERA del dato (código/HSM/env).
//! La fuerza está aquí + en el AEAD; nunca en la representación.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

/// Longitud de clave derivada (256 bits).
pub const KEY_LEN: usize = 32;
/// Longitud del salt (128 bits).
pub const SALT_LEN: usize = 16;

/// Coste de Argon2id (la "dificultad personal" ajustable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memoria en KiB.
    pub mem_kib: u32,
    /// Iteraciones (t_cost).
    pub iterations: u32,
    /// Paralelismo (p_cost).
    pub parallelism: u32,
}

impl Default for KdfParams {
    /// Coste interactivo de referencia (64 MiB, 3 iteraciones, 1 hilo).
    fn default() -> Self {
        Self {
            mem_kib: 65536,
            iterations: 3,
            parallelism: 1,
        }
    }
}

impl KdfParams {
    /// Memoria máxima soportada (256 MiB). Acota dos cosas: el overflow de
    /// Argon2 con parámetros maliciosos, y la AMPLIFICACIÓN de coste al descifrar
    /// entrada NO confiable — un contenedor ajeno fija sus propios params y el
    /// KDF corre ANTES de que el tag AEAD falle, así que un blob diminuto no debe
    /// poder forzar 1 GiB. 256 MiB sigue siendo 4× el coste interactivo por
    /// defecto (64 MiB) y cubre de sobra los presets sensibles habituales.
    pub const MAX_MEM_KIB: u32 = 262_144;
    /// Iteraciones máximas.
    pub const MAX_ITERATIONS: u32 = 16;
    /// Paralelismo máximo.
    pub const MAX_PARALLELISM: u32 = 16;

    /// `true` si los parámetros están dentro de límites seguros. Se usa para
    /// rechazar parámetros KDF de una cabecera manipulada ANTES de derivar
    /// (evita panic/DoS por agotamiento de memoria).
    pub fn is_sane(&self) -> bool {
        self.parallelism >= 1
            && self.parallelism <= Self::MAX_PARALLELISM
            && self.iterations >= 1
            && self.iterations <= Self::MAX_ITERATIONS
            && self.mem_kib >= 8 * self.parallelism
            && self.mem_kib <= Self::MAX_MEM_KIB
    }
}

/// Deriva la clave maestra desde la passphrase (normalizada NFKC), el salt,
/// un pepper opcional y el coste Argon2id.
pub fn derive_master_key(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
    pepper: &[u8],
    params: &KdfParams,
) -> [u8; KEY_LEN] {
    // NFKC: la "misma" contraseña deriva siempre la misma clave.
    let mut normalized: String = passphrase.nfkc().collect();
    // El pepper se concatena al material de contraseña.
    let mut secret = normalized.clone().into_bytes();
    normalized.zeroize(); // O5: no dejar la passphrase normalizada en memoria
    secret.extend_from_slice(pepper);

    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            params.mem_kib,
            params.iterations,
            params.parallelism,
            Some(KEY_LEN),
        )
        .expect("parámetros Argon2id válidos"),
    );
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(&secret, salt, &mut out)
        .expect("derivación Argon2id no debe fallar con entradas válidas");
    secret.zeroize(); // O5: borra passphrase+pepper del buffer intermedio
    out
}

/// Deriva una subclave independiente desde la clave maestra y una etiqueta de
/// dominio (`info`), vía HKDF-SHA256. Distinta etiqueta -> distinta subclave.
pub fn derive_subkey(master: &[u8; KEY_LEN], info: &[u8]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut out = [0u8; KEY_LEN];
    hk.expand(info, &mut out)
        .expect("longitud de expansión HKDF válida");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cheap() -> KdfParams {
        // Coste bajo para que los tests sean rápidos (NO usar en producción).
        KdfParams {
            mem_kib: 64,
            iterations: 1,
            parallelism: 1,
        }
    }

    #[test]
    fn is_sane_bounds_the_cost_ceiling() {
        // El default es sano.
        assert!(KdfParams::default().is_sane());
        // 256 MiB (el techo) es sano; por encima se rechaza (anti-amplificación).
        assert!(
            KdfParams {
                mem_kib: KdfParams::MAX_MEM_KIB,
                iterations: 3,
                parallelism: 1,
            }
            .is_sane()
        );
        assert!(
            !KdfParams {
                mem_kib: KdfParams::MAX_MEM_KIB + 1,
                iterations: 3,
                parallelism: 1,
            }
            .is_sane()
        );
        // Params extremos (u32::MAX) siguen rechazados.
        assert!(
            !KdfParams {
                mem_kib: u32::MAX,
                iterations: u32::MAX,
                parallelism: u32::MAX,
            }
            .is_sane()
        );
    }

    #[test]
    fn different_passphrases_yield_different_keys() {
        let salt = [3u8; SALT_LEN];
        let a = derive_master_key("password-A", &salt, b"", &cheap());
        let b = derive_master_key("password-B", &salt, b"", &cheap());
        assert_ne!(a, b);
    }

    #[test]
    fn is_deterministic_for_same_inputs() {
        let salt = [3u8; SALT_LEN];
        let a = derive_master_key("pw", &salt, b"pep", &cheap());
        let b = derive_master_key("pw", &salt, b"pep", &cheap());
        assert_eq!(a, b);
    }

    #[test]
    fn nfkc_equivalent_passphrases_yield_same_key() {
        // "café" con é precompuesta (U+00E9) vs e + acento combinante (U+0301).
        let precomposed = "caf\u{00e9}";
        let decomposed = "cafe\u{0301}";
        assert_ne!(precomposed.as_bytes(), decomposed.as_bytes()); // bytes distintos
        let salt = [3u8; SALT_LEN];
        let a = derive_master_key(precomposed, &salt, b"", &cheap());
        let b = derive_master_key(decomposed, &salt, b"", &cheap());
        assert_eq!(a, b); // pero misma clave gracias a NFKC
    }

    #[test]
    fn different_pepper_yields_different_key() {
        let salt = [3u8; SALT_LEN];
        let a = derive_master_key("pw", &salt, b"pepper-1", &cheap());
        let b = derive_master_key("pw", &salt, b"pepper-2", &cheap());
        assert_ne!(a, b);
    }

    #[test]
    fn different_salt_yields_different_key() {
        let a = derive_master_key("pw", &[1u8; SALT_LEN], b"", &cheap());
        let b = derive_master_key("pw", &[2u8; SALT_LEN], b"", &cheap());
        assert_ne!(a, b);
    }

    #[test]
    fn subkeys_are_domain_separated() {
        let master = [42u8; KEY_LEN];
        let k_cipher = derive_subkey(&master, b"cipher");
        let k_codebook = derive_subkey(&master, b"codebook");
        assert_ne!(k_cipher, k_codebook); // distinta etiqueta -> distinta subclave
        assert_eq!(k_cipher, derive_subkey(&master, b"cipher")); // determinista
    }
}
