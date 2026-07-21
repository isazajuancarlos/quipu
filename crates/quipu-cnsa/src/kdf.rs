// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Derivación de clave del perfil CNSA:
//!   passphrase -> NFKC -> (+ pepper) -> Argon2id -> clave maestra
//!   clave maestra -> HKDF-**SHA-384** (etiqueta `info`) -> subclaves.
//!
//! Segunda divergencia real con `quipu`, que expande con HKDF-SHA-256.
//!
//! # Por qué Argon2id NO se cambia
//!
//! CNSA 2.0 **no se pronuncia** sobre derivación desde contraseña: cubre
//! cifrado, firma, intercambio de claves y hash, no el paso
//! contraseña → clave. Sustituir Argon2id por PBKDF2 para «parecer conforme»
//! sería debilitar el sistema por estética normativa — PBKDF2 no tiene coste en
//! memoria y es órdenes de magnitud más barato de atacar con hardware
//! dedicado. Se mantiene Argon2id y se declara.
//!
//! # Por qué SHA-384 y no SHA-512
//!
//! CNSA 2.0 nombra SHA-384 explícitamente. SHA-512 sería igual de fuerte —
//! SHA-384 es SHA-512 truncado con otro IV— pero el objetivo de este perfil es
//! poder señalar cada algoritmo en el documento. Elegir uno «equivalente» que
//! no aparece obliga a explicarlo en cada auditoría.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha384;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

/// Longitud de clave derivada (256 bits), la que exige AES-256.
pub const KEY_LEN: usize = 32;
/// Longitud del salt (128 bits).
///
/// **Es esta sal, y no el nonce, la que garantiza que nunca se repita el par
/// `(clave, nonce)` de AES-GCM.** Ver el doc de `cipher`.
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
    /// 64 MiB, 3 pasadas, 1 hilo: el perfil interactivo recomendado por el
    /// RFC 9106 para Argon2id.
    fn default() -> Self {
        Self {
            mem_kib: 65536,
            iterations: 3,
            parallelism: 1,
        }
    }
}

impl KdfParams {
    /// Techo de memoria admitido al DESCIFRAR: 256 MiB.
    pub const MAX_MEM_KIB: u32 = 256 * 1024;
    /// Techo de iteraciones admitido al descifrar.
    pub const MAX_ITERATIONS: u32 = 32;
    /// Techo de paralelismo admitido al descifrar.
    pub const MAX_PARALLELISM: u32 = 16;

    /// ¿Son unos parámetros que se puede aceptar de un blob ajeno?
    ///
    /// Los parámetros viajan EN LA CABECERA, y aunque están autenticados como
    /// AAD, la autenticación ocurre **después** de derivar la clave. Un blob
    /// hostil con `mem_kib = u32::MAX` haría que la víctima intentara reservar
    /// 4 TiB antes de descubrir que el tag no valida: una bomba de
    /// amplificación con un archivo de 60 bytes.
    ///
    /// Por eso se valida ANTES de derivar. No es paranoia: es el único punto
    /// del descifrado donde se actúa sobre datos todavía no autenticados
    /// (invariante I2 de `docs/ATAQUES_TAXONOMIA.md`).
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
    // NFKC: la "misma" contraseña deriva siempre la misma clave, aunque el
    // teclado o el sistema la compongan de otra forma.
    let mut normalized: String = passphrase.nfkc().collect();
    let mut secret = normalized.clone().into_bytes();
    normalized.zeroize();
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
    secret.zeroize();
    out
}

/// Deriva una subclave independiente desde la clave maestra y una etiqueta de
/// dominio (`info`), vía HKDF-SHA-384. Distinta etiqueta -> distinta subclave.
pub fn derive_subkey(master: &[u8; KEY_LEN], info: &[u8]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha384>::new(None, master);
    let mut out = [0u8; KEY_LEN];
    hk.expand(info, &mut out)
        .expect("longitud de expansión HKDF válida");
    out
}

/// Expande un flujo pseudoaleatorio desde la clave maestra (HKDF-SHA-384).
///
/// El máximo es 255*48 = **12240** bytes, no 8160: SHA-384 produce 48 bytes por
/// bloque frente a los 32 de SHA-256, y el límite de HKDF-Expand es 255 bloques.
pub fn derive_stream(master: &[u8; KEY_LEN], info: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha384>::new(None, master);
    hk.expand(info, out)
        .expect("longitud de expansión HKDF dentro del límite (<= 12240 bytes)");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Barato a propósito: estas pruebas comprueban la ESTRUCTURA de la
    /// derivación, no su coste. Con los parámetros reales tardarían minutos.
    fn barato() -> KdfParams {
        KdfParams {
            mem_kib: 64,
            iterations: 1,
            parallelism: 1,
        }
    }

    #[test]
    fn contrasenas_distintas_dan_claves_distintas() {
        let salt = [3u8; SALT_LEN];
        assert_ne!(
            derive_master_key("password-A", &salt, b"", &barato()),
            derive_master_key("password-B", &salt, b"", &barato())
        );
    }

    #[test]
    fn es_determinista_con_las_mismas_entradas() {
        let salt = [3u8; SALT_LEN];
        assert_eq!(
            derive_master_key("pw", &salt, b"pep", &barato()),
            derive_master_key("pw", &salt, b"pep", &barato())
        );
    }

    #[test]
    fn sales_distintas_dan_claves_distintas() {
        assert_ne!(
            derive_master_key("pw", &[1u8; SALT_LEN], b"", &barato()),
            derive_master_key("pw", &[2u8; SALT_LEN], b"", &barato())
        );
    }

    #[test]
    fn el_pepper_cambia_la_clave() {
        let salt = [3u8; SALT_LEN];
        assert_ne!(
            derive_master_key("pw", &salt, b"pepper-1", &barato()),
            derive_master_key("pw", &salt, b"pepper-2", &barato())
        );
    }

    /// NFKC: la misma contraseña escrita precompuesta o descompuesta debe dar
    /// la MISMA clave, o un usuario con teclado distinto no abre su archivo.
    #[test]
    fn normaliza_unicode_antes_de_derivar() {
        let salt = [3u8; SALT_LEN];
        let precompuesta = "cafe\u{0301}"; // e + acento combinante
        let compuesta = "caf\u{00e9}"; // é
        assert_eq!(
            derive_master_key(precompuesta, &salt, b"", &barato()),
            derive_master_key(compuesta, &salt, b"", &barato())
        );
    }

    #[test]
    fn etiquetas_distintas_dan_subclaves_distintas() {
        let master = [5u8; KEY_LEN];
        assert_ne!(
            derive_subkey(&master, b"quipu-cnsa/cipher"),
            derive_subkey(&master, b"quipu-cnsa/mac")
        );
    }

    /// LA PRUEBA QUE JUSTIFICA ESTE ARCHIVO. Si `quipu-cnsa` expandiera con el
    /// mismo hash que `quipu`, el perfil no existiría: la divergencia tiene que
    /// ser observable, no solo declarada en un comentario.
    #[test]
    fn expande_con_sha384_y_no_con_sha256() {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let master = [5u8; KEY_LEN];
        let nuestra = derive_subkey(&master, b"info");

        let mut con_sha256 = [0u8; KEY_LEN];
        Hkdf::<Sha256>::new(None, &master)
            .expand(b"info", &mut con_sha256)
            .unwrap();

        assert_ne!(
            nuestra, con_sha256,
            "la subclave del perfil CNSA debe salir de SHA-384, no de SHA-256"
        );
    }

    /// El límite de HKDF-SHA-384 es 255*48 bytes. Se comprueba que un flujo
    /// justo por debajo funciona: si alguien copiara el límite de SHA-256
    /// (8160) al migrar, se quedaría corto sin motivo.
    #[test]
    fn el_flujo_llega_al_limite_de_sha384() {
        let master = [5u8; KEY_LEN];
        let mut out = vec![0u8; 255 * 48];
        derive_stream(&master, b"info", &mut out);
        assert!(out.iter().any(|&b| b != 0), "el flujo no puede salir vacío");
    }
}
