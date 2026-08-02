// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

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
    /// [`KdfParams::EQUILIBRADO`]: 64 MiB, 3 iteraciones, 1 hilo.
    ///
    /// El defecto ES un peldaño de la escalera canónica, y no por casualidad:
    /// así el caso abrumadoramente común escribe en la cabecera los mismos doce
    /// bytes que todo el mundo. Ver [`KdfParams::canonicos`].
    fn default() -> Self {
        Self::EQUILIBRADO
    }
}

impl KdfParams {
    // # La escalera canónica, y por qué existe
    // 
    // Los tres parámetros del KDF **viajan en claro en la cabecera** y son
    // idénticos entre todos los contenedores que una misma persona escriba. Con
    // valores ajustados a mano —a la memoria de su máquina, a su gusto— esos
    // doce bytes son **una huella de su configuración** que agrupa sus archivos
    // en un corpus de procedencia mezclada. Está medido y declarado en N9 de
    // `docs/THREAT_MODEL.md`.
    // 
    // La escalera lo colapsa **sin tocar el formato**: los doce bytes siguen
    // ahí, pero pasan a llevar la elección entre tres valores en vez de
    // configuración arbitraria. Todo el que use `EQUILIBRADO` se ve igual.
    // 
    // Es la misma forma que `negacion::tamano_canonico` para el tamaño del
    // contenedor, y por la misma razón: lo que protege no es que cada uno elija
    // bien, sino que **todos elijan entre los mismos pocos valores**.
    // 
    // **No se impone.** `Options::kdf_params` sigue aceptando cualquier valor
    // sensato: quien tenga un motivo real —un dispositivo con 32 MiB, una
    // política que exija otro coste— no puede quedarse sin camino. Lo que se
    // hace es decirlo: **fuera de la escalera vive la huella**.

    /// Para dispositivos con poca memoria o interacción muy frecuente.
    /// 16 MiB, 3 iteraciones, 1 hilo.
    pub const LIGERO: Self = Self {
        mem_kib: 16 * 1024,
        iterations: 3,
        parallelism: 1,
    };

    /// El de referencia, y el que devuelve `Default`. 64 MiB, 3 iteraciones.
    pub const EQUILIBRADO: Self = Self {
        mem_kib: 64 * 1024,
        iterations: 3,
        parallelism: 1,
    };

    /// Para secretos de alto valor. 256 MiB —el máximo que se acepta al leer— y
    /// 4 iteraciones. Coincide con `negacion::Perfil::V1`, que es deliberado:
    /// dos módulos que eligen el mismo coste no deben escribir números
    /// distintos.
    pub const FUERTE: Self = Self {
        mem_kib: Self::MAX_MEM_KIB,
        iterations: 4,
        parallelism: 1,
    };

    /// La escalera completa, de menor a mayor coste.
    #[must_use]
    pub const fn canonicos() -> &'static [Self] {
        &[Self::LIGERO, Self::EQUILIBRADO, Self::FUERTE]
    }

    /// `true` si estos parámetros están en la escalera.
    ///
    /// Sirve para que una herramienta encima de Quipu pueda AVISAR —no
    /// rechazar— cuando alguien se sale de ella.
    #[must_use]
    pub fn es_canonico(&self) -> bool {
        Self::canonicos().contains(self)
    }

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

/// Normaliza la passphrase EXACTAMENTE como lo hace [`derive_master_key`].
///
/// Es la única definición de «la misma contraseña» que existe en Quipu, y está
/// expuesta al crate para que nadie la reimplemente: quien tenga que decidir si
/// dos frases son la misma —`negacion::crear` lo hace antes de gastar un
/// Argon2id— tiene que usar el mismo criterio que la derivación. Comparar bytes
/// crudos donde el KDF compara tras NFKC abre un hueco entre lo que la
/// comprobación dice y lo que la clave hace.
pub(crate) fn normalizar(passphrase: &str) -> String {
    passphrase.nfkc().collect()
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
    let mut normalized: String = normalizar(passphrase);
    // El pepper se concatena al material de contraseña.
    //
    // AMBIGÜEDAD DE CODIFICACIÓN CONOCIDA, sin explotación hallada y anotada
    // aquí porque este es el sitio donde se arreglaría. `NFKC(pw) ‖ pepper` sin
    // separador significa que los pares (pw="ab", pepper="c") y (pw="a",
    // pepper="bc") derivan LA MISMA clave. En el modo online la cadena es
    // `pw ‖ pepper_base ‖ endurecido(64)`, con el mismo problema.
    //
    // POR QUÉ NO SE HA ENCONTRADO ATAQUE: quien elige la contraseña y quien
    // elige el pepper son la misma parte, así que la colisión hay que
    // provocársela uno mismo; y en el modo online el sufijo endurecido depende
    // del propio `pw`, de modo que un par colisionante exigiría además
    // `OPRF(pw₁) = OPRF(pw₂)`.
    //
    // POR QUÉ AUN ASÍ HAY QUE ARREGLARLO: es una ambigüedad gratuita en la ruta
    // de derivación de claves, y las ambigüedades gratuitas son las que un día
    // sostienen un ataque que nadie previó. El arreglo es un prefijo de longitud
    // por campo, y es RUPTURA DE FORMATO — todas las claves derivadas cambian.
    // Por eso va agrupado con las otras rupturas pendientes y no suelto:
    // quitar `codebook_id`, borrar `src/oprf.rs`, perfiles canónicos de KDF y
    // huella de alfabeto con clave. Una sola ruptura en vez de cinco.
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

/// Expande un flujo pseudoaleatorio de longitud arbitraria desde la clave
/// maestra (HKDF-SHA256, etiqueta de dominio `info`). El máximo es 255*32 =
/// 8160 bytes por el límite de HKDF-Expand.
pub fn derive_stream(master: &[u8; KEY_LEN], info: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(None, master);
    hk.expand(info, out)
        .expect("longitud de expansión HKDF dentro del límite (<= 8160 bytes)");
}

#[cfg(test)]
mod tests {
    /// EL DEFECTO NO CAMBIÓ NI UN BYTE al introducir la escalera.
    ///
    /// Es la prueba que convierte esto en aditivo: si `Default` hubiera pasado a
    /// devolver otra cosa, TODO contenedor nuevo escribiría parámetros distintos
    /// y los viejos derivarían otra clave. La escalera se diseñó alrededor del
    /// defecto que ya había, no al revés.
    #[test]
    fn el_defecto_sigue_siendo_exactamente_el_de_siempre() {
        let d = KdfParams::default();
        assert_eq!(d.mem_kib, 65536, "64 MiB, como desde la 0.10.0");
        assert_eq!(d.iterations, 3);
        assert_eq!(d.parallelism, 1);
        assert_eq!(d, KdfParams::EQUILIBRADO);
        assert!(d.es_canonico(), "el defecto TIENE que estar en la escalera");
    }

    /// LO QUE LA ESCALERA COMPRA: los doce bytes de la cabecera dejan de ser
    /// una huella de la configuración y pasan a llevar una elección entre tres.
    #[test]
    fn la_escalera_colapsa_la_huella_de_configuracion() {
        use std::collections::HashSet;

        // Con la escalera: tres valores observables, se elija el que se elija.
        let con: HashSet<[u8; 12]> = KdfParams::canonicos().iter().map(bytes_de).collect();
        assert_eq!(con.len(), 3, "la escalera tiene que dar exactamente 3 huellas");

        // Sin ella, ajustando a mano como invita `Options`: cada configuración
        // es su propia huella. Se barre un rango PLAUSIBLE de ajustes humanos.
        let mut sin: HashSet<[u8; 12]> = HashSet::new();
        for mem in [8u32, 16, 32, 48, 64, 96, 128, 192, 256] {
            for it in 2..=6u32 {
                for par in 1..=4u32 {
                    let p = KdfParams { mem_kib: mem * 1024, iterations: it, parallelism: par };
                    if p.is_sane() {
                        sin.insert(bytes_de(&p));
                    }
                }
            }
        }
        assert!(
            sin.len() > 100,
            "solo {} configuraciones a mano: el barrido no representa el problema",
            sin.len()
        );
        assert!(
            con.len() * 30 < sin.len(),
            "la escalera da {} huellas y el ajuste a mano {}: el colapso no compensa",
            con.len(), sin.len()
        );
    }

    /// Los doce bytes tal como van en la cabecera, en el mismo orden.
    fn bytes_de(p: &KdfParams) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[0..4].copy_from_slice(&p.mem_kib.to_be_bytes());
        b[4..8].copy_from_slice(&p.iterations.to_be_bytes());
        b[8..12].copy_from_slice(&p.parallelism.to_be_bytes());
        b
    }

    /// La escalera entera tiene que pasar `is_sane`, o un peldaño sería
    /// irrecuperable al leer: `recover` rechaza los parámetros insensatos ANTES
    /// de derivar, así que un canónico que no lo fuera crearía contenedores que
    /// la propia librería no puede abrir.
    #[test]
    fn todos_los_peldanos_son_sensatos_y_distintos() {
        let c = KdfParams::canonicos();
        for p in c {
            assert!(p.is_sane(), "peldaño insensato: {p:?}");
            assert!(p.es_canonico());
        }
        // Ordenados por coste creciente, que es lo que la documentación promete.
        for par in c.windows(2) {
            assert!(
                par[0].mem_kib < par[1].mem_kib || par[0].iterations < par[1].iterations,
                "la escalera no crece: {:?} antes que {:?}", par[0], par[1]
            );
        }
        // Y discrimina: un ajuste a mano NO cuenta como canónico.
        let a_mano = KdfParams { mem_kib: 100 * 1024, iterations: 3, parallelism: 1 };
        assert!(a_mano.is_sane(), "el caso de prueba tiene que ser legítimo");
        assert!(!a_mano.es_canonico(), "un ajuste a mano no puede pasar por canónico");
    }

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
