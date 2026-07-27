// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! `quipu-cnsa`: el perfil de Quipu alineado con los algoritmos de CNSA 2.0.
//!
//! # ALINEACIÓN NO ES CUMPLIMIENTO
//!
//! Esta librería **implementa los algoritmos** que exige CNSA 2.0. **NO está
//! validada FIPS 140-3.** No lo estará por escribir más código: la validación
//! es un proceso de laboratorio acreditado y cuesta dinero.
//!
//! Quien necesite cumplimiento formal —no alineación— debe saberlo antes de
//! elegir, no después de que alguien pregunte en una auditoría. Por eso está
//! aquí arriba y en la primera pantalla del README.
//!
//! # Qué relación tiene con `quipu`
//!
//! La de Devuan con Debian: no una rama de mantenimiento, sino una
//! distribución con un **compromiso declarado** que comparte casi todo y tiene
//! identidad propia.
//!
//! | | `quipu` | `quipu-cnsa` |
//! |---|---|---|
//! | AEAD | XChaCha20-Poly1305 | **AES-256-GCM** |
//! | Nonce | 192 bits (extendido) | **96 bits** |
//! | Derivación | Argon2id + HKDF-**SHA-256** | Argon2id + HKDF-**SHA-384** |
//! | Huella de codebook | SHA-256 | **SHA-384** |
//! | Formato, codec, ECC, PNG | `quipu-nucleo` | `quipu-nucleo` (el mismo) |
//!
//! Lo compartido vive en [`quipu_nucleo`] y se arregla **una vez**. Copiar el
//! repositorio y dejarlo divergir es como mueren los forks, y en criptografía
//! muere con una vulnerabilidad corregida en una rama y no en la otra.
//!
//! # Por qué XChaCha20 sigue siendo el que recomendamos
//!
//! Que exista este perfil no significa que sea mejor. **En hardware sin
//! aceleración AES, AES-GCM es una REGRESIÓN**: las implementaciones en
//! software son más lentas y más difíciles de escribir en tiempo constante.
//! ChaCha20 no tiene tablas de sustitución y es constante por construcción.
//!
//! Este perfil existe para quien tiene un mandato normativo, no para quien
//! busca la mejor criptografía disponible. Si puedes elegir, usa `quipu`.
//!
//! # Argon2id NO se cambia, y es deliberado
//!
//! CNSA 2.0 no se pronuncia sobre derivación desde contraseña. Sustituir
//! Argon2id por PBKDF2 para «parecer conforme» **debilitaría el sistema por
//! estética normativa**: PBKDF2 no tiene coste en memoria y es órdenes de
//! magnitud más barato de atacar con hardware dedicado.
//!
//! # El nonce de 96 bits NO necesita estado global
//!
//! Es la duda razonable que plantea todo el que ve un nonce de 96 bits, y
//! merece respuesta explícita: el fallo catastrófico de AES-GCM es reutilizar
//! el par `(clave, nonce)`.
//!
//! Aquí **la clave es distinta en cada operación**: se deriva con Argon2id
//! desde una sal aleatoria de 128 bits que se genera en cada cifrado. Repetir
//! `(clave, nonce)` exigiría colisión de la sal *y* del nonce. La unicidad la
//! garantiza la sal, no el nonce.
//!
//! En términos de SP 800-38D: el modo normal usa la construcción aleatoria
//! (§8.2.2), cuyo límite es 2^32 invocaciones **por clave** — y aquí cada clave
//! se usa **exactamente una vez**. Un contador persistente no añadiría
//! seguridad y sí traería un archivo de estado que corromper y sincronizar.
//!
//! # Lo que TODAVÍA no cubre
//!
//! **No hay firma.** Este perfil solo cifra y descifra. Faltan también el modo
//! streaming, el canal de destinatario (ML-KEM) y los enlaces para otros
//! lenguajes.
//!
//! Sobre LMS/XMSS, con el matiz correcto —lo escribimos mal en una versión
//! previa de este doc—: **ML-DSA-87 está aprobado para cualquier uso**, incluida
//! la firma de software y firmware. LMS y XMSS (SP 800-208) están aprobados
//! **exclusivamente** para ese renglón, y la NSA los priorizó ahí por razones
//! prácticas, no porque ML-DSA no sirva. SLH-DSA, en cambio, **no está en CNSA
//! 2.0** en absoluto.
//!
//! Consecuencia: cuando se añada firma aquí, **ML-DSA-87 basta para estar
//! alineados**. LMS/XMSS sería una opción adicional para firmar firmware, con un
//! coste operativo serio: son esquemas CON ESTADO y reutilizar el contador es
//! catastrófico.

#![forbid(unsafe_code)]

pub mod api;
pub mod cipher;
pub mod dictionary;
pub mod kdf;

/// El contenedor de `quipu-nucleo` con el perfil CNSA ya fijado
/// (sal de 16 bytes, nonce de 12).
pub mod container {
    pub use quipu_nucleo::container::{ContainerError, MAGIC, VERSION};

    use crate::cipher::NONCE_LEN;
    use crate::kdf::SALT_LEN;

    /// Cabecera con el perfil CNSA: 56 bytes, doce menos que la de `quipu`
    /// porque su nonce es de 96 bits en vez de 192.
    pub type Header = quipu_nucleo::container::Header<SALT_LEN, NONCE_LEN>;

    /// Serializa cabecera + ciphertext en un único blob.
    pub fn serialize(header: &Header, ciphertext: &[u8]) -> Vec<u8> {
        quipu_nucleo::container::serialize(header, ciphertext)
    }

    /// Parsea un blob en (cabecera, ciphertext). Valida magic y versión.
    pub fn parse(blob: &[u8]) -> Result<(Header, &[u8]), ContainerError> {
        quipu_nucleo::container::parse(blob)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Guardián del perfil. Si alguien cambiara `NONCE_LEN` sin darse
        /// cuenta de que arrastra el formato en disco, tiene que fallar aquí.
        #[test]
        fn el_perfil_cnsa_es_16_12_y_la_cabecera_56() {
            assert_eq!(SALT_LEN, 16);
            assert_eq!(NONCE_LEN, 12);
            assert_eq!(Header::SIZE, 56);
        }

        /// Y la prueba que da sentido a la separación: este formato NO es el de
        /// `quipu`. Son 12 bytes menos, exactamente el nonce que se recorta.
        #[test]
        fn el_formato_difiere_del_de_quipu_en_los_doce_bytes_del_nonce() {
            type CabeceraQuipu = quipu_nucleo::container::Header<16, 24>;
            assert_eq!(CabeceraQuipu::SIZE - Header::SIZE, 12);
        }
    }
}

/// Reexporta el núcleo compartido para que quien use `quipu-cnsa` no tenga que
/// declarar `quipu-nucleo` por su cuenta.
pub use quipu_nucleo::{codec, ecc, prelayers};

#[cfg(test)]
mod promesa {
    //! Que la portada no prometa lo que las tripas no tienen.
    //!
    //! El 2026-07-27 el `description` de este crate —el texto que se publica en
    //! crates.io— anunciaba ML-KEM-1024 mientras la documentación de dentro lo
    //! listaba entre lo que FALTA. No era un fallo de seguridad; era una
    //! promesa de alcance sin respaldo, y este perfil se sostiene precisamente
    //! sobre que su alcance sea comprobable.
    //!
    //! Un README no lo caza nadie hasta que lo lee un tercero. Esto sí.

    use std::collections::HashMap;

    /// Cómo se ve en el código cada algoritmo que se puede nombrar.
    fn marcadores() -> HashMap<&'static str, Vec<&'static str>> {
        HashMap::from([
            ("AES-256-GCM", vec!["Aes256Gcm"]),
            ("HKDF", vec!["Hkdf", "hkdf"]),
            ("SHA-384", vec!["Sha384"]),
            ("SHA-512", vec!["Sha512"]),
            ("ML-KEM", vec!["MlKem", "ml_kem", "MlKem1024"]),
            ("ML-DSA", vec!["MlDsa", "ml_dsa"]),
            ("SLH-DSA", vec!["SlhDsa", "slh_dsa"]),
            ("Argon2", vec!["Argon2", "argon2"]),
            ("XChaCha20", vec!["XChaCha20", "xchacha"]),
        ])
    }

    /// El código del crate, SIN este módulo de prueba.
    ///
    /// El recorte se hace archivo por archivo. La primera versión concatenaba
    /// todo y truncaba en la primera aparición de `mod promesa`, lo que se
    /// llevaba por delante cuanto se hubiera concatenado después — y el orden de
    /// `read_dir` no está definido, así que la prueba fallaba o no según qué
    /// archivo se leyera primero. Un banco que depende del orden del sistema de
    /// archivos no mide nada.
    fn fuente_del_crate() -> String {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut todo = String::new();
        for e in std::fs::read_dir(&dir).expect("src/ del crate") {
            let ruta = e.expect("entrada").path();
            if ruta.extension().is_some_and(|x| x == "rs") {
                let texto = std::fs::read_to_string(&ruta).expect("fuente");
                let util = match texto.find("mod promesa {") {
                    Some(i) => &texto[..i],
                    None => &texto[..],
                };
                todo.push_str(util);
            }
        }
        todo
    }

    #[test]
    fn la_descripcion_no_nombra_algoritmos_que_no_estan() {
        let manifiesto =
            std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
                .expect("Cargo.toml");
        let descripcion = manifiesto
            .lines()
            .find(|l| l.trim_start().starts_with("description"))
            .expect("el crate debe tener description")
            .to_string();

        let fuente = fuente_del_crate();

        let mut mentiras = Vec::new();
        for (nombre, marcas) in marcadores() {
            if !descripcion.contains(nombre) {
                continue;
            }
            if !marcas.iter().any(|m| fuente.contains(m)) {
                mentiras.push(nombre);
            }
        }
        assert!(
            mentiras.is_empty(),
            "el `description` del crate promete {mentiras:?}, y no está en el código. \n\
             O se implementa, o se quita de la promesa: este perfil se vende sobre que \n\
             su alcance sea comprobable, y una promesa de más resta credibilidad a la \n\
             afirmación que sí importa (implementa los algoritmos, NO está validado).",
        );
    }

    /// Y que DISCRIMINE: si el buscador no encontrara nada nunca, la prueba de
    /// arriba pasaría con cualquier descripción.
    #[test]
    fn la_prueba_encuentra_lo_que_si_esta() {
        let fuente = fuente_del_crate();
        assert!(
            fuente.contains("Aes256Gcm"),
            "AES-256-GCM está implementado y el buscador no lo ve: la otra prueba no vale nada",
        );
        assert!(
            !fuente.contains("Aes128"),
            "el buscador tiene que poder decir que NO: encontró algo que no existe",
        );
    }
}
