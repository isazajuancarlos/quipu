// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Autopruebas de arranque: vectores de respuesta conocida sobre el binario que
//! realmente se está ejecutando.
//!
//! ## Por qué existe
//!
//! Los vectores de `tests/` prueban **el build de CI**. No prueban el binario
//! que corre en la máquina del cliente: una rueda compilada con un flag raro, un
//! backend SIMD roto, una CPU defectuosa o una biblioteca sustituida en el
//! sistema pasarían inadvertidos. Los módulos criptográficos certificados —FIPS
//! 140-3 y los GM/T chinos por igual— exigen por eso **autopruebas de encendido**:
//! el módulo se verifica a sí mismo antes de operar, y si falla **se niega a
//! funcionar** en vez de producir resultados silenciosamente incorrectos.
//!
//! ## En qué va más allá de lo exigido
//!
//! 1. **Vectores publicados, no propios.** Donde existe un vector oficial se usa
//!    ese: HKDF-SHA256 contra el **caso de prueba 1 del RFC 5869**. Un módulo
//!    certificado puede usar vectores elegidos por el propio fabricante, que
//!    solo demuestran consistencia consigo mismo; un vector del RFC demuestra
//!    conformidad con el estándar.
//! 2. **Pruebas negativas.** No basta con que lo correcto funcione: se comprueba
//!    que **lo manipulado FALLA**. Un módulo que valide siempre pasaría unas
//!    autopruebas convencionales, que solo son positivas.
//! 3. **Salud del RNG en continuo.** Dos extracciones consecutivas no pueden
//!    coincidir ni ser todo ceros: detecta un generador muerto, que es el modo de
//!    fallo más silencioso y más catastrófico.
//!
//! ## Uso
//!
//! ```
//! // Explícito, con informe detallado (para diagnóstico o arranque de servicio):
//! let informe = quipu::selftest::run();
//! assert!(informe.ok(), "{informe}");
//! ```
//!
//! [`ensure`] las ejecuta **una sola vez por proceso** y entra en estado de
//! error si algo falla. El núcleo la invoca solo, así que no hay que acordarse.

use crate::antihacker::ct_eq;
use crate::cipher;
use crate::kdf::{self, KdfParams};
use crate::{pqhybrid, pqsign};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use std::sync::OnceLock;

/// Resultado de una prueba individual.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// Qué se probó.
    pub name: &'static str,
    /// Si pasó.
    pub passed: bool,
    /// Origen del vector, para poder auditarlo.
    pub source: &'static str,
}

/// Informe completo de las autopruebas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Cada prueba, en orden de ejecución.
    pub checks: Vec<Check>,
}

impl Report {
    /// `true` si todas pasaron.
    pub fn ok(&self) -> bool {
        self.checks.iter().all(|c| c.passed)
    }

    /// Nombres de las que fallaron.
    pub fn failures(&self) -> Vec<&'static str> {
        self.checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.name)
            .collect()
    }
}

impl core::fmt::Display for Report {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(
            f,
            "autopruebas quipu: {}/{} correctas",
            self.checks.iter().filter(|c| c.passed).count(),
            self.checks.len()
        )?;
        for c in &self.checks {
            writeln!(
                f,
                "  [{}] {:<34} ({})",
                if c.passed { "ok" } else { "FALLA" },
                c.name,
                c.source
            )?;
        }
        Ok(())
    }
}

/// Convierte hex de vector a bytes. Solo se usa con literales del propio
/// módulo, así que un hex inválido es un error de programación.
fn h(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex de vector válido"))
        .collect()
}

// --- Vectores -----------------------------------------------------------------

// RFC 5869, apéndice A.1 — caso de prueba 1 (HKDF-SHA256 básico).
// Vector PUBLICADO: demuestra conformidad con el estándar, no solo consistencia.
const RFC5869_IKM: &str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
const RFC5869_SALT: &str = "000102030405060708090a0b0c";
const RFC5869_INFO: &str = "f0f1f2f3f4f5f6f7f8f9";
const RFC5869_OKM: &str = "3cb25f25faacd57a90434f64d0362f2a\
                           2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                           34007208d5b887185865";

// Vectores congelados del proyecto (`tests/vectors/quipu_vectors.json`,
// 2026-07-04). Los mismos que verifica el CI, aquí embebidos para que viajen
// DENTRO del binario publicado.
const ARGON2_SALT: &str = "0102030405060708090a0b0c0d0e0f10";
const ARGON2_PASS: &str = "correct horse";
const ARGON2_MASTER: &str = "5d93644e2809e3ba0b45544e86a16b73d710a4787befda41324580d6d542af60";
const SUBKEY_INFO: &[u8] = b"quipu/v1/cipher";
const SUBKEY_EXPECTED: &str = "d90e65cda080025c232961f2bf4a6b27991842755c5341dffa484bac2f8212a9";

const AEAD_KEY: &str = "5a5b58595e5f5c5d52535051565754554a4b48494e4f4c4d4243404146474445";
const AEAD_NONCE: &str = "202122232425262728292a2b2c2d2e2f3031323334353637";
const AEAD_PLAIN: &str = "5843686143686132302d506f6c7931333035206b6e6f776e2d616e73776572";
const AEAD_AAD: &str = "63616265636572612d636f6d6f2d414144";
const AEAD_CIPHER: &str = "dbfa22815adba089dfe8a52d8defc8b8a55301bb2fec13ee5284dfb2b91249e07\
                           beb10eac5272f204be6f5c31e3dde";

// --- Pruebas individuales -----------------------------------------------------

/// HKDF-SHA256 contra el vector del RFC 5869. Conformidad con el estándar.
fn check_hkdf_rfc5869() -> bool {
    check_hkdf_rfc5869_contra(&h(RFC5869_OKM))
}

/// Igual, contra un vector dado, para probar que discrimina.
fn check_hkdf_rfc5869_contra(esperado_in: &[u8]) -> bool {
    let esperado = esperado_in.to_vec();
    let ikm = h(RFC5869_IKM);
    let salt = h(RFC5869_SALT);
    let info = h(RFC5869_INFO);

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = vec![0u8; esperado.len()];
    if hk.expand(&info, &mut okm).is_err() {
        return false;
    }
    ct_eq(&okm, &esperado)
}

/// Argon2id: la derivación maestra reproduce el vector congelado.
fn check_argon2id() -> bool {
    let salt: [u8; 16] = h(ARGON2_SALT).try_into().expect("salt de 16 bytes");
    let params = KdfParams {
        mem_kib: 64,
        iterations: 1,
        parallelism: 1,
    };
    let master = kdf::derive_master_key(ARGON2_PASS, &salt, b"", &params);
    ct_eq(&master, &h(ARGON2_MASTER))
}

/// HKDF con la etiqueta de dominio del cifrado, tal como lo usa el núcleo.
fn check_derive_subkey() -> bool {
    let master: [u8; 32] = h(ARGON2_MASTER).try_into().expect("maestra de 32 bytes");
    let sub = kdf::derive_subkey(&master, SUBKEY_INFO);
    ct_eq(&sub, &h(SUBKEY_EXPECTED))
}

/// XChaCha20-Poly1305: cifrado determinista contra el vector congelado.
fn check_aead_encrypt() -> bool {
    check_aead_encrypt_contra(&h(AEAD_CIPHER))
}

/// Igual, pero contra un vector dado. Existe para poder demostrar en pruebas que
/// la comprobación DISCRIMINA: una que devolviera `true` siempre pasaría el
/// autotest igual que una correcta, y sería decorativa.
fn check_aead_encrypt_contra(esperado: &[u8]) -> bool {
    if FALLO_INYECTADO {
        return false;
    }
    let key: [u8; 32] = h(AEAD_KEY).try_into().expect("clave de 32 bytes");
    let nonce: [u8; 24] = h(AEAD_NONCE).try_into().expect("nonce de 24 bytes");
    let ct = cipher::encrypt(&key, &nonce, &h(AEAD_PLAIN), &h(AEAD_AAD));
    ct_eq(&ct, esperado)
}

/// XChaCha20-Poly1305: el descifrado recupera el texto claro.
fn check_aead_decrypt() -> bool {
    let key: [u8; 32] = h(AEAD_KEY).try_into().expect("clave de 32 bytes");
    let nonce: [u8; 24] = h(AEAD_NONCE).try_into().expect("nonce de 24 bytes");
    match cipher::decrypt(&key, &nonce, &h(AEAD_CIPHER), &h(AEAD_AAD)) {
        Ok(pt) => ct_eq(&pt, &h(AEAD_PLAIN)),
        Err(_) => false,
    }
}

/// PRUEBA NEGATIVA: un ciphertext alterado DEBE rechazarse.
///
/// Un AEAD roto que aceptara siempre pasaría las pruebas positivas. Esta es la
/// que lo detecta, y es la que las autopruebas convencionales no traen.
fn check_aead_rejects_tamper() -> bool {
    let key: [u8; 32] = h(AEAD_KEY).try_into().expect("clave de 32 bytes");
    let nonce: [u8; 24] = h(AEAD_NONCE).try_into().expect("nonce de 24 bytes");
    let mut ct = h(AEAD_CIPHER);
    ct[0] ^= 0x01;
    cipher::decrypt(&key, &nonce, &ct, &h(AEAD_AAD)).is_err()
}

/// PRUEBA NEGATIVA: un AAD distinto DEBE rechazarse (el ligado de contexto
/// funciona de verdad).
fn check_aead_rejects_wrong_aad() -> bool {
    let key: [u8; 32] = h(AEAD_KEY).try_into().expect("clave de 32 bytes");
    let nonce: [u8; 24] = h(AEAD_NONCE).try_into().expect("nonce de 24 bytes");
    cipher::decrypt(&key, &nonce, &h(AEAD_CIPHER), b"aad-distinto").is_err()
}

/// Consistencia de par de claves ML-KEM-1024 (lo que FIPS 140-3 llama PCT):
/// la encapsulación y la decapsulación coinciden sobre un par recién generado.
fn check_mlkem_pairwise() -> bool {
    let (pk, sk) = pqhybrid::generate_keypair_unchecked();
    let (k1, enc) = pqhybrid::encapsulate(&pk);
    match pqhybrid::decapsulate(&sk, &enc) {
        Some(k2) => ct_eq(&k1, &k2),
        None => false,
    }
}

/// PRUEBA NEGATIVA: decapsular con la clave equivocada NO puede dar la misma
/// clave de contenido (rechazo implícito de ML-KEM).
fn check_mlkem_wrong_key_differs() -> bool {
    let (pk, _sk) = pqhybrid::generate_keypair_unchecked();
    let (_pk2, sk2) = pqhybrid::generate_keypair_unchecked();
    let (k1, enc) = pqhybrid::encapsulate(&pk);
    match pqhybrid::decapsulate(&sk2, &enc) {
        Some(k2) => !ct_eq(&k1, &k2),
        None => true,
    }
}

/// Consistencia de par de claves de firma híbrida (Ed25519 + ML-DSA-87).
fn check_signature_pairwise() -> bool {
    let (vk, sk) = pqsign::generate_keypair_unchecked();
    let firma = sk.sign(b"quipu selftest");
    vk.verify(b"quipu selftest", &firma)
}

/// PRUEBA NEGATIVA: una firma alterada DEBE rechazarse.
fn check_signature_rejects_forgery() -> bool {
    let (vk, sk) = pqsign::generate_keypair_unchecked();
    let mut firma = sk.sign(b"quipu selftest");
    firma[0] ^= 0x01;
    !vk.verify(b"quipu selftest", &firma)
}

/// PRUEBA NEGATIVA: la firma de OTRO mensaje no vale para este.
fn check_signature_rejects_wrong_message() -> bool {
    let (vk, sk) = pqsign::generate_keypair_unchecked();
    let firma = sk.sign(b"mensaje A");
    !vk.verify(b"mensaje B", &firma)
}

/// Salud del generador de aleatoriedad, en continuo.
///
/// Dos extracciones no pueden coincidir ni ser todo ceros. Un RNG muerto es el
/// fallo más silencioso posible: todo "funciona", y todas las claves son la
/// misma.
fn check_rng_health() -> bool {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut a);
    OsRng.fill_bytes(&mut b);
    a != b && a != [0u8; 32] && b != [0u8; 32]
}

/// La comparación en tiempo constante distingue de verdad.
///
/// Si `ct_eq` devolviera siempre `true`, todas las verificaciones de tag y firma
/// del núcleo se volverían decorativas.
fn check_ct_eq_discriminates() -> bool {
    ct_eq(b"identico", b"identico") && !ct_eq(b"identico", b"distinto") && !ct_eq(b"ab", b"abc")
}

// --- Ejecución ----------------------------------------------------------------

/// Ejecuta todas las autopruebas y devuelve el informe.
///
/// No entra en pánico: informa. Para el arranque fail-closed, ver [`ensure`].
pub fn run() -> Report {
    let checks = vec![
        Check {
            name: "HKDF-SHA256",
            passed: check_hkdf_rfc5869(),
            source: "RFC 5869 A.1 caso 1",
        },
        Check {
            name: "Argon2id (derivación maestra)",
            passed: check_argon2id(),
            source: "vector congelado del proyecto",
        },
        Check {
            name: "HKDF (subclave de dominio)",
            passed: check_derive_subkey(),
            source: "vector congelado del proyecto",
        },
        Check {
            name: "XChaCha20-Poly1305 cifra",
            passed: check_aead_encrypt(),
            source: "vector congelado del proyecto",
        },
        Check {
            name: "XChaCha20-Poly1305 descifra",
            passed: check_aead_decrypt(),
            source: "vector congelado del proyecto",
        },
        Check {
            name: "AEAD rechaza manipulación",
            passed: check_aead_rejects_tamper(),
            source: "prueba negativa",
        },
        Check {
            name: "AEAD rechaza AAD ajeno",
            passed: check_aead_rejects_wrong_aad(),
            source: "prueba negativa",
        },
        Check {
            name: "ML-KEM-1024 par consistente",
            passed: check_mlkem_pairwise(),
            source: "PCT (FIPS 140-3 §7.10.3)",
        },
        Check {
            name: "ML-KEM rechazo implícito",
            passed: check_mlkem_wrong_key_differs(),
            source: "prueba negativa",
        },
        Check {
            name: "Firma híbrida par consistente",
            passed: check_signature_pairwise(),
            source: "PCT (FIPS 140-3 §7.10.3)",
        },
        Check {
            name: "Firma rechaza falsificación",
            passed: check_signature_rejects_forgery(),
            source: "prueba negativa",
        },
        Check {
            name: "Firma rechaza otro mensaje",
            passed: check_signature_rejects_wrong_message(),
            source: "prueba negativa",
        },
        Check {
            name: "Salud del RNG",
            passed: check_rng_health(),
            source: "prueba continua de RNG",
        },
        Check {
            name: "Comparación en tiempo constante",
            passed: check_ct_eq_discriminates(),
            source: "meta-prueba de defensa",
        },
    ];
    Report { checks }
}

/// Informe de la única ejecución de este proceso.
static INFORME: OnceLock<Report> = OnceLock::new();

/// Inyección de fallo: fuerza a que una comprobación falle, para poder EJERCITAR
/// el camino de error de punta a punta (pánico en Rust, código de error en la C
/// ABI, excepción en Python) en vez de suponer que funciona.
///
/// Tras un feature no-default que nunca se activa en un build publicado, igual
/// que el Security Lab. Sin esto, el camino de fallo sería el único del módulo
/// que jamás se ejecuta — y es precisamente el que tiene que funcionar el día
/// que haga falta.
#[cfg(feature = "selftest-fault")]
const FALLO_INYECTADO: bool = true;
#[cfg(not(feature = "selftest-fault"))]
const FALLO_INYECTADO: bool = false;

/// Ejecuta las autopruebas una sola vez por proceso y devuelve el informe si
/// alguna falló.
///
/// Es la variante para quien quiera **manejar** el fallo en vez de que aborte:
/// los bindings la usan para lanzar una excepción legible en lugar de un pánico.
pub fn try_ensure() -> Result<(), &'static Report> {
    let informe = INFORME.get_or_init(run);
    if informe.ok() {
        Ok(())
    } else {
        Err(informe)
    }
}

/// Redacta el fallo en lenguaje humano.
///
/// Un autotest fallido **casi nunca es culpa de quien usa la librería**: no
/// tiene que ver con su contraseña, sus datos ni cómo la invocó. Significa que
/// el binario, la máquina o la instalación no son de fiar. El mensaje tiene que
/// decir eso, decir qué NO pasó —para que nadie tema por sus datos— y decir qué
/// hacer. Un volcado técnico sin más genera desconfianza y no ayuda a nadie.
pub fn explicar_fallo(informe: &Report) -> String {
    format!(
        "\n\
         Quipu se detuvo y no realizó la operación.\n\
         \n\
         Las comprobaciones internas de la librería no dieron el resultado\n\
         esperado, así que se negó a operar en lugar de producir un resultado en\n\
         el que no se puede confiar.\n\
         \n\
         ESTO NO ES UN PROBLEMA DE TUS DATOS NI DE TU CONTRASEÑA.\n\
         No se cifró, descifró ni guardó nada. Tus archivos están intactos.\n\
         \n\
         No superaron la comprobación: {fallidas}\n\
         \n\
         Causas posibles, de la más a la menos frecuente:\n\
         \n\
           1. La librería se compiló para un procesador distinto del que la está\n\
              ejecutando. Reinstálala para esta máquina.\n\
           2. El archivo de la librería está dañado o fue reemplazado.\n\
              Reinstálala desde su origen oficial (PyPI, crates.io o npm).\n\
           3. Memoria o procesador con fallos. Es poco común, pero ocurre.\n\
         \n\
         Si tras reinstalar vuelve a ocurrir, repórtalo en\n\
         https://github.com/isazajuancarlos/quipu/issues e incluye el informe\n\
         completo de abajo: es justo lo que hace falta para diagnosticarlo.\n\
         \n\
         {informe}",
        fallidas = informe.failures().join(", "),
        informe = informe
    )
}

/// Ejecuta las autopruebas **una sola vez por proceso** y aborta si alguna falla.
///
/// Fail-closed a propósito, y no es una elección estética: si el AEAD o el KDF
/// no producen el resultado conocido, seguir adelante significa emitir
/// contenedores que nadie podrá descifrar o que no protegen lo que dicen
/// proteger. Un módulo criptográfico que se sabe defectuoso debe detenerse, no
/// avisar y continuar.
///
/// Para manejar el fallo en vez de abortar, ver [`try_ensure`].
///
/// # Panics
///
/// Si alguna autoprueba falla, con el mensaje de [`explicar_fallo`]. No hay
/// forma de desactivarlo: una válvula de escape aquí sería el primer sitio donde
/// miraría un atacante.
pub fn ensure() {
    if let Err(informe) = try_ensure() {
        panic!("{}", explicar_fallo(informe));
    }
}

/// `true` si las autopruebas ya se ejecutaron con éxito en este proceso.
pub fn ready() -> bool {
    INFORME.get().map(|r| r.ok()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // Sin sentido con `selftest-fault`: ahí el módulo debe fallar a
    // propósito. La contraparte es `con_fallo_inyectado_el_modulo_se_niega`.
    #[cfg(not(feature = "selftest-fault"))]
    fn todas_las_autopruebas_pasan() {
        let informe = run();
        assert!(informe.ok(), "{informe}");
    }

    #[test]
    fn el_informe_cubre_lo_que_dice_cubrir() {
        let informe = run();
        // Si alguien quita una prueba, esto lo delata.
        assert_eq!(informe.checks.len(), 14);
        let nombres: Vec<_> = informe.checks.iter().map(|c| c.name).collect();
        for esperado in [
            "HKDF-SHA256",
            "Argon2id (derivación maestra)",
            "XChaCha20-Poly1305 cifra",
            "ML-KEM-1024 par consistente",
            "Firma híbrida par consistente",
            "Salud del RNG",
        ] {
            assert!(nombres.contains(&esperado), "falta la prueba {esperado}");
        }
    }

    #[test]
    fn hay_pruebas_negativas_de_verdad() {
        // El punto que distingue estas autopruebas de las convencionales: al
        // menos un tercio deben ser negativas o de defensa.
        let informe = run();
        let negativas = informe
            .checks
            .iter()
            .filter(|c| c.source.contains("negativa") || c.source.contains("meta-prueba"))
            .count();
        assert!(
            negativas >= informe.checks.len() / 3,
            "solo {negativas} pruebas negativas de {}",
            informe.checks.len()
        );
    }

    #[test]
    // Sin sentido con `selftest-fault`: ahí el módulo debe fallar a
    // propósito. La contraparte es `con_fallo_inyectado_el_modulo_se_niega`.
    #[cfg(not(feature = "selftest-fault"))]
    fn ensure_es_idempotente_y_deja_ready() {
        ensure();
        ensure();
        assert!(ready());
        assert!(try_ensure().is_ok());
    }

    // --- ¿el autotest DETECTA de verdad? ---
    //
    // La pregunta que ninguna de las pruebas anteriores responde: si una
    // primitiva estuviera rota, ¿lo veríamos? Una comprobación que devolviera
    // `true` siempre pasaría el autotest exactamente igual que una correcta.

    #[test]
    fn la_comprobacion_del_aead_discrimina() {
        let bueno = h(AEAD_CIPHER);
        // Con el fallo inyectado la comprobación devuelve false siempre; sin él,
        // el vector correcto debe pasar.
        assert_eq!(check_aead_encrypt_contra(&bueno), !FALLO_INYECTADO);

        // Un solo bit distinto tiene que hacerla fallar.
        let mut malo = bueno.clone();
        malo[0] ^= 0x01;
        assert!(!check_aead_encrypt_contra(&malo), "no detectó un bit cambiado");

        // Y longitudes distintas, y el vector vacío.
        assert!(!check_aead_encrypt_contra(&malo[..malo.len() - 1]));
        assert!(!check_aead_encrypt_contra(&[]));
    }

    #[test]
    fn la_comprobacion_de_hkdf_discrimina() {
        let bueno = h(RFC5869_OKM);
        assert!(check_hkdf_rfc5869_contra(&bueno));

        let mut malo = bueno.clone();
        malo[41] ^= 0x80; // último byte del vector del RFC
        assert!(!check_hkdf_rfc5869_contra(&malo), "no detectó un bit cambiado");
        assert!(!check_hkdf_rfc5869_contra(&[0u8; 42]));
    }

    #[test]
    #[cfg(feature = "selftest-fault")]
    fn con_fallo_inyectado_el_modulo_se_niega() {
        // Simulación del camino que importa: con una comprobación rota, el
        // informe falla, `try_ensure` devuelve Err y `ensure` aborta.
        let informe = run();
        assert!(!informe.ok(), "la inyección de fallo no surtió efecto");
        assert!(try_ensure().is_err());
        assert!(!ready());

        let r = std::panic::catch_unwind(ensure);
        assert!(r.is_err(), "ensure() debía abortar y no lo hizo");
    }

    #[test]
    fn el_mensaje_de_fallo_es_para_una_persona() {
        // No basta con que falle: tiene que explicarse. Un volcado técnico deja
        // al usuario sin saber si sus datos corren peligro ni qué hacer.
        let malo = Report {
            checks: vec![Check {
                name: "XChaCha20-Poly1305 cifra",
                passed: false,
                source: "vector congelado del proyecto",
            }],
        };
        let m = explicar_fallo(&malo);

        // Dice qué NO pasó, que es lo que quita el miedo.
        assert!(m.contains("NO ES UN PROBLEMA DE TUS DATOS"), "{m}");
        assert!(m.contains("Tus archivos están intactos"), "{m}");
        assert!(m.contains("no realizó la operación"), "{m}");
        // Nombra lo que falló.
        assert!(m.contains("XChaCha20-Poly1305 cifra"), "{m}");
        // Dice qué hacer, con pasos concretos y una vía de reporte.
        assert!(m.contains("Reinstálala"), "{m}");
        assert!(m.contains("issues"), "{m}");
        // Y adjunta el informe para que el reporte sirva de algo.
        assert!(m.contains("autopruebas quipu"), "{m}");
    }

    #[test]
    // Sin sentido con `selftest-fault`: ahí el módulo debe fallar a
    // propósito. La contraparte es `con_fallo_inyectado_el_modulo_se_niega`.
    #[cfg(not(feature = "selftest-fault"))]
    fn generar_claves_no_reentra_en_la_autoprueba() {
        // REGRESIÓN. `generate_keypair` dispara `ensure()`, y `ensure()` corre
        // `run()`, que a su vez necesita generar claves. Si esas pruebas
        // llamasen a la versión PÚBLICA se reentraría en `Once::call_once`,
        // que no es reentrante: la hebra se bloquea para siempre esperando una
        // inicialización que ella misma está haciendo. Por eso `run()` usa las
        // variantes `_unchecked`.
        //
        // Se ejecuta con límite de tiempo a propósito: sin él, la regresión se
        // manifestaría como un CI colgado en vez de como una prueba en rojo, y
        // eso cuesta mucho más de diagnosticar.
        use std::sync::mpsc;
        use std::time::Duration;

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = crate::pqhybrid::generate_keypair();
            let _ = crate::pqsign::generate_keypair();
            let _ = tx.send(());
        });

        assert!(
            rx.recv_timeout(Duration::from_secs(30)).is_ok(),
            "generate_keypair se bloqueó: la autoprueba volvió a reentrar en Once"
        );
    }

    #[test]
    fn el_vector_del_rfc_5869_es_el_del_rfc() {
        // Vigila que nadie "arregle" el vector publicado para que pase: sus
        // longitudes son las del apéndice A.1.
        assert_eq!(h(RFC5869_IKM).len(), 22, "IKM del RFC 5869 A.1");
        assert_eq!(h(RFC5869_SALT).len(), 13, "salt del RFC 5869 A.1");
        assert_eq!(h(RFC5869_INFO).len(), 10, "info del RFC 5869 A.1");
        assert_eq!(h(RFC5869_OKM).len(), 42, "L=42 del RFC 5869 A.1");
    }

    #[test]
    fn un_informe_con_fallos_se_reporta_como_tal() {
        let malo = Report {
            checks: vec![
                Check {
                    name: "buena",
                    passed: true,
                    source: "x",
                },
                Check {
                    name: "mala",
                    passed: false,
                    source: "x",
                },
            ],
        };
        assert!(!malo.ok());
        assert_eq!(malo.failures(), vec!["mala"]);
        assert!(format!("{malo}").contains("FALLA"));
    }
}
