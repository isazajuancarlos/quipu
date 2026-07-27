#![no_main]
//! Fuzz del parser del contenedor FIRMADO: bytes arbitrarios nunca deben
//! provocar panic, y jamás deben verificar.
//!
//! `docs/ATAQUES_TAXONOMIA.md`, familia 7, pedía ampliar el fuzz «a todos los
//! parsers de contenedor nuevos, no solo el simétrico». Este es el de la firma.
//!
//! Lo que se busca aquí no es solo la ausencia de pánico. Un contenedor firmado
//! lleva DOS firmas de longitud fija (Ed25519 y ML-DSA-87) y el parser tiene que
//! rebanarlas antes de verificar: es exactamente el sitio donde un índice mal
//! calculado desborda, y donde un contenedor truncado a la longitud justa podría
//! hacer que se lea basura como si fuera una firma.

use libfuzzer_sys::fuzz_target;
use quipu::{api, dictionaries, pqsign};

fuzz_target!(|data: &[u8]| {
    let dict = dictionaries::flagship();
    // Una clave de verificación FIJA: lo que se fuzzea es el contenedor, no la
    // clave. Con una clave aleatoria por iteración, el corpus no acumularía.
    let vk_bytes = [0x42u8; pqsign::VERIFYING_KEY_LEN];
    if let Some(vk) = pqsign::VerifyingKey::from_bytes(&vk_bytes) {
        if let Ok(s) = std::str::from_utf8(data) {
            // Ok o Err, nunca pánico. Y si devolviera Ok, sería una falsificación
            // contra una clave que nadie usó para firmar.
            assert!(
                api::decode_verified(s, &vk, &dict).is_err(),
                "un contenedor arbitrario verificó contra una clave ajena"
            );
        }
    }
});
