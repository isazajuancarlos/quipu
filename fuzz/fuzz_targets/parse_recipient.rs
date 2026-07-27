#![no_main]
//! Fuzz del contenedor HÍBRIDO post-cuántico (`QPQ1`).
//!
//! `docs/ATAQUES_TAXONOMIA.md`, familia 7. Este parser es el más delicado de los
//! tres: además de la cabecera lleva una encapsulación ML-KEM de longitud fija y
//! una clave efímera X25519, y el descifrado hace decapsulación ANTES de que
//! ningún tag lo autentique — es el orden que obliga a que la decapsulación sea
//! robusta ante basura, no solo ante entrada bien formada.

use libfuzzer_sys::fuzz_target;
use quipu::{api, dictionaries, pqhybrid};

fuzz_target!(|data: &[u8]| {
    let dict = dictionaries::flagship();
    // Clave secreta FIJA y derivada de bytes constantes: lo que se fuzzea es el
    // contenedor. Si la clave no es válida, no hay nada que probar.
    let sk_bytes = [0x37u8; pqhybrid::SECRET_KEY_LEN];
    if let Some(sk) = pqhybrid::SecretKey::from_bytes(&sk_bytes) {
        if let Ok(s) = std::str::from_utf8(data) {
            // Nunca pánico. Y nunca Ok: nadie cifró hacia esta clave.
            let _ = api::decode_as_recipient(s, &sk, &dict);
        }
    }
});
