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
//!
//! POR QUÉ HAY DOS PASADAS, y no es adorno. `decode_verified` recibe TEXTO y lo
//! primero que hace es `dict.decode`, que exige que CADA carácter esté en el
//! alfabeto insignia — 4096 glifos CJK contiguos desde U+4E00. Pasarle los bytes
//! del fuzzer tal cual, como se hacía hasta el 2026-07-31, es morir en esa puerta
//! siempre: MEDIDO, 96.923 ejecuciones con la cobertura congelada desde la
//! ejecución nº 5 y un corpus que degeneró a unidades de UN byte, porque alargar
//! la entrada no abría nada. El objetivo estaba verde sin haber tocado jamás el
//! parser que dice fuzzear. Así que:
//!
//!   1. DOMINIO DEL BLOB — se traduce la entrada al alfabeto por el mismo camino
//!      que usa `armar_firmado`, de modo que el parser reciba EXACTAMENTE los
//!      bytes del fuzzer como blob. Aquí se fuzzea el rebanado de las firmas.
//!   2. DOMINIO DEL TEXTO — si la entrada es UTF-8, se pasa además cruda, que es
//!      lo único que ejercitaba la versión anterior. Cubre el decodificador del
//!      alfabeto contra texto hostil, y no se pierde por hacer lo de arriba.
//!
//! Con la pasada (1) este objetivo consume el MISMO idioma de entrada que
//! `parse_container` y `unpad` —bytes crudos de blob—, que es lo que hace que
//! encadenar sus corpus signifique algo. Ver `fuzz/README.md`.
//!
//! Y LA CLAVE SALE DE UNA SEMILLA, no de un relleno constante. Hasta el
//! 2026-07-31 aquí decía `VerifyingKey::from_bytes(&[0x42; 2624])` dentro de un
//! `if let Some(vk)`. Esa clave NO PARSEA —los 32 primeros bytes son un punto
//! Ed25519 comprimido, y `0x42` repetido no lo es—, así que la condición era
//! falsa en cada iteración y el cuerpo entero no se ejecutaba nunca: el objetivo
//! llevaba en verde desde que se añadió fuzzeando literalmente nada. Una semilla
//! de 64 bytes sí es válida por construcción —`SigningKey::from_bytes` toma dos
//! semillas, no puntos— y da una clave fija, real y determinista.

use libfuzzer_sys::fuzz_target;
use quipu::{api, codec, dictionaries, pqsign};

fuzz_target!(|data: &[u8]| {
    let dict = dictionaries::flagship();
    // Clave de verificación FIJA y DETERMINISTA: lo que se fuzzea es el
    // contenedor, no la clave. Con una clave aleatoria por iteración el corpus no
    // acumularía; con una constante que no parsea, no se fuzzea nada.
    let Some(sk) = pqsign::SigningKey::from_bytes(&[0x42u8; pqsign::SIGNING_KEY_LEN]) else {
        panic!("la semilla de firma de longitud correcta debe parsear");
    };
    let vk = sk.verifying_key();

    // (1) Dominio del blob. El round-trip del codec es exacto —lo sostiene el
    // objetivo `codec_roundtrip`—, así que el parser ve `data` sin alterar.
    let indices = codec::encode_base_n(data, dict.base());
    if let Ok(simbolos) = dict.encode(&indices) {
        assert!(
            api::decode_verified(&simbolos, &vk, &dict).is_err(),
            "un contenedor arbitrario verificó contra una clave ajena"
        );
    }

    // (2) Dominio del texto: el decodificador del alfabeto contra bytes hostiles.
    if let Ok(s) = std::str::from_utf8(data) {
        assert!(
            api::decode_verified(s, &vk, &dict).is_err(),
            "un contenedor arbitrario verificó contra una clave ajena"
        );
    }
});
