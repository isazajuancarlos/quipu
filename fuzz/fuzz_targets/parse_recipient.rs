#![no_main]
//! Fuzz del contenedor HÍBRIDO post-cuántico (`QPQ1`).
//!
//! `docs/ATAQUES_TAXONOMIA.md`, familia 7. Este parser es el más delicado de los
//! tres: además de la cabecera lleva una encapsulación ML-KEM de longitud fija y
//! una clave efímera X25519, y el descifrado hace decapsulación ANTES de que
//! ningún tag lo autentique — es el orden que obliga a que la decapsulación sea
//! robusta ante basura, no solo ante entrada bien formada.
//!
//! Dos pasadas, por la misma razón que en `parse_signed`: `decode_as_recipient`
//! recibe TEXTO y empieza por `dict.decode`, que exige que cada carácter esté en
//! los 4096 glifos CJK del alfabeto insignia. Alimentarlo con los bytes crudos
//! del fuzzer es morir en esa puerta y no llegar nunca a la decapsulación, que es
//! justo lo que este objetivo existe para castigar. Así que se traduce la entrada
//! al alfabeto (dominio del blob) y, además, si es UTF-8 se pasa cruda (dominio
//! del texto).
//!
//! La pasada del blob es la que pone a este objetivo a hablar el mismo idioma de
//! entrada que `parse_container` y `unpad`, y por tanto la que hace que compartir
//! corpus entre ellos sirva de algo. Ver `fuzz/README.md`.

use libfuzzer_sys::fuzz_target;
use quipu::{api, codec, dictionaries, pqhybrid};

fuzz_target!(|data: &[u8]| {
    let dict = dictionaries::flagship();
    // Clave secreta FIJA y derivada de bytes constantes: lo que se fuzzea es el
    // contenedor, no la clave. Si no parsea se CAE, no se sale de puntillas: aquí
    // había un `return` silencioso, y en el objetivo hermano esa misma forma dejó
    // el cuerpo sin ejecutar durante días con el CI en verde. Un objetivo de fuzz
    // que no fuzzea tiene que doler.
    let sk_bytes = [0x37u8; pqhybrid::SECRET_KEY_LEN];
    let Some(sk) = pqhybrid::SecretKey::from_bytes(&sk_bytes) else {
        panic!("la clave secreta híbrida constante debe parsear");
    };

    // (1) Dominio del blob: el parser recibe los bytes del fuzzer sin alterar.
    // Nunca pánico. Y nunca Ok: nadie cifró hacia esta clave.
    let indices = codec::encode_base_n(data, dict.base());
    if let Ok(simbolos) = dict.encode(&indices) {
        assert!(
            api::decode_as_recipient(&simbolos, &sk, &dict).is_err(),
            "un contenedor arbitrario se abrió con una clave que no lo cifró"
        );
    }

    // (2) Dominio del texto: el decodificador del alfabeto contra bytes hostiles.
    if let Ok(s) = std::str::from_utf8(data) {
        assert!(
            api::decode_as_recipient(s, &sk, &dict).is_err(),
            "un contenedor arbitrario se abrió con una clave que no lo cifró"
        );
    }
});
