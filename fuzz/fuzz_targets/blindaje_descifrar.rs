#![no_main]
//! Fuzz de `blindaje::descifrar`: bytes hostiles nunca deben provocar pánico.
//!
//! # Por qué faltaba, y por qué importa
//!
//! Era el ÚNICO parser de bytes hostiles del repositorio sin objetivo de fuzz.
//! Lo señaló el crítico de completitud de la revisión del 2026-08-17, y es un
//! hueco de los que no se ven: `parse_container`, `parse_recipient`,
//! `parse_signed`, `unpad` y `honey_decrypt` sí lo tenían, así que la ausencia
//! parecía cobertura.
//!
//! `descifrar` tiene exactamente la forma que el fuzz caza mejor: un largo
//! DECLARADO por quien manda el blob (`largo_c1`, 4 bytes en claro y sin
//! autenticar), un `split_at` que depende de él, un `checked_sub` y una
//! comparación de longitudes. Su propio código lleva escrito un comentario sobre
//! el desbordamiento en objetivos de 32 bits — o sea que la clase de fallo está
//! identificada y nadie la estaba ejercitando.
//!
//! # Qué se afirma aquí, exactamente
//!
//! Solo esto: **ninguna entrada provoca un pánico**. No se afirma nada sobre el
//! valor devuelto — para un blob arbitrario, `Err` es lo correcto y `Ok` es
//! imposible sin la clave. Los tres caminos de `Formato`, el de `OtraVersion` y
//! el de `NoAutentica` son todos resultados legítimos.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Una maestra fija: lo que se fuzzea es el PARSER, no la criptografía. Con
    // una clave derivada del propio `data` el fuzzer gastaría su presupuesto en
    // variar la clave, que no cambia ningún camino de decisión antes del AEAD.
    let master = [0x5Au8; 32];

    // Sin datos asociados y con ellos: `aad_de_capa` concatena el `aad` del
    // llamante ANTES de la magia, así que un `aad` no vacío mueve el troceado de
    // la cadena y es un segundo camino que conviene ejercitar.
    let _ = quipu::blindaje::descifrar(&master, data, b"");
    let _ = quipu::blindaje::descifrar(&master, data, b"contexto");

    // Y EL CAMINO QUE DE VERDAD IMPORTA: un blob con la marca correcta. Sin
    // esto, el fuzzer casi nunca acierta los cuatro bytes de `QBL2` por azar y
    // se pasa el presupuesto entero rebotando en la primera línea de
    // `descifrar` — o sea, midiendo el chequeo de magia y nada más. Es el mismo
    // fallo que un banco de solo negativos: parece cobertura y no lo es.
    if data.len() >= 4 {
        let mut con_marca = data.to_vec();
        con_marca[..4].copy_from_slice(quipu::blindaje::MAGIA);
        let _ = quipu::blindaje::descifrar(&master, &con_marca, b"");
    }
});
