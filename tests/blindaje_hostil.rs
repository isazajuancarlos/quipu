// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

//! `blindaje::descifrar` contra bytes hostiles: **ninguna entrada puede provocar
//! un pánico**.
//!
//! # Por qué existe, y por qué NO es un objetivo de fuzz
//!
//! `descifrar` era el ÚNICO parser de bytes hostiles del repositorio sin
//! cobertura de este tipo —lo señaló la revisión del 2026-08-17—, y tiene
//! exactamente la forma que estos bancos cazan mejor: un largo **declarado por
//! quien manda el blob** (`largo_c1`, cuatro bytes en claro y sin autenticar), un
//! `split_at` que depende de él, un `checked_sub` y una comparación de
//! longitudes. Su propio código lleva un comentario sobre el desbordamiento en
//! objetivos de 32 bits, o sea que la clase de fallo estaba identificada y nadie
//! la ejercitaba.
//!
//! Se escribió el objetivo de fuzz (`fuzz/fuzz_targets/blindaje_descifrar.rs`).
//!
//! **ESTE PÁRRAFO DECÍA QUE NO SE PODÍA CORRER, Y LLEVA SIENDO FALSO DESDE EL
//! 2026-08-17**: decía que `libfuzzer-sys` no estaba vendorizado y que por eso
//! el arnés entero estaba muerto. Se vendorizó ese mismo día, y hoy
//! `cargo check --offline --all-targets` dentro de `fuzz/` sale en **0 con los
//! SIETE objetivos** —siete, no seis—; `fuzz/` no necesita su propio
//! `.cargo/config.toml` porque cargo hereda el de la raíz al subir por los
//! directorios padre.
//!
//! Se corrige porque un comentario caducado no es inofensivo: una auditoría
//! independiente del 2026-08-17 lo leyó, dio por muerto el arnés, y abrió su
//! informe declarando que «lo cubre el fuzz» no valía como respuesta en ningún
//! sitio. Un documento equivocado no solo no informa: desinforma a quien viene
//! a comprobar.
//!
//! Entretanto, esto: `proptest` ya es dependencia de desarrollo, corre dentro de
//! `cargo test` y por tanto dentro de `verificar.py`. **Un banco que vive en la
//! suite no se puede olvidar**; uno que necesita un ritual aparte se muere en
//! silencio, que es justo lo que le pasó al de fuzz.
//!
//! # Qué se afirma, exactamente
//!
//! Solo que no hay pánico. No se afirma nada sobre el valor devuelto: para un
//! blob arbitrario, `Err` es lo correcto y `Ok` es imposible sin la clave.
//! `Formato`, `OtraVersion` y `NoAutentica` son los tres resultados legítimos.

#![cfg(feature = "blindaje")]

use proptest::prelude::*;
use quipu::blindaje::{self, ID_LEN, MAGIA};

/// Maestra fija: lo que se ejercita es el PARSER, no la criptografía. Con una
/// clave derivada de la entrada, el generador gastaría su presupuesto variando
/// algo que no cambia ningún camino de decisión antes del AEAD.
const MAESTRA: [u8; 32] = [0x5A; 32];

/// Cabecera de `QBL2`: magia 4 + id 16 + largo 4.
const CABECERA: usize = 4 + ID_LEN + 4;

proptest! {
    /// Bytes arbitrarios. Es el caso barato y el que menos encuentra: casi nunca
    /// acierta la magia, así que la mayoría muere en la primera línea.
    #[test]
    fn bytes_arbitrarios_no_provocan_panico(datos in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = blindaje::descifrar(&MAESTRA, &datos, b"");
        let _ = blindaje::descifrar(&MAESTRA, &datos, b"contexto");
    }

    /// **CON LA MARCA PUESTA**, que es donde de verdad hay parser. Sin esto el
    /// banco mediría el chequeo de magia y nada más — el mismo defecto que un
    /// banco de solo negativos: parece cobertura y no lo es.
    #[test]
    fn con_la_marca_correcta_no_hay_panico(cuerpo in prop::collection::vec(any::<u8>(), 0..2048)) {
        let mut blob = Vec::with_capacity(4 + cuerpo.len());
        blob.extend_from_slice(MAGIA);
        blob.extend_from_slice(&cuerpo);
        let _ = blindaje::descifrar(&MAESTRA, &blob, b"");
    }

    /// **EL LARGO DECLARADO, BARRIDO A PROPÓSITO.** `largo_c1` lo elige quien
    /// manda el blob y llega hasta `u32::MAX`; de él dependen el `checked_sub`,
    /// el `split_at` y la comparación de mitades. Es el campo que motiva todo
    /// este archivo, y un generador uniforme sobre bytes casi nunca produce los
    /// valores interesantes: aquí se construyen.
    #[test]
    fn cualquier_largo_declarado_no_provoca_panico(
        largo in prop::strategy::Union::new_weighted(vec![
            // Los valores de frontera pesan más que el azar uniforme: son los
            // que rompen, y un `u32` uniforme casi nunca cae en ellos.
            (3, prop::sample::select(vec![
                0u32, 1, 15, 16, 17, 31, 32, 33,
                0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFE, u32::MAX,
            ]).boxed()),
            (1, any::<u32>().boxed()),
        ]),
        cuerpo in prop::collection::vec(any::<u8>(), 0..512),
        id in prop::array::uniform16(any::<u8>()),
    ) {
        let mut blob = Vec::with_capacity(CABECERA + cuerpo.len());
        blob.extend_from_slice(MAGIA);
        blob.extend_from_slice(&id);
        blob.extend_from_slice(&largo.to_be_bytes());
        blob.extend_from_slice(&cuerpo);
        let _ = blindaje::descifrar(&MAESTRA, &blob, b"");
    }

    /// **BLOBS CASI VÁLIDOS**: se parte de uno real y se le tocan bytes. Es lo
    /// que llega más lejos dentro de la función —pasa el marco, llega a los dos
    /// AEAD— y ninguna de las otras estrategias lo alcanza por azar.
    #[test]
    fn un_blob_real_con_bytes_tocados_no_provoca_panico(
        claro in prop::collection::vec(any::<u8>(), 0..300),
        cortes in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 0..8),
        recorte in 0usize..64,
    ) {
        let mut blob = blindaje::cifrar(&MAESTRA, &claro, b"").expect("hay entropía");
        for (donde, valor) in cortes {
            if !blob.is_empty() {
                let i = donde.index(blob.len());
                blob[i] ^= valor;
            }
        }
        blob.truncate(blob.len().saturating_sub(recorte));
        let _ = blindaje::descifrar(&MAESTRA, &blob, b"");
    }
}

/// CONTROL DEL BANCO: el camino bueno sigue abriendo.
///
/// Sin él, todo lo de arriba se cumpliría con un `descifrar` que devolviera
/// `Err` sin mirar nada — «no hay pánico» es una afirmación que un cascarón vacío
/// cumple de sobra. Aquí es donde se comprueba que hay una función debajo.
#[test]
fn el_control_el_camino_bueno_sigue_abriendo() {
    let claro = b"documento de control".to_vec();
    let blob = blindaje::cifrar(&MAESTRA, &claro, b"aad").expect("hay entropía");
    assert_eq!(
        blindaje::descifrar(&MAESTRA, &blob, b"aad"),
        Ok(claro),
        "el control: si esto no abre, los «no hay pánico» de arriba no valen nada"
    );
}
