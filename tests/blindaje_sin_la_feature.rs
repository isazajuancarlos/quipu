// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

//! La mitad que SOLO existe cuando `blindaje` NO está compilado.
//!
//! Es el caso que nadie prueba y que le va a pasar a alguien: un binario del
//! producto por defecto encontrándose un contenedor blindado. Tiene que
//! negarse DICIENDO POR QUÉ, no fallar como si la passphrase estuviera mal —
//! ese error manda a quien lo lea media hora a buscar una contraseña correcta.

#![cfg(not(feature = "blindaje"))]

use quipu::api::{self, DecodeError, Options};
use quipu::container;
use quipu::dictionaries;
use quipu::dictionary::HuellaDeCodebook;

#[test]
fn un_contenedor_blindado_se_rechaza_diciendo_que_falta_la_feature() {
    let d = dictionaries::ascii94();
    let huella = d.fingerprint();
    let opts = Options {
        kdf_params: quipu::kdf::KdfParams::LIGERO,
        ..Default::default()
    };

    let mut blob = api::encode_to_blob(b"mensaje", "clave-de-prueba-larga", huella, &opts);

    // CONTROL: intacto, este binario lo abre. Sin esto, la aserción de abajo
    // pasaría igual con un blob corrupto por cualquier otro motivo.
    assert_eq!(
        api::decode_from_blob(&blob, "clave-de-prueba-larga", huella, b"").expect("abre"),
        b"mensaje"
    );

    // Se le marca el bit de reparto ciego. El contenido NO lo es —no se puede
    // fabricar sin la feature— pero eso da igual: el rechazo tiene que ocurrir
    // al LEER EL FLAG, antes de tocar el contenido.
    blob[5] = container::FLAG_BLINDAJE;

    // El error NO lleva texto, y es a propósito: dieciséis bytes de más en este
    // enum empujan la clave de contenido fuera del alcance del limpiador de
    // pila. Ver `DecodeError::ModoNoCompilado`.
    match api::decode_from_blob(&blob, "clave-de-prueba-larga", huella, b"") {
        Err(DecodeError::ModoNoCompilado) => {}
        otro => panic!(
            "sin la feature, un contenedor blindado tiene que decir ModoNoCompilado \
             y no {otro:?} — que manda a buscar una passphrase equivocada"
        ),
    }
}

/// Y el flag sigue siendo aceptable para el CONTENEDOR aunque el modo no esté
/// compilado: el rechazo es de `api`, no del parseo. Si lo rechazara el parseo,
/// el mensaje sería `FlagsDesconocidos` y diría lo que no es —el bit sí se
/// conoce en esta versión, lo que falta es el código que lo implementa—.
#[test]
fn el_contenedor_parsea_el_flag_aunque_el_modo_no_este_compilado() {
    let d = dictionaries::ascii94();
    let opts = Options {
        kdf_params: quipu::kdf::KdfParams::LIGERO,
        ..Default::default()
    };
    let mut blob = api::encode_to_blob(b"x", "clave-de-prueba-larga", d.fingerprint(), &opts);
    blob[5] = container::FLAG_BLINDAJE;

    let (h, _) = container::parse(&blob).expect("el bit es conocido: tiene que parsear");
    assert_eq!(h.flags, container::FLAG_BLINDAJE);
}
