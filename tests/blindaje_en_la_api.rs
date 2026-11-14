// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

//! El reparto ciego a través de `api::`, que es como lo usa quien integra.
//!
//! Las pruebas del módulo miden la primitiva; éstas miden el CONTENEDOR: que el
//! flag viaje, que `decode` reconozca el modo sola, que un binario que no lo
//! tiene compilado se niegue diciéndolo, y que el modo normal no se haya movido
//! ni un byte por el camino.

#![cfg(feature = "blindaje")]

use quipu::api::{self, DecodeError, Options};
use quipu::container;
use quipu::dictionaries;
use quipu::dictionary::HuellaDeCodebook;

fn dict() -> quipu::dictionary::Dictionary {
    dictionaries::ascii94()
}

fn opts<'a>() -> Options<'a> {
    Options {
        kdf_params: quipu::kdf::KdfParams::LIGERO,
        ..Default::default()
    }
}

#[test]
fn ida_y_vuelta_por_la_api() {
    let d = dict();
    for datos in [&b""[..], b"secreto", &[0u8; 1024][..]] {
        let simbolos = api::encode_blindado(datos, "contraseña larga y buena", &d, &opts());
        let vuelta = api::decode(&simbolos, "contraseña larga y buena", &d, b"")
            .expect("tiene que abrir");
        assert_eq!(vuelta, datos, "con {} bytes", datos.len());
    }
}

/// **`decode` reconoce el modo sola.** No hay `decode_blindado`: el artefacto
/// declara cómo se escribió. Es la propiedad que hace que esto sirva para datos
/// guardados — quien los abra dentro de dos años no tiene que acordarse.
#[test]
fn la_misma_decode_abre_los_dos_modos() {
    let d = dict();
    let normal = api::encode(b"mensaje", "clave-de-prueba-larga", &d, &opts());
    let blindado = api::encode_blindado(b"mensaje", "clave-de-prueba-larga", &d, &opts());
    assert_ne!(normal, blindado, "los dos modos no pueden dar lo mismo");

    for (nombre, simbolos) in [("normal", &normal), ("blindado", &blindado)] {
        assert_eq!(
            api::decode(simbolos, "clave-de-prueba-larga", &d, b"").expect(nombre),
            b"mensaje",
            "la misma decode tiene que abrir el modo {nombre}"
        );
    }
}

/// El flag viaja en la cabecera, y solo en el modo que lo pide.
#[test]
fn el_flag_llega_al_contenedor_y_solo_en_su_modo() {
    let huella = dict().fingerprint();
    let normal = api::encode_to_blob(b"x", "clave-de-prueba-larga", huella, &opts());
    let blindado = api::encode_to_blob_blindado(b"x", "clave-de-prueba-larga", huella, &opts());

    let (h_normal, _) = container::parse(&normal).expect("parsea");
    let (h_blindado, cuerpo) = container::parse(&blindado).expect("parsea");

    assert_eq!(h_normal.flags, 0, "el modo normal no puede marcar nada");
    assert_eq!(h_blindado.flags, container::FLAG_BLINDAJE);
    assert_eq!(&cuerpo[..4], b"QBL2", "dentro tiene que ir un blob QBL2");
}

/// **La cabecera es AAD, así que mentir sobre el modo NO pasa desapercibido.**
///
/// Es la razón por la que el modo puede ir en claro: quien le cambie el bit a un
/// contenedor ya escrito rompe la autenticación de las dos capas.
#[test]
fn cambiarle_el_flag_a_un_contenedor_lo_tumba() {
    let huella = dict().fingerprint();
    let mut blob = api::encode_to_blob_blindado(b"x", "clave-de-prueba-larga", huella, &opts());
    // Control: intacto, abre.
    assert!(api::decode_from_blob(&blob, "clave-de-prueba-larga", huella, b"").is_ok());

    blob[5] = 0; // «esto no es un reparto ciego»
    assert_eq!(
        api::decode_from_blob(&blob, "clave-de-prueba-larga", huella, b""),
        Err(DecodeError::Decrypt),
        "quitarle el flag tiene que romper la autenticación"
    );
}

/// **El precio, en la unidad que se ve.** El camino simbólico da ~2× de glifos.
/// Se fija aquí para que nadie lo descubra en producción.
#[test]
fn el_modo_blindado_cuesta_el_doble_de_simbolos() {
    let d = dict();
    let datos = [7u8; 1024];
    let normal = api::encode(&datos, "clave-de-prueba-larga", &d, &opts()).chars().count();
    let blindado = api::encode_blindado(&datos, "clave-de-prueba-larga", &d, &opts())
        .chars()
        .count();
    let razon = blindado as f64 / normal as f64;
    assert!(
        (1.9..2.1).contains(&razon),
        "el blindado da {blindado} glifos frente a {normal}: ×{razon:.2}"
    );
}

/// El modo normal no se movió NI UN BYTE al añadir el otro. Es lo que convierte
/// este cambio en aditivo: los contenedores que ya existen se siguen abriendo.
#[test]
fn el_modo_normal_sigue_siendo_el_de_siempre() {
    let d = dict();
    let huella = d.fingerprint();
    let blob = api::encode_to_blob(b"lo de siempre", "clave-de-prueba-larga", huella, &opts());
    let (h, _) = container::parse(&blob).expect("parsea");
    assert_eq!(h.flags, 0);
    assert_eq!(h.version, container::VERSION);
    assert_eq!(
        api::decode_from_blob(&blob, "clave-de-prueba-larga", huella, b"").expect("abre"),
        b"lo de siempre"
    );
}

// === LO QUE NO MEDÍA NADIE ====================================================
//
// El banco de mutación del 2026-08-17 aplicó 64 mutantes y encontró que **el
// rasgo `BlindajeDeOtraVersion` entero no tenía una sola prueba**: borrar el
// `return` de `api.rs`, invertirlo a `Formato` o ponerlo en `is_err()` dejaban
// las 235 pruebas en verde. `grep BlindajeDeOtraVersion` daba cinco apariciones
// y ninguna era una aserción.
//
// Es el rasgo que costó dos rondas de revisión —una para crearlo y otra para
// corregir a qué error respondía—, o sea que el esfuerzo se había ido entero en
// razonar sobre algo que nada sujetaba.

/// **UN CONTENEDOR DE OTRA VERSIÓN SE ANUNCIA; UNO FORJADO, NO.** Y la segunda
/// mitad es la que costó dos rondas.
///
/// El diagnóstico «esto es de otra versión» miraba tres bytes de una marca que
/// viaja EN CLARO y que no cubre ningún AEAD: la revisión adversaria del
/// 2026-08-17 lo forzó con **un byte**, escribiendo `QBL1` encima de un `QBL2`,
/// con la contraseña correcta y con la equivocada. O sea que el mensaje que ve la
/// víctima —«no es la contraseña, es el formato», que la manda a buscar una
/// versión vieja del programa en vez de a sospechar— lo elegía quien tocó el
/// archivo.
///
/// Se dio por imposible de cerrar con este argumento: *la versión dice cómo
/// autenticar, así que hay que leerla antes de autenticar*. Cierto, y la
/// conclusión no se sigue: **no hace falta autenticarla antes, basta no
/// afirmarla hasta después**. Hoy el módulo intenta abrir el blob bajo la
/// versión que dice ser y solo concede el diagnóstico si las dos capas
/// AUTENTICAN. Un atacante no puede conseguir eso sin la clave.
///
/// El vector de abajo es un contenedor `QBL1` **auténtico**, producido por el
/// código de `db1392c` —la versión que lo escribía— en un worktree de ese
/// commit. No está fabricado: es el artefacto real de la versión anterior, que
/// es lo único que prueba de verdad este camino.
#[test]
fn un_blindaje_de_otra_version_se_anuncia_y_uno_forjado_no() {
    let huella = dict().fingerprint();
    let frase = "clave-de-prueba-larga";

    // (a) EL AUTÉNTICO: un `QBL1` de verdad, y se anuncia como tal.
    let hex_v1 = "515549500101000049f8b11875475bdf84b98a316d16fc3a6922636ed9da9dafc8f919d56b\
               304837f67178706872b9c68f6d57b11a6f2b8300004000000000030000000151424c31be56\
               f575779059401be724f833f2be5a0000002e809edf1748ca735d01f4b3f404f31f62aece17\
               450093cc0a5f211bd120c0085bec2c548d36edea88d61c7a7b3f086bf83c49f92a13071f39\
               dd37f3b8d22e440f61d3918135d39c93b3b369255e9aade9ab6de28d915c093574a70962";
    let limpio: String = hex_v1.chars().filter(|c| !c.is_whitespace()).collect();
    let v1: Vec<u8> = (0..limpio.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&limpio[i..i + 2], 16).expect("hex válido"))
        .collect();
    assert_eq!(
        api::decode_from_blob(&v1, frase, huella, b""),
        Err(DecodeError::BlindajeDeOtraVersion),
        "un contenedor QBL1 auténtico tiene que anunciarse como de otra versión"
    );

    // (b) EL FORJADO: un `QBL2` con la marca cambiada a `QBL1`. **No autentica
    // bajo esa versión**, así que NO puede llevarse el diagnóstico. Ésta es la
    // propiedad que el arreglo compra, y sin ella (a) se cumpliría igual con la
    // versión vulnerable.
    let bueno = api::encode_to_blob_blindado(b"x", frase, huella, &opts());
    assert!(
        api::decode_from_blob(&bueno, frase, huella, b"").is_ok(),
        "el control: un contenedor intacto tiene que abrir"
    );
    let i = bueno
        .windows(4)
        .position(|w| w == b"QBL2")
        .expect("el cuerpo lleva la marca QBL2");
    let mut forjado = bueno.clone();
    forjado[i + 3] = b'1';
    assert_eq!(
        api::decode_from_blob(&forjado, frase, huella, b""),
        Err(DecodeError::Decrypt),
        "una marca QBL1 escrita encima de un QBL2 NO autentica bajo la v1: no puede \
         anunciarse como «otra versión», que es el diagnóstico que desorienta"
    );

    // (c) El marco manipulado tampoco.
    let mut tocado = bueno.clone();
    tocado[i + 4 + 16] ^= 0x01;
    assert_eq!(
        api::decode_from_blob(&tocado, frase, huella, b""),
        Err(DecodeError::Decrypt),
        "un largo manipulado NO puede anunciarse como «otra versión»"
    );

    // (d) La contraseña equivocada tampoco. Ojo: contra el contenedor AUTÉNTICO
    // de la v1, porque con otra clave la v1 tampoco autentica y el diagnóstico
    // tiene que caer a `Decrypt`.
    assert_eq!(
        api::decode_from_blob(&v1, "otra-clave-de-prueba-larga", huella, b""),
        Err(DecodeError::Decrypt),
        "sin la clave correcta ni siquiera se puede afirmar de qué versión es"
    );

    // (e) Y una marca que comparte prefijo pero no es de la familia.
    let mut casi = bueno;
    casi[i..i + 4].copy_from_slice(b"QBX2");
    assert_eq!(
        api::decode_from_blob(&casi, frase, huella, b""),
        Err(DecodeError::Decrypt)
    );
}

/// **LOS DOS MODOS DERIVAN MATERIAL DISTINTO, medido sobre el ARTEFACTO.**
///
/// Ya existía una prueba con este objetivo en `src/api.rs`, escrita justo
/// porque un mutante había sobrevivido… y el banco de mutación encontró que
/// comprueba las CONSTANTES (`CIPHER_SUBKEY_INFO != BLINDAJE_SUBKEY_INFO`) y no
/// los SITIOS DE USO: cambiando **los dos** sitios a la vez para que el modo
/// blindado derive con la etiqueta del normal, las constantes siguen siendo
/// distintas y las 235 pruebas siguen verdes. La propiedad desaparecía con su
/// propia prueba en verde.
///
/// Ésta mira lo que sale: el mismo dato, la misma frase y la misma sal en los
/// dos modos tienen que producir cuerpos que no se abran cruzados.
#[test]
fn los_dos_modos_no_comparten_material_en_el_artefacto() {
    let huella = dict().fingerprint();
    let frase = "clave-de-prueba-larga";
    let datos = b"el mismo dato en los dos modos";

    let normal = api::encode_to_blob(datos, frase, huella, &opts());
    let blindado = api::encode_to_blob_blindado(datos, frase, huella, &opts());

    // CONTROL: cada uno abre por su lado, y con el mismo contenido.
    assert_eq!(
        api::decode_from_blob(&normal, frase, huella, b"").expect("el normal abre"),
        datos
    );
    assert_eq!(
        api::decode_from_blob(&blindado, frase, huella, b"").expect("el blindado abre"),
        datos
    );

    // LO QUE SE EXIGE: los cuerpos no coinciden. Si los dos modos derivaran con
    // la misma etiqueta, el material sería el mismo y el cuerpo del blindado
    // sería función directa del mismo secreto que abre el normal.
    let cuerpo = |b: &[u8]| b[b.len().saturating_sub(32)..].to_vec();
    assert_ne!(
        cuerpo(&normal),
        cuerpo(&blindado),
        "los dos modos produjeron el mismo material: comparten subclave"
    );
}

/// **UN CONTENEDOR BLINDADO GUARDADO SIGUE ABRIENDO**, y era el hueco de fondo.
///
/// El banco de mutación del 2026-08-17 lo dijo con esas palabras: «no hay ni un
/// vector congelado a nivel de `api` para el modo blindado, y ese hueco es lo
/// que deja pasar varios mutantes». El de más peso: cambiar **los dos sitios de
/// uso** para que el modo blindado derive su subclave con la etiqueta del modo
/// normal. Las constantes siguen siendo distintas —así que la prueba que existía
/// para eso, que las compara a ellas, sigue verde— y lo que cambia es a cuál se
/// llama. La propiedad desaparecía con su propia prueba en verde.
///
/// Un artefacto congelado no se puede engañar así: se escribió con una etiqueta
/// concreta y solo abre con ésa. Y no depende del camino de CIFRADO —si mañana
/// se reescribe `encode_to_blob_blindado`, esta prueba sigue sujetando la
/// compatibilidad, que es lo que de verdad le importa a quien guardó un archivo.
#[test]
fn un_contenedor_blindado_guardado_sigue_abriendo() {
    let hex = "515549500101000049f8b11875475bdf3ff895d3ddf1cd8e2a9431660e19cea8dbff603692\
               f9769e60219a78593e9f3a582cda9454e59cb300004000000000030000000151424c32fe80\
               e6efecd3de604967057caf88334a0000002cf6f31d31a1f37af7e19e7fff2610a8906ce33f\
               603fbfacf60247684563c9ab62b78c743df0c45cc494e97f61b33a3a1ca0856a091c211b3a\
               e40ad68234d985e2f74cf0597d7f1295bbae7a2983d34877a9821ffb907e4ec9";
    let limpio: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    let blob: Vec<u8> = (0..limpio.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&limpio[i..i + 2], 16).expect("hex válido"))
        .collect();

    assert_eq!(
        api::decode_from_blob(&blob, "clave-de-prueba-larga", dict().fingerprint(), b""),
        Ok(b"quipu QBL2 congelado".to_vec()),
        "un contenedor blindado guardado dejó de abrirse: cambió la derivación, el \
         formato del cuerpo, o el relleno"
    );

    // CONTROL: con otra frase NO abre, o sea que lo de arriba no pasa porque
    // `decode` devuelva algo pase lo que pase.
    assert_eq!(
        api::decode_from_blob(&blob, "otra-clave-de-prueba-larga", dict().fingerprint(), b""),
        Err(DecodeError::Decrypt)
    );
}
