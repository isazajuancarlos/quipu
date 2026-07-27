// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Sondas de los invariantes del modelo de amenaza.
//!
//! `docs/ATAQUES_TAXONOMIA.md` clasifica los ataques en diez familias y, para
//! cada una, dice qué herramienta **existe** y cuál **falta**. Este archivo
//! implementa tres de las que faltaban. Son las tres que el propio documento
//! pone alto en su orden y que se pueden construir sin infraestructura nueva:
//!
//! | Familia | Lo que faltaba | Invariante |
//! |---|---|---|
//! | 4 · Oráculo | «verificador de uniformidad de errores que recorra cada punto de fallo» | I4 |
//! | 8 · Gestión de clave | «un chequeo de que la clave no aparece en logs/errores» | I3 |
//! | 3 · Ataques de fallo | «sonda que inyecte fallos en la firma y compruebe que el AND los absorbe» | I2 + I4 |
//!
//! El documento cierra con una condición que estas pruebas respetan: **cada
//! invariante necesita una prueba que DISCRIMINE**. Una que siempre diga
//! «seguro» no vale. Cada sonda de aquí se validó rompiendo a propósito lo que
//! vigila y comprobando que se pone roja; el commit lo deja escrito.

use quipu::api::{
    decode, decode_from_blob, decode_verified, encode, encode_signed, encode_to_blob, Options,
};
use quipu::dictionaries;
use quipu::kdf::KdfParams;
use quipu::pqsign;

fn baratos() -> Options<'static> {
    Options {
        pepper: b"",
        kdf_params: KdfParams {
            mem_kib: 64,
            iterations: 1,
            parallelism: 1,
        },
        codebook_id: 0,
    }
}

// ===========================================================================
// I4 — EL FALLO NO REVELA NADA
// ===========================================================================

/// Todo fallo que dependa del SECRETO tiene que dar el mismo error.
///
/// La distinción importa y no es un tecnicismo. Los errores de FORMATO —un
/// símbolo fuera del diccionario, una cabecera corta— ocurren **antes** de que
/// el secreto entre en juego, así que distinguirlos no filtra nada sobre él y
/// además es útil para quien integra. Lo que no puede discriminar es todo lo
/// que pasa DESPUÉS: si el error dijera «passphrase incorrecta» frente a «datos
/// alterados», el atacante sabría cuál de las dos cosas acertó, y eso convierte
/// una búsqueda de dos dimensiones en dos búsquedas de una.
///
/// Es el mismo defecto que ya apareció en el canal de glifos: los errores decían
/// en qué capa había fallado el intento. Se corrigió a mano; esto lo vigila en
/// continuo, que es lo que pedía la taxonomía.
///
/// LO QUE ESTA PRUEBA NO MIDE: el TIEMPO. Que dos caminos devuelvan el mismo
/// error no implica que tarden lo mismo, y el documento pide las dos cosas.
/// El tiempo es trabajo del distinguidor y de dudect, que viven tras la feature
/// `lab`; aquí se cubre el mensaje y el tipo, que es lo que se puede afirmar sin
/// instrumentación de medida.
#[test]
fn los_fallos_que_dependen_del_secreto_son_indistinguibles() {
    let opts = baratos();
    let datos = b"un secreto cualquiera, del tamano que sea";
    let clave = "la-passphrase-correcta";
    let blob = encode_to_blob(datos, clave, [0u8; 8], &opts);

    // Cada entrada es un ATAQUE DISTINTO sobre el mismo contenedor. Todos deben
    // ser indistinguibles entre sí para quien solo ve el error.
    let mut ataques: Vec<(&str, Vec<u8>, &str)> = Vec::new();
    ataques.push(("passphrase equivocada", blob.clone(), "otra-passphrase"));

    // Cabecera: la sal y el nonce entran como AAD, así que tocarlos rompe la
    // autenticación igual que tocar el cuerpo. Que el error sea el mismo es
    // justo lo que impide saber QUÉ se tocó.
    for (nombre, pos) in [
        ("sal alterada", 16),
        ("nonce alterado", 40),
        ("primer byte del cuerpo", 68),
    ] {
        let mut roto = blob.clone();
        roto[pos] ^= 0x01;
        ataques.push((nombre, roto, clave));
    }
    // El tag va al final: es el caso clásico del oráculo de padding.
    let mut tag_roto = blob.clone();
    let ultimo = tag_roto.len() - 1;
    tag_roto[ultimo] ^= 0x01;
    ataques.push(("tag alterado", tag_roto, clave));

    // Truncar el cuerpo sin tocar la cabecera.
    let mut truncado = blob.clone();
    truncado.truncate(blob.len() - 4);
    ataques.push(("cuerpo truncado", truncado, clave));

    let mut vistos: Vec<(String, String)> = Vec::new();
    for (nombre, datos_rotos, passphrase) in &ataques {
        match decode_from_blob(datos_rotos, passphrase, [0u8; 8], b"") {
            Ok(_) => panic!("«{nombre}» NO debería descifrar"),
            Err(e) => vistos.push((nombre.to_string(), format!("{e:?}"))),
        }
    }

    let distintos: std::collections::BTreeSet<&String> = vistos.iter().map(|(_, e)| e).collect();
    assert_eq!(
        distintos.len(),
        1,
        "los fallos que dependen del secreto DISCRIMINAN la causa — es un oráculo:\n{}",
        vistos
            .iter()
            .map(|(n, e)| format!("  {n:<24} -> {e}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert_eq!(
        vistos[0].1, "Decrypt",
        "el error uniforme debería ser `Decrypt`, y es {}",
        vistos[0].1
    );
    assert!(
        ataques.len() >= 6,
        "solo {} caminos de fallo: el banco no recorre bastante",
        ataques.len()
    );
}

/// Y el canal de símbolos se comporta igual que el binario.
///
/// Va aparte porque `decode` añade una capa —el diccionario— antes de llegar al
/// contenedor, y esa capa SÍ puede devolver un error propio. Lo que se exige
/// aquí es que, una vez pasada, no reaparezca la discriminación.
#[test]
fn el_canal_de_simbolos_no_reintroduce_el_oraculo() {
    let opts = baratos();
    let dict = dictionaries::flagship();
    let simbolos = encode(b"mensaje de prueba", "clave-buena", &dict, &opts);

    let mut errores = std::collections::BTreeSet::new();
    // Passphrase equivocada.
    errores.insert(format!(
        "{:?}",
        decode(&simbolos, "clave-mala", &dict, b"").unwrap_err()
    ));
    // Pepper equivocado, con la passphrase BUENA: el atacante no debe poder
    // separar «fallé la clave» de «fallé el pepper».
    errores.insert(format!(
        "{:?}",
        decode(&simbolos, "clave-buena", &dict, b"pepper-que-no-es").unwrap_err()
    ));

    assert_eq!(
        errores.len(),
        1,
        "fallar la passphrase y fallar el pepper dan errores DISTINTOS: {errores:?}"
    );
}

// ===========================================================================
// I3 — LA CLAVE NO SE ESCAPA POR UN ERROR
// ===========================================================================

/// Ningún error puede llevar dentro material sensible.
///
/// La taxonomía lo pide en la familia 8 —«un chequeo de que la clave no aparece
/// en logs/errores»— y engancha con una regla que este proyecto tiene escrita
/// aparte: los secretos nunca aparecen en la salida.
///
/// Por qué es un riesgo real y no teórico: un `Debug` derivado imprime los
/// campos de la estructura. Basta con que alguien añada la passphrase o la
/// subclave a un error «para depurar mejor» y esa cadena acaba en un log, en un
/// informe de fallo o en la consola de un cliente. El material no se filtra por
/// criptoanálisis; se filtra por comodidad.
#[test]
fn ningun_error_lleva_dentro_el_secreto() {
    let opts = baratos();
    let dict = dictionaries::flagship();

    // Cadenas RECONOCIBLES: si aparecen en un error, se ven a simple vista.
    let clave = "PASSPHRASE-SECRETA-QUE-NO-DEBE-SALIR";
    let pepper = b"PEPPER-SECRETO-QUE-TAMPOCO";
    let datos = b"CONTENIDO-EN-CLARO-QUE-MENOS-AUN";

    let opts_con_pepper = Options {
        pepper,
        ..opts
    };
    let simbolos = encode(datos, clave, &dict, &opts_con_pepper);
    let blob = encode_to_blob(datos, clave, [0u8; 8], &opts_con_pepper);

    let mut textos = Vec::new();
    // Todos los caminos de fallo que se pueden provocar desde fuera.
    textos.push(format!("{:?}", decode(&simbolos, "otra", &dict, b"").unwrap_err()));
    textos.push(format!(
        "{:?}",
        decode(&simbolos, clave, &dict, b"pepper-malo").unwrap_err()
    ));
    textos.push(format!(
        "{:?}",
        decode("§§§ simbolos que no existen §§§", clave, &dict, pepper).unwrap_err()
    ));
    textos.push(format!(
        "{:?}",
        decode_from_blob(&blob[..10], clave, [0u8; 8], pepper).unwrap_err()
    ));
    textos.push(format!(
        "{:?}",
        decode_from_blob(&blob, clave, [9u8; 8], pepper).unwrap_err()
    ));

    let agujas: [(&str, &[u8]); 3] = [
        ("la passphrase", clave.as_bytes()),
        ("el pepper", pepper),
        ("el texto en claro", datos),
    ];
    let mut fugas = Vec::new();
    for texto in &textos {
        for (nombre, aguja) in &agujas {
            let s = String::from_utf8_lossy(aguja);
            if texto.contains(s.as_ref()) {
                fugas.push(format!("{nombre} aparece en: {texto}"));
            }
        }
    }
    assert!(
        fugas.is_empty(),
        "hay material sensible dentro de un error:\n  {}",
        fugas.join("\n  ")
    );
    assert!(textos.len() >= 5, "el banco solo miró {} errores", textos.len());
}

// ===========================================================================
// I2 + I4 — EL COMBINADOR AND ABSORBE EL FALLO INYECTADO
// ===========================================================================

/// Romper UNA mitad de la firma híbrida tiene que invalidarla entera.
///
/// La taxonomía lo pide en la familia 3: «una sonda de lab que inyecte fallos en
/// la firma y compruebe que el combinador AND los absorbe — probar que la
/// defensa estructural discrimina, no asumirlo».
///
/// La defensa: la firma es Ed25519 ∧ ML-DSA-87, y verificar exige que validen
/// LAS DOS. Contra un ataque de fallo —un glitch de voltaje, un bit volteado por
/// Rowhammer— eso convierte lo que en un esquema simple sería una FILTRACIÓN en
/// un simple «no verifica»: hay que fallar las dos mitades a la vez, con dos
/// matemáticas distintas, para producir algo que pase.
///
/// Se inyecta el fallo en cada mitad por separado, y en varias posiciones de
/// cada una, porque un solo byte podría caer en una zona que el decodificador
/// rechace por formato antes de llegar a la verificación — eso probaría el
/// parser, no el combinador.
#[test]
fn un_fallo_en_una_sola_mitad_invalida_la_firma_entera() {
    let dict = dictionaries::flagship();
    let (vk, sk) = pqsign::generate_keypair();
    let mensaje = b"orden que alguien querria falsificar";
    let firmado = encode_signed(mensaje, &sk, &dict);

    // Control: sin tocar nada, verifica.
    assert_eq!(
        decode_verified(&firmado, &vk, &dict).expect("la firma intacta debe verificar"),
        mensaje,
        "el control falló: la prueba no mediría nada"
    );

    // El artefacto es texto de símbolos, así que se ataca sobre los BYTES de la
    // firma: se rehace el contenedor firmado a partir de la firma cruda.
    let firma = sk.sign(mensaje);
    assert_eq!(firma.len(), pqsign::SIGNATURE_LEN, "cambió el formato de la firma");

    let mut absorbidos = 0usize;
    let mut colados = Vec::new();
    // Ed25519 ocupa los primeros 64 bytes; ML-DSA-87, el resto.
    let posiciones: [(&str, usize); 6] = [
        ("Ed25519, primer byte", 0),
        ("Ed25519, medio", pqsign::ED25519_SIG_LEN / 2),
        ("Ed25519, último byte", pqsign::ED25519_SIG_LEN - 1),
        ("ML-DSA, primer byte", pqsign::ED25519_SIG_LEN),
        ("ML-DSA, medio", pqsign::ED25519_SIG_LEN + pqsign::MLDSA_SIG_LEN / 2),
        ("ML-DSA, último byte", pqsign::SIGNATURE_LEN - 1),
    ];
    for (nombre, pos) in posiciones {
        let mut rota = firma.clone();
        rota[pos] ^= 0x01;
        if vk.verify(mensaje, &rota) {
            colados.push(nombre);
        } else {
            absorbidos += 1;
        }
    }

    assert!(
        colados.is_empty(),
        "el combinador AND NO absorbió el fallo en: {colados:?} — una firma con \
         una mitad rota verificó, así que la defensa estructural no está"
    );
    assert_eq!(absorbidos, 6, "se esperaban 6 fallos absorbidos, hubo {absorbidos}");
}

/// Y una mitad válida con la otra AUSENTE tampoco pasa.
///
/// Es el caso degenerado del anterior y merece su propia comprobación: un
/// atacante que consiga la mitad Ed25519 correcta —la curva que caerá primero
/// ante un ordenador cuántico— no debe poder presentar solo esa.
#[test]
fn media_firma_valida_no_autoriza_nada() {
    let (vk, sk) = pqsign::generate_keypair();
    let mensaje = b"lo mismo, con media firma";
    let firma = sk.sign(mensaje);

    // Solo la mitad clásica, rellenando la post-cuántica con ceros.
    let mut solo_ed = firma[..pqsign::ED25519_SIG_LEN].to_vec();
    solo_ed.resize(pqsign::SIGNATURE_LEN, 0);
    assert!(
        !vk.verify(mensaje, &solo_ed),
        "una firma con SOLO la mitad Ed25519 verificó: el AND no se está aplicando"
    );

    // Y solo la post-cuántica.
    let mut solo_ml = vec![0u8; pqsign::ED25519_SIG_LEN];
    solo_ml.extend_from_slice(&firma[pqsign::ED25519_SIG_LEN..]);
    assert!(
        !vk.verify(mensaje, &solo_ml),
        "una firma con SOLO la mitad ML-DSA verificó: el AND no se está aplicando"
    );
}
