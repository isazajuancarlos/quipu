// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! El ciclo de custodia del seed, cerrado contra el BINARIO REAL.
//!
//! Las pruebas de `custodia` comprueban que reconstruir el seed deriva la misma
//! clave pública. Esto comprueba lo que de verdad importa el día de la
//! emergencia: que **el proceso levantado con el seed restaurado sirve esa
//! misma clave**.
//!
//! No es la misma pregunta. Entre `clave_publica_de` y lo que el servidor sirve
//! hay un `main.rs` que podría derivar de otra forma —otro `info`, otra
//! función— y entonces la unidad seguiría verde mientras la restauración real
//! deja fuera a todos los clientes. Que `DERIVE_INFO` sea una sola constante
//! compartida cierra media rendija; esta prueba cierra la otra media,
//! preguntándole al proceso de verdad.
//!
//! # Por qué se lee la salida y no se consulta el endpoint
//!
//! `GET /v1/public-key` responde exactamente `public_key_hex`, la MISMA
//! variable que el arranque imprime (`http.rs`: se calcula una vez y se usa en
//! los dos sitios). Leer la línea da la misma garantía sin meter un cliente
//! HTTP en una prueba que no va de HTTP — el primer intento lo llevaba y su
//! único efecto fue un 500 propio que no tenía nada que ver con el seed.
//!
//! Corre con `--features custodia`.
#![cfg(feature = "custodia")]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

use quipu_oprf_server::custodia::{clave_publica_de, repartir, verificar_restauracion, SEED_LEN};

fn a_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Seed determinista y evidentemente falso. Nunca uno real en el código.
fn seed_de_prueba() -> [u8; SEED_LEN] {
    let mut s = [0u8; SEED_LEN];
    for (i, b) in s.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(11).wrapping_add(5);
    }
    s
}

/// Arranca el binario con ese seed y devuelve la clave pública que anuncia
/// servir. Mata el proceso antes de volver.
fn clave_que_sirve_el_proceso(seed_hex: &str, etiqueta: &str) -> String {
    let bin = env!("CARGO_BIN_EXE_quipu-oprf-server");
    let dir = std::env::temp_dir().join(format!(
        "quipu-restaura-{}-{etiqueta}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("oprf.db");

    let salida = Command::new(bin)
        .arg("init")
        .env("QUIPU_OPRF_DB", &db)
        .env("QUIPU_OPRF_SEED", seed_hex)
        .output()
        .expect("init");
    assert!(salida.status.success(), "init falló: {salida:?}");

    // Puerto 0: el sistema asigna uno libre. Fijar un puerto haría que dos
    // pruebas en paralelo se pisaran, y ese fallo sería intermitente.
    let mut hijo = Command::new(bin)
        .arg("serve")
        .arg("127.0.0.1:0")
        .env("QUIPU_OPRF_DB", &db)
        .env("QUIPU_OPRF_SEED", seed_hex)
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("serve");

    let err = hijo.stderr.take().expect("stderr");
    let mut lector = BufReader::new(err);
    let mut encontrada = String::new();
    for _ in 0..20 {
        let mut linea = String::new();
        if lector.read_line(&mut linea).unwrap_or(0) == 0 {
            break;
        }
        if let Some(pos) = linea.find("clave pública") {
            encontrada = linea[pos..]
                .rsplit(' ')
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            break;
        }
    }

    let _ = hijo.kill();
    let _ = hijo.wait();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        encontrada.len() == 64,
        "no se pudo leer la clave pública del proceso ({etiqueta}): {encontrada:?}"
    );
    encontrada
}

/// EL CICLO ENTERO: repartir → perder el original → reconstruir con dos de tres
/// → levantar el servicio → y que sirva la MISMA clave que los clientes fijaron.
#[test]
fn el_servicio_restaurado_sirve_la_misma_clave_que_los_clientes_fijaron() {
    let seed = seed_de_prueba();
    let esperada = clave_publica_de(&seed).unwrap();

    // Lo que un cliente habría fijado ANTES del desastre, tomado del proceso en
    // marcha y no de la función: es el valor con el que se compara después.
    let antes = clave_que_sirve_el_proceso(&a_hex(&seed), "antes");
    assert_eq!(
        antes,
        a_hex(&esperada),
        "el servicio original no sirve lo que la custodia calcula: si estos dos \
         se separan, todo lo demás mide la cosa equivocada"
    );

    // Se reparte 2-de-3. Aquí había un `drop(seed)` para «perder el original»
    // y clippy lo señaló: `[u8; 32]` es `Copy`, así que no borraba nada — la
    // prueba decía una cosa y hacía otra. Lo que de verdad demuestra que el
    // seed no hace falta es que de aquí en adelante NO se vuelve a leer: todo
    // sale de `partes`. Eso lo garantiza el compilador, no un comentario.
    let partes = repartir(&seed, 2, 3).unwrap();

    // Emergencia: aparecen la primera y la tercera.
    let recuperado = verificar_restauracion(&[partes[0].clone(), partes[2].clone()], &esperada)
        .expect("dos de tres tienen que bastar");

    // Y el servicio levantado con ellas es el MISMO para sus clientes.
    let despues = clave_que_sirve_el_proceso(&a_hex(&recuperado), "despues");
    assert_eq!(
        despues, antes,
        "el servicio restaurado sirve OTRA clave: los clientes quedarían fuera"
    );
}

/// El control negativo: un seed distinto levanta un servicio que arranca
/// perfectamente y sirve OTRA clave. Sin esta prueba, la de arriba no
/// distinguiría «restauré bien» de «arrancó algo».
#[test]
fn un_seed_distinto_levanta_un_servicio_sano_con_otra_clave() {
    let seed = seed_de_prueba();
    let esperada = clave_publica_de(&seed).unwrap();

    let mut otro = seed_de_prueba();
    otro[31] ^= 0x80; // un bit
    let suya = clave_publica_de(&otro).unwrap();
    assert_ne!(esperada, suya, "el control negativo debe cambiar la clave");

    // Arranca y sirve: por eso perder el seed es tan peligroso — el servicio
    // equivocado no se queja, responde con normalidad.
    let servida = clave_que_sirve_el_proceso(&a_hex(&otro), "ajeno");
    assert_eq!(servida, a_hex(&suya));
    assert_ne!(
        servida,
        a_hex(&esperada),
        "un seed distinto NO puede servir la clave buena"
    );
}
