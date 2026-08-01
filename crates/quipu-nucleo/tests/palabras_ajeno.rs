// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! El marco de palabras, leído por OTRA implementación de la BIP-39.
//!
//! POR QUÉ ESTE ARCHIVO EXISTE, y es la misma razón que trajo `rqrr` para el
//! QR: una prueba de ida y vuelta contra nuestro propio codificador la pasa
//! igual un codificador roto **de forma consistente**. Escribir y leer con las
//! mismas 200 líneas solo demuestra que son coherentes consigo mismas.
//!
//! Y lo que este marco promete no es coherencia interna: promete que **en 2050
//! lo decodifica cualquiera sin que Quipu exista**. Esa frase solo la puede
//! sostener un tercero. `bip39` es ese tercero, y NO viaja en el artefacto —
//! es `[dev-dependencies]`.
//!
//! Los vectores oficiales ya están probados dentro del módulo. Aquí se prueba
//! la otra mitad: que el camino completo (nuestro escritor → su lector, y su
//! escritor → nuestro lector) cierra sobre datos que no son los de la norma.

#![cfg(feature = "palabras")]

use quipu_nucleo::papel::palabras;
use std::str::FromStr;

/// Datos reproducibles y distintos para cada tamaño. Sin aleatoriedad: una
/// prueba que falla una vez de cada mil no se puede depurar.
fn muestra(n: usize, semilla: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u32 * 97 + semilla as u32 * 31 + 7) as u8)
        .collect()
}

#[test]
fn lo_que_escribimos_lo_lee_una_implementacion_ajena() {
    for &n in palabras::TAMANOS {
        for semilla in 0u8..8 {
            let secreto = muestra(n, semilla);
            let nuestra = palabras::escribir(&secreto).expect("tamaño válido");

            let suya = bip39::Mnemonic::from_str(&nuestra).unwrap_or_else(|e| {
                panic!("una implementación ajena RECHAZÓ nuestra frase de {n} B: {e}")
            });

            let (bytes, largo) = suya.to_entropy_array();
            assert_eq!(
                &bytes[..largo],
                &secreto[..],
                "la implementación ajena sacó otra entropía de nuestra frase de {n} B"
            );
        }
    }
}

#[test]
fn lo_que_escribe_una_implementacion_ajena_lo_leemos() {
    for &n in palabras::TAMANOS {
        for semilla in 0u8..8 {
            let secreto = muestra(n, semilla);
            let suya = bip39::Mnemonic::from_entropy(&secreto).expect("tamaño válido");
            let texto = suya.to_string();

            assert_eq!(
                palabras::leer(&texto).expect("su frase tiene que valer"),
                secreto,
                "no supimos leer la frase de {n} B que escribió otra implementación"
            );
            assert_eq!(
                palabras::escribir(&secreto).unwrap(),
                texto,
                "escribimos algo distinto que la implementación ajena para {n} B"
            );
        }
    }
}

/// EL CASO ROJO DE ESTE ARCHIVO.
///
/// Sin esto, los dos de arriba serían dos verdes que no demuestran que la
/// prueba pueda ponerse roja — el defecto que este repositorio lleva un mes
/// corrigiendo. Se fabrica a mano una frase con una palabra cambiada y se
/// exige que **las DOS** implementaciones la rechacen: si la ajena la aceptara,
/// el que estaría mal sería el modelo de esta prueba, no el código.
#[test]
fn las_dos_implementaciones_rechazan_la_misma_frase_corrompida() {
    let secreto = muestra(32, 3);
    let buena = palabras::escribir(&secreto).unwrap();
    let mut ps: Vec<&str> = buena.split_whitespace().collect();
    ps[5] = if ps[5] == "zoo" { "zone" } else { "zoo" };
    let mala = ps.join(" ");

    assert_eq!(
        palabras::leer(&mala),
        Err(palabras::PalabrasError::SumaDeVerificacion),
        "nosotros teníamos que detectar la palabra cambiada"
    );
    assert!(
        bip39::Mnemonic::from_str(&mala).is_err(),
        "la implementación ajena NO detectó la corrupción: la prueba mide mal, \
         no el código"
    );

    // Y la buena la aceptan las dos, o lo de arriba no discrimina nada.
    assert!(palabras::leer(&buena).is_ok());
    assert!(bip39::Mnemonic::from_str(&buena).is_ok());
}
