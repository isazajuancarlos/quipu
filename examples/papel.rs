// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! La medición que decide el portador de papel (hoja de ruta §6).
//!
//! Ejecutar: `cargo run --release --example papel --features lab`
//!
//! Área FIJA para todos —esa es la condición «a igual área de papel»—, la MISMA
//! corrección de errores para todos, y una escalera de degradación de
//! fotocopiadora. Lo que se busca no es «cuál aguanta más», sino **cuántos bytes
//! de secreto entrega cada uno, íntegros, en la misma superficie**.

use quipu::lab::engine::Rng;
use quipu::lab::papel::{medir, Fotocopia, Matriz, Portador, Texto};

/// Lado de la hoja, en puntos. Cuadrada para que ninguna disposición salga
/// favorecida por la forma.
const LADO: usize = 240;
/// Repeticiones por celda de la tabla.
const INTENTOS: usize = 40;

fn escalera() -> Vec<(&'static str, Fotocopia)> {
    vec![
        (
            "copia limpia",
            Fotocopia {
                desenfoque: 0,
                umbral: 0.5,
                mota: 0.0,
                franja: 0,
            },
        ),
        (
            "1a copia",
            Fotocopia {
                desenfoque: 1,
                umbral: 0.45,
                mota: 0.005,
                franja: 0,
            },
        ),
        (
            "3a copia",
            Fotocopia {
                desenfoque: 1,
                umbral: 0.55,
                mota: 0.02,
                franja: 0,
            },
        ),
        (
            "fax",
            Fotocopia {
                desenfoque: 2,
                umbral: 0.50,
                mota: 0.05,
                franja: 0,
            },
        ),
        (
            "copia sucia",
            Fotocopia {
                desenfoque: 2,
                umbral: 0.60,
                mota: 0.08,
                franja: 0,
            },
        ),
        (
            "raya de toner",
            Fotocopia {
                desenfoque: 1,
                umbral: 0.50,
                mota: 0.02,
                franja: 6,
            },
        ),
    ]
}

fn main() {
    println!("== Portador de papel: qué sobrevive a una fotocopia ==");
    println!(
        "Hoja de {LADO}x{LADO} puntos ({} puntos de área) para TODOS · {INTENTOS} intentos por celda",
        LADO * LADO
    );
    println!("Corrección de errores idéntica (quipu_nucleo::ecc, Reed-Solomon GF(256)).\n");

    let portadores: Vec<Box<dyn Portador>> = vec![
        // Emparejados por RASGO MÍNIMO, que es la variable que domina el
        // canal: matriz de lado s contra texto de escala s. Comparar s=1 contra
        // s=3 mediría el grosor del trazo y no el sustrato.
        Box::new(Matriz { lado: 1 }),
        Box::new(Texto { escala: 1 }),
        Box::new(Matriz { lado: 2 }),
        Box::new(Texto { escala: 2 }),
        Box::new(Matriz { lado: 3 }),
        Box::new(Texto { escala: 3 }),
        Box::new(Matriz { lado: 4 }),
        Box::new(Texto { escala: 4 }),
        // El barrido llega hasta donde la matriz SOBREVIVE al fax. Cortarlo
        // antes fue el primer error: se concluía «el texto gana en fax» sin
        // haber probado el módulo grande que también lo aguanta.
        Box::new(Matriz { lado: 6 }),
        Box::new(Matriz { lado: 8 }),
        Box::new(Matriz { lado: 10 }),
    ];

    for paridad in [0.15f64, 0.30] {
        println!("--- paridad {:.0} % de la capacidad ---", paridad * 100.0);
        print!("{:<18}{:>7}", "portador", "bytes");
        for (nombre, _) in escalera() {
            print!("{nombre:>15}");
        }
        println!();

        // Lo que de verdad se busca: por cada nivel de degradación, quién
        // entrega MÁS bytes íntegros. Se acumula mientras se imprime la tabla.
        let mut campeon: Vec<(String, usize)> =
            escalera().iter().map(|_| (String::new(), 0)).collect();

        for p in &portadores {
            let mut rng = Rng::seeded(0x5A17);
            let mut fila = Vec::new();
            let mut carga = 0usize;
            for (i, (_, copia)) in escalera().iter().enumerate() {
                let c = medir(p.as_ref(), LADO, LADO, paridad, *copia, INTENTOS, &mut rng);
                carga = c.carga_util;
                if c.fiable() && c.carga_util > campeon[i].1 {
                    campeon[i] = (c.portador.clone(), c.carga_util);
                }
                fila.push(c);
            }
            print!("{:<18}{:>7}", p.nombre(), carga);
            for c in &fila {
                if c.vacia() {
                    // No se imprime su tasa: recuperar la nada da 100 % y leído
                    // deprisa parecería el portador más robusto de la tabla.
                    print!("{:>15}", "no cabe");
                } else {
                    let marca = if c.fiable() { "" } else { "*" };
                    print!("{:>14.0}%{marca}", c.tasa() * 100.0);
                }
            }
            println!();
        }
        println!("(* = por debajo del 95 %, o sea NO fiable)");

        println!("\n  bytes íntegros que entrega el mejor portador de cada columna:");
        for ((nombre, _), (quien, bytes)) in escalera().iter().zip(&campeon) {
            if *bytes == 0 {
                println!("    {nombre:<16} ninguno llega al 95 %");
            } else {
                println!("    {nombre:<16} {bytes:>5} B  con {quien}");
            }
        }
        println!();
    }
}
