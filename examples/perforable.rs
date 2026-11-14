// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

//! Cifrado perforable: destruir la clave al abrir el lacre.
//!
//!   cargo run --example perforable --features perforable
//!
//! Muestra la propiedad central —abrir un lacre destruye la capacidad de
//! reabrirlo, aunque después se robe el estado completo— y la única forma de
//! romperla: conservar una instantánea vieja del estado.

use quipu::api::{abrir, sellar, SelloError};
use quipu::perforable::Perforable;

fn main() {
    // La raíz es aleatoria y esta es su única copia: no se deriva de una frase.
    let mut pf = Perforable::nueva().expect("entropía del sistema");

    // Sellamos tres expedientes, cada uno bajo su etiqueta.
    let e1 = sellar(&pf, b"expediente/2026-001", b"acta reservada #1").unwrap();
    let e2 = sellar(&pf, b"expediente/2026-002", b"acta reservada #2").unwrap();
    let e3 = sellar(&pf, b"expediente/2026-003", b"acta reservada #3").unwrap();
    println!("Tres lacres creados. Coberturas del estado: {}", pf.coberturas());

    // Abrimos el primero. Al abrirlo, su clave se destruye.
    let leido = abrir(&mut pf, b"expediente/2026-001", &e1).unwrap();
    println!("\nAbierto 2026-001 -> {:?}", String::from_utf8_lossy(&leido));

    // Intentar reabrirlo: ya no hay clave.
    match abrir(&mut pf, b"expediente/2026-001", &e1) {
        Err(SelloError::Perforada) => println!("Reabrir 2026-001 -> RECHAZADO (clave destruida) ✔"),
        otro => panic!("debía estar perforado, salió {otro:?}"),
    }
    println!("Perforaciones: {} · Coberturas ahora: {}", pf.perforadas(), pf.coberturas());

    // El caso que importa: un atacante roba el ESTADO COMPLETO de después.
    let robado = pf.a_bytes();
    let mut atacante = Perforable::de_bytes(&robado).unwrap();

    // No puede reabrir lo ya leído...
    assert_eq!(abrir(&mut atacante, b"expediente/2026-001", &e1), Err(SelloError::Perforada));
    println!("\nCon el estado robado, 2026-001 sigue irrecuperable ✔");
    // ...pero SÍ lo que nunca se abrió (por eso el estado robado es peligroso
    // para lo pendiente: perforar protege lo leído, no lo que falta por leer).
    let pend = abrir(&mut atacante, b"expediente/2026-002", &e2).unwrap();
    println!("...pero 2026-002 (nunca abierto) sí se abre: {:?}", String::from_utf8_lossy(&pend));

    // Y el otro pendiente sigue disponible para el dueño legítimo.
    let _ = e3;
    assert!(!pf.esta_perforada(b"expediente/2026-003"));
    println!("\nRegla de oro: destruye la copia vieja del estado tras cada apertura,");
    println!("o quien la conserve vuelve a abrir lo que creías cerrado.");
}
