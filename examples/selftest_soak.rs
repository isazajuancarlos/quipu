// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Simulación de carga de las autopruebas de arranque.
//!
//! Una prueba unitaria que corre una vez demuestra poco de un mecanismo que se
//! ejecuta una vez por proceso y del que depende que la librería opere. Esto lo
//! ejercita en volumen y en concurrencia, que es donde viven los fallos que una
//! pasada única no ve: no determinismo, carreras y bloqueos.
//!
//! ```text
//! cargo run --release --example selftest_soak
//! cargo run --release --example selftest_soak -- 500 200
//! ```
//!
//! Argumentos opcionales: nº de pasadas secuenciales y nº de hebras.

use quipu::selftest;
use std::sync::mpsc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Mínimos por defecto. 100 es el piso pedido; se usan 200 para tener margen.
const PASADAS: usize = 200;
const HEBRAS: usize = 100;

fn main() {
    let mut args = std::env::args().skip(1);
    let pasadas: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(PASADAS);
    let hebras: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(HEBRAS);

    println!("== Simulación de las autopruebas de arranque ==");
    println!("   {pasadas} pasadas secuenciales · {hebras} hebras concurrentes\n");

    let mut fallos = 0usize;

    // --- Fase 1: determinismo y estabilidad -----------------------------------
    //
    // `run()` genera pares de claves ML-KEM y ML-DSA de verdad en cada pasada,
    // así que cada una es material aleatorio distinto. Si alguna primitiva
    // tuviera un caso raro dependiente del valor, aquí es donde aparece.
    print!("[1/3] Determinismo sobre {pasadas} pasadas… ");
    let mut tiempos = Vec::with_capacity(pasadas);
    let mut fallidas_por_nombre: Vec<&'static str> = Vec::new();
    let esperadas = selftest::run().checks.len();

    for i in 0..pasadas {
        let t0 = Instant::now();
        let informe = selftest::run();
        tiempos.push(t0.elapsed());

        if informe.checks.len() != esperadas {
            println!("\n      ✗ pasada {i}: {} comprobaciones, se esperaban {esperadas}",
                     informe.checks.len());
            fallos += 1;
        }
        if !informe.ok() {
            fallidas_por_nombre.extend(informe.failures());
            fallos += 1;
        }
    }

    if fallidas_por_nombre.is_empty() {
        println!("ok — {esperadas} comprobaciones correctas en las {pasadas}");
    } else {
        println!("✗ FALLARON: {fallidas_por_nombre:?}");
    }

    tiempos.sort();
    let mediana = tiempos[tiempos.len() / 2];
    let p99 = tiempos[(tiempos.len() * 99 / 100).min(tiempos.len() - 1)];
    println!(
        "      tiempo: mediana {:?} · p99 {:?} · mín {:?} · máx {:?}",
        mediana,
        p99,
        tiempos[0],
        tiempos[tiempos.len() - 1]
    );

    // Una varianza enorme delataría contención o algo no acotado.
    if p99 > mediana * 10 {
        println!("      ⚠ el p99 supera 10× la mediana: revisar contención");
        fallos += 1;
    }

    // --- Fase 2: concurrencia -------------------------------------------------
    //
    // Aquí vive el fallo real de este mecanismo. `ensure()` se apoya en un
    // `OnceLock`: muchas hebras compitiendo por inicializarlo a la vez es
    // exactamente el escenario que produjo el interbloqueo por reentrada. Cada
    // hebra genera además un par de claves, que es lo que dispara `ensure()` en
    // el uso real.
    print!("[2/3] {hebras} hebras concurrentes contra ensure()… ");
    let listas = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = mpsc::channel();

    for _ in 0..hebras {
        let listas = Arc::clone(&listas);
        let tx = tx.clone();
        std::thread::spawn(move || {
            selftest::ensure();
            let (_pk, _sk) = quipu::pqhybrid::generate_keypair();
            let (_vk, _sk2) = quipu::pqsign::generate_keypair();
            listas.fetch_add(1, Ordering::SeqCst);
            let _ = tx.send(());
        });
    }
    drop(tx);

    // Con límite de tiempo: un interbloqueo tiene que salir como fallo, no como
    // una simulación que nunca termina.
    let limite = Duration::from_secs(120);
    let t0 = Instant::now();
    let mut recibidas = 0usize;
    while recibidas < hebras {
        match rx.recv_timeout(limite.saturating_sub(t0.elapsed())) {
            Ok(()) => recibidas += 1,
            Err(_) => break,
        }
    }

    if recibidas == hebras && listas.load(Ordering::SeqCst) == hebras {
        println!("ok — las {hebras} terminaron en {:?}", t0.elapsed());
    } else {
        println!("✗ solo {recibidas}/{hebras} terminaron — posible bloqueo");
        fallos += 1;
    }

    // --- Fase 3: coherencia del estado ---------------------------------------
    print!("[3/3] Coherencia del estado tras la carga… ");
    let mut problemas = Vec::new();
    if !selftest::ready() {
        problemas.push("ready() es falso tras ensure()");
    }
    if selftest::try_ensure().is_err() {
        problemas.push("try_ensure() falla tras haber pasado");
    }
    // Idempotencia: llamarlo mil veces más no debe cambiar nada ni tardar.
    let t0 = Instant::now();
    for _ in 0..1000 {
        selftest::ensure();
    }
    let repetido = t0.elapsed();
    if repetido > Duration::from_millis(100) {
        problemas.push("1000 ensure() repetidos tardaron demasiado");
    }
    if problemas.is_empty() {
        println!("ok — 1000 ensure() repetidos en {repetido:?}");
    } else {
        println!("✗ {problemas:?}");
        fallos += problemas.len();
    }

    println!();
    if fallos == 0 {
        println!("Resultado: sin fallos en {} operaciones simuladas.",
                 pasadas + hebras + 1000);
    } else {
        eprintln!("Resultado: {fallos} problema(s) detectado(s).");
        std::process::exit(1);
    }
}
