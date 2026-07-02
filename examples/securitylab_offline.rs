//! Quipu Security Lab — banco OFFLINE (Etapa B). Timing (superficie 2) y coste de
//! guessing (superficie 3). Pensado para correr AISLADO dentro del contenedor
//! `quipu-lab` (--network none, sin claves reales).
//!
//! Ejecutar: `cargo run --release --example securitylab_offline --features lab-offline`

use quipu::lab::guessing::guessing_cost;
use quipu::lab::timing::{ct_eq_timing, decode_timing};

fn main() {
    println!("== Quipu Security Lab — banco offline (Etapa B) ==");

    // Superficie 2: timing.
    let ct = ct_eq_timing(4000);
    println!(
        "[timing] {:<28} a={:?} b={:?} ratio={:.3}",
        ct.name,
        ct.a,
        ct.b,
        ct.ratio()
    );
    let dt = decode_timing(32);
    println!(
        "[timing] {:<28} a={:?} b={:?} ratio={:.3}",
        dt.name,
        dt.a,
        dt.b,
        dt.ratio()
    );

    // Superficie 3: coste de guessing.
    let g = guessing_cost(128, 2026);
    println!(
        "[guessing] intentos={} descifrados={} coste/intento={:?}",
        g.attempts, g.cracked, g.per_guess
    );
    println!(
        "[guessing] extrapolación a 2^40 intentos: {:.1} años (1 hilo)",
        g.cost_years(40)
    );

    let clean = ct.within(0.5, 2.0) && dt.within(0.5, 2.0) && g.cracked == 0;
    if clean {
        println!("Resultado: sin fuga gruesa de timing y 0 descifrados.");
    } else {
        eprintln!("Resultado: revisar — posible fuga de timing o descifrado.");
        std::process::exit(1);
    }
}
