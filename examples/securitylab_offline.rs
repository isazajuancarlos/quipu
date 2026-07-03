//! Quipu Security Lab — banco OFFLINE (Etapa B). Timing (superficie 2) y coste de
//! guessing (superficie 3). Pensado para correr AISLADO dentro del contenedor
//! `quipu-lab` (--network none, sin claves reales).
//!
//! Ejecutar: `cargo run --release --example securitylab_offline --features lab-offline`

use quipu::lab::guessing::guessing_cost;
use quipu::lab::timing::{ct_eq_timing, decode_timing, dudect_ct_eq, DUDECT_T_THRESHOLD};

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

    // Superficie 2 (dudect): t de Welch sobre ct_eq. |t| > umbral = posible fuga.
    // Una sola corrida es sensible al ruido del sistema, así que tomamos la
    // MEDIANA de varias corridas por |t|. La mediana descarta un valor atípico
    // en CUALQUIER dirección: no oculta una fuga real (a diferencia de quedarse
    // con el menor |t|, que sería fail-open) ni falla por un pico espurio.
    let mut runs: Vec<_> = (0..3).map(|_| dudect_ct_eq(10_000)).collect();
    runs.sort_by(|a, b| a.t.abs().partial_cmp(&b.t.abs()).unwrap());
    let dud = runs.swap_remove(runs.len() / 2);
    let verdict = if dud.is_constant_time(DUDECT_T_THRESHOLD) {
        "constant-time"
    } else {
        "POSIBLE FUGA (mediana de 3 corridas)"
    };
    println!(
        "[dudect]   {:<27} t={:.2} (n={}, umbral={:.0}) -> {}",
        dud.name, dud.t, dud.n, DUDECT_T_THRESHOLD, verdict
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

    let clean = ct.within(0.5, 2.0)
        && dt.within(0.5, 2.0)
        && g.cracked == 0
        && dud.is_constant_time(DUDECT_T_THRESHOLD);
    if clean {
        println!("Resultado: sin fuga gruesa de timing y 0 descifrados.");
    } else {
        eprintln!("Resultado: revisar — posible fuga de timing o descifrado.");
        std::process::exit(1);
    }
}
