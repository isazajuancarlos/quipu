//! Quipu Security Lab — banco OFFLINE (Etapa B). Timing (superficie 2) y coste de
//! guessing (superficie 3). Pensado para correr AISLADO dentro del contenedor
//! `quipu-lab` (--network none, sin claves reales).
//!
//! Ejecutar: `cargo run --release --example securitylab_offline --features lab-offline`

use quipu::lab::guessing::guessing_cost;
use quipu::lab::timing::{
    ct_eq_timing, decode_timing, dudect_ct_eq, dudect_decapsulate_two_keys,
    dudect_decapsulate_valid_vs_corrupt, DudectReport, DUDECT_T_THRESHOLD,
};

/// Mediana por |t| de varias corridas. Una sola corrida es sensible al ruido del
/// sistema; la mediana descarta un atípico en CUALQUIER dirección, así que no
/// oculta una fuga real (a diferencia de quedarse con el menor |t|, que sería
/// fail-open) ni falla por un pico espurio.
fn mediana_de(corridas: usize, mut f: impl FnMut() -> DudectReport) -> DudectReport {
    let mut v: Vec<_> = (0..corridas).map(|_| f()).collect();
    v.sort_by(|a, b| a.t.abs().partial_cmp(&b.t.abs()).unwrap());
    v.swap_remove(v.len() / 2)
}

/// Imprime un veredicto dudect con el mismo formato para todas las superficies.
fn reportar(d: &DudectReport) -> bool {
    let ok = d.is_constant_time(DUDECT_T_THRESHOLD);
    println!(
        "[dudect]   {:<40} t={:.2} (n={}, umbral={:.0}) -> {}",
        d.name,
        d.t,
        d.n,
        DUDECT_T_THRESHOLD,
        if ok {
            "constant-time"
        } else {
            "POSIBLE FUGA (mediana de 3 corridas)"
        }
    );
    ok
}

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
    let dud = mediana_de(3, || dudect_ct_eq(10_000));
    let dud_ok = reportar(&dud);

    // Superficie 2 (dudect) sobre la ruta POST-CUÁNTICA. Aquí está el único
    // punto del modo asimétrico donde un tiempo dependiente del secreto es
    // explotable: `decapsulate` toma la clave secreta.
    //
    // Muchas menos muestras que en `ct_eq` a propósito: una decapsulación
    // ML-KEM-1024 es órdenes de magnitud más cara que una comparación, y el
    // banco tiene que terminar en un tiempo razonable.
    let dec_ct = mediana_de(3, || dudect_decapsulate_valid_vs_corrupt(300));
    let dec_ct_ok = reportar(&dec_ct);

    let dec_k = mediana_de(3, || dudect_decapsulate_two_keys(300));
    let dec_k_ok = reportar(&dec_k);

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

    let clean =
        ct.within(0.5, 2.0) && dt.within(0.5, 2.0) && g.cracked == 0 && dud_ok && dec_ct_ok && dec_k_ok;
    if clean {
        println!("Resultado: sin fuga gruesa de timing y 0 descifrados.");
    } else {
        eprintln!("Resultado: revisar — posible fuga de timing o descifrado.");
        std::process::exit(1);
    }
}
