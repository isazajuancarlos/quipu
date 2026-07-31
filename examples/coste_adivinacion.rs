// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Coste real de un intento de adivinación, en CPU medida y en GPU acotada.
//!
//!   cargo run --release --example coste_adivinacion
//!
//! Existe porque `docs/ATAQUES_TAXONOMIA.md` publicaba «6 intentos/s» sin decir
//! con qué parámetros ni en qué máquina, y la cifra que se publica tiene que ser
//! la que sufre el usuario, no la del banco. El banco (`src/lab/guessing.rs`)
//! deriva con 16 MiB y 2 iteraciones; `KdfParams::default()` entrega 64 MiB y 3.
//! Son seis veces el trabajo de memoria: la misma frase describe dos mundos.
//!
//! Lo que hace esta herramienta:
//!
//!   1. MIDE en esta CPU el coste por intento del camino que recorre el atacante
//!      —`decode` con la contraseña equivocada— en los dos juegos de parámetros,
//!      e imprime el modelo de CPU para que la cifra tenga procedencia.
//!   2. ACOTA el coste en GPU. No lo mide: aquí no hay GPU. Es una cota
//!      superior de la capacidad del atacante derivada del ancho de banda de
//!      memoria, con la aritmética a la vista para que cualquiera la rehaga.
//!      Se declara ESTIMACIÓN, nunca medición.

use quipu::api::{Options, decode, encode};
use quipu::dictionaries;
use quipu::kdf::KdfParams;
use std::time::Instant;

/// Intentos por juego de parámetros. A 64 MiB cada uno cuesta cientos de ms.
const INTENTOS: u32 = 24;

/// Especificación pública de un acelerador: (nombre, VRAM GiB, ancho de banda GB/s).
/// Son fichas técnicas del fabricante, no mediciones nuestras.
const ACELERADORES: &[(&str, f64, f64)] = &[
    ("NVIDIA RTX 4090 (GDDR6X)", 24.0, 1008.0),
    ("NVIDIA RTX 5090 (GDDR7)", 32.0, 1792.0),
    ("NVIDIA A100 80GB (HBM2e)", 80.0, 2039.0),
    ("NVIDIA H100 SXM (HBM3)", 80.0, 3350.0),
];

fn cpu_modelo() -> String {
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split(':').nth(1))
                .map(|v| v.trim().to_string())
        })
        .unwrap_or_else(|| "desconocida (no hay /proc/cpuinfo)".into())
}

/// Mide el coste por intento del camino del atacante: descifrar con la clave
/// equivocada. Devuelve (segundos por intento, intentos por segundo).
fn medir(params: KdfParams) -> (f64, f64) {
    let dict = dictionaries::ascii94();
    let opts = Options {
        pepper: b"",
        kdf_params: params,
        codebook_id: 0,
    };
    let sym = encode(b"tesoro", "la-correcta-y-fuera-del-ranking", &dict, &opts);

    // Un intento en frío para no cargar el arranque en la media.
    let _ = decode(&sym, "calentamiento", &dict, b"");

    let inicio = Instant::now();
    for i in 0..INTENTOS {
        // Si alguno acertara, el banco estaría roto, no el cifrado.
        assert!(
            decode(&sym, &format!("intento-{i}"), &dict, b"").is_err(),
            "una contraseña del barrido descifró: el banco está mal montado"
        );
    }
    let por_intento = inicio.elapsed().as_secs_f64() / f64::from(INTENTOS);
    (por_intento, 1.0 / por_intento)
}

/// Años para recorrer `bits` de espacio de claves a `por_segundo` intentos/s.
fn anios(bits: u32, por_segundo: f64) -> f64 {
    2f64.powi(bits as i32) / por_segundo / (365.25 * 24.0 * 3600.0)
}

fn main() {
    let def = KdfParams::default();
    let banco = KdfParams {
        mem_kib: 16 * 1024,
        iterations: 2,
        parallelism: 1,
    };

    println!("== CPU: MEDIDO ==");
    println!("Máquina: {}", cpu_modelo());
    println!("Intentos por juego: {INTENTOS}\n");

    let mut medidos = Vec::new();
    for (etiqueta, p) in [("default() — lo que recibe el usuario", def), (
        "guessing.rs — lo que mide el banco",
        banco,
    )] {
        let (seg, por_s) = medir(p);
        println!(
            "{etiqueta}\n  Argon2id m={} MiB t={} p={}\n  {:.3} s/intento → {:.2} intentos/s\n",
            p.mem_kib / 1024,
            p.iterations,
            p.parallelism,
            seg,
            por_s
        );
        medidos.push((etiqueta, p, por_s));
    }

    // La cota de GPU se calcula sobre lo que el usuario recibe, no sobre el banco.
    let m_bytes = f64::from(def.mem_kib) * 1024.0;
    let pases = f64::from(def.iterations);
    // Tráfico MÍNIMO por derivación: cada pase lee y escribe cada bloque una vez.
    // Argon2 mueve más (lee además el bloque de referencia), así que tomar el
    // mínimo da la cota SUPERIOR del rendimiento del atacante — el lado
    // conservador para quien se defiende.
    let bytes_por_intento = 2.0 * pases * m_bytes;

    println!("== GPU: ESTIMADO, NO MEDIDO ==");
    println!("Aquí no hay GPU. Lo de abajo es una COTA SUPERIOR por ancho de banda");
    println!("de memoria, no una medición con hashcat ni con nada.\n");
    println!(
        "Tráfico mínimo por derivación con default(): 2 × {} pases × {} MiB = {:.0} MiB",
        def.iterations,
        def.mem_kib / 1024,
        bytes_por_intento / (1024.0 * 1024.0)
    );
    println!("Cota por ancho de banda:  intentos/s ≤ BW / tráfico");
    println!("Cota por capacidad:       instancias simultáneas ≤ VRAM / memoria por derivación\n");

    let cpu_por_s = medidos[0].2;
    println!(
        "{:<26} {:>10} {:>12} {:>10} {:>14}",
        "Acelerador", "≤ int/s", "× vs CPU", "≤ simult.", "años 60 bits"
    );
    for (nombre, vram_gib, bw_gbs) in ACELERADORES {
        let cota_bw = bw_gbs * 1e9 / bytes_por_intento;
        let cota_cap = vram_gib * 1024.0 / f64::from(def.mem_kib / 1024);
        println!(
            "{nombre:<26} {:>10.0} {:>11.0}× {:>10.0} {:>14.2e}",
            cota_bw,
            cota_bw / cpu_por_s,
            cota_cap,
            anios(60, cota_bw)
        );
    }

    println!("\nLímites de esta estimación, que van con la cifra a donde vaya:");
    println!("  · Es una COTA, no un rendimiento observado. El real es menor: el");
    println!("    direccionamiento dependiente de datos de la segunda mitad de");
    println!("    Argon2id castiga a la GPU, y ninguna implementación satura el bus.");
    println!("  · No cubre ASIC/FPGA con memoria a medida. Ahí la cota de ancho de");
    println!("    banda es otra y esta tabla no dice nada.");
    println!("  · Supone una contraseña de la entropía que se declare. Contra una");
    println!("    contraseña débil ningún KDF salva: el coste por intento es el");
    println!("    suelo, no el techo.");
}
