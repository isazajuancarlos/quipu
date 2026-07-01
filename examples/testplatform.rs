//! Plataforma de test: orquestador único de validación de Quipu.
//!
//!   cargo run --example testplatform --release
//!
//! Corre: (1) round-trip masivo, (2) batería de ataques (hackerbot),
//! (3) estadística de uniformidad de la salida, (4) mini-benchmark.
//! Emite un reporte unificado y sale con código != 0 si algo falla.

use std::time::Instant;

use quipu::api::{decode, encode, Options};
use quipu::dictionary::Dictionary;
use quipu::hackerbot::{tamper_attack, truncation_attack, uniqueness_attack};
use quipu::kdf::KdfParams;

fn rand_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    getrandom::getrandom(&mut v).expect("RNG");
    v
}

fn main() {
    let dict = Dictionary::new((0x21u8..=0x7e).map(|b| b as char).collect()).unwrap();
    let opts = Options {
        pepper: b"pepper-app",
        kdf_params: KdfParams {
            mem_kib: 512,
            iterations: 1,
            parallelism: 1,
        },
        codebook_id: 1,
    };
    let pass = "passphrase-plataforma";
    let mut failures = 0;

    println!("================ PLATAFORMA DE TEST :: Quipu ================\n");

    // (1) Round-trip masivo sobre tamaños variados.
    print!("[1] Round-trip masivo (200 mensajes)... ");
    let mut ok = 0;
    for i in 0..200 {
        let data = rand_bytes(i % 137);
        let sym = encode(&data, pass, &dict, &opts);
        if decode(&sym, pass, &dict, opts.pepper).as_deref() == Ok(&data[..]) {
            ok += 1;
        }
    }
    report(ok == 200, &format!("{ok}/200 recuperados"), &mut failures);

    // (2) Batería de ataques (hackerbot).
    println!("[2] Ataques (hackerbot):");
    let data = b"objetivo del red-team";
    for r in [
        tamper_attack(data, pass, &dict, opts.pepper, &opts),
        truncation_attack(data, pass, &dict, opts.pepper, &opts),
        uniqueness_attack(data, pass, &dict, &opts, 30),
    ] {
        print!("    - {:<11} ", r.name);
        report(
            r.is_clean(),
            &format!("intentos={} brechas={}", r.attempts, r.breaches),
            &mut failures,
        );
    }

    // (3) Estadística: uniformidad de la salida sobre un mensaje grande.
    print!("[3] Uniformidad de símbolos... ");
    let big = rand_bytes(8192);
    let sym = encode(&big, pass, &dict, &opts);
    let distinct = distinct_ratio(&sym, dict.base());
    report(
        distinct > 0.95,
        &format!("símbolos distintos = {:.1}% del alfabeto", distinct * 100.0),
        &mut failures,
    );

    // (4) Mini-benchmark.
    print!("[4] Benchmark (encode+decode 1 KiB)... ");
    let payload = rand_bytes(1024);
    let t = Instant::now();
    let rounds = 20;
    for _ in 0..rounds {
        let s = encode(&payload, pass, &dict, &opts);
        let _ = decode(&s, pass, &dict, opts.pepper);
    }
    let per = t.elapsed().as_secs_f64() / rounds as f64 * 1000.0;
    println!("OK  ({per:.1} ms/ciclo, dominado por Argon2)");

    println!("\n------------------------------------------------------------");
    if failures == 0 {
        println!("RESULTADO GLOBAL: TODO VERDE.");
    } else {
        println!("RESULTADO GLOBAL: {failures} FALLO(S).");
        std::process::exit(1);
    }
}

fn report(ok: bool, detail: &str, failures: &mut u32) {
    if ok {
        println!("OK   ({detail})");
    } else {
        println!("FAIL ({detail})");
        *failures += 1;
    }
}

/// Fracción del alfabeto que aparece en `symbols`.
fn distinct_ratio(symbols: &str, base: u32) -> f64 {
    let mut seen = std::collections::HashSet::new();
    for c in symbols.chars() {
        seen.insert(c);
    }
    seen.len() as f64 / base as f64
}
