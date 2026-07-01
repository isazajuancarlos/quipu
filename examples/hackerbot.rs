//! Hackerbot: corre la batería de ataques contra la propia librería y reporta.
//!
//!   cargo run --example hackerbot
//!
//! Salida: por cada ataque, intentos y brechas. breaches > 0 = fallo a corregir.

use quipu::dictionary::Dictionary;
use quipu::hackerbot::{tamper_attack, truncation_attack, uniqueness_attack, AttackReport};
use quipu::kdf::KdfParams;
use quipu::api::Options;

fn main() {
    let dict = Dictionary::new((0x21u8..=0x7e).map(|b| b as char).collect()).unwrap();
    let opts = Options {
        pepper: b"pepper-app",
        kdf_params: KdfParams {
            mem_kib: 256,
            iterations: 1,
            parallelism: 1,
        },
        codebook_id: 1,
    };
    let data = b"objetivo del red-team: un mensaje a proteger";
    let pass = "passphrase-de-prueba";

    println!("== HACKERBOT :: red-team interno de Quipu ==\n");

    let reports = [
        tamper_attack(data, pass, &dict, opts.pepper, &opts),
        truncation_attack(data, pass, &dict, opts.pepper, &opts),
        uniqueness_attack(data, pass, &dict, &opts, 50),
    ];

    let mut total_breaches = 0;
    for r in &reports {
        print_report(r);
        total_breaches += r.breaches;
    }

    println!("\n-------------------------------------------");
    if total_breaches == 0 {
        println!("RESULTADO: LIMPIO. La librería resistió todos los ataques.");
    } else {
        println!("RESULTADO: {total_breaches} BRECHA(S). Convertir en test de regresión y corregir.");
        std::process::exit(1);
    }
}

fn print_report(r: &AttackReport) {
    let estado = if r.is_clean() { "OK " } else { "FAIL" };
    println!(
        "[{estado}] {:<11} intentos={:<5} brechas={}",
        r.name, r.attempts, r.breaches
    );
}
