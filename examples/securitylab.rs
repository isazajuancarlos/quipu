//! Quipu Security Lab (Etapa A). Corre los ataques adaptativos con semilla fija,
//! sella los hallazgos en un corpus encadenado y sale con código != 0 si hay
//! brecha o si alguna defensa antihacker fue debilitada.
//!
//! Ejecutar: `cargo run --example securitylab --features lab`

use quipu::lab::corpus::Corpus;
use quipu::lab::engine::{run, LabReport};
use quipu::lab::forge::ForgeAttack;
use quipu::lab::guard::all_defenses_intact;
use quipu::lab::leak::LeakAttack;

fn record(corpus: &mut Corpus, report: &LabReport) -> bool {
    println!(
        "  {:<16} intentos={:<4} avances={:<4} brechas={}",
        report.name,
        report.attempts,
        report.advances,
        report.breaches.len()
    );
    for b in &report.breaches {
        println!("    !! BRECHA: {b}");
        corpus.append("breach", b.as_bytes());
    }
    corpus.append("run", report.name.as_bytes());
    report.is_clean()
}

fn main() {
    println!("== Quipu Security Lab — Etapa A ==");
    let mut corpus = Corpus::new();
    let mut clean = true;

    print!("Defensas antihacker intactas... ");
    if all_defenses_intact() {
        println!("OK");
    } else {
        println!("¡DEBILITADAS!");
        clean = false;
    }

    let leak = run(&mut LeakAttack::new(), 20260701, 128);
    clean &= record(&mut corpus, &leak);

    let forge = run(&mut ForgeAttack::new(), 1337, 120);
    clean &= record(&mut corpus, &forge);

    let corpus_ok = corpus.verify();
    println!(
        "Corpus: {} entradas, cadena {}",
        corpus.len(),
        if corpus_ok { "íntegra" } else { "ROTA" }
    );
    clean &= corpus_ok;

    if clean {
        println!("Resultado: LIMPIO (0 brechas).");
    } else {
        eprintln!("Resultado: FALLO — revisar brechas/defensas.");
        std::process::exit(1);
    }
}
