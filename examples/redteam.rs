//! Quipu Red-Team — simulación integral de ataques contra la propia librería.
//!
//! Lanza TODAS las superficies adversarias a la vez y consolida el veredicto:
//!   - adaptativas (aprenden por semilla): leak, forja simétrica, streaming,
//!     forja triple-híbrida (feature `slh`), oráculo honey (feature `honey`);
//!   - deterministas (`hackerbot`): tamper, truncación, unicidad de salt/nonce,
//!     forja de firma;
//!   - candado de defensas: `ct_eq` / `is_sane` / `wipe` siguen presentes.
//!
//! Sale con código != 0 si hay UNA sola brecha. Ejecutar:
//!   cargo run --example redteam --features "lab slh honey" --release

use quipu::api::Options;
use quipu::dictionaries::ascii94;
use quipu::hackerbot;
use quipu::kdf::KdfParams;
use quipu::lab::engine::{run, LabReport};
use quipu::lab::forge::ForgeAttack;
use quipu::lab::guard::all_defenses_intact;
use quipu::lab::leak::LeakAttack;
use quipu::lab::stream_attack::StreamAttack;
use quipu::pqsign;

#[cfg(feature = "slh")]
use quipu::lab::forge_triple::ForgeTripleAttack;
#[cfg(feature = "honey")]
use quipu::lab::honey_attack::HoneyAttack;

/// Coste Argon2id bajo: la simulación mide defensas, no la dureza del KDF.
fn cheap() -> KdfParams {
    KdfParams {
        mem_kib: 64,
        iterations: 1,
        parallelism: 1,
    }
}

struct Row {
    name: &'static str,
    kind: &'static str,
    attempts: usize,
    breaches: usize,
    details: Vec<String>,
}

fn from_lab(r: &LabReport, kind: &'static str) -> Row {
    Row {
        name: r.name,
        kind,
        attempts: r.attempts,
        breaches: r.breaches.len(),
        details: r.breaches.clone(),
    }
}

fn from_bot(r: &hackerbot::AttackReport, kind: &'static str) -> Row {
    Row {
        name: r.name,
        kind,
        attempts: r.attempts,
        breaches: r.breaches,
        details: Vec::new(),
    }
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║   QUIPU RED-TEAM · simulación integral de ataques            ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    // Superficies opcionales realmente compiladas.
    let mut surfaces = vec!["leak", "forge", "stream", "tamper", "trunc", "unique", "sig-forge"];
    if cfg!(feature = "slh") {
        surfaces.push("triple(slh)");
    }
    if cfg!(feature = "honey") {
        surfaces.push("honey");
    }
    println!("Superficies activas: {}\n", surfaces.join(" · "));

    // -- Candado de defensas ------------------------------------------------
    let defenses = all_defenses_intact();
    println!(
        "[0] Defensas antihacker (ct_eq / is_sane / wipe): {}",
        if defenses { "INTACTAS ✔" } else { "¡DEBILITADAS! ✘" }
    );
    println!();

    let dict = ascii94();
    let opts = Options {
        pepper: b"",
        kdf_params: cheap(),
        codebook_id: 0,
    };
    let data = b"acta confidencial del red-team: el tesoro esta bajo el arbol viejo";

    let mut rows: Vec<Row> = Vec::new();

    // -- Adaptativas --------------------------------------------------------
    rows.push(from_lab(&run(&mut LeakAttack::new(), 20_260_701, 128), "adaptativo"));
    rows.push(from_lab(&run(&mut ForgeAttack::new(), 1337, 120), "adaptativo"));
    rows.push(from_lab(&run(&mut StreamAttack::new(), 4242, 60), "adaptativo"));
    #[cfg(feature = "slh")]
    rows.push(from_lab(&run(&mut ForgeTripleAttack::new(), 7, 24), "adaptativo·slh"));
    #[cfg(feature = "honey")]
    rows.push(from_lab(&run(&mut HoneyAttack::new(), 909_090, 60), "adaptativo·honey"));

    // -- Deterministas (hackerbot) -----------------------------------------
    rows.push(from_bot(
        &hackerbot::tamper_attack(data, "clave-roja", &dict, b"", &opts),
        "determinista",
    ));
    rows.push(from_bot(
        &hackerbot::truncation_attack(data, "clave-roja", &dict, b"", &opts),
        "determinista",
    ));
    rows.push(from_bot(
        &hackerbot::uniqueness_attack(data, "clave-roja", &dict, &opts, 64),
        "determinista",
    ));
    let (vk, sk) = pqsign::generate_keypair();
    rows.push(from_bot(
        &hackerbot::forgery_attack(data, &sk, &vk, &dict, 8),
        "determinista",
    ));

    // -- Reporte ------------------------------------------------------------
    println!(
        "{:<20} {:<18} {:>9} {:>9}",
        "ATAQUE", "TIPO", "INTENTOS", "BRECHAS"
    );
    println!("{}", "─".repeat(60));
    let mut total_attempts = 0usize;
    let mut total_breaches = 0usize;
    for r in &rows {
        let mark = if r.breaches == 0 { "✔" } else { "✘" };
        println!(
            "{:<20} {:<18} {:>9} {:>7} {}",
            r.name, r.kind, r.attempts, r.breaches, mark
        );
        for d in &r.details {
            println!("      !! BRECHA: {d}");
        }
        total_attempts += r.attempts;
        total_breaches += r.breaches;
    }
    println!("{}", "─".repeat(60));
    println!(
        "{:<20} {:<18} {:>9} {:>7}",
        "TOTAL",
        format!("{} superficies", rows.len()),
        total_attempts,
        total_breaches
    );
    println!();

    let clean = defenses && total_breaches == 0;
    if clean {
        println!(
            "VEREDICTO: LIMPIO — {} intentos, 0 brechas, defensas intactas. ✅",
            total_attempts
        );
    } else {
        eprintln!("VEREDICTO: FALLO — {total_breaches} brecha(s) o defensa debilitada. ✘");
        std::process::exit(1);
    }
}
