//! Firma detached de un CBOM con la firma híbrida de Quipu (Ed25519 + ML-DSA-87).
//!
//! Emite `<cbom>.sig.json` atado al SHA-256 del artefacto exacto (D31: la firma
//! se ancla al artefacto, no al nombre). Verifica en la misma corrida —round-trip
//! y caso rojo (un byte alterado debe romper la firma)— antes de dar por buena
//! ninguna firma.
//!
//! La clave es de DEMOSTRACIÓN, generada en la corrida: prueba el mecanismo sin
//! comprometer una identidad. La clave de identidad de Xiliux es decisión aparte.
//!
//!   cargo run --example firmar_cbom -- herramientas/cbom/cbom.json herramientas/cbom/cbom-quipu.json

use quipu::pqsign;
use sha2::{Digest, Sha256};
use std::fs;

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn main() {
    let rutas: Vec<String> = std::env::args().skip(1).collect();
    if rutas.is_empty() {
        eprintln!("uso: firmar_cbom <cbom.json> [<cbom2.json> ...]");
        std::process::exit(2);
    }

    let epoch = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);

    // Una sola clave demo firma todos los artefactos de esta corrida.
    let (vk, sk) = pqsign::generate_keypair();
    let vk_bytes = vk.to_bytes();

    for ruta in &rutas {
        let datos = fs::read(ruta).unwrap_or_else(|e| panic!("no pude leer {ruta}: {e}"));

        let sha = hex(&Sha256::digest(&datos));
        let firma = sk.sign(&datos);

        // Verificación por la vía real: round-trip DEBE pasar.
        assert!(vk.verify(&datos, &firma), "round-trip: la firma recién hecha no verifica");

        // Caso rojo: un byte alterado DEBE romper la firma (si no, el verificador es ciego).
        let mut alterado = datos.clone();
        alterado[0] ^= 0x01;
        assert!(!vk.verify(&alterado, &firma), "CONTROL: un CBOM alterado NO debería verificar");

        // Y una clave ajena NO debe verificar.
        let (otra_vk, _) = pqsign::generate_keypair();
        assert!(!otra_vk.verify(&datos, &firma), "CONTROL: clave ajena no debe verificar");

        let nombre = std::path::Path::new(ruta)
            .file_name().unwrap().to_string_lossy();
        let sig_json = format!(
            "{{\n  \"artefacto\": \"{nombre}\",\n  \"sha256_artefacto\": \"{sha}\",\n  \"algoritmo\": \"quipu-hibrido-Ed25519+ML-DSA-87\",\n  \"longitud_firma\": {lf},\n  \"clave_publica_hex\": \"{pk}\",\n  \"firma_hex\": \"{fw}\",\n  \"firmado_epoch\": {epoch},\n  \"nota\": \"Clave de DEMOSTRACION generada en la corrida. NO es la clave de identidad de Xiliux; la firma prueba el mecanismo y la integridad del CBOM.\"\n}}\n",
            lf = firma.len(), pk = hex(&vk_bytes), fw = hex(&firma),
        );
        let destino = format!("{ruta}.sig.json");
        fs::write(&destino, sig_json).unwrap_or_else(|e| panic!("no pude escribir {destino}: {e}"));

        println!("✔ {nombre}");
        println!("   sha256   {sha}");
        println!("   firma    {} bytes (Ed25519 {} + ML-DSA-87 {}), clave pública {} bytes",
                 firma.len(), pqsign::ED25519_SIG_LEN, pqsign::MLDSA_SIG_LEN, vk_bytes.len());
        println!("   round-trip verifica ✔ · CBOM alterado rechazado ✔ · clave ajena rechazada ✔");
        println!("   -> {destino}");
    }
}
