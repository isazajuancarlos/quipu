//! Verificador INDEPENDIENTE de un CBOM firmado: lee `<cbom>.sig.json`
//! (autocontenido: clave pública + firma + sha256), lee el `<cbom>`, y comprueba
//! (1) integridad SHA-256 y (2) la firma híbrida, reconstruyendo la clave pública
//! desde el propio .sig. Es lo que haría un tercero — no comparte estado con el
//! firmador. Cruza la frontera (D28).
//!
//!   cargo run --example verificar_cbom -- herramientas/cbom/cbom.json

use quipu::pqsign::{self, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs;

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b { s.push_str(&format!("{x:02x}")); }
    s
}
fn de_hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
/// Extrae el valor string de un campo de un JSON plano (nuestro propio formato).
fn campo<'a>(json: &'a str, clave: &str) -> &'a str {
    let pat = format!("\"{clave}\":");
    let i = json.find(&pat).unwrap_or_else(|| panic!("falta el campo {clave}")) + pat.len();
    let resto = &json[i..];
    let a = resto.find('"').expect("valor abre comilla") + 1;
    let b = resto[a..].find('"').expect("valor cierra comilla");
    &resto[a..a + b]
}

fn main() {
    let cbom = std::env::args().nth(1).expect("uso: verificar_cbom <cbom.json>");
    let sig_path = format!("{cbom}.sig.json");

    let sig = fs::read_to_string(&sig_path).unwrap_or_else(|e| panic!("no pude leer {sig_path}: {e}"));
    let datos = fs::read(&cbom).unwrap_or_else(|e| panic!("no pude leer {cbom}: {e}"));

    // 1. Integridad: el sha256 del archivo debe casar con el del .sig.
    let sha_real = hex(&Sha256::digest(&datos));
    let sha_sig = campo(&sig, "sha256_artefacto");
    let integridad = sha_real == sha_sig;

    // 2. Firma: reconstruir clave pública desde el .sig y verificar.
    let pk = de_hex(campo(&sig, "clave_publica_hex"));
    let firma = de_hex(campo(&sig, "firma_hex"));
    let vk = VerifyingKey::from_bytes(&pk).expect("clave pública del .sig mal formada");
    let firma_ok = vk.verify(&datos, &firma);

    println!("Artefacto : {cbom}");
    println!("Algoritmo : {}", campo(&sig, "algoritmo"));
    println!("SHA-256   : {} {}", sha_real, if integridad { "== .sig OK" } else { "!= .sig ALTERADO" });
    println!("Firma     : {} bytes -> {}", firma.len(), if firma_ok { "VALIDA OK" } else { "INVALIDA" });
    println!("Longitudes: Ed25519 {} + ML-DSA-87 {} = {}", pqsign::ED25519_SIG_LEN, pqsign::MLDSA_SIG_LEN, pqsign::SIGNATURE_LEN);

    if integridad && firma_ok {
        println!("\nOK: CBOM integro y firma verificada desde el .sig (verificación independiente).");
    } else {
        eprintln!("\nFALLO: verificación FALLÓ");
        std::process::exit(1);
    }
}
