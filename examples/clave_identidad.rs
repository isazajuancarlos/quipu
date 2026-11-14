//! Custodia de la clave de identidad de Xiliux (firma híbrida Ed25519 + ML-DSA-87).
//!
//! La clave privada se genera aleatoria y se guarda CIFRADA con una passphrase,
//! usando el propio Quipu (Argon2id + XChaCha20). Dos factores: el blob cifrado y
//! la frase. La privada nunca toca el disco en claro.
//!
//! LA FRASE SE LEE DE LA VARIABLE DE ENTORNO `QUIPU_FRASE_IDENTIDAD` — nunca de un
//! argumento (quedaría en el historial) ni se imprime. La pones tú por terminal.
//!
//!   # generar (una sola vez):
//!   read -rsp "Frase: " F; echo; read -rsp "Repite: " F2; echo
//!   [ "$F" = "$F2" ] && QUIPU_FRASE_IDENTIDAD="$F" cargo run --release --example clave_identidad -- \
//!       generar ~/.claves/identidad-xiliux.clave herramientas/cbom/identidad-xiliux.pub
//!   unset F F2 QUIPU_FRASE_IDENTIDAD
//!
//!   # firmar los CBOM con la clave estable:
//!   read -rsp "Frase: " F; echo
//!   QUIPU_FRASE_IDENTIDAD="$F" cargo run --release --example clave_identidad -- \
//!       firmar ~/.claves/identidad-xiliux.clave herramientas/cbom/identidad-xiliux.pub \
//!       herramientas/cbom/cbom.json herramientas/cbom/cbom-quipu.json
//!   unset F QUIPU_FRASE_IDENTIDAD

use quipu::api::{decode, encode, Options};
use quipu::dictionaries;
use quipu::pqsign::{self, SigningKey};
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
fn frase() -> String {
    std::env::var("QUIPU_FRASE_IDENTIDAD").unwrap_or_else(|_| {
        eprintln!("falta la variable de entorno QUIPU_FRASE_IDENTIDAD");
        std::process::exit(2);
    })
}
fn huella(vk_bytes: &[u8]) -> String {
    hex(&Sha256::digest(vk_bytes))[..16].to_string()
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let dict = dictionaries::ascii94();
    let opts = Options::default();

    match a.first().map(String::as_str) {
        Some("generar") => {
            let (blob_path, pub_path) = (&a[1], &a[2]);
            let f = frase();
            let (vk, sk) = pqsign::generate_keypair();
            let privada = sk.to_bytes(); // Zeroizing<Vec<u8>>, 64 B
            let blob = encode(&privada, &f, &dict, &opts);

            // Verificar el blob ANTES de darlo por bueno: descifrar y reconstruir.
            let recuperada = decode(&blob, &f, &dict, b"").expect("re-descifrado del blob recién hecho");
            let sk2 = SigningKey::from_bytes(&recuperada).expect("clave reconstruida");
            assert_eq!(sk2.verifying_key().to_bytes(), vk.to_bytes(), "el blob no recupera la clave");

            if let Some(p) = std::path::Path::new(blob_path).parent() { let _ = fs::create_dir_all(p); }
            fs::write(blob_path, &blob).expect("escribir blob cifrado");
            fs::write(pub_path, hex(&vk.to_bytes())).expect("escribir clave pública");

            println!("Clave de identidad de Xiliux GENERADA y cifrada.");
            println!("  blob cifrado : {blob_path}  ({} bytes de texto)", blob.len());
            println!("  clave pública: {pub_path}  ({} bytes)", vk.to_bytes().len());
            println!("  huella       : {}", huella(&vk.to_bytes()));
            println!("  blob verificado: descifra y recupera la clave ✔");
            println!("\nApunta la huella; identifica esta clave en las firmas. La frase no está en ninguna parte salvo tu memoria.");
        }
        Some("firmar") => {
            let (blob_path, pub_path) = (&a[1], &a[2]);
            let archivos = &a[3..];
            let f = frase();
            let blob = fs::read_to_string(blob_path).expect("leer blob cifrado");
            let pub_hex = fs::read_to_string(pub_path).expect("leer clave pública");
            let pub_bytes = de_hex(pub_hex.trim());

            let privada = match decode(&blob, &f, &dict, b"") {
                Ok(p) => p,
                Err(_) => { eprintln!("FRASE INCORRECTA o blob corrupto: no se pudo descifrar."); std::process::exit(1); }
            };
            let sk = SigningKey::from_bytes(&privada).expect("clave reconstruida");
            assert_eq!(sk.verifying_key().to_bytes(), pub_bytes.as_slice(),
                       "la clave descifrada no corresponde a la pública guardada");

            let epoch = std::env::var("SOURCE_DATE_EPOCH").ok().and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
            println!("Clave de identidad cargada · huella {}", huella(&pub_bytes));

            for ruta in archivos {
                let datos = fs::read(ruta).unwrap_or_else(|e| panic!("leer {ruta}: {e}"));
                let sha = hex(&Sha256::digest(&datos));
                let firma = sk.sign(&datos);
                assert!(sk.verifying_key().verify(&datos, &firma), "round-trip");
                let mut alt = datos.clone(); alt[0] ^= 1;
                assert!(!sk.verifying_key().verify(&alt, &firma), "CONTROL: alterado no debe verificar");

                let nombre = std::path::Path::new(ruta).file_name().unwrap().to_string_lossy();
                let sig = format!(
                    "{{\n  \"artefacto\": \"{nombre}\",\n  \"sha256_artefacto\": \"{sha}\",\n  \"algoritmo\": \"quipu-hibrido-Ed25519+ML-DSA-87\",\n  \"clave\": \"identidad-xiliux\",\n  \"huella_clave\": \"{h}\",\n  \"longitud_firma\": {lf},\n  \"clave_publica_hex\": \"{pk}\",\n  \"firma_hex\": \"{fw}\",\n  \"firmado_epoch\": {epoch}\n}}\n",
                    h = huella(&pub_bytes), lf = firma.len(), pk = hex(&pub_bytes), fw = hex(&firma),
                );
                let destino = format!("{ruta}.sig.json");
                fs::write(&destino, sig).expect("escribir .sig.json");
                println!("  ✔ {nombre}  sha256 {}…  firma {} B  -> {destino}", &sha[..16], firma.len());
            }
            println!("Firmado con la clave de identidad estable. Verifica con: cargo run --release --example verificar_cbom -- <cbom>");
        }
        _ => { eprintln!("uso: clave_identidad generar <blob> <pub> | firmar <blob> <pub> <archivo...>"); std::process::exit(2); }
    }
}
