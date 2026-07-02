//! Quickstart de Quipu (Rust) — ejemplo funcional de punta a punta.
//!
//!   cargo run --example quickstart
//!
//! Demuestra los modos principales con datos reales y verifica cada round-trip
//! con `assert_eq!`. Si el ejemplo termina, TODO funcionó.

use quipu::api::{
    Options, decode, decode_as_recipient, decode_from_glyph_image, decode_verified, encode,
    encode_signed, encode_to_glyph_image, encode_to_recipient,
};
use quipu::dictionaries;
use quipu::{pqhybrid, pqsign};

fn main() {
    let secret = b"Mensaje confidencial: el tesoro esta bajo el arbol viejo.";
    println!("Secreto original: {:?}\n", String::from_utf8_lossy(secret));

    // -------------------------------------------------------------------------
    // 1) Modo simétrico (passphrase) con el alfabeto ASCII-94.
    // -------------------------------------------------------------------------
    let dict = dictionaries::ascii94();
    let opts = Options::default();

    let encoded = encode(secret, "correct-horse-battery-staple", &dict, &opts);
    println!("[1] Simétrico -> {} símbolos", encoded.chars().count());
    println!("    {encoded}");

    let decoded = decode(&encoded, "correct-horse-battery-staple", &dict, b"")
        .expect("passphrase correcta debe descifrar");
    assert_eq!(decoded, secret, "round-trip simétrico");
    println!("    round-trip OK ✔\n");

    // -------------------------------------------------------------------------
    // 2) Passphrase incorrecta -> RECHAZADO (integridad autenticada).
    // -------------------------------------------------------------------------
    let wrong = decode(&encoded, "passphrase-incorrecta", &dict, b"");
    assert!(wrong.is_err(), "una passphrase incorrecta debe fallar");
    println!("[2] Passphrase incorrecta rechazada ✔  ({:?})\n", wrong.unwrap_err());

    // -------------------------------------------------------------------------
    // 3) Con pepper (secreto que vive fuera del dato: código/HSM/env).
    // -------------------------------------------------------------------------
    let opts_pepper = Options {
        pepper: b"pepper-en-el-codigo",
        ..Options::default()
    };
    let e = encode(secret, "misma-pass", &dict, &opts_pepper);
    // Sin el pepper correcto no se puede descifrar:
    assert!(decode(&e, "misma-pass", &dict, b"").is_err());
    let d = decode(&e, "misma-pass", &dict, b"pepper-en-el-codigo").expect("pepper correcto");
    assert_eq!(d, secret);
    println!("[3] Pepper: solo con el pepper correcto se descifra ✔\n");

    // -------------------------------------------------------------------------
    // 4) Canal visual: glifos nativos (PNG) -> reconocer -> descifrar.
    // -------------------------------------------------------------------------
    let png = encode_to_glyph_image(secret, "clave-visual", &opts);
    std::fs::write("quickstart_glifos.png", &png).expect("escribir PNG");
    let from_glyphs = decode_from_glyph_image(&png, "clave-visual", b"")
        .expect("reconocer glifos y descifrar");
    assert_eq!(from_glyphs, secret, "round-trip por glifos");
    println!(
        "[4] Glifos: {} bytes PNG (guardado en quickstart_glifos.png) -> round-trip OK ✔\n",
        png.len()
    );

    // -------------------------------------------------------------------------
    // 5) Modo asimétrico POST-CUÁNTICO (cifrar a una clave pública).
    // -------------------------------------------------------------------------
    let (pk, sk) = pqhybrid::generate_keypair();
    let enc_pq = encode_to_recipient(secret, &pk, &dict);
    let dec_pq = decode_as_recipient(&enc_pq, &sk, &dict).expect("decapsular con la clave secreta");
    assert_eq!(dec_pq, secret, "round-trip post-cuántico");
    println!("[5] Post-cuántico (X25519 + ML-KEM-1024) -> round-trip OK ✔\n");

    // -------------------------------------------------------------------------
    // 6) Firma híbrida (autenticidad/no-repudio, NO confidencialidad).
    // -------------------------------------------------------------------------
    let (vk, signing_key) = pqsign::generate_keypair();
    let signed = encode_signed(secret, &signing_key, &dict);
    let verified = decode_verified(&signed, &vk, &dict).expect("firma válida verifica");
    assert_eq!(verified, secret, "round-trip firmado");
    // Otra clave NO debe verificar la firma:
    let (other_vk, _) = pqsign::generate_keypair();
    assert!(
        decode_verified(&signed, &other_vk, &dict).is_err(),
        "una clave de verificación equivocada debe fallar"
    );
    println!("[6] Firma híbrida (Ed25519 + ML-DSA-87) -> verifica y rechaza clave ajena ✔");

    println!("\n✅ Todos los modos funcionaron correctamente.");
}
