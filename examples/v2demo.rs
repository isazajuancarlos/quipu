//! Demo de las capacidades v2 de Quipu.
//!
//!   cargo run --example v2demo
//!
//! Muestra: (1) cifrado híbrido post-cuántico a clave pública y (2) endurecimiento
//! OPRF con rate-limit de servidor.

use quipu::api::{decode_as_recipient, encode_to_recipient};
use quipu::dictionaries;
use quipu::{oprf, pqhybrid};

fn main() {
    println!("================ QUIPU v2 ================\n");

    // (1) Híbrido post-cuántico (X25519 + ML-KEM-1024).
    println!("[1] Cifrado híbrido post-cuántico a clave pública");
    let (pk, sk) = pqhybrid::generate_keypair().unwrap();
    println!("    clave pública: {} bytes  | secreta: {} bytes",
        pqhybrid::PUBLIC_KEY_LEN, pqhybrid::SECRET_KEY_LEN);
    let dict = dictionaries::flagship();
    let mensaje = b"Solo el dueno de la clave secreta puede leer esto.";
    let cifrado = encode_to_recipient(mensaje, &pk, &dict).unwrap();
    println!("    cifrado ({} glifos): {}...", cifrado.chars().count(),
        cifrado.chars().take(24).collect::<String>());
    let recuperado = decode_as_recipient(&cifrado, &sk, &dict).unwrap();
    println!("    recuperado: {}", String::from_utf8_lossy(&recuperado));
    assert_eq!(recuperado, mensaje);

    // (2) OPRF: endurecimiento online con rate-limit real.
    println!("\n[2] OPRF: antibot/rate-limit real (servidor)");
    let mut server = oprf::Server::new(3); // presupuesto: 3 consultas
    let pw = b"passphrase-del-usuario";
    let (st1, blinded1) = oprf::blind(pw);
    let ev1 = server.evaluate(&blinded1).unwrap();
    let hardened1 = oprf::finalize(pw, &st1, &ev1).unwrap();
    let (st2, blinded2) = oprf::blind(pw);
    let ev2 = server.evaluate(&blinded2).unwrap();
    let hardened2 = oprf::finalize(pw, &st2, &ev2).unwrap();
    println!("    misma passphrase -> mismo output endurecido: {}",
        hardened1 == hardened2);
    println!("    el servidor nunca vio la passphrase (cegado): {}",
        blinded1 != blinded2);
    // Agota el presupuesto.
    let (_st3, b3) = oprf::blind(pw);
    let _ = server.evaluate(&b3); // 3a consulta
    let (_st4, b4) = oprf::blind(pw);
    println!("    tras agotar el presupuesto, el servidor rechaza: {}",
        server.evaluate(&b4).is_none());

    println!("\n========================================");
    println!("v2: post-cuantico + OPRF -> TODO OK");
}
