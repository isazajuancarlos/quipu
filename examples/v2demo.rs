//! Demo de las capacidades v2 de Quipu.
//!
//!   cargo run --example v2demo
//!
//! Muestra: (1) cifrado híbrido post-cuántico a clave pública y (2) endurecimiento
//! OPRF con rate-limit de servidor.

use quipu::api::{decode_as_recipient, encode_to_recipient};
use quipu::dictionaries;
use quipu::{pqhybrid, voprf};

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

    // (2) VOPRF: endurecimiento online CON PRUEBA DLEQ.
    //
    // ESTE EJEMPLO DEMOSTRABA EL CAMINO SIN VERIFICAR (`quipu::oprf`), y eso es
    // peor que no demostrar nada: un ejemplo es lo primero que se copia. El
    // OPRF a secas endurece igual pero el cliente NO PUEDE SABER si el servidor
    // usó la clave correcta — o sea que un servidor deshonesto (T4 del modelo
    // de amenaza) desvía la derivación sin que nadie se entere.
    //
    // Lo que hay que enseñar es el camino con prueba: `quipu::voprf`, conforme
    // a la RFC 9497. Corregido el 2026-08-01.
    println!("\n[2] VOPRF (RFC 9497): endurecimiento con prueba DLEQ verificada");
    let servidor = voprf::Server::from_seed(b"semilla-del-servidor-legitimo", b"demo")
        .expect("DeriveKeyPair");
    let pub_fijada = servidor.public_key();
    let pw = b"passphrase-del-usuario";

    let (st1, cegada1) = voprf::blind(pw).unwrap();
    let (z1, prueba1) = servidor.blind_evaluate(&cegada1).unwrap();
    let duro1 = voprf::finalize(pw, &st1, &z1, &prueba1, &pub_fijada).unwrap();

    let (st2, cegada2) = voprf::blind(pw).unwrap();
    let (z2, prueba2) = servidor.blind_evaluate(&cegada2).unwrap();
    let duro2 = voprf::finalize(pw, &st2, &z2, &prueba2, &pub_fijada).unwrap();

    println!("    misma passphrase -> mismo output endurecido: {}", duro1 == duro2);
    println!("    el servidor nunca vio la passphrase (cegado): {}", cegada1 != cegada2);

    // LO QUE ESTE EJEMPLO EXISTE PARA ENSEÑAR: un servidor deshonesto se DETECTA.
    // Se fabrica uno con otra clave y se le presenta al cliente, que sigue
    // fijando la clave pública del bueno. `finalize` tiene que negarse.
    let impostor = voprf::Server::from_seed(b"semilla-de-OTRO-servidor", b"demo")
        .expect("DeriveKeyPair");
    let (st3, cegada3) = voprf::blind(pw).unwrap();
    let (z3, prueba3) = impostor.blind_evaluate(&cegada3).unwrap();
    let colado = voprf::finalize(pw, &st3, &z3, &prueba3, &pub_fijada);
    println!("    un servidor DESHONESTO se detecta y se rechaza: {}", colado.is_none());
    assert!(
        colado.is_none(),
        "la prueba DLEQ no detectó un servidor con otra clave: eso es T4 abierto"
    );

    println!("\n========================================");
    println!("v2: post-cuantico + VOPRF verificable -> TODO OK");
}
