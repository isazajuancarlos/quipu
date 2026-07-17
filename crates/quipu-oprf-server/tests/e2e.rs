//! Test de integración de punta a punta (M1–M4): levanta el servidor HTTP en un
//! hilo, emite una API key y corre el cliente de endurecimiento, comparando el
//! resultado con un cálculo VOPRF independiente. Sin dependencias externas ni
//! servidor previo: solo `cargo test -p quipu-oprf-server`.

use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use quipu::voprf;
use quipu_oprf_server::client;
use quipu_oprf_server::http::{self, Config};
use quipu_oprf_server::store::Store;

/// Reserva un puerto libre efímero y lo libera para que lo tome el servidor.
fn free_addr() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    format!("127.0.0.1:{port}")
}

fn wait_ready(addr: &str) {
    for _ in 0..100 {
        if client::fetch_public_key(addr).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("el servidor no arrancó en {addr}");
}

#[test]
fn end_to_end_hardening() {
    let seed = [7u8; 32];
    let server_key = voprf::Server::from_seed(&seed, b"quipu-oprf-server-v1").unwrap();
    let server_pub = server_key.public_key();

    // Emite la key ANTES de mover el store al hilo del servidor.
    let store = Store::open_in_memory().unwrap();
    let customer = store.create_customer("t@example.com", "pro").unwrap();
    let api_key = store.issue_key(&customer, 1000, None).unwrap().secret;

    let addr = free_addr();
    let cfg = Config {
        addr: addr.clone(),
        admin_token: None,
        rate_capacity: 100.0,
        rate_refill_per_sec: 100.0,
    };
    {
        let addr = addr.clone();
        thread::spawn(move || {
            // Silencioso si el puerto se tomó entre free_addr() y el bind:
            // wait_ready hará panic con un mensaje claro.
            let _ = http::serve(store, server_key, cfg);
            let _ = addr;
        });
    }
    wait_ready(&addr);

    let pw = b"contrasena-del-usuario";
    let hardened = client::harden(&addr, &api_key, pw, &server_pub).expect("harden");

    // Verificación independiente: mismo (password, k) => mismo output.
    let reference = voprf::Server::from_seed(&seed, b"quipu-oprf-server-v1").unwrap();
    let (st, blinded) = voprf::blind(pw).unwrap();
    let (z, proof) = reference.blind_evaluate(&blinded).unwrap();
    let expected = voprf::finalize(pw, &st, &z, &proof, &server_pub).unwrap();
    assert_eq!(hardened, expected, "el secreto por HTTP debe igualar al directo");

    // Determinismo a través del transporte.
    let again = client::harden(&addr, &api_key, pw, &server_pub).expect("harden 2");
    assert_eq!(hardened, again);

    // Clave pública fijada incorrecta (servidor "suplantado") => rechazo.
    let wrong_pub = voprf::Server::from_seed(&[9u8; 32], b"quipu-oprf-server-v1").unwrap().public_key();
    assert!(
        client::harden(&addr, &api_key, pw, &wrong_pub).is_err(),
        "una clave pública fijada incorrecta debe rechazar la prueba DLEQ"
    );
}

#[test]
fn rejects_unknown_api_key() {
    let seed = [3u8; 32];
    let server_key = voprf::Server::from_seed(&seed, b"quipu-oprf-server-v1").unwrap();
    let server_pub = server_key.public_key();
    let store = Store::open_in_memory().unwrap(); // sin keys emitidas

    let addr = free_addr();
    let cfg = Config {
        addr: addr.clone(),
        admin_token: None,
        rate_capacity: 100.0,
        rate_refill_per_sec: 100.0,
    };
    thread::spawn(move || {
        let _ = http::serve(store, server_key, cfg);
    });
    wait_ready(&addr);

    let bogus = "quipu_live_".to_string() + &"a".repeat(64);
    assert!(client::harden(&addr, &bogus, b"x", &server_pub).is_err());
}
