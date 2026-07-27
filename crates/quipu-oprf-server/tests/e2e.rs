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


/// GET crudo por TCP. El crate no arrastra un cliente HTTP para las pruebas y
/// no hace falta: la respuesta cabe en una lectura.
fn get(addr: &str, path: &str) -> String {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    write!(s, "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").unwrap();
    let mut buf = String::new();
    s.read_to_string(&mut buf).unwrap();
    buf
}

/// Petición cruda con el método que se le pida. Igual que `get`, pero HEAD.
fn peticion(addr: &str, metodo: &str, path: &str) -> String {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    write!(s, "{metodo} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").unwrap();
    let mut buf = String::new();
    s.read_to_string(&mut buf).unwrap();
    buf
}

/// La sonda del servicio no puede mentir sobre el servicio.
///
/// HEAD es lo que usan los monitores de disponibilidad, y aquí devolvía 404
/// donde GET devolvía 200: el enrutador solo contemplaba `Method::Get` y HEAD
/// caía al 404 final. Un monitor estándar habría dado el servicio por caído
/// desde el primer día — o alguien lo habría configurado para aceptar ese 404,
/// y entonces no avisaría el día que se cayera de verdad.
///
/// RFC 9110 §9.3.2: la respuesta a HEAD es la de GET sin cuerpo. Invariante I7.
/// Detectado el 2026-07-27 auditando producción con `verificar.py desplegado`.
#[test]
fn head_responde_igual_que_get_en_las_rutas_de_lectura() {
    let seed = [9u8; 32];
    let server_key = voprf::Server::from_seed(&seed, b"quipu-oprf-server-v1").unwrap();
    let store = Store::open_in_memory().unwrap();
    let addr = free_addr();
    let cfg = Config {
        addr: addr.clone(),
        admin_token: None,
    };
    thread::spawn(move || {
        let _ = http::serve(store, server_key, cfg);
    });
    wait_ready(&addr);

    for ruta in ["/healthz", "/v1/public-key", "/v1/plans"] {
        let g = peticion(&addr, "GET", ruta);
        let h = peticion(&addr, "HEAD", ruta);
        let estado = |r: &str| r.lines().next().unwrap_or("").to_string();
        assert_eq!(
            estado(&g),
            estado(&h),
            "HEAD {ruta} no coincide con GET: un monitor de disponibilidad mentiría",
        );
    }

    // Y que DISCRIMINE: una ruta que no existe debe seguir siendo 404 por los
    // dos métodos. Sin esto, «responder 200 a todo» pasaría la prueba de arriba.
    let inexistente = peticion(&addr, "HEAD", "/no-existe");
    assert!(
        inexistente.contains("404"),
        "HEAD sobre una ruta inexistente debe dar 404, no 200",
    );
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
    };
    thread::spawn(move || {
        let _ = http::serve(store, server_key, cfg);
    });
    wait_ready(&addr);

    let bogus = "quipu_live_".to_string() + &"a".repeat(64);
    assert!(client::harden(&addr, &bogus, b"x", &server_pub).is_err());
}

/// El catálogo publicado debe reflejar EXACTAMENTE lo que el servidor concede.
/// Es la costura que permite a la web comprobar que vende lo que aquí se otorga:
/// el descuadre que motivó esto (250 000 anunciadas, 100 000 concedidas) habría
/// sido invisible sin un sitio donde contrastarlo.
#[test]
fn plans_endpoint_publishes_what_the_server_grants() {
    use quipu_oprf_server::plans;

    let store = Store::open_in_memory().unwrap();
    let server_key = voprf::Server::from_seed(&[9u8; 32], b"test").unwrap();
    let addr = free_addr();
    let cfg = Config {
        addr: addr.clone(),
        admin_token: None,
    };
    thread::spawn(move || {
        let _ = http::serve(store, server_key, cfg);
    });
    wait_ready(&addr);

    let body = get(&addr, "/v1/plans");

    for p in plans::PLANS {
        assert!(
            body.contains(&format!("\"name\":\"{}\"", p.name)),
            "falta el plan {} en {body}",
            p.name
        );
        assert!(
            body.contains(&format!("\"quota_monthly\":{}", p.quota_monthly)),
            "la cuota de {} no coincide con la que concede el servidor: {body}",
            p.name
        );
    }
    // El plan retirado no puede seguir publicándose.
    assert!(!body.contains("\"name\":\"beta\""), "beta sigue anunciándose: {body}");
}
