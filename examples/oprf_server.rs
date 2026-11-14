//! Servidor OPRF de Quipu (std-only) — desplegable en un VPS (p. ej. OVH).
//!
//!   cargo run --release --example oprf_server -- [puerto] [archivo_semilla]
//!
//! - Persiste la clave del servidor en un archivo (permisos 0600). Si la clave
//!   se pierde o cambia, TODOS los secretos endurecidos quedan irrecuperables:
//!   ¡haz backup offline de ese archivo!
//! - Rate-limit por IP con expiración y tope de memoria (`quipu::netlimit`).
//! - Timeouts de E/S por conexión (anti slowloris) + pool de hilos acotado
//!   (atiende clientes en paralelo, sin que uno lento bloquee a los demás).
//! - PRODUCCIÓN: poner detrás de TLS (nginx stream / stunnel) y systemd, y una
//!   capa anti-DDoS si el servicio es público (el rate-limit por IP no frena
//!   una botnet distribuida).

use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use quipu::netlimit::RateLimiter;
use quipu::oprf_net::handle_connection_verified;
use quipu::voprf::Server;

/// Consultas permitidas por IP dentro de la ventana.
const MAX_PER_WINDOW: u32 = 10;
/// Ventana deslizante del rate-limit.
const WINDOW: Duration = Duration::from_secs(60);
/// Tope de IPs distintas rastreadas en memoria.
const MAX_TRACKED_IPS: usize = 100_000;
/// Hilos trabajadores que atienden conexiones en paralelo.
const WORKERS: usize = 8;
/// Timeout de lectura/escritura por conexión: un cliente que no completa su
/// mensaje libera el worker en vez de bloquearlo indefinidamente (anti slowloris).
const IO_TIMEOUT: Duration = Duration::from_secs(10);

fn load_or_create_seed(path: &str) -> [u8; 32] {
    if let Ok(bytes) = std::fs::read(path)
        && bytes.len() == 32
    {
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes);
        println!("Clave del servidor cargada de {path}");
        return s;
    }
    let mut seed = [0u8; 32];
    quipu::aleatorio::llenar(&mut seed).expect("RNG del sistema");
    std::fs::write(path, seed).expect("escribir semilla");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    println!("Nueva clave de servidor generada y guardada en {path} (¡haz backup!)");
    seed
}

/// Atiende una conexión: fija timeouts, decide rate-limit y responde.
fn serve(mut stream: TcpStream, server: &Server, limiter: &Mutex<RateLimiter>) {
    // Sin timeouts, un cliente que abre y no envía nada retendría el worker
    // para siempre. Con ellos, `read_exact` falla y la conexión se descarta.
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));

    let ip = stream
        .peer_addr()
        .map(|a| a.ip())
        .unwrap_or(IpAddr::from([0, 0, 0, 0]));
    let allowed = limiter.lock().expect("rate-limiter mutex").allow(ip);

    if let Err(e) = handle_connection_verified(&mut stream, server, allowed) {
        eprintln!("error con {ip}: {e}");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let port: u16 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(9999);
    let seed_path = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "oprf_seed.bin".to_string());

    let seed = load_or_create_seed(&seed_path);
    // `info` de DeriveKeyPair (RFC 9497 §3.2): entra en la derivación, así que
    // cambiarlo cambia la clave. El servidor real usa "quipu-oprf-server-v1".
    let server = Arc::new(
        Server::from_seed(&seed, b"quipu-oprf-example").expect("DeriveKeyPair"),
    ); // VOPRF; rate-limit real va por IP
    let limiter = Arc::new(Mutex::new(RateLimiter::new(
        MAX_PER_WINDOW,
        WINDOW,
        MAX_TRACKED_IPS,
    )));

    // Clave pública a FIJAR (pin) en los clientes para que verifiquen la prueba.
    let pk_hex: String = server
        .public_key()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let listener = TcpListener::bind(("0.0.0.0", port)).expect("bind");
    println!("VOPRF server escuchando en 0.0.0.0:{port} ({WORKERS} workers)");
    println!("Clave pública (fíjala en el cliente): {pk_hex}");
    println!(
        "Rate-limit: {MAX_PER_WINDOW} consultas / {}s por IP",
        WINDOW.as_secs()
    );

    // Pool de hilos acotado: el aceptador solo encola; los workers atienden en
    // paralelo. Un cliente lento ocupa un worker (hasta IO_TIMEOUT), no el server.
    let (tx, rx) = mpsc::channel::<TcpStream>();
    let rx = Arc::new(Mutex::new(rx));
    for _ in 0..WORKERS {
        let rx = Arc::clone(&rx);
        let server = Arc::clone(&server);
        let limiter = Arc::clone(&limiter);
        thread::spawn(move || {
            loop {
                // Toma un trabajo (suelta el lock antes de atender).
                let job = rx.lock().expect("cola mutex").recv();
                match job {
                    Ok(stream) => serve(stream, &server, &limiter),
                    Err(_) => break, // canal cerrado
                }
            }
        });
    }

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                // Si todos los workers están ocupados, la conexión espera en la
                // cola; no se pierde ni bloquea el aceptador.
                let _ = tx.send(stream);
            }
            Err(_) => continue,
        }
    }
}
