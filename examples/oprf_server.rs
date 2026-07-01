//! Servidor OPRF de Quipu (std-only) — desplegable en un VPS (p. ej. OVH).
//!
//!   cargo run --release --example oprf_server -- [puerto] [archivo_semilla]
//!
//! - Persiste la clave del servidor en un archivo (permisos 0600). Si la clave
//!   se pierde o cambia, TODOS los secretos endurecidos quedan irrecuperables:
//!   ¡haz backup offline de ese archivo!
//! - Rate-limit por IP (ventana deslizante simple, en memoria).
//! - PRODUCCIÓN: poner detrás de TLS (nginx stream / stunnel) y systemd.

use std::collections::HashMap;
use std::net::{IpAddr, TcpListener};
use std::time::{Duration, Instant};

use quipu::oprf_net::handle_connection_verified;
use quipu::voprf::Server;

const MAX_PER_WINDOW: u32 = 10;
const WINDOW: Duration = Duration::from_secs(60);

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
    getrandom::getrandom(&mut seed).expect("RNG del sistema");
    std::fs::write(path, seed).expect("escribir semilla");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    println!("Nueva clave de servidor generada y guardada en {path} (¡haz backup!)");
    seed
}

/// Rate-limit por IP: como mucho MAX_PER_WINDOW consultas por ventana.
struct RateLimiter {
    hits: HashMap<IpAddr, (u32, Instant)>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            hits: HashMap::new(),
        }
    }

    fn allow(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let entry = self.hits.entry(ip).or_insert((0, now));
        if now.duration_since(entry.1) > WINDOW {
            *entry = (0, now); // reinicia la ventana
        }
        if entry.0 >= MAX_PER_WINDOW {
            return false;
        }
        entry.0 += 1;
        true
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
    let server = Server::from_seed(&seed); // VOPRF; rate-limit real va por IP
    let mut limiter = RateLimiter::new();

    // Clave pública a FIJAR (pin) en los clientes para que verifiquen la prueba.
    let pk_hex: String = server
        .public_key()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let listener = TcpListener::bind(("0.0.0.0", port)).expect("bind");
    println!("VOPRF server escuchando en 0.0.0.0:{port}");
    println!("Clave pública (fíjala en el cliente): {pk_hex}");
    println!(
        "Rate-limit: {MAX_PER_WINDOW} consultas / {}s por IP",
        WINDOW.as_secs()
    );

    for conn in listener.incoming() {
        let mut stream = match conn {
            Ok(s) => s,
            Err(_) => continue,
        };
        let ip = stream
            .peer_addr()
            .map(|a| a.ip())
            .unwrap_or(IpAddr::from([0, 0, 0, 0]));
        let allowed = limiter.allow(ip);
        if let Err(e) = handle_connection_verified(&mut stream, &server, allowed) {
            eprintln!("error con {ip}: {e}");
        }
    }
}
