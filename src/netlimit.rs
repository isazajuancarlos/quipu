//! Rate-limiter por IP para el servidor OPRF online.
//!
//! Endurece dos problemas del contador ingenuo (hallazgo O3 de la auditoría):
//!   - **Crecimiento de memoria sin límite**: el mapa expira entradas viejas y
//!     tiene un tope de IPs rastreadas; al alcanzarlo, deja de admitir IPs
//!     nuevas (fail-closed en memoria) en lugar de crecer indefinidamente.
//!   - Sigue siendo por-IP: NO frena una botnet distribuida (eso es trabajo de
//!     una capa anti-DDoS/proxy por delante); acota el guessing de una fuente.
//!
//! Es `std`-only, igual que el resto del transporte OPRF.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Contador de consultas por IP con ventana deslizante y expiración.
pub struct RateLimiter {
    hits: HashMap<IpAddr, (u32, Instant)>,
    max_per_window: u32,
    window: Duration,
    max_tracked: usize,
}

impl RateLimiter {
    /// - `max_per_window`: consultas permitidas por IP dentro de `window`.
    /// - `window`: duración de la ventana deslizante.
    /// - `max_tracked`: tope de IPs distintas en memoria (acota el consumo).
    pub fn new(max_per_window: u32, window: Duration, max_tracked: usize) -> Self {
        Self {
            hits: HashMap::new(),
            max_per_window,
            window,
            max_tracked: max_tracked.max(1),
        }
    }

    /// `true` si la IP puede consultar ahora; actualiza el contador.
    pub fn allow(&mut self, ip: IpAddr) -> bool {
        self.allow_at(ip, Instant::now())
    }

    /// Núcleo con tiempo inyectable (para tests deterministas).
    fn allow_at(&mut self, ip: IpAddr, now: Instant) -> bool {
        // Al alcanzar el tope de memoria, purga las entradas ya expiradas.
        if self.hits.len() >= self.max_tracked {
            let window = self.window;
            self.hits
                .retain(|_, (_, seen)| now.duration_since(*seen) <= window);
            // Si tras purgar sigue lleno, rechaza IPs NUEVAS (no dejes crecer el
            // mapa). Las IPs ya rastreadas siguen atendiéndose con su cuota.
            if self.hits.len() >= self.max_tracked && !self.hits.contains_key(&ip) {
                return false;
            }
        }

        let entry = self.hits.entry(ip).or_insert((0, now));
        if now.duration_since(entry.1) > self.window {
            *entry = (0, now); // ventana expirada: reinicia
        }
        if entry.0 >= self.max_per_window {
            return false;
        }
        entry.0 += 1;
        true
    }

    /// Nº de IPs actualmente rastreadas (para observabilidad/tests).
    pub fn tracked(&self) -> usize {
        self.hits.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    #[test]
    fn allows_up_to_the_limit_then_denies() {
        let mut rl = RateLimiter::new(3, Duration::from_secs(60), 1000);
        let t = Instant::now();
        assert!(rl.allow_at(ip(1), t));
        assert!(rl.allow_at(ip(1), t));
        assert!(rl.allow_at(ip(1), t));
        assert!(!rl.allow_at(ip(1), t), "la 4ª en la ventana se deniega");
    }

    #[test]
    fn window_resets_after_expiry() {
        let mut rl = RateLimiter::new(1, Duration::from_secs(60), 1000);
        let t0 = Instant::now();
        assert!(rl.allow_at(ip(1), t0));
        assert!(!rl.allow_at(ip(1), t0), "consumida la cuota");
        // Pasada la ventana, la cuota se reinicia.
        let t1 = t0 + Duration::from_secs(120);
        assert!(rl.allow_at(ip(1), t1));
    }

    #[test]
    fn independent_ips_have_independent_quotas() {
        let mut rl = RateLimiter::new(1, Duration::from_secs(60), 1000);
        let t = Instant::now();
        assert!(rl.allow_at(ip(1), t));
        assert!(rl.allow_at(ip(2), t), "otra IP tiene su propia cuota");
    }

    #[test]
    fn caps_tracked_ips_and_denies_new_ones_when_full() {
        // Tope de 4 IPs. Cinco IPs distintas dentro de la ventana: la 5ª se
        // rechaza en vez de hacer crecer el mapa (fail-closed en memoria).
        let mut rl = RateLimiter::new(10, Duration::from_secs(60), 4);
        let t = Instant::now();
        for n in 0..4 {
            assert!(rl.allow_at(ip(n), t));
        }
        assert_eq!(rl.tracked(), 4);
        assert!(!rl.allow_at(ip(99), t), "IP nueva con el mapa lleno: denegada");
        assert_eq!(rl.tracked(), 4, "el mapa no crece más allá del tope");
    }

    #[test]
    fn expired_entries_are_evicted_to_make_room() {
        // Con el mapa lleno de entradas EXPIRADAS, una IP nueva entra tras purga.
        let mut rl = RateLimiter::new(10, Duration::from_secs(60), 4);
        let t0 = Instant::now();
        for n in 0..4 {
            assert!(rl.allow_at(ip(n), t0));
        }
        // Mucho después: las 4 están expiradas; la nueva las purga y entra.
        let t1 = t0 + Duration::from_secs(600);
        assert!(rl.allow_at(ip(99), t1));
        assert!(rl.tracked() <= 4);
    }
}
