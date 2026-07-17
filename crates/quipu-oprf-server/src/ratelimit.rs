//! Rate-limit de ráfaga por API key (token bucket en memoria).
//!
//! Es la defensa anti-DoS de corto plazo; la cuota mensual (en `store`) es el
//! límite de facturación. El servidor es de un solo hilo (tráfico limitado por
//! diseño), así que un `HashMap` bajo `&mut self` basta y es correcto.

use std::collections::HashMap;
use std::time::Instant;

pub struct RateLimiter {
    capacity: f64,
    refill_per_sec: f64,
    buckets: HashMap<String, (f64, Instant)>,
}

impl RateLimiter {
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            capacity,
            refill_per_sec,
            buckets: HashMap::new(),
        }
    }

    /// Consume un token para `key`. Devuelve `false` si no quedan (rechazar).
    pub fn allow(&mut self, key: &str) -> bool {
        let now = Instant::now();
        let entry = self
            .buckets
            .entry(key.to_string())
            .or_insert((self.capacity, now));
        let (tokens, last) = entry;
        let elapsed = now.duration_since(*last).as_secs_f64();
        *tokens = (*tokens + elapsed * self.refill_per_sec).min(self.capacity);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_capacity_then_blocks() {
        let mut rl = RateLimiter::new(3.0, 0.0); // sin recarga
        assert!(rl.allow("k"));
        assert!(rl.allow("k"));
        assert!(rl.allow("k"));
        assert!(!rl.allow("k")); // agotado
    }

    #[test]
    fn buckets_are_per_key() {
        let mut rl = RateLimiter::new(1.0, 0.0);
        assert!(rl.allow("a"));
        assert!(!rl.allow("a"));
        assert!(rl.allow("b")); // otra key, su propio cubo
    }
}
