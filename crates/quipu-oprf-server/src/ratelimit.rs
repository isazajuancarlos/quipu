// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Rate-limit de ráfaga por API key (token bucket en memoria).
//!
//! Es la defensa anti-DoS de corto plazo; la cuota mensual (en `store`) es el
//! límite de facturación. El servidor es de un solo hilo (tráfico limitado por
//! diseño), así que un `HashMap` bajo `&mut self` basta y es correcto.
//!
//! Los límites **no** viven aquí: se pasan en cada llamada porque dependen del
//! plan de quien presenta la clave (ver `plans::limits_for`). El limitador solo
//! sabe contar tokens; cuántos concede es una decisión comercial, y mezclar
//! ambas cosas fue justo lo que dejó a todos los planes con la misma ráfaga.

use std::collections::HashMap;
use std::time::Instant;

#[derive(Default)]
pub struct RateLimiter {
    buckets: HashMap<String, (f64, Instant)>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Consume un token para `key`, con los límites de SU plan.
    /// Devuelve `false` si no quedan (rechazar con 429).
    ///
    /// `capacity` es el tope de ráfaga y `refill_per_sec` el ritmo sostenido.
    /// Un cubo nuevo nace lleno: el primer uso de una clave no debe penalizarse.
    pub fn allow(&mut self, key: &str, capacity: f64, refill_per_sec: f64) -> bool {
        let now = Instant::now();
        let entry = self
            .buckets
            .entry(key.to_string())
            .or_insert((capacity, now));
        let (tokens, last) = entry;
        let elapsed = now.duration_since(*last).as_secs_f64();
        // Se recorta a `capacity` en cada paso: si el plan del cliente cambia a
        // uno menor, el cubo se ajusta solo en la siguiente petición en vez de
        // quedarse con crédito del plan anterior.
        *tokens = (*tokens + elapsed * refill_per_sec).min(capacity);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Cubos vivos. Solo para pruebas y diagnóstico.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_capacity_then_blocks() {
        let mut rl = RateLimiter::new();
        assert!(rl.allow("k", 3.0, 0.0)); // sin recarga
        assert!(rl.allow("k", 3.0, 0.0));
        assert!(rl.allow("k", 3.0, 0.0));
        assert!(!rl.allow("k", 3.0, 0.0)); // agotado
    }

    #[test]
    fn buckets_are_per_key() {
        let mut rl = RateLimiter::new();
        assert!(rl.allow("a", 1.0, 0.0));
        assert!(!rl.allow("a", 1.0, 0.0));
        assert!(rl.allow("b", 1.0, 0.0)); // otra key, su propio cubo
        assert_eq!(rl.len(), 2);
    }

    /// El fallo que motivó el cambio: dos claves de planes distintos deben
    /// recibir ráfagas distintas. Con los límites fijos en el limitador, esta
    /// prueba era imposible de escribir.
    #[test]
    fn different_plans_get_different_bursts() {
        let mut rl = RateLimiter::new();
        // El plan pequeño se agota a las 2; el grande sigue admitiendo.
        assert!(rl.allow("pequeno", 2.0, 0.0));
        assert!(rl.allow("pequeno", 2.0, 0.0));
        assert!(!rl.allow("pequeno", 2.0, 0.0));

        for _ in 0..10 {
            assert!(rl.allow("grande", 10.0, 0.0));
        }
        assert!(!rl.allow("grande", 10.0, 0.0));
    }

    /// Bajar de plan no debe dejar crédito del plan anterior.
    #[test]
    fn downgrading_the_plan_clamps_the_bucket() {
        let mut rl = RateLimiter::new();
        assert!(rl.allow("k", 100.0, 0.0)); // nace con 100, gasta 1 -> 99
        // Ahora el mismo cliente pasa a un plan de capacidad 2: el cubo se
        // recorta a 2, no conserva los 99.
        assert!(rl.allow("k", 2.0, 0.0));
        assert!(rl.allow("k", 2.0, 0.0));
        assert!(!rl.allow("k", 2.0, 0.0));
    }

    #[test]
    fn refills_over_time() {
        let mut rl = RateLimiter::new();
        assert!(rl.allow("k", 1.0, 1000.0));
        assert!(!rl.allow("k", 1.0, 1000.0)); // vacío al instante
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(rl.allow("k", 1.0, 1000.0)); // recargado
    }
}
