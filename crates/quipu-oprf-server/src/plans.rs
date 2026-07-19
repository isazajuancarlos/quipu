// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Planes de suscripción: cuota mensual y límites de ráfaga.
//!
//! **Fuente única de verdad de lo que recibe un cliente por su dinero.** Antes
//! la cuota vivía aquí y los límites de ráfaga estaban incrustados en `main.rs`,
//! iguales para todos: un cliente de `pro` pagaba 22 veces más que uno de `beta`
//! y recibía la misma ráfaga de 20. Tenerlo junto hace imposible subir un plan
//! y olvidarse de la mitad.
//!
//! Estos valores DEBEN coincidir con los que anuncia la web
//! (`quipu_sales.PLANS` en el portafolio) y con los planes de PayPal. Venderle a
//! alguien 250 000 evaluaciones y concederle 100 000 no es un descuadre
//! estético: como el cliente falla CERRADO, al toparse con el límite real sus
//! usuarios dejan de poder iniciar sesión.

/// Lo que un plan concede. Todo junto, a propósito.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Plan {
    /// Nombre tal como se factura.
    pub name: &'static str,
    /// Evaluaciones OPRF al mes. Límite duro: al agotarlo se responde 429.
    pub quota_monthly: u64,
    /// Tope de ráfaga instantánea (tokens del cubo).
    pub rate_capacity: f64,
    /// Ritmo sostenido de recarga, en tokens por segundo.
    pub rate_refill_per_sec: f64,
}

/// Planes que se venden hoy. `beta` se retiró en 2026-07 al pasar a Live: la vía
/// gratuita es auto-hospedar bajo AGPL, no un plan barato.
pub const PLANS: &[Plan] = &[
    Plan {
        name: "starter",
        quota_monthly: 250_000,
        rate_capacity: 60.0,
        rate_refill_per_sec: 30.0,
    },
    Plan {
        name: "pro",
        quota_monthly: 1_500_000,
        rate_capacity: 200.0,
        rate_refill_per_sec: 100.0,
    },
];

/// Límites para una clave cuyo plan no reconocemos (fila heredada, plan
/// retirado). Deliberadamente modestos pero NO nulos: negarle el paso a alguien
/// que ya pagó porque no encontramos su plan en una tabla sería el peor fallo
/// posible — el cliente falla cerrado y sus usuarios se quedan fuera.
pub const FALLBACK: Plan = Plan {
    name: "desconocido",
    quota_monthly: 10_000,
    rate_capacity: 20.0,
    rate_refill_per_sec: 10.0,
};

/// El plan por su nombre, o `None` si no se vende.
pub fn plan_for(name: &str) -> Option<&'static Plan> {
    PLANS.iter().find(|p| p.name == name)
}

/// Límites aplicables a un plan, cayendo a `FALLBACK` si no se reconoce.
/// Se usa en la ruta de evaluación, donde rechazar nunca es una opción válida.
pub fn limits_for(name: &str) -> Plan {
    plan_for(name).copied().unwrap_or(FALLBACK)
}

/// Cuota mensual por plan. `None` si el plan no existe — aquí sí se rechaza:
/// emitir una clave para un plan inventado sería un error de configuración.
pub fn quota_for(plan: &str) -> Option<u64> {
    plan_for(plan).map(|p| p.quota_monthly)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_plans_have_quota() {
        assert!(quota_for("starter").is_some());
        assert!(quota_for("pro").unwrap() > quota_for("starter").unwrap());
        assert_eq!(quota_for("nope"), None);
    }

    /// Fija las cifras que se anuncian y se cobran. Si alguien cambia un plan
    /// aquí sin cambiarlo en la web y en PayPal, esta prueba lo delata.
    /// El caso real: la web vendía Starter con 250 000 y el servidor concedía
    /// 100 000 — el 40 % de lo comprado.
    #[test]
    fn quotas_match_what_is_sold() {
        assert_eq!(quota_for("starter"), Some(250_000));
        assert_eq!(quota_for("pro"), Some(1_500_000));
    }

    /// El defecto que motivó reunir todo aquí: los límites de ráfaga eran
    /// idénticos para todos los planes.
    #[test]
    fn rate_limits_scale_with_the_plan() {
        let s = plan_for("starter").unwrap();
        let p = plan_for("pro").unwrap();
        assert!(p.rate_capacity > s.rate_capacity);
        assert!(p.rate_refill_per_sec > s.rate_refill_per_sec);
    }

    /// Un plan desconocido NO puede dejar sin servicio a quien ya pagó.
    #[test]
    fn unknown_plan_falls_back_instead_of_denying() {
        let l = limits_for("un-plan-que-ya-no-existe");
        assert_eq!(l, FALLBACK);
        assert!(l.rate_capacity > 0.0);
        assert!(l.rate_refill_per_sec > 0.0);
        assert!(l.quota_monthly > 0);
    }

    /// Un plan retirado deja de poder emitirse, pero sigue siendo tolerado por
    /// `limits_for`. Son decisiones distintas y conviene que no se confundan.
    #[test]
    fn retired_plan_cannot_be_issued_but_is_tolerated_at_runtime() {
        assert_eq!(quota_for("beta"), None);
        assert_eq!(limits_for("beta"), FALLBACK);
    }
}
