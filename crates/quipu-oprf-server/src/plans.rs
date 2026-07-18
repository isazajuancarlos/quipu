// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Planes de suscripción y su cuota mensual (nº de evaluaciones OPRF/mes).

/// Cuota mensual por plan. `None` si el plan no existe.
pub fn quota_for(plan: &str) -> Option<u64> {
    match plan {
        "beta" => Some(10_000),
        "starter" => Some(100_000),
        "pro" => Some(1_000_000),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_plans_have_quota() {
        assert!(quota_for("beta").is_some());
        assert!(quota_for("pro").unwrap() > quota_for("starter").unwrap());
        assert_eq!(quota_for("nope"), None);
    }
}
