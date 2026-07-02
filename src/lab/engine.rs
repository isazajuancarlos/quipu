//! Motor del laboratorio: PRNG determinista + bucle de ataque guiado por brechas.

/// PRNG determinista (SplitMix64). NO es criptográfico: sirve SOLO para hacer los
/// ataques reproducibles con una semilla fija (CI verde y auditable).
pub struct Rng {
    state: u64,
}

impl Rng {
    /// Crea un generador con semilla fija.
    pub fn seeded(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Siguiente valor de 64 bits (SplitMix64).
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Entero uniforme en `[0, n)`. Devuelve 0 si `n == 0`.
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.next_u64() % n as u64) as usize
    }

    /// Un byte pseudoaleatorio.
    pub fn byte(&mut self) -> u8 {
        self.next_u64() as u8
    }
}

/// Resultado de un paso de ataque.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttackOutcome {
    /// El paso se acercó a una brecha (guía la búsqueda), sin romper nada.
    Advanced,
    /// ¡Brecha! La librería aceptó indebidamente algo forjado/alterado.
    Breach(String),
    /// El paso no aportó información nueva.
    NoProgress,
}

/// Un ataque adaptativo contra Quipu. Cada superficie implementa este trait como
/// una unidad aislada y testeable.
pub trait Attack {
    /// Nombre estable del ataque (aparece en el reporte).
    fn name(&self) -> &'static str;
    /// Ejecuta un intento. `rng` es determinista: el ataque debe ser reproducible.
    fn step(&mut self, rng: &mut Rng) -> AttackOutcome;
}

/// Reporte de una corrida de ataque.
#[derive(Debug, Clone)]
pub struct LabReport {
    /// Nombre del ataque.
    pub name: &'static str,
    /// Intentos realizados.
    pub attempts: usize,
    /// Pasos que se "acercaron" (guía; no son brechas).
    pub advances: usize,
    /// Brechas: cada una es un fallo real que hay que convertir en regresión.
    pub breaches: Vec<String>,
}

impl LabReport {
    /// `true` si no hubo ninguna brecha.
    pub fn is_clean(&self) -> bool {
        self.breaches.is_empty()
    }
}

/// Corre `attack` durante `budget` pasos con una semilla fija (reproducible) y
/// acumula las brechas encontradas.
pub fn run(attack: &mut dyn Attack, seed: u64, budget: usize) -> LabReport {
    let mut rng = Rng::seeded(seed);
    let mut report = LabReport {
        name: attack.name(),
        attempts: 0,
        advances: 0,
        breaches: Vec::new(),
    };
    for _ in 0..budget {
        report.attempts += 1;
        match attack.step(&mut rng) {
            AttackOutcome::Advanced => report.advances += 1,
            AttackOutcome::Breach(detail) => report.breaches.push(detail),
            AttackOutcome::NoProgress => {}
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prng_is_deterministic_for_a_seed() {
        let mut a = Rng::seeded(42);
        let mut b = Rng::seeded(42);
        let seq_a: Vec<u64> = (0..8).map(|_| a.next_u64()).collect();
        let seq_b: Vec<u64> = (0..8).map(|_| b.next_u64()).collect();
        assert_eq!(seq_a, seq_b, "misma semilla debe dar misma secuencia");
    }

    #[test]
    fn prng_differs_across_seeds() {
        let mut a = Rng::seeded(1);
        let mut b = Rng::seeded(2);
        assert_ne!(a.next_u64(), b.next_u64(), "semillas distintas divergen");
    }

    #[test]
    fn below_stays_in_range() {
        let mut r = Rng::seeded(7);
        for _ in 0..1000 {
            assert!(r.below(10) < 10);
        }
    }

    struct BreachOnThird {
        count: usize,
    }
    impl Attack for BreachOnThird {
        fn name(&self) -> &'static str {
            "breach-on-third"
        }
        fn step(&mut self, _rng: &mut Rng) -> AttackOutcome {
            self.count += 1;
            if self.count == 3 {
                AttackOutcome::Breach("simulada".into())
            } else {
                AttackOutcome::Advanced
            }
        }
    }

    #[test]
    fn run_collects_breaches_and_is_reproducible() {
        let mut a = BreachOnThird { count: 0 };
        let report = run(&mut a, 99, 5);
        assert_eq!(report.attempts, 5);
        assert_eq!(report.advances, 4);
        assert_eq!(report.breaches, vec!["simulada".to_string()]);
        assert!(!report.is_clean());
    }

    #[test]
    fn clean_report_has_no_breaches() {
        struct Always(AttackOutcome);
        impl Attack for Always {
            fn name(&self) -> &'static str {
                "always"
            }
            fn step(&mut self, _rng: &mut Rng) -> AttackOutcome {
                match self.0 {
                    AttackOutcome::NoProgress => AttackOutcome::NoProgress,
                    _ => AttackOutcome::Advanced,
                }
            }
        }
        let mut a = Always(AttackOutcome::NoProgress);
        let report = run(&mut a, 1, 10);
        assert!(report.is_clean());
        assert_eq!(report.advances, 0);
    }
}
