// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Superficie 1: distinguidor de fuga en ciphertext/formato.
//!
//! ¿El contenedor / Padmé / codec base-N filtran estructura del plaintext? Como
//! el AEAD no depende del contenido en longitud y Padmé rellena por longitud, dos
//! plaintexts del MISMO tamaño deben producir la MISMA cantidad de símbolos. Si no,
//! la longitud de salida filtra el contenido: brecha.

use crate::api::{encode, Options};
use crate::dictionaries;
use crate::kdf::KdfParams;
use crate::lab::engine::{Attack, AttackOutcome, Rng};

/// Ataca la confidencialidad estructural: busca que la LONGITUD de salida dependa
/// del CONTENIDO (no solo del tamaño) del plaintext.
pub struct LeakAttack;

impl LeakAttack {
    /// Nuevo ataque de fuga.
    pub fn new() -> Self {
        Self
    }
}

impl Default for LeakAttack {
    fn default() -> Self {
        Self::new()
    }
}

impl Attack for LeakAttack {
    fn name(&self) -> &'static str {
        "leak/length"
    }

    fn step(&mut self, rng: &mut Rng) -> AttackOutcome {
        let dict = dictionaries::ascii94();
        // Coste KDF barato para que el barrido sea ágil (no afecta la longitud).
        let opts = Options {
            pepper: b"",
            kdf_params: KdfParams {
                mem_kib: 64,
                iterations: 1,
                parallelism: 1,
            },
            codebook_id: 0,
        };

        // Longitud común, contenidos distintos: uno estructurado, uno aleatorio.
        let len = 1 + rng.below(256);
        let structured = vec![0xABu8; len];
        let random: Vec<u8> = (0..len).map(|_| rng.byte()).collect();

        let a = encode(&structured, "clave-lab", &dict, &opts);
        let b = encode(&random, "clave-lab", &dict, &opts);

        if a.chars().count() != b.chars().count() {
            AttackOutcome::Breach(format!(
                "longitud de salida depende del contenido (len={len}): {} vs {}",
                a.chars().count(),
                b.chars().count()
            ))
        } else {
            AttackOutcome::Advanced
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::engine::run;

    #[test]
    fn length_does_not_leak_plaintext_content() {
        let mut attack = LeakAttack::new();
        let report = run(&mut attack, 20260701, 64);
        assert!(report.attempts > 0);
        assert!(
            report.is_clean(),
            "la longitud de salida no debe depender del contenido: {:?}",
            report.breaches
        );
    }
}
