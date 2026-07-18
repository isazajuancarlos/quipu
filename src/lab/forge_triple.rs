// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Superficie 4 (triple): falsificación adaptativa contra el modo QSG3.
//!
//! Refleja `forge.rs` para el AND 3-de-3: frankensignature sobre cada uno de los
//! tres componentes, key-substitution y manipulación de región. Cualquier
//! `decode_verified_triple` que devuelva Ok sobre algo forjado es una brecha.

use crate::api::{decode_verified_triple, encode_signed_triple};
use crate::dictionaries;
use crate::lab::engine::{Attack, AttackOutcome, Rng};
use crate::pqsign;

/// Falsificador triple adaptativo.
pub struct ForgeTripleAttack;

impl ForgeTripleAttack {
    /// Nuevo ataque de falsificación triple.
    pub fn new() -> Self {
        Self
    }
}

impl Default for ForgeTripleAttack {
    fn default() -> Self {
        Self::new()
    }
}

impl Attack for ForgeTripleAttack {
    fn name(&self) -> &'static str {
        "forge/triple"
    }

    fn step(&mut self, rng: &mut Rng) -> AttackOutcome {
        let dict = dictionaries::ascii94();
        let (vk1, sk1) = pqsign::generate_triple_keypair();
        let (vk2, sk2) = pqsign::generate_triple_keypair();
        let message = b"orden triple del laboratorio";

        let ed_end = pqsign::ED25519_SIG_LEN;
        let ml_end = pqsign::ED25519_SIG_LEN + pqsign::MLDSA_SIG_LEN;

        match rng.below(3) {
            // Frankensignature: intercambia un componente (ed/ml/slh) de sk2.
            0 => {
                let sig1 = sk1.sign(message);
                let sig2 = sk2.sign(message);
                let which = rng.below(3);
                let spliced = match which {
                    0 => {
                        let mut s = sig2[..ed_end].to_vec();
                        s.extend_from_slice(&sig1[ed_end..]);
                        s
                    }
                    1 => {
                        let mut s = sig1[..ed_end].to_vec();
                        s.extend_from_slice(&sig2[ed_end..ml_end]);
                        s.extend_from_slice(&sig1[ml_end..]);
                        s
                    }
                    _ => {
                        let mut s = sig1[..ml_end].to_vec();
                        s.extend_from_slice(&sig2[ml_end..]);
                        s
                    }
                };
                // Reconstruye el artefacto QSG3 público a mano (Kerckhoffs).
                let mut blob = Vec::new();
                blob.extend_from_slice(b"QSG3");
                blob.push(1);
                blob.push(0);
                blob.extend_from_slice(&(message.len() as u32).to_be_bytes());
                blob.extend_from_slice(message);
                blob.extend_from_slice(&spliced);
                let indices = crate::codec::encode_base_n(&blob, dict.base());
                let artifact = dict.encode(&indices).expect("índices en rango");
                if decode_verified_triple(&artifact, &vk1, &dict).is_ok()
                    || decode_verified_triple(&artifact, &vk2, &dict).is_ok()
                {
                    return AttackOutcome::Breach(format!(
                        "frankensig triple (comp {which}) verificó"
                    ));
                }
                AttackOutcome::Advanced
            }
            // Key-substitution.
            1 => {
                let artifact = encode_signed_triple(message, &sk1, &dict);
                if decode_verified_triple(&artifact, &vk2, &dict).is_ok() {
                    return AttackOutcome::Breach(
                        "firma triple verificó con clave equivocada".into(),
                    );
                }
                AttackOutcome::Advanced
            }
            // Manipulación de región.
            _ => {
                let artifact = encode_signed_triple(message, &sk1, &dict);
                let mut chars: Vec<char> = artifact.chars().collect();
                if chars.is_empty() {
                    return AttackOutcome::NoProgress;
                }
                let pos = rng.below(chars.len());
                let idx = dict.symbol_to_index(chars[pos]).expect("símbolo propio");
                let new = dict
                    .index_to_symbol((idx + 1) % dict.base())
                    .expect("índice válido");
                if new == chars[pos] {
                    return AttackOutcome::NoProgress;
                }
                chars[pos] = new;
                let mutated: String = chars.into_iter().collect();
                if decode_verified_triple(&mutated, &vk1, &dict).is_ok() {
                    return AttackOutcome::Breach(format!("mutación triple en pos {pos} verificó"));
                }
                AttackOutcome::Advanced
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::engine::run;

    #[test]
    fn adaptive_triple_forgery_never_verifies() {
        // Pocas iteraciones a propósito: firmar SLH-DSA-256s es lento (~2 s/firma
        // en release). El motor es determinista (semilla fija), así que 12 pasadas
        // ejercitan las tres estrategias de forma reproducible sin castigar CI.
        let mut attack = ForgeTripleAttack::new();
        let report = run(&mut attack, 1337, 12);
        assert!(report.attempts > 0);
        assert!(
            report.is_clean(),
            "ninguna falsificación triple debe verificar: {:?}",
            report.breaches
        );
    }
}
