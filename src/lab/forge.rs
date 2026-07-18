// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Superficie 4: falsificación adaptativa contra el modo firmado (QSG1).
//!
//! Tres estrategias que un atacante consciente de Kerckhoffs intentaría:
//!
//! - Frankensignature: mezclar el componente Ed25519 de una firma con el
//!   componente ML-DSA de otra (el combinador AND debe rechazar).
//! - Key-substitution: firmar con una clave y verificar con otra.
//! - Manipulación de región: mutar un símbolo del artefacto válido.
//!
//! Cualquier `decode_verified` que devuelva Ok sobre algo forjado es una brecha.

use crate::api::{decode_verified, encode_signed};
use crate::dictionaries;
use crate::lab::engine::{Attack, AttackOutcome, Rng};
use crate::pqsign;

/// Cabecera pública QSG1 antes del mensaje (magic+version+flags+len).
const QSG1_PREFIX_LEN: usize = 4 + 1 + 1 + 4;

/// Ensambla un artefacto QSG1 crudo (formato público) y lo representa con `dict`.
/// El atacante conoce el formato: reconstruirlo es legítimo (Kerckhoffs).
fn build_qsg1(message: &[u8], signature: &[u8], dict: &crate::dictionary::Dictionary) -> String {
    let mut blob = Vec::with_capacity(QSG1_PREFIX_LEN + message.len() + signature.len());
    blob.extend_from_slice(b"QSG1");
    blob.push(1u8); // version
    blob.push(0u8); // flags
    blob.extend_from_slice(&(message.len() as u32).to_be_bytes());
    blob.extend_from_slice(message);
    blob.extend_from_slice(signature);
    let indices = crate::codec::encode_base_n(&blob, dict.base());
    dict.encode(&indices).expect("índices en rango")
}

/// Falsificador adaptativo: rota entre estrategias según el PRNG.
pub struct ForgeAttack;

impl ForgeAttack {
    /// Nuevo ataque de falsificación.
    pub fn new() -> Self {
        Self
    }
}

impl Default for ForgeAttack {
    fn default() -> Self {
        Self::new()
    }
}

impl Attack for ForgeAttack {
    fn name(&self) -> &'static str {
        "forge/adaptive"
    }

    fn step(&mut self, rng: &mut Rng) -> AttackOutcome {
        let dict = dictionaries::ascii94();
        let (vk1, sk1) = pqsign::generate_keypair();
        let (vk2, sk2) = pqsign::generate_keypair();
        let message = b"orden firmada del laboratorio";

        match rng.below(3) {
            // 1) Frankensignature: Ed25519 de sk1 + ML-DSA de sk2.
            0 => {
                let sig1 = sk1.sign(message);
                let sig2 = sk2.sign(message);
                let mut spliced = Vec::with_capacity(pqsign::SIGNATURE_LEN);
                spliced.extend_from_slice(&sig1[..pqsign::ED25519_SIG_LEN]);
                spliced.extend_from_slice(&sig2[pqsign::ED25519_SIG_LEN..]);
                let artifact = build_qsg1(message, &spliced, &dict);
                if decode_verified(&artifact, &vk1, &dict).is_ok() {
                    return AttackOutcome::Breach("frankensignature verificó bajo vk1".into());
                }
                if decode_verified(&artifact, &vk2, &dict).is_ok() {
                    return AttackOutcome::Breach("frankensignature verificó bajo vk2".into());
                }
                AttackOutcome::Advanced
            }
            // 2) Key-substitution: firma de sk1 verificada con vk2.
            1 => {
                let artifact = encode_signed(message, &sk1, &dict);
                if decode_verified(&artifact, &vk2, &dict).is_ok() {
                    return AttackOutcome::Breach("firma verificó con clave equivocada".into());
                }
                AttackOutcome::Advanced
            }
            // 3) Manipulación de región: mutar un símbolo del artefacto válido.
            _ => {
                let artifact = encode_signed(message, &sk1, &dict);
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
                if decode_verified(&mutated, &vk1, &dict).is_ok() {
                    return AttackOutcome::Breach(format!("mutación en pos {pos} verificó"));
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
    fn adaptive_forgery_never_verifies() {
        let mut attack = ForgeAttack::new();
        let report = run(&mut attack, 1337, 90);
        assert!(report.attempts > 0);
        assert!(
            report.is_clean(),
            "ninguna falsificación debe verificar: {:?}",
            report.breaches
        );
    }
}
