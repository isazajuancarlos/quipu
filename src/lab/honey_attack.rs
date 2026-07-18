// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Superficie honey: busca un **oráculo de éxito** contra el cifrado con
//! señuelos. Sobre un contenedor honey válido, el atacante prueba passphrases al
//! azar. La propiedad a romper: que la passphrase *correcta* se distinga de las
//! equivocadas por algún rasgo estructural del resultado.
//!
//! Es brecha si alguna passphrase (correcta o no) se comporta distinto: un
//! error de "clave", un secreto de longitud errónea, o un token inválido. Si
//! todas devuelven un secreto plausible e indistinguible, el atacante no avanza
//! — que es exactamente lo que Honey Encryption promete.

use crate::honey::{decrypt, encrypt, Alphabet, HoneyOptions};
use crate::kdf::KdfParams;
use crate::lab::engine::{Attack, AttackOutcome, Rng};

const ALPHABET: u16 = 10; // PIN decimal
const LEN: usize = 6;

fn opts() -> HoneyOptions<'static> {
    HoneyOptions {
        pepper: b"",
        kdf_params: KdfParams {
            mem_kib: 64,
            iterations: 1,
            parallelism: 1,
        },
    }
}

/// Atacante que busca un oráculo de éxito en el modo honey.
pub struct HoneyAttack;

impl HoneyAttack {
    /// Nuevo ataque honey.
    pub fn new() -> Self {
        Self
    }
}

impl Default for HoneyAttack {
    fn default() -> Self {
        Self::new()
    }
}

impl Attack for HoneyAttack {
    fn name(&self) -> &'static str {
        "honey/success-oracle"
    }

    fn step(&mut self, rng: &mut Rng) -> AttackOutcome {
        let ab = Alphabet::new(ALPHABET).expect("alfabeto válido");
        // Secreto real aleatorio y su cifrado.
        let secret: Vec<u16> = (0..LEN).map(|_| rng.below(ALPHABET as usize) as u16).collect();
        let real_pw = format!("real-{}", rng.next_u64());
        let blob = encrypt(&secret, ab, &real_pw, &opts()).expect("cifrado honey");

        // La passphrase correcta DEBE recuperar el secreto (correctitud).
        match decrypt(&blob, &real_pw, b"") {
            Ok(t) if t == secret => {}
            _ => return AttackOutcome::Breach("la passphrase correcta no recuperó el secreto".into()),
        }

        // Ahora el atacante prueba passphrases equivocadas: ninguna debe delatar
        // que lo es. Todas tienen que dar un secreto estructuralmente válido.
        for _ in 0..8 {
            let guess = format!("guess-{}", rng.next_u64());
            match decrypt(&blob, &guess, b"") {
                Ok(t) => {
                    if t.len() != LEN {
                        return AttackOutcome::Breach("señuelo con longitud distinta: oráculo".into());
                    }
                    if t.iter().any(|&x| x >= ALPHABET) {
                        return AttackOutcome::Breach("señuelo con token inválido: oráculo".into());
                    }
                }
                // Un error para una passphrase equivocada ES un oráculo de éxito.
                Err(e) => {
                    return AttackOutcome::Breach(format!("passphrase equivocada devolvió error {e:?}: oráculo"));
                }
            }
        }
        AttackOutcome::Advanced
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::engine::run;

    #[test]
    fn honey_exposes_no_success_oracle() {
        let mut attack = HoneyAttack::new();
        let report = run(&mut attack, 909_090, 60);
        assert!(report.attempts > 0);
        assert!(
            report.is_clean(),
            "el modo honey no debe delatar la passphrase correcta: {:?}",
            report.breaches
        );
    }
}
