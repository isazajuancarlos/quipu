//! Fuzzer del parser honey: alimenta bytes ADVERSARIOS a `honey::decrypt` y
//! exige que nunca entre en pánico ni asigne memoria sin cota — solo puede
//! devolver `Ok(señuelo)` o un error estructural. Un pánico es brecha.
//!
//! Cubre el hueco que dejan los tests dirigidos: entradas totalmente arbitrarias,
//! cabeceras casi-válidas, longitudes declaradas gigantes, parámetros KDF
//! absurdos y contenedores válidos truncados o con cola basura.

use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::honey::{decrypt, encrypt_pin, HoneyOptions};
use crate::kdf::{KdfParams, SALT_LEN};
use crate::lab::engine::{Attack, AttackOutcome, Rng};

const MAGIC: [u8; 4] = *b"QHNY";

fn cheap() -> HoneyOptions<'static> {
    HoneyOptions {
        pepper: b"",
        kdf_params: KdfParams {
            mem_kib: 64,
            iterations: 1,
            parallelism: 1,
        },
    }
}

/// Fuzzer de robustez del parser honey.
pub struct HoneyFuzz;

impl HoneyFuzz {
    /// Nuevo fuzzer.
    pub fn new() -> Self {
        Self
    }
}

impl Default for HoneyFuzz {
    fn default() -> Self {
        Self::new()
    }
}

impl Attack for HoneyFuzz {
    fn name(&self) -> &'static str {
        "honey/parser-fuzz"
    }

    fn step(&mut self, rng: &mut Rng) -> AttackOutcome {
        let blob = build_adversarial(rng);
        let n = blob.len();
        // Un pánico dentro de decrypt es exactamente lo que buscamos: lo atrapamos
        // para reportarlo como brecha en vez de abortar la corrida.
        let res = catch_unwind(AssertUnwindSafe(|| {
            let _ = decrypt(&blob, "clave-fuzz", b"");
        }));
        if res.is_err() {
            return AttackOutcome::Breach(format!("pánico en honey::decrypt con {n} bytes"));
        }
        AttackOutcome::Advanced
    }
}

/// Cabecera honey estructuralmente bien formada con `declared_len` como longitud.
fn valid_header(rng: &mut Rng, declared_len: u32) -> Vec<u8> {
    let mut v = MAGIC.to_vec();
    v.push(1); // versión
    for _ in 0..SALT_LEN {
        v.push(rng.byte());
    }
    v.extend_from_slice(&64u32.to_be_bytes()); // mem_kib
    v.extend_from_slice(&1u32.to_be_bytes()); // iterations
    v.extend_from_slice(&1u32.to_be_bytes()); // parallelism
    v.extend_from_slice(&10u16.to_be_bytes()); // alphabet A
    v.extend_from_slice(&declared_len.to_be_bytes()); // L
    v
}

fn build_adversarial(rng: &mut Rng) -> Vec<u8> {
    match rng.below(6) {
        // Bytes puramente aleatorios de longitud variable.
        0 => (0..rng.below(200)).map(|_| rng.byte()).collect(),
        // Magic válido + resto arbitrario (fuerza el parseo profundo).
        1 => {
            let mut v = MAGIC.to_vec();
            for _ in 0..rng.below(80) {
                v.push(rng.byte());
            }
            v
        }
        // Cabecera válida con longitud declarada GIGANTE (prueba la cota de memoria).
        2 => valid_header(rng, u32::MAX),
        // Cabecera válida con parámetros KDF absurdos (prueba el is_sane anti-DoS).
        3 => {
            let mut v = valid_header(rng, 4);
            let off = 5 + SALT_LEN; // mem_kib
            v[off..off + 4].copy_from_slice(&u32::MAX.to_be_bytes());
            v
        }
        // Contenedor válido truncado a la mitad.
        4 => {
            let full = encrypt_pin("4913", "otra", &cheap()).expect("cifrado");
            full[..full.len() / 2].to_vec()
        }
        // Contenedor válido con cola de bytes basura.
        _ => {
            let mut full = encrypt_pin("4913", "otra", &cheap()).expect("cifrado");
            for _ in 0..rng.below(40) {
                full.push(rng.byte());
            }
            full
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::engine::run;

    #[test]
    fn honey_parser_never_panics_on_adversarial_input() {
        let mut fuzz = HoneyFuzz::new();
        let report = run(&mut fuzz, 0xF0F0, 1000);
        assert!(report.attempts > 0);
        assert!(
            report.is_clean(),
            "el parser honey no debe entrar en pánico: {:?}",
            report.breaches
        );
    }
}
