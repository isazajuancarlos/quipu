//! Superficie 3 (banco offline): modelo de coste de guessing acelerado por IA.
//!
//! Un atacante prioriza contraseñas con un modelo local (aquí, una lista "rankeada"
//! simulada). Lo que protege a Quipu NO es ocultar el ranking: es que CADA intento
//! cuesta una derivación Argon2id memory-hard. Este banco verifica que ningún
//! intento del ranking descifra y estima el coste por intento (el piso que arruina
//! el guessing masivo, con o sin IA).

use crate::api::{decode, encode, Options};
use crate::dictionaries;
use crate::kdf::KdfParams;
use crate::lab::engine::Rng;
use std::time::{Duration, Instant};

/// Resultado del modelo de coste de guessing.
pub struct GuessReport {
    /// Intentos del ranking probados.
    pub attempts: usize,
    /// Cuántos descifraron (debe ser 0).
    pub cracked: usize,
    /// Tiempo total del barrido.
    pub total: Duration,
    /// Coste medio por intento.
    pub per_guess: Duration,
}

impl GuessReport {
    /// Estima los años para recorrer un espacio de `keyspace_bits` bits al coste
    /// medido por intento (una sola máquina, un solo hilo).
    pub fn cost_years(&self, keyspace_bits: u32) -> f64 {
        let secs_per = self.per_guess.as_secs_f64();
        let guesses = 2f64.powi(keyspace_bits as i32);
        secs_per * guesses / (365.25 * 24.0 * 3600.0)
    }
}

/// Cifra un secreto con una passphrase real y luego prueba `guesses` candidatos
/// "rankeados" (deterministas vía `seed`), ninguno igual al real. Mide el coste.
pub fn guessing_cost(guesses: usize, seed: u64) -> GuessReport {
    let dict = dictionaries::ascii94();
    // Coste moderado y realista para el banco (Argon2id memory-hard).
    let opts = Options {
        pepper: b"",
        kdf_params: KdfParams {
            mem_kib: 16 * 1024,
            iterations: 2,
            parallelism: 1,
        },
        codebook_id: 0,
    };
    let real_pass = "correcta-y-fuera-del-ranking-2026";
    let secret = b"tesoro";
    let sym = encode(secret, real_pass, &dict, &opts);

    // Lista "rankeada por IA": candidatos prioritarios simulados, deterministas.
    let mut rng = Rng::seeded(seed);
    let mut cracked = 0usize;
    let start = Instant::now();
    for i in 0..guesses {
        let guess = format!("guess-{}-{}", i, rng.next_u64());
        // El pepper vacío es el mismo del cifrado; el guess es la única variable.
        if decode(&sym, &guess, &dict, b"").is_ok() {
            cracked += 1;
        }
    }
    let total = start.elapsed();
    let per_guess = if guesses == 0 {
        Duration::ZERO
    } else {
        total / guesses as u32
    };

    GuessReport {
        attempts: guesses,
        cracked,
        total,
        per_guess,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranked_guesses_never_crack_and_cost_holds() {
        let report = guessing_cost(64, 2026);
        assert_eq!(report.attempts, 64);
        assert_eq!(report.cracked, 0, "ningún intento del ranking debe descifrar");
        assert!(
            report.per_guess > Duration::ZERO,
            "cada intento debe costar una derivación real"
        );
    }
}
