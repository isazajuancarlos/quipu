//! Hackerbot: red-team interno. Ataca AUTOMÁTICAMENTE nuestra propia librería
//! para descubrir debilidades y convertirlas en tests de regresión.
//!
//! Es testing de seguridad sobre código PROPIO (autorizado), no ofensiva contra
//! terceros. Cada hallazgo (breach) debe ser 0; si no, hay un fallo que arreglar.

use crate::api::{decode, encode, Options};
use crate::dictionary::Dictionary;

/// Resultado de un ataque.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackReport {
    /// Nombre del ataque.
    pub name: &'static str,
    /// Intentos realizados.
    pub attempts: usize,
    /// Brechas: intentos que la librería aceptó indebidamente (debe ser 0).
    pub breaches: usize,
}

impl AttackReport {
    /// `true` si no hubo ninguna brecha.
    pub fn is_clean(&self) -> bool {
        self.breaches == 0
    }
}

/// Ataque de manipulación: sustituye cada símbolo del output por otro válido y
/// exige que `decode` lo rechace. Un `decode` exitoso sobre un mensaje alterado
/// es una brecha.
pub fn tamper_attack(
    data: &[u8],
    passphrase: &str,
    dict: &Dictionary,
    pepper: &[u8],
    opts: &Options,
) -> AttackReport {
    let symbols = encode(data, passphrase, dict, opts);
    let chars: Vec<char> = symbols.chars().collect();
    let mut attempts = 0;
    let mut breaches = 0;

    for i in 0..chars.len() {
        // Sustituye el símbolo i por otro válido (índice + 1 mod base).
        let idx = dict
            .symbol_to_index(chars[i])
            .expect("símbolo del propio diccionario");
        let new_sym = dict
            .index_to_symbol((idx + 1) % dict.base())
            .expect("índice válido");
        if new_sym == chars[i] {
            continue;
        }
        let mut mutated = chars.clone();
        mutated[i] = new_sym;
        let candidate: String = mutated.into_iter().collect();

        attempts += 1;
        // Cualquier decode exitoso sobre un mensaje alterado es una brecha.
        if decode(&candidate, passphrase, dict, pepper).is_ok() {
            breaches += 1;
        }
    }

    AttackReport {
        name: "tamper",
        attempts,
        breaches,
    }
}

/// Ataque de truncación: corta el output en cada posición y exige rechazo.
pub fn truncation_attack(
    data: &[u8],
    passphrase: &str,
    dict: &Dictionary,
    pepper: &[u8],
    opts: &Options,
) -> AttackReport {
    let symbols = encode(data, passphrase, dict, opts);
    let chars: Vec<char> = symbols.chars().collect();
    let mut attempts = 0;
    let mut breaches = 0;

    for cut in 0..chars.len() {
        let truncated: String = chars[..cut].iter().collect();
        attempts += 1;
        if decode(&truncated, passphrase, dict, pepper).is_ok() {
            breaches += 1;
        }
    }

    AttackReport {
        name: "truncation",
        attempts,
        breaches,
    }
}

/// Ataque de unicidad: codifica el mismo dato `rounds` veces y exige que cada
/// salida sea distinta (salt/nonce aleatorios). Una colisión es una brecha.
pub fn uniqueness_attack(
    data: &[u8],
    passphrase: &str,
    dict: &Dictionary,
    opts: &Options,
    rounds: usize,
) -> AttackReport {
    let mut seen = std::collections::HashSet::new();
    let mut breaches = 0;

    for _ in 0..rounds {
        let symbols = encode(data, passphrase, dict, opts);
        if !seen.insert(symbols) {
            breaches += 1; // colisión = reutilización de salt/nonce
        }
    }

    AttackReport {
        name: "uniqueness",
        attempts: rounds,
        breaches,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::KdfParams;

    fn ascii_dict() -> Dictionary {
        Dictionary::new((0x21u8..=0x7e).map(|b| b as char).collect()).unwrap()
    }

    fn test_opts() -> Options<'static> {
        Options {
            pepper: b"",
            kdf_params: KdfParams {
                mem_kib: 64,
                iterations: 1,
                parallelism: 1,
            },
            codebook_id: 1,
        }
    }

    #[test]
    fn library_survives_tamper_attack() {
        let dict = ascii_dict();
        let report = tamper_attack(b"mensaje secreto", "clave", &dict, b"", &test_opts());
        assert!(report.attempts > 0, "el ataque debe intentar algo");
        assert_eq!(report.breaches, 0, "ninguna manipulación debe aceptarse");
    }

    #[test]
    fn library_survives_truncation_attack() {
        let dict = ascii_dict();
        let report = truncation_attack(b"mensaje secreto", "clave", &dict, b"", &test_opts());
        assert!(report.attempts > 0);
        assert_eq!(report.breaches, 0, "ninguna truncación debe aceptarse");
    }

    #[test]
    fn outputs_are_unique_across_encodes() {
        let dict = ascii_dict();
        let report = uniqueness_attack(b"mismo dato", "clave", &dict, &test_opts(), 20);
        assert_eq!(report.attempts, 20);
        assert_eq!(report.breaches, 0, "salt/nonce deben ser aleatorios por encode");
    }
}
