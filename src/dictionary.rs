// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! El diccionario de Quipu: el codebook genérico de `quipu-nucleo` con la
//! huella de integridad de ESTE perfil.
//!
//! El codebook —la biyección índice <-> símbolo— vive en
//! `quipu_nucleo::dictionary` y no contiene criptografía. Lo que sí es una
//! elección criptográfica es CON QUÉ se resume: `quipu` usa SHA-256 truncado a
//! 8 bytes; `quipu-cnsa` usará SHA-384 sobre exactamente los mismos bytes de
//! entrada.
//!
//! Ese reparto no es un tecnicismo. Si cada hermana serializara los símbolos a
//! su manera, el mismo alfabeto daría huellas distintas por una razón que no es
//! la elección de hash, y depurarlo sería una pesadilla. El QUÉ se resume vive
//! una sola vez en el núcleo; el CON QUÉ, aquí.

use sha2::{Digest, Sha256};

pub use quipu_nucleo::dictionary::{Dictionary, DictionaryError};

/// Huella de integridad del codebook, en el perfil de `quipu`.
///
/// Se implementa como trait de extensión para que `dict.fingerprint()` siga
/// escribiéndose igual que antes de separar el núcleo: el método no podía
/// quedarse en `quipu-nucleo` —hashear es criptografía— pero tampoco tenía por
/// qué cambiar de forma para quien lo usa.
pub trait HuellaDeCodebook {
    /// Primeros 8 bytes de SHA-256 sobre la serialización canónica de los
    /// símbolos. Identifica el diccionario y permite verificar en la
    /// decodificación que se usa el codebook correcto.
    fn fingerprint(&self) -> [u8; 8];
}

impl HuellaDeCodebook for Dictionary {
    fn fingerprint(&self) -> [u8; 8] {
        let mut hasher = Sha256::new();
        hasher.update(self.bytes_canonicos());
        hasher.finalize()[0..8]
            .try_into()
            .expect("SHA-256 produce >= 8 bytes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_huella_es_estable_y_distingue_alfabetos() {
        let d1 = Dictionary::new(vec!['A', 'B', 'C']).unwrap();
        let d1_otra_vez = Dictionary::new(vec!['A', 'B', 'C']).unwrap();
        let d2 = Dictionary::new(vec!['A', 'B', 'D']).unwrap();
        assert_eq!(d1.fingerprint(), d1_otra_vez.fingerprint());
        assert_ne!(d1.fingerprint(), d2.fingerprint());
    }

    /// Guardián de compatibilidad: la huella tiene que salir IDÉNTICA a como
    /// salía antes de separar el núcleo, o todo blob ya escrito deja de
    /// verificar su codebook. El valor está calculado con la implementación
    /// anterior (SHA-256 sobre los puntos de código en 4 bytes big-endian).
    #[test]
    fn la_huella_no_cambio_al_separar_el_nucleo() {
        let dict = Dictionary::new(vec!['A', 'B', 'C']).unwrap();
        let esperada = {
            // Réplica literal del código previo a la extracción.
            let mut h = Sha256::new();
            for sym in ['A', 'B', 'C'] {
                h.update((sym as u32).to_be_bytes());
            }
            let salida: [u8; 8] = h.finalize()[0..8].try_into().unwrap();
            salida
        };
        assert_eq!(dict.fingerprint(), esperada);
    }
}
