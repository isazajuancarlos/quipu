// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! El diccionario del núcleo con la huella de integridad de ESTE perfil:
//! **SHA-384** truncado a 8 bytes, frente al SHA-256 de `quipu`.
//!
//! El codebook —la biyección índice ↔ símbolo— es agnóstico y vive en
//! `quipu_nucleo::dictionary`. Lo que es una elección criptográfica es con qué
//! se resume, y eso lo pone cada perfil.
//!
//! **Los bytes que se resumen son los mismos en las dos hermanas**
//! (`bytes_canonicos`: 4 bytes big-endian por punto de código). Si cada una
//! serializara los símbolos a su manera, el mismo alfabeto daría huellas
//! distintas por una razón que no es la elección de hash, y depurarlo sería
//! una pesadilla.

use sha2::{Digest, Sha384};

pub use quipu_nucleo::dictionary::{Dictionary, DictionaryError};

/// Huella de integridad del codebook, en el perfil CNSA.
pub trait HuellaDeCodebook {
    /// Primeros 8 bytes de SHA-384 sobre la serialización canónica de los
    /// símbolos. Identifica el diccionario y permite verificar en la
    /// decodificación que se usa el codebook correcto.
    fn fingerprint(&self) -> [u8; 8];
}

impl HuellaDeCodebook for Dictionary {
    fn fingerprint(&self) -> [u8; 8] {
        let mut hasher = Sha384::new();
        hasher.update(self.bytes_canonicos());
        hasher.finalize()[0..8]
            .try_into()
            .expect("SHA-384 produce 48 bytes")
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

    /// LA PRUEBA QUE JUSTIFICA ESTE ARCHIVO: la huella del perfil CNSA NO puede
    /// coincidir con la de `quipu`. Si coincidiera, el perfil sería decorativo.
    #[test]
    fn la_huella_difiere_de_la_de_quipu_que_usa_sha256() {
        use sha2::Sha256;

        let dict = Dictionary::new(vec!['A', 'B', 'C']).unwrap();

        let mut con_sha256 = Sha256::new();
        con_sha256.update(dict.bytes_canonicos());
        let huella_quipu: [u8; 8] = con_sha256.finalize()[0..8].try_into().unwrap();

        assert_ne!(
            dict.fingerprint(),
            huella_quipu,
            "la huella CNSA debe salir de SHA-384, no de SHA-256"
        );
    }

    /// Y la otra mitad del reparto: los BYTES que se resumen sí son idénticos
    /// en las dos hermanas. Es lo que garantiza que la única diferencia sea el
    /// hash y no la serialización.
    #[test]
    fn los_bytes_resumidos_son_los_mismos_que_en_quipu() {
        let dict = Dictionary::new(vec!['A', 'Ñ']).unwrap();
        assert_eq!(
            dict.bytes_canonicos(),
            vec![0, 0, 0, 0x41, 0, 0, 0x00, 0xD1]
        );
    }
}
