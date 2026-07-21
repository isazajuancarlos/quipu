// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Diccionario (codebook): biyección entre índices (0..base) e identidades de
//! símbolo. En v1 la identidad es un `char` (sirve para el fallback ASCII y para
//! glifos Unicode). El "binario" de un símbolo es su índice (posicional); este
//! módulo solo traduce índice <-> identidad. No aporta seguridad (es la "oruga").

use std::collections::HashMap;

/// Errores del diccionario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DictionaryError {
    /// Un alfabeto necesita al menos 2 símbolos.
    TooSmall,
    /// El mismo símbolo aparece dos veces (rompe la biyección).
    DuplicateSymbol(char),
    /// Al decodificar apareció un símbolo que no está en el diccionario.
    UnknownSymbol(char),
    /// Al codificar se pidió un índice fuera de [0, base).
    IndexOutOfRange(u32),
}

/// Codebook biyectivo índice <-> símbolo.
pub struct Dictionary {
    symbols: Vec<char>,
    inverse: HashMap<char, u32>,
}

impl Dictionary {
    /// Construye un diccionario a partir de una lista ordenada de símbolos.
    /// El índice de cada símbolo es su posición en la lista.
    pub fn new(symbols: Vec<char>) -> Result<Self, DictionaryError> {
        if symbols.len() < 2 {
            return Err(DictionaryError::TooSmall);
        }
        let mut inverse = HashMap::with_capacity(symbols.len());
        for (idx, &sym) in symbols.iter().enumerate() {
            if inverse.insert(sym, idx as u32).is_some() {
                return Err(DictionaryError::DuplicateSymbol(sym));
            }
        }
        Ok(Self { symbols, inverse })
    }

    /// Tamaño del alfabeto (la base N).
    pub fn base(&self) -> u32 {
        self.symbols.len() as u32
    }

    /// Identidad del símbolo en un índice dado.
    pub fn index_to_symbol(&self, index: u32) -> Option<char> {
        self.symbols.get(index as usize).copied()
    }

    /// Índice de un símbolo dado.
    pub fn symbol_to_index(&self, symbol: char) -> Option<u32> {
        self.inverse.get(&symbol).copied()
    }

    /// Serialización canónica del codebook: cada símbolo como su punto de
    /// código en 4 bytes big-endian, en orden de índice.
    ///
    /// Es la ENTRADA de la huella de integridad, no la huella. El hash lo pone
    /// el perfil, porque es justo lo que cambia entre hermanas: `quipu` usa
    /// SHA-256 y `quipu-cnsa` usará SHA-384. Lo que NO puede cambiar entre
    /// ellas es qué bytes se hashean —si difiriera, el mismo alfabeto daría
    /// huellas distintas por una razón que no es la elección de hash—, y por
    /// eso esa parte vive aquí, una sola vez.
    ///
    /// Este crate no hashea nada: no contiene primitivas criptográficas.
    pub fn bytes_canonicos(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.symbols.len() * 4);
        for &sym in &self.symbols {
            bytes.extend_from_slice(&(sym as u32).to_be_bytes());
        }
        bytes
    }

    /// Traduce una secuencia de índices a una cadena de símbolos.
    pub fn encode(&self, indices: &[u32]) -> Result<String, DictionaryError> {
        let mut out = String::with_capacity(indices.len());
        for &index in indices {
            let sym = self
                .index_to_symbol(index)
                .ok_or(DictionaryError::IndexOutOfRange(index))?;
            out.push(sym);
        }
        Ok(out)
    }

    /// Traduce una cadena de símbolos de vuelta a índices.
    pub fn decode(&self, text: &str) -> Result<Vec<u32>, DictionaryError> {
        text.chars()
            .map(|sym| {
                self.symbol_to_index(sym)
                    .ok_or(DictionaryError::UnknownSymbol(sym))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn maps_indices_to_symbols_and_back() {
        let dict = Dictionary::new(vec!['A', 'B', 'C', 'D']).unwrap();
        let symbols = dict.encode(&[0, 1, 2, 3, 2, 1, 0]).unwrap();
        assert_eq!(symbols, "ABCDCBA");
        let indices = dict.decode("ABCDCBA").unwrap();
        assert_eq!(indices, vec![0, 1, 2, 3, 2, 1, 0]);
    }

    #[test]
    fn rejects_alphabet_smaller_than_two() {
        assert!(matches!(
            Dictionary::new(vec!['A']),
            Err(DictionaryError::TooSmall)
        ));
    }

    #[test]
    fn rejects_duplicate_symbol() {
        assert!(matches!(
            Dictionary::new(vec!['A', 'B', 'A']),
            Err(DictionaryError::DuplicateSymbol('A'))
        ));
    }

    #[test]
    fn decode_rejects_unknown_symbol() {
        let dict = Dictionary::new(vec!['A', 'B']).unwrap();
        assert_eq!(dict.decode("AZ"), Err(DictionaryError::UnknownSymbol('Z')));
    }

    #[test]
    fn encode_rejects_index_out_of_range() {
        let dict = Dictionary::new(vec!['A', 'B']).unwrap();
        assert_eq!(
            dict.encode(&[0, 2]),
            Err(DictionaryError::IndexOutOfRange(2))
        );
    }

    #[test]
    fn los_bytes_canonicos_son_estables_y_distinguen_alfabetos() {
        let d1 = Dictionary::new(vec!['A', 'B', 'C']).unwrap();
        let d1_otra_vez = Dictionary::new(vec!['A', 'B', 'C']).unwrap();
        let d2 = Dictionary::new(vec!['A', 'B', 'D']).unwrap();
        assert_eq!(d1.bytes_canonicos(), d1_otra_vez.bytes_canonicos());
        assert_ne!(d1.bytes_canonicos(), d2.bytes_canonicos());
    }

    /// El orden importa: dos alfabetos con los mismos símbolos en distinto
    /// orden son codebooks DISTINTOS (el índice de cada símbolo cambia), y la
    /// serialización tiene que reflejarlo o la huella no protegería de nada.
    #[test]
    fn el_orden_de_los_simbolos_cambia_los_bytes() {
        let ordenado = Dictionary::new(vec!['A', 'B', 'C']).unwrap();
        let revuelto = Dictionary::new(vec!['C', 'B', 'A']).unwrap();
        assert_ne!(ordenado.bytes_canonicos(), revuelto.bytes_canonicos());
    }

    /// Formato fijado: 4 bytes big-endian por símbolo. Es lo que `quipu` y
    /// `quipu-cnsa` deben hashear IGUAL aunque usen hashes distintos.
    #[test]
    fn el_formato_canonico_es_cuatro_bytes_big_endian_por_simbolo() {
        let dict = Dictionary::new(vec!['A', 'Ñ']).unwrap();
        assert_eq!(
            dict.bytes_canonicos(),
            vec![0, 0, 0, 0x41, 0, 0, 0x00, 0xD1]
        );
    }

    proptest! {
        /// Milestone: bytes -> índices (codec) -> símbolos (dict) -> índices -> bytes.
        #[test]
        fn codec_plus_dictionary_round_trip(
            data in proptest::collection::vec(any::<u8>(), 0..200),
        ) {
            // Alfabeto de 94 símbolos ASCII imprimibles ('!'..='~').
            let symbols: Vec<char> = (0x21u8..=0x7e).map(|b| b as char).collect();
            let dict = Dictionary::new(symbols).unwrap();
            let n = dict.base();

            let indices = crate::codec::encode_base_n(&data, n);
            let text = dict.encode(&indices).unwrap();
            let back_indices = dict.decode(&text).unwrap();
            let back = crate::codec::decode_base_n(&back_indices, n);

            prop_assert_eq!(back, data);
        }
    }
}
