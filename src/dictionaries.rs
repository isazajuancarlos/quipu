// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Diccionarios incorporados (codebooks enchufables).
//!
//! El núcleo (codec) es agnóstico al alfabeto; aquí viven los alfabetos
//! concretos. Cada uno es una "piel" distinta sobre el mismo dato cifrado.
//!
//!   - `ascii94`: 94 símbolos ASCII imprimibles. Denso, copy-paste universal.
//!   - `flagship`: 4096 glifos (12 bits/símbolo, ~2x más denso que ASCII).
//!   - `from_range`: constructor genérico desde un rango de codepoints.

use crate::dictionary::{Dictionary, DictionaryError};

/// 94 símbolos ASCII imprimibles ('!'..='~'). Fallback denso y universal.
pub fn ascii94() -> Dictionary {
    Dictionary::new((0x21u8..=0x7e).map(|b| b as char).collect())
        .expect("el alfabeto ASCII es válido")
}

/// Construye un diccionario con glifos contiguos desde el codepoint `start`,
/// tomando los primeros `count` codepoints válidos (sin surrogates).
pub fn from_range(start: u32, count: u32) -> Result<Dictionary, DictionaryError> {
    // Acotado al rango de scalar values de Unicode (evita iterador sin fin).
    let symbols: Vec<char> = (start..0x11_0000)
        .filter_map(char::from_u32)
        .take(count as usize)
        .collect();
    Dictionary::new(symbols)
}

/// Diccionario insignia: 4096 glifos CJK (rango U+4E00..), single-codepoint y
/// ampliamente renderizados. 12 bits por símbolo.
pub fn flagship() -> Dictionary {
    from_range(0x4E00, 4096).expect("el rango CJK insignia es válido")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flagship_has_4096_glyphs() {
        assert_eq!(flagship().base(), 4096);
    }

    #[test]
    fn from_range_builds_requested_count() {
        let d = from_range(0x4E00, 100).unwrap();
        assert_eq!(d.base(), 100);
    }

    #[test]
    fn flagship_round_trips_and_is_denser_than_ascii() {
        use crate::api::{decode, encode, Options};
        use crate::kdf::KdfParams;

        let opts = Options {
            pepper: b"",
            kdf_params: KdfParams {
                mem_kib: 64,
                iterations: 1,
                parallelism: 1,
            },
            codebook_id: 0,
        };
        let data = b"un mensaje suficientemente largo para comparar densidad de alfabetos";
        let ascii = ascii94();
        let flag = flagship();

        // Round-trip por el pipeline completo con el diccionario insignia.
        let s_flag = encode(data, "clave", &flag, &opts);
        assert_eq!(decode(&s_flag, "clave", &flag, b"").unwrap(), data);

        // El insignia (12 bits/símbolo) usa menos símbolos que ASCII (~6.5).
        let s_ascii = encode(data, "clave", &ascii, &opts);
        assert!(s_flag.chars().count() < s_ascii.chars().count());
    }
}
