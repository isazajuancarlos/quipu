// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Codec base-N: convierte una secuencia de bytes en una secuencia de índices
//! de símbolo (0..N) y viceversa, de forma totalmente reversible.
//!
//! El "valor binario" de un símbolo es su índice (codificación posicional): el
//! codebook (capa superior) solo traduce índice -> identidad de símbolo.
//!
//! Para preservar bytes cero a la izquierda y la entrada vacía, se antepone un
//! marcador 0x01 antes de interpretar los bytes como un entero grande.

use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};

/// Codifica `data` a una secuencia de índices en base `n` (orden big-endian:
/// el dígito más significativo primero).
pub fn encode_base_n(data: &[u8], n: u32) -> Vec<u32> {
    // Marcador 0x01 al frente: preserva ceros a la izquierda y la entrada vacía.
    let mut buf = Vec::with_capacity(data.len() + 1);
    buf.push(1u8);
    buf.extend_from_slice(data);

    let base = BigUint::from(n);
    let mut value = BigUint::from_bytes_be(&buf);
    let mut digits = Vec::new();
    while !value.is_zero() {
        let rem = &value % &base;
        digits.push(rem.to_u32().expect("rem < n cabe en u32"));
        value /= &base;
    }
    digits.reverse(); // little-endian -> big-endian
    digits
}

/// Operación inversa de [`encode_base_n`].
pub fn decode_base_n(indices: &[u32], n: u32) -> Vec<u8> {
    let base = BigUint::from(n);
    let mut value = BigUint::zero();
    for &d in indices {
        value = value * &base + BigUint::from(d);
    }
    let bytes = value.to_bytes_be();
    // Quita el marcador 0x01 inicial.
    bytes[1..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn round_trips_simple_bytes() {
        let data = b"hello";
        let encoded = encode_base_n(data, 94);
        let decoded = decode_base_n(&encoded, 94);
        assert_eq!(decoded, data);
    }

    #[test]
    fn round_trips_empty_input() {
        let data = b"";
        let encoded = encode_base_n(data, 94);
        let decoded = decode_base_n(&encoded, 94);
        assert_eq!(decoded, data);
    }

    #[test]
    fn round_trips_leading_zero_bytes() {
        // El marcador 0x01 debe preservar los ceros a la izquierda.
        let data = &[0u8, 0, 0, 42];
        let encoded = encode_base_n(data, 94);
        let decoded = decode_base_n(&encoded, 94);
        assert_eq!(decoded, data);
    }

    proptest! {
        #[test]
        fn round_trips_any_bytes_any_base(
            data in proptest::collection::vec(any::<u8>(), 0..256),
            n in 2u32..=4096,
        ) {
            let encoded = encode_base_n(&data, n);
            // Todo índice debe estar en el rango [0, n).
            prop_assert!(encoded.iter().all(|&d| d < n));
            let decoded = decode_base_n(&encoded, n);
            prop_assert_eq!(decoded, data);
        }
    }
}
