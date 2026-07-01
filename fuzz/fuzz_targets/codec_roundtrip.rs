#![no_main]
//! Fuzz del codec: para cualquier entrada y base, el round-trip debe ser exacto
//! y los índices deben quedar en rango. Nunca debe entrar en pánico.

use libfuzzer_sys::fuzz_target;
use quipu::codec;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    // Primeros 2 bytes = base (>= 2); el resto = payload.
    let n = (u16::from_le_bytes([data[0], data[1]]) as u32).max(2);
    let payload = &data[2..];

    let encoded = codec::encode_base_n(payload, n);
    assert!(encoded.iter().all(|&d| d < n), "índice fuera de rango");
    let decoded = codec::decode_base_n(&encoded, n);
    assert_eq!(decoded, payload, "round-trip del codec roto");
});
