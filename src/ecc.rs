// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Corrección de errores Reed-Solomon (GF(256)) para canales ruidosos
//! (impreso/fotografiado). Añade paridad que corrige errores en posiciones
//! DESCONOCIDAS (no solo borrados), hasta `parity/2` por bloque de 255 bytes.
//!
//! Formato:
//!   [ parity(1) | data_len(4 LE) | bloques RS... ]
//!   cada bloque = chunk_de_datos (hasta 255-parity) + bytes de paridad
//!
//! La cabecera (5 bytes) NO está protegida: si se corrompe, la recuperación
//! falla limpiamente (devuelve None).

use reed_solomon::{Decoder, Encoder};

/// Cabecera: parity(1) + data_len(4).
const HEADER: usize = 5;

/// Protege `data` con Reed-Solomon usando `parity` bytes de paridad por bloque.
pub fn protect(data: &[u8], parity: u8) -> Vec<u8> {
    let parity = parity.max(2); // mínimo para corregir 1 error
    let chunk = 255 - parity as usize;
    let encoder = Encoder::new(parity as usize);

    let mut out = Vec::with_capacity(HEADER + data.len() + parity as usize);
    out.push(parity);
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    for block in data.chunks(chunk) {
        let encoded = encoder.encode(block);
        out.extend_from_slice(&encoded); // chunk de datos + paridad
    }
    out
}

/// Recupera los datos corrigiendo errores. Devuelve `None` si hay demasiados
/// errores o la cabecera está corrupta.
pub fn recover(protected: &[u8]) -> Option<Vec<u8>> {
    if protected.len() < HEADER {
        return None;
    }
    let parity = protected[0];
    // `parity` viene de la cabecera NO protegida. Debe dejar sitio para datos:
    // con parity==255 el chunk sería 0 (bloque de pura paridad) -> trabajo inútil
    // y parámetros Reed-Solomon degenerados. Exige 2 <= parity <= 254.
    if parity < 2 || 255 - (parity as usize) == 0 {
        return None;
    }
    let data_len = u32::from_le_bytes(protected[1..HEADER].try_into().ok()?) as usize;
    // Anti-DoS: un data_len mayor que los bytes disponibles es imposible y
    // evitaría una asignación gigante (with_capacity con un u32 malicioso).
    if data_len > protected.len() {
        return None;
    }
    let chunk = 255 - parity as usize;
    let decoder = Decoder::new(parity as usize);

    let mut body = &protected[HEADER..];
    let mut out = Vec::with_capacity(data_len);
    let mut remaining = data_len;
    while remaining > 0 {
        let data_in_block = remaining.min(chunk);
        let block_len = data_in_block + parity as usize;
        if body.len() < block_len {
            return None;
        }
        let corrected = decoder.correct(&body[..block_len], None).ok()?;
        out.extend_from_slice(&corrected.data()[..data_in_block]);
        body = &body[block_len..];
        remaining -= data_in_block;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_without_errors() {
        let data = b"datos a proteger con correccion de errores";
        let prot = protect(data, 8);
        assert_eq!(recover(&prot).unwrap(), data);
    }

    #[test]
    fn round_trips_large_data_across_blocks() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let prot = protect(&data, 8);
        assert_eq!(recover(&prot).unwrap(), data);
    }

    #[test]
    fn corrects_errors_within_capacity() {
        let data = b"mensaje que sufrira corrupcion en el canal";
        let mut prot = protect(data, 8); // corrige hasta 4 errores/bloque
        // Corrompe 4 bytes dentro del primer bloque (tras la cabecera de 5).
        for k in 0..4 {
            prot[HEADER + k] ^= 0xFF;
        }
        assert_eq!(recover(&prot).unwrap(), data);
    }

    #[test]
    fn fails_when_too_many_errors() {
        let data = b"corto";
        let mut prot = protect(data, 4); // corrige hasta 2 errores
        // Corrompe 5 bytes -> excede la capacidad.
        for k in 0..5 {
            prot[HEADER + k] ^= 0xFF;
        }
        assert!(recover(&prot).is_none());
    }

    #[test]
    fn round_trips_empty() {
        let prot = protect(b"", 8);
        assert_eq!(recover(&prot).unwrap(), b"");
    }

    #[test]
    fn rejects_malicious_data_len_without_oom() {
        // Cabecera con data_len = u32::MAX en un buffer minúsculo -> None, sin OOM.
        let mut prot = protect(b"hola", 8);
        prot[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(recover(&prot).is_none());
    }

    #[test]
    fn rejects_degenerate_parity_byte() {
        // parity==255 (chunk==0) en la cabecera manipulada -> None, sin bucle inútil.
        let mut prot = protect(b"hola", 8);
        prot[0] = 255;
        assert!(recover(&prot).is_none());
        // parity==254 (chunk==1) sigue siendo un valor límite aceptable de leer.
        let mut prot2 = protect(b"hola", 8);
        prot2[0] = 254;
        // No debe entrar en pánico; devuelve None por longitudes inconsistentes.
        let _ = recover(&prot2);
    }
}
