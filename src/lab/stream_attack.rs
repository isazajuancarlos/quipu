// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Superficie de streaming: manipulación adaptativa de contenedores QST1.
//!
//! Sobre un cifrado válido de varios chunks, intenta truncar, reordenar, hacer
//! splice desde otro archivo y manipular bytes. Cualquier `decrypt_stream_bytes`
//! que devuelva Ok con datos ≠ originales (o acepte un flujo forjado) es brecha.

use crate::api::{decrypt_stream_bytes, encrypt_stream_bytes, StreamOptions};
use crate::kdf::KdfParams;
use crate::lab::engine::{Attack, AttackOutcome, Rng};

const HEADER_LEN: usize = 57;
const CHUNK: usize = 4096;
const TAG: usize = 16;
const CT_BLOCK: usize = CHUNK + TAG;

fn opts() -> StreamOptions<'static> {
    StreamOptions {
        pepper: b"",
        kdf_params: KdfParams {
            mem_kib: 64,
            iterations: 1,
            parallelism: 1,
        },
        chunk_size: CHUNK,
    }
}

/// Atacante adaptativo contra el modo streaming.
pub struct StreamAttack;

impl StreamAttack {
    /// Nuevo ataque de streaming.
    pub fn new() -> Self {
        Self
    }
}

impl Default for StreamAttack {
    fn default() -> Self {
        Self::new()
    }
}

impl Attack for StreamAttack {
    fn name(&self) -> &'static str {
        "stream/forge"
    }

    fn step(&mut self, rng: &mut Rng) -> AttackOutcome {
        let data: Vec<u8> = (0..CHUNK * 2 + 7).map(|i| (i % 251) as u8).collect();
        let blob = encrypt_stream_bytes(&data, "clave-lab", &opts());

        let forged: Vec<u8> = match rng.below(5) {
            // Truncar el último bloque.
            0 => blob[..HEADER_LEN + 2 * CT_BLOCK].to_vec(),
            // Truncar el bloque intermedio.
            1 => {
                let mut v = blob[..HEADER_LEN + CT_BLOCK].to_vec();
                v.extend_from_slice(&blob[HEADER_LEN + 2 * CT_BLOCK..]);
                v
            }
            // Append (duplicar primer bloque).
            2 => {
                let mut v = blob.clone();
                v.extend_from_slice(&blob[HEADER_LEN..HEADER_LEN + CT_BLOCK]);
                v
            }
            // Reordenar los dos primeros bloques.
            3 => {
                let mut v = blob[..HEADER_LEN].to_vec();
                v.extend_from_slice(&blob[HEADER_LEN + CT_BLOCK..HEADER_LEN + 2 * CT_BLOCK]);
                v.extend_from_slice(&blob[HEADER_LEN..HEADER_LEN + CT_BLOCK]);
                v.extend_from_slice(&blob[HEADER_LEN + 2 * CT_BLOCK..]);
                v
            }
            // Splice desde OTRO archivo (otra clave por archivo).
            _ => {
                let other = encrypt_stream_bytes(&data, "clave-lab", &opts());
                let mut v = blob[..HEADER_LEN].to_vec();
                v.extend_from_slice(&other[HEADER_LEN..HEADER_LEN + CT_BLOCK]);
                v.extend_from_slice(&blob[HEADER_LEN + CT_BLOCK..]);
                v
            }
        };

        match decrypt_stream_bytes(&forged, "clave-lab", b"") {
            Ok(out) if out == data => {
                AttackOutcome::Breach("forjado descifró a los datos originales".into())
            }
            Ok(_) => AttackOutcome::Breach("forjado descifró (datos distintos, pero Ok)".into()),
            Err(_) => AttackOutcome::Advanced,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::engine::run;

    #[test]
    fn adaptive_stream_forgery_never_verifies() {
        let mut attack = StreamAttack::new();
        let report = run(&mut attack, 4242, 40);
        assert!(report.attempts > 0);
        assert!(
            report.is_clean(),
            "ninguna manipulación de streaming debe descifrar: {:?}",
            report.breaches
        );
    }
}
