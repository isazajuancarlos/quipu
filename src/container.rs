// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Contenedor: serializa/parsea la cabecera + el payload cifrado.
//!
//! Disposición (68 bytes de cabecera, todo big-endian):
//!   magic(4) | version(1) | flags(1) | codebook_id(2) | codebook_hash_prefix(8)
//!   | salt(16) | nonce(24) | kdf_mem_kib(4) | kdf_iterations(4) | kdf_parallelism(4)
//!   seguido de: padded_ciphertext+tag (variable)
//!
//! La cabecera completa se usa como Associated Data del AEAD: cualquier
//! alteración de versión/codebook_id/salt/nonce/params invalida el descifrado.

use crate::cipher::NONCE_LEN;
use crate::kdf::SALT_LEN;

/// Identificador de formato.
pub const MAGIC: [u8; 4] = *b"QUIP";
/// Versión de formato soportada.
pub const VERSION: u8 = 1;

/// Errores de parseo del contenedor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerError {
    /// El blob es más corto que una cabecera.
    TooShort,
    /// Los bytes mágicos no coinciden.
    BadMagic,
    /// Versión de formato no soportada.
    UnsupportedVersion(u8),
}

/// Cabecera del contenedor (en claro, pero autenticada como AAD).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub flags: u8,
    pub codebook_id: u16,
    pub codebook_hash_prefix: [u8; 8],
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub kdf_mem_kib: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u32,
}

impl Header {
    /// Tamaño serializado de la cabecera, en bytes.
    pub const SIZE: usize = 68;

    /// Serializa la cabecera. Estos bytes son además el AAD del AEAD.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(Self::SIZE);
        b.extend_from_slice(&MAGIC);
        b.push(self.version);
        b.push(self.flags);
        b.extend_from_slice(&self.codebook_id.to_be_bytes());
        b.extend_from_slice(&self.codebook_hash_prefix);
        b.extend_from_slice(&self.salt);
        b.extend_from_slice(&self.nonce);
        b.extend_from_slice(&self.kdf_mem_kib.to_be_bytes());
        b.extend_from_slice(&self.kdf_iterations.to_be_bytes());
        b.extend_from_slice(&self.kdf_parallelism.to_be_bytes());
        debug_assert_eq!(b.len(), Self::SIZE);
        b
    }
}

/// Serializa cabecera + ciphertext en un único blob.
pub fn serialize(header: &Header, ciphertext: &[u8]) -> Vec<u8> {
    let mut out = header.to_bytes();
    out.extend_from_slice(ciphertext);
    out
}

/// Parsea un blob en (cabecera, ciphertext). Valida magic y versión.
pub fn parse(blob: &[u8]) -> Result<(Header, &[u8]), ContainerError> {
    if blob.len() < Header::SIZE {
        return Err(ContainerError::TooShort);
    }
    let (head, rest) = blob.split_at(Header::SIZE);

    if head[0..4] != MAGIC {
        return Err(ContainerError::BadMagic);
    }
    let version = head[4];
    if version != VERSION {
        return Err(ContainerError::UnsupportedVersion(version));
    }

    let header = Header {
        version,
        flags: head[5],
        codebook_id: u16::from_be_bytes([head[6], head[7]]),
        codebook_hash_prefix: head[8..16].try_into().expect("8 bytes"),
        salt: head[16..32].try_into().expect("16 bytes"),
        nonce: head[32..56].try_into().expect("24 bytes"),
        kdf_mem_kib: u32::from_be_bytes(head[56..60].try_into().expect("4 bytes")),
        kdf_iterations: u32::from_be_bytes(head[60..64].try_into().expect("4 bytes")),
        kdf_parallelism: u32::from_be_bytes(head[64..68].try_into().expect("4 bytes")),
    };
    Ok((header, rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> Header {
        Header {
            version: VERSION,
            flags: 0,
            codebook_id: 0x0102,
            codebook_hash_prefix: [1, 2, 3, 4, 5, 6, 7, 8],
            salt: [9u8; SALT_LEN],
            nonce: [7u8; NONCE_LEN],
            kdf_mem_kib: 65536,
            kdf_iterations: 3,
            kdf_parallelism: 1,
        }
    }

    #[test]
    fn round_trips_header_and_ciphertext() {
        let h = sample_header();
        let ct = vec![10u8, 20, 30, 40, 50];
        let blob = serialize(&h, &ct);
        let (parsed, parsed_ct) = parse(&blob).unwrap();
        assert_eq!(parsed, h);
        assert_eq!(parsed_ct, &ct[..]);
    }

    #[test]
    fn header_serializes_to_fixed_size() {
        assert_eq!(sample_header().to_bytes().len(), Header::SIZE);
    }

    #[test]
    fn rejects_too_short_blob() {
        let short = [0u8; Header::SIZE - 1];
        assert_eq!(parse(&short), Err(ContainerError::TooShort));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut blob = serialize(&sample_header(), b"ct");
        blob[0] = b'X';
        assert_eq!(parse(&blob), Err(ContainerError::BadMagic));
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut blob = serialize(&sample_header(), b"ct");
        blob[4] = 99;
        assert_eq!(parse(&blob), Err(ContainerError::UnsupportedVersion(99)));
    }
}
