// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Cifrado AEAD: envoltorio fino sobre XChaCha20-Poly1305 (RFC 8439 / extendido).
//!
//! AQUÍ VIVE LA SEGURIDAD de la librería. No inventamos cripto: orquestamos una
//! primitiva probada. Confidencialidad + integridad vienen del par clave + AEAD.
//! Los datos asociados (`aad`) atan la cabecera del contenedor al ciphertext.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

/// Longitud de la clave (256 bits).
pub const KEY_LEN: usize = 32;
/// Longitud del nonce extendido (192 bits).
pub const NONCE_LEN: usize = 24;

/// Errores de descifrado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CipherError {
    /// El tag de autenticación no validó: clave, nonce, aad o ciphertext alterados.
    DecryptFailed,
}

/// Cifra `plaintext` con `key`/`nonce`, autenticando además `aad`.
/// Devuelve `ciphertext || tag`.
pub fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    cipher
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encrypt no debe fallar con entradas válidas")
}

/// Operación inversa de [`encrypt`]. Falla si algo fue alterado.
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CipherError> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    cipher
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CipherError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; KEY_LEN] {
        [7u8; KEY_LEN]
    }
    fn nonce() -> [u8; NONCE_LEN] {
        [9u8; NONCE_LEN]
    }

    #[test]
    fn round_trips_plaintext() {
        let pt = b"datos secretos";
        let aad = b"cabecera";
        let ct = encrypt(&key(), &nonce(), pt, aad);
        let back = decrypt(&key(), &nonce(), &ct, aad).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn round_trips_empty_plaintext() {
        let aad = b"cabecera";
        let ct = encrypt(&key(), &nonce(), b"", aad);
        let back = decrypt(&key(), &nonce(), &ct, aad).unwrap();
        assert_eq!(back, b"");
    }

    #[test]
    fn detects_tampered_ciphertext() {
        let mut ct = encrypt(&key(), &nonce(), b"hola", b"ad");
        ct[0] ^= 0x01; // voltea un bit
        assert_eq!(
            decrypt(&key(), &nonce(), &ct, b"ad"),
            Err(CipherError::DecryptFailed)
        );
    }

    #[test]
    fn fails_with_wrong_key() {
        let ct = encrypt(&key(), &nonce(), b"hola", b"ad");
        let wrong = [8u8; KEY_LEN];
        assert_eq!(
            decrypt(&wrong, &nonce(), &ct, b"ad"),
            Err(CipherError::DecryptFailed)
        );
    }

    #[test]
    fn fails_with_wrong_nonce() {
        let ct = encrypt(&key(), &nonce(), b"hola", b"ad");
        let wrong = [1u8; NONCE_LEN];
        assert_eq!(
            decrypt(&key(), &wrong, &ct, b"ad"),
            Err(CipherError::DecryptFailed)
        );
    }

    #[test]
    fn fails_with_wrong_aad() {
        // El binding de contexto: cambiar el aad invalida el descifrado.
        let ct = encrypt(&key(), &nonce(), b"hola", b"contexto-A");
        assert_eq!(
            decrypt(&key(), &nonce(), &ct, b"contexto-B"),
            Err(CipherError::DecryptFailed)
        );
    }
}
