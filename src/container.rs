// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! El contenedor de Quipu: el formato genérico de `quipu-nucleo` con el perfil
//! de ESTA librería ya fijado.
//!
//! El formato vive en `quipu_nucleo::container`, parametrizado por las dos
//! únicas medidas que dependen de la criptografía elegida: la longitud del salt
//! y la del nonce. Aquí se atan a las de `quipu` —16 y 24, las de Argon2id y
//! XChaCha20-Poly1305— y el resto de la librería vuelve a ver un `Header`
//! normal, sin genéricos a la vista.
//!
//! Esa es toda la gracia del reparto: `quipu-cnsa` escribirá este mismo archivo
//! con `NONCE_LEN` = 12 y compartirá byte por byte el serializador, el parseo y
//! sus pruebas. Un fallo en el formato se arregla una vez.

use crate::cipher::NONCE_LEN;
use crate::kdf::SALT_LEN;

pub use quipu_nucleo::container::{ContainerError, MAGIC, VERSION};

/// Cabecera del contenedor con el perfil de `quipu` (salt 16, nonce 24).
pub type Header = quipu_nucleo::container::Header<SALT_LEN, NONCE_LEN>;

/// Serializa cabecera + ciphertext en un único blob.
pub fn serialize(header: &Header, ciphertext: &[u8]) -> Vec<u8> {
    quipu_nucleo::container::serialize(header, ciphertext)
}

/// Parsea un blob en (cabecera, ciphertext). Valida magic y versión.
pub fn parse(blob: &[u8]) -> Result<(Header, &[u8]), ContainerError> {
    quipu_nucleo::container::parse(blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guardián del formato en disco. `quipu-nucleo` prueba que la
    /// parametrización funciona; esto prueba que ESTA librería sigue atada al
    /// perfil correcto. Si alguien cambiara `NONCE_LEN` sin darse cuenta de que
    /// arrastra el formato, todo blob ya escrito dejaría de leerse — y el
    /// número tiene que fallar aquí, no en un cliente.
    #[test]
    fn el_perfil_de_quipu_sigue_siendo_16_24_y_la_cabecera_68() {
        assert_eq!(SALT_LEN, 16);
        assert_eq!(NONCE_LEN, 24);
        assert_eq!(Header::SIZE, 68);
    }
}
