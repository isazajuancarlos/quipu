// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! AEAD del perfil CNSA: **AES-256-GCM**.
//!
//! Es la primera de las dos divergencias reales con `quipu`, que usa
//! XChaCha20-Poly1305. Misma interfaz, distinta primitiva y distinto tamaño de
//! nonce: 96 bits en vez de 192.
//!
//! # El nonce de 96 bits, y por qué no hace falta un contador global
//!
//! El fallo catastrófico de AES-GCM es reutilizar el par `(clave, nonce)`: con
//! dos mensajes bajo el mismo par se recupera el XOR de los textos claros y,
//! peor, se puede recuperar la clave de autenticación y forjar mensajes.
//!
//! Aquí eso no puede ocurrir por repetición de nonce, porque **la clave cambia
//! en cada operación**: se deriva con Argon2id desde una sal aleatoria de 128
//! bits generada en el momento del cifrado. Reutilizar `(clave, nonce)` exige
//! colisionar la sal *y* el nonce.
//!
//! En términos de SP 800-38D, el modo normal usa la construcción aleatoria
//! (§8.2.2), cuyo límite son 2^32 invocaciones **por clave**; aquí cada clave
//! se usa exactamente **una** vez. Llevar un contador persistente no añadiría
//! seguridad y sí un archivo de estado que corromper.
//!
//! **La responsabilidad que esto traslada al llamante es real y hay que
//! decirla:** quien use esta capa con una clave FIJA para varios mensajes
//! —saltándose la KDF— sí debe garantizar nonces únicos. Por eso `encrypt`
//! recibe el nonce en vez de generarlo: quien elige la clave elige el nonce, y
//! así la decisión es visible en el código de quien la toma.

// `from_slice` está deprecado en aes-gcm 0.11 (acepta cualquier longitud y
// entra en pánico si no cuadra). Aquí las longitudes son constantes de tipo, así
// que la conversión infalible `From<[u8; N]>` es a la vez más correcta y más
// barata: el compilador comprueba el tamaño, no el runtime.
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;

/// Longitud de la clave (256 bits).
pub const KEY_LEN: usize = 32;
/// Longitud del nonce de AES-GCM (96 bits). Es el tamaño que SP 800-38D
/// recomienda: cualquier otro obliga a pasar el nonce por GHASH y no aporta.
pub const NONCE_LEN: usize = 12;
/// Longitud del tag de autenticación (128 bits).
pub const TAG_LEN: usize = 16;

/// El descifrado no autenticó.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherError {
    /// El tag no validó: clave, nonce, aad o ciphertext alterados.
    ///
    /// **Un solo error para las cuatro causas, a propósito.** Distinguir «mala
    /// clave» de «ciphertext alterado» le daría a un atacante un oráculo que
    /// acota su búsqueda. Ver la invariante I4 de `docs/ATAQUES_TAXONOMIA.md`:
    /// el fallo no revela nada.
    Decrypt,
}

/// Cifra `plaintext` con `key`/`nonce`, autenticando además `aad`.
pub fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    Aes256Gcm::new(&(*key).into())
        .encrypt(&(*nonce).into(), Payload { msg: plaintext, aad })
        // Solo falla si el mensaje excede el límite de AES-GCM (~64 GiB), que
        // esta API no puede alcanzar: el modo streaming trocea antes.
        .expect("AES-256-GCM no falla salvo por longitud imposible")
}

/// Descifra y verifica. Devuelve `Err` si el tag no valida.
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CipherError> {
    Aes256Gcm::new(&(*key).into())
        .decrypt(&(*nonce).into(), Payload { msg: ciphertext, aad })
        .map_err(|_| CipherError::Decrypt)
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
    fn ida_y_vuelta() {
        let ct = encrypt(&key(), &nonce(), b"secreto", b"cabecera");
        assert_eq!(decrypt(&key(), &nonce(), &ct, b"cabecera").unwrap(), b"secreto");
    }

    #[test]
    fn el_texto_vacio_tambien_va_y_vuelve() {
        let ct = encrypt(&key(), &nonce(), b"", b"ad");
        assert_eq!(decrypt(&key(), &nonce(), &ct, b"ad").unwrap(), b"");
        // Aun vacío lleva su tag: no hay ciphertext sin autenticar.
        assert_eq!(ct.len(), TAG_LEN);
    }

    #[test]
    fn rechaza_el_ciphertext_alterado() {
        let mut ct = encrypt(&key(), &nonce(), b"hola", b"ad");
        ct[0] ^= 1;
        assert_eq!(decrypt(&key(), &nonce(), &ct, b"ad"), Err(CipherError::Decrypt));
    }

    #[test]
    fn rechaza_el_tag_alterado() {
        let mut ct = encrypt(&key(), &nonce(), b"hola", b"ad");
        let ultimo = ct.len() - 1;
        ct[ultimo] ^= 1;
        assert_eq!(decrypt(&key(), &nonce(), &ct, b"ad"), Err(CipherError::Decrypt));
    }

    #[test]
    fn rechaza_la_clave_equivocada() {
        let ct = encrypt(&key(), &nonce(), b"hola", b"ad");
        assert_eq!(decrypt(&[8u8; KEY_LEN], &nonce(), &ct, b"ad"), Err(CipherError::Decrypt));
    }

    #[test]
    fn rechaza_el_nonce_equivocado() {
        let ct = encrypt(&key(), &nonce(), b"hola", b"ad");
        assert_eq!(decrypt(&key(), &[1u8; NONCE_LEN], &ct, b"ad"), Err(CipherError::Decrypt));
    }

    /// El AAD es la cabecera del contenedor. Alterar la versión, el id de
    /// codebook o los parámetros de KDF tiene que invalidar el descifrado.
    #[test]
    fn rechaza_el_aad_alterado() {
        let ct = encrypt(&key(), &nonce(), b"hola", b"cabecera");
        assert_eq!(decrypt(&key(), &nonce(), &ct, b"CABECERA"), Err(CipherError::Decrypt));
    }

    /// Las cuatro causas dan EXACTAMENTE el mismo error. Si alguna se
    /// distinguiera, sería un oráculo para acotar la búsqueda (invariante I4).
    #[test]
    fn los_cuatro_fallos_son_indistinguibles() {
        let ct = encrypt(&key(), &nonce(), b"hola", b"ad");
        let mut alterado = ct.clone();
        alterado[0] ^= 1;

        let errores = [
            decrypt(&[8u8; KEY_LEN], &nonce(), &ct, b"ad").unwrap_err(),
            decrypt(&key(), &[1u8; NONCE_LEN], &ct, b"ad").unwrap_err(),
            decrypt(&key(), &nonce(), &ct, b"otro").unwrap_err(),
            decrypt(&key(), &nonce(), &alterado, b"ad").unwrap_err(),
        ];
        assert!(errores.iter().all(|e| *e == CipherError::Decrypt));
    }

    /// El tamaño del nonce es el que fija el formato del contenedor. Si cambia,
    /// todo blob ya escrito deja de leerse.
    #[test]
    fn el_nonce_mide_96_bits() {
        assert_eq!(NONCE_LEN, 12);
        assert_eq!(NONCE_LEN * 8, 96);
    }

    /// El ciphertext expande exactamente el tag, ni un byte más: la longitud
    /// del texto claro NO se oculta aquí — la oculta el relleno Padmé del
    /// núcleo, una capa más arriba.
    #[test]
    fn la_expansion_es_exactamente_el_tag() {
        for n in [0usize, 1, 15, 16, 17, 1000] {
            let pt = vec![0xABu8; n];
            assert_eq!(encrypt(&key(), &nonce(), &pt, b"").len(), n + TAG_LEN);
        }
    }
}
