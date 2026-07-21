// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! La API de cifrado del perfil CNSA: `encode_to_blob` / `decode_from_blob`.
//!
//! Es la misma secuencia que la de `quipu` —sal aleatoria, Argon2id, subclave,
//! relleno Padmé, AEAD con la cabecera como AAD— con las primitivas del perfil:
//! AES-256-GCM y HKDF-SHA-384.
//!
//! El orden importa y no es negociable:
//!
//! 1. Sal y nonce **aleatorios** en cada operación. La sal es lo que garantiza
//!    que el par `(clave, nonce)` de AES-GCM nunca se repita.
//! 2. Argon2id → clave maestra → HKDF-SHA-384 → subclave de cifrado. La maestra
//!    se borra en cuanto deja de hacer falta.
//! 3. Relleno Padmé **antes** de cifrar: oculta la longitud real del dato.
//! 4. La cabecera **completa** va como Associated Data. Alterar la versión, el
//!    id de codebook, la sal, el nonce o los parámetros de coste invalida el
//!    descifrado.

use zeroize::Zeroize;

use crate::cipher::{self, NONCE_LEN};
use crate::container::{self, ContainerError, Header, VERSION};
use crate::kdf::{self, KdfParams, SALT_LEN};
use quipu_nucleo::prelayers;

/// Etiqueta de dominio de la subclave de cifrado.
///
/// Lleva el nombre del PERFIL, no solo el de la librería: si `quipu` y
/// `quipu-cnsa` usaran la misma etiqueta, dos subclaves de perfiles distintos
/// derivadas de la misma maestra estarían relacionadas de forma innecesaria.
/// Separar dominios es gratis; volver atrás, no.
const CIPHER_SUBKEY_INFO: &[u8] = b"quipu-cnsa/v1/cipher";

/// El RNG del sistema no pudo dar entropía.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinEntropia;

/// Errores del descifrado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// El contenedor no se pudo parsear (magic, versión o longitud).
    Container(ContainerError),
    /// El blob se escribió con otro codebook.
    CodebookMismatch,
    /// No se pudo descifrar. **Una sola variante para todas las causas**:
    /// contraseña mala, ciphertext alterado, AAD alterado o parámetros de coste
    /// fuera de rango. Distinguirlas daría un oráculo (invariante I4).
    Decrypt,
}

/// Opciones de cifrado.
#[derive(Debug, Clone)]
pub struct Options<'a> {
    /// Coste de Argon2id.
    pub kdf_params: KdfParams,
    /// Secreto que vive FUERA del dato (código, HSM, variable de entorno).
    pub pepper: &'a [u8],
    /// Identificador del codebook usado para la representación.
    pub codebook_id: u16,
}

impl Default for Options<'_> {
    fn default() -> Self {
        Self {
            kdf_params: KdfParams::default(),
            pepper: b"",
            codebook_id: 0,
        }
    }
}

/// Construye el contenedor binario cifrado con el perfil CNSA.
pub fn encode_to_blob(
    data: &[u8],
    passphrase: &str,
    codebook_fingerprint: [u8; 8],
    opts: &Options,
) -> Result<Vec<u8>, SinEntropia> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    // Falla ruidosamente si no hay entropía: cifrar con una sal predecible
    // sería peor que no cifrar, porque parecería que funciona (directiva 20).
    getrandom::fill(&mut salt).map_err(|_| SinEntropia)?;
    getrandom::fill(&mut nonce).map_err(|_| SinEntropia)?;

    let mut master = kdf::derive_master_key(passphrase, &salt, opts.pepper, &opts.kdf_params);
    let mut cipher_key = kdf::derive_subkey(&master, CIPHER_SUBKEY_INFO);
    master.zeroize();

    let header = Header {
        version: VERSION,
        flags: 0,
        codebook_id: opts.codebook_id,
        codebook_hash_prefix: codebook_fingerprint,
        salt,
        nonce,
        kdf_mem_kib: opts.kdf_params.mem_kib,
        kdf_iterations: opts.kdf_params.iterations,
        kdf_parallelism: opts.kdf_params.parallelism,
    };

    let mut padded = prelayers::pad(data);
    let aad = header.to_bytes();
    let ciphertext = cipher::encrypt(&cipher_key, &nonce, &padded, &aad);
    cipher_key.zeroize();
    padded.zeroize();

    Ok(container::serialize(&header, &ciphertext))
}

/// Operación inversa de [`encode_to_blob`].
pub fn decode_from_blob(
    blob: &[u8],
    passphrase: &str,
    expected_fingerprint: [u8; 8],
    pepper: &[u8],
) -> Result<Vec<u8>, DecodeError> {
    let (header, ciphertext) = container::parse(blob).map_err(DecodeError::Container)?;

    if header.codebook_hash_prefix != expected_fingerprint {
        return Err(DecodeError::CodebookMismatch);
    }

    // Los parámetros vienen de la cabecera y están autenticados como AAD, PERO
    // la autenticación ocurre después de derivar. Hay que acotarlos antes o un
    // blob de 60 bytes con `mem_kib = u32::MAX` hace reservar 4 TiB.
    let params = KdfParams {
        mem_kib: header.kdf_mem_kib,
        iterations: header.kdf_iterations,
        parallelism: header.kdf_parallelism,
    };
    if !params.is_sane() {
        return Err(DecodeError::Decrypt);
    }

    let mut master = kdf::derive_master_key(passphrase, &header.salt, pepper, &params);
    let mut cipher_key = kdf::derive_subkey(&master, CIPHER_SUBKEY_INFO);
    master.zeroize();

    let aad = header.to_bytes();
    let result = cipher::decrypt(&cipher_key, &header.nonce, ciphertext, &aad);
    cipher_key.zeroize(); // antes de cualquier retorno

    let mut padded = result.map_err(|_| DecodeError::Decrypt)?;
    // El relleno solo se quita DESPUÉS de que el tag valide: hasta entonces el
    // bloque es entrada hostil (invariante I2: autenticar antes de actuar).
    let data = prelayers::unpad(&padded).map_err(|_| DecodeError::Decrypt);
    padded.zeroize();
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    fn barato() -> Options<'static> {
        Options {
            kdf_params: KdfParams {
                mem_kib: 64,
                iterations: 1,
                parallelism: 1,
            },
            pepper: b"",
            codebook_id: 0,
        }
    }

    const HUELLA: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    #[test]
    fn ida_y_vuelta() {
        let blob = encode_to_blob(b"secreto en reposo", "contrasena", HUELLA, &barato()).unwrap();
        let claro = decode_from_blob(&blob, "contrasena", HUELLA, b"").unwrap();
        assert_eq!(claro, b"secreto en reposo");
    }

    #[test]
    fn el_dato_vacio_va_y_vuelve() {
        let blob = encode_to_blob(b"", "pw", HUELLA, &barato()).unwrap();
        assert_eq!(decode_from_blob(&blob, "pw", HUELLA, b"").unwrap(), b"");
    }

    #[test]
    fn rechaza_la_contrasena_equivocada() {
        let blob = encode_to_blob(b"dato", "correcta", HUELLA, &barato()).unwrap();
        assert_eq!(
            decode_from_blob(&blob, "incorrecta", HUELLA, b""),
            Err(DecodeError::Decrypt)
        );
    }

    #[test]
    fn rechaza_otro_codebook() {
        let blob = encode_to_blob(b"dato", "pw", HUELLA, &barato()).unwrap();
        assert_eq!(
            decode_from_blob(&blob, "pw", [9; 8], b""),
            Err(DecodeError::CodebookMismatch)
        );
    }

    #[test]
    fn el_pepper_es_obligatorio_para_abrir() {
        let mut opts = barato();
        opts.pepper = b"secreto-fuera-del-dato";
        let blob = encode_to_blob(b"dato", "pw", HUELLA, &opts).unwrap();
        assert_eq!(
            decode_from_blob(&blob, "pw", HUELLA, b""),
            Err(DecodeError::Decrypt)
        );
        assert_eq!(
            decode_from_blob(&blob, "pw", HUELLA, b"secreto-fuera-del-dato").unwrap(),
            b"dato"
        );
    }

    /// Cada byte de la cabecera es AAD. Alterar CUALQUIERA debe invalidar.
    #[test]
    fn cualquier_alteracion_de_la_cabecera_invalida() {
        let blob = encode_to_blob(b"dato", "pw", HUELLA, &barato()).unwrap();
        // Del byte 5 (flags) en adelante: los 5 primeros son magic+version, que
        // el parseo rechaza antes con otro error, y eso ya se prueba aparte.
        for i in 5..Header::SIZE {
            let mut roto = blob.clone();
            roto[i] ^= 1;
            assert!(
                decode_from_blob(&roto, "pw", HUELLA, b"").is_err(),
                "alterar el byte {i} de la cabecera debía invalidar el descifrado"
            );
        }
    }

    #[test]
    fn rechaza_el_ciphertext_alterado() {
        let mut blob = encode_to_blob(b"dato", "pw", HUELLA, &barato()).unwrap();
        let ultimo = blob.len() - 1;
        blob[ultimo] ^= 1;
        assert_eq!(
            decode_from_blob(&blob, "pw", HUELLA, b""),
            Err(DecodeError::Decrypt)
        );
    }

    /// Una cabecera con coste imposible NO puede hacernos reservar memoria.
    /// Se rechaza antes de derivar, y con el error genérico.
    #[test]
    fn rechaza_los_parametros_de_coste_absurdos_sin_derivar() {
        let mut blob = encode_to_blob(b"dato", "pw", HUELLA, &barato()).unwrap();
        // kdf_mem_kib ocupa 4 bytes tras salt(16) y nonce(12), en 16+16+12 = 44.
        let inicio = 16 + SALT_LEN + NONCE_LEN;
        blob[inicio..inicio + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            decode_from_blob(&blob, "pw", HUELLA, b""),
            Err(DecodeError::Decrypt)
        );
    }

    /// Dos cifrados del MISMO dato con la MISMA contraseña deben dar blobs
    /// distintos: si no, la sal o el nonce no son aleatorios y se filtra que el
    /// contenido se repite.
    #[test]
    fn dos_cifrados_iguales_dan_blobs_distintos() {
        let a = encode_to_blob(b"mismo dato", "pw", HUELLA, &barato()).unwrap();
        let b = encode_to_blob(b"mismo dato", "pw", HUELLA, &barato()).unwrap();
        assert_ne!(a, b, "sal y nonce deben ser aleatorios en cada operación");
        // Y las dos se abren igual.
        assert_eq!(decode_from_blob(&a, "pw", HUELLA, b"").unwrap(), b"mismo dato");
        assert_eq!(decode_from_blob(&b, "pw", HUELLA, b"").unwrap(), b"mismo dato");
    }

    /// El relleno Padmé oculta la longitud: datos de tamaños próximos deben
    /// producir blobs del MISMO tamaño.
    #[test]
    fn el_relleno_agrupa_longitudes_proximas() {
        let a = encode_to_blob(&[0u8; 100], "pw", HUELLA, &barato()).unwrap();
        let b = encode_to_blob(&[0u8; 101], "pw", HUELLA, &barato()).unwrap();
        assert_eq!(a.len(), b.len(), "Padmé debe agrupar 100 y 101 bytes");
    }

    /// Un blob de `quipu` NO se abre con `quipu-cnsa`. Es lo que hay que
    /// exigirle a dos perfiles distintos: que no se confundan en silencio.
    #[test]
    fn no_lee_un_blob_del_perfil_de_quipu() {
        // Cabecera de `quipu`: 68 bytes, nonce de 24. Se simula el tamaño.
        let mut falso = vec![0u8; 68 + 32];
        falso[0..4].copy_from_slice(b"QUIP");
        falso[4] = VERSION;
        // El parseo CNSA lee 56 bytes de cabecera; los campos caen desplazados
        // y el descifrado no puede validar.
        assert!(decode_from_blob(&falso, "pw", HUELLA, b"").is_err());
    }
}
