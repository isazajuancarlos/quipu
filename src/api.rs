//! Fachada de la librería: une todo el pipeline.
//!
//! encode: datos -> KDF(passphrase+pepper) -> AEAD -> contenedor -> codec -> diccionario -> símbolos
//! decode: símbolos -> diccionario -> codec -> contenedor -> KDF -> AEAD -> datos
//!
//! La seguridad vive en KDF + AEAD. El codec y el diccionario son representación.

use crate::cipher::{self, NONCE_LEN};
use crate::codec;
use crate::container::{self, ContainerError, Header, VERSION};
use crate::dictionary::{Dictionary, DictionaryError};
use crate::kdf::{self, KdfParams, SALT_LEN};
use crate::antihacker;
use crate::oprf_net;
use crate::pqhybrid;
use crate::pqsign;
use crate::prelayers;
use crate::voprf;

pub use crate::stream::{
    decrypt_stream, decrypt_stream_bytes, encrypt_stream, encrypt_stream_bytes, StreamError,
    StreamOptions,
};

/// Etiqueta de dominio HKDF para la subclave de cifrado.
const CIPHER_SUBKEY_INFO: &[u8] = b"quipu/v1/cipher";

/// Opciones de codificación.
pub struct Options<'a> {
    /// Secreto que vive fuera del dato (código/HSM/env). `b""` si no se usa.
    pub pepper: &'a [u8],
    /// Coste Argon2id (dificultad ajustable).
    pub kdf_params: KdfParams,
    /// Identificador del codebook (informativo en la cabecera).
    pub codebook_id: u16,
}

impl Default for Options<'_> {
    fn default() -> Self {
        Self {
            pepper: b"",
            kdf_params: KdfParams::default(),
            codebook_id: 0,
        }
    }
}

/// Errores de decodificación.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Un símbolo no pertenece al diccionario.
    Symbol(DictionaryError),
    /// La cabecera del contenedor es inválida.
    Container(ContainerError),
    /// El codebook no corresponde al usado al codificar.
    CodebookMismatch,
    /// Descifrado fallido: passphrase/pepper incorrectos o datos alterados.
    Decrypt,
    /// La firma híbrida no valida: mensaje alterado o firmante incorrecto.
    BadSignature,
}

/// Codifica `data` protegido por `passphrase`, representado con `dict`.
pub fn encode(data: &[u8], passphrase: &str, dict: &Dictionary, opts: &Options) -> String {
    // Autoprueba de arranque: una vez por proceso. Tras la primera, el coste
    // medido es de ~8,7 ns por llamada — despreciable, y órdenes de magnitud
    // menor que el Argon2id que esta misma función va a ejecutar (64 MiB, 3
    // iteraciones por defecto). No tiene sentido dejar la ruta más usada sin
    // verificar para ahorrar eso.
    crate::selftest::ensure();

    let blob = encode_to_blob(data, passphrase, dict.fingerprint(), opts);
    let indices = codec::encode_base_n(&blob, dict.base());
    dict.encode(&indices)
        .expect("los índices del codec están en [0, base)")
}

/// Operación inversa de [`encode`].
pub fn decode(
    symbols: &str,
    passphrase: &str,
    dict: &Dictionary,
    pepper: &[u8],
) -> Result<Vec<u8>, DecodeError> {
    // Autoprueba de arranque: una vez por proceso. Tras la primera, el coste
    // medido es de ~8,7 ns por llamada — despreciable, y órdenes de magnitud
    // menor que el Argon2id que esta misma función va a ejecutar (64 MiB, 3
    // iteraciones por defecto). No tiene sentido dejar la ruta más usada sin
    // verificar para ahorrar eso.
    crate::selftest::ensure();

    let indices = dict.decode(symbols).map_err(DecodeError::Symbol)?;
    let blob = codec::decode_base_n(&indices, dict.base());
    decode_from_blob(&blob, passphrase, dict.fingerprint(), pepper)
}

/// Construye el contenedor binario cifrado (modo passphrase), sin la capa de
/// representación. Reutilizable por canales alternativos (p. ej. imagen).
pub fn encode_to_blob(
    data: &[u8],
    passphrase: &str,
    codebook_fingerprint: [u8; 8],
    opts: &Options,
) -> Vec<u8> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut salt).expect("RNG del sistema");
    getrandom::getrandom(&mut nonce).expect("RNG del sistema");

    let mut master = kdf::derive_master_key(passphrase, &salt, opts.pepper, &opts.kdf_params);
    let mut cipher_key = kdf::derive_subkey(&master, CIPHER_SUBKEY_INFO);
    antihacker::wipe(&mut master); // ya no se necesita tras derivar la subclave

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

    // Precapa: padding Padmé sobre el plaintext (oculta la longitud real).
    let mut padded = prelayers::pad(data);

    // La cabecera completa es el Associated Data: la ata al ciphertext.
    let aad = header.to_bytes();
    let ciphertext = cipher::encrypt(&cipher_key, &nonce, &padded, &aad);
    antihacker::wipe(&mut cipher_key);
    antihacker::wipe(&mut padded); // el plaintext con padding ya no se necesita

    container::serialize(&header, &ciphertext)
}

/// Operación inversa de [`encode_to_blob`].
pub fn decode_from_blob(
    blob: &[u8],
    passphrase: &str,
    expected_fingerprint: [u8; 8],
    pepper: &[u8],
) -> Result<Vec<u8>, DecodeError> {
    let (header, ciphertext) = container::parse(blob).map_err(DecodeError::Container)?;

    // Verifica que se decodifica con el codebook correcto.
    if header.codebook_hash_prefix != expected_fingerprint {
        return Err(DecodeError::CodebookMismatch);
    }

    // Los parámetros KDF vienen de la cabecera. Aunque están autenticados (AAD),
    // la autenticación ocurre DESPUÉS de derivar la clave, así que primero hay
    // que rechazar valores fuera de rango para evitar un DoS por memoria/overflow.
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
    antihacker::wipe(&mut master);

    let aad = header.to_bytes();
    let result = cipher::decrypt(&cipher_key, &header.nonce, ciphertext, &aad);
    antihacker::wipe(&mut cipher_key); // wipe antes de cualquier retorno

    let mut padded = result.map_err(|_| DecodeError::Decrypt)?;
    // Quita el padding Padmé. Tras validar el tag AEAD, el bloque es de confianza.
    let data = prelayers::unpad(&padded).map_err(|_| DecodeError::Decrypt);
    antihacker::wipe(&mut padded); // el plaintext intermedio ya no se necesita
    data
}

// ============================ Modo online (OPRF, antibot real) ============================

/// Errores del modo online.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnlineError {
    /// Fallo de red al hablar con el servidor.
    Network,
    /// El servidor denegó la consulta (rate-limit).
    Denied,
    /// La PRUEBA DLEQ no validó: el servidor no usó la clave pública fijada
    /// (servidor deshonesto/comprometido o clave incorrecta).
    Verification,
    /// Fallo de decodificación.
    Decode(DecodeError),
}

/// Endurece la passphrase vía el servidor VOPRF, VERIFICANDO la prueba contra la
/// clave pública fijada (`server_pub`). Cierra el hallazgo F1.
///
/// Devuelve 64 B: es la salida de RFC 9497 (`Hash` = SHA-512). Antes eran 32,
/// con la construcción propia; truncarla haría fallar los vectores oficiales.
fn harden(
    passphrase: &str,
    server_addr: &str,
    server_pub: &[u8; 32],
) -> Result<[u8; voprf::OUTPUT_LEN], OnlineError> {
    // `blind` puede fallar si la entrada mapea a la identidad (RFC §3.3.2:
    // InvalidInputError). Es astronómicamente improbable, pero no se ignora.
    let (state, blinded) = voprf::blind(passphrase.as_bytes()).ok_or(OnlineError::Verification)?;
    let resp = oprf_net::evaluate_remote_verified(server_addr, &blinded)
        .map_err(|_| OnlineError::Network)?;
    let (z, proof) = resp.ok_or(OnlineError::Denied)?;
    voprf::finalize(passphrase.as_bytes(), &state, &z, &proof, server_pub)
        .ok_or(OnlineError::Verification)
}

/// Como [`encode`] pero ENDURECE la passphrase vía un servidor VOPRF: adivinarla
/// requiere consultar al servidor (rate-limit real), y el cliente VERIFICA que
/// el servidor usó la clave correcta (`server_pub` fijada). El output se añade al
/// pepper. Tanto encode como decode deben hablar con el mismo servidor.
pub fn encode_online(
    data: &[u8],
    passphrase: &str,
    server_addr: &str,
    server_pub: &[u8; 32],
    dict: &Dictionary,
    opts: &Options,
) -> Result<String, OnlineError> {
    let hardened = harden(passphrase, server_addr, server_pub)?;
    let mut pepper = opts.pepper.to_vec();
    pepper.extend_from_slice(&hardened);
    let opts2 = Options {
        pepper: &pepper,
        kdf_params: opts.kdf_params,
        codebook_id: opts.codebook_id,
    };
    Ok(encode(data, passphrase, dict, &opts2))
}

/// Operación inversa de [`encode_online`] (también consulta y verifica).
pub fn decode_online(
    symbols: &str,
    passphrase: &str,
    server_addr: &str,
    server_pub: &[u8; 32],
    dict: &Dictionary,
    base_pepper: &[u8],
) -> Result<Vec<u8>, OnlineError> {
    let hardened = harden(passphrase, server_addr, server_pub)?;
    let mut pepper = base_pepper.to_vec();
    pepper.extend_from_slice(&hardened);
    decode(symbols, passphrase, dict, &pepper).map_err(OnlineError::Decode)
}

// ============================ Canal visual (imagen) ============================

/// Cifra `data` y lo representa como una imagen PNG en escala de grises.
pub fn encode_to_image(data: &[u8], passphrase: &str, opts: &Options) -> Vec<u8> {
    let blob = encode_to_blob(data, passphrase, [0u8; 8], opts);
    crate::render::bytes_to_png(&blob)
}

/// Operación inversa de [`encode_to_image`].
pub fn decode_from_image(
    png: &[u8],
    passphrase: &str,
    pepper: &[u8],
) -> Result<Vec<u8>, DecodeError> {
    let blob = crate::render::png_to_bytes(png)
        .ok_or(DecodeError::Container(ContainerError::TooShort))?;
    decode_from_blob(&blob, passphrase, [0u8; 8], pepper)
}

/// Como [`encode_to_image`] pero añade corrección de errores Reed-Solomon
/// (`parity` bytes/bloque) para tolerar ruido del canal (foto/impreso).
pub fn encode_to_robust_image(
    data: &[u8],
    passphrase: &str,
    opts: &Options,
    parity: u8,
) -> Vec<u8> {
    let blob = encode_to_blob(data, passphrase, [0u8; 8], opts);
    let protected = crate::ecc::protect(&blob, parity);
    crate::render::bytes_to_png(&protected)
}

/// Operación inversa de [`encode_to_robust_image`]: corrige errores y descifra.
pub fn decode_from_robust_image(
    png: &[u8],
    passphrase: &str,
    pepper: &[u8],
) -> Result<Vec<u8>, DecodeError> {
    let protected = crate::render::png_to_bytes(png)
        .ok_or(DecodeError::Container(ContainerError::TooShort))?;
    let blob = crate::ecc::recover(&protected).ok_or(DecodeError::Decrypt)?;
    decode_from_blob(&blob, passphrase, [0u8; 8], pepper)
}

/// Cifra `data` y lo pinta como una tira de GLIFOS del alfabeto IA nativo.
pub fn encode_to_glyph_image(data: &[u8], passphrase: &str, opts: &Options) -> Vec<u8> {
    let blob = encode_to_blob(data, passphrase, [0u8; 8], opts);
    let font = crate::glyphfont::standard();
    let indices = codec::encode_base_n(&blob, font.base());
    font.render(&indices)
}

/// Operación inversa de [`encode_to_glyph_image`]: reconoce los glifos y descifra.
pub fn decode_from_glyph_image(
    png: &[u8],
    passphrase: &str,
    pepper: &[u8],
) -> Result<Vec<u8>, DecodeError> {
    let font = crate::glyphfont::standard();
    let indices = font
        .recognize(png)
        .ok_or(DecodeError::Container(ContainerError::TooShort))?;
    let blob = codec::decode_base_n(&indices, font.base());
    decode_from_blob(&blob, passphrase, [0u8; 8], pepper)
}

// ============================ Modo híbrido post-cuántico ============================

/// Magic del contenedor híbrido (X25519 + ML-KEM).
const HYBRID_MAGIC: [u8; 4] = *b"QPQ1";
const HYBRID_VERSION: u8 = 1;
/// Bytes de cabecera híbrida antes de la encapsulación: magic+version+flags+nonce.
const HYBRID_PREFIX: usize = 4 + 1 + 1 + NONCE_LEN;

/// Cifra `data` hacia la clave pública híbrida del destinatario (post-cuántico).
/// No usa passphrase: la clave de contenido sale del KEM híbrido.
pub fn encode_to_recipient(
    data: &[u8],
    recipient: &pqhybrid::PublicKey,
    dict: &Dictionary,
) -> String {
    let (mut content_key, encapsulation) = pqhybrid::encapsulate(recipient);
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).expect("RNG del sistema");

    // Cabecera (AAD): magic | version | flags | nonce | encapsulación.
    let mut header = Vec::with_capacity(HYBRID_PREFIX + encapsulation.len());
    header.extend_from_slice(&HYBRID_MAGIC);
    header.push(HYBRID_VERSION);
    header.push(0u8); // flags
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&encapsulation);

    let mut padded = prelayers::pad(data);
    let ciphertext = cipher::encrypt(&content_key, &nonce, &padded, &header);
    antihacker::wipe(&mut content_key);
    antihacker::wipe(&mut padded);

    let mut blob = header;
    blob.extend_from_slice(&ciphertext);
    let indices = codec::encode_base_n(&blob, dict.base());
    dict.encode(&indices)
        .expect("los índices del codec están en [0, base)")
}

/// Descifra con la clave secreta híbrida del destinatario.
pub fn decode_as_recipient(
    symbols: &str,
    recipient: &pqhybrid::SecretKey,
    dict: &Dictionary,
) -> Result<Vec<u8>, DecodeError> {
    let indices = dict.decode(symbols).map_err(DecodeError::Symbol)?;
    let blob = codec::decode_base_n(&indices, dict.base());

    let header_len = HYBRID_PREFIX + pqhybrid::ENCAPSULATION_LEN;
    if blob.len() < header_len {
        return Err(DecodeError::Container(ContainerError::TooShort));
    }
    if blob[0..4] != HYBRID_MAGIC {
        return Err(DecodeError::Container(ContainerError::BadMagic));
    }
    if blob[4] != HYBRID_VERSION {
        return Err(DecodeError::Container(ContainerError::UnsupportedVersion(
            blob[4],
        )));
    }
    let nonce: [u8; NONCE_LEN] = blob[6..HYBRID_PREFIX].try_into().expect("24 bytes");
    let encapsulation = &blob[HYBRID_PREFIX..header_len];
    let aad = &blob[0..header_len];
    let ciphertext = &blob[header_len..];

    let mut content_key =
        pqhybrid::decapsulate(recipient, encapsulation).ok_or(DecodeError::Decrypt)?;
    let result = cipher::decrypt(&content_key, &nonce, ciphertext, aad);
    antihacker::wipe(&mut content_key);

    let mut padded = result.map_err(|_| DecodeError::Decrypt)?;
    let data = prelayers::unpad(&padded).map_err(|_| DecodeError::Decrypt);
    antihacker::wipe(&mut padded);
    data
}

// ============================ Modo firmado (autenticidad, no confidencialidad) ============================

/// Magic del contenedor firmado híbrido (Ed25519 + ML-DSA).
const SIGNED_MAGIC: [u8; 4] = *b"QSG1";
const SIGNED_VERSION: u8 = 1;
/// Cabecera del contenedor firmado antes del mensaje: magic+version+flags+msg_len.
const SIGNED_PREFIX: usize = 4 + 1 + 1 + 4;

#[cfg(feature = "slh")]
const SIGNED_TRIPLE_MAGIC: [u8; 4] = *b"QSG3";
#[cfg(feature = "slh")]
const SIGNED_TRIPLE_VERSION: u8 = 1;
/// Cabecera QSG3: magic+version+flags+msg_len (idéntico layout que QSG1).
#[cfg(feature = "slh")]
const SIGNED_TRIPLE_PREFIX: usize = 4 + 1 + 1 + 4;

/// Firma `data` con la clave triple-híbrida y lo representa con `dict` (contenedor
/// QSG3). Autosuficiente, FIRMADO PERO EN CLARO: autenticidad/integridad/no-repudio,
/// no confidencialidad. Modo de alta garantía (firma ~34 KB, firma lenta).
#[cfg(feature = "slh")]
pub fn encode_signed_triple(
    data: &[u8],
    signer: &pqsign::TripleSigningKey,
    dict: &Dictionary,
) -> String {
    let signature = signer.sign(data);
    let mut blob = Vec::with_capacity(SIGNED_TRIPLE_PREFIX + data.len() + signature.len());
    blob.extend_from_slice(&SIGNED_TRIPLE_MAGIC);
    blob.push(SIGNED_TRIPLE_VERSION);
    blob.push(0u8); // flags
    blob.extend_from_slice(&(data.len() as u32).to_be_bytes());
    blob.extend_from_slice(data);
    blob.extend_from_slice(&signature);

    let indices = codec::encode_base_n(&blob, dict.base());
    dict.encode(&indices)
        .expect("los índices del codec están en [0, base)")
}

/// Verifica un artefacto QSG3 contra la clave triple FIJADA y, sólo si valida,
/// devuelve el mensaje. Un artefacto QSG1 aquí da `BadMagic` (sin downgrade).
#[cfg(feature = "slh")]
pub fn decode_verified_triple(
    symbols: &str,
    verifier: &pqsign::TripleVerifyingKey,
    dict: &Dictionary,
) -> Result<Vec<u8>, DecodeError> {
    let indices = dict.decode(symbols).map_err(DecodeError::Symbol)?;
    let blob = codec::decode_base_n(&indices, dict.base());

    if blob.len() < SIGNED_TRIPLE_PREFIX + pqsign::TRIPLE_SIGNATURE_LEN {
        return Err(DecodeError::Container(ContainerError::TooShort));
    }
    if blob[0..4] != SIGNED_TRIPLE_MAGIC {
        return Err(DecodeError::Container(ContainerError::BadMagic));
    }
    if blob[4] != SIGNED_TRIPLE_VERSION {
        return Err(DecodeError::Container(ContainerError::UnsupportedVersion(
            blob[4],
        )));
    }
    let msg_len = u32::from_be_bytes(blob[6..10].try_into().expect("4 bytes")) as usize;

    // Aritmética verificada (misma defensa F4 que decode_verified).
    let Some(msg_end) = SIGNED_TRIPLE_PREFIX.checked_add(msg_len) else {
        return Err(DecodeError::Container(ContainerError::TooShort));
    };
    let Some(expected_len) = msg_end.checked_add(pqsign::TRIPLE_SIGNATURE_LEN) else {
        return Err(DecodeError::Container(ContainerError::TooShort));
    };
    if blob.len() != expected_len {
        return Err(DecodeError::Container(ContainerError::TooShort));
    }
    let message = &blob[SIGNED_TRIPLE_PREFIX..msg_end];
    let signature = &blob[msg_end..];

    if !verifier.verify(message, signature) {
        return Err(DecodeError::BadSignature);
    }
    Ok(message.to_vec())
}

/// Firma `data` con la clave híbrida `signer` y lo representa con `dict`.
///
/// El resultado es un artefacto AUTOSUFICIENTE, FIRMADO PERO EN CLARO: cualquiera
/// con la clave de verificación puede comprobar autoría e integridad Y leer el
/// mensaje. Da autenticidad, integridad y no-repudio; NO da confidencialidad (si
/// necesitas ocultar el contenido, usa además un modo de cifrado).
pub fn encode_signed(data: &[u8], signer: &pqsign::SigningKey, dict: &Dictionary) -> String {
    let signature = signer.sign(data);

    let mut blob = Vec::with_capacity(SIGNED_PREFIX + data.len() + signature.len());
    blob.extend_from_slice(&SIGNED_MAGIC);
    blob.push(SIGNED_VERSION);
    blob.push(0u8); // flags
    blob.extend_from_slice(&(data.len() as u32).to_be_bytes());
    blob.extend_from_slice(data);
    blob.extend_from_slice(&signature);

    let indices = codec::encode_base_n(&blob, dict.base());
    dict.encode(&indices)
        .expect("los índices del codec están en [0, base)")
}

/// Verifica la firma de un artefacto de [`encode_signed`] contra la clave pública
/// FIJADA `verifier` y, sólo si valida, devuelve el mensaje.
pub fn decode_verified(
    symbols: &str,
    verifier: &pqsign::VerifyingKey,
    dict: &Dictionary,
) -> Result<Vec<u8>, DecodeError> {
    let indices = dict.decode(symbols).map_err(DecodeError::Symbol)?;
    let blob = codec::decode_base_n(&indices, dict.base());

    if blob.len() < SIGNED_PREFIX + pqsign::SIGNATURE_LEN {
        return Err(DecodeError::Container(ContainerError::TooShort));
    }
    if blob[0..4] != SIGNED_MAGIC {
        return Err(DecodeError::Container(ContainerError::BadMagic));
    }
    if blob[4] != SIGNED_VERSION {
        return Err(DecodeError::Container(ContainerError::UnsupportedVersion(
            blob[4],
        )));
    }
    let msg_len = u32::from_be_bytes(blob[6..10].try_into().expect("4 bytes")) as usize;

    // La longitud declarada debe encajar EXACTAMENTE con mensaje + firma fija.
    // Aritmética VERIFICADA: en targets de 32 bits, `msg_len` (hasta ~4 GiB)
    // podría desbordar `usize` al sumar y hacer pasar el chequeo con un rango de
    // slice fuera de límites (panic/DoS). `checked_add` lo rechaza limpiamente.
    let Some(msg_end) = SIGNED_PREFIX.checked_add(msg_len) else {
        return Err(DecodeError::Container(ContainerError::TooShort));
    };
    let Some(expected_len) = msg_end.checked_add(pqsign::SIGNATURE_LEN) else {
        return Err(DecodeError::Container(ContainerError::TooShort));
    };
    if blob.len() != expected_len {
        return Err(DecodeError::Container(ContainerError::TooShort));
    }
    let message = &blob[SIGNED_PREFIX..msg_end];
    let signature = &blob[msg_end..];

    if !verifier.verify(message, signature) {
        return Err(DecodeError::BadSignature);
    }
    Ok(message.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn test_opts() -> Options<'static> {
        // Coste bajo para tests rápidos.
        Options {
            pepper: b"",
            kdf_params: KdfParams {
                mem_kib: 64,
                iterations: 1,
                parallelism: 1,
            },
            codebook_id: 1,
        }
    }

    fn ascii_dict() -> Dictionary {
        Dictionary::new((0x21u8..=0x7e).map(|b| b as char).collect()).unwrap()
    }

    #[test]
    fn round_trips_data() {
        let dict = ascii_dict();
        let data = b"mensaje secreto";
        let symbols = encode(data, "clave-correcta", &dict, &test_opts());
        let back = decode(&symbols, "clave-correcta", &dict, b"").unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn hides_length_within_padme_bucket() {
        // 100 y 101 bytes caen en el mismo cubo Padmé -> misma longitud de salida.
        let dict = ascii_dict();
        let a = encode(&[0u8; 100], "clave", &dict, &test_opts());
        let b = encode(&[1u8; 101], "clave", &dict, &test_opts());
        assert_eq!(a.chars().count(), b.chars().count());
    }

    #[test]
    fn round_trips_empty_data() {
        let dict = ascii_dict();
        let symbols = encode(b"", "clave", &dict, &test_opts());
        assert_eq!(decode(&symbols, "clave", &dict, b"").unwrap(), b"");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let dict = ascii_dict();
        let symbols = encode(b"datos", "correcta", &dict, &test_opts());
        assert_eq!(
            decode(&symbols, "incorrecta", &dict, b""),
            Err(DecodeError::Decrypt)
        );
    }

    #[test]
    fn wrong_pepper_fails() {
        let dict = ascii_dict();
        let opts = Options {
            pepper: b"pepper-correcto",
            ..test_opts()
        };
        let symbols = encode(b"datos", "clave", &dict, &opts);
        assert_eq!(
            decode(&symbols, "clave", &dict, b"pepper-incorrecto"),
            Err(DecodeError::Decrypt)
        );
    }

    #[test]
    fn decode_rejects_malicious_kdf_params_without_panic() {
        // Regresión del hallazgo del hackerbot: parámetros KDF gigantes en una
        // cabecera manipulada causaban panic por overflow en Argon2.
        use crate::container::{self, Header, VERSION};
        let dict = ascii_dict();
        let header = Header {
            version: VERSION,
            flags: 0,
            codebook_id: 1,
            codebook_hash_prefix: dict.fingerprint(),
            salt: [0u8; 16],
            nonce: [0u8; 24],
            kdf_mem_kib: u32::MAX,
            kdf_iterations: u32::MAX,
            kdf_parallelism: u32::MAX,
        };
        let blob = container::serialize(&header, b"ciphertext-falso-con-tag-relleno");
        let indices = crate::codec::encode_base_n(&blob, dict.base());
        let symbols = dict.encode(&indices).unwrap();
        assert_eq!(
            decode(&symbols, "clave", &dict, b""),
            Err(DecodeError::Decrypt)
        );
    }

    #[test]
    fn tampered_symbols_fail() {
        let dict = ascii_dict();
        let symbols = encode(b"datos importantes", "clave", &dict, &test_opts());
        // Cambia un símbolo por otro válido del alfabeto.
        let mut chars: Vec<char> = symbols.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert!(decode(&tampered, "clave", &dict, b"").is_err());
    }

    #[test]
    fn decode_verified_rejects_overflowing_msg_len_without_panic() {
        // Contenedor firmado manipulado con msg_len = u32::MAX: en 32-bit la suma
        // SIGNED_PREFIX+msg_len+SIGNATURE_LEN desbordaría; `checked_add` lo
        // rechaza limpiamente en cualquier target, sin panic de slice.
        let dict = ascii_dict();
        let mut blob = Vec::new();
        blob.extend_from_slice(b"QSG1");
        blob.push(1); // version
        blob.push(0); // flags
        blob.extend_from_slice(&u32::MAX.to_be_bytes()); // msg_len malicioso
        blob.extend_from_slice(&[0u8; 200]); // cuerpo corto (no cuadra)
        let indices = crate::codec::encode_base_n(&blob, dict.base());
        let symbols = dict.encode(&indices).unwrap();
        let (vk, _sk) = pqsign::generate_keypair();
        // No debe entrar en pánico; devuelve error de contenedor/firma.
        assert!(decode_verified(&symbols, &vk, &dict).is_err());
    }

    proptest! {
        #[test]
        fn round_trips_any_data(
            data in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            let dict = ascii_dict();
            let symbols = encode(&data, "clave", &dict, &test_opts());
            let back = decode(&symbols, "clave", &dict, b"").unwrap();
            prop_assert_eq!(back, data);
        }
    }

    #[test]
    fn image_channel_round_trips() {
        let data = b"secreto representado como imagen";
        let png = encode_to_image(data, "clave", &test_opts());
        assert_eq!(
            &png[0..8],
            &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]
        );
        assert_eq!(decode_from_image(&png, "clave", b"").unwrap(), data);
    }

    #[test]
    fn image_wrong_passphrase_fails() {
        let png = encode_to_image(b"x", "correcta", &test_opts());
        assert!(decode_from_image(&png, "incorrecta", b"").is_err());
    }

    #[test]
    fn glyph_image_round_trips() {
        let data = b"secreto pintado con glifos IA nativos";
        let png = encode_to_glyph_image(data, "clave", &test_opts());
        assert_eq!(&png[0..8], &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
        assert_eq!(decode_from_glyph_image(&png, "clave", b"").unwrap(), data);
    }

    #[test]
    fn robust_image_survives_channel_noise() {
        let data = b"este mensaje sobrevive al ruido del canal impreso";
        let png = encode_to_robust_image(data, "clave", &test_opts(), 16);
        // Simula ruido: voltea 8 bytes del payload (corregibles con parity=16).
        let mut payload = crate::render::png_to_bytes(&png).unwrap();
        for byte in &mut payload[5..13] {
            *byte ^= 0xFF;
        }
        let noisy = crate::render::bytes_to_png(&payload);
        let recovered = decode_from_robust_image(&noisy, "clave", b"").unwrap();
        assert_eq!(recovered, data);
    }

    fn spawn_voprf_server(
        connections: usize,
        allowed: bool,
    ) -> (String, [u8; 32], std::thread::JoinHandle<()>) {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = voprf::Server::new();
        let pubkey = server.public_key();
        let handle = std::thread::spawn(move || {
            for _ in 0..connections {
                let (mut stream, _) = listener.accept().unwrap();
                crate::oprf_net::handle_connection_verified(&mut stream, &server, allowed).unwrap();
            }
        });
        (addr, pubkey, handle)
    }

    #[test]
    fn online_mode_round_trips_via_server() {
        let (addr, pk, handle) = spawn_voprf_server(2, true); // encode + decode
        let dict = ascii_dict();
        let data = b"secreto endurecido online";
        let sym = encode_online(data, "clave", &addr, &pk, &dict, &test_opts()).unwrap();
        let back = decode_online(&sym, "clave", &addr, &pk, &dict, b"").unwrap();
        assert_eq!(back, data);
        handle.join().unwrap();
    }

    #[test]
    fn online_mode_denied_by_server_errors() {
        let (addr, pk, handle) = spawn_voprf_server(1, false); // servidor deniega
        let dict = ascii_dict();
        let r = encode_online(b"x", "clave", &addr, &pk, &dict, &test_opts());
        assert_eq!(r, Err(OnlineError::Denied));
        handle.join().unwrap();
    }

    #[test]
    fn online_mode_detects_dishonest_server() {
        // El cliente fija una clave pública que NO es la del servidor -> la
        // prueba DLEQ no valida -> se detecta (Verification), no se usa la salida.
        let (addr, _real_pk, handle) = spawn_voprf_server(1, true);
        let wrong_pk = voprf::Server::new().public_key();
        let dict = ascii_dict();
        let r = encode_online(b"x", "clave", &addr, &wrong_pk, &dict, &test_opts());
        assert_eq!(r, Err(OnlineError::Verification));
        handle.join().unwrap();
    }

    #[test]
    fn hybrid_round_trips_to_recipient() {
        let (pk, sk) = pqhybrid::generate_keypair();
        let dict = ascii_dict();
        let data = b"secreto resistente a cuantica";
        let symbols = encode_to_recipient(data, &pk, &dict);
        assert_eq!(decode_as_recipient(&symbols, &sk, &dict).unwrap(), data);
    }

    #[test]
    fn hybrid_wrong_recipient_fails() {
        let (pk, _sk) = pqhybrid::generate_keypair();
        let (_pk2, sk2) = pqhybrid::generate_keypair();
        let dict = ascii_dict();
        let symbols = encode_to_recipient(b"datos", &pk, &dict);
        assert!(decode_as_recipient(&symbols, &sk2, &dict).is_err());
    }

    #[test]
    fn signed_round_trips_and_reveals_message() {
        let (vk, sk) = pqsign::generate_keypair();
        let dict = ascii_dict();
        let data = b"acta firmada verificable por terceros";
        let symbols = encode_signed(data, &sk, &dict);
        assert_eq!(decode_verified(&symbols, &vk, &dict).unwrap(), data);
    }

    #[test]
    fn signed_wrong_signer_fails() {
        let (_vk, sk) = pqsign::generate_keypair();
        let (vk2, _sk2) = pqsign::generate_keypair();
        let dict = ascii_dict();
        let symbols = encode_signed(b"datos", &sk, &dict);
        assert_eq!(
            decode_verified(&symbols, &vk2, &dict),
            Err(DecodeError::BadSignature)
        );
    }

    #[test]
    fn signed_tampered_message_fails() {
        let (vk, sk) = pqsign::generate_keypair();
        let dict = ascii_dict();
        let symbols = encode_signed(b"transferir 100", &sk, &dict);
        // Sustituye un símbolo por otro válido del alfabeto.
        let mut chars: Vec<char> = symbols.chars().collect();
        chars[SIGNED_PREFIX] = if chars[SIGNED_PREFIX] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert!(decode_verified(&tampered, &vk, &dict).is_err());
    }

    #[test]
    fn signed_empty_message_round_trips() {
        let (vk, sk) = pqsign::generate_keypair();
        let dict = ascii_dict();
        let symbols = encode_signed(b"", &sk, &dict);
        assert_eq!(decode_verified(&symbols, &vk, &dict).unwrap(), b"");
    }

    proptest! {
        #[test]
        fn signed_round_trips_any_data(
            data in proptest::collection::vec(any::<u8>(), 0..96),
        ) {
            let (vk, sk) = pqsign::generate_keypair();
            let dict = ascii_dict();
            let symbols = encode_signed(&data, &sk, &dict);
            let back = decode_verified(&symbols, &vk, &dict).unwrap();
            prop_assert_eq!(back, data);
        }
    }

    #[cfg(feature = "slh")]
    #[test]
    fn triple_signed_round_trips() {
        let dict = ascii_dict();
        let (vk, sk) = pqsign::generate_triple_keypair();
        let data = b"artefacto de altisimo valor";
        let symbols = encode_signed_triple(data, &sk, &dict);
        assert_eq!(decode_verified_triple(&symbols, &vk, &dict).unwrap(), data);
    }

    #[cfg(feature = "slh")]
    #[test]
    fn triple_wrong_key_rejected() {
        let dict = ascii_dict();
        let (_vk, sk) = pqsign::generate_triple_keypair();
        let (vk2, _sk2) = pqsign::generate_triple_keypair();
        let symbols = encode_signed_triple(b"datos", &sk, &dict);
        assert!(matches!(
            decode_verified_triple(&symbols, &vk2, &dict),
            Err(DecodeError::BadSignature)
        ));
    }

    #[cfg(feature = "slh")]
    #[test]
    fn triple_region_tamper_rejected() {
        let dict = ascii_dict();
        let (vk, sk) = pqsign::generate_triple_keypair();
        let symbols = encode_signed_triple(b"transferir 100", &sk, &dict);
        let mut chars: Vec<char> = symbols.chars().collect();
        chars[SIGNED_TRIPLE_PREFIX] = if chars[SIGNED_TRIPLE_PREFIX] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert!(decode_verified_triple(&tampered, &vk, &dict).is_err());
    }

    #[cfg(feature = "slh")]
    #[test]
    fn triple_empty_message_round_trips() {
        let dict = ascii_dict();
        let (vk, sk) = pqsign::generate_triple_keypair();
        let symbols = encode_signed_triple(b"", &sk, &dict);
        assert_eq!(decode_verified_triple(&symbols, &vk, &dict).unwrap(), b"");
    }

    #[cfg(feature = "slh")]
    #[test]
    fn triple_rejects_overflowing_msg_len_without_panic() {
        let dict = ascii_dict();
        let (vk, _sk) = pqsign::generate_triple_keypair();
        let mut blob = Vec::new();
        blob.extend_from_slice(b"QSG3");
        blob.push(1); // version
        blob.push(0); // flags
        blob.extend_from_slice(&u32::MAX.to_be_bytes()); // msg_len enorme
        let indices = codec::encode_base_n(&blob, dict.base());
        let symbols = dict.encode(&indices).unwrap();
        assert!(decode_verified_triple(&symbols, &vk, &dict).is_err());
    }
}
