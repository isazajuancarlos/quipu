//! Bindings de Python (PyO3). Exponen una API mínima de alto nivel sobre el
//! diccionario ASCII por defecto, para usar Quipu desde Python:
//!
//!   import quipu
//!   s = quipu.encode(b"datos", "passphrase")
//!   d = quipu.decode(s, "passphrase")
//!
//! Construir con:  maturin develop --features python

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::api::{
    decode as core_decode, decode_as_recipient as core_decode_pq,
    decode_verified as core_decode_verified, encode as core_encode,
    encode_signed as core_encode_signed, encode_to_recipient as core_encode_pq, Options,
};
use crate::dictionary::Dictionary;
use crate::glyphopt;
use crate::kdf::KdfParams;
use crate::stream::{
    decrypt_stream_bytes as core_decrypt_stream, encrypt_stream as core_encrypt_stream,
    StreamOptions,
};
use crate::voprf;
use crate::{pqhybrid, pqsign};

/// Diccionario por defecto: 94 símbolos ASCII imprimibles.
fn default_dict() -> Dictionary {
    Dictionary::new((0x21u8..=0x7e).map(|b| b as char).collect())
        .expect("el alfabeto ASCII por defecto es válido")
}

/// Codifica `data` protegido por `passphrase` (con `pepper` opcional).
#[pyfunction]
#[pyo3(signature = (data, passphrase, pepper = None))]
fn encode(data: &[u8], passphrase: &str, pepper: Option<&[u8]>) -> String {
    let dict = default_dict();
    let opts = Options {
        pepper: pepper.unwrap_or(b""),
        kdf_params: KdfParams::default(),
        codebook_id: 0,
    };
    core_encode(data, passphrase, &dict, &opts)
}

/// Decodifica `symbols` con `passphrase` (y `pepper` opcional). Lanza
/// `ValueError` si la autenticación falla.
#[pyfunction]
#[pyo3(signature = (symbols, passphrase, pepper = None))]
fn decode<'py>(
    py: Python<'py>,
    symbols: &str,
    passphrase: &str,
    pepper: Option<&[u8]>,
) -> PyResult<Bound<'py, PyBytes>> {
    let dict = default_dict();
    match core_decode(symbols, passphrase, &dict, pepper.unwrap_or(b"")) {
        Ok(bytes) => Ok(PyBytes::new(py, &bytes)),
        Err(_) => Err(PyValueError::new_err("decode failed: autenticación inválida")),
    }
}

/// Genera un par de claves híbrido post-cuántico. Devuelve `(public, secret)`
/// como bytes.
#[pyfunction]
fn generate_keypair(py: Python<'_>) -> (Bound<'_, PyBytes>, Bound<'_, PyBytes>) {
    let (pk, sk) = pqhybrid::generate_keypair();
    (
        PyBytes::new(py, &pk.to_bytes()),
        PyBytes::new(py, &sk.to_bytes()),
    )
}

/// Cifra `data` hacia la clave pública híbrida del destinatario (post-cuántico).
#[pyfunction]
fn encode_to_recipient(data: &[u8], public_key: &[u8]) -> PyResult<String> {
    let pk = pqhybrid::PublicKey::from_bytes(public_key)
        .ok_or_else(|| PyValueError::new_err("clave pública inválida"))?;
    Ok(core_encode_pq(data, &pk, &default_dict()))
}

/// Descifra con la clave secreta híbrida del destinatario.
#[pyfunction]
fn decode_as_recipient<'py>(
    py: Python<'py>,
    symbols: &str,
    secret_key: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let sk = pqhybrid::SecretKey::from_bytes(secret_key)
        .ok_or_else(|| PyValueError::new_err("clave secreta inválida"))?;
    match core_decode_pq(symbols, &sk, &default_dict()) {
        Ok(bytes) => Ok(PyBytes::new(py, &bytes)),
        Err(_) => Err(PyValueError::new_err("decode failed: autenticación inválida")),
    }
}

/// Genera un par de claves de FIRMA híbrida (Ed25519 + ML-DSA-87). Devuelve
/// `(verifying_key, signing_key)` como bytes. La clave de firma es sensible.
#[pyfunction]
fn generate_signing_keypair(py: Python<'_>) -> (Bound<'_, PyBytes>, Bound<'_, PyBytes>) {
    let (vk, sk) = pqsign::generate_keypair();
    (
        PyBytes::new(py, &vk.to_bytes()),
        PyBytes::new(py, &sk.to_bytes()),
    )
}

/// Firma `data` con la clave de firma híbrida. El resultado es autosuficiente y
/// FIRMADO PERO EN CLARO (autenticidad y no-repudio; NO confidencialidad).
#[pyfunction]
fn encode_signed(data: &[u8], signing_key: &[u8]) -> PyResult<String> {
    let sk = pqsign::SigningKey::from_bytes(signing_key)
        .ok_or_else(|| PyValueError::new_err("clave de firma inválida"))?;
    Ok(core_encode_signed(data, &sk, &default_dict()))
}

/// Verifica la firma de un artefacto contra la clave de verificación FIJADA y,
/// solo si valida, devuelve el mensaje. Lanza `ValueError` si no verifica.
#[pyfunction]
fn decode_verified<'py>(
    py: Python<'py>,
    symbols: &str,
    verifying_key: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let vk = pqsign::VerifyingKey::from_bytes(verifying_key)
        .ok_or_else(|| PyValueError::new_err("clave de verificación inválida"))?;
    match core_decode_verified(symbols, &vk, &default_dict()) {
        Ok(bytes) => Ok(PyBytes::new(py, &bytes)),
        Err(_) => Err(PyValueError::new_err("verificación fallida: firma inválida")),
    }
}

/// Cifra `data` en el formato de streaming AEAD (construcción STREAM, cabecera
/// `QST1`) y devuelve el contenedor completo como bytes. Memoria acotada:
/// procesa por trozos de `chunk_size` bytes (por defecto el del formato; debe
/// estar entre 4 KiB y 16 MiB, si no lanza `ValueError`). El resultado resiste
/// truncado, reordenado, duplicado, splicing entre ficheros y manipulación. A
/// diferencia de `encode`, la salida son bytes binarios, no símbolos.
#[pyfunction]
#[pyo3(signature = (data, passphrase, pepper = None, chunk_size = None))]
fn encrypt_stream<'py>(
    py: Python<'py>,
    data: &[u8],
    passphrase: &str,
    pepper: Option<&[u8]>,
    chunk_size: Option<usize>,
) -> PyResult<Bound<'py, PyBytes>> {
    let mut opts = StreamOptions::default();
    if let Some(p) = pepper {
        opts.pepper = p;
    }
    if let Some(cs) = chunk_size {
        opts.chunk_size = cs;
    }
    // `encrypt_stream` valida `chunk_size` (y los KdfParams) y devuelve un
    // error en vez de entrar en pánico, así un `chunk_size` fuera de rango
    // desde Python se convierte en `ValueError`, no en un cierre del intérprete.
    let mut blob = Vec::new();
    core_encrypt_stream(data, &mut blob, passphrase, &opts)
        .map_err(|e| PyValueError::new_err(format!("encrypt failed: {e}")))?;
    Ok(PyBytes::new(py, &blob))
}

/// Descifra un contenedor de streaming AEAD producido por `encrypt_stream` (con
/// el mismo `pepper`). El `chunk_size` se lee de la cabecera, no hace falta
/// indicarlo. Lanza `ValueError` si la autenticación falla, incluido truncado,
/// reordenado o manipulación.
#[pyfunction]
#[pyo3(signature = (blob, passphrase, pepper = None))]
fn decrypt_stream<'py>(
    py: Python<'py>,
    blob: &[u8],
    passphrase: &str,
    pepper: Option<&[u8]>,
) -> PyResult<Bound<'py, PyBytes>> {
    match core_decrypt_stream(blob, passphrase, pepper.unwrap_or(b"")) {
        Ok(bytes) => Ok(PyBytes::new(py, &bytes)),
        Err(_) => Err(PyValueError::new_err(
            "decrypt failed: autenticación inválida",
        )),
    }
}

/// Distancia mínima entre cualquier par de huellas (métrica de separabilidad).
#[pyfunction]
fn glyph_min_distance(fingerprints: Vec<Vec<u8>>) -> u32 {
    glyphopt::min_pairwise_distance(&fingerprints)
}

/// Selecciona los `k` glifos más separables (farthest-point). Devuelve índices.
#[pyfunction]
fn select_separable(fingerprints: Vec<Vec<u8>>, k: usize) -> Vec<usize> {
    glyphopt::select_separable_subset(&fingerprints, k)
}

/// Cegado VOPRF del lado cliente para hablar con un `quipu-oprf-server`. Devuelve
/// `(state, blinded)`: `state` (64 B) se guarda para `voprf_finalize`; `blinded`
/// (32 B) se envía al servidor. El servidor NUNCA ve la contraseña.
#[pyfunction]
fn voprf_blind<'py>(
    py: Python<'py>,
    password: &[u8],
) -> (Bound<'py, PyBytes>, Bound<'py, PyBytes>) {
    // RFC 9497 §3.3.2: falla si la entrada mapea a la identidad del grupo.
    let (st, b) = voprf::blind(password).expect("entrada inválida para VOPRF");
    (PyBytes::new(py, &st.to_bytes()), PyBytes::new(py, &b))
}

/// Finaliza VOPRF: VERIFICA la prueba DLEQ contra `server_pub` (fijada) y, solo
/// si valida, devuelve el secreto endurecido (32 B). Lanza `ValueError` si la
/// prueba es inválida (servidor deshonesto o clave incorrecta).
#[pyfunction]
fn voprf_finalize<'py>(
    py: Python<'py>,
    password: &[u8],
    state: &[u8],
    evaluated: &[u8],
    proof: &[u8],
    server_pub: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let st_arr: [u8; 64] = state
        .try_into()
        .map_err(|_| PyValueError::new_err("state debe ser de 64 bytes"))?;
    let ev_arr: [u8; 32] = evaluated
        .try_into()
        .map_err(|_| PyValueError::new_err("evaluated debe ser de 32 bytes"))?;
    let pf_arr: [u8; 64] = proof
        .try_into()
        .map_err(|_| PyValueError::new_err("proof debe ser de 64 bytes"))?;
    let sp_arr: [u8; 32] = server_pub
        .try_into()
        .map_err(|_| PyValueError::new_err("server_pub debe ser de 32 bytes"))?;
    let st = voprf::BlindState::from_bytes(&st_arr)
        .ok_or_else(|| PyValueError::new_err("state inválido"))?;
    match voprf::finalize(password, &st, &ev_arr, &pf_arr, &sp_arr) {
        Some(key) => Ok(PyBytes::new(py, &key)),
        None => Err(PyValueError::new_err(
            "prueba DLEQ inválida: servidor deshonesto o clave incorrecta",
        )),
    }
}

/// Módulo `quipu`.
#[pymodule]
fn quipu(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encode, m)?)?;
    m.add_function(wrap_pyfunction!(decode, m)?)?;
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(encode_to_recipient, m)?)?;
    m.add_function(wrap_pyfunction!(decode_as_recipient, m)?)?;
    m.add_function(wrap_pyfunction!(generate_signing_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(encode_signed, m)?)?;
    m.add_function(wrap_pyfunction!(decode_verified, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_stream, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_stream, m)?)?;
    m.add_function(wrap_pyfunction!(glyph_min_distance, m)?)?;
    m.add_function(wrap_pyfunction!(select_separable, m)?)?;
    m.add_function(wrap_pyfunction!(voprf_blind, m)?)?;
    m.add_function(wrap_pyfunction!(voprf_finalize, m)?)?;
    Ok(())
}
