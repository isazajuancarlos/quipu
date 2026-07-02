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
    m.add_function(wrap_pyfunction!(glyph_min_distance, m)?)?;
    m.add_function(wrap_pyfunction!(select_separable, m)?)?;
    Ok(())
}
