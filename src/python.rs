// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Bindings de Python (PyO3). Exponen una API mínima de alto nivel sobre el
//! diccionario ASCII por defecto, para usar Quipu desde Python:
//!
//!   import quipu
//!   s = quipu.encode(b"datos", "passphrase")
//!   d = quipu.decode(s, "passphrase")
//!
//! Construir con:  maturin develop --features python

use pyo3::exceptions::{PyOSError, PyValueError};

/// El fallo de entropía se traduce a `OSError` y no a `ValueError`: no es que
/// el llamante haya pasado algo mal, es que el sistema no pudo cumplir. En
/// Python esa distinción decide si el `except` correcto está en el código de
/// aplicación o en el de despliegue.
fn sin_entropia(e: quipu_aleatorio::SinEntropia) -> pyo3::PyErr {
    PyOSError::new_err(e.to_string())
}
use crate::aleatorio as quipu_aleatorio;
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};

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
use crate::{pqhybrid, pqsign};
#[cfg(feature = "escrow")]
use crate::shamir;

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
fn generate_keypair(py: Python<'_>) -> PyResult<(Bound<'_, PyBytes>, Bound<'_, PyBytes>)> {
    let (pk, sk) = pqhybrid::generate_keypair().map_err(sin_entropia)?;
    Ok((
        PyBytes::new(py, &pk.to_bytes()),
        PyBytes::new(py, &sk.to_bytes()),
    ))
}

/// Cifra `data` hacia la clave pública híbrida del destinatario (post-cuántico).
#[pyfunction]
fn encode_to_recipient(data: &[u8], public_key: &[u8]) -> PyResult<String> {
    let pk = pqhybrid::PublicKey::from_bytes(public_key)
        .ok_or_else(|| PyValueError::new_err("clave pública inválida"))?;
    core_encode_pq(data, &pk, &default_dict()).map_err(sin_entropia)
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

/// Firma con una clave que vive en un dispositivo PKCS#11 (HSM, token) y **no
/// sale de él**. El artefacto es idéntico al de `encode_signed`; lo verifica el
/// mismo `decode_verified`.
///
/// Es la pieza que un comité de seguridad pide: la clave privada nunca cruza a
/// Python. Este objeto sostiene la sesión con el dispositivo; se crea una vez y
/// se reutiliza. La aplicación abre y autentica el dispositivo por fuera (con
/// `python-pkcs11`, `pkcs11-tool`, etc.) y aquí solo se nombran las claves.
///
///     firmante = quipu.CustodioHsm(
///         "/usr/lib64/pkcs11/libkryoptic_pkcs11.so",
///         pin="1234", ed25519="firma-ed", mldsa="firma-ml")
///     blob = firmante.encode_signed(datos)          # la clave no entra a Python
///     msg  = quipu.decode_verified(blob, firmante.verifying_key())
// `unsendable`: una sesión PKCS#11 está atada al hilo que la abrió —lleva
// estado de login y punteros del módulo—, así que el objeto no puede viajar
// entre hilos. No es una limitación que sortear: es la naturaleza del recurso.
// PyO3 lo hace cumplir en runtime con un error claro si se cruza de hilo, en
// vez de arriesgar corrupción silenciosa.
#[cfg(feature = "hsm")]
#[pyclass(unsendable)]
struct CustodioHsm {
    inner: crate::firmante::pkcs11::CustodioPkcs11,
}

#[cfg(feature = "hsm")]
#[pymethods]
impl CustodioHsm {
    /// Carga el módulo PKCS#11, abre sesión en el primer slot, presenta el PIN
    /// (si se da) y localiza las dos claves por etiqueta.
    #[new]
    #[pyo3(signature = (module, ed25519, mldsa, pin = None))]
    fn new(module: &str, ed25519: &str, mldsa: &str, pin: Option<&str>) -> PyResult<Self> {
        use cryptoki::session::UserType;
        use cryptoki::types::AuthPin;

        let ctx = pkcs11_contexto(module)?;
        let slot = *ctx
            .get_all_slots()
            .map_err(|e| PyOSError::new_err(format!("slots PKCS#11: {e}")))?
            .first()
            .ok_or_else(|| PyOSError::new_err("el módulo PKCS#11 no expone ningún slot"))?;
        let sesion = ctx
            .open_rw_session(slot)
            .map_err(|e| PyOSError::new_err(format!("abrir sesión PKCS#11: {e}")))?;
        if let Some(p) = pin {
            sesion
                .login(UserType::User, Some(&AuthPin::new(p.into())))
                .map_err(|e| PyValueError::new_err(format!("login PKCS#11: {e}")))?;
        }
        let inner = crate::firmante::pkcs11::CustodioPkcs11::por_etiqueta(sesion, ed25519, mldsa)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Firma `data` dentro del dispositivo y devuelve el artefacto codificado.
    fn encode_signed(&self, data: &[u8]) -> PyResult<String> {
        crate::api::encode_signed_con_custodio(data, &self.inner, &default_dict())
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// La clave pública de la identidad del dispositivo, para `decode_verified`.
    fn verifying_key<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        use crate::firmante::Custodio;
        let vk = self
            .inner
            .clave_de_verificacion()
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(PyBytes::new(py, &vk.to_bytes()))
    }
}

/// Contexto PKCS#11 único del proceso. `C_Initialize` solo puede llamarse una
/// vez por librería cargada, así que se comparte; si se pide otro módulo
/// distinto al ya cargado, se avisa en vez de fallar de forma opaca.
#[cfg(feature = "hsm")]
fn pkcs11_contexto(module: &str) -> PyResult<&'static cryptoki::context::Pkcs11> {
    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    use std::sync::OnceLock;
    static CTX: OnceLock<(String, Pkcs11)> = OnceLock::new();
    let (cargado, ctx) = CTX.get_or_init(|| {
        let p = Pkcs11::new(module).expect("cargar el módulo PKCS#11");
        p.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .expect("initialize PKCS#11");
        (module.to_string(), p)
    });
    if cargado != module {
        return Err(PyOSError::new_err(format!(
            "ya hay un módulo PKCS#11 cargado en este proceso ({cargado}); \
             no se puede cargar además {module}"
        )));
    }
    Ok(ctx)
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

/// Parte `secret` en `shares` comparticiones, de las que `threshold` bastan.
///
/// Devuelve una lista de `bytearray`, cada una una compartición serializada que
/// debe custodiarse por separado. Para material de clave de ALTA entropía; no
/// repartas contraseñas con esto (ver `quipu::shamir`).
///
/// **Devuelve `bytearray` y no `bytes` a propósito.** El lado Rust borra su
/// copia al soltarla, pero lo que cruza a Python vive hasta que lo recoja el
/// recolector de basura. Un `bytes` es inmutable: no hay forma de limpiarlo ni
/// queriendo. Un `bytearray` sí se puede sobrescribir en sitio, así que el
/// llamante puede acotar cuánto tiempo permanece vivo:
///
/// ```python
/// partes = quipu.split_secret(clave, 3, 5)
/// # …custodiarlas…
/// for p in partes:
///     p[:] = b"\x00" * len(p)
/// ```
#[cfg(feature = "escrow")]
#[pyfunction]
#[pyo3(name = "split_secret")]
fn split_secret(
    py: Python<'_>,
    secret: &[u8],
    threshold: u8,
    shares: u8,
) -> PyResult<Vec<Py<PyByteArray>>> {
    let partes = shamir::split(secret, threshold, shares)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(partes
        .iter()
        .map(|s| PyByteArray::new(py, &s.to_bytes()).unbind())
        .collect())
}

/// Reconstruye un secreto a partir de al menos `threshold` comparticiones.
///
/// Lanza `ValueError` si faltan comparticiones, si no son del mismo reparto o
/// si alguna está corrupta.
///
/// **Devuelve `bytearray` y no `bytes` a propósito**, por lo mismo que
/// [`split_secret`]: lo que importa no es que exista una copia temporal, sino
/// **cuánto tiempo permanece viva**. En Rust el secreto se borra al salir del
/// ámbito; lo que cruza a Python sobrevive hasta el recolector de basura. Con
/// `bytes` esa vida es incontrolable porque es inmutable; con `bytearray` el
/// llamante la acota:
///
/// ```python
/// clave = quipu.combine_secret(partes)
/// try:
///     firmado = quipu.encode_signed(datos, bytes(clave))
/// finally:
///     clave[:] = b"\x00" * len(clave)   # acota la vida del secreto
/// ```
///
/// No es garantía absoluta: el intérprete pudo copiar el buffer al cruzar la
/// frontera FFI, y esas copias no se pueden alcanzar. Lo que sí hace es pasar de
/// "imposible de limpiar" a "limpiable por quien la tiene".
#[cfg(feature = "escrow")]
#[pyfunction]
#[pyo3(name = "combine_secret")]
fn combine_secret(py: Python<'_>, shares: Vec<Vec<u8>>) -> PyResult<Py<PyByteArray>> {
    let partes: Result<Vec<_>, _> = shares.iter().map(|b| shamir::Share::from_bytes(b)).collect();
    let partes = partes.map_err(|e| PyValueError::new_err(e.to_string()))?;
    let secreto = shamir::combine(&partes).map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(PyByteArray::new(py, &secreto).unbind())
}

// VOPRF NO se expone aquí, a propósito.
//
// Vive en el paquete `quipu-voprf` (PyPI, Apache-2.0). Exponerlo también desde
// `quipu-crypto` daría dos formas de hacer lo mismo en Python, y la de aquí es
// la equivocada: arrastra la AGPL de este núcleo al servidor de auth del
// cliente — justo lo que la separación en `crates/quipu-voprf` existe para
// impedir — y encima le cuelga ML-KEM, ML-DSA y todo lo demás, que no necesita.
//
// Un cliente del servicio OPRF instala `quipu-oprf-django` (o `quipu-voprf` a
// secas) y nada de este crate. Para Rust no cambia nada: `quipu::voprf` sigue
// re-exportado desde lib.rs.
//
// Se quitó antes de publicar 0.8.0: el 0.7.0 de PyPI nunca las expuso, así que
// nadie las usa y borrarlas no rompe a nadie. Ver LICENSING.md §0.

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
    #[cfg(feature = "hsm")]
    m.add_class::<CustodioHsm>()?;
    m.add_function(wrap_pyfunction!(encrypt_stream, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_stream, m)?)?;
    m.add_function(wrap_pyfunction!(glyph_min_distance, m)?)?;
    m.add_function(wrap_pyfunction!(select_separable, m)?)?;
    #[cfg(feature = "escrow")]
    m.add_function(wrap_pyfunction!(split_secret, m)?)?;
    #[cfg(feature = "escrow")]
    m.add_function(wrap_pyfunction!(combine_secret, m)?)?;
    Ok(())
}
