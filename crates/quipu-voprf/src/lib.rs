//! VOPRF: OPRF VERIFICABLE sobre ristretto255, **conforme a RFC 9497**
//! (ciphersuite `ristretto255-SHA512`, modo VOPRF).
//!
//! El servidor publica `Y = k·G` y, con cada evaluacion, adjunta una prueba
//! DLEQ de que uso la MISMA `k` de `Y`, sin revelarla. El cliente VERIFICA la
//! prueba contra la clave publica fijada antes de usar el resultado. Cierra el
//! hallazgo F1: un servidor malicioso no puede dar respuestas falsas sin ser
//! detectado.
//!
//! Toda la mecanica vive en [`rfc9497`] y se verifica contra los vectores
//! oficiales del Apendice A.1.2 (`tests/rfc9497_vectors.rs`). Se re-exporta aqui
//! para que `quipu_voprf::blind(..)` siga siendo el camino corto.
//!
//! ## Ruptura respecto de 0.1.0
//!
//! La version anterior usaba una construccion PROPIA (`quipu/v2/voprf`),
//! inspirada en la RFC pero no conforme: dominio propio, `hash_to_curve` sin
//! `expand_message_xmd` y transcripcion DLEQ propia. No interoperaba con nadie
//! ni heredaba el analisis de seguridad de la RFC. Se elimino, no se deprecio:
//! dejarla solo invitaba a usarla por error.
//!
//! Lo que cambia, y no es reversible:
//!
//! - La **salida pasa de 32 a 64 bytes** (`Hash` es SHA-512; truncarla habria
//!   hecho fallar los vectores).
//! - La **clave publica del servidor cambia para la misma semilla**: ahora se
//!   deriva con `DeriveKeyPair` de la RFC (§3.2).
//! - Todo secreto endurecido con la version anterior queda invalidado.
//!
//! Se hizo con cero clientes, que era la unica ventana: el dominio esta horneado
//! en cada secreto y, como `k`, no rota nunca.

pub mod rfc9497;

pub use rfc9497::{
    blind, derive_key_pair, finalize, BlindState, Server, OUTPUT_LEN, PROOF_LEN,
};

// --- Modulo de Python (feature `python`) -------------------------------------
//
// Se publica en PyPI como `quipu-voprf`, APARTE de `quipu-crypto`. Ese es el
// punto: un cliente del servicio OPRF instala solo esto (Apache-2.0) y nunca
// enlaza el nucleo AGPL en su servidor de autenticacion.
#[cfg(feature = "python")]
mod python {
    use pyo3::exceptions::PyValueError;
    use pyo3::prelude::*;
    use pyo3::types::PyBytes;

    /// Cegado VOPRF del lado cliente. Devuelve `(state, blinded)`: `state` (64 B)
    /// se guarda para `voprf_finalize`; `blinded` (32 B) se envia al servidor.
    /// El servidor NUNCA ve la contrasena.
    #[pyfunction]
    fn voprf_blind<'py>(
        py: Python<'py>,
        password: &[u8],
    ) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        // RFC 9497 §3.3.2: falla si la entrada mapea a la identidad del grupo
        // (InvalidInputError). Astronomicamente improbable, pero la RFC obliga.
        let (st, b) = super::blind(password)
            .ok_or_else(|| PyValueError::new_err("entrada invalida para VOPRF"))?;
        Ok((PyBytes::new(py, &st.to_bytes()), PyBytes::new(py, &b)))
    }

    /// Finaliza VOPRF: VERIFICA la prueba DLEQ contra `server_pub` (fijada) y,
    /// solo si valida, devuelve el secreto endurecido (64 B). Lanza `ValueError`
    /// si la prueba es invalida (servidor deshonesto o clave incorrecta).
    ///
    /// 64 B, no 32: es la salida de RFC 9497 (`Hash` = SHA-512).
    #[pyfunction]
    fn voprf_finalize<'py>(
        py: Python<'py>,
        password: &[u8],
        state: &[u8],
        evaluated: &[u8],
        proof: &[u8],
        server_pub: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let st: [u8; 64] = state
            .try_into()
            .map_err(|_| PyValueError::new_err("state debe ser de 64 bytes"))?;
        let ev: [u8; 32] = evaluated
            .try_into()
            .map_err(|_| PyValueError::new_err("evaluated debe ser de 32 bytes"))?;
        let pf: [u8; super::PROOF_LEN] = proof
            .try_into()
            .map_err(|_| PyValueError::new_err("proof debe ser de 64 bytes"))?;
        let pk: [u8; 32] = server_pub
            .try_into()
            .map_err(|_| PyValueError::new_err("server_pub debe ser de 32 bytes"))?;
        let st = super::BlindState::from_bytes(&st)
            .ok_or_else(|| PyValueError::new_err("state invalido"))?;
        // None = la prueba no valida. Nunca se devuelve un secreto sin verificar.
        super::finalize(password, &st, &ev, &pf, &pk)
            .map(|s| PyBytes::new(py, &s))
            .ok_or_else(|| {
                PyValueError::new_err(
                    "la prueba DLEQ no valida contra la clave publica fijada: \
                     el servidor no es el que fijaste, o roto su clave",
                )
            })
    }

    #[pymodule]
    fn quipu_voprf(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(voprf_blind, m)?)?;
        m.add_function(wrap_pyfunction!(voprf_finalize, m)?)?;
        m.add("__doc__", "VOPRF sobre ristretto255 con pruebas DLEQ (Apache-2.0).")?;
        Ok(())
    }
}
