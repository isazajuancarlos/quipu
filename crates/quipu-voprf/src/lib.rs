#![forbid(unsafe_code)]
// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

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
//! ## Nota: la construccion propia nunca se publico
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
