//! Quipu: librería de codificación con protección criptográfica y simbología propia.
//!
//! Arquitectura por capas (ver QUIPU_PROYECTO_Y_REQUISITOS.txt):
//!   kdf -> cipher -> codec -> dictionary -> renderer (opc) ; container, prelayers, api.
//!
//! La seguridad vive en el cifrado (clave + AEAD). El codec y el diccionario son
//! representación (la "oruga"): no aportan seguridad, solo forma.

pub mod antihacker;
pub mod api;
pub mod cipher;
pub mod codec;
pub mod container;
pub mod dictionaries;
pub mod dictionary;
pub mod ecc;
pub mod glyphfont;
pub mod glyphopt;
pub mod hackerbot;
pub mod kdf;
pub mod oprf;
pub mod oprf_net;
pub mod pqhybrid;
pub mod prelayers;
pub mod render;
pub mod voprf;

#[cfg(feature = "python")]
pub mod python;
