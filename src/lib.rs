// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Quipu: librería de codificación con protección criptográfica y simbología propia.
//!
//! Arquitectura por capas (ver QUIPU_PROYECTO_Y_REQUISITOS.txt):
//!   kdf -> cipher -> codec -> dictionary -> renderer (opc) ; container, prelayers, api.
//!
//! La seguridad vive en el cifrado (clave + AEAD). El codec y el diccionario son
//! representación (la "oruga"): no aportan seguridad, solo forma.

pub mod antihacker;
pub mod aleatorio;
pub mod api;
pub mod cipher;
pub mod container;
pub mod dictionaries;
pub mod dictionary;
pub mod hackerbot;

// El núcleo agnóstico de primitivas vive ahora en su propio crate, para que
// `quipu` y su hermana `quipu-cnsa` compartan UNA sola implementación de todo
// lo que no es criptografía. Se re-exporta módulo a módulo para que
// `quipu::codec::*`, `quipu::ecc::*`, etc. sigan funcionando igual: ningún
// consumidor tiene que cambiar nada. Mismo patrón que `quipu-voprf`.
pub use quipu_nucleo::{codec, ecc, glyphfont, glyphopt, glyphscan, prelayers, render};
/// Honey Encryption (modo con señuelos, opt-in). Ver el modelo de amenaza del
/// módulo: **sin autenticación** por diseño, solo para secretos uniformes de
/// baja entropía; no sustituye al núcleo AEAD.
#[cfg(feature = "honey")]
pub mod honey;
pub mod kdf;
pub mod netlimit;
/// OPRF **sin verificación** (sin prueba DLEQ). Prefiere `voprf` (verificable):
/// con él el cliente detecta un servidor deshonesto. Se mantiene por
/// compatibilidad y usos de bajo nivel; oculto de la documentación para no
/// invitar a saltarse la verificación.
#[doc(hidden)]
pub mod oprf;
pub mod oprf_net;
pub mod pqhybrid;
pub mod firmante;
pub mod pqsign;
pub mod selftest;
#[cfg(feature = "escrow")]
pub mod shamir;
pub mod stream;
// VOPRF vive ahora en su propio crate (Apache-2.0) para que los clientes del
// servicio OPRF no arrastren esta AGPL. Se re-exporta para que `quipu::voprf::*`
// siga funcionando igual: ningun consumidor tiene que cambiar nada.
pub use quipu_voprf as voprf;

#[cfg(feature = "lab")]
pub mod lab;

#[cfg(feature = "python")]
pub mod python;
