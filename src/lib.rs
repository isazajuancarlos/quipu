#![forbid(unsafe_code)]
// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Quipu: librería de codificación con protección criptográfica y simbología propia.
//!
//! Arquitectura por capas (ver [`docs/SPEC.md`](https://github.com/isazajuancarlos/quipu/blob/estable/docs/SPEC.md)):
//!   kdf -> cipher -> codec -> dictionary ; container, prelayers, api.
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
pub use quipu_nucleo::{codec, ecc, prelayers};
/// Honey Encryption (modo con señuelos, opt-in). Ver el modelo de amenaza del
/// módulo: **sin autenticación** por diseño, solo para secretos uniformes de
/// baja entropía; no sustituye al núcleo AEAD.
#[cfg(feature = "honey")]
pub mod honey;
pub mod kdf;
/// Contenedor con negación (feature `negacion`). Un archivo con señuelo y
/// volumen oculto, sin ningún campo que revele si el segundo existe. Protege
/// contra la PRUEBA, no contra la SOSPECHA: leer el encabezado del módulo antes
/// de usarlo.
#[cfg(feature = "negacion")]
pub mod negacion;
pub mod netlimit;
/// OPRF **sin verificación** (sin prueba DLEQ). **OBSOLETO: use [`voprf`].**
///
/// # Por qué está marcado y no solo oculto
///
/// Con este módulo el cliente **no puede saber si el servidor usó la clave
/// correcta**: un servidor deshonesto o comprometido —T4 del modelo de
/// amenaza— desvía la derivación y nadie se entera. `voprf` (RFC 9497) lo
/// cierra con una prueba DLEQ que el cliente verifica contra una clave fijada.
///
/// Llevaba `#[doc(hidden)]`, y eso **no es una barrera**: oculta de la
/// documentación, pero el autocompletado del editor sigue ofreciéndolo, y el
/// autocompletado no lee documentación. `#[deprecated]` sí avisa —en el sitio
/// de uso, con el motivo— sin romper a nadie que ya dependa de él.
///
/// Cero consumidores en el árbol desde el 2026-08-01: el único que quedaba era
/// `examples/v2demo.rs`, que **demostraba precisamente el camino sin
/// verificar** — lo peor posible, porque un ejemplo es lo primero que se copia.
/// Ahora demuestra el verificable, incluida la detección de un servidor
/// deshonesto.
///
/// Se retira en la próxima ruptura de API.
///
/// La marca `#[deprecated]` va en los ÍTEMS y no en el módulo: puesta aquí
/// contagiaría a las funciones de `#[test]` de dentro, y el arnés que genera
/// `#[test]` las referencia desde fuera de cualquier `allow`. Marcar los ítems
/// es además más preciso — apunta exactamente a lo que un consumidor llamaría.
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
