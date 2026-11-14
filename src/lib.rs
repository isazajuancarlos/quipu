#![forbid(unsafe_code)]
// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

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
// **EL ARMA NO VIAJA EN EL PRODUCTO.** Todo el arsenal ofensivo/interno vive bajo
// `lab` (feature `lab`) en UN solo namespace: `hackerbot` se movió a
// `lab::hackerbot` el 2026-09-02. Antes era `pub mod hackerbot` suelto, API
// pública en todo build por defecto (lo cazó la auditoría del 2026-08-17); ahora
// no hay más que un punto de entrada (`quipu::lab`) que gatear y excluir. Además
// la fuente del arsenal (`src/lab/`) se EXCLUYE del `.crate` publicado, así que
// no viaja ni como fuente: quien consuma el crate no puede compilar `lab` aunque
// pase la feature. Ver `Cargo.toml` (`exclude`) y `lab/mod.rs`.

// El núcleo agnóstico de primitivas vive ahora en su propio crate, para que
// `quipu` y su hermana `quipu-cnsa` compartan UNA sola implementación de todo
// lo que no es criptografía. Se re-exporta módulo a módulo para que
// `quipu::codec::*`, `quipu::ecc::*`, etc. sigan funcionando igual: ningún
// consumidor tiene que cambiar nada. Mismo patrón que `quipu-voprf`.
pub use quipu_nucleo::{codec, ecc, prelayers};
/// Reparto ciego (feature `blindaje`, opt-in). Dos AEAD independientes de los
/// que **ninguno ve el texto en claro**: defiende de que una de las dos
/// librerías esté comprometida, que es lo único que el cifrado normal no
/// cubre. Cuesta el DOBLE de salida, y ese precio es necesario, no un detalle
/// de implementación.
#[cfg(feature = "blindaje")]
pub mod blindaje;
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
/// Cifrado **perforable** (feature `perforable`, opt-in). Destruir la clave al
/// abrir el lacre: *forward secrecy* sobre datos en reposo, vía un PPRF de árbol
/// GGM. **Lee el modelo de amenaza del módulo antes de usarlo**: la raíz es
/// aleatoria (no se deriva de una frase) y una instantánea vieja del estado
/// deshace la protección.
#[cfg(feature = "perforable")]
pub mod perforable;
/// Registro **encadenado** de aperturas del lacre (feature `perforable`): un
/// rastro auditable y a prueba de manipulación de qué lacres se abrieron y en qué
/// orden. Acompaña al sobre de un solo uso de [`perforable`]. Ver [`lacre`].
#[cfg(feature = "perforable")]
pub mod lacre;
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
/// **X-Wing-768** (feature `xwing`, opt-in): el KEM híbrido PQ/T **wire-compatible**
/// con `draft-connolly-cfrg-xwing-kem` (X25519 + ML-KEM-768 + combinador
/// SHA3-256), como opción de INTEROPERABILIDAD. Es distinto del canal a
/// destinatario del núcleo ([`pqhybrid`]), que es X-Wing-*style* pero NO
/// interoperable (ML-KEM-1024 + HKDF, nivel 5). No entra por `api.rs` a
/// propósito: la interoperabilidad vive en el secreto compartido, no en el
/// contenedor propio. Lee el modelo de amenaza del módulo.
#[cfg(feature = "xwing")]
pub mod xwing;
pub mod stream;
// VOPRF vive ahora en su propio crate (Apache-2.0) para que los clientes del
// servicio OPRF no arrastren esta AGPL. Se re-exporta para que `quipu::voprf::*`
// siga funcionando igual: ningun consumidor tiene que cambiar nada.
pub use quipu_voprf as voprf;

#[cfg(feature = "lab")]
pub mod lab;

