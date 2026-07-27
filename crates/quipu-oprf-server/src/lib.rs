// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! `quipu-oprf-server`: plano de datos del endurecimiento OPRF/VOPRF de Quipu.
//!
//! Expone la primitiva `voprf::Server` (de la lib `quipu`) como una API HTTP
//! autenticada por API key y medida por cuota. La gestión de keys (`store`) es
//! la costura con el plano de control (pagos vía portafolio).
//!
//! Milestones (ver docs/quipu-oprf-server-plan.md):
//!   M1 — almacén de usuarios + API keys + CLI de admin.
//!   M2 — servidor HTTP sobre `voprf::Server` (auth + rate-limit + medición).
//!   M3 — endpoints /admin (costura con la pasarela) + despliegue.
//!   M4 — cliente de referencia (`examples/client.rs`).

pub mod client;
/// Custodia del seed por umbral. Tras `--features custodia`: es herramienta de
/// operador y no viaja en el binario del VPS.
#[cfg(feature = "custodia")]
pub mod custodia;
pub mod hexutil;
pub mod http;
pub mod keys;
pub mod plans;
pub mod ratelimit;
pub mod store;

/// `info` de `DeriveKeyPair` (RFC 9497 §3.2). Fijo y versionado: entra en la
/// derivación, así que cambiarlo cambia la clave para la misma semilla e
/// invalida todos los secretos endurecidos. **No se toca.**
///
/// Vive AQUÍ y no en `main.rs` a propósito. La usan el arranque del servidor y
/// la verificación de una restauración (`custodia`), y si cada uno llevara su
/// copia podrían divergir: la prueba de restauración seguiría en verde
/// comparando contra la clave equivocada, que es el único modo en que un
/// respaldo puede mentir sin que se note.
pub const DERIVE_INFO: &[u8] = b"quipu-oprf-server-v1";
