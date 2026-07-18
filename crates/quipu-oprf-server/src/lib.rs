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
pub mod hexutil;
pub mod http;
pub mod keys;
pub mod plans;
pub mod ratelimit;
pub mod store;
