// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Quipu Security Lab: red-team adaptativo AUTO-HOSPEDADO (Etapa A, núcleo CI).
//!
//! Se ataca a sí mismo, aprende de cada corrida y convierte cada brecha en un
//! test de regresión. Todo el módulo está tras `#[cfg(feature = "lab")]`: NO se
//! compila en release ni en la rueda de PyPI (el arma no viaja con el producto).
//!
//! Nunca inventa ni sustituye primitivas: compone las existentes y ataca a Quipu.

pub mod corpus;
pub mod distinguidor;
pub mod engine;
pub mod forge;
#[cfg(feature = "slh")]
pub mod forge_triple;
pub mod guard;
#[cfg(feature = "honey")]
pub mod honey_attack;
#[cfg(feature = "honey")]
pub mod honey_fuzz;
pub mod leak;
pub mod stream_attack;

#[cfg(feature = "lab-offline")]
pub mod guessing;
#[cfg(feature = "lab-offline")]
pub mod timing;
