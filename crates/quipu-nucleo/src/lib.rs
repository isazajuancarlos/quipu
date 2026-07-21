// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Núcleo agnóstico de Quipu: todo lo que **no** es criptografía.
//!
//! # Por qué existe este crate
//!
//! Quipu va a tener una librería hermana, `quipu-cnsa`, comprometida con las
//! primitivas de CNSA 2.0 (AES-256-GCM, SHA-384, nonce de 96 bits con contador)
//! frente al compromiso de `quipu` (XChaCha20-Poly1305, SHA-256, nonce extendido
//! de 192 bits). Dos compromisos declarados, no dos configuraciones.
//!
//! Copiar el repositorio y dejarlo divergir es como mueren los forks, y en
//! criptografía muere con una vulnerabilidad arreglada en una rama y no en la
//! otra. Así que lo que ambas comparten —el formato del contenedor, el codec
//! base-N, la corrección de errores, el canal visual— vive aquí, una sola vez.
//! Un fallo se arregla una vez.
//!
//! Precedente en casa: `quipu-voprf` ya está separado por razón estructural (su
//! licencia Apache-2.0). Este se separa por razón arquitectónica.
//!
//! # Qué NO vive aquí, y no es negociable
//!
//! Ninguna primitiva criptográfica. Ni AEAD, ni KDF, ni firma, ni intercambio de
//! claves, ni generación de aleatoriedad. Si un módulo de este crate necesita
//! importar `chacha20poly1305`, `argon2`, `sha2`, `ml-kem` o `ed25519`, es que
//! está en el crate equivocado.
//!
//! El corolario incómodo: **este crate no aporta seguridad**. La seguridad de
//! Quipu vive entera en el cifrado (clave + AEAD). Lo de aquí es representación
//! —la "oruga"— y formato. Que sea agnóstico no lo vuelve inofensivo: parsea
//! entrada no confiable, y ahí los fallos son de memoria y de disponibilidad,
//! no de confidencialidad.

pub mod codec;
pub mod container;
pub mod dictionary;
pub mod ecc;
pub mod glyphfont;
pub mod glyphopt;
pub mod glyphscan;
pub mod prelayers;
pub mod render;
