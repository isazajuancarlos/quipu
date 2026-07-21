<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas
-->

# quipu-nucleo

Núcleo agnóstico de [Quipu](https://github.com/isazajuancarlos/quipu): todo lo
que **no** es criptografía.

- `codec` — codificación base-N reversible sobre enteros grandes.
- `ecc` — corrección de errores Reed-Solomon del canal visual.
- `prelayers` — capas previas de transformación.
- `render` / `glyphfont` / `glyphopt` / `glyphscan` — canal visual de glifos:
  generación, tipografía, optimización y lectura desde imagen.

## Por qué es un crate aparte

Quipu tendrá una librería hermana, `quipu-cnsa`, comprometida con las primitivas
de [CNSA 2.0](https://www.nsa.gov/) —AES-256-GCM, SHA-384, nonce de 96 bits con
contador— frente al compromiso de `quipu`: XChaCha20-Poly1305, SHA-256 y nonce
extendido de 192 bits. **Dos compromisos declarados, no dos configuraciones.**

La relación es la de Devuan con Debian: no una rama de mantenimiento, sino una
distribución con un compromiso explícito que comparte casi todo y tiene identidad
propia. Un fork sin compromiso declarado se pudre porque nadie sabe cuándo debe
converger; uno con compromiso declarado sabe exactamente en qué diverge.

Copiar el repositorio y dejarlo divergir es como mueren los forks — y en
criptografía muere con una vulnerabilidad arreglada en una rama y no en la otra.
Así que lo que ambas comparten vive aquí, una sola vez. **Un fallo se arregla una
vez.**

## Qué NO vive aquí

Ninguna primitiva criptográfica: ni AEAD, ni KDF, ni firma, ni intercambio de
claves, ni generación de aleatoriedad. Si un módulo de este crate necesitara
importar `chacha20poly1305`, `argon2`, `sha2`, `ml-kem` o `ed25519`, estaría en
el crate equivocado.

## Advertencia

**Este crate no aporta seguridad.** La seguridad de Quipu vive entera en el
cifrado (clave + AEAD); lo de aquí es representación y formato. Que sea agnóstico
no lo vuelve inofensivo: parsea entrada no confiable, y ahí los fallos son de
memoria y de disponibilidad, no de confidencialidad.

No uses este crate por su cuenta esperando protección. Usa
[`quipu`](https://crates.io/crates/quipu).

## Licencia

AGPL-3.0-or-later. © 2024-2026 Juan Carlos Isaza Arenas.

Igual que `quipu`, se ofrece también bajo licencia comercial para quien no pueda
cumplir la AGPL: lo que se cobra es la **exención de publicar**, no el uso.
