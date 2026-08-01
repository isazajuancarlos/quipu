<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas
-->

# quipu-nucleo

Núcleo agnóstico de [Quipu](https://github.com/isazajuancarlos/quipu): todo lo
que **no** es criptografía.

- `codec` — codificación base-N reversible sobre enteros grandes.
- `container` — el formato del contenedor: cabecera, campos y validación.
- `dictionary` — los alfabetos de la codificación.
- `ecc` — corrección de errores Reed-Solomon.
- `papel` — el portador de papel: trocear la carga, la simbología estándar y
  las tres formas de escribirla para teclear.
- `prelayers` — capas previas de transformación (incluido el relleno Padmé).

Esta lista anunciaba hasta el 2026-08-01 cuatro módulos de canal visual
—`render`, `glyphfont`, `glyphopt`, `glyphscan`— que **no existen desde los PR
#93 y #99**, y se callaba tres que sí. Queda escrito porque es el defecto que la
directiva 24 persigue: la documentación pública sobrevive al código que
describe, y quien la lee no tiene forma de saberlo.

## Features

Ninguna es *default*.

| Feature | Qué añade | Qué arrastra |
|---|---|---|
| `qr` | el símbolo de papel ya renderizado | `qrcode` (cero dependencias transitivas) |
| `palabras` | el marco BIP-39 de la capa tecleable | `sha2` |

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
importar `chacha20poly1305`, `argon2`, `ml-kem` o `ed25519`, estaría en el crate
equivocado.

**La única excepción, y va acotada al pie de la letra:** la feature `palabras`
—no-default— arrastra `sha2`, porque la BIP-39 define su suma de verificación
como los primeros bits de SHA-256 sobre la entropía. No es criptografía: no hay
clave, no hay secreto y no hay nada que proteger — es una suma de verificación
que el formato exige, y cambiarla sería inventar otro formato. **La compilación
por defecto de este crate sigue sin llevar ni una función criptográfica**, y eso
se comprueba con `cargo tree -p quipu-nucleo -e normal`, no leyendo esta frase.

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
