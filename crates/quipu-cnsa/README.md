<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas
-->

# quipu-cnsa

Perfil de [Quipu](https://github.com/isazajuancarlos/quipu) alineado con los
algoritmos de **CNSA 2.0**: AES-256-GCM, HKDF-SHA-384 y ML-KEM-1024.

## Antes de nada: alineación no es cumplimiento

**Esta librería implementa los algoritmos que exige CNSA 2.0. NO está validada
FIPS 140-3.**

No lo estará por escribir más código. La validación FIPS 140-3 es un proceso de
laboratorio acreditado, con coste y calendario propios, y **es a lo que se
destina la financiación que buscamos**, no un requisito previo que ya hayamos
cumplido.

Si necesitas cumplimiento formal —no alineación— para un contrato o una
auditoría, esto todavía no te sirve. Preferimos que lo sepas ahora y no cuando
alguien lo pregunte en una revisión.

Esta advertencia está en la primera pantalla a propósito. No es letra pequeña.

## Qué relación tiene con `quipu`

La de Devuan con Debian: no una rama de mantenimiento, sino una distribución con
un **compromiso declarado** que comparte casi todo y tiene identidad propia.

| | `quipu` | `quipu-cnsa` |
|---|---|---|
| AEAD | XChaCha20-Poly1305 | **AES-256-GCM** |
| Nonce | 192 bits (extendido) | **96 bits** |
| Derivación de subclaves | HKDF-**SHA-256** | HKDF-**SHA-384** |
| Huella de codebook | SHA-256 | **SHA-384** |
| Cabecera del contenedor | 68 bytes | **56 bytes** |
| Contraseña → clave | Argon2id | Argon2id (**igual**) |
| Formato, codec, ECC, glifos | `quipu-nucleo` | `quipu-nucleo` (**el mismo**) |

Todo lo que no es criptografía vive en
[`quipu-nucleo`](../quipu-nucleo) y se arregla **una vez**. Copiar el
repositorio y dejarlo divergir es como mueren los forks — y en criptografía
muere con una vulnerabilidad corregida en una rama y no en la otra.

## Si puedes elegir, usa `quipu`

Que exista este perfil no significa que sea mejor.

**En hardware sin aceleración AES, AES-GCM es una regresión.** Las
implementaciones en software son más lentas y bastante más difíciles de escribir
en tiempo constante: las tablas de sustitución de AES son un canal lateral
clásico. ChaCha20 no tiene tablas y es constante por construcción.

Este perfil existe para quien tiene un **mandato normativo**, no para quien busca
la mejor criptografía disponible.

## Argon2id no se cambia, y es deliberado

CNSA 2.0 **no se pronuncia** sobre derivación desde contraseña: cubre cifrado,
firma, intercambio de claves y hash, no el paso contraseña → clave.

Sustituir Argon2id por PBKDF2 para «parecer conforme» sería **debilitar el
sistema por estética normativa**. PBKDF2 no tiene coste en memoria y es órdenes
de magnitud más barato de atacar con hardware dedicado. Se mantiene Argon2id y
se declara aquí en vez de esconderlo.

## El nonce de 96 bits no necesita estado global

Es la primera duda de cualquiera que vea AES-GCM con 96 bits, y merece respuesta
explícita. El fallo catastrófico de AES-GCM es reutilizar el par
`(clave, nonce)`.

Aquí **la clave es distinta en cada operación**: se deriva con Argon2id desde una
sal aleatoria de 128 bits generada en el momento de cifrar. Repetir
`(clave, nonce)` exigiría colisionar la sal *y* el nonce; la unicidad la
garantiza la sal, no el nonce.

En términos de SP 800-38D, el modo normal usa la construcción aleatoria
(§8.2.2), cuyo límite son 2³² invocaciones **por clave**, y aquí cada clave se
usa exactamente **una** vez. Un contador persistente no añadiría seguridad y sí
un archivo de estado que corromper y sincronizar entre procesos.

## Lo que todavía NO cubre

**CNSA 2.0 exige LMS o XMSS (SP 800-208) para firma de software.** SLH-DSA no
cubre ese renglón: es FIPS-205, otro documento y otro uso. Es un desajuste real,
no una elección de diseño, y está pendiente.

Tampoco están todavía: el modo streaming, el canal de destinatario (ML-KEM), la
firma y los enlaces para otros lenguajes. Llegan sobre el mismo núcleo.

## Estado

**Alfa.** Existe, compila y sus pruebas pasan. No ha sido auditada de forma
independiente. No la uses para proteger nada que importe de verdad todavía.

## Licencia

AGPL-3.0-or-later. © 2024-2026 Juan Carlos Isaza Arenas.

Como `quipu`, se ofrece también bajo licencia comercial para quien no pueda
cumplir la AGPL: lo que se cobra es la **exención de publicar**, no el uso.
