<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas
-->

# Fuzzing de Quipu

Seis objetivos libFuzzer sobre los parsers que reciben entrada no confiable.
Cubren la **familia 7** de `docs/ATAQUES_TAXONOMIA.md` (formato y parsing).

```bash
cargo +nightly fuzz list                    # la lista se deriva, no se escribe
cargo +nightly fuzz run parse_signed        # una sesión larga, en local
cargo run --release --example gen_semillas_fuzz   # regenerar el corpus semilla
```

## El idioma de entrada, que es lo que decide qué corpus se comparte

Encadenar corpus «entre objetivos» solo sirve si los objetivos **consumen el
mismo idioma**. Una entrada interesante para un parser que espera un blob crudo
no dice nada a un parser que espera texto de un alfabeto de 4096 glifos CJK: se
rechaza en el primer carácter y gasta una ejecución.

Por eso el criterio no es «todos con todos», sino la tabla:

| Objetivo | Idioma de entrada | Comparte corpus |
|---|---|---|
| `parse_container` | blob crudo (`QUIP…`) | **familia del blob** |
| `unpad` | blob crudo (texto rellenado) | **familia del blob** |
| `parse_signed` | blob crudo (`QSG1…`) | **familia del blob** |
| `parse_recipient` | blob crudo (`QPQ1…`) | **familia del blob** |
| `honey_decrypt` | contenedor `QHNY` con parámetros Argon2 propios | no |
| `codec_roundtrip` | 2 bytes de base + payload | no |

Los cuatro de la familia del blob comparten estructura real —mágico, versión,
banderas, campos de longitud en offsets fijos—, así que lo que uno descubre
(una truncación en la frontera, un campo de longitud que hace aritmética
peligrosa) le sirve a los otros tres. Los dos de abajo quedan fuera porque su
primer byte significa otra cosa; meterlos sería ruido disfrazado de cobertura.

Cuando se añada un objetivo nuevo, lo que hay que decidir es **en qué fila entra**.
Si no entra en ninguna, empieza su propia familia; lo que no vale es dejarlo sin
declarar y suponer que el encadenado lo cubre.

**Lo que el encadenado da hoy, medido y sin adornar: nada de cobertura.** Con los
corpus hermanos enchufados, `parse_container` se queda en `cov: 49` con 5 unidades
y `unpad` en `cov: 32` con 5 — los mismos que tenían solos. No es que el
encadenado falle: es que esos dos parsers son pequeños y su corpus ya los
**satura**, así que no hay nada que ganar. Se deja montado porque no cuesta nada y
porque paga el día que un parser de esa familia crezca; lo que no se hace es
apuntarlo como mejora medida, porque no lo es. La ganancia medida de esta pasada
está toda en los dos objetivos que no fuzzeaban (abajo).

## Los dos objetivos que estaban verdes sin fuzzear nada

Al ir a encadenar el corpus se midió primero lo que había. Lo que había era esto,
y lo llevaba siendo desde que los dos objetivos se añadieron, con el CI en verde:

**`parse_signed` no ejecutaba ni una línea de su cuerpo.** Fijaba la clave con
`VerifyingKey::from_bytes(&[0x42; 2624])` dentro de un `if let Some(vk)`. Esa
clave no parsea —sus 32 primeros bytes son un punto Ed25519 comprimido, y `0x42`
repetido no lo es—, así que la condición era falsa en cada iteración y el `if let`
se saltaba todo, en silencio. Hoy la clave se deriva de una **semilla** de 64
bytes, válida por construcción porque son semillas y no puntos, y si no parseara
el objetivo **se cae**: un `return` silencioso es exactamente lo que dejó pasar
esto, y un objetivo de fuzz que no fuzzea tiene que doler.

**`parse_recipient` sí corría, pero moría en la puerta del alfabeto** (abajo).

Medido antes y después, mismas condiciones — 45 s, `parse_signed`, arrancando de
corpus vacío contra arrancando de las semillas:

| | antes | después |
|---|---|---|
| `cov` | 207 | **1 688** |
| features | 225 | **3 220** |
| corpus final | 10 unidades / 10 B | 128 unidades / 337 KB |
| ejec/s | 2 107 | 78 |

Las 2 107 ejec/s de antes no son una regresión al bajar a 78: eran ejecuciones que
no hacían nada. El coste por ejecución de hoy lo domina la traducción al alfabeto
(conversión de base sobre 4,7 KB), no el parser; para un smoke de 20 s en CI da de
sobra, y en una sesión larga en local es el precio de estar fuzzeando de verdad.

## Por qué `parse_signed` y `parse_recipient` traducen la entrada

Los dos reciben `&str` y empiezan por `dict.decode`, que exige que **cada**
carácter esté en el alfabeto insignia. Hasta el 2026-07-31 se les pasaban los
bytes del fuzzer tal cual, y eso los dejaba muriendo siempre en esa puerta.

Está **medido**, no razonado: `parse_signed` desde corpus vacío hizo 96.923
ejecuciones con la cobertura congelada desde la ejecución nº 5, y su corpus
degeneró a unidades de **un byte** — alargar la entrada no abría nada, porque
todo moría igual. El objetivo llevaba en verde desde que se añadió sin haber
tocado nunca el rebanado de firmas que su propio comentario decía fuzzear.

Hoy cada uno hace dos pasadas: traduce la entrada al alfabeto por el mismo camino
que la usa al construir (con lo que el parser recibe los bytes del fuzzer sin
alterar), y además, si la entrada es UTF-8, la pasa cruda para no perder el
decodificador del alfabeto contra texto hostil.

## Por qué las semillas no son opcional

`decode_verified` rechaza por `TooShort` todo blob de menos de
`SIGNED_PREFIX + SIGNATURE_LEN` = **4701 bytes**. El `-max_len` por defecto de
libFuzzer es **4096**. Sin una semilla más larga que ese umbral, el objetivo *no
puede* construir una entrada que pase la comprobación, corra las horas que corra.

Una semilla del tamaño real resuelve las dos cosas de golpe: pasa la puerta, y
libFuzzer sube solo su `-max_len` al mayor de las unidades del corpus.

`examples/gen_semillas_fuzz.rs` escribe un artefacto válido y sus mutaciones de
frontera (mágico roto, versión desconocida, longitud declarada en 0 / `u32::MAX`,
truncados al mínimo exacto y al mínimo menos uno, un bit volteado en la firma).
Escribe con prefijo `semilla-` y **no borra nada**: lo que libFuzzer haya
descubierto por su cuenta —nombres sha1— se queda donde está.
