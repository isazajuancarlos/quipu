<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: 2026 Juan Carlos Isaza Arenas
-->

# padme-frame

Padding **Padmé** con un marco de longitud autodescriptivo: `pad` y `unpad`
cierran el círculo, el sobrecoste está acotado, `no_std`, y **cero
dependencias**.

```rust
use padme_frame::{pad, unpad};

let secreto = b"31 bytes que no quiero que midan";
let bloque  = pad(secreto);
assert_eq!(unpad(&bloque).unwrap(), secreto);
```

## Qué problema resuelve

El tamaño de un archivo cifrado habla. Dos ficheros de 1 024 y 1 031 bytes se
distinguen aunque su contenido sea indescifrable, y esa diferencia basta a
menudo para identificar de cuál se trata.

Padmé cuantiza la longitud a un conjunto pequeño de valores. **Medido sobre esta
implementación: 99 999 longitudes distintas colapsan en 189 tamaños
observables**, con un sobrecoste que se mantiene por debajo del 13 %.

Del artículo de Nikitin et al., [*Reducing Metadata Leakage from Encrypted Files
and Communication with PURBs*](https://petsymposium.org/2019/files/papers/issue4/popets-2019-0056.pdf),
PoPETs 2019(4).

## Por qué existe, si Padmé ya estaba implementado

[`padme-padding`](https://crates.io/crates/padme-padding) de jedisct1 —MIT, y de
un autor con todo el crédito del mundo— implementa **la aritmética**: dado `l`,
a cuánto hay que rellenar. Son veinte líneas y están bien.

**Lo que falta después es el marco**, y es donde viven los fallos. Para poder
QUITAR el relleno hay que saber dónde acababan los datos, así que hace falta:

- un prefijo de longitud, y decidir su tamaño y su orden de bytes;
- validar ese prefijo **cuando llega de fuera**, porque uno fabricado que declare
  más longitud de la que hay es una lectura fuera del bloque esperando a ocurrir.

Este crate trae las dos mitades juntas y probadas. `padded_len` sigue estando
expuesta, así que es un superconjunto: si solo quiere la aritmética, aquí la
tiene igual.

## Lo que NO hace

- **No cifra ni autentica.** El relleno va en claro. Esto se aplica al texto en
  claro *antes* de cifrar; la integridad la pone el AEAD de encima.
- **No oculta el tamaño, lo CUANTIZA.** Deja la longitud verdadera dentro de una
  ventana de ~±0,8 %. En el extremo pequeño la ventana es de pocos bytes: un dato
  de 1 a 24 bytes comparte longitud con apenas otro. Si necesita un conjunto de
  tamaños observables verdaderamente pequeño, quiere una escalera —potencias de
  dos—, que cuesta mucho más relleno y esconde mucho más.
- **No es de tiempo constante**, y no lo necesita: no toca material secreto, solo
  longitudes que ya son públicas.

## Procedencia

Extraído de [`quipu-nucleo`](https://crates.io/crates/quipu-nucleo) —AGPL-3.0— y
relicenciado por su autor, que es el mismo. La extracción a un crate hermano ya
había ocurrido y no servía de nada: **lo que hace útil a Padmé fuera de Quipu es
que cualquiera pueda enlazarlo**, y eso lo decide la licencia, no el directorio.

## Licencia

**MIT OR Apache-2.0**, a elección de quien lo use. Es la doble licencia
convencional de Rust, elegida por alcance: es la que el ecosistema espera y la
que no obliga a nadie a leerse nada antes de usarla.

© 2026 Juan Carlos Isaza Arenas.
