<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza -->

# Auditoría del pegamento compartido de RustCrypto

**Fecha de lectura: 2026-08-17.** Anclada por huella en
`tests/pegamento_auditado.rs`: si el código cambia, esta auditoría se pone roja
sola. Un veredicto sin SHA es un dato que caduca sin avisar.

## La pregunta

`src/blindaje.rs` promete un **AND**: hacen falta dos componentes comprometidos
para leer el documento. Hasta el 2026-08-16 esa promesa tenía un agujero
documentado en el propio módulo: `aes-gcm` y `chacha20poly1305` **no implementan
el `fn encrypt` que recibe el mensaje**, lo heredan del `impl<T: AeadInOut> Aead
for T` genérico del crate `aead`. O sea que `aead` recibe `S1` en una llamada y
`S2` en la siguiente, en el mismo proceso y el mismo turno, y `S1 xor S2 = P`.

La pregunta de esta auditoría es la que estaba sin responder: **¿qué hace de
verdad ese pegamento con los bytes?**

## Alcance: el camino EJECUTABLE, no el recuento de líneas

Los cuatro paquetes suman 3 501 líneas de código. Auditar las 3 501 habría sido
medir lo fácil: la inmensa mayoría son declaraciones de traits, cotas y tipos
que no ven un byte. Lo que se leyó es lo que se EJECUTA cuando `blindaje` cifra
o descifra:

| paquete | qué corre con el mensaje delante | tamaño real |
|---|---|---|
| `aead` | `Aead::encrypt`/`decrypt` (blanket) y `AeadInOut::encrypt_in_place`/`decrypt_in_place` | **~35 líneas** |
| `inout` | construcción y troceado de `InOutBuf` | ~60 líneas |
| `cipher` | traits de `StreamCipher*`, que delegan | ~40 líneas |
| `crypto-common` | `KeyInit::new` | ~10 líneas |

El cuerpo entero de `aead` que toca el claro es éste:

```rust
let mut buffer = Vec::with_capacity(payload.msg.len() + Self::TagSize::to_usize());
buffer.extend_from_slice(payload.msg);
self.encrypt_in_place(nonce, payload.aad, &mut buffer)?;
```

## Hallazgos

**Ninguno de los cuatro tiene `build.rs`, ni una sola llamada a
`std::io`/`net`/`fs`/`process`, ni un `println!`.** No hay por dónde sacar nada
del proceso sin añadir código nuevo y visible.

| | `unsafe` | `static`/`OnceLock`/`thread_local` | I/O | `build.rs` |
|---|---|---|---|---|
| `aead` | **`#![forbid(unsafe_code)]`** | 0 (ver nota) | 0 | no |
| `cipher` | **`#![forbid(unsafe_code)]`** | 0 | 0 | no |
| `crypto-common` | **`#![forbid(unsafe_code)]`** | 0 | 0 | no |
| `inout` | 30, todos vistas de punteros | 0 | 0 | no |

**Nota sobre los dos `static` de `aead`.** El barrido los encontró en
`src/dev.rs`, y son inertes por partida doble: el módulo está tras
`#[cfg(feature = "dev")]` —que no está activa en este árbol— y los `static`
viven dentro del cuerpo de un `macro_rules!` que genera un `#[test]`. Un cuerpo
de macro no invocada no genera nada.

**Los 30 `unsafe` de `inout`.** Todos son `slice::from_raw_parts`,
`ptr::add` y un `ptr::copy`, sobre el búfer que le pasa el llamante. La
estructura entera es `{ in_ptr, out_ptr, len, PhantomData }`: **no hay dónde
guardar nada**. `inout` es una vista, no un dueño; no asigna memoria en ningún
punto del camino.

## La medición que cambió el diseño

Se calcularon los cierres de dependencias de las dos rutas, resueltos por
**(nombre, versión)**. Eso importa: el `Cargo.lock` de quipu tiene dos `digest`,
dos `crypto-common`, dos `block-buffer` y dos `sha2`, y un grafo indexado solo
por el nombre fusiona o pierde ramas enteras — la primera versión de la medición
daba `subtle` como compartido, que era falso: cuelga de `digest 0.10.7`, que
entra por `fips205`, no de nuestro `sha2 0.11`.

| | |
|---|---|
| cierre del camino AEAD | 32 paquetes |
| cierre de la máscara (`hkdf` + `sha2`) | 23 paquetes |
| **exclusivos del AEAD** | **14** |
| compartidos | 18 |

Los 14 exclusivos son `aead`, `cipher`, `inout`, `aes`, `ctr`, `ghash`,
`polyval`, `chacha20`, `poly1305`, `subtle`, `universal-hash`, `cpubits` y los
dos AEAD. **Ninguno está en el camino del HKDF.** Ése es el hecho sobre el que
se construyó `QBL2`.

De los 18 compartidos, **CUATRO tocan datos**. Este documento dijo «uno» y
luego «dos», y las dos veces estuvo mal por la misma razón: **un recuento no es
un criterio**. Lo que hay que publicar es qué recibe cada uno:

| paquete | qué RECIBE por el camino legítimo | qué le faltaría |
|---|---|---|
| `zeroize` | **`S1` y `S2` en claro** (`Mitad = Zeroizing<Vec<u8>>`, `Drop` en las dos) | **nada** |
| `getrandom` | **`S1` entero**, y lo CONTROLA (`repartir` → `aleatorio::llenar` → `getrandom::fill`) | `S2`, que no ve |
| `block-buffer` | `S2 xor M` (envoltorio de `chacha20`) y bloques de entrada del HKDF | `S1`, que no ve |
| `hybrid-array` | es el TIPO de los bloques (`Block<B> = Array<u8, BlockSize>`) en las dos rutas | según lo que instrumente |

Los dos últimos los encontró la revisión del 2026-08-17, y los dos estaban
tolerados con motivos que contestaban a otra pregunta —«entropía del sistema»,
«sin lógica de datos»— que es exactamente el defecto que este documento decía
haber corregido para `zeroize`. Una excepción cuyo motivo contesta a otra cosa
es una excepción que nadie vuelve a mirar.

**Y sobre la tabla manda el cierre de dependencias**, que es más pesimista: los
cuatro están enlazados dentro de `cipher` y de `digest`, y un crate comprometido
no espera a que se le llame por donde creemos. La columna «qué le faltaría»
describe el ataque barato, no el techo.

El resto son tipos (`crypto-common`, `typenum`, `ctutils`, `cmov`), plataforma
(`libc`, `cfg-if`, `cpufeatures`, `rand_core`, `r-efi`) o macros de compilación
(`syn`, `quote`, `proc-macro2`, `unicode-ident`, `zeroize_derive`).

**Sobre las macros, el motivo que se escribió primero estaba mal encuadrado.**
Decía «solo en tiempo de compilación, nunca con datos del usuario», y en un
modelo de amenaza de CADENA DE SUMINISTRO —que es el modelo entero de este
módulo— un proc-macro comprometido es la **mejor** posición, no la más inocua:
corre en la máquina de compilación e inyecta código arbitrario en el binario que
sí ve los datos. Se toleran porque no hay forma de compilar sin ellos. Es un
riesgo **aceptado**, no un riesgo ausente.

## Veredicto

**El pegamento está limpio, y eso NO cerraba el agujero.** Las dos frases van
juntas a propósito. Que `aead` no exfiltre nada hoy no cambia que reciba las dos
mitades: el modelo de amenaza de `blindaje` es precisamente **que ese crate esté
comprometido**, o sea una versión distinta de la que aquí se leyó. Auditar
reduce el riesgo de lo que hay; no hace verdadera la promesa.

Por eso la auditoría terminó en una construcción y no en un informe:
**`QBL2`** enmascara la mitad de la capa AES con material derivado por HKDF, de
forma que ninguno de los 14 exclusivos —`aead` el primero— vuelve a ver dos
valores cuyo XOR sea el claro. Ver `src/blindaje.rs`, sección «Hasta dónde llega
el AND».

## Lo que esta auditoría NO establece

- **Que `block-buffer` sea inofensivo.** No se auditó, y está en las dos rutas.
  Es el residuo declarado, y lo vigila `tests/pegamento_disjunto.rs`.
- **Que el camino de ejecución sea el único que importa.** Un crate comprometido
  no está obligado a esperar a que se le llame por donde creemos: le vale un
  `Drop` o un inicializador. Por eso el invariante de `QBL2` se apoya en el
  **cierre de dependencias**, que sobreestima el peligro, y no en esta lectura.
- **Que esto siga siendo cierto mañana.** Lo dice la huella, no la confianza.

## Cómo repetirla

```bash
cargo test --features blindaje --test pegamento_auditado   # ¿sigue siendo el mismo código?
cargo test --features blindaje --test pegamento_disjunto   # ¿entró alguien en las dos rutas?
```
