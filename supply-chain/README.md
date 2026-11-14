<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# `supply-chain/` — qué garantiza cada archivo, y qué NO

Medido el 2026-08-14. Todo lo de aquí se comprobó con su pareja; lo que no se
pudo medir se dice.

**Esta documentación vive aquí y no en `config.toml` por una razón práctica:
`cargo vet` REESCRIBE ese archivo y se come los comentarios.** Se intentó, y
`cargo vet --locked` se negó a correr con un error de formato hasta quitarlos.
Un documento dentro de un archivo que una herramienta regenera es un documento
que desaparece sin avisar.

## Los dos archivos hacen cosas distintas, y confundirlos es creerse cubierto

| archivo | qué vigila | quién lo escribe |
|---|---|---|
| `config.toml` + `audits.toml` | **si lo que compilamos está limpio** — procedencia y auditoría por `(crate, versión)` | `cargo vet` |
| `ejecutan-al-compilar.txt` | **si CAMBIA lo que corre al compilar** — `build.rs`, proc-macros, fuentes nativas | `conocimiento/lo-que-corre-al-compilar` |

El primero pregunta *«¿es de fiar?»*; el segundo, *«¿es el mismo de ayer?»*.
Ninguno responde por el otro.

## Estado

    65 auditadas · 1 parcial · 94 exentas

Empezó en **167 exentas, 0 auditorías propias y 0 importaciones**: todo exento y
nada mirado. Eso es el estado normal al adoptar cargo-vet —arranca exentando el
árbol para que puedas empezar—, y la segunda mitad no se había hecho.

Cómo se llegó aquí. **Ninguno de los dos pasos es una auditoría nuestra**, y
decirlo importa:

1. **Siete conjuntos de auditoría IMPORTADOS** — Mozilla, Google, Bytecode
   Alliance, Zcash, ISRG, Embark Studios, Fermyon. Son organizaciones que
   auditan de verdad y publican el resultado.
2. **Dieciséis entradas de CONFIANZA en publicador** (`[[trusted.*]]` de
   `audits.toml`): dtolnay, rust-lang-owner, BurntSushi, sunfishcode, cuviper,
   Amanieu, alexcrichton, kennykerr. **A los ocho los avalan ya ISRG, Mozilla y
   Bytecode Alliance a la vez** — no se confía en nadie que esas tres no
   confíen ya.

Se declaran **por crate**, no con `cargo vet trust --all <publicador>`, que es lo
más estrecho que la herramienta ofrece: confiar en dtolnay para `syn` no acepta
cualquier otra cosa que publique.

**LA REGLA VALE POR PERSONA, NO POR PAREJA (crate, persona), y eso hay que
decirlo.** Los ocho publicadores están en los tres conjuntos; pero al nivel que
de verdad importa, solo **10 de las 17** parejas están avaladas por los tres a
la vez. Las excepciones y quién falta:

    cc / rust-lang-owner            falta bytecode-alliance
    num-bigint / cuviper            falta bytecode-alliance
    hashbrown / Amanieu             falta isrg
    linux-raw-sys / sunfishcode     falta isrg
    unicode-ident / dtolnay         falta isrg

**Y hubo una decimoséptima que rompía la regla entera: `autocfg` / cuviper, que
NO avala ninguna de las tres.** Se retiró y volvió a su exención. No es un
detalle: `autocfg` se ejecuta DENTRO de los `build.rs` ajenos —`num-traits` la
usa así—, o sea en nuestra máquina y en la clase de mayor riesgo. Lo cazó la
revisión de seguridad de este mismo cambio, y la corrección fue honrar la regla
en vez de reescribirla para que encajara.

**Sobre la ventana de fechas, con la precisión que faltaba**: lo que dura como
mucho un año es el `end`, o sea lo que queda POR DELANTE. La ventana entera
`start..end` puede ser mucho más ancha —`syn`/dtolnay va de 2019-03-01 a
2027-08-15, ocho años y medio y 251 versiones—. El `start` es siempre la fecha de
la primera publicación de esa persona en ese crate, que es lo más estrecho que la
herramienta produce por ese lado.

## Lo que SÍ discrimina

Quitar una exención sin auditoría que la cubra pone el paso **rojo**. Medido dos
veces, con `cc` y con `curve25519-dalek`:

    Vetting Failed!
      curve25519-dalek:5.0.0 missing ["safe-to-deploy"]     (salida 255)

y verde otra vez al restaurar. O sea que **el verde no es por construcción**: una
dependencia nueva sin cubrir lo pone rojo. Es un trinquete sobre lo que ENTRA.

## Lo que NO mira, y es lo que más importa tras vendorizar

**`cargo vet` audita `(crate, VERSIÓN)`. No mira los BYTES.**

Probado: se añadió una línea a `vendor/cc/src/lib.rs` y `cargo vet --locked`
siguió diciendo *«Vetting Succeeded»*. Git sí lo veía; cargo-vet no.

Es la misma grieta que documenta `.cargo/config.toml` para cargo: nadie ata el
campo `package` con el contenido de `files`. Una auditoría `safe-to-deploy` dice
«la versión 1.2.66 de `cc` se revisó y es segura», y lo que se compila es
`vendor/cc/`, cuyos bytes no están atados a esa versión por ningún mecanismo de
cargo.

Quien cierra ese eslabón es el **anclaje** —`cargo vendor` a un temporal con
`CARGO_HOME` limpio + `diff -r`—, que **ya no es un comando en un comentario**:
es `conocimiento/anclar-vendor`, deja constancia en `anclaje.txt`, y
`lo-que-corre-al-compilar` se pone en NO SE PUDO COMPROBAR si el árbol cambió
después del sello. **Las dos son la misma grieta vista por dos lados, y ninguna
se arregla con la otra.**

## Lo que queda, con su tamaño real

`cargo vet suggest` estima el trabajo restante en **3 038 283 líneas**. Nadie
audita eso a mano, y decirlo es más útil que fingir un plan.

*(Este número decía «3,84 millones» y era el de ANTES de añadir las entradas de
confianza. Lo cazó la revisión de seguridad. Un número medido en un estado y
copiado a otro es justo el dato que caduca sin avisar — directiva 31.)*

De las 94 exentas, las que priorizan son las **14 que EJECUTAN AL COMPILAR** —esas
corren en NUESTRA máquina, no en la del cliente—:

    autocfg · cc · cryptoki-sys · curve25519-dalek · curve25519-dalek-derive
    g2gen · generic-array · getrandom · libsqlite3-sys · pkg-config
    version_check · zerocopy · zerocopy-derive · zeroize_derive

La lista no se mantiene a mano: sale de cruzar las exenciones de `config.toml`
con `ejecutan-al-compilar.txt`.

```bash
ejec=$(grep -oP '^\S+ vendor/\K[^/]+' supply-chain/ejecutan-al-compilar.txt |
       sed 's/-[0-9][0-9.]*$//' | sort -u)
exe=$(grep -oP '^\[\[exemptions\.\K[^\]]+' supply-chain/config.toml | sort -u)
comm -12 <(echo "$ejec") <(echo "$exe")
```

**`cc` sigue exento pese a confiar en `rust-lang-owner`, y el motivo NO es el
que este archivo decía.** Escribí que «la versión que usamos la publicó otra
persona», y es falso: crates.io devuelve `published_by: null` para `cc 1.2.66`
—y para `find-msvc-tools 0.1.9`—. **No la publicó nadie atribuible**: se subió
por *Trusted Publishing* (OIDC desde CI), que no registra usuario.

La diferencia importa, y por eso se corrige en vez de borrarse: yo usaba ese caso
como demostración de que «la confianza no se derrama a versiones que ese
publicador no firmó», y **el ejemplo no demuestra eso**. `cc` no está cubierto
porque falta la atribución, no porque el mecanismo discriminara. Creérselo invita
a añadir más entradas `trusted` pensando que se autolimitan.

*(El efecto lateral sí es tranquilizador, y conviene saberlo: a medida que el
ecosistema migra a OIDC, las entradas `trusted` se vuelven inertes solas. Falla
CERRADO.)*

## El arnés de fuzz: qué lo cubre y qué NO (2026-08-17)

Vendorizar `libfuzzer-sys` metió tres crates en `vendor/` que **no son del
producto**: `arbitrary`, `jobserver` y `libfuzzer-sys`. `fuzz/` es un workspace
aparte —lo tiene que ser, `cargo-fuzz` lo construye en nightly con banderas de
sanitizer— pero **hereda el `.cargo/config.toml` de la raíz**, así que resuelve
contra el mismo `vendor/`.

**Eso rompió el anclaje, y de la peor forma: en silencio.** `cargo vendor` bajaba
solo el árbol del producto, los tres aparecían como *«sólo en vendor»*, el sello
no podía escribirse y `lo-que-corre-al-compilar` se quedaba en **NO SE PUDO
COMPROBAR** — el vigilante de la cadena de suministro, mudo, sin un solo error.
Arreglado declarando el workspace en `arboles-extra.txt`, que `anclar-vendor`
pasa a `cargo vendor --sync`. Reanclado: **158 crates, cero diferencias**.

### Lo que el arnés SÍ tiene

| eje | ¿cubierto? |
|---|---|
| bytes idénticos a crates.io | **sí** — el anclaje ahora sincroniza los dos workspaces |
| qué corre al compilar | **sí** — 54 piezas nuevas en `ejecutan-al-compilar.txt` (550 → 604) |
| congelado, sin red en el build | **sí** — mismo `vendor/`, mismo `config.toml` |

Las 54 piezas son `libfuzzer-sys/build.rs` y las fuentes C++ de libFuzzer.
`arbitrary` y `jobserver` no aportaron ninguna: los dos llevan `build = false` y
no son proc-macro. El `build.rs` se leyó al aceptarlo (46 líneas): compila los
`.cpp` de `libfuzzer/` con `cc` en C++17, o enlaza una librería externa si está
puesto `CUSTOM_LIBFUZZER_PATH`. Ni red, ni nada más.

**DOS de esas 54 las trajo la revisión de seguridad de este mismo cambio, y son
la clase que no se ve venir: los `.def`.** `FuzzerFlags.def` y
`FuzzerExtFunctions.def` no son unidades de traducción —`cc` no las compila
solas— pero cinco `.cpp` las traen con `#include`, y su contenido se convierte
en código. `lo-que-corre-al-compilar` no listaba esa extensión, así que se podía
editar uno de los dos, que el cambio se compilara en la máquina, y que el
manifiesto no lo dijera. Arreglado en la REGLA (`.def` entra en `NATIVAS`), con
su pareja de pruebas y el mutante comprobado, y barridos los **11** repositorios
con manifiesto: los `.def` de quipu son los únicos del disco, y los otros diez
siguen AL DÍA.

**Y la lista vigila de MÁS, a propósito**: el `read_dir("libfuzzer")` del
`build.rs` no es recursivo, así que `afl/afl_driver.cpp` y los tres de
`dataflow/` están listados y no se compilan. Cerrar de más es el lado seguro; se
escribe para que nadie lea esta lista como «lo que se compila».

**Y ahí está el punto que no se puede rebajar: el arnés COMPILA C++ DE TERCEROS
EN NUESTRA MÁQUINA.** Que no viaje en el producto no lo saca del riesgo —lo
cambia de sitio, del cliente a nosotros—, y ése es exactamente el eje que
`ejecutan-al-compilar.txt` vigila. Por eso el árbol del arnés entra en el
perímetro en vez de declararse fuera.

### Lo que el arnés NO tiene, y es una decisión

**`cargo vet` NO lo alcanza**, y no se le va a pedir que lo alcance. Medido:

    cargo vet --manifest-path fuzz/Cargo.toml --store-path supply-chain --locked
    → 5 sin vetar: arbitrary 1.4.2 · getrandom 0.3.4 · jobserver 0.1.34
                   libfuzzer-sys 0.4.13 · r-efi 5.3.0

Son **cinco, no tres** — `getrandom 0.3.4` y `r-efi 5.3.0` entran por la línea
nueva de `getrandom`, que el producto no usa. Vale la pena decirlo porque la
cuenta anterior era de tres y salió de mirar el `Cargo.toml`, no de correr la
herramienta.

Cubrirlos con `cargo vet` costaría **un segundo store** (el del producto lo
regenera `cargo vet` y podaría lo que no ve) y cinco exenciones más — o sea
cinco líneas que dicen *«exento»*, que es la palabra para «no lo ha mirado
nadie». `cargo vet` responde *«¿es de fiar para DESPLEGAR?»*, y esto no se
despliega: no entra en la rueda, ni en el binario, ni en el contenedor.

**La determinación, entonces:** el perímetro de `cargo vet` es el **PRODUCTO**;
el del anclaje y el de `ejecutan-al-compilar.txt` es **todo lo que se compila
aquí**, arnés incluido. Un tercero que pregunte por la cadena de suministro
recibe esta tabla, no un verde que abarque de más.

*(Si algún día el arnés dejara de ser solo nuestro —si se publicara, o si un
cliente lo compilara— esta decisión cambia, porque cambia quién ejecuta.)*

## Solo quipu usa cargo-vet

Comprobado en los repositorios Rust: **ninguno más tiene
`supply-chain/config.toml`**.

Lo que sí tienen es `ejecutan-al-compilar.txt`, que es la otra mitad. **Son 11 y
ya no falta nexus** (medido el 2026-08-17 corriendo la herramienta sobre todos):
chasqui, chunsua, chuspa, guaca, informes, inventario, medico, mirilla, nexus,
quipu y tunjo, los once AL DÍA. Cuando se escribió esta frase eran «10 de 11» y
nexus era la excepción; se corrige por medición, que es para lo que sirve
volver a verificarlas.

## Correrlo

    cargo vet --locked          # lo que corre el verde (ci.yml)
    cargo vet suggest           # qué falta y cuánto pesa    (necesita RED)
    cargo vet prune             # quita exenciones ya cubiertas
    cargo vet fmt               # reformatea el store; se come los comentarios

**`suggest` y refrescar los imports necesitan RED, y eso NO contradice el
protocolo.** Vendorizar quitó la red del BUILD; auditar es otra fase, se hace a
mano, y lo que se descarga son datos de auditoría, no código que se ejecute. Lo
mismo vale para `cargo deny check advisories`, que consulta RustSec. Son los dos
instrumentos que sí miran si lo congelado está limpio.
