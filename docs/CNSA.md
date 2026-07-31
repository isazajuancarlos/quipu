<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas
-->

# Quipu y CNSA 2.0

**Posición: entre `quipu` y `quipu-cnsa` están cubiertas CUATRO de las cinco
funciones de CNSA 2.0. Falta una —la firma de software (SP 800-208)— y hay una
salvedad que se explica abajo: lo asimétrico de `quipu` es HÍBRIDO. Nada de esto
es cumplimiento: alineación de algoritmos no es validación FIPS 140-3.**

Este documento existe para que la divergencia sea una posición defendible y no
un hueco que alguien descubra en una evaluación.

**Reverificado contra el repositorio el 31 de julio de 2026.** La versión
anterior de este archivo decía que el perfil «no está construido», y desde el
2026-07-21 la mitad simétrica SÍ lo está: `crates/quipu-cnsa` existe en el
workspace. Un documento que le dice a un comprador lo que hay tiene que decir lo
que hay.

---

## Qué exige CNSA 2.0 y qué hace Quipu

| Función | CNSA 2.0 exige | `quipu` | `quipu-cnsa` | ¿Cubierta? |
|---|---|---|---|:--:|
| Establecimiento de clave | ML-KEM-1024 | X25519 **+** ML-KEM-1024 (híbrido) | — | **sí, con salvedad** |
| Firma | ML-DSA-87 | Ed25519 **+** ML-DSA-87 (híbrido) | — | **sí, con salvedad** |
| Cifrado simétrico | AES-256 | XChaCha20-Poly1305 | **AES-256-GCM** | **sí**, en la hermana |
| Resumen | SHA-384 (preferido) o SHA-512 | SHA-256 | **SHA-384** | **sí**, en la hermana |
| Firma de software/firmware | LMS o XMSS (SP 800-208) | SLH-DSA-SHA2-256s (feature `slh`) | — | **no** |

**LA SALVEDAD, y conviene decirla antes de que la pregunten:** lo asimétrico de
`quipu` es HÍBRIDO. `pqhybrid` combina X25519 con ML-KEM-1024 y `pqsign` combina
Ed25519 con ML-DSA-87 — comprobado en `src/pqhybrid.rs` y `src/pqsign.rs`, no
citado de memoria. Los algoritmos que CNSA 2.0 nombra están ahí y con los
parámetros de TOP SECRET, pero lo que se ejecuta lleva además la mitad clásica.
Para un comprador que exija exactamente lo que dice la lista, un perfil CNSA
necesitaría las variantes PURAS, que hoy no existen: reusar el código de `quipu`
tal cual no da esa afirmación, y eso es trabajo nuevo, no cableado.

La coincidencia en la parte post-cuántica no es casual: ML-KEM-1024 y ML-DSA-87
son los parámetros para TOP SECRET y se eligieron por eso. La divergencia
simétrica tampoco es descuido.

**Fecha que importa:** desde **enero de 2027**, toda adquisición nueva de un
National Security System estadounidense debe soportar CNSA 2.0.

---

## Por qué XChaCha20-Poly1305 y no AES-256

**Resistencia a canal lateral en software.** AES en software puro es vulnerable
a ataques de temporización por caché: sus tablas de sustitución se indexan con
datos derivados de la clave. La defensa es la aceleración por hardware (AES-NI,
ARMv8 Crypto). ChaCha20 no tiene tablas: es suma, XOR y rotación sobre
registros, constante en tiempo por construcción, en cualquier CPU.

Quipu está pensado para **datos en reposo** en máquinas cualesquiera —incluido
un portátil viejo o un contenedor sin las extensiones—, no para un servidor
homogéneo. Ahí la garantía por construcción vale más que la garantía por
hardware disponible.

**Nonce extendido.** XChaCha20 usa nonce de 192 bits, que se puede generar al
azar sin llevar contador ni temer colisiones. AES-GCM usa 96 bits, donde el
nonce aleatorio empieza a ser arriesgado alrededor de 2³² mensajes con la misma
clave y obliga a llevar estado. Para cifrado de archivos, eso es una fuente de
fallo operativo real.

**Este argumento tiene un límite, y conviene decirlo.** En servidores modernos
x86-64 y aarch64 la aceleración de AES es universal, y el crate `aes-gcm` la usa
cuando está. Contra ese despliegue concreto, la ventaja de canal lateral de
ChaCha20 es teórica. El argumento se sostiene para el resto de escenarios, no
para todos.

---

## Qué hay construido, y por qué el resto no

**Construido y en el workspace desde el 2026-07-21: `crates/quipu-cnsa`**, la
mitad simétrica del perfil. AES-256-GCM, HKDF-SHA-384, huella de diccionario
sobre SHA-384 y cabecera de 56 bytes; el formato, el codec, Padmé y el ECC los
comparte con `quipu` a través de `quipu-nucleo`, así que un fallo de formato se
arregla una vez. Argon2id se mantiene a propósito (ver abajo).

**NO está publicado.** Comprobado en el índice el 2026-07-31:
`index.crates.io/qu/ip/quipu-cnsa` no devuelve nada. Publicar necesita visto
bueno explícito, y antes hay que decidir si el perfil se queda como está.

Lo que sigue explica por qué el resto —lo asimétrico puro y la firma de
software— no se ha construido, y sigue siendo válido.

No es que sea difícil. Es que **alinear algoritmos no es cumplir**, y confundir
las dos cosas sería vender algo que no está.

Para un NSS estadounidense, CNSA 2.0 se acompaña de validación FIPS 140-3 del
módulo (CMVP). Eso es un laboratorio acreditado, meses y decenas de miles de
dólares. Sin esa validación, un perfil AES-256 permite decir *«implementa los
algoritmos de CNSA 2.0»* y **no** *«es CNSA 2.0»*. Un comprador serio de ese
mercado nota la diferencia en la primera reunión.

Para el mercado realista de Quipu —sector público y empresa en Colombia y la
región, que usan NIST y NSA como listón de calidad— lo que se comprueba es la
alineación de algoritmos, y ahí el hueco es real. Pero **nadie lo ha pedido
todavía**, y construirlo antes de que alguien pregunte añade:

- una dependencia (`aes-gcm`) y su presupuesto en `cargo-vet`;
- una segunda ruta criptográfica completa en una biblioteca que se vende por
  auditable — la superficie que hay que revisar se duplica;
- una matriz de pruebas duplicada por cada feature;
- SHA-384 en sitios que están **en el formato**: la huella de diccionario de la
  cabecera son los primeros 8 bytes de un SHA-256, así que cambiar el resumen
  cambia el contenedor.

---

## La cuarta vía: una librería hermana

Lo anterior asume que el perfil viviría dentro de `quipu`. Hay una alternativa
mejor y está anotada como trabajo aparte: **`quipu-cnsa`, una librería hermana**,
en la relación que Devuan guarda con Debian.

No es una variante ni un flag: es un proyecto con su propio compromiso declarado
—las primitivas de CNSA 2.0 y la vía FIPS— frente al de `quipu`, que se queda
con XChaCha20 y su argumento de canal lateral. Dos compromisos, no dos
configuraciones.

Eso desactiva la objeción de siempre contra los forks. Un fork sin compromiso
declarado se pudre porque nadie sabe cuándo debe converger; uno con compromiso
declarado sabe exactamente en qué diverge y en qué no.

**Condición innegociable:** no se copia el repositorio. Se extrae el núcleo
—formato, contenedor, Padmé, base-N, ECC— como crate agnóstico de primitivas, y
los dos perfiles quedan encima. Un fallo se arregla una vez. Copiar y dejar
divergir es cómo mueren los forks, y en criptografía muere con una
vulnerabilidad corregida en una rama y no en la otra.

Precedente en casa: `quipu-voprf` ya está separado por una razón estructural.

Y la extracción del núcleo **mejora `quipu` aunque la hermana nunca se
construya**, que es la prueba de que la dirección es correcta.

---

## Cómo se construiría, si se pide

Especificado ahora para que la decisión futura sea de ejecución y no de diseño.

**Perfil aparte, con su propio magic, sin negociación.** No se toca el núcleo:
`tests/vectors.rs::symmetric_container_is_byte_exact` fija el formato en cable y
tiene que seguir pasando. El perfil CNSA es un contenedor distinto, elegido por
el llamante al cifrar.

**Nada de agilidad negociable.** El contenedor no lleva un campo «algoritmo» que
el descifrador obedezca: eso es el anti-patrón de `alg:none` y de las
degradaciones de TLS. El magic identifica el perfil y cada perfil tiene sus
primitivas fijas. Un contenedor CNSA se descifra con AES-256-GCM o no se
descifra.

**Alcance mínimo coherente**, porque un perfil a medias es peor que ninguno.
Estado al 2026-07-31, leído del crate y no de esta lista:

1. AES-256-GCM en lugar de XChaCha20-Poly1305. — **HECHO** (`aes-gcm 0.11`).
2. HKDF-SHA-384 en lugar de HKDF-SHA-256. — **HECHO** (`sha2 0.11`, `hkdf 0.13`).
3. Huella de diccionario sobre SHA-384. — **HECHO**.
4. Nonce de 96 bits **con contador**, no aleatorio. — **RESUELTO POR ARGUMENTO,
   y el argumento está en la cabecera de `cipher.rs`**: la sal es fresca en cada
   cifrado, así que la clave cambia con cada operación y un contador persistente
   no añadiría nada. Quien use `encrypt` saltándose la KDF sí debe garantizar
   nonces únicos, y por eso la API le exige pasar el nonce. No hay estado que
   llevar, que era el coste que este punto temía.
5. Para firma de software: LMS o XMSS. SLH-DSA **no** sirve aquí; es FIPS-205 y
   CNSA 2.0 pide SP 800-208 para ese uso concreto. — **PENDIENTE**, y es una
   dependencia nueva con gestión de estado de clave (LMS y XMSS son *stateful*:
   reusar un índice rompe la firma). El `slh` que hay no lo sustituye.
6. **AÑADIDO EL 2026-07-31, y no estaba en esta lista:** ML-KEM-1024 y ML-DSA-87
   **puros**. `quipu` los tiene en HÍBRIDO (X25519 y Ed25519 al lado), así que
   una hermana que quiera afirmar «los algoritmos de CNSA 2.0» sin asterisco
   necesita las variantes puras, con su formato y sus pruebas. Es la parte cara
   de crecer el perfil, y la lista anterior la daba por cableada.

**Lo que NO se hace:** cambiar Argon2id. CNSA 2.0 no se pronuncia sobre
derivación desde contraseña, y sustituirlo por PBKDF2 para «parecer conforme»
sería debilitar el sistema por estética normativa.

---

## Cuándo revisar esta decisión

Se construye el perfil cuando ocurra **cualquiera** de estas tres:

1. Un comprador identificable lo pide por escrito en un pliego o una evaluación.
2. Aparece un pliego público colombiano que referencie CNSA 2.0 como requisito.
3. Un contrato firmado exige validación FIPS 140-3 **y la paga o la cofinancia**
   — entonces el perfil deja de ser un coste aislado y pasa a ser parte de un
   trabajo que ya se hace.

   Antes decía «se decide ir a FIPS por otra razón», y esa puerta estaba
   demasiado abierta. **Ir a FIPS por iniciativa propia está DESCARTADO**, con
   tres razones y ninguna es el precio del laboratorio: la cola del CMVP promedió
   542 días a principios de 2024 (histórico de 12 a 18 meses), así que un envío
   de hoy certifica después de enero de 2027, que es cuando CNSA 2.0 empieza a
   morder; un certificado lo es de UNA versión, y esta librería corrige cosas
   cada semana; y quien exige FIPS es el gobierno federal estadounidense, que no
   es nuestro comprador. Para un pliego que lo exija, la vía real es un
   dispositivo PKCS#11 ya validado debajo —que `quipu` ya soporta con la feature
   `hsm`—, no validar la librería.

Mientras tanto, la respuesta a *«¿es compatible con CNSA 2.0?»* es este
documento: los algoritmos asimétricos son los suyos —en híbrido—, la mitad
simétrica está construida en `quipu-cnsa`, la firma de software falta, y ninguna
de las dos cosas es validación FIPS 140-3.

**Y la recomendación, para que la decisión no se quede abierta por no estar
escrita: el perfil se queda simétrico.** Crecerlo hoy cuesta dos rutas
criptográficas puras nuevas más una dependencia *stateful* (LMS/XMSS), y ninguno
de los tres disparadores de arriba se ha dado. En una ronda la frase defendible
no es «cubre un renglón» sino la de la tabla: cuatro de las cinco funciones, con
la salvedad del híbrido dicha por nosotros y no descubierta por ellos. Eso se
sostiene mejor que un perfil puro a medio construir.

Y sobre la validación, que es donde estaba la frase equivocada: **lo que se busca
financiar es la auditoría independiente, no el certificado FIPS.** Financian
auditorías los sitios donde hay solicitudes en curso —OTF, NLnet/NGI Zero—, no
validaciones CMVP; la auditoría cuesta un orden de magnitud menos, no congela la
versión y es lo que un comité de seguridad de aquí sabe leer. FIPS solo si un
contrato lo exige y lo paga.

Saber por qué no lo hiciste vale más que haberlo hecho sin saber para quién.
