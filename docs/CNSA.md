<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas
-->

# Quipu y CNSA 2.0

**Posición: Quipu implementa la mitad asimétrica de CNSA 2.0 y se aparta a
propósito en la simétrica. El perfil CNSA 2.0 completo está especificado aquí y
no está construido. Se construye cuando un comprador lo pida, no antes.**

Este documento existe para que la divergencia sea una posición defendible y no
un hueco que alguien descubra en una evaluación.

Verificado contra el repositorio el 20 de julio de 2026, versión `0.8.0`.

---

## Qué exige CNSA 2.0 y qué hace Quipu

| Función | CNSA 2.0 exige | Quipu usa | ¿Coincide? |
|---|---|---|:--:|
| Establecimiento de clave | ML-KEM-1024 | ML-KEM-1024 | **sí** |
| Firma | ML-DSA-87 | ML-DSA-87 | **sí** |
| Cifrado simétrico | AES-256 | XChaCha20-Poly1305 | **no** |
| Resumen | SHA-384 (preferido) o SHA-512 | SHA-256 | **no** |
| Firma de software/firmware | LMS o XMSS (SP 800-208) | SLH-DSA-SHA2-256s (feature `slh`) | **no** |

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

## Por qué el perfil no está construido

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

**Alcance mínimo coherente**, porque un perfil a medias es peor que ninguno:

1. AES-256-GCM en lugar de XChaCha20-Poly1305.
2. HKDF-SHA-384 en lugar de HKDF-SHA-256.
3. Huella de diccionario sobre SHA-384.
4. Nonce de 96 bits **con contador**, no aleatorio — es la consecuencia
   obligada de perder el nonce extendido, y hay que llevar el estado.
5. Para firma de software: LMS o XMSS. SLH-DSA **no** sirve aquí; es FIPS-205 y
   CNSA 2.0 pide SP 800-208 para ese uso concreto.

**Lo que NO se hace:** cambiar Argon2id. CNSA 2.0 no se pronuncia sobre
derivación desde contraseña, y sustituirlo por PBKDF2 para «parecer conforme»
sería debilitar el sistema por estética normativa.

---

## Cuándo revisar esta decisión

Se construye el perfil cuando ocurra **cualquiera** de estas tres:

1. Un comprador identificable lo pide por escrito en un pliego o una evaluación.
2. Aparece un pliego público colombiano que referencie CNSA 2.0 como requisito.
3. Se decide ir a validación FIPS 140-3 por otra razón — entonces el perfil deja
   de ser un coste aislado y pasa a ser parte de un trabajo que ya se hace.

Mientras tanto, la respuesta a *«¿es compatible con CNSA 2.0?»* es este
documento: coincide en lo asimétrico, se aparta en lo simétrico con motivo
técnico, y el perfil está especificado.

Saber por qué no lo hiciste vale más que haberlo hecho sin saber para quién.
