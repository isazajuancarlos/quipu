<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza
-->

# Quipu y CNSA 2.0

**Posición: `quipu-cnsa` implementa un algoritmo aprobado para CADA UNA de las
cinco funciones de CNSA 2.0. Lo que falta no es un algoritmo: es LMS/XMSS, que
la NSA prefiere —no exige— para una raíz de confianza en firmware, y que
NINGUNA librería de software puro puede implementar de forma conforme —SP
800-208 §8.1 lo confina a módulos hardware validados, verificado en fuente
primaria el 2026-08-13—. Nada de esto es cumplimiento: alineación de algoritmos
no es validación FIPS 140-3.**

> **ESTA CIFRA SUBIÓ DE CUATRO A CINCO EL 2026-08-02, y conviene saber por qué
> antes de repetirla.** No se construyó nada nuevo ese día: lo que se corrigió
> es que este documento contradecía al README del propio crate. Aquí ponía «para
> firma de software: LMS o XMSS», y el README ya se había corregido a sí mismo
> con el matiz exacto — **LMS y XMSS están aprobados EXCLUSIVAMENTE para firma de
> software y firmware, que no es lo mismo que ser los únicos aprobados PARA
> ella**. ML-DSA-87 está aprobado para cualquier uso de firma, incluido ese, y
> `quipu-cnsa` lo tiene desde el 2026-07-31.
>
> **VERIFICADO EN FUENTE PRIMARIA el 2026-08-13.** Este aviso decía que el
> matiz solo se apoyaba en fuentes secundarias porque el FAQ de la NSA respondía
> **403**. Sigue respondiendo 403 —a `curl` con UA de navegador, a WebFetch, y
> **también desde una IP canadiense**: es un muro de Akamai contra clientes
> automatizados (`errors.edgesuite.net`), no un bloqueo geográfico—. Se leyó
> **abriéndolo en un navegador de verdad**, que sí pasa.
>
> Documento: *«The Commercial National Security Algorithm Suite 2.0 and Quantum
> Computing FAQ»*, NSA Cybersecurity Information Sheet, **21 páginas**, en
> `media.defense.gov/2022/Sep/07/2003071836/-1/-1/1/CSI_CNSA_2.0_FAQ_.PDF`.
> Citas literales, con su página:
>
> - **p. 3, tabla «Commercial National Security Algorithm Suite 2.0»** —
>   ML-DSA: *«Asymmetric algorithm for digital signatures in any use case,
>   **including signing firmware and software**»*, ML-DSA-87 para todos los
>   niveles de clasificación. LMS y XMSS aparecen bajo el epígrafe **«Algorithms
>   Allowed in Specific Applications»**. **El matiz queda confirmado: ML-DSA-87
>   sirve para firma de software, y LMS/XMSS no son los únicos aprobados para
>   ella.**
> - **p. 6** — *«NSA has only approved LMS and XMSS for use in NSS. The
>   multi-tree algorithms HSS and XMSSMT are not allowed.»* Confirma el árbol
>   único.
> - **p. 5** — *«QR algorithms should be implemented in NSS mission systems as
>   NIAP validated products… Typically, this will include, but not be limited
>   to, requiring modules be validated by the NIST Cryptographic Module
>   Validation Program (CMVP).»* Confirma que **alineación no es cumplimiento**.
>
> **Y un hallazgo que no estaba escrito y toca a `quipu` directamente (p. 6):**
> *«Q: Can I use SLH-DSA (aka SPHINCS+) to sign software? A: While SLH-DSA is
> hash-based, it is **not part of CNSA and is not approved for any use in
> NSS**.»* La feature `slh` de `quipu` es SLH-DSA-SHA2-256s: es una buena firma
> y **no cuenta para CNSA 2.0 en absoluto**. En la tabla de abajo aparece en la
> columna de `quipu`, que es correcto como descripción, pero **no debe leerse
> como cobertura**.

Este documento existe para que la divergencia sea una posición defendible y no
un hueco que alguien descubra en una evaluación.

**Reverificado contra el repositorio el 2 de agosto de 2026, y la posición
CAMBIÓ.** Hasta el 2026-07-31 este archivo decía que el perfil se quedaba
simétrico y su tabla marcaba firma y establecimiento de clave como no
construidos en la hermana. **Se construyeron esa misma noche** (commit `ff16187`, 23:41):
`quipu-cnsa` tiene hoy ML-DSA-87 y ML-KEM-1024 **puros**, comprobado en
`crates/quipu-cnsa/src/firma.rs` y `destinatario.rs` —longitudes 2592/4627 y
1568/1568, las de nivel 5— con `ml-dsa` y `ml-kem` como dependencias DIRECTAS y
no a través de `quipu`.

Este archivo llevaba un día contradiciendo al código, y es la segunda vez que le
pasa lo mismo: la versión anterior decía «el perfil no está construido» cuando
la mitad simétrica ya existía. Un documento que le dice a un comprador lo que
hay se mira **en la misma pasada** del cambio, no cuando alguien pregunta.

---

## Qué exige CNSA 2.0 y qué hace Quipu

| Función | CNSA 2.0 exige | `quipu` | `quipu-cnsa` | ¿Cubierta? |
|---|---|---|---|:--:|
| Establecimiento de clave | ML-KEM-1024 | X25519 **+** ML-KEM-1024 (híbrido) | **ML-KEM-1024 puro** | **sí** |
| Firma | ML-DSA-87 | Ed25519 **+** ML-DSA-87 (híbrido) | **ML-DSA-87 puro** | **sí** |
| Cifrado simétrico | AES-256 | XChaCha20-Poly1305 | **AES-256-GCM** | **sí**, en la hermana |
| Resumen | SHA-384 (preferido) o SHA-512 | SHA-256 | **SHA-384** | **sí**, en la hermana |
| Firma de software/firmware | ML-DSA-87, o LMS/XMSS de árbol único (SP 800-208) | SLH-DSA-SHA2-256s (feature `slh`) | **ML-DSA-87 puro** | **sí, en algoritmo** |

**LA SALVEDAD, y conviene decirla antes de que la pregunten:** lo asimétrico de
`quipu` es HÍBRIDO. `pqhybrid` combina X25519 con ML-KEM-1024 y `pqsign` combina
Ed25519 con ML-DSA-87 — comprobado en `src/pqhybrid.rs` y `src/pqsign.rs`, no
citado de memoria. Los algoritmos que CNSA 2.0 nombra están ahí y con los
parámetros de TOP SECRET, pero lo que se ejecuta lleva además la mitad clásica.

**Para quien exija exactamente lo que dice la lista, sin asterisco, está la
hermana:** `quipu-cnsa` implementa los dos PUROS desde el 2026-07-31. La
salvedad, por tanto, ya no es un hueco del catálogo — es la diferencia entre los
dos perfiles, y hay que saber leerla en la dirección correcta.

**Y la dirección correcta es incómoda: el perfil puro es MÁS DÉBIL.** El híbrido
exige romper DOS familias —curva y retículo— para caer; el puro no tiene socio
clásico, así que si el retículo cae no queda nada. La asimetría que más pesa:
una firma rota se explota el día que se rompe, pero **un secreto cifrado hoy se
guarda y se descifra mañana**, así que contra «cosecha ahora, descifra después»
el híbrido protege y el puro no.

Dicho de una vez, que es como conviene decirlo en una evaluación: `quipu-cnsa`
existe para quien tiene la OBLIGACIÓN normativa, no para quien puede elegir. Si
se puede elegir, `quipu`.

La coincidencia en la parte post-cuántica no es casual: ML-KEM-1024 y ML-DSA-87
son los parámetros para TOP SECRET y se eligieron por eso. La divergencia
simétrica tampoco es descuido.

## Las fechas, leídas del FAQ de la NSA (p. 11-12), no de un resumen

| Fecha | Qué ocurre | Cita |
|---|---|---|
| **31 dic 2025** | no se exige transición antes | *«no requirement to transition will be enforced prior to December 31, 2025»* |
| **6 meses tras publicarse el CNSSP 15 actualizado** | un NSS que no cumpla **CNSA 1.0** debe pasar a CNSA 2.0 (o 90 días para pedir prórroga) | *«any NSS not CNSA 1.0 compliant has six months from the publication date of the updated CNSSP 15… or 90 days to request a waiver»* |
| **1 ene 2027** | **toda adquisición nueva de NSS debe cumplir CNSA 2.0**, y NSA espera que los despliegues nuevos cumplan | *«CNSSP 15 states that by January 1, 2027, all new acquisitions for NSS will be required to be CNSA 2.0 compliant»* (p. 11) y *«Starting January 1, 2027, NSA expects new deployments to be compliant»* (p. 12) |
| **31 dic 2030** | se retira el equipo que no pueda soportar CNSA 2.0 | *«all equipment and services that cannot support CNSA 2.0 must be phased out»* |
| **31 dic 2031** | CNSA 2.0 pasa a ser **obligatorio** de uso | *«CNSA 2.0 algorithms are mandated for use unless otherwise noted»* |
| **2035** | todo NSS resistente a cuántica (meta de NSM-10) | *«NSA intends that all NSS will be quantum-resistant by 2035»* |

**Fecha que importa, y es la de arriba: 1 de enero de 2027.** Es la única que
convierte a CNSA 2.0 en requisito de compra.

**No hay ninguna fecha de octubre de 2026 en el documento.** El único plazo que
NO es una fecha fija es el de los seis meses tras publicarse el CNSSP 15
actualizado — ése sí podría caer en octubre de 2026 según cuándo se publicara, y
es el único sitio del que puede salir esa cifra. **Aplica a quien no cumple
CNSA 1.0**, que no es el caso de un producto nuevo.

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

**Construido y en el workspace: `crates/quipu-cnsa`**, hoy el perfil ENTERO y no
solo su mitad simétrica.

- Desde el **2026-07-21**, lo simétrico: AES-256-GCM, HKDF-SHA-384, huella de
  diccionario sobre SHA-384 y cabecera de 56 bytes.
- Desde el **2026-07-31**, lo asimétrico PURO: `firma` (ML-DSA-87) y
  `destinatario` (ML-KEM-1024 sobre AES-256-GCM).
- Desde el **2026-08-13**, la CUSTODIA: `firmante` con dos backends —la clave
  en memoria, o dentro de un dispositivo PKCS#11 del que no sale (feature
  `hsm`)—. Es la primera pregunta de todo comité de seguridad, y aquí contesta
  además a las dos normativas que ninguna librería puede contestar sola: la
  validación FIPS 140-3 y el §8.1 de SP 800-208.

El formato, el codec, Padmé y el ECC los comparte con `quipu` a través de
`quipu-nucleo`, así que un fallo de formato se arregla una vez. Argon2id se
mantiene a propósito (ver abajo).

**74 pruebas en verde**, y las tres cifras miden cosas distintas a propósito:
67 sin features (`cargo test -p quipu-cnsa`, exit 0 el 2026-08-13) y **7 más
contra un dispositivo PKCS#11 REAL** —kryoptic con `pqc`, en un contenedor
`fedora:43`—, que incluyen el soak de 128 firmas concurrentes de la directiva 8.
Esas 7 se SALTAN con aviso si no hay token: en la máquina de casa salen en
`0,00 s`, que es el positivo de control de que no midieron nada.

**SE PUBLICÓ, y este párrafo decía lo contrario — es la TERCERA vez que este
documento contradice a la realidad, y las dos anteriores están dos secciones más
arriba.** Aquí ponía «NO está publicado, y sigue sin estarlo», con la fecha de
comprobación del 2026-08-02 como si fuera vigente. Lo que pasó después:

- **2026-08-05, 21:40 UTC — `cnsa-v0.1.1` publicó a crates.io por OIDC, a la
  primera.** Consta en el commit `9a15d30` de `release.yml`, cuyo asunto es
  literalmente *«los comentarios decían que cnsa y padme-frame dan 404, y los
  cinco están publicados»*. La maquinaria que este párrafo daba por recién
  estrenada se usó tres días después de escribirlo.
- **2026-08-10 — quedó *yanked***, con las otras 23 versiones de la familia, al
  declararse el protocolo «solo local». *Yank* corta instalaciones nuevas; **no
  retira el `.crate` ya publicado**, que sigue descargable con el código fuente
  completo, y crates.io no permite borrarlo nunca.

Así que la respuesta correcta hoy, delante de un comprador, es: **`quipu-cnsa`
0.1.1 EXISTIÓ en crates.io, hoy está *yanked*, y su fuente es públicamente
recuperable de forma permanente.** Volver a publicar sigue necesitando visto
bueno explícito **y va contra el protocolo vigente**, que no caduca solo.

**Y la lección, ya que van tres:** un documento que dice a un comprador lo que
hay envejece por el lado que nadie mira — no por el algoritmo, que se toca poco,
sino por el ESTADO (publicado, probado, desplegado), que cambia solo y sin avisar
a nadie. Un estado con fecha de comprobación no es un estado verificado: es un
estado que caducó (directiva 31).

Lo que sigue explica por qué **LMS/XMSS** —lo único que falta— no se ha
construido, y sigue siendo válido. Con una corrección del 2026-08-13 que lo
refuerza: además de no convenir, **no se puede** desde una librería de software
(SP 800-208 §8.1, citado abajo).

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
5. Para firma de software: **CUBIERTO POR ML-DSA-87**, que es lo que este punto
   decía mal. Estaba escrito como «CNSA 2.0 pide SP 800-208 para ese uso
   concreto», y es al revés de como suena: LMS y XMSS están aprobados
   *exclusivamente* PARA ese uso —no pueden usarse en otro— y ML-DSA-87 está
   aprobado para **todos** los usos de firma, ese incluido. El crate lo tiene.

   Lo que sigue faltando, y es distinto: **LMS/XMSS de árbol único**, que la NSA
   prefiere hoy para una raíz de confianza en firmware porque ya hay
   implementaciones validadas. Solo hace falta si el comprador firma firmware y
   lo pide por nombre; su coste no es criptográfico sino operativo — son
   esquemas *con estado*, cada clave da un número finito de firmas y reutilizar
   el índice es catastrófico, así que exige un contador persistente que
   sobreviva a caídas y no se duplique en un restore.

   SLH-DSA **sigue sin servir** para afirmar conformidad: es FIPS-205 y no está
   en CNSA 2.0. `quipu` lo ofrece como refuerzo propio, no como conformidad.

   **CONFIRMADO EN PRIMARIA EL 2026-08-13, y el resultado cambia el renglón de
   sitio.** Aquí ponía «sin confirmar, y hay que confirmarlo antes de venderlo:
   si SP 800-208 obligara a generar las firmas en hardware, una librería de
   software puro no podría implementarlo de forma conforme». Obliga. NIST SP
   800-208, §8.1 *Conformance*: *«Implementations of the key generation and
   signature algorithms in this document shall only be validated for use within
   hardware cryptographic modules. The cryptographic modules shall be validated
   to provide FIPS 140-2 or FIPS 140-3 Level 3 or higher physical security…»*, y
   en la introducción, *«…hardware cryptographic modules that do not allow
   secret keying material to be exported, even in encrypted form»*.

   O sea que LMS/XMSS **deja de ser una carencia de este crate**: no es que no
   se haya construido, es que construirlo no daría conformidad. En un pliego eso
   se dice al revés de como suena — la vía para ese renglón es un HSM validado
   debajo, no una librería mejor. **Y desde el 2026-08-13 la soporta también
   `quipu-cnsa`** (feature `hsm`, módulo `firmante`), que era el hueco: la
   recomendación existía y solo la cumplía el hermano híbrido.
6. **AÑADIDO Y HECHO EL MISMO DÍA, el 2026-07-31:** ML-KEM-1024 y ML-DSA-87
   **puros**. `quipu` los tiene en HÍBRIDO (X25519 y Ed25519 al lado), así que
   una hermana que quiera afirmar «los algoritmos de CNSA 2.0» sin asterisco
   necesita las variantes puras, con su formato y sus pruebas. Se dijo que era
   la parte cara de crecer el perfil, y lo era: son `firma.rs` y
   `destinatario.rs`, con dependencias directas a `ml-dsa` y `ml-kem` para no
   arrastrar `quipu` entero —este perfil es HERMANO de aquel, no cliente suyo—.

   Detalles que un evaluador sí pregunta: la clave pública COMPLETA se ata al
   material firmado y al derivado, con la longitud explícita delante, para que
   no se pueda mover el corte entre campos; la clave secreta del KEM se guarda
   como semilla de 64 bytes y no expandida de 3168, envuelta en `Zeroizing`; y
   el canal de destinatario tiene UN SOLO error, porque separar «encapsulación
   mal formada» de «tag inválido» sería el oráculo que I4 prohíbe.

**Lo que NO se hace:** cambiar Argon2id. CNSA 2.0 no se pronuncia sobre
derivación desde contraseña, y sustituirlo por PBKDF2 para «parecer conforme»
sería debilitar el sistema por estética normativa.

---

## Cuándo revisar esta decisión

> **NOTA DEL 2026-08-02, y se deja escrita en vez de limpiarla.** Los tres
> disparadores de abajo gobernaban «se construye el perfil», y **el perfil se
> construyó esa misma noche sin que ninguno de los tres conste como dado**. No es
> que se decidiera saltárselos: es que la decisión no quedó registrada en
> ninguna parte — el commit `ff16187` explica el CÓMO con mucho detalle y no
> dice una palabra del POR QUÉ AHORA.
>
> Aquí no se rellena ese hueco con una razón plausible, que sería justo el error
> que este documento existe para no cometer. Se deja señalado: **falta que Juan
> diga si se dio un disparador o si la recomendación se revocó a propósito.**
> Mientras tanto, lo que sigue vigente es el CÓDIGO, y la tabla de arriba ya lo
> refleja.
>
> Lo que estos tres disparadores gobernaban era lo ÚNICO que seguía sin
> construirse: la firma de software con LMS/XMSS (SP 800-208), *stateful* —
> reusar un índice rompe la firma—. **Desde el 2026-08-13 ya no gobiernan nada
> ahí**: el §8.1 de esa misma norma confina la generación de claves y de firmas
> a módulos hardware validados, así que ningún disparador comercial lo vuelve
> construible aquí. Lo que un comprador de ese renglón dispara es integrar un
> HSM, no escribir el algoritmo.

Se construye lo que falte cuando ocurra **cualquiera** de estas tres:

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
   dispositivo PKCS#11 ya validado debajo —que soportan los DOS crates desde el
   2026-08-13, cada uno con su perfil de firma—, no validar la librería.

Mientras tanto, la respuesta a *«¿es compatible con CNSA 2.0?»* es este
documento: `quipu-cnsa` implementa un algoritmo aprobado para cada una de las
cinco funciones —ML-KEM-1024 y ML-DSA-87 **puros**, AES-256-GCM y SHA-384, y
ML-DSA-87 también para la firma de software—, falta LMS/XMSS como opción
preferida para raíz de confianza en firmware, y nada de eso es validación
FIPS 140-3.

**La recomendación anterior —«el perfil se queda simétrico»— está RETIRADA por
los hechos**, no por un argumento mejor: el perfil creció esa misma noche. Se
retira la frase y se deja el rastro, porque una recomendación que el código
desmiente y sigue escrita es peor que ninguna — la lee alguien, la repite en una
reunión, y la desmiente el `grep` del comprador.

La frase defendible en una ronda ha MEJORADO dos veces, y conviene decirla
entera: **las cinco funciones con un algoritmo aprobado cada una, y en la
hermana sin asterisco** — los algoritmos puros que nombra la lista, no híbridos
que «los contienen». Con las tres salvedades dichas por nosotros y no
descubiertas por ellos:

1. El perfil puro es **más débil** que el híbrido frente a «cosecha ahora,
   descifra después».
2. Falta **LMS/XMSS de árbol único**, que es lo que hoy prefiere la NSA para una
   raíz de confianza en firmware — y no lo va a traer esta librería, ni ninguna:
   SP 800-208 §8.1 lo confina a módulos hardware validados. Quien lo necesite lo
   pone debajo, en un HSM.
3. ~~Lo del punto 5 solo está en fuentes secundarias.~~ **CERRADA el
   2026-08-13**: el FAQ de la NSA se leyó abriéndolo en un navegador de verdad
   —a `curl` y a los clientes automatizados les sigue dando 403— y confirma el
   matiz, con la cita y la página arriba. Esta salvedad ya no se dice.

Decir las tres cuesta menos que una sola pregunta incómoda a la que no se tenga
respuesta. Y ninguna de ellas es la que decide la partida, que sigue siendo la
validación y no el quinto renglón.

Y sobre la validación, que es donde estaba la frase equivocada: **lo que se busca
financiar es la auditoría independiente, no el certificado FIPS.** Financian
auditorías los sitios donde hay solicitudes en curso —OTF, NLnet/NGI Zero—, no
validaciones CMVP; la auditoría cuesta un orden de magnitud menos, no congela la
versión y es lo que un comité de seguridad de aquí sabe leer. FIPS solo si un
contrato lo exige y lo paga.

Saber por qué no lo hiciste vale más que haberlo hecho sin saber para quién.
