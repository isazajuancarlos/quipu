<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas
-->

# Quipu y CNSA 2.0

**Posición: `quipu-cnsa` implementa un algoritmo aprobado para CADA UNA de las
cinco funciones de CNSA 2.0. Lo que falta no es un algoritmo: es LMS/XMSS, que
la NSA prefiere —no exige— para una raíz de confianza en firmware. Nada de esto
es cumplimiento: alineación de algoritmos no es validación FIPS 140-3.**

> **ESTA CIFRA SUBIÓ DE CUATRO A CINCO EL 2026-08-02, y conviene saber por qué
> antes de repetirla.** No se construyó nada nuevo ese día: lo que se corrigió
> es que este documento contradecía al README del propio crate. Aquí ponía «para
> firma de software: LMS o XMSS», y el README ya se había corregido a sí mismo
> con el matiz exacto — **LMS y XMSS están aprobados EXCLUSIVAMENTE para firma de
> software y firmware, que no es lo mismo que ser los únicos aprobados PARA
> ella**. ML-DSA-87 está aprobado para cualquier uso de firma, incluido ese, y
> `quipu-cnsa` lo tiene desde el 2026-07-31.
>
> **Estado de la evidencia, dicho como toca:** el matiz está confirmado en
> fuentes secundarias coincidentes, y **NO en fuente primaria** — el FAQ de la
> NSA (`media.defense.gov/.../CSI_CNSA_2.0_FAQ_.PDF`) responde **403** tanto por
> navegador como por `curl`. No se puede llamar verificado. Antes de llevar esta
> cifra a una ronda o a un pliego, conseguir el PDF por otra vía y leerlo.
>
> Dos detalles que salieron de la misma consulta y no estaban escritos: solo se
> admite **LMS y XMSS de ÁRBOL ÚNICO** —HSS y XMSS^MT quedan fuera para NSS—, y
> la propia NSA advierte que espera que las implementaciones validadas de ML-DSA
> tarden, así que para una fecha de hardware puede no llegar a tiempo.

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

**Construido y en el workspace: `crates/quipu-cnsa`**, hoy el perfil ENTERO y no
solo su mitad simétrica.

- Desde el **2026-07-21**, lo simétrico: AES-256-GCM, HKDF-SHA-384, huella de
  diccionario sobre SHA-384 y cabecera de 56 bytes.
- Desde el **2026-07-31**, lo asimétrico PURO: `firma` (ML-DSA-87) y
  `destinatario` (ML-KEM-1024 sobre AES-256-GCM).

El formato, el codec, Padmé y el ECC los comparte con `quipu` a través de
`quipu-nucleo`, así que un fallo de formato se arregla una vez. Argon2id se
mantiene a propósito (ver abajo). **62 pruebas en verde** (`cargo test
-p quipu-cnsa`, exit 0 el 2026-08-02).

**NO está publicado**, y sigue sin estarlo: comprobado contra la API de
crates.io el 2026-08-02. Lo que SÍ cambió ese día es que ya existe la
maquinaria para publicarlo —tag `cnsa-v*` y job `crate-cnsa` en `release.yml`,
que antes no existían: un crate terminado sin ninguna forma de salir—. Publicar
necesita visto bueno explícito.

Lo que sigue explica por qué **LMS/XMSS** —lo único que falta— no se ha
construido, y sigue siendo válido.

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

   *(Sin confirmar en fuente primaria, y hay que confirmarlo antes de venderlo:
   si SP 800-208 obligara a generar las firmas en hardware, una librería de
   software puro no podría implementarlo de forma conforme.)*
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
> Lo que estos tres disparadores gobiernan a partir de ahora es lo ÚNICO que
> sigue sin construirse: la firma de software (SP 800-208, LMS o XMSS), que es
> la que trae una dependencia nueva y *stateful* — reusar un índice rompe la
> firma— y por tanto la que de verdad conviene no construir sin comprador.

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
   dispositivo PKCS#11 ya validado debajo —que `quipu` ya soporta con la feature
   `hsm`—, no validar la librería.

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
   raíz de confianza en firmware.
3. Lo del punto 5 está confirmado en fuentes secundarias y **no en primaria**:
   el FAQ de la NSA da 403. Hasta leerlo, la cifra se dice con esa nota.

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
