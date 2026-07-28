<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas
-->

# Taxonomía de ataques a cifrado, y las herramientas que los contienen

Investigación para una versión futura. El objetivo no es catalogar por catalogar:
es **encontrar los factores comunes** de todos los métodos de ataque a cifrado,
para que la defensa no sean *N* herramientas sueltas sino unas pocas que vigilen
las propiedades que casi todos los ataques violan.

Quipu ya tiene infraestructura defensiva —`src/lab/` (distinguidor, forja,
guessing, timing, honey_attack, stream_attack), `docs/THREAT_MODEL.md`, dudect,
hackerbot, autopruebas de arranque—. Este documento la ordena y dice qué falta.

> ### ALCANCE — leer antes que la tesis
>
> Este documento cubre **ataques al cifrado**. Su conclusión —«casi todo reduce a
> violar uno de cinco invariantes»— es cierta dentro de ese alcance y **falsa
> fuera de él**, y como la frase se lee universal conviene decirlo aquí.
>
> Comprobado el 2026-07-26 contra incidentes reales (`THREAT_MODEL.md` §10,
> *Empirical evidence*): **ninguno atacó la criptografía**. Fueron denegación de
> servicio, ransomware por un proveedor y acceso comprometido. Los cinco
> invariantes no habrían cambiado ningún desenlace.
>
> Lo que queda fuera de I1–I5 y sí ocurre: el factor humano, la superficie
> desplegada, la cadena de proveedores y la disponibilidad del canal de
> actualizaciones. Ver **I6** e **I7**, abajo.

---

## La tesis: cinco invariantes, no cien ataques

Después de recorrer las familias (abajo), casi todo reduce a **violar uno de
cinco invariantes**. Esa es la clave para herramientas universales: se vigilan
cinco propiedades, no cien ataques.

| # | Invariante | Qué lo viola | Herramienta universal |
|---|---|---|---|
| **I1** | Ningún observable depende del secreto | timing, caché, potencia, oráculos | banco de indistinguibilidad (dudect + distinguidor) |
| **I2** | Autenticar antes de actuar | maleabilidad, truncación, splicing, padding oracle | fuzz dirigido + meta-test de "nada se procesa sin verificar" |
| **I3** | Entropía fresca y nonce único | RNG débil, reutilización de nonce, semilla predecible | monitor de salud del RNG + detector de reúso de nonce |
| **I4** | El fallo no revela nada | oráculos de error, mensajes distintos por causa | verificador de uniformidad de errores |
| **I5** | Procedencia verificada | dependencia comprometida, primitiva con puerta trasera | cargo-vet/audit + vectores publicados + build reproducible |
| **I6** | **El humano es parte del sistema** | pretexto, phishing, coacción, hombro | asimetría cerrar/abrir en `/admin/*`: cerrar sin verificar a nadie, reabrir lo revocado no está disponible |
| **I7** | **La superficie desplegada responde por sí misma** | XSS/SQLi/hardening del servidor OPRF, proveedor caído, canal de actualización tumbado | postura del despliegue comprobable + plan de continuidad + modo degradado |

**Estado de I6 e I7**, que la tabla no decía y las diez familias sí dicen de las
suyas — auditado el 2026-07-27 contra el repositorio:

| | Estado | Dónde |
|---|---|---|
| **I6** | **CUBIERTO.** Revocar es definitivo: `revoked_at` entra en la consulta de verificación y `activate` no toca una key revocada, así que la asimetría no depende de que nadie juzgue una petición | `crates/quipu-oprf-server/src/store.rs`, con la prueba `una_key_revocada_no_se_reactiva_por_mucho_que_lo_pidan` |
| **I7** | **CUBIERTO, con residuo declarado.** Postura del despliegue comprobable (HSTS, `/admin/keys` no 2xx); SQL parametrizado y fijado por una meta-prueba; continuidad y modo degradado escritos. Lo que sigue sin resolver está enumerado, no escondido: sin respaldo verificado del *seed* fuera del VPS, sin réplica, sin objetivo de disponibilidad y sin alerta automática | `verificar.py desplegado`; `store.rs` (`el_almacen_no_concatena_sql`, `el_dato_hostil_no_se_ejecuta`); **`docs/CONTINUIDAD.md`** |

Un ataque nuevo casi siempre es una forma nueva de romper **uno** de estos. Si el
lab prueba los siete en continuo y con adversario adaptativo, cubre el espacio,
no la lista.

**I6 e I7 se añadieron el 2026-07-26** tras contrastar la taxonomía con *Hacking
Ético* (Tori) y con incidentes reales. El libro dedica capítulos enteros a
recabar información, ingeniería social, aplicaciones web y hardening: de sus
nueve capítulos, **solo uno** cruza con las cinco familias que teníamos —fuerza
bruta—. Y sus frecuencias lo resumen: 54 menciones de XSS, 41 de ingeniería
social, 27 de SQL injection, **6 de criptografía**.

Para Quipu no son teóricos. `oprf.xiliux.com` es un servicio desplegado y
cobrando (I7), y las operaciones de `/admin/*` las ejecuta una persona (I6):
«nos revocaron la key por error, reactívanos» es un correo que cualquiera puede
escribir, y quien atiende no distingue al cliente de quien lo suplanta. Un
señuelo perfecto no defiende de una llamada.

**La justificación de I6 cambió el 2026-07-27.** Nació apoyada en la custodia en
papel —alguien fotografía la hoja, alguien lee las palabras por teléfono—, y ese
canal se eliminó entero en el PR #93. Reencuadrado sobre la operación que existe
hoy, I6 se defiende con una ASIMETRÍA y no con acertar en el juicio: cerrar se
puede hacer ante cualquiera, porque equivocarse cerrando es una molestia
reversible; reabrir lo que se cerró a propósito no está disponible ni para quien
atiende. Un invariante defendido sobre un caso de uso que ya no se tiene no
defiende nada.

---

## Las familias

Para cada una: los métodos, si **Quipu está expuesto** y por qué, la
**herramienta** (existe / falta), y el **invariante** que ataca.

### 1. Criptoanálisis de la primitiva — romper la matemática

**Métodos.** Diferencial y lineal (cifradores de bloque/flujo); algebraico y de
interpolación; encuentro-en-el-medio y ataques de clave relacionada; para
retículos (ML-KEM, ML-DSA): reducción de base (BKZ), *primal/dual*, y los
cuánticos Shor (rompe RSA/ECC) y Grover (halva la seguridad simétrica);
para hash: colisión, preimagen, segunda preimagen, extensión de longitud.

**Exposición de Quipu.** **Baja, por política, no por suerte.** Quipu *no inventa
primitivas*: usa XChaCha20-Poly1305, Argon2id, HKDF-SHA256, Ed25519, ML-KEM-1024,
ML-DSA-87, todas vetadas y con parámetros en categoría NIST 5. El criptoanálisis
de la primitiva es responsabilidad de la comunidad que la mantiene; la de Quipu
es *no degradarla* (parámetros, no reinventar, KyberSlash verificado ausente en
la fuente vendida).

**Herramienta.** *Existe:* fijado de versiones, `cargo-audit` (RustSec), y desde
el 2026-07-27 el chequeo que faltaba: `tests/vectores_de_norma.rs` liga las
primitivas a vectores de una norma EXTERNA, no a los que genera el propio Quipu.

La distinción es el punto: `tests/vectors.rs` compara contra
`quipu_vectors.json`, que produce Quipu, así que prueba que la implementación no
cambió — no que sea correcta. Si Quipu llamara a Argon2i en vez de Argon2id, o
invirtiera `salt` e `info`, todo seguiría verde.

Cubierto hoy:

| Primitiva | Vectores | Qué prueba |
|---|---|---|
| XChaCha20-Poly1305 | Wycheproof | el envoltorio AEAD |
| VOPRF ristretto255 | RFC 9497 A.1.2 | conformidad del protocolo |
| **HKDF-SHA256** | **Wycheproof, 8 vectores en 5 tamaños** | **el cableado de Quipu**, vía `derive_stream`, más que `derive_subkey` coincida con él |
| **Ed25519** | **Wycheproof, 88 válidas + 62 inválidas** | **procedencia**: que la dependencia siga conformando |

*Falta:* Argon2id (RFC 9106) y las KAT de NIST para ML-KEM-1024 y ML-DSA-87.
Ninguna de las tres viene en `wycheproof`, y **no se escriben a mano**: un vector
transcrito con un byte cambiado haría «arreglar» el código para que encaje con
algo falso, que es el peor desenlace posible aquí.

**Invariante:** I5.

### 2. Canales laterales de implementación — no la matemática, la ejecución

**Métodos.** Timing por rama o acceso a memoria dependiente del secreto; caché
(Flush+Reload, Prime+Probe, evict+time); potencia y EM (SPA, DPA, CPA, y análisis
por *deep learning* que rompe AES en ~350 trazas donde una plantilla clásica
necesita ~52 000); microarquitectónicos (Spectre/Meltdown, port contention).

**Exposición de Quipu.** **Es el frente principal de una librería de software.**
XChaCha20-Poly1305 es ARX sin tablas → tiempo constante *incondicional*, sin
depender del hardware (a diferencia de AES sin AES-NI, que cae a S-boxes
indexadas por bytes secretos — canal de caché clásico, y **la caída es
silenciosa**). Comparación en tiempo constante, GF(2^8) de Shamir sin tablas.

**Herramienta.** *Existe:* dudect sobre seis rutas con secreto en
`src/lab/timing.rs` — `ct_eq`, decapsulación *válido vs corrupto*, decapsulación
con *dos claves distintas*, rechazo por causa, verificación de firma y derivación
de subclaves.
*Falta:* extender dudect a **cada** ruta con secreto de forma sistemática (hoy
son seis, elegidas).

> **La alarma de «build caído a tablas» NO hay que construirla, y merece
> explicarse** (auditado el 2026-07-27, corrigiendo lo que este mismo documento
> pedía). El aviso de arriba sobre AES sin AES-NI es cierto *en general* y
> **no aplica a este stack**, por dos razones independientes:
>
> 1. **El núcleo no lleva AES.** `cargo tree -p quipu` no devuelve ninguna
>    dependencia de `aes`: el AEAD es `chacha20poly1305`, ARX sin tablas.
> 2. **El único AES es el de `quipu-cnsa`** (`aes-gcm` → `aes`, por mandato
>    CNSA 2.0), y su backend portátil **no usa tablas**. El crate lo dice
>    textualmente: implementación *fixslicing*, «entirely in terms of bitwise
>    arithmetic with no use of any lookup tables or data-dependent branches», y
>    la detección en runtime cae a ella cuando no hay AES-NI.
>
> Es decir: en este stack, perder AES-NI cuesta **rendimiento, no tiempo
> constante**. Una alarma aquí no vigilaría ningún riesgo; sonaría por lentitud,
> y una alarma que suena por lo que no importa es una alarma que se acaba
> ignorando. Lo que sí queda es una **dependencia de una promesa ajena**: si
> `aes` cambiara de backend, la propiedad se perdería en silencio. Ese es un
> caso de I5 (procedencia) y lo cubre `cargo-vet`, no una sonda de I1.

**Invariante:** I1.

### 3. Ataques de fallo — inducir un error para extraer

**Métodos.** Glitching de voltaje/reloj, Rowhammer (bit-flip desde software),
láser/EM localizado; fallo diferencial de firma (un error en RSA-CRT o ECDSA
filtra la clave); *safe-error*.

**Exposición de Quipu.** **Media, y con una defensa estructural regalada.** La
firma **híbrida AND** (Ed25519 ∧ ML-DSA-87, y triple con SLH-DSA) hace que un
fallo inyectado en *una* mitad produzca una firma que **no verifica**, en vez de
una filtración: hace falta fallar las dos a la vez. Las autopruebas de arranque
detectan un binario que computa mal.

**Herramienta.** *Existe:* autopruebas (`selftest`) con inyección de fallo
(`selftest-fault`), firma híbrida, y desde el 2026-07-27 la sonda que faltaba:
`tests/invariantes.rs` inyecta fallos en **las dos mitades** por separado y en
seis posiciones, y comprueba además que media firma —una mitad válida y la otra
ausente— no autoriza nada.

Añade cobertura real sobre la autoprueba, que solo altera el byte 0 y por tanto
solo toca la mitad Ed25519: se verificó con una mutación que ignora `ml_ok`, la
autoprueba PASA y la sonda falla. Es el peor caso posible —dejar la seguridad
colgando de la curva, que es la que cae primero ante un ordenador cuántico— y
hasta ahora nadie lo habría visto.

**Invariante:** I2 (integridad del cómputo) + I4.

### 4. Ataques de oráculo — explotar diferencias observables en el fallo

**Métodos.** Padding oracle (CBC — Vaudenay); Bleichenbacher (RSA PKCS#1 v1.5);
oráculo de timing en la verificación de MAC; oráculo de compresión (CRIME/BREACH);
y el que Quipu ataca de frente en honey: el **oráculo de éxito** en secretos de
baja entropía.

**Exposición de Quipu.** **Baja por diseño.** AEAD (Poly1305) → no hay padding
que dé oráculo; errores **uniformes** (mismo mensaje ante cualquier fallo de
autenticación); comparación en tiempo constante; y honey elimina el oráculo de
éxito devolviendo un señuelo, no un error. **Sin compresión** en el contenedor →
no hay CRIME/BREACH.

**Herramienta.** *Existe:* el distinguidor entrenado (#91) es exactamente un
detector de oráculo — pregunta "¿puede un modelo notar la diferencia entre estas
dos salidas?"; honey_attack; y desde el 2026-07-27 el **verificador de uniformidad
de errores** (`tests/invariantes.rs`), que recorre seis caminos de fallo —
passphrase, pepper, sal, nonce, cuerpo, tag y truncación — y exige que el tipo y
el mensaje sean idénticos.

Distingue a propósito lo que SÍ puede diferenciarse: los errores de FORMATO
ocurren antes de que el secreto entre en juego, así que separarlos no filtra nada
y le sirve a quien integra. Lo que no puede discriminar es lo que pasa después.

El **tiempo** se cubrió el 2026-07-27 con `lab::timing::dudect_rechazo_por_causa`
(feature `lab-offline`): compara el rechazo por passphrase equivocada contra el
rechazo por tag alterado, que es el par que importa — los dos pagan Argon2id
entero y fallan en el AEAD, así que si el reloj los separa, el atacante sabe si
acertó la contraseña aunque el error no se lo diga.

Se mide con parámetros KDF **baratos** a propósito: con los de producción,
Argon2id domina y taparía cualquier diferencia del AEAD — saldría limpio por el
motivo equivocado. Es la condición más exigente, no la más cómoda.

Y hay una comparación que NO se hace, deliberadamente: un contenedor con
parámetros KDF absurdos se rechaza en microsegundos porque `is_sane()` corta
antes de derivar, contra los milisegundos de los otros dos. Mismo error, órdenes
de magnitud de diferencia — y **no es un oráculo**: lo que ese tiempo revela es
que la cabecera traía basura, un dato que el atacante puso él mismo. I4 exige que
el fallo no revele nada SOBRE EL SECRETO, no que todo rechazo tarde igual.
Medirlo como fuga llenaría el informe de falsos positivos.

*Falta todavía:* extender esta medición al resto de rutas con secreto, que es el
punto 4 del orden (dudect sistemático).

**Invariante:** I1 + I4.

### 5. Aleatoriedad y generación de clave — la raíz

**Métodos.** RNG débil o muerto (Debian OpenSSL 2008: 32 767 claves posibles;
routers con el mismo par de fábrica); reutilización de nonce (PS3 ECDSA con `k`
fijo → clave privada; nonce repetido en GCM → pérdida de autenticación); semillas
predecibles; ROCA (claves RSA con estructura de Infineon); sesgo en el muestreo.

**Exposición de Quipu.** **Era el punto ciego; 0.9.0 lo cerró.** `aleatorio.rs`
es el único punto donde se pide entropía: ante ausencia **falla ruidoso, nunca
sustituye** (ninguna clave nace de un RNG muerto), con reintento acotado solo
para la causa transitoria. Las autopruebas vigilan la salud del RNG en continuo
(dos tiradas seguidas deben diferir y no ser ceros). El nonce extendido de
XChaCha (192 bits) hace la colisión por azar despreciable.

**Herramienta.** *Existe:* `selftest::check_rng_health`, el manejo falible, y
desde el 2026-07-27 las dos que faltaban (`tests/taxonomia.rs`):

- **Detector de reúso de nonce** sobre un conjunto de contenedores, que devuelve
  QUÉ pares colisionan y no un booleano — quien lo corra necesita saber cuáles
  para recifrarlos. Probado en las dos direcciones: cero falsos positivos en 40
  contenedores sanos, y encuentra el duplicado sembrado. El riesgo no es que
  Quipu repita —cada nonce sale del RNG— sino que un integrador serialice mal o
  restaure una copia de seguridad sobre un cifrado nuevo. Con XChaCha20, dos
  mensajes que comparten clave y nonce entregan el XOR de sus textos claros, sin
  error ni aviso.
- **Batería estadística**: monobit y rachas sobre 131 072 bits reales del RNG,
  más la comprobación de 64 bytes seguidos a cero que es lo que falló en Debian.
  El umbral es de 5 sigma A PROPÓSITO: con el 0,01 habitual, la prueba fallaría
  una de cada cien veces sobre un RNG perfecto, y una prueba que falla sin motivo
  se acaba ignorando.

*Falta todavía:* que el detector de nonce sea API pública y no solo una prueba,
para que un integrador pueda correrlo sobre su propio almacén.

**Invariante:** I3.

### 6. Protocolo y composición — el ataque entre piezas correctas

**Métodos.** Confusión de algoritmo (aceptar `alg:none`, JWT); downgrade
(forzar la versión débil); cross-protocol; replay y reflexión; **sustitución de
clave/firma** (tomar la firma de un mensaje y reclamarla para otra clave); mezcla
de componentes en esquemas híbridos.

**Exposición de Quipu.** **Baja, y es donde Quipu pone trabajo propio.** La firma
ata la **clave pública completa del firmante y una etiqueta de dominio** en la
preimagen → impide sustitución de clave y mezcla de mitades. El KEM híbrido liga
el transcript estilo X-Wing. AAD/contexto en el AEAD. No hay negociación de
algoritmo → no hay downgrade. Contenedor versionado (`magic ‖ version`).

**Herramienta.** *Existe:* la forja adaptativa del lab (`forge.rs`,
`forge_triple.rs`), meta-tests que fallan si se debilita una defensa, y desde el
2026-07-27 las **sondas de downgrade y confusión** (`tests/taxonomia.rs`): una
versión anterior, una posterior y un `magic` ajeno tienen que rechazarse.

Su valor no es defender de un ataque de hoy —hoy no hay negociación que forzar—
sino de una CARACTERÍSTICA FUTURA. Es el `alg:none` de JWT: nadie lo diseñó como
agujero, apareció al añadir flexibilidad. Si mañana se añade un segundo cifrador
y un byte que elija, la prueba se pone roja y obliga a pensarlo.

**Invariante:** I2 + el binding de dominio como caso de I4.

### 7. Formato y parsing — atacar al que interpreta

**Métodos.** Maleabilidad (alterar el ciphertext y que aún descifre a algo);
truncación; splicing (unir trozos de contenedores distintos); reordenado y
duplicado en streaming; confusión de contenedor; manipulación de campos de
longitud → sobreescritura/entero.

**Exposición de Quipu.** **Baja por AEAD + hackerbot.** Poly1305 hace toda
alteración detectable; el streaming (`QST1`) resiste truncación, reordenado,
duplicado y splicing entre ficheros; `overflow-checks` **en release** evita el
wraparound silencioso al parsear longitudes de entrada no confiable.

**Herramienta.** *Existe:* hackerbot (tamper/truncation/uniqueness),
`stream_attack.rs`, fuzzing con libFuzzer sobre **cuatro** objetivos
(parse_container, unpad, codec_roundtrip, honey_decrypt). Desde el 2026-07-27 son **seis**: se añadieron `parse_signed` y
`parse_recipient`, que eran los que faltaban. El de la firma exige además que
ningún contenedor arbitrario verifique contra una clave ajena, no solo que no
entre en pánico.

Y la lista del CI **se deriva** con `cargo fuzz list` en vez de escribirse: la
anterior tenía cuatro nombres a mano y habría dejado los dos nuevos fuera sin que
nadie lo notara — el job seguiría verde fuzzeando menos de lo que hay.

*Falta todavía:* el corpus encadenado entre objetivos.

**Invariante:** I2.

### 8. Gestión de clave y operacional — donde vive la clave

**Métodos.** Extracción de memoria (cold boot; lectura de swap; volcado de
proceso); reutilización de clave entre contextos; KDF débil o pocas iteraciones;
clave en variable de entorno o log; residencia excesiva de la clave.

**Exposición de Quipu.** **Media, y 0.9.0 dio la respuesta fuerte.** `zeroize` en
todo material sensible; Argon2id memoria-dura (64 MiB); Shamir para custodia por
umbral; y el **custodio PKCS#11 (HSM): la clave privada no sale del dispositivo**.
`firmar_con_comparticiones` acota la vida del secreto a una llamada de Rust.
Residuo honesto documentado: la zeroización es *best-effort* (el optimizador o el
swap pueden dejar copias) — solo el HSM lo cierra del todo.

**Herramienta.** *Existe:* zeroize, HSM, Shamir, y desde el 2026-07-27 el chequeo
de que **el material sensible no viaja dentro de un error**
(`tests/invariantes.rs`): cifra con una passphrase, un pepper y un texto en claro
reconocibles, provoca cinco caminos de fallo y exige que ninguna de las tres
cadenas aparezca en el `Debug` del error.

El riesgo que cubre no es criptográfico sino de comodidad: basta con que alguien
añada la passphrase a un error «para depurar mejor» y esa cadena acaba en un log
o en la consola de un cliente.

*Falta todavía:* `mlock` opcional para el material reconstruido.

**Invariante:** I3 (residencia) + I5 (procedencia de la custodia).

### 9. Fuerza bruta y adivinación — cuando el secreto es débil

**Métodos.** Diccionario; rainbow tables; aceleración por GPU/ASIC; credential
stuffing; y para lo estructurado, modelos de "lo que parece humano" (medido: ×70
de ventaja contra señuelos uniformes con PIN humano).

**Exposición de Quipu.** **Contenida en tres capas complementarias.** Argon2id
hace cada conjetura cara (medido: **6 intentos/s** con el contenedor en la mano);
el OPRF **online** hace la fuerza bruta imposible sin el servidor (endurecimiento
de credenciales); honey **offline** quita el oráculo de éxito para secretos
uniformes de baja entropía. Tres respuestas a la misma amenaza para tres
despliegues.

**Herramienta.** *Existe:* `guessing.rs` (coste de adivinación acelerado por IA),
la simulación de ataque de diccionario (5000 intentos → 5000 rechazados).
*Falta:* medir el coste real en GPU/ASIC (hoy es CPU), y llevar la tabla de
señuelos estática de honey a un ×1 (hoy ×70 con secreto humano — el techo de #28).

**Invariante:** I4 (honey) + coste como refuerzo de I3.

### 10. Cadena de suministro y meta — atacar antes de que corra

**Métodos.** Dependencia comprometida (event-stream, xz/liblzma 2024);
typosquatting; actualización maliciosa; **primitiva con puerta trasera**
(Dual_EC_DRBG — el caso que define la paranoia sana); compromiso del build o del
publicador.

**Exposición de Quipu.** **Baja, y es de las mejor cubiertas.** `cargo-vet`
(supply chain) y `cargo-audit` (RustSec) obligatorios en CI —comprobado: son dos
de los tres checks que exige la rama `estable`—; SBOM (CycloneDX); *no se
inventan primitivas* → no hay un DRBG propio que pueda esconder una puerta.

**La publicación está a medias, y decirlo entero importa.** PyPI va por *trusted
publishing* (OIDC, sin tokens de larga vida). **crates.io NO**: usa un token de
larga vida en el disco de quien publica. Se comprobó de la peor manera el
2026-07-27, con un 403 al publicar `quipu-nucleo` porque al token le faltaba el
alcance `publish-new`. Mientras esa asimetría exista, el compromiso de ese token
es un camino real a una actualización maliciosa — justo la amenaza de esta
familia. Las
autopruebas corren sobre el binario que ejecuta, no sobre el de CI.

**Herramienta.** *Existe:* vet, audit, SBOM, autopruebas, y trusted publishing
SOLO en PyPI.
*Falta:* build reproducible verificable por terceros (que dos compilaciones den
el mismo binario), y un chequeo de que la rueda publicada = el commit etiquetado
(instalar del índice y comparar, ya es política manual — automatizarlo).

**Invariante:** I5.

---

## Lo que esto implica para las herramientas universales

La lectura vertical de la tabla de invariantes da el diseño:

1. **El lab ES la herramienta universal**, reestructurado alrededor de los cinco
   invariantes en vez de por ataque suelto. Cada método de arriba se vuelve una
   *sonda* de un invariante. Añadir un ataque nuevo es añadir una sonda a un
   invariante existente, no una herramienta nueva.

2. **El distinguidor entrenado (#91) generaliza a I1+I4.** Ya pregunta lo
   correcto —"¿un modelo nota la diferencia?"—. Aplicado a timing, a errores y a
   ciphertext, es *el* detector de observables dependientes del secreto y de
   oráculos. Es la pieza con más apalancamiento.

3. **Los invariantes deben probarse en TODOS los bindings (ligado a #100).** Una
   herramienta universal que solo corre en Rust no protege al usuario de Python.
   La paridad de características incluye la paridad de *garantías verificables*.

4. **Cada invariante necesita una prueba que DISCRIMINE** (directiva 8): una que
   siempre diga "seguro" no vale. El patrón ya está en el distinguidor (fuga
   sembrada a 20σ valida el silencio) y en el soak del HSM (error inyectado).

## Qué construir primero (borrador de orden)

1. **Generalizar el distinguidor** a un banco que cubra I1+I4 sobre las tres
   señales (timing, error, ciphertext), con adversario adaptativo. Máximo
   apalancamiento.
2. ~~**Detector de reúso de nonce** y batería estadística del RNG (I3).~~
   **HECHO** el 2026-07-27 (`tests/taxonomia.rs`). Queda promover el detector a
   API pública.
3. ~~**Verificador de uniformidad de errores** (I4) recorriendo cada punto de
   fallo.~~ **HECHO** el 2026-07-27: el mensaje y el tipo en `tests/invariantes.rs`,
   y el **tiempo** en `lab::timing::dudect_rechazo_por_causa`.
4. **dudect sistemático** sobre cada ruta con secreto (I1). ~~Con alarma si un
   build cae a implementación con tablas.~~ **La alarma se retira**: este stack
   no tiene AES en el núcleo y el de `quipu-cnsa` es *fixsliced* sin tablas —
   ver el recuadro de la familia 2.
5. ~~**Paridad de las herramientas en los bindings** (#100)~~ **RESUELTO POR
   ELIMINACIÓN**: desde 0.10 hay un solo binding, y un binding no puede divergir
   de sí mismo. Queda la **build reproducible** (I5).
6. **I7 — continuidad y modo degradado.** Añadido al orden el 2026-07-27, y va
   antes de lo que queda de I1: la evidencia empírica del propio bloque ALCANCE
   dice que los incidentes reales fueron disponibilidad y proveedor, no
   criptografía. Primera pasada **HECHA** (`docs/CONTINUIDAD.md`, meta-prueba de
   SQL, arranque que muere con seed inválido); el residuo está enumerado allí, y
   lo primero es el respaldo del *seed* fuera del VPS.

Nada de esto se implementa sin cerrar el diseño y el modelo de amenaza de cada
sonda. Este documento es el mapa, no la implementación.

**Y el mapa se audita contra el repositorio, no se hereda.** La pasada del
2026-07-27 comprobó una a una las afirmaciones de arriba: casi todas se
sostuvieron —incluidos los conteos finos, «8 vectores en 5 tamaños» y «88
válidas + 62 inválidas», medidos corriendo las pruebas— y dos no: I6 figuraba
como pendiente estando hecho, y el punto 4 pedía una alarma para un riesgo que
este stack no tiene. Un mapa que manda construir lo que no hace falta cuesta más
que uno incompleto.

---

## Reauditoría 2026-07-28 — amenazas recientes contra la pila real

Barrido de documentación reciente (2025–2026) de los métodos de ataque y las
primitivas que Quipu usa, contrastado contra las versiones PINEADAS, no contra la
teoría:

| Amenaza reciente | ¿Toca a Quipu? | Estado, medido |
|---|---|---|
| **RUSTSEC-2025-0144 / CVE-2026-22705** — canal lateral de temporización en `ml-dsa` (algoritmo *Decompose* al firmar; división en tiempo variable), publicado 2026-01-27, corregido en `>=0.1.0-rc.3` | Sí — Quipu firma con ML-DSA-87 | **CUBIERTO.** El árbol pinea `ml-dsa 0.1.1`, que ya trae la reducción de Barrett en tiempo constante. `cargo-audit` (obligatorio en CI) lo confirmaría en rojo si se bajara |
| **KyberSlash 1/2 + Clangover** (CVE-2024-37880) — timing por división dependiente del secreto en ML-KEM; el segundo lo introducía el optimizador de Clang | Sí — `ml-kem 0.3.2` | Parcheado aguas arriba; la familia 1 ya lo daba por ausente en la fuente vendida |
| **OWASP 2025 — Argon2id mínimo 19 MiB / t=2 / p=1** | Sí — KDF offline | Quipu por defecto **64 MiB / t=3 / p=1**, por encima del mínimo |

Lo que confirma la reauditoría, y es la tesis del bloque ALCANCE otra vez: el CVE
reciente que sí tocaba a Quipu era **un canal lateral de división en tiempo
variable** —exactamente la familia 2, I1— y la defensa que valió no fue una sonda
nueva sino **la procedencia (I5)**: pinear la versión corregida y que `cargo-audit`
lo vigile. La versión de la dependencia es el control, no el criptoanálisis.

**Añadido en esta pasada:** el KAT de Argon2id contra el RFC 9106 §5.3
(`tests/vectores_de_norma.rs`), que era el primer «falta» de la familia 1 — cierra
la procedencia de Argon2id igual que los de HKDF y Ed25519, y un test de cableado
que exige que `derive_master_key` sea Argon2id V0x13 y no Argon2i. Siguen faltando
las KAT de NIST para ML-KEM-1024 y ML-DSA-87 (vectores ACVP grandes; no se
transcriben a mano).
