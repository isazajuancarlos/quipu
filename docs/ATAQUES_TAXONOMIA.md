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

Un ataque nuevo casi siempre es una forma nueva de romper **uno** de estos. Si el
lab prueba los cinco en continuo y con adversario adaptativo, cubre el espacio,
no la lista.

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
primitivas*: usa XChaCha20-Poly1305, Argon2id, HKDF-SHA512, Ed25519, ML-KEM-1024,
ML-DSA-87, todas vetadas y con parámetros en categoría NIST 5. El criptoanálisis
de la primitiva es responsabilidad de la comunidad que la mantiene; la de Quipu
es *no degradarla* (parámetros, no reinventar, KyberSlash verificado ausente en
la fuente vendida).

**Herramienta.** *Existe:* fijado de versiones + vectores publicados (RFC 5869,
Wycheproof) + `cargo-audit` (RustSec) que avisa de un aviso nuevo contra una
primitiva. *Falta:* un chequeo que ligue cada primitiva a su vector de referencia
y falle si la implementación deja de conformar (no solo "es consistente consigo
misma").

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

**Herramienta.** *Existe:* dudect sobre la ruta post-cuántica (clases *válido vs
corrupto* en decapsulación, *dos claves distintas*), `src/lab/timing.rs`.
*Falta:* extender dudect a **cada** ruta con secreto de forma sistemática (hoy es
selectivo), y un chequeo que marque si un build cae a una implementación con
tablas (el caso AES-sin-NI, que hoy pasa callado).

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
(`selftest-fault`), firma híbrida. *Falta:* una sonda de lab que inyecte fallos
en la firma y **compruebe que el combinador AND los absorbe** (probar que la
defensa estructural discrimina, no asumirlo).

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
dos salidas?"; honey_attack. *Falta:* un **verificador de uniformidad de errores**
que recorra cada punto de fallo y confirme que el mensaje, el tipo y el *tiempo*
no discriminan la causa (hoy se afirma, conviene medirlo en continuo).

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

**Herramienta.** *Existe:* `selftest::check_rng_health`, el manejo falible.
*Falta:* un **detector de reúso de nonce** a nivel de contenedor/stream (que un
integrador que serialice mal no repita nonce entre mensajes bajo la misma clave),
y una batería estadística sobre la salida del RNG (monobit, runs, ya hay parte en
el distinguidor).

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
`forge_triple.rs`) ataca justo esto; meta-tests que fallan si se debilita una
defensa. *Falta:* sondas de **downgrade/confusión** explícitas (aunque hoy no hay
negociación, documentar y probar que añadir un modo nunca reintroduce
negociación insegura).

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
`stream_attack.rs`, fuzzing con libFuzzer (parse_container, unpad,
codec_roundtrip). *Falta:* ampliar el fuzz a **todos** los parsers de contenedor
nuevos (firma, recipient, honey) con corpus encadenado, no solo el simétrico.

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

**Herramienta.** *Existe:* zeroize, HSM, Shamir. *Falta:* un chequeo de "la clave
no aparece en logs/errores" (grep de material sensible en la salida, ligado a la
regla de no exponer secretos), y `mlock` opcional para el material reconstruido.

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
(supply chain) y `cargo-audit` (RustSec) obligatorios en CI; SBOM (CycloneDX);
publicación por *trusted publishing* (OIDC, sin tokens de larga vida); *no se
inventan primitivas* → no hay un DRBG propio que pueda esconder una puerta. Las
autopruebas corren sobre el binario que ejecuta, no sobre el de CI.

**Herramienta.** *Existe:* vet, audit, SBOM, trusted publishing, autopruebas.
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
2. **Detector de reúso de nonce** y batería estadística del RNG (I3).
3. **Verificador de uniformidad de errores** (I4) recorriendo cada punto de fallo.
4. **dudect sistemático** sobre cada ruta con secreto (I1), con alarma si un
   build cae a implementación con tablas.
5. **Paridad de las herramientas en los bindings** (#100) y build reproducible
   (I5).

Nada de esto se implementa sin cerrar el diseño y el modelo de amenaza de cada
sonda. Este documento es el mapa, no la implementación.
