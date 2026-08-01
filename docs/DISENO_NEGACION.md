<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas
-->

# Contenedor con negación — diseño, e implementación

Estado: **implementado** el 2026-07-31 en `src/negacion.rs`, tras la feature
`negacion` (no-default). Cierra las fichas **#99** (el mecanismo) y **#118** (los
tres hallazgos que lo fijan), que son la misma cosa mirada dos veces.

El diseño de aquí se escribió antes que el código y el código lo siguió, con
**tres desviaciones argumentadas** que se listan en la §10 — no enterradas al
final por vergüenza, sino porque solo se entienden después de leer el diseño.

Lo que la §8 pedía medir está medido, y con sus casos rojos:

| Sonda | Resultado |
|---|---|
| Contenedor contra azar (agregada) | no distingue |
| **Ninguna posición predecible** | no delata — y la sonda hubo que **construirla**, ver §10.4 |
| Con oculto contra sin oculto | no distingue |
| Tiempo: abrir señuelo vs abrir oculto | `t = 0,73` con umbral 10 — indistinguible |
| Tiempo: acertar vs fallar | `t = 3,35` con umbral 10 — bajo umbral, ver §10.5 |

Todo lo que sigue está verificado contra el repositorio, no citado de memoria.

---

## 1. Qué se promete, y qué no

La negación tiene **dos frentes**, y hasta el 2026-07-31 el diseño solo cubría
uno. La decisión de Juan fue cubrir los dos.

| Frente | La pregunta del adversario | Qué lo cubre |
|---|---|---|
| **La prueba** | «Demuéstrame que hay un segundo volumen» | El volumen oculto, indistinguible del relleno |
| **La sospecha** | «Sé que esto es Quipu, y sé que Quipu tiene negación: dame la segunda contraseña» | Un contenedor sin cabecera reconocible |

El primero es criptográfico y se resuelve. El segundo es de **formato**, y es el
caro: hoy `MAGIC = b"QUIP"` va en claro en el byte 0 de la cabecera
(`quipu-nucleo/src/container.rs`) y **además es el AAD del AEAD**. Mientras siga
ahí, cualquiera con el archivo sabe que es Quipu.

**El límite que va en el README en negrita, no enterrado en un doc de diseño:**
la negación protege contra la PRUEBA, no contra la SOSPECHA de quien ya decidió
sospechar, y ante coacción física esa distinción puede no valer nada. Quien use
esta función puede ser alguien cuya libertad dependa de entenderlo. No se anuncia
como «cifrado indetectable».

---

## 2. Modelo de amenaza, explícito

**El adversario puede:** obtener el contenedor completo, **una vez**; conocer el
formato entero y esta documentación; exigir contraseñas bajo coacción legal o
física; disponer de cómputo clásico y cuántico dentro de lo razonable.

**El adversario NO puede:** ver el contenedor en **dos momentos distintos** y
comparar; observar la máquina mientras se escribe; obtener las claves de otra
vía.

**Por qué la instantánea única es defendible aquí y no en general.** El alcance
declarado de Quipu son **datos en reposo** —no mensajería, no sesiones—. Un
artefacto en reposo se escribe una vez y se guarda; no hay un flujo de versiones
que comparar. Un producto de volumen montable (VeraCrypt) tiene que defenderse de
la comparación entre instantáneas porque el usuario escribe dentro a diario; aquí
no. Eso **simplifica el diseño de verdad**, no por conveniencia: desaparece el
problema más difícil del diseño de VeraCrypt —que escribir en el señuelo pise el
volumen oculto—, porque no se escribe dos veces en el mismo contenedor.

Se documenta como límite, no se esconde: **quien guarde versiones sucesivas del
mismo contenedor en un respaldo pierde la negación.** Eso va en la API, no solo
aquí.

---

## 3. Por qué el formato de hoy no sirve (verificado contra el código)

La cabecera son **68 bytes** (`Header::SIZE`, atado por prueba en
`src/container.rs`), y de ellos solo el salt y el nonce parecen azar:

| Campo | Bytes | ¿Parece azar? |
|---|---|---|
| `MAGIC` (`QUIP`) | 4 | **No** — constante |
| `version` | 1 | **No** |
| `flags` | 1 | **No** |
| `codebook_id` | 2 | **No** |
| `codebook_hash_prefix` | 8 | **No** — constante por alfabeto |
| `salt` | 16 | Sí |
| `nonce` | 24 | Sí |
| `kdf_mem_kib` / `iterations` / `parallelism` | 12 | **No** — enteros pequeños |

**28 de 68 bytes gritan «Quipu».** Ese es el frente de la sospecha, medido.

Y de #118, verificado en `src/api.rs`: el AEAD cifra **y autentica** todo el
bloque rellenado (`encrypt(key, nonce, padded, aad=header)`), así que **el volumen
oculto no puede vivir dentro del relleno de Padmé**. Meter datos ahí rompe el tag
del señuelo y abrir con la contraseña A fallaría — lo contrario de lo que se
busca. El espacio oculto tiene que quedar FUERA de lo que autentica el AEAD del
señuelo. Es la razón concreta por la que hace falta formato nuevo.

---

## 4. El diseño

Un contenedor de **tamaño total S declarado por el usuario**, no derivado del
contenido. Tres tramos:

```
[ salt 16 ][ cabecera cifrada ][ ---------- cuerpo de tamaño S ---------- ]
             (indistinguible)    señuelo (AEAD propio) | resto = azar u oculto
```

Los tres requisitos de #118, que sin ellos la negación no existe:

1. **El tamaño total lo elige el usuario.** Si se ajustara al contenido del
   señuelo, cualquier hueco delataría.
2. **El resto se rellena SIEMPRE con azar**, haya o no volumen oculto.
3. **Ningún campo indica si existe el segundo volumen**, ni siquiera
   implícitamente.

Cómo se abre:

- **Contraseña A** → deriva la clave del señuelo, abre el señuelo. El resto del
  cuerpo es, para quien solo tenga A, indistinguible de relleno.
- **Contraseña B** → deriva una clave y un **desplazamiento** distintos; abre el
  volumen verdadero, con el AEAD de fuerza completa. Su región no se solapa con
  la que autentica el AEAD del señuelo.
- **Contraseña equivocada** → falla igual en los dos casos, y tarda lo mismo.

Que la región del señuelo sea localizable **no es fuga**: el relleno posterior es
azar exista o no el oculto, así que saber dónde empieza no distingue los dos
mundos. Lo que no puede existir es un campo que diga «aquí hay más».

---

## 5. La consecuencia cara, que es la decisión de verdad

Para que la cabecera sea indistinguible de azar hay que cifrarla. Para cifrarla
hace falta derivar una clave de la contraseña + salt. Y para derivarla hacen falta
**los parámetros del KDF** — que hoy viven **dentro** de esa misma cabecera.

Es circular, y solo tiene tres salidas:

- **(a) Los parámetros salen del contenedor** y los fija la versión de formato.
  Cabecera indistinguible; se pierde la agilidad de parámetros: subir el coste de
  Argon2id exige versión de formato nueva.
- **(b) Los parámetros quedan en claro** delante de la cabecera cifrada.
  Se conserva la agilidad; **12 bytes de enteros pequeños siguen siendo una
  firma** y el frente de la sospecha queda a medio cubrir. Es decir: no cumple.
- **(c) Los parámetros se prueban por fuerza** sobre un juego pequeño y fijo.
  Cabecera indistinguible y algo de agilidad, a cambio de multiplicar el coste de
  abrir por el número de combinaciones — y ese coste lo paga el usuario legítimo
  en cada apertura, no el atacante una sola vez.

**DECIDIDA POR JUAN LA (a)** (2026-07-31), con el encargo de analizar
independientemente qué arrastra, para que no haya sorpresas. Sigue el análisis.

### 5.1 Lo que (a) GANA, y no estaba en la cuenta

Hoy `api.rs` lee `kdf_mem_kib`, `kdf_iterations` y `kdf_parallelism` **de la
cabecera que aporta quien entrega el archivo**, y se los pasa a Argon2id. La
autenticación del AEAD ocurre *después* de derivar la clave, así que el coste lo
elige el atacante antes de que nada lo valide. El código ya lo sabe y lo acota
—`is_sane()` en `api.rs:165`, verificado, y también en `honey.rs` y `stream.rs`—,
de modo que **no hay vulnerabilidad viva**; pero el techo sigue siendo suyo: 256
MiB × 16 iteraciones por intento, y multiplicado por cuantos archivos quiera
entregar.

Con (a) esa entrada **desaparece**: los parámetros dejan de venir del archivo. No
es solo el precio de esconder la cabecera, es que se quita del mapa una entrada
controlada por el adversario. Ese es el argumento más fuerte a favor de (a) y no
lo teníamos escrito.

### 5.2 La sorpresa: (a) NO escapa del coste de (c), lo APLAZA

Aquí está lo que hay que saber antes de escribir código.

La lógica de (a) es «los parámetros los fija la versión de formato». Pero **la
versión tampoco puede ir en claro**: un byte de versión es un campo reconocible,
y el frente de la sospecha exige que no haya ninguno. Luego el lector **no puede
saber qué versión tiene delante**.

Consecuencia directa: el día que se publique una versión 2 con parámetros
distintos, todo lector tendrá que probar los de la v1 *y* los de la v2, porque el
archivo no le dice cuál es. Es decir, **cada juego de parámetros que se publique
añade para siempre una pasada de Argon2id a cada apertura**. Que es exactamente el
coste de la opción (c), solo que diferido y creciendo solo.

No invalida la decisión —(c) empieza en N pasadas y (a) empieza en UNA—, pero
cambia cómo hay que diseñarla:

1. **Los parámetros se eligen UNA vez y de forma conservadora.** No es «ya lo
   subiremos»: subirlo cuesta, y el que paga es el usuario legítimo, en cada
   apertura, para siempre.
2. **Publicar una versión de formato nueva pasa a ser una decisión cara.** Debe
   quedar escrito como tal donde se decida, no descubrirse cuando pese.

### 5.3 Lo que hay que CONSTRUIR para que eso no muerda

La salida es que el usuario legítimo pueda decir qué perfil usar **sin que el
archivo lo diga**. Una pista fuera de banda:

- La API de apertura acepta un **perfil opcional**. Si se da, se prueba solo ese:
  una pasada, coste idéntico al de hoy.
- Si no se da, se prueban los perfiles conocidos **del más nuevo al más viejo**,
  de modo que el caso común —un archivo reciente— cuesta una pasada igualmente y
  solo los antiguos pagan más.
- **No filtra nada**: la pista viaja en la cabeza del usuario o junto al archivo,
  nunca dentro. Dos contenedores del mismo tamaño siguen siendo indistinguibles
  entre sí, que es lo único que la negación promete.

Esto es lo que convierte a (a) en la opción buena de verdad y no solo en la menos
mala: sin la pista, (a) degenera en (c) con el tiempo; con ella, no.

### 5.4 Lo que NO cambia, para que no se busque

- **No rompe nada de lo escrito.** Es un formato nuevo y convive con el actual; el
  contenedor `QUIP` de hoy sigue leyéndose con sus parámetros en la cabecera.
- **No toca el coste de Argon2id** en el camino normal de `encode`/`decode`.
- **No afecta a `honey` ni a `stream`**, que tienen su propia validación.

---

## 6. Primitivas: ninguna nueva

No se inventa nada, y la ficha lo exigía. Todo lo que hace falta ya está en el
árbol y ya tiene KAT: **Argon2id** (`src/kdf.rs`) para derivar,
**XChaCha20-Poly1305** (`src/cipher.rs`) para el señuelo y para el volumen
verdadero, el **CSPRNG** (`src/aleatorio.rs`) para el relleno, y **Padmé**
(`quipu-nucleo/src/prelayers.rs`) para que la longitud dentro de cada volumen no
hable.

El relleno del cuerpo tiene que salir del CSPRNG, **no de un cifrado de ceros**:
si saliera de un keystream con clave derivada, existiría una clave que lo
«explica», y eso es precisamente el campo que no puede existir.

---

## 7. Feature gate y ruedas

- **Nombre: `negacion`.** No `deniable`: el árbol nombra en castellano lo que es
  suyo (`antihacker`, `aleatorio`, `firmante`, `prelayers` es la excepción
  heredada) y esto es formato propio, no un término de arte importado.
- **No es *default*.** El bloque `[features]` de `Cargo.toml` lleva en comentario
  la razón de cada uno; la de este es que un formato con promesa de seguridad
  seria no se enciende por descuido.
- **En las ruedas de Python: NO, en la primera versión.** Razón: la superficie
  PyO3 tendría que exponer la contraseña B y el tamaño declarado, y una API mal
  usada aquí no produce un error, produce una falsa sensación de negación. Se
  expone cuando el formato haya pasado el banco y esté estable. Recordar que los
  features de la rueda viven en **dos** sitios (`pyproject.toml` y `release.yml`)
  y tienen que concordar.

---

## 8. Cómo se prueba que el frente de la sospecha está cubierto

No se da por cubierto por argumento. Se **mide**, y la herramienta ya existe: el
banco de indistinguibilidad de `src/lab/indistinguibilidad.rs`, que unifica I1 e
I4 bajo un veredicto común y acepta cualquier sonda de bytes.

Tres sondas, y las tres tienen que salir «no distingue»:

1. **Contenedor contra azar.** El blob completo frente a bytes del CSPRNG. Si el
   distinguidor los separa, la cabecera sigue hablando y el frente de la sospecha
   NO está cubierto. Esta es la que hoy fallaría con los 28 bytes de estructura.
2. **Con oculto contra sin oculto.** Dos poblaciones de contenedores del mismo
   tamaño declarado, unos con volumen verdadero y otros solo con relleno. Es la
   prueba del frente de la prueba, y la razón por la que el relleno tiene que ser
   azar siempre.
3. **Tiempo de fallo.** Contraseña equivocada contra contraseña de señuelo
   contra contraseña verdadera, por dudect. Si abrir el oculto tarda distinto,
   el reloj es el campo que dijimos que no existía.

Y las tres tienen que **discriminar**: se corren contra un contenedor
deliberadamente roto —con el mágico puesto a mano— y ahí el banco tiene que
ponerse rojo. Un banco que nunca dice que no, no dice nada.

---

## 9. Lo que queda por decidir, y es de Juan

1. ~~**La salida de la circularidad del KDF** (§5).~~ **DECIDIDA: (a)**
   (2026-07-31). El análisis de sus consecuencias está en §5.1–§5.4; lo que
   arrastra y no se había visto es que **(a) aplaza el coste de (c) en vez de
   evitarlo**, y que por eso hace falta construir la pista de perfil fuera de
   banda (§5.3).
2. ~~**Si el señuelo es obligatorio.**~~ **RESUELTA: sí**, tomando la propuesta
   que este mismo punto traía. Un contenedor con volumen oculto y señuelo VACÍO,
   abierto con A, muestra nada — y «no tengo nada guardado ahí» es una respuesta
   peor que un señuelo creíble. `crear` devuelve `SenueloVacio` y el mensaje
   explica el porqué, no solo la regla.
3. ~~**Si esto va en la próxima versión o en una rama de formato.**~~
   **RESUELTA: formato nuevo que convive**, tras la feature `negacion`
   (no-default) y sin tocar el contenedor `QUIP`. No rompe nada de lo escrito, y
   no entra en las ruedas de Python en esta versión (§7).

---

## 10. Lo que el código hizo distinto, y por qué

El diseño se escribió antes que el código. Tres cosas cambiaron al escribirlo, y
una cuarta la descubrió una prueba que falló.

### 10.1 No hay «cabecera cifrada» aparte

El §4 la dibujaba para llevar la longitud del señuelo. **No hace falta**: si el
AEAD cubre la región ENTERA, la longitud viaja dentro del texto en claro —el
prefijo de Padmé, que ya existía— y el ciphertext mide siempre lo mismo. Una
pieza menos, y ninguna fuera del cifrado, que es justo lo que pide el frente de
la sospecha.

### 10.2 Las regiones son fijas, no derivadas de la contraseña

El §4 hablaba de un «desplazamiento distinto» para el oculto. No aporta, y el
argumento está en el propio §4: **localizar una región no es fuga**, porque el
relleno es azar exista o no el oculto. Derivar el desplazamiento sí añade un modo
de fallo real —solapar con la región que autentica el AEAD del señuelo, que el §4
prohíbe expresamente— a cambio de nada.

El precio, dicho para que nadie lo descubra a la mala: **el volumen oculto no
puede pasar de la mitad del cuerpo**. Es predecible y sale por error (`NoCabe`),
no por truncamiento.

### 10.3 Se prueban SIEMPRE las dos regiones

Aunque la primera acierte. Salir antes haría que abrir el señuelo costara un AEAD
menos que abrir el oculto, y el §8.3 exige que el reloj no sea el campo que
dijimos que no existía. Medido: `t = 0,73` frente a un umbral de 10.

### 10.4 La sonda que el §8 daba por hecha NO existía

El §8 decía que el banco de indistinguibilidad «acepta cualquier sonda de bytes»
y que la sonda 1 cazaría el mágico. **No lo cazaba.** El caso rojo —estampar
`QUIP` a mano en un contenedor de 1024 bytes— dio **53 % de acierto**, o sea
nada, y el banco lo habría aprobado.

La causa no es un fallo del distinguidor sino su alcance: sus doce rasgos son
**agregados de todo el blob** —monobit, chi², correlación serial— y cuatro bytes
constantes en mil quedan diluidos. La pregunta del frente de la sospecha es otra,
y es **posicional**: ¿hay alguna posición de byte cuyo valor se pueda predecir?

Se construyó `distinguidor::posicion_mas_delatora`, que la contesta: cuenta, para
cada posición, cuántas veces se repite su valor más frecuente, con un umbral
derivado de la cola de Poisson y corregido por mirar `largo × 256` casillas a la
vez. Con el mágico puesto, delata y **dice en qué posición**; sin él, no delata
ni contra el azar puro.

La lección, que vale más que la sonda: **un caso rojo que falla no siempre
significa que el sistema esté roto — a veces significa que el medidor no mide lo
que creías.** Arreglarlo en el caso (buscar un rojo que la sonda sí viera) habría
dejado el agujero intacto y con un verde encima.

### 10.5 Acertar y fallar no cuestan exactamente lo mismo

`t = 3,35` frente al umbral de 10: pasa, pero es el número más alto del banco y
conviene no venderlo como cero. Es esperable —el camino de acierto hace el
`unpad` y construye el resultado— y **no distingue cuál de los dos volúmenes
abrió**, que es lo único que el formato promete. El adversario, además, ya sabe
si la contraseña abrió: recibe el contenido.

Lo que sí habría que revisar si ese número creciera: que no empiece a distinguir
*qué región* falló.
