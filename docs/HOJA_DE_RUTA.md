<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas -->

# Hoja de ruta

Estado al **2026-07-31**, tras el recorte a un solo binding. Todo lo que sigue
está medido contra el repositorio, los índices de paquetes y la producción; nada
citado de memoria.

Esta lista es **exclusiva de Quipu**. El índice general de pendientes mezcla seis
proyectos y no sirve para trabajar aquí.

## Dónde estamos

| | |
|---|---|
| Publicado en | crates.io y PyPI (la versión, en `Cargo.toml`) |
| Pruebas | **380 en verde en 38 binarios**, 0 fallidas (`cargo test --workspace --all-targets`, 2026-08-03, tras fusionar #265 con la rama de trabajo) · 883 sumando todas las combinaciones de features, medido antes y no vuelto a medir — esa segunda cifra envejece y hay que remedirla antes de citarla |
| `unsafe` de primera parte | **0** en todo el repositorio |
| Superficies publicadas | 2 — crates.io y PyPI |
| Sitios de versión | 4, verificados por el CI en 5 segundos |
| Servidor OPRF en producción | 9 comprobaciones, 0 fallos |
| Clientes de pago | **0** |

El código está sano. El negocio no ha arrancado. Esas dos frases mandan sobre el
orden de todo lo que viene.

## Lo primero, y no es código

Nada de lo demás importa hasta que el dinero pueda entrar.

### 1. `xiliux.com`: las cabeceras YA ESTÁN; queda el `HEAD /` — **medio HECHO**

Es el sitio que cobra con PayPal. Este punto pedía dos cosas y hoy solo falta
una. **Medido contra producción el 2026-08-05**, no recordado:

- **HSTS puesto** — `Strict-Transport-Security: max-age=31536000`. Con él, la
  primera petición de un cliente nuevo ya no viaja en claro. Van además
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` y una CSP con
  `object-src 'none'`, `base-uri 'self'` y `frame-ancestors 'none'`.
- **`HEAD /` sigue devolviendo 405**, y `GET /` devuelve 200. Un monitor
  estándar sondea con `HEAD`: hoy reportaría CAÍDA la página de pago. Eso no se
  arregla en nginx —lo contesta la aplicación NiceGUI—, así que el trabajo es de
  `/mnt/data/portafolio`, no de aquí.

Cómo volver a comprobarlo sin creerle a este documento:

```bash
curl -sI https://xiliux.com/ -w 'http=%{http_code}\n' | grep -iE 'strict-transport|x-content-type'
```

### 2. Probar el camino del dinero de punta a punta

`PAYPAL_ENV` cae a `sandbox` por defecto. Un pago real tiene que disparar el
aprovisionamiento contra `quipu-oprf-server` y entregar la clave al cliente.
Mientras eso no esté comprobado, mejorar el producto es pulir algo que no puede
cobrar.

### 3. Desbloquear la publicación antes de necesitarla — **HECHO el 2026-07-27**

Los dos bloqueos que este punto describía están cerrados, y se comprueba en los
índices, no en el recuerdo:

- **`quipu-nucleo` ya está en crates.io**, así que la dependencia por
  `path` + `version` de `quipu` sobre él no volverá a tumbar un release.
- **La rueda de `quipu-voprf` alcanzó al crate**: misma versión en PyPI y en
  crates.io, y es el paquete que se le indica al cliente del SaaS.
- **`quipu-cnsa` y `padme-frame` entraron al índice el 2026-08-04**, los dos en
  0.1.0. Este punto decía que el perfil CNSA quedaba fuera —cierto hasta el
  2026-08-03, cuando `curl` al índice daba 404 para los dos— y ya no lo está:
  con `padme-frame` publicado, `cargo package -p quipu-nucleo` deja de fallar
  con `no matching package named 'padme-frame' found`.

Los números concretos NO se copian aquí a propósito: este documento no es un
sitio de versión, y duplicarlos garantizaría que un día digan algo distinto de
la verdad. Se preguntan a los índices con `verificar.py publicado`.

TRAMPA AL COMPROBARLO, y cuesta media hora: la API de crates.io responde **403**
a una petición sin cabecera `User-Agent`, y un script descuidado lee esa
respuesta como «no publicado». Hay que mandar `User-Agent` y mirar el cuerpo.

Descubrir esto en mitad de un release es cómo se perdió la 0.9.0.

## Lo que hace vendible y financiable el producto

### 4. Build reproducible — invariante I5

El único de los siete invariantes que está señalado y sin herramienta *y* que
además vale dinero. Permite que cualquiera compruebe que la rueda de PyPI salió
del código publicado. Es lo que mira un financiador tipo OTF, y lo que convierte
«confía en mí» en «compruébalo».

**Medido el 2026-07-31, y estaba mucho más cerca de lo que este punto suponía.**
El compilador nunca fue el problema: el `.crate` ya se reconstruía byte a byte
(cargo normaliza mtimes y uid/gid) y el `quipu.abi3.so` también. Lo ÚNICO no
determinista de la rueda eran dos campos del SBOM CycloneDX que escribe maturin
—un `serialNumber` UUID aleatorio y un `timestamp` de reloj—; el `RECORD` cambiaba
solo porque los hashea. Con `SOURCE_DATE_EPOCH` tomado de la fecha del commit, la
rueda sale idéntica. Y con `--remap-path-prefix` desaparecen las rutas absolutas
de la máquina que el binario llevaba dentro (`/home/<usuario>/.cargo/...`, de los
metadatos de `panic`), que es lo que lo rompería en otra máquina.

Ya no se afirma: el CI reconstruye dos veces y exige el mismo sha256, y comprueba
que el binario no lleve rutas de quien lo construyó. Los dos checks se probaron
contra una rueda hecha a propósito sin el remap, y ahí se ponen rojos.

La receta para terceros está en `docs/REPRODUCIBILIDAD.md`, con lo que **falta**
dicho al lado: la rueda **manylinux publicada** todavía no se ha reconstruido en
su propio contenedor —el CI construye en `ubuntu-latest` y el release en el
contenedor de `maturin-action`—, y aquí solo hay una máquina física.

### 5. Auditoría independiente

`docs/PRE_AUDIT.md` deja el terreno preparado: primitivas vetadas, cero `unsafe`
propio, modelo de amenaza escrito. El recorte de julio redujo lo que hay que
auditar — ya no hay ABI de C ni cuatro envoltorios.

## Los invariantes sin vigilancia

Actualizado el 2026-07-27 tras los PR #110 a #117: de los cuatro que aquí
figuraban, **I4 se cierra entero** y los otros tres bajan a un resto nombrado.
Todos venían del mismo sitio: el plan que los nombraba se cerró como entregado
porque el *documento* se entregó, y el documento era un mapa.

| | Estado | Falta |
|---|---|---|
| **I1** Ningún observable depende del secreto | casi | seis rutas cubiertas por `dudect_*` en `src/lab/timing.rs` — `ct_eq`, decapsulación válida-vs-corrupta, dos claves, rechazo por causa, verificación de firma y derivación de subclaves. Falta **solo** la alarma si un build cae a una implementación con tablas |
| **I3** Entropía fresca y nonce único | hecho, sin exponer | `tests/simulacion.rs` mide colisiones de sal y nonce en 800 cifrados, y `tests/taxonomia.rs` (PR #113) añade el detector de reúso —que dice QUÉ pares colisionan— y la batería del RNG: monobit y rachas sobre 131 072 bits, 0,27σ y 0,73σ. Falta promoverlo a **API pública** para que un integrador lo corra sobre su propio almacén |
| **I4** El fallo no revela nada | **hecho** | nada. El mensaje y el tipo en el PR #110 (`tests/invariantes.rs`) y el TIEMPO en el #114 (`lab::timing::dudect_rechazo_por_causa`) |
| **I5** Procedencia verificada | casi | la rueda ya se reconstruye byte a byte y el CI lo exige (punto 4). Falta **solo** rehacer la rueda **manylinux publicada** dentro de su propio contenedor y comparar: hoy el CI construye en `ubuntu-latest` y el release en el de `maturin-action`, así que se caza el no-determinismo de origen pero no se demuestra lo del artefacto que se descarga |

## Producto: lo que aún no existe

### 6. Portador de papel sobre simbología estándar

El objetivo nunca fueron los glifos: es que un secreto sobreviva fuera de todo
disco. El canal propio se eliminó porque el modelo de amenaza ya decía que no
aportaba seguridad, y el canal PNG le siguió por la misma razón de custodia — un
formato propio solo lo decodifica Quipu, y lo que decide a veinte años es que el
decodificador exista en 2050.

Tres capas en cascada: QR con *Structured Append* por defecto, Base32 con
Reed-Solomon como respaldo tecleable, y nada de discreción hasta medirla.
`ecc` se conservó justo para la capa de respaldo.

**MEDIDO el 2026-07-31** (`src/lab/papel.rs`, `cargo run --release --example
papel --features lab`). Hoja de 240×240 puntos para todos, la MISMA corrección de
errores para todos, y los dos portadores emparejados por **rasgo mínimo**, que es
la variable que domina el canal.

Bytes de secreto entregados **íntegros** (≥95 % de 40 intentos), paridad 15 %:

| Degradación | Mejor portador | Bytes |
|---|---|---|
| copia limpia | matriz, módulo 1 | **6 083** |
| 1ª y 3ª copia | matriz, módulo 3 | **651** |
| fax / copia sucia | matriz, módulo 6 | **147** |
| raya de tóner | matriz, módulo 4 | **359** |

**La matriz gana en TODAS las columnas.** A igual rasgo mínimo lleva entre 10× y
23× más que el texto (6 083 vs 621 con rasgo 1; 651 vs 28 con rasgo 3), y cuando
hace falta robustez sale más barato **engordar el módulo** que pasarse a glifos:
un glifo gasta 48·s² puntos para llevar 5 bits, un módulo gasta s² para llevar 1.
Esa diferencia de 9,6× es un impuesto que ningún aumento de robustez compensa.

Puesto en la escala que importa: **una estampilla de 240×240 puntos con módulos
de 6 puntos entrega 147 B a través de un fax sucio**, y una clave de Quipu son 32.

**Consecuencia para el diseño: la capa Base32 NO se justifica por robustez.** Se
justifica solo por otra propiedad, que esta medición no toca — que un humano
pueda **teclearla sin escáner**.

### Lo decidido con ese dato (2026-07-31)

**1. La capa tecleable SE CONSERVA, y deja de llamarse «respaldo».** El argumento
que la salva no es la robustez sino que **degrada a «teclee estos caracteres en
cualquier decodificador Base32»**: cero dependencia de que Quipu exista en 2050,
que es el objetivo declarado de esta sección. Condición para que ese argumento se
sostenga: **el marco Reed-Solomon tiene que ser OPCIONAL**, o el Base32 crudo
volvería a necesitar herramienta nuestra y perdería su única ventaja. Alcance
nuevo: papel limpio, carga de tamaño de clave (≤64 B).

**HECHO** en `quipu_nucleo::papel::tecleable`. `Marco::Desnudo` es
`Base32(secreto)` según la RFC 4648 —relleno incluido, porque un decodificador
estricto lo exige— y lo sujeta un KAT contra los vectores del §10 de la propia
norma, no contra nosotros mismos. `Marco::Protegido` añade el Reed-Solomon y
tolera errores de tecleo, a cambio de necesitar esta librería. **No hay valor por
defecto**: quien escribe elige, porque son artefactos con promesas distintas.

Y el artefacto que sobrevive veinte años no son los caracteres: son los
caracteres **más la frase que dice qué hacer con ellos**, que la da
`tecleable::instruccion` para imprimirla al lado.

**1-bis. Y le faltaba la mitad, descubierta el 2026-08-01 al auditar la ficha
#106.** Los dos marcos de arriba no cubren el caso que da nombre a esa ficha
—«custodia en papel sin máquina»— por una razón que no estaba escrita:

| | ¿lo lee cualquiera sin Quipu? | ¿detecta el error de tecleo? | ¿se dicta por teléfono? |
|---|---|---|---|
| `Desnudo` (Base32) | **sí** | **no** | mal: 52 caracteres |
| `Protegido` (Base32+RS) | **no** | corrige hasta su cota; pasada, **puede devolver otro secreto** | mal |
| `palabras` (BIP-39) | **sí** | **sí** (detecta, no corrige) | **sí**: 24 palabras |

Lo grave era la casilla del medio: `Desnudo` devuelve **otro secreto en
silencio** si se transcribe mal un carácter, y con una clave eso no se nota
hasta que hace falta. `Protegido` lo tapa, pero al precio de necesitar esta
librería — o sea, deshaciendo la única razón por la que la capa existe.

**Y esa casilla decía de más hasta el 2026-08-01**, cosa que corrigió la revisión
independiente con un número: la fila de `Protegido` ponía «sí, y además corrige».
Reed-Solomon **miscorrige**. Medido sobre 5 000 hojas con daño por encima de su
capacidad: 1 318 se recuperaron bien, 3 425 dieron error y **257 devolvieron
bytes equivocados como si fueran buenos** — el 7 % de las que no se recuperaron.
Es una propiedad del código, no un fallo de esta implementación, pero era
exactamente la casilla que este mismo documento califica de «lo grave» cuando la
tiene `Desnudo`. Solo el marco de palabras detecta sin ambigüedad, y solo hasta
sus ENT/32 bits de suma.

Para `papel::reensamblar` el riesgo se cierra por otro lado y conviene decirlo:
la carga es *ciphertext*, así que una miscorrección la caza el AEAD de arriba. La
capa tecleable **no tiene esa red**: lo que sale de ella es el secreto.

**HECHO** en `quipu_nucleo::papel::palabras`, detrás de la feature `palabras`.
Se ata a los **24 vectores oficiales de la norma** en los dos sentidos y a una
implementación **ajena** (`bip39`, solo `dev-dependencies`, mismo papel que
`rqrr` con el QR). La lista de 2 048 palabras se guarda verbatim y una prueba
comprueba su SHA-256 contra el canónico: nadie tiene que fiarse de nuestra
transcripción.

**Por qué la BIP-39 y no una lista propia**: es el mismo argumento que mató los
glifos. Una lista nuestra exige que Quipu exista en 2050; la BIP-39 la
decodifica cualquier herramienta de las que ya hay en todos los lenguajes.

**Límites, declarados y no escondidos**: admite exactamente 16, 20, 24, 28 o 32
bytes —con cualquier otro tamaño **falla**, porque rellenar devolvería al leer
bytes que nadie guardó—, y su suma es de **detección, no de corrección**.

**2. En el NÚCLEO no entra ninguna dependencia de QR.** La simbología estándar sí
es obligatoria —inventar una matriz propia recrea el problema de los glifos—,
pero **renderizar el símbolo no tiene por qué hacerlo Quipu**. El trabajo de
Quipu es la carga útil: trocear, proteger con ECC y poner la cabecera de índice y
total. Dibujar es presentación.

| Capa | Dependencia |
|---|---|
| `papel::empaquetar` / `reensamblar` | **ninguna nueva** |
| feature `qr` (no-default), símbolo hecho | `qrcode` (MIT OR Apache-2.0, encoder) |
| solo pruebas | `rqrr` como dev-dependency (decoder) |

El decoder **no viaja en el artefacto**: el usuario decodifica con su teléfono, y
`rqrr` existe para que la prueba de ida y vuelta no sea un `assert` sobre nuestro
propio encoder.

**3. Sin *Structured Append*.** N símbolos QR independientes, cada uno con
`[versión][índice][total]` dentro de su carga: cada símbolo es un QR estándar
válido por su cuenta, no se depende de que la librería soporte SA, y la cabecera
de reensamblado viaja DENTRO del flujo protegido por ECC.

Lo que se le exige a `qrcode` es **disponibilidad, no confidencialidad**: la carga
es ciphertext más ECC, así que un encoder con fallos solo puede producir un
símbolo ilegible — nunca filtrar la clave. Eso baja el listón de `cargo-vet`, que
es el check que gobierna esto (aquí no hay `deny.toml`).

Y una advertencia sobre la propia medición, porque estuvo a punto de decir lo
contrario: con el barrido cortado en módulo 4 el texto parecía ganar en «fax»
(28 B contra 0). Ganaba solo porque no se había probado el módulo que también lo
aguanta. Ver `src/lab/papel.rs` para el modelo, sus tres límites declarados y sus
casos rojos.

### 7. Cifrado con negación

Honey no generaliza —su señuelo está atado a la distribución del secreto— pero
un contenedor con negación sí. Tres hallazgos verificados fijan el diseño.

**Diseño cerrado el 2026-07-31 en `docs/DISENO_NEGACION.md`; sin implementar, que
es lo que autorizaba la luz verde.** Ya no es «exponerlo en un binding»: al
decidir Juan que se cubran los dos frentes —la prueba Y la sospecha— el alcance
cambió. Cubrir la sospecha exige un contenedor indistinguible de aleatorio, y hoy
**28 de los 68 bytes de cabecera gritan «Quipu»** (mágico, versión, banderas,
`codebook_id`, huella del alfabeto y los tres enteros del KDF). Eso obliga a
cifrar la cabecera, y cifrarla obliga a sacar del contenedor los parámetros del
KDF, porque hacen falta para derivar la clave que la abriría.

**HECHO el 2026-07-31**, tras la decisión de la salida (a) —los parámetros del
KDF salen del contenedor—. Vive en `src/negacion.rs` tras la feature `negacion`,
no-default y fuera de las ruedas de Python en esta versión.

Las cuatro sondas del §8 están medidas y cada una trae su caso rojo: el
contenedor no se distingue de azar, ninguna posición de byte es predecible, uno
con oculto no se distingue de uno sin él, y abrir el señuelo cuesta lo mismo que
abrir el oculto (`t = 0,73` frente a un umbral de 10).

Un aviso que se ganó a pulso y está en el §10.4 del diseño: **la sonda que el §8
daba por hecha no existía**. El banco agregado no veía un mágico de 4 bytes en
1024 —53 % de acierto— y habría aprobado un contenedor que gritaba «Quipu». Hubo
que construir la sonda posicional. Un caso rojo que falla no siempre dice que el
sistema esté roto; a veces dice que el medidor no mide lo que creías.

### 8. El laboratorio no manda sobre nada

El red-team adaptativo mide, y lo que mide no alimenta ningún parámetro del
producto. Inteligencia sin mando.

### 9. La calidad del señuelo de honey — MEDIDO el 2026-07-31, y el mínimo no existe

Este punto pedía el número del señuelo **menos** convincente. Ese número **no
puede existir** para el honey de hoy, y no por falta de escribirlo: «el peor
señuelo» solo se puede medir cuando el espacio de secretos tiene ESTRUCTURA que
un señuelo pueda violar —una frase fuera del diccionario, un día 32, un formato
que no cierra—. `honey` modela el secreto como L tokens **uniformes**, así que
todo señuelo es un elemento válido del espacio y el peor es tan convincente como
el mejor. Medido: la plausibilidad mínima de 500 señuelos es 0, y la de un
secreto humano también. Una métrica que no puede dispararse nunca es un generador
de ceros con otro nombre.

Lo que sí se mide ahora, y es la primera vez que se mide sobre la **librería** y
no sobre una simulación de sus salidas: 500 señuelos reales de
`encrypt_pin`/`decrypt_pin` con frases equivocadas, y la cola contra el espacio
uniforme que honey declara proteger. En `feat/peor-senuelo`, pendiente de
integrar.

La consecuencia de diseño sigue en pie: **mientras el secreto se modele como
tokens uniformes, el modo no debe extenderse a más superficies** — no porque
falte el número, sino porque no hay estructura que un señuelo pueda respetar.

## Decisiones tomadas, para no reabrirlas

- **Quipu es Rust, y solo Rust.** No puede ser Python: el `int` de precisión
  arbitraria hace que el coste de operar con un escalar dependa de su valor —
  medido, 2,6× entre 32 y 512 bits— y un secreto no se puede borrar de la
  memoria. Son I1 y O5, dos propiedades que el producto vende. Y «criptografía
  en Python puro» no existe: las implementaciones que hay lo advierten en su
  propia portada, y las de producción envuelven C.
- **Un solo binding, Python.** Node, Go, la C ABI y las integraciones de Express
  y Go se retiraron en julio de 2026. Nadie las usaba y su coste era invisible.
- **`encode_to_blob` no se expone.** Los bindings ya tienen salida binaria
  (`encrypt_stream`) y salida con longitud oculta (`encode`). Una tercera forma
  sería decir lo mismo dos veces.
- **El VOPRF vive en `quipu-voprf` (Apache-2.0), nunca en el núcleo AGPL.** Es
  lo que permite vender el servicio a quien no quiere publicar su servidor de
  autenticación.
- **La clave `k` y el dominio del OPRF no rotan jamás.** Rotar invalidaría todo
  lo derivado.

## Lo que este documento no cubre

`quipu-cnsa` (perfil CNSA 2.0) espera una cotización de laboratorio: es una
gestión, no código.

Lo que sí era código —«¿se queda en cifrado simétrico o crece a firma y KEM?»—
**está decidido y hecho desde el 2026-07-31**: el perfil añadió `firma`
(ML-DSA-87) y `destinatario` (ML-KEM-1024), y van **puros**, no híbridos, que es
lo que distingue a esta hermana de `quipu`. Con eso quedan cubiertas cuatro de
las cinco funciones de CNSA 2.0. Su README ya no dice que falten.

La línea que sigue sin cruzarse, y está escrita en ese README: implementar los
algoritmos **no** es estar validado FIPS 140-3. Eso lo certifica un laboratorio
acreditado y no está en el plan.

El modelo de tres ramas está descrito en [`RAMAS.md`](RAMAS.md) y **ya no está
pendiente**: `estable`, `testing` y `desarrollo` existen, y las dos primeras
tienen `enforce_admins` activo.

Y una asimetría que había entre lo escrito y lo configurado, corregida el
2026-07-27: `RAMAS.md` promete que a `estable` se le exija «todo lo anterior
**más**», pero en GitHub `testing` requería el check «coherencia de versiones» y
`estable` no. La rama publicada tenía la puerta más floja que la candidata. Los
checks son ya los mismos en las dos, y desde el 2026-07-31 son **siete**: a los
cuatro de entonces se suman `rueda de Python` —la que comprueba I5—,
`security lab` y `HSM`, que corrían en cada PR sin bloquear nada. Un check que no
bloquea es un aviso. Se comprueba así, y no leyendo esta frase:

```bash
gh api repos/isazajuancarlos/quipu/branches/estable/protection \
  -q '.required_status_checks.contexts'
```
