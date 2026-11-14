<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza -->

# Hoja de ruta

Estado al **2026-08-05**, revisado punto por punto contra el repositorio, los
índices de paquetes y la producción; nada citado de memoria. La estructura viene
del recorte a un solo binding (2026-07-31).

Esta lista es **exclusiva de Quipu**. El índice general de pendientes mezcla seis
proyectos y no sirve para trabajar aquí.

## Dónde estamos

| | |
|---|---|
| Publicado en | crates.io y PyPI (la versión, en `Cargo.toml`) |
| Pruebas | **398 en verde** con las features por omisión y **497 con las cinco opt-in**, 0 fallidas (`cargo test --workspace --all-targets`, remedido el **2026-08-16**; eran 382 el 2026-08-05 sobre `7cd7f0c`, y 380 el 2026-08-03). Las dos ignoradas miden coste, no corrección, y se corren a mano con `-- --ignored`. Los **doctests** van aparte y también en verde —`--all-targets` los EXCLUYE— y el banco del verificador da 28 pruebas / 120 comprobaciones · 883 sumando todas las combinaciones de features, medido antes y no vuelto a medir — esa segunda cifra envejece y hay que remedirla antes de citarla |
| `unsafe` de primera parte | **0** en todo el repositorio |
| Superficies publicadas | 2 — crates.io y PyPI |
| Sitios de versión | 4, verificados por el CI en 5 segundos |
| Servidor OPRF en producción | **desplegado el 2026-08-16** (antes, el binario era del 27 de julio y 170 commits atrás). `md5 aa6eb7b7`, `/healthz` y `/v1/plans` en 200 contra el dominio, `/v1/oprf/evaluate` ejercitado (401/400/401), y **la clave pública intacta** — los clientes la fijan (S5) |
| Clientes de pago | **0** |

El código está sano. El negocio no ha arrancado. Esas dos frases mandan sobre el
orden de todo lo que viene.

## Lo primero, y no es código

Nada de lo demás importa hasta que el dinero pueda entrar.

### 1. `xiliux.com` sin HSTS ni `nosniff` — **HECHO el 2026-08-05**

Es el sitio que cobra con PayPal. El punto pedía dos cosas y las dos están, las
dos **medidas contra producción**, no recordadas:

- **Cabeceras puestas** — `Strict-Transport-Security: max-age=31536000`, así que
  la primera petición de un cliente nuevo ya no viaja en claro. Van además
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` y una CSP con
  `object-src 'none'`, `base-uri 'self'` y `frame-ancestors 'none'`.
- **El `HEAD` ya responde 200**, desplegado el 2026-08-05. Y el problema era
  cuatro veces mayor de lo que decía este punto: no fallaba `/`, fallaban
  **diez de las once rutas públicas** —incluidas `/robots.txt` y
  `/sitemap.xml`, que los rastreadores piden así—. Solo `/favicon.ico` se
  salvaba.

  La causa no era de la portada: **FastAPI no añade `HEAD` al registrar un
  `GET`** (Starlette sí lo hace en su `Route`; `APIRoute` no, y NiceGUI monta
  sus páginas por ahí). Por eso el arreglo es un middleware que vale para todas
  las rutas y para las que se escriban mañana, y **no** un `@app.head('/')` que
  habría tapado el caso del informe dejando nueve rotas.

  **No se arregló en nginx a propósito**, que era la salida obvia y es peor: si
  nginx contesta el `HEAD`, el monitor recibe 200 aunque el proceso esté muerto
  —«sano» y «muerto» se verían igual, que es justo lo que un monitor existe para
  distinguir—. Contestando desde la aplicación, el 200 prueba que el proceso
  vive y que su router funciona.

Cómo volver a comprobarlo sin creerle a este documento — las dos mitades:

```bash
curl -sI https://xiliux.com/ -w 'http=%{http_code}\n' | grep -iE 'strict-transport|x-content-type'
for u in / /blog /servicios /quipu /informes /cotizador /quipu/precios \
         /robots.txt /sitemap.xml /manifest.json /favicon.ico; do
  printf '%-16s HEAD=%s GET=%s\n' "$u" \
    "$(curl -sI -o /dev/null -w '%{http_code}' https://xiliux.com$u)" \
    "$(curl -s  -o /dev/null -w '%{http_code}' https://xiliux.com$u)"
done   # 11/11 en 200 el 2026-08-05
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

## Del estudio de matemática clásica (2026-08-16)

Los tres huecos que salieron medidos de [`MATEMATICA_Y_CAOS.md`](MATEMATICA_Y_CAOS.md).
La medición ya está hecha, que es lo caro; falta el arreglo.

### 1. La *Adaptive Proportion Test* de la SP 800-90B — **HECHA el 2026-08-16**

`salud_de` implementaba una de las dos pruebas continuas que exige la norma.
Ahora están las dos, y el ciclo corto ya no pasa: la prueba que decía
«esto hoy NO se detecta» está **dada la vuelta** y verde por el otro lado.

Dos desviaciones de la letra de la norma, las dos con motivo escrito en el
código: la ventana es el búfer y no un W fijo de 512 —Quipu pide 16–32 bytes, y
un W que no se llena nunca es un vigilante que no corre—, y se compara contra el
valor más frecuente y no contra el primero, que es más potente por el precio de
una cota de unión ya pagada en la tabla.

Calibrada a **α ≤ 2⁻⁶⁴ por búfer** en vez del 2⁻²⁰ de NIST, porque aquí un fallo
**para** en vez de informar y un falso positivo le rompe el día a un cliente
legítimo (directiva 21). La tabla no se cree: `la_tabla_de_cortes_es_la_calculada`
la recalcula y exige las dos mitades —que el corte cumple y que uno menos NO—.

Su límite está escrito, que es la mitad que se olvida: por debajo de 12 bytes no
hay corte posible, y un ciclo de periodo 3 en 32 bytes da 11 apariciones frente a
un corte de 13 — no se caza; en 48 sí. Caza el sesgo de FRECUENCIA, no toda
periodicidad.

Cuatro mutantes, los cuatro muertos, uno de ellos en la dirección contraria
(cortes demasiado estrictos → falsos positivos sobre azar real).

### 2 y 3. El códec cuadrático y su README — **HECHO el 2026-08-16**

`encode_base_n` convertía de base con un bucle de divisiones: O(m²), ×4,00 al
duplicar, 50,7 s para 512 KiB y unas 5,6 h para 10 MiB. Reescrito con conversión
de base por **divide y vencerás**, con la tabla de potencias `paso^(2^i)`:

| | antes | después | |
|---|---:|---:|---:|
| 512 KiB | 50 698,8 ms | **456,7 ms** | **111×** |
| 10 MiB | ~5,6 h | **41,4 s** | medido, no extrapolado |
| factor al duplicar | ×4,00 | **×2,82** | `M(m)·log m` con Toom-3 |

Los dígitos que salen son **byte a byte los mismos** —lo fija la proptest contra
la implementación ingenua, que es la definición del formato, más los vectores de
referencia—, y eso importa porque el códec produce un artefacto FIRMADO que ya
está en bases de datos de clientes.

Lo que sostiene la mejora, y hay que re-verificarlo si se cambia de librería de
enteros grandes: **`num-bigint` divide con Burnikel-Ziegler**. Con división
escolar el algoritmo sería cuadrático con PEOR constante que el bucle.

El README lo dice ahora en los dos idiomas, con las dos cifras y con el matiz de
que la mejora es de **tiempo, no de espacio**. Y hay guardia contra la
regresión, que es lo que faltaba de verdad —una deriva de coste no la ve un banco
de corrección—:

```bash
cargo test --release -p quipu-nucleo --test escala_del_codec -- --ignored --nocapture
```

## Reparto ciego (`blindaje`) — nace el 2026-08-16

Modo opt-in contra una amenaza que ningún otro modo cubre: **que una de las
librerías esté comprometida**. `S1` aleatorio, `S2 = P xor S1`, cada mitad a un
AEAD de un crate distinto — así ninguno de los dos ve el claro. Detalle en el
README y en `docs/THREAT_MODEL.md §3`.

Precio medido: **×2,00 de tamaño** y **×17 de tiempo** a 256 KiB (×52 a 1 KiB;
el ×5,2 de la primera medición era `QBL1`, antes de la máscara). El doble
de tamaño no es optimizable y está explicado.

**Las tres tareas que quedaban, cerradas el mismo día:**

1. **Enchufado a `api::`.** `api::encode_blindado` cifra; **`api::decode`, la de
   siempre, abre los dos modos** — el modo viaja en el bit 0 de `flags` de la
   cabecera, así que el artefacto declara cómo se escribió. Es aditivo: el
   contenedor no cambia de forma ni de versión, y el modo normal sigue byte a
   byte igual (hay prueba). Como la cabecera es AAD, cambiarle el bit a un
   contenedor ya escrito rompe la autenticación en vez de degradarlo en silencio.

   **Es el PRIMER bit de `flags` que se usa desde que existe el formato**, y la
   regla estricta que lo rechazaba todo demostró para qué estaba: un binario
   anterior devuelve `FlagsDesconocidos`, y uno sin la feature devuelve
   `DecodeError::ModoNoCompilado`. Los dos en voz alta.

2. **El gate corre las features opt-in.** `verificar.py local` medía sólo el
   juego por omisión, así que las pruebas del blindaje —y las de `honey`,
   `negacion`, `slh` y `escrow`— no las ejecutaba nadie. Ahora hay una pasada
   más, y **la lista se DERIVA de `[features]` de Cargo.toml**: una feature nueva
   entra sola, y dejarla fuera obliga a escribir el motivo en `FEATURES_FUERA`.
   398 pruebas por omisión, **497** con las cinco.

   Y pagó en la primera corrida: cazó **una fuga de la clave maestra que yo
   acababa de introducir** al enchufar el blindaje. Ver el punto siguiente.

3. **Vectores congelados de `QBL1`.** Tres vectores con el azar fijo, el material
   derivado, y —la que de verdad importa para un cliente— un blob escrito a mano
   que tiene que seguir abriendo. Se congeló ANTES de enchufarlo a `api`, que era
   la condición. Tres mutantes de formato muertos.

   **Regenerados para `QBL2` el 2026-08-17**, que es el único caso en que se
   tocan: el formato cambió a propósito al entrar la máscara del reparto ciego.
   El vector viejo NO se tiró — se quedó como caso rojo en
   `un_blob_qbl1_no_se_abre_en_silencio`, que fija que un contenedor de la v1 se
   rechace con `OtraVersion` y no devuelva basura autenticada. La marca que
   produce ese diagnóstico viaja en claro, así que el diagnóstico solo se emite
   si el contenedor AUTENTICA bajo la versión que dice ser: es un hecho.

**Y un hallazgo que no buscaba nadie: el tamaño de `DecodeError` es parte del
presupuesto de pila.** Añadirle una variante con un `&'static str` —dieciséis
bytes— puso en rojo la prueba de residuo del camino del DESTINATARIO, que ni
siquiera se había tocado: al crecer el enum crece `Result<Vec<u8>, DecodeError>`,
se mueven los marcos y la clave de contenido acaba fuera de los 128 KiB que
alcanza `antihacker::limpiar_pila`. La variante se dejó sin carga y el
acoplamiento, que era invisible, lo vigila ahora
`api::tests::los_result_del_camino_de_descifrado_no_crecen` — que se pone rojo antes y
diciendo por qué.

**Lo que sigue abierto y NO es de este bloque:** `verificar.py local` deja un
«sin comprobar» heredado del 2026-08-14 —la coherencia de features de la rueda de
Python, que se retiró—. Se deja como está a propósito: ahí no hay dos listas que
comparar, y colapsarlo a verde sería aprobar sobre cero datos (directiva 30). Es
distinto de las features excluidas de la pasada opt-in, que son una comprobación
que SÍ corrió y saltó a conciencia lo que no puede probar aquí.

## Decisiones tomadas, para no reabrirlas

### Criptografía «caótica»: descartada (2026-08-16)

No entra en el núcleo. Motivos, con el detalle en
[`MATEMATICA_Y_CAOS.md`](MATEMATICA_Y_CAOS.md) §1: choca con la filosofía
declarada —*nunca inventamos primitivas*—; los mapas caóticos degeneran al
discretizarse (ciclos cortos, irreproducibilidad entre plataformas) y el flujo
que producen suele ser independiente del texto claro, o sea recuperable con **un**
par elegido; y la parte aprovechable —las *mixing transformations* de la teoría
ergódica— entró en la criptografía con Shannon en **1949** y hoy vive
cuantificada en el criptoanálisis diferencial y lineal.

Importa dejarlo escrito porque Quipu **renderiza a imagen**, que es justo el
género donde vive esa literatura (gato de Arnold + mapa logístico + histograma
plano como «prueba»). La propuesta va a reaparecer; la respuesta ya está.

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
