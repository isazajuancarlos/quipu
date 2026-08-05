# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.1] — 2026-08-05

**Un corte de EMPAQUETADO y titularidad: ni una línea de código de la librería
cambia.** Salen cuatro artefactos —`quipu` **0.11.1**, `quipu-voprf` **0.2.4**,
`quipu-nucleo` **0.1.3** y `quipu-cnsa` **0.1.1**— y los cuatro existen por la
misma razón: crates.io es INMUTABLE, así que un defecto en lo que viaja dentro
del `.crate` no se corrige donde se cometió, solo en la versión siguiente.

Los tres defectos que lo motivan se cometieron el 2026-08-04 y **ninguno lo vio
una prueba en verde**, porque ninguna prueba miraba el ARTEFACTO. Los tres se
habrían cazado con un `cargo package --list` antes de subir.

### Fixed

- **`quipu` 0.11.0 se publicó con los 15 borradores de `docs/superpowers/`
  dentro** —149 archivos frente a los 134 de este corte, y la diferencia son
  exactamente esos 15—. Tres de ellos diseñan subsistemas **eliminados en la
  0.10** (la ABI de C, los bindings de Node y los de Go), así que un consumidor
  que abriera el `.crate` leía documentación de algo muerto sin forma de
  saberlo; y todos llevan instrucciones para agentes que no significan nada
  fuera del repositorio.

  La causa es de calendario y conviene que quede escrita: el tag `v0.11.0`
  apunta a `690cbc3`, y el `exclude` que los saca entró **41 minutos después de
  publicar**, en `cbe6d66`. El veredicto estaba anclado a la rama y no al
  artefacto (directiva 31). La 0.11.0 no se retira con `yank`: no está rota ni
  es insegura, y `^0.11` resuelve solo a esta.

- **`quipu-voprf` 0.2.3 se publicó sin `NOTICE`.** Es el crate **Apache-2.0** de
  la familia —el que enlazan terceros sin arrastrar la AGPL—, y la atribución es
  justo lo que esa licencia pide propagar (§4(d)). El archivo se escribió a las
  20:34 y la publicación salió a las 21:30 desde un estado que no lo incluía:
  **2 h 24 min tarde**. Quedaban dentro las cabeceras SPDX y el campo `authors`,
  así que la titularidad nunca desapareció del todo; lo que se perdió es su
  exigibilidad en la cadena de esa versión.

- **`quipu-nucleo` y `quipu-cnsa` declaraban AGPL-3.0-or-later y no entregaban
  el texto de la licencia** — ni `LICENSE` ni `NOTICE`, en ninguna de sus
  versiones publicadas. El campo SPDX **declara** la licencia; no la **entrega**,
  y la familia GPL/AGPL pide que cada receptor reciba copia. Quien los sacaba de
  crates.io —que es como los saca todo el mundo, no clonando el repositorio— no
  la recibía. Los dos llevan ahora el texto AGPL y un `NOTICE` propio.

- **`scripts/oprf-e2e.sh` llevaba meses sin poder ejecutarse, y viajaba dentro
  del `.crate`.** Invocaba `quipu-capi`, `bindings/node` y `bindings/go`,
  eliminados en la 0.10, y moría en su primera orden. Es el mismo defecto que
  motivó sacar los documentos muertos, aplicado a medias: aquella pasada quitó
  los documentos y dejó dentro el guion. Se **arregla** en vez de excluirse,
  porque es lo único del repositorio que cruza la frontera del programa para el
  OPRF: arranca el binario de verdad y le habla por HTTP.

  Y al correrlo salió lo de fondo: **ese e2e no podía ponerse rojo nunca**
  —`run_client` se tragaba el estado del cliente y la última orden era un
  `echo`—. Ahora el cliente de Rust es obligatorio y falla con `exit 1`; el de
  Python es best-effort y se marca **SALTADO**, que no puede verse igual que
  «pasó». Verificado con su pareja: mutando el cliente, `exit 1`; sin mutante,
  `exit 0`.

### Added

- `NOTICE` en el crate raíz, en `quipu-nucleo` y en `quipu-cnsa`. Existen además
  de `COPYRIGHT` porque son dos lectores distintos: `COPYRIGHT` es la
  declaración jurídica, y `NOTICE` es lo que cosechan las herramientas de
  cumplimiento del cliente para armar su página de atribuciones.

  Los tres declaran los **datos normativos de terceros** que hasta ahora no
  constaban en ninguna parte: los vectores ACVP de NIST (FIPS 203 y FIPS 204) en
  el raíz, y en `quipu-nucleo` la lista canónica BIP-39 —atada a su fuente por
  el SHA-256 que verifica `la_lista_es_la_canonica`— junto con los vectores
  oficiales de `trezor/python-mnemonic`. En los tres casos la atribución es a la
  ESPECIFICACIÓN, no a código incorporado.

### Changed

- **La regla que rige la lista `exclude` estaba escrita al revés**, y en la
  dirección que más duele. Decía que empaquetando desde el repositorio git
  —el camino normal, el de los cinco jobs `crate-*` de `release.yml`—
  «`.gitignore` decide solo, y estas entradas no llegan a opinar». Es falso para
  lo **rastreado**: git no aplica `.gitignore` a lo que ya está en el índice, así
  que ahí `exclude` no es el segundo cinturón sino el único. El positivo de
  control estaba dentro del propio repositorio —`docs/superpowers/` son 15
  archivos rastreados, no ignorados, ausentes del paquete—. De creer la versión
  anterior se concluye que para publicar basta con ignorar.

  Con la regla corregida vuelven a la lista `PENDIENTES.txt` —que se había
  podado por no existir hoy en el árbol, y podar por ausencia es lo que la regla
  prohíbe— y entra `CLAUDE.md`, que faltaba desde siempre.

- **La portada de docs.rs remitía a un archivo inexistente.** `src/lib.rs` decía
  «Arquitectura por capas (ver `QUIPU_PROYECTO_Y_REQUISITOS.txt`)», y ese archivo
  está excluido y sin rastrear: ni en el `.crate` ni en GitHub. Ahora apunta a
  `docs/SPEC.md`, por URL absoluta —igual que los dos README desde el
  2026-08-04—, porque una ruta relativa resuelve en GitHub y se rompe desde
  crates.io y docs.rs.

- **La cabecera de `docs/SPEC.md` decía «through v0.6.0»** mientras el crate iba
  por 0.11.0 y el propio documento ya cubría en sus §§7–11 el modo híbrido PQ, el
  VOPRF, las firmas híbridas, el streaming y honey. Lo caducado era el banner, no
  el cuerpo — pero es la primera línea que lee quien llega desde docs.rs. Declara
  ahora los **seis** formatos que especifica (`QUIP`, `QPQ1`, `QSG1`, `QSG3`,
  `QST1`, `QHNY`) con su sección, y que el modo con negación no estrena formato.

### Security

Ninguna vulnerabilidad. La revisión de seguridad de este corte —`estable`
`7cd7f0c` contra `testing` `48bab4c`, y el delta posterior— salió **sin
hallazgos ≥ 8** en contextos independientes. Los defectos de arriba son de
empaquetado, documentación y titularidad; ninguno afecta a la criptografía, y
ninguno expuso nada no público: los 134 archivos del paquete están todos
rastreados en un repositorio público, con cero coincidencias en un barrido de
claves, tokens, rutas de máquina e IPs.

## [0.11.0] — 2026-08-04

**Cinco artefactos salen en el mismo corte**, y por eso llevan una sola sección
en vez de una cada uno: `quipu` **0.11.0**, `quipu-nucleo` **0.1.2**,
`quipu-voprf` **0.2.3**, y las dos PRIMERAS publicaciones del workspace,
`quipu-cnsa` **0.1.0** y `padme-frame` **0.1.0**.

Las notas de abajo no se repartieron por crate a propósito: están escritas como
prosa continua que se cruza entre paquetes —el portador de papel toca
`quipu-nucleo` y `lab`, el `forbid(unsafe_code)` toca los seis—, y trocearlas
habría sido reescribirlas. La atribución va dentro de cada entrada, que es donde
ya estaba.

### Security
- **`negacion::crear` comparaba las dos contraseñas por BYTES, y el KDF las
  compara tras NFKC.** En ese hueco cabía justo el fallo que la guarda existía
  para impedir: `caf\u{e9}` y `cafe\u{301}` son cadenas distintas byte a byte,
  pasaban la comprobación de «no pueden compartir contraseña», y
  `derive_master_key` derivaba de las dos LA MISMA maestra. El contenedor nacía
  con las dos regiones bajo la misma clave y, como `intentar` da prioridad al
  oculto cuando ambas abren, entregar el «señuelo» bajo coacción devolvía el
  volumen verdadero.

  No es alcanzable por un atacante —hace falta que el propio usuario elija dos
  frases visualmente idénticas—, y por eso no salió como hallazgo de la revisión
  de seguridad sino como observación. Se arregla igual, porque una guarda que no
  significa lo que dice es una salvaguarda falsa.

  El arreglo va en la REGLA y no en el caso (directiva 23): la noción de «la
  misma contraseña» se define **una vez**, en `kdf::normalizar`, y la usan tanto
  la derivación como la comparación. Comparar con un criterio y derivar con otro
  era la causa; añadir un caso especial para los acentos habría sido el síntoma.

  Prueba que discrimina: tres parejas NFKC-equivalentes —acento combinante,
  ligadura `ﬁ`, superíndice `⁵`— con la premisa medida (bytes distintos, maestra
  idéntica) y el gemelo obligado, `café` contra `cafe`, que SÍ difieren tras
  NFKC y tienen que seguir aceptándose abriendo cada una lo suyo.
- **`#![forbid(unsafe_code)]` en los SEIS paquetes del workspace, no en uno.**
  Estaba solo en `quipu-cnsa`; `quipu`, `quipu-nucleo`, `quipu-voprf`,
  `padme-frame` y el servidor OPRF tenían cero `unsafe` **hoy** y nada que lo
  impidiera **mañana**.

  Esta entrada decía «los CINCO crates» y **contaba de menos**, que es el mismo
  error que venía a corregir: el workspace tiene seis miembros, y el sexto
  —`quipu-oprf-server`— llevaba el atributo solo en `main.rs`. Su **lib**, que
  es todo el código que corre en el VPS, no estaba cubierta: un `[[bin]]` es una
  unidad de compilación aparte y no hereda nada de la lib. Cerrado el 2026-08-02
  poniéndolo en `src/lib.rs` y en `src/bin/custodia-seed.rs`.

  **Y la garantía no llegaba a quien la compra.** `git diff origin/estable HEAD
  -- crates/quipu-voprf/` devolvía UN cambio, y era exactamente esa línea: el
  atributo existía en el árbol y no en la 0.2.2 del índice, que es lo que
  descarga quien hace `cargo add quipu-voprf`. crates.io no deja re-subir una
  versión, así que sin bumpear se quedaba aquí para siempre. **`quipu-voprf` sube
  a 0.2.3** — parche, porque un atributo de lint no cambia ninguna firma.

  Importa justo en ese crate y no en otro: es el Apache-2.0, el que enlazan
  clientes ajenos del servicio OPRF. Y es la misma lección por tercera vez en un
  día — «los seis paquetes llevan `forbid`» era cierto en el árbol y falso en el
  índice, igual que «los CINCO crates» era cierto de los cinco que contaba.

  Es la diferencia entre una propiedad medida y una garantizada, y el `CLAUDE.md`
  la difuminaba sin querer: «la única aparición en el árbol es un
  `forbid(unsafe_code)`» es literalmente cierto y se lee como si el árbol entero
  estuviera protegido.

  Nota para quien lo herede: se probó primero con
  `cfg_attr(not(feature = "python"), ...)` suponiendo que las 28 macros de PyO3
  generarían `unsafe` en el crate. **No lo hacen** — el `forbid` incondicional
  compila también con `--features python`—, así que el condicional se quitó. Un
  mecanismo que sobra engaña sobre por qué está.

### Added
- **Simulación de enlazabilidad (N9): la afirmación es de POBLACIÓN y no tenía
  prueba de población.** Los dos cambios que cierran N9 —la escalera canónica
  del KDF y el `codebook_id` en cero— llegaron con pruebas unitarias buenas que
  no pueden sostener lo que prometen: `la_escalera_colapsa_la_huella_de_
  configuracion` cuenta las huellas de `KdfParams::canonicos()`, o sea **el
  catálogo de la API, no lo que `encode` acaba escribiendo**. Y «todo el que use
  `EQUILIBRADO` se ve igual» es una frase sobre un conjunto: no se verifica con
  un elemento.

  `tests/enlazabilidad_simulacion.rs` escribe **126 contenedores de 13 autores**
  —cada uno con su frase, su pepper, su peldaño y **pidiendo un `codebook_id`
  propio y no nulo**— en 13 hilos con `recv_timeout`, y mide sobre el blob los
  15 bytes de cabecera que son a la vez visibles y estables: `flags`,
  `codebook_id` y los doce del KDF. Salt y nonce quedan FUERA a propósito — son
  frescos por operación, y meterlos daría 126 huellas únicas y un verde falso.

  Exige tres cosas: como mucho 3 huellas para 13 autores, ninguna huella con un
  solo autor detrás, y `codebook_id` en cero pese a que todos pidieron el suyo.

  Con dos rojos que la validan, porque un banco que no discrimina es un
  generador de ceros: reintroducir `codebook_id: opts.codebook_id` da «13
  huellas distintas para 13 autores», y sustituir el Associated Data por una
  constante rompe el camino de error que comprueba que el metadato está
  AUTENTICADO — que no agrupe sirve de poco si se puede reescribir en tránsito.

  Coste medido: 90 s en debug, 7,9 s en release (~11× de Argon2id). Es la prueba
  más lenta del árbol y **la población no se recorta**: con tres personas el
  aserto se cumpliría por aritmética y no por el mecanismo.

- **`papel::tecleable` — la capa que un humano copia sin ninguna máquina, con el
  marco Reed-Solomon OPCIONAL.** Es la condición que hace válida la única razón
  por la que esa capa existe: `Marco::Desnudo` es `Base32(secreto)` según la RFC
  4648 y **cualquier decodificador del mundo lo abre**, hoy y en 2050;
  `Marco::Protegido` tolera errores de tecleo a cambio de necesitar esta
  librería. Sin defecto: quien escribe elige.

  Lo sujeta un KAT contra los vectores del §10 de la RFC —no contra nosotros
  mismos—, con relleno `=` incluido porque un decodificador estricto lo exige.

  Al leer se tolera cómo escribe la gente (minúsculas, espacios, guiones) y se
  corrige el `0` por `O`, que es inequívoco. **Lo ambiguo se RECHAZA diciendo las
  dos lecturas**: un `1` puede ser `I` o `L`, y adivinar produciría un secreto
  distinto en silencio, que es el único fallo que este formato no puede
  permitirse.

- **Feature `qr` en `quipu-nucleo`: el símbolo hecho**, para quien no tenga
  frontend que lo dibuje. `papel::qr::simbolos` devuelve la matriz de módulos de
  cada trozo, con nivel de corrección **alto (30 %)** por defecto — más de lo
  habitual, porque la medición mostró que el papel castiga más de lo que sugiere
  la intuición. Cada símbolo es un QR estándar independiente: sin *Structured
  Append*.

  El círculo se cierra con un decoder **ajeno** (`rqrr`, dev-dependency): un
  encoder roto de forma consistente pasaría una prueba contra sí mismo y fallaría
  en el primer papel real. Y las dos capas de corrección quedan fijadas por
  separado — la del QR repara una mancha DENTRO de un símbolo, la de Reed-Solomon
  repara que un símbolo ENTERO no se pueda leer— con el caso rojo que comprueba
  que un símbolo destrozado de verdad no se lee.

- **`quipu-nucleo::papel` — la carga útil del portador de papel, sin ninguna
  dependencia nueva.** `empaquetar` trocea, protege con Reed-Solomon e
  **intercala**; `reensamblar` reconstruye con los trozos que se hayan podido
  leer, en cualquier orden y sin necesitarlos todos.

  El núcleo **no renderiza el símbolo**, y es la decisión que salió de medir
  (hoja de ruta §6): dibujar un QR es presentación, y en la mayoría de los
  productos ya lo hace el frontend. Así la simbología estándar se usa sin que el
  núcleo cargue con una dependencia para dibujarla.

  El intercalado es lo que convierte «se perdió un símbolo» en «falta un byte de
  cada N», que es la diferencia entre recuperarse y no.

  **Y el cuello de botella no está donde parecía.** La cuenta por bloques de
  datos daba 50 símbolos perdidos tolerables con 155 símbolos y paridad 200; la
  prueba dijo que con 50 no se recupera nada. La causa: `ecc::protect` antepone
  un bloque propio de **15 bytes que corrige 5 errores**, y esos 15 bytes caen en
  los 15 PRIMEROS símbolos — perder los 50 primeros no le quita a ese bloque una
  fracción, se lo lleva entero. El bloque más pequeño es el más frágil y es el
  que manda. `simbolos_perdidos_tolerados` devuelve ahora el mínimo de las dos
  cuentas, y la garantía se prueba perdiendo los símbolos del PRINCIPIO, que es
  el peor caso.

- **`quipu-cnsa` crece a firma y canal de destinatario.** El perfil ya no es solo
  cifrado simétrico: `firma` implementa **ML-DSA-87** y `destinatario`
  **ML-KEM-1024** sobre AES-256-GCM, que son los dos algoritmos que CNSA 2.0
  exige para esas funciones.

  **Van PUROS, no híbridos, y eso es MÁS DÉBIL que `quipu`** — que firma
  Ed25519 *y* ML-DSA-87 y encapsula X25519 *y* ML-KEM-1024. Aquí, si el
  algoritmo de retículos cae, no queda socio clásico sujetando. Es lo que dice
  el mandato, que no pide híbrido, y está escrito en negrita en la cabecera de
  cada módulo y en el README: **si puedes elegir, usa `quipu`**. La asimetría que
  más pesa: una firma rota se explota el día que se rompe, pero un secreto
  cifrado hoy se guarda y se descifra mañana.

  Se depende de `ml-dsa` y `ml-kem` **directamente** y no vía `quipu`: este
  perfil es hermano de aquel, no cliente suyo, y arrastrarlo traería XChaCha20 y
  todo lo demás. La derivación usa HKDF-**SHA-384** (no SHA-256) y ata la clave
  pública completa al transcript, estilo X-Wing, para que sustituir la clave en
  tránsito no lleve a la misma clave de contenido.

- **Contenedor con negación (feature `negacion`, no-default).** Un archivo con dos
  contraseñas: una abre el señuelo que se entrega bajo coacción, otra el volumen
  verdadero. Ningún campo dice si el segundo existe, el tamaño total lo declara
  quien lo crea, y el resto se rellena con azar del CSPRNG exista o no el oculto.
  Implementa `docs/DISENO_NEGACION.md`, con la salida (a) del §5: **los parámetros
  del KDF NO viajan en el contenedor**, lo que además quita del mapa una entrada
  controlada por el adversario —hoy el camino normal toma el coste de Argon2id de
  la cabecera que aporta quien entrega el archivo—.

  El límite va en el README en negrita porque quien lo use puede depender de
  entenderlo: **protege contra la PRUEBA, no contra la SOSPECHA**, y quien guarde
  versiones sucesivas del mismo contenedor pierde la negación.

- **`lab::papel` — la medición que decide el portador de papel** (hoja de ruta §6),
  pendiente desde que se eliminaron los glifos. Hoja de área fija, la MISMA
  corrección de errores para los dos portadores, y emparejados por **rasgo
  mínimo**, que es la variable que domina el canal de la fotocopia.

  **Gana la matriz en todas las degradaciones.** A igual rasgo lleva entre 10× y
  23× más que el texto Base32, y engordar el módulo compra robustez más barato
  que pasarse a glifos: un glifo gasta 48·s² puntos para llevar 5 bits, un módulo
  s² para llevar 1. Una estampilla de 240×240 puntos con módulos de 6 entrega
  147 B a través de un fax sucio; una clave de Quipu son 32.

  Consecuencia: **la capa Base32 no se justifica por robustez**, solo por que un
  humano pueda teclearla sin escáner. Y dos avisos que la propia medición se ganó:
  la primera tabla comparaba un portador de trazo 1 contra uno de trazo 3 (medía
  el grosor, no el sustrato), y con el barrido cortado en módulo 4 la conclusión
  salía **invertida**.

- **`lab::distinguidor::posicion_mas_delatora`**, la sonda posicional. Nació de un
  caso rojo que falló: `entrenar_y_evaluar` **no vio un mágico `QUIP` de 4 bytes**
  estampado a mano en un contenedor de 1024 (53 % de acierto), porque sus doce
  rasgos son agregados de todo el blob y un campo corto queda diluido. La pregunta
  del frente de la sospecha es posicional —«¿hay algún byte que siempre valga lo
  mismo?»— y ahora hay con qué contestarla, con el umbral derivado de la cola de
  Poisson y corregido por mirar `largo × 256` casillas a la vez.

### Fixed
- **`quipu` sube a 0.11.0: catorce archivos llevaban meses bajo un número ya
  publicado.** Lo encontró el guardián de deriva nada más existir —`git diff
  v0.10.0 HEAD -- src Cargo.toml` da 14 archivos— y es la instancia más grande
  del fallo que se repitió cuatro veces en un día: `aleatorio`, `antihacker`,
  `api`, `kdf`, `negacion`, `lab/papel` y el resto del trabajo de la rama no
  habrían llegado nunca a crates.io, porque una versión no se re-sube.

  **0.11.0 y no 0.10.1, y el motivo no es el tamaño.** La superficie pública
  contra `v0.10.0` es estrictamente aditiva: ni un ítem retirado, ni una firma
  cambiada. Por esa vara sola tocaba parche. Lo que lo mueve es un cambio de
  COMPORTAMIENTO que el compilador no ve: `Options.codebook_id` pasó a
  ignorarse, y era público y ajustable desde la 0.10.0. Quien lo estuviera
  poniendo sigue compilando y obtiene otra cosa.

  Con consecuencia medible, no teórica: `guaca` y `tunjo` piden
  `quipu = "0.10"`. Con 0.10.1 se habrían llevado ese cambio solos en el
  siguiente `cargo update`; con 0.11.0 no se mueven hasta que alguien edite el
  requisito. Un cambio de comportamiento se hereda decidiéndolo.

- **`quipu-nucleo` sube a 0.1.2, y el requisito que lo nombraba MENTÍA.** El
  árbol se había quedado en 0.1.0 mientras `estable` y crates.io iban por 0.1.1
  — una regresión que ningún check veía, porque «coherencia de versiones»
  compara dentro de una rama y la promoción solo miraba el paquete raíz contra
  PyPI. Es el fallo que vive ENTRE dos árboles: cada uno coherente, la relación
  no.

  **0.1.2 y no 0.2.0**: comparada la superficie pública ítem a ítem contra la
  0.1.1, la diferencia entera es `ecc::PARIDAD_MAXIMA` y el módulo `papel`. Cero
  removals, cero cambios de firma. En 0.x el minor hace de major para cargo, así
  que 0.2.0 declararía una ruptura que no ocurrió.

  Lo que apareció al arreglarlo era peor que la regresión: `Cargo.toml` pedía
  `quipu-nucleo = { version = "0.1.0" }` mientras `src/lab/papel.rs` usa
  `ecc::PARIDAD_MAXIMA`, **que no existe en ninguna de las dos versiones
  publicadas**. Desde el árbol no se nota jamás, porque el `path` gana y siempre
  resuelve a lo local; desde crates.io, `quipu --features lab` no compilaba. Un
  requisito laxo no es tolerante: es una afirmación falsa sobre lo que hace
  falta. `quipu-cnsa` se deja en `0.1.0` a propósito — no usa nada de lo nuevo, y
  subirlo «por coherencia» sería el mismo error del otro lado.

  Y la extracción de Padmé no cambió el formato, que era lo único que había que
  demostrar: `crates/padme-frame/tests/paridad_con_la_implementacion_original.rs`
  compara contra una copia literal del código de la 0.1.1 sobre 200 000
  longitudes y 4 000 bloques, byte a byte. Existe porque la prueba del envoltorio
  solo hace ida y vuelta **consigo misma**, y eso saldría verde igual si el
  algoritmo hubiera cambiado.

- **La cadena de publicación tenía un eslabón sin maquinaria.** `quipu-nucleo`
  depende de `padme-frame` por `path` + `version` y `padme-frame` no está en
  crates.io, así que `cargo publish -p quipu-nucleo` habría fallado el día del
  release — el mismo fallo de `quipu-voprf`, que estuvo roto desde `a1c9056` sin
  que nadie lo notara. `release.yml` ni siquiera reconocía un tag suyo. Añadidos
  el disparador `padme-v*` y el job `crate-padme`; el orden completo es
  `padme-frame → quipu-nucleo → quipu-voprf → quipu`.

  Y `quipu-cnsa` estaba en el mismo hueco sin que nadie lo hubiera notado: no
  lleva `publish = false` —o sea que ES publicable, con 62 pruebas en verde y
  los dos perfiles terminados— y no tenía ni tag ni job. Un crate acabado sin
  ninguna forma de salir. Lo delató el guardián de deriva al NEGARSE a aprobarlo
  por no tener prefijo declarado, en vez de callarse: añadidos `cnsa-v*` y
  `crate-cnsa`.

  De paso, el gate de `wheels` y `sdist` pasa a ser **positivo**. Era una lista
  de negaciones (`!voprf-v && !django-v`), y una lista de negaciones falla por lo
  que no enumera: un tag `nucleo-v*` construía las tres ruedas —ubuntu, macOS y
  Windows— y el `sdist` para después no publicarlos, porque el job `pypi` sí
  exigía `refs/tags/v`. Añadir `!padme-v` habría arreglado el caso dejando la
  regla igual de rota para el siguiente crate.

- **`limpiar_pila` no limpiaba nada en `--release`, y nadie lo había visto porque
  la prueba que lo mide no corría ahí** (#265, T6). El medidor de residuo estaba
  gateado con `feature = "escrow"`, y la pasada de release del CI
  (`cargo test --features slh --release`) no activa ese feature: el archivo
  entero se saltaba. Al quitar el gate y correrlo, en release quedaban **1 copia
  del canario tras limpiar la pila**, **3 de la clave maestra** y **3 de la clave
  de contenido**; en debug, cero. La defensa funcionaba justo en la mitad que no
  se publica.

  Tres causas, y las tres son la misma forma de error —el marco muerto que nadie
  puede borrar desde dentro—:

  1. `limpiar_pila` **se incrustaba**. Sin marco propio, su lienzo pasa a ser una
     variable más del marco del llamante y puede quedar por encima de la región
     que había que pisar. Lleva `#[inline(never)]`, que es lo que garantiza que
     el lienzo caiga DONDE estuvieron los marcos muertos.
  2. `pqhybrid::combine` devolvía la clave de contenido por valor con el mismo
     defecto que el KDF (`[u8; 32]` es `Copy`). Ahora borra su buffer y limpia la
     pila de HKDF, y lo heredan encapsulación y decapsulación.
  3. `decode_as_recipient` borraba con `wipe` la copia que tiene NOMBRE, pero la
     clave le llegaba devuelta por valor desde `decapsulate` y ese viaje deja
     copias en el marco —ya muerto— de quien la produjo. La regla que sale de
     aquí, y que vale para toda la librería: **quien recibe un secreto por valor
     limpia la pila del que se lo dio**.

  El archivo ya no lleva gate de feature: cada escenario pide el suyo, así que
  las mediciones corren en la pasada por defecto, en la de `honey`, en la de
  `escrow` **y en la de release**.

- **La medición de residuo de la clave maestra buscaba una clave que el proceso
  nunca había derivado, y al arreglarla aparecieron copias de verdad** (#265, T6).
  El arnés derivaba la clave con un salt fijo suyo mientras `encode` lo saca del
  RNG en cada llamada, así que la aguja no existía en el hijo más que en el
  escenario de fuga —donde se derivaba igual de mal—. El control pasaba, la
  medición no medía nada, y el verde era indistinguible del verde real.

  Con el salt REAL —el padre parsea la cabecera y comprueba que la clave derivada
  abre el contenedor— quedaban **2 copias de la clave maestra** en la pila del
  hilo después de `decode`. Dos causas, las dos arregladas en `kdf.rs`:

  1. `[u8; 32]` es `Copy`: devolver la clave no vacía el marco del KDF, lo COPIA.
     Ahora el buffer de salida se borra tras copiarlo al valor de retorno.
  2. Argon2id deja el resto en marcos que no son nuestros, **a 99 KiB de
     profundidad**, y `limpiar_pila` llegaba a 64 KiB. El limpiador pasa a 128 KiB
     —medido, no elegido: con 64 quedaba 1 copia, con 128 quedan 0— y se llama
     desde `derive_master_key`, donde nace el secreto, para que lo hereden
     `encode`, `decode`, el streaming y honey sin tener que acordarse cada uno.
     La profundidad NO escala con `mem_kib` (se midió con 64 y con 4096): los
     bloques de Argon2 viven en el montón; lo hondo son los marcos.

- **El streaming soltaba el texto en claro sin borrarlo, en las dos direcciones**
  (#265, T6). Al descifrar, cada trozo salía de `cipher::decrypt` en un `Vec` que
  se escribía al destino y se soltaba tal cual: **1 copia del claro en el montón**
  tras `decrypt_stream_bytes`, con el llamante habiendo borrado la suya. Al
  cifrar, los dos buffers de lectura por trozo se soltaban igual. Ahora son
  `Zeroizing`, que además cubre los retornos por error de en medio, donde un
  borrado al final no llegaría.

### Added
- **El medidor de residuo (T6) cubre CINCO caminos, con doce mediciones y sus doce
  controles** (#265). Antes cubría tres, y la taxonomía lo decía; ahora se añaden
  `decode_as_recipient` —la clave secreta del destinatario, la clave de contenido
  que sale de la decapsulación y el texto en claro—, el **texto en claro** que
  devuelve `decode`, el streaming `QST1` **al descifrar y al cifrar**, y `honey`.

  Cada camino trae su propia fuga deliberada: el control de un escenario no valida
  otro, y de eso ya hay tres precedentes en este mismo archivo. Dos piezas nuevas
  del arnés hacen que las agujas sean las de verdad y no una reconstrucción:

  - el **padre** monta los sobres y le pasa al hijo el material sensible en
    hexadecimal —que no es la aguja—, porque quien mide tiene que conocer el
    secreto y plantárselo al hijo lo convertiría en residuo propio;
  - las claves que exigen abrir una cabecera a mano (la de contenido del híbrido,
    la maestra del camino de contraseña) se **validan descifrando** el contenedor
    con ellas: si el formato cambia, la prueba rompe en voz alta en vez de medir
    humo.

  Lo que sigue sin medirse va escrito en `docs/ATAQUES_TAXONOMIA.md` y en
  `docs/THREAT_MODEL.md`: la clave que derivan el streaming y honey, cuyas
  cabeceras son privadas. Heredan el arreglo del KDF, pero heredar no es medir.

- **Dos objetivos de fuzz llevaban desde el 2026-07-27 en verde sin tocar el parser
  que decían fuzzear.** Se descubrió al ir a encadenar el corpus (#131.1): antes de
  encadenar nada se midió lo que había, y lo que había era nada.

  `parse_signed` **no ejecutaba ni una línea de su cuerpo**. Fijaba la clave con
  `VerifyingKey::from_bytes(&[0x42; 2624])` dentro de un `if let Some(vk)`, y esa
  clave no parsea —sus 32 primeros bytes son un punto Ed25519 comprimido y `0x42`
  repetido no lo es—, así que la condición era falsa en cada iteración y el `if let`
  se saltaba todo en silencio. `parse_recipient` sí corría, pero moría en
  `dict.decode`, que exige que cada carácter esté entre los 4096 glifos CJK del
  alfabeto insignia. Y aunque hubieran pasado, no cabían: el parser firmado exige
  4701 bytes y el `-max_len` por defecto de libFuzzer es 4096.

  Medido antes y después, 45 s desde corpus vacío contra desde semillas:

  | | antes | ahora |
  |---|---|---|
  | `cov` de `parse_signed` | 207 | 1 693 |
  | features | 225 | 3 246 |
  | corpus final | 10 unidades / 10 B | 87 unidades / 178 KB |

  Arreglado en cuatro piezas: la clave se deriva de una semilla de 64 bytes (válida
  por construcción, porque son semillas y no puntos) y el guardia silencioso pasa a
  ser `panic!`; cada objetivo traduce su entrada al alfabeto por el mismo camino que
  usa al construir, y además la pasa cruda si es UTF-8; `examples/gen_semillas_fuzz.rs`
  siembra artefactos reales con sus mutaciones de frontera —lo que de paso sube solo
  el `-max_len`—; y el CI **genera** ese corpus antes de fuzzear, porque
  `fuzz/corpus` está en `.gitignore` y en una copia limpia no hay ni una unidad.

  Lo sostiene una prueba y no un comentario:
  `tests/taxonomia.rs::el_fuzz_de_los_contenedores_alcanza_el_parser_y_no_muere_en_el_alfabeto`,
  que fue la que encontró lo de la clave. El comentario del objetivo afirmaba lo
  contrario.

### Added
- **«La zeroización es *best-effort*» ya tiene número: CERO (#131.2).** Era la
  única frase del modelo de amenaza que reconocía un residuo sin medirlo, y de ahí
  salía la petición de `mlock`. `mlock` se descartó —protege del swap y de nada
  más, al precio de meter `libc`—, pero descartarlo dejaba la pregunta de verdad
  sin responder: **¿sobrevive algo?**

  Primero hubo que corregir el encuadre. T6 es «atacante con acceso a la memoria
  **DESPUÉS** de la operación» (volcado, swap, hibernación, cold boot); el
  atacante presente MIENTRAS corre es R5, endpoint comprometido, y ya estaba fuera
  de alcance por declaración. Mezclarlos es lo que hacía parecer que la brecha no
  se podía cerrar: contra quien manda en el kernel en vivo, no; contra quien lee
  la memoria después, sí.

  `tests/residuo_memoria.rs` lo mide: un proceso HIJO hace la operación real y se
  queda quieto, y el PADRE lee `/proc/<hijo>/mem` y cuenta apariciones de un
  canario. Solo `std` — en Linux la memoria de un proceso es un fichero, así que
  no hace falta `libc` ni ptrace explícito. Dos decisiones que no son de estilo
  sino de que el número signifique algo:

  - **Dos procesos, no uno.** Un escáner que lee su propio montón copia dentro de
    su buffer los bytes que busca; medido al intentarlo, la misma situación daba
    0, 17 o 33 según el orden del barrido.
  - **Se busca un tramo INTERIOR del canario.** Al liberar un trozo el asignador
    escribe sus punteros sobre los primeros 16 bytes, y exigir coincidencia
    completa informaba «no hay residuo» con 240 de 256 bytes del secreto intactos
    en memoria liberada.

  **Resultado, en debug y en release: cero residuo** en los tres caminos — la
  semilla de firma reconstruida por Shamir, la clave maestra derivada y la
  contraseña misma. Cada medida lleva su **control**, que deja una copia viva a
  propósito y exige que el escáner la vea; sin eso un cero sería indistinguible de
  un escáner que mira donde no es.

  **Y el aviso vale más que el cero: este medidor dio cero FALSO tres veces**, por
  causas distintas y todas invisibles — se contaba a sí mismo; exigía coincidencia
  completa del secreto y la metadata del asignador la rompía; y leía cada región de
  un tirón, de modo que una página sin mapear descartaba la pila del hilo entera,
  que era justo donde estaba el secreto. Esa tercera explicaba una diferencia
  local/CI que se había atribuido al entorno: era no haber mirado. Encima, la
  primera medida buena contaba el rastro del propio banco de pruebas, que
  construía la clave para montar el escenario. Un medidor de ausencia no puede
  avisar de que está ciego: solo lo dice el caso que lo pone rojo.

  Se declara T6 cerrado **en esos tres caminos y no en la librería entera**. Faltan
  `decode_as_recipient`, el texto en claro que devuelve `decode`, `stream` y
  `honey`, cada uno con su propio control.
- **Build reproducible de la rueda de Python (invariante I5, #124).** Medido antes
  de tocar nada, y estaba mucho más cerca de lo que la ficha suponía: el compilador
  nunca fue el problema. El `.crate` ya se reconstruía byte a byte —cargo normaliza
  las mtime a una época fija y uid/gid a 0/0— y el `quipu.abi3.so` también. Lo
  **único** no determinista de la rueda eran dos campos del SBOM CycloneDX que
  escribe maturin: un `serialNumber` con UUID aleatorio y un `timestamp` de reloj.
  El `RECORD` cambiaba solo porque los hashea.

  Con `SOURCE_DATE_EPOCH` tomado de la fecha del **commit** —no de `now`, para que
  el artefacto se derive del código y no del momento de construirlo— la rueda sale
  idéntica entre corridas. Y con `--remap-path-prefix` desaparecen las rutas
  absolutas que el binario llevaba dentro (72 cadenas `/home/<usuario>/.cargo/…`
  de los metadatos de `panic`), que es lo que lo rompería en otra máquina.
  `[profile.release] trim-paths` haría lo mismo más limpio pero **no está
  estabilizado** en cargo 1.97.1 — comprobado, no supuesto.

  No se afirma, se comprueba: el CI reconstruye la rueda y exige el mismo sha256, y
  verifica aparte que el binario no lleve rutas de quien lo construyó. Los dos
  checks se probaron contra una rueda hecha a propósito sin el remap, y ahí se
  ponen rojos. Las mismas variables van en `release.yml`, porque si solo estuvieran
  en el CI se estaría comprobando una propiedad que el artefacto publicado no
  tiene.

  Receta para terceros en `docs/REPRODUCIBILIDAD.md`, con el límite escrito al
  lado: **falta** rehacer la rueda **manylinux publicada** en su propio contenedor
  —el CI construye en `ubuntu-latest` y el release en el de `maturin-action`—, así
  que hoy se caza el no-determinismo de origen pero no se demuestra lo del artefacto
  que se descarga.
- **`examples/coste_adivinacion.rs`** — el coste por intento con su procedencia, y la
  cota de GPU. La taxonomía publicaba «6 intentos/s» sin decir con qué parámetros ni
  en qué máquina, y una cifra de coste sin sus parámetros no dice nada: el
  `KdfParams::default()` entrega 64 MiB y 3 iteraciones, y el banco `guessing.rs`
  deriva con 16 MiB y 2. Medido, el `default()` da **5,69 intentos/s** y el banco
  **42,16** en la misma máquina. El «6» que se publicaba era correcto y describía el
  `default()`; lo que le faltaba era decirlo. La cota de GPU (2 503–8 320 intentos/s
  según acelerador) va declarada **estimación y no medición**: se deriva del ancho de
  banda de memoria, aquí no hay GPU.
- **`fuzz/README.md`** — la tabla de familias de idioma de entrada, que es lo que
  decide qué corpus se comparte con cuál. Encadenar «entre objetivos» solo sirve
  dentro de un mismo idioma; `honey_decrypt` y `codec_roundtrip` quedan fuera porque
  su primer byte significa otra cosa. Con el dato honesto de que el encadenado no
  sube hoy la cobertura de `parse_container` ni `unpad` —están saturados—: se deja
  montado porque no cuesta nada y paga cuando un parser de la familia crezca.
- **`docs/DISENO_NEGACION.md`** — diseño cerrado del contenedor con negación (#99 y
  #118), **sin implementar**, que es lo que autorizaba la luz verde. Modelo de
  amenaza explícito, los dos frentes (la prueba y la sospecha), la medida de que 28
  de los 68 bytes de cabecera gritan «Quipu», la circularidad del KDF que fuerza la
  decisión de formato, primitivas sin inventar nada, y las tres sondas del banco
  I1/I4 con las que se comprueba en vez de argumentarse.

### Fixed
- **`encode_base_n` era cuadrático por una razón evitable, y eso costaba el 98 % de
  `encode_signed`.** El codec convertía el mensaje entero como UN número grande y le
  sacaba los dígitos **de uno en uno**: una división del entero completo por dígito.
  Cada división cuesta O(m) en limbos y hay O(m) dígitos, así que el coste crecía con
  el cuadrado del tamaño — medido a 3,40 ns/n² constante a lo largo de un rango de 16×
  (512 B → 8 KiB).

  Lo que lo hizo visible: firmar un evento de bitácora de **61 bytes** tardaba 78 ms en
  release, de los cuales solo **1,6 ms eran criptografía** (ML-DSA-87 + Ed25519). Los
  otros 76,4 ms eran la conversión a base 94. Se descubrió persiguiendo por qué una
  prueba de concurrencia de un consumidor se caía bajo carga; la firma nunca fue el
  problema.

  Arreglado dividiendo por `n^k` —el mayor `n^k` que cabe en un `u64`, 9 para la base 94
  por defecto— y desmenuzando el resto con aritmética de máquina: **9 dígitos por
  división grande en vez de uno**, y con `Integer::div_rem` se paga una división donde
  antes eran dos (`%` y `/` por separado). Sigue siendo cuadrático, con una constante
  17,8 veces menor.

  **La salida es byte a byte la misma.** No hay cambio de formato y las firmas ya
  emitidas siguen verificando; lo garantizan una prueba de propiedad contra la
  implementación ingenua —conservada como oráculo— y vectores fijos tomados antes del
  cambio. La prueba se comprobó inyectando la mutación que este rediseño podría
  introducir (comerse los ceros de relleno de un bloque interior): la cazan cuatro
  pruebas.

  | | antes | ahora |
  |---|---|---|
  | `encode_base_n` | 3,40 ns/n² | 0,19 ns/n² |
  | `encode_signed` (61 B → 5 813 glifos) | 78,0 ms | 5,6 ms |

  `decode_base_n` también es cuadrático, pero su constante ya era 55 veces menor
  (multiplicar por un dígito pequeño es mucho más barato que dividir), así que **no se
  ha tocado**: no era el problema medido.

- **Una base menor que 2 colgaba el proceso en silencio.** `encode_base_n(_, 1)` entraba
  en un bucle infinito —`value % 1 == 0` y `value / 1 == value`— en vez de decir que una
  base de 1 no representa nada. Ahora falla de forma ruidosa (directiva 20).

### Planned
- Independent security audit and public remediation of findings.
- Reference deployment of the online VOPRF hardening server.

## [quipu-nucleo 0.1.1] — 2026-07-31

Release **solo del crate `quipu-nucleo`**; `quipu` sigue en 0.10.0 y no se
republica. No hace falta: `quipu 0.10.0` ya declara `quipu-nucleo = "^0.1.0"`
—verificado contra el índice sparse de crates.io—, así que todo el que dependa
de `quipu` recoge esta versión en su siguiente `cargo update`. Y como la salida
es byte a byte la misma, actualizar no puede invalidar nada de lo ya firmado.

### Fixed
- **`encode_base_n` era cuadrático por una razón evitable, y eso costaba el 98 % de
  `encode_signed`.** El codec convertía el mensaje entero como UN número grande y le
  sacaba los dígitos **de uno en uno**: una división del entero completo por dígito.
  Cada división cuesta O(m) en limbos y hay O(m) dígitos, así que el coste crecía con
  el cuadrado del tamaño — medido a 3,40 ns/n² constante a lo largo de un rango de 16×
  (512 B → 8 KiB).

  Lo que lo hizo visible: firmar un evento de bitácora de **61 bytes** tardaba 78 ms en
  release, de los cuales solo **1,6 ms eran criptografía** (ML-DSA-87 + Ed25519). Los
  otros 76,4 ms eran la conversión a base 94. Se descubrió persiguiendo por qué una
  prueba de concurrencia de un consumidor se caía bajo carga; la firma nunca fue el
  problema.

  Arreglado dividiendo por `n^k` —el mayor `n^k` que cabe en un `u64`, 9 para la base 94
  por defecto— y desmenuzando el resto con aritmética de máquina: **9 dígitos por
  división grande en vez de uno**, y con `Integer::div_rem` se paga una división donde
  antes eran dos (`%` y `/` por separado). Sigue siendo cuadrático, con una constante
  17,8 veces menor.

  **La salida es byte a byte la misma.** No hay cambio de formato y las firmas ya
  emitidas siguen verificando; lo garantizan una prueba de propiedad contra la
  implementación ingenua —conservada como oráculo— y vectores fijos tomados antes del
  cambio. La prueba se comprobó inyectando la mutación que este rediseño podría
  introducir (comerse los ceros de relleno de un bloque interior): la cazan cuatro
  pruebas.

  | | antes | ahora |
  |---|---|---|
  | `encode_base_n` | 3,40 ns/n² | 0,19 ns/n² |
  | `encode_signed` (61 B → 5 813 símbolos) | 78,0 ms | 5,6 ms |

  `decode_base_n` también es cuadrático, pero su constante ya era 55 veces menor
  (multiplicar por un dígito pequeño es mucho más barato que dividir), así que **no se
  ha tocado**: no era el problema medido.

- **Una base menor que 2 colgaba el proceso en silencio.** `encode_base_n(_, 1)` entraba
  en un bucle infinito —`value % 1 == 0` y `value / 1 == value`— en vez de decir que una
  base de 1 no representa nada. Ahora falla de forma ruidosa (directiva 20).

## [0.10.0] — 2026-07-28

### Fixed
- **`quipu-cnsa` anunciaba ML-KEM-1024 sin implementarlo.** El titular del README y —peor— el
  campo `description` del `Cargo.toml`, que es el texto que se publica en crates.io, decían
  «AES-256-GCM, HKDF-SHA-384 y ML-KEM-1024». Los tres primeros están; el cuarto no aparecía en
  ninguna parte del crate salvo en su propia documentación interna, que lo listaba entre **lo que
  falta**. La portada afirmaba lo que las tripas negaban.

  No es un fallo de seguridad y nada estaba roto: es una promesa de alcance que el código no
  respaldaba. Importa porque este crate se sostiene sobre que su alcance sea comprobable — su
  primer titular es «alineación no es cumplimiento» —, y una promesa de más resta credibilidad
  justo a la afirmación que sí es cierta y valiosa: que implementa los algoritmos pero **no está
  validado FIPS 140-3**.

  Corregido diciéndolo, no borrándolo: el README explica el alcance real —**solo cifrado
  simétrico**, sin firma ni establecimiento de clave— y deja constancia de qué se anunciaba antes.

- `quipu-cnsa` mencionaba el canal de glifos en su tabla de módulos compartidos. Residuo del
  PR #93, que lo eliminó.

### Removed
- **BREAKING — `integrations/go` también se va.** Se me pasó en el recorte anterior,
  y salió al preguntarme si el repositorio era realmente todo Rust: quedaban 585
  líneas de Go en 3 archivos versionados.

  No era un binding sino una integración —el hermano en Go de
  `integrations/django`—, y por eso no cayó con `bindings/go`. Se va por tres
  razones que se acumulan:

  1. **Estaba roto desde el commit anterior.** Su `go.mod` traía
     `replace … => ../../bindings/go`, y ese directorio ya no existe.
  2. **Nunca lo vigiló nadie.** Ningún workflow del CI lo compilaba ni lo
     probaba, así que llevaba tiempo pudiéndose romper en silencio.
  3. **Nunca se publicó, y por la misma razón que motivó todo esto.** Su propio
     `go.mod` lo dejaba escrito: *«depende de bindings/go, que enlaza el C ABI
     con las 12 funciones del núcleo AGPL. Mientras siga así, este SDK
     arrastraría copyleft de red al SaaS del cliente y NO se publica.»*

  El equivalente resuelto es `integrations/django`, que usa `quipu-voprf`
  (Apache-2.0) y sí se publica. Si algún día hace falta el de Go, se construye
  sobre ese mismo SDK, no sobre el núcleo AGPL.

- **BREAKING — un solo binding: Python. Se van Node, Go, la C ABI y la integración
  de Express.** `bindings/c` (`quipu-capi`), `bindings/node` (`quipu-crypto` en npm),
  `bindings/go` e `integrations/express` ya no existen, ni sus jobs de CI, ni el
  workflow `npm-publish.yml`.

  **Por qué.** Nadie los usaba. Medido contra los índices el 2026-07-27: npm
  acumulaba 486 descargas en cuatro meses y crates.io 307 en toda su historia —
  cifras que a esa escala son espejos y rastreadores, no usuarios. La C ABI
  llevaba `publish = false`, así que jamás salió del repositorio: sus únicos
  consumidores eran los envoltorios de Node y Go, que se van con ella.

  Lo que sí generaban era coste, y del que no se ve: la matriz de paridad entre
  cinco superficies estaba mal en cuatro celdas; la lista de «doce archivos de
  versión» estaba mal en tres formas; y los **93 `unsafe`** del ABI de C eran el
  único lugar del repositorio donde podía vivir un fallo de memoria.

  **Qué se gana, en números.** Sitios de versión: 13 → **4**. `unsafe` de primera
  parte: 93 → **0**. Registros de paquetes: 4 → **2**. Jobs de CI: 14 → 11.
  Y desaparece el problema de paridad entero, porque un binding no puede
  divergir de sí mismo.

  **Qué NO cambia.** Quipu sigue siendo Rust, entero. La rueda de PyPI se
  construye del mismo código con maturin y PyO3 — una sola rueda `abi3` que vale
  de Python 3.9 en adelante. `crates.io` se mantiene: es el canal de reputación,
  donde `docs.rs` genera la API y donde `cargo-vet`/`cargo-audit` operan, y
  además Tunjo depende de `quipu` desde ahí.

  **Migración.** Quien usara `quipu-crypto` desde npm o el módulo de Go: las
  versiones publicadas siguen instalables, pero no habrá más. La ruta soportada
  es `pip install quipu-crypto`. Para el VOPRF desde otro lenguaje, el SDK es
  `quipu-voprf` (Apache-2.0), que además nunca debió viajar dentro de un paquete
  AGPL — ese era un defecto de reparto de licencias que se corrige al retirarlo.

  **Vuelve cuando haga falta.** Todo está en el historial. Si aparece el cliente
  OEM de la hoja de ruta, el ABI de C que necesite tendrá la forma que ese
  cliente pida, no la que adivinamos hoy.

  **No es un fallo de seguridad y no cierra ninguna vulnerabilidad.**

- **BREAKING — the PNG channel is gone too, and with it the `image` dependency.**
  `api::encode_to_image`, `api::decode_from_image`, `api::encode_to_robust_image` and
  `api::decode_from_robust_image` no longer exist, nor does the `render` module (removed from
  `quipu`, `quipu-cnsa` and `quipu-nucleo`).

  **Why.** Two reasons, neither of them "it was dead code" — it ran, and it had its own tests.

  First, **custody**. A greyscale PNG of raw bytes can only be decoded by Quipu, which is exactly
  the property this project rejected when it chose a standard 2D symbology (Data Matrix, QR) as
  the paper carrier: what decides at twenty years is that the decoder still exists in 2050. The
  PNG channel was the same bet as the glyphs, made in a simpler way — and just as unproven for
  the print-and-photograph path it claimed to serve. `encode_to_robust_image` layered
  Reed-Solomon over a **lossless** container: error correction against a corruption the container
  does not have, unless it is printed, which was never measured.

  Second, **audit surface**. It was the only user of the `image` crate, which pulled 12
  transitive crates: `image`, `png`, `flate2`, `miniz_oxide`, `bytemuck`, `moxcms`, `pxfm`,
  `crc32fast`, `fdeflate`, `simd-adler32`, `adler2`, `byteorder-lite`. The lock file drops from
  156 packages to 144. In a project whose argument is auditability — and which turned down
  `rxing` for precisely this reason — carrying an image decoder for an unused channel was
  incoherent. PNG parsing over attacker-controlled input was listed in `docs/PRE_AUDIT.md` as an
  area needing more fuzzing; now there is nothing to fuzz.

  **Kept: `ecc` (Reed-Solomon).** It stays public and unchanged. The planned paper carrier needs
  it for the fallback layer (Base32 with Reed-Solomon in groups), so removing it would be
  deleting what the plan asks for.

  **Migration.** `encode`/`decode` with any `dictionaries::*` alphabet produces the same
  ciphertext as dense text; `encrypt_stream` produces bytes. Neither changed. For an image, wrap
  the output yourself, or wait for the standard-symbology carrier.

  **This is not a security fix and closes no vulnerability.** Like the glyph removal, it drops a
  representation layer that never carried one.

- **BREAKING — the native glyph channel is gone in its entirety.** `api::encode_to_glyph_image`,
  `api::decode_from_glyph_image` and `api::huella_del_portador` no longer exist, nor do the
  `glyphfont`, `glyphopt` and `glyphscan` modules, the `glyph_min_distance` / `select_separable`
  Python bindings, and the grouped codec that only fed them.

  **Why.** `docs/THREAT_MODEL.md` already stated that the visual channel is *"purely
  representation: adds/subtracts no security"*, and no invariant (I1–I7) depended on it. What it
  did add was attack surface: PNG decoding, adaptive binarisation, grid detection and ECC, all
  over attacker-controlled input, all of it to be fuzzed and audited. Removing it makes the
  library smaller and the audit narrower without weakening any guarantee.

  **This is not a security fix and closes no vulnerability.** It removes a representation layer
  that never carried one.

  **Migration.** The dense-text channel is unchanged and covers the same use cases:
  `encode`/`decode` with any `dictionaries::*` alphabet. *(The PNG channel was offered here as a
  migration route and has since been removed as well — see the entry above. Use `encode`/`decode`
  or `encrypt_stream`.)* For a paper carrier, a standard 2D symbology (Data Matrix, QR) is the
  recommended route: the decoder will still exist in twenty years, which a proprietary alphabet
  cannot promise.

  Unaffected: `dictionaries::flagship()` and the other dictionaries. Those are Unicode glyphs in
  the **text** channel, a different thing that merely shares the word.

### Added
- **`crates/quipu-nucleo`** — the primitive-agnostic core: container format,
  base-N codec, Reed-Solomon, Padmé padding and the visual glyph channel.
  Contains **no cryptography at all**. Extracted so that `quipu` and its sibling
  profile share one implementation of everything that isn't crypto: a bug there
  is fixed once, not twice.
- **`crates/quipu-cnsa`** — a sibling profile aligned with the **CNSA 2.0**
  algorithms: AES-256-GCM, HKDF-SHA-384, SHA-384 codebook fingerprint, 96-bit
  nonce, 56-byte header. Built *on top of* `quipu-nucleo`, not copied from
  `quipu`. **It is NOT FIPS 140-3 validated**, and its README says so on the
  first screen. Alpha: it encrypts and decrypts, nothing else.
- **`herramientas/verificar.py`** — verifies the working tree *and the published
  artifacts*: downloads the `.crate` from crates.io and compiles it feature by
  feature, installs the wheel in a clean venv and checks the promised symbols
  exist. Three outcomes, not two — pass, fail, and **NOT CHECKED**, with its own
  exit code, because filing "I couldn't look" under "it passed" is the defect it
  exists to prevent. Ships with a 37-check bench, proven against 4 mutations.
- **CI: `matriz de features`** — compiles every declared feature and then
  `--all-features`. The feature list is **derived from `Cargo.toml`**, not
  written into the YAML: a duplicated list is a list that diverges.
- **CI: doctests.** `--all-targets` excludes them despite the name, so they had
  never run in this project's history.
- **Sondas de invariantes** (`tests/invariantes.rs`, `tests/taxonomia.rs`): las
  que la taxonomía de ataques pedía y no existían. Fallo inyectado en **las dos
  mitades** de la firma híbrida por separado (un fallo en una no autoriza nada);
  uniformidad de errores (mismo tipo y mensaje ante cualquier fallo de
  autenticación); el material sensible no viaja dentro de un error; detector de
  reúso de nonce y batería estadística del RNG (monobit + rachas, 5σ); sondas de
  downgrade y confusión de versión.
- **dudect ampliado** (`src/lab/timing.rs`): sobre la verificación de firma, la
  derivación de subclaves, y el **tiempo del rechazo por causa** — que el reloj
  no delate si se acertó la contraseña aunque el error no lo diga.
- **Banco de indistinguibilidad** (`src/lab/indistinguibilidad.rs`): un
  vocabulario de veredicto ÚNICO para I1 e I4 sobre tres señales —tiempo,
  ciphertext y error—. dudect (t de Welch) y el distinguidor entrenado (σ) se
  convierten a él sin reescribir ninguno; un conductor los junta en un informe
  comparable. Cada señal trae su fuga sembrada como control de que discrimina.
- **KAT contra norma EXTERNA** (`tests/vectores_de_norma.rs`): las primitivas
  atadas a vectores de un estándar, no a los que genera Quipu. HKDF-SHA256
  (Wycheproof/RFC 5869), Ed25519 (Wycheproof/RFC 8032), **Argon2id (RFC 9106)** y
  **ML-KEM-1024 y ML-DSA-87 keyGen (NIST ACVP)**, con los vectores ACVP
  vendorizados en `tests/vectors/`. Cierra la familia 1 de la taxonomía: caza una
  subida regresiva de una dependencia —como la que RustSec persiguió en `ml-dsa`—
  antes de una release.
- **`antihacker::nonces_repetidos`** — detector de reúso de nonce como API
  PÚBLICA, para que un integrador lo corra sobre su propio almacén. Devuelve los
  pares que colisionan (no un booleano) e ignora lo que no parsea como contenedor.
- **`custodia-seed`** (`quipu-oprf-server`, feature `custodia`) — respaldo Shamir
  k-de-n del *seed* del OPRF, verificado por que reconstruye la MISMA clave
  pública (un seed que restaura íntegro pero da otra clave es peor que perderlo).
- **`verificar.py desplegado`** — invariante I7: audita la superficie en
  PRODUCCIÓN (HSTS, `/admin` no 2xx, HEAD coincide con GET, TLS 1.0/1.1 rechazado)
  sin ser intrusivo. Y `verificar.py promover` comprueba la promoción entre ramas.

### Security
- **Reauditoría de amenazas recientes (2026-07-28), contrastada contra la pila
  PINEADA**: `ml-dsa 0.1.1` ya trae la corrección de **RUSTSEC-2025-0144**
  (canal lateral de división en tiempo variable, ML-DSA Decompose); `ml-kem 0.3.2`
  está por encima de KyberSlash/Clangover; y los parámetros Argon2id por defecto
  (64 MiB / t=3) superan el mínimo OWASP 2025. La defensa que valió fue la
  procedencia (versión pineada + `cargo-audit`), no una sonda nueva. Ninguno era
  explotable en Quipu; se documenta como constancia, no como parche.

### Fixed
- **`--features lab-offline` did not compile** — not just here: the published
  `quipu` 0.9.1 on crates.io doesn't compile with it either. `src/lab/timing.rs`
  destructured `pqhybrid::generate_keypair()` and `encapsulate()` as tuples;
  they return `Result<_, SinEntropia>` since the fallible-RNG work. The other 8
  feature paths were fine. It fails loudly at compile time and affects nobody
  encrypting data, so it did not warrant an emergency release.
- **The CI ran 137 of 235 tests.** `cargo test --all-targets` without
  `--workspace` only tests the root package. `quipu-voprf`'s RFC 9497 vectors —
  the evidence that the paid VOPRF service conforms to the standard — had never
  run in CI. Neither had the OPRF server's e2e suite nor the C ABI tests.
- **The wheel's feature list and version were each written in two places.**
  `release.yml` no longer repeats `--features` (maturin reads them from
  `pyproject.toml`), and both `pyproject.toml` files now take their version from
  `Cargo.toml` via `dynamic = ["version"]`. They had already diverged:
  `quipu-voprf` was 0.2.2 on crates.io and 0.2.1 on PyPI, so the next tag would
  have built a wheel PyPI rejects as a duplicate.

### Changed
- **`Dictionary::fingerprint()` now comes from the `HuellaDeCodebook` trait**
  and needs it in scope. The codebook itself is agnostic and moved to
  `quipu-nucleo`; hashing is a profile decision. The wire format is unchanged —
  `symmetric_container_is_byte_exact` still passes byte for byte.
- `container::Header` is now generic over the salt and nonce lengths. `quipu`
  pins `<16, 24>` behind a type alias, so nothing downstream changes.

## [0.9.1] — 2026-07-20

### Fixed
- **The PyPI wheel now ships the `hsm` feature.** The 0.9.0 wheel was built by
  the release workflow with `--features python,escrow` only, so `CustodioHsm` —
  the PKCS#11 custody advertised in the README — was missing from the published
  package, even though `pyproject.toml` requested it. The feature set was pinned
  in two places (`pyproject.toml` and `release.yml`) and only one was updated.
  Caught by installing 0.9.0 from PyPI in a clean environment and checking for
  the symbol, not by trusting the workflow's green status. No code changed
  between 0.9.0 and 0.9.1; the crate on crates.io and the Rust API are identical.
  0.9.0 is yanked from PyPI.

## [0.9.0] — 2026-07-20

### Added
- **Key custody in a PKCS#11 device (feature `hsm`).** The signing private key
  can live in an HSM, token or smartcard and **never leave it**: both halves of
  the hybrid signature (Ed25519 + ML-DSA-87) are generated and used *inside* the
  device. The `firmante::Custodio` trait separates *who holds the key* from *how
  the signature is assembled* — it asks for operations, never for the key
  material. A signature made in a device and one made in memory are byte-for-byte
  identical and verify with the same verifier. Exposed to Python as
  `quipu.CustodioHsm`, shipped in the wheel. Tested end-to-end against a real
  PKCS#11 token (128 concurrent signatures under a timeout).
- **Threshold signing (`firmante::firmar_con_comparticiones`, feature `escrow`).**
  Reconstructs a signing key from Shamir shares, signs, and drops it in a single
  Rust call, so the key never crosses the FFI boundary into a binding.

### Changed
- **BREAKING — the RNG boundary is fallible.** When the OS cannot provide
  randomness, Quipu no longer substitutes a weaker source and no longer panics:
  it reports an actionable error, with a bounded retry for the one transient
  cause. No key is ever born from a dead RNG (the Debian OpenSSL 2008 failure
  mode, prevented by construction), and `Drop`/zeroize still runs on the failure
  path. The functions that acquire randomness now return `Result`.
- **BREAKING — hybrid secret-key serialization.** `ml-kem` 0.3 serializes the
  decapsulation key as its 64-byte **seed** rather than the 3168-byte expanded
  form, so the hybrid secret key is now **96 bytes** instead of 3200. **Both
  formats are read; the new one is written** — keys created by 0.8.0 still
  decrypt. Public keys and on-wire ciphertext are unchanged, so a 0.8.0 sender
  can still encrypt to a 0.9.0 recipient. Verified across versions.
- **Coupled primitives migration:** `ml-kem` 0.3, `x25519-dalek` 3,
  `rand_core` 0.10, `getrandom` 0.4, `rand_chacha` 0.10. An API migration that
  had to land as one block, not four separate bumps.

### Security
- **A trained adversary as evidence of indistinguishability (feature `lab`).**
  `SPEC.md` claimed the ciphertext is indistinguishable from random by citing
  XChaCha20-Poly1305; it is now measured against the implementation. A logistic
  regression over twelve statistical features (not a neural net, so an auditor
  can read it) finds no distinguisher: over 100 rounds the sigma is a standard
  Gaussian. The lab never ships in a released build.
- **Export-control notification** filed under EAR §742.15(b) (`docs/EXPORT.md`).

### Fixed
- **`quipu-voprf` moved from `getrandom` 0.2 to 0.4** — the last old version left
  in the normal dependency tree. `cargo tree` now shows a single `getrandom`.

## [0.8.0] — 2026-07-18

### Added
- **Documented side-channel posture (`docs/SPEC.md` §15)** and **dudect coverage
  of the post-quantum path**. Two findings worth stating plainly:

  **XChaCha20-Poly1305 is constant-time without a hardware dependency.** It is an
  ARX construction with no lookup tables, so the guarantee holds *unconditionally*
  — every architecture, with or without cryptographic hardware. AES has the same
  property only where the hardware provides it; without AES instructions it falls
  back to S-box tables indexed by secret bytes, the classic cache-timing channel.
  On a modern server with AES-NI the two are equivalent; below that line they are
  not, and **the fallback is silent** — no warning, no test, no API change. In an
  air-gapped on-premise deployment the hardware belongs to the client and is often
  unknown to the vendor, so a property that must be verified per machine is not one
  a specification can promise. §15.2 states this as a table across targets rather
  than as a blanket claim: a CNSA-conformant profile would be a compliance
  decision, and on hardware without AES acceleration a regression on this axis.

  **KyberSlash does not apply.** The attack recovered Kyber keys in minutes by
  exploiting a secret-dependent division; verified in the vendored source that
  `ml-kem` replaces it with a multiply-and-shift and that its only division is a
  compile-time constant. `RUSTSEC-2023-0079` is filed against `pqc_kyber`, not
  used here.

  The bench now measures what the analysis claims: dudect probes over ML-KEM
  decapsulation, with classes *valid vs corrupted encapsulation* (implicit
  rejection must be indistinguishable, or a chosen-ciphertext attack opens up)
  and *two different secret keys* (key-dependent timing). Both report
  constant-time. Signature verification is deliberately **not** a target — key,
  message and signature are all public, so its timing reveals no secret — and
  ML-DSA *signing* is excluded because rejection sampling makes its time vary by
  specification, which would read as a leak that is not one.

  Also recorded: deep-learning side-channel analysis reports breaking an AES
  implementation in ~350 traces where a classical template attack needs ~52,000.
  "The leak is too small to matter" is no longer a defensible position, which is
  precisely why the defence here is absence of leakage by construction rather
  than obfuscation of it.
- **Shamir secret sharing (`quipu::shamir`, opt-in feature `escrow`)** — split a
  secret into `n` shares of which any `k` reconstruct it, over GF(2^8) with
  constant-time field arithmetic (no lookup tables, which would leak through the
  cache). Exposed to Python as `split_secret` / `combine_secret`; the PyPI wheel
  and CI enable the feature explicitly.

  It sits behind a non-default gate on principle, not out of caution: a tool
  should be **contained to its single purpose**. Whoever encrypts data does not
  need to split keys, and code that is not compiled exposes no API, cannot be
  invoked by mistake and cannot interfere with anything else.

  This closes residual risk **R2** of the threat model, whose documented
  mitigation was "offline backup": splitting the OPRF server key into k-of-n
  shares held separately *is* that backup, done with discipline. It equally
  covers custody of an integrator's ML-DSA signing key and contractual escrow,
  and it needs neither network nor HSM — the condition of air-gapped
  deployments.

  **The integrity tag travels inside what is split, not in the header** —
  `secret ‖ SHA-256(domain ‖ secret)[0..8]`. That single placement decision is
  what makes the design hold: with `k-1` shares perfect secrecy covers the whole
  payload, tag included, so **there is no guessing oracle** — whoever can verify
  a guess already holds `k` shares, and therefore already holds the secret. A
  corrupted share, or one from a different split, is still detected: the
  reconstruction is not the payload and the tag does not match.

  It also makes shares **unlinkable**. The header carries only
  `magic ‖ threshold ‖ index ‖ length`, so two shares of the same split look no
  more related than two of different splits. This matters wherever shares for
  several secrets are stored together: a shared field would partition them into
  equivalence classes and hand a reader a map of which shares are worth
  combining.

  An earlier draft put the verifier in the header. That opened an oracle and
  required four patches to contain it — a minimum length floor, Argon2id
  hardening, a documented "high-entropy only" caveat, and per-share salts for
  unlinkability. Moving eight bytes removed all four. Not threshold signing: the
  secret is reassembled in memory to be used.

  Cross-validated against an independent implementation using a different
  approach (log/antilog tables), and against the AES field's known vectors.
- **Power-on self-tests (`quipu::selftest`)** — known-answer tests run against
  the binary actually executing, not the CI build. A wheel compiled with an odd
  flag, a broken SIMD backend or a faulty CPU would otherwise go unnoticed:
  the vectors in `tests/` only ever prove the build that ran them. Certified
  cryptographic modules — FIPS 140-3 and the Chinese GM/T alike — require this
  for that reason, and the module **refuses to operate** if a check fails
  rather than returning silently wrong results.

  Three ways it goes beyond what those standards ask:
  1. **Published vectors, not vendor-chosen ones.** HKDF-SHA256 is checked
     against **RFC 5869 test case 1**. A certified module may use vectors of the
     vendor's own making, which only prove self-consistency; an RFC vector
     proves conformance to the standard.
  2. **Negative tests.** It is not enough that the correct path works — tampered
     ciphertexts, wrong AAD, forged signatures and wrong-key decapsulation must
     all *fail*. A module that always validated would pass conventional
     self-tests, which are purely positive.
  3. **Continuous RNG health.** Two consecutive draws must differ and must not
     be all zeros — a dead generator is the quietest and most catastrophic
     failure mode there is.

  14 checks in total, wired into **every entry point that uses the crypto core**
  — `api::encode`/`decode`, `stream::encrypt`/`decrypt_stream` and both keypair
  generators. The first call costs ~9 ms (median over 200 runs); every call after
  it costs **8.7 ns**, which is nothing next to the Argon2id the same function is
  about to run at 64 MiB.

  **The failure path is treated as a feature, not an afterthought.** A failing
  self-test is almost never the caller's fault — it means a build compiled for a
  different CPU, a corrupted or substituted library file, or failing hardware. So
  the message says that in plain language, states what did *not* happen ("nothing
  was encrypted, decrypted or saved; your files are intact"), lists probable
  causes in order, and gives a reporting path. A technical dump would leave a
  person unsure whether their data was at risk.

  It is also **exercised rather than assumed**: a non-default `selftest-fault`
  feature forces a check to fail so the whole error path runs in CI, and each
  check is proven to *discriminate* — flip a bit of the expected vector and it
  must reject it. A check that always returned `true` would pass a conventional
  self-test suite exactly like a correct one.

  Backed by `examples/selftest_soak.rs`: 200 sequential passes + 100 concurrent
  threads + 1000 repeated calls = **1300 simulated operations**, wired into CI.


## [0.7.0] — 2026-07-06

### Added
- **Multi-language bindings over a stable C ABI.** Quipu's post-quantum core is
  now reachable from C, Node.js and Go, all through one `extern "C"` surface,
  each with a cross-language interop test that decrypts Rust-produced `QST1`
  vectors. Distribution: the Python package (`quipu-crypto`) and signed source
  ship to PyPI + the GitHub Release on tag; the Go module is consumable at
  `github.com/isazajuancarlos/quipu/bindings/go@v0.7.0`; the npm package
  (`quipu-crypto`) publishes via a prebuild matrix (Linux/macOS/Windows).
- **Written specification + machine-readable interoperability test vectors.**
  `docs/SPEC.md` now documents every container format byte-by-byte through v0.6.0
  (adds the streaming `QST1`, honey `QHNY`, and triple-signature `QSG3` formats to
  the existing symmetric/PQ/VOPRF/signature spec). New
  `tests/vectors/quipu_vectors.json` holds known-answer vectors — deterministic
  entries (KDF, HKDF, XChaCha20-Poly1305, Padmé, `QUIP`, `QHNY`) freeze the format
  byte-for-byte; frozen entries pin the decode/verify direction for streaming, PQ
  and signatures. Generated by `examples/gen_vectors.rs`, checked on every
  `cargo test` by `tests/vectors.rs`. Closes a roadmap item and is a prerequisite
  for an external audit and for multi-language bindings.
- **C ABI bindings** (`bindings/c`, crate `quipu-capi`): a stable, stateless,
  panic-safe `extern "C"` surface with parity to the Python bindings (symmetric
  codec, streaming AEAD, post-quantum recipient, hybrid signature). Ships a
  cbindgen-generated `quipu.h`, a `cdylib`/`staticlib`, and a C integration test
  wired into CI (build + header-drift gate + Rust ABI tests + linked C test).
  Output buffers are wiped on free, so no secret-key or plaintext residue
  remains. Foundation for future Node.js/Go bindings.
- **Node.js bindings** (`bindings/node`, npm package `quipu-crypto`): an idiomatic
  `Buffer`-in/out API over the C ABI via Koffi runtime FFI — symmetric codec,
  streaming AEAD, post-quantum recipient, and hybrid signature — with thrown
  `QuipuError`s, hand-written TypeScript types, and a `node:test` suite including
  a **cross-language interop** test that decrypts Rust-produced QST1 vectors. New
  `node` CI job. The API is synchronous in v1: koffi's async path runs on a libuv
  worker whose stack is too small for the core's ML-DSA-87 operations; a
  non-blocking `worker_threads` wrapper is a planned follow-up.
- **Go bindings** (`bindings/go`, module `github.com/isazajuancarlos/quipu/bindings/go`):
  an idiomatic `(result, error)` API over the C ABI via cgo, static-linking
  `libquipu_capi.a` — symmetric codec, streaming AEAD, post-quantum recipient, and
  hybrid signature. Errors are `*quipu.Error` sentinels (`errors.Is`-matchable). A
  `testing` suite includes a **cross-language interop** test that decrypts
  Rust-produced QST1 vectors. Unlike the Node bindings, no async workaround is
  needed: cgo runs on the goroutine system stack, so ML-DSA-87 has room and calls
  are concurrency-safe. New `go` CI job.

### Security Lab
- **Coverage-guided fuzzing wired into CI**: the `fuzz/` libFuzzer harness gains a
  `honey_decrypt` target (the newest untrusted parser) and a nightly `fuzz (smoke)`
  CI job that runs every target (`honey_decrypt`, `parse_container`, `unpad`,
  `codec_roundtrip`) on each push. Local verification found no crashes across
  ~53M executions.

## [0.6.0] — 2026-07-04

### Added
- **Honey Encryption — decoy mode for low-entropy secrets (opt-in `honey`
  feature)**: `honey::encrypt`/`decrypt` (and `encrypt_pin`/`decrypt_pin`) protect
  a secret modelled as a uniform fixed-alphabet sequence (a PIN, a mnemonic
  phrase) so that **any wrong passphrase decrypts to a different but plausible
  secret**, not an error. An offline brute-force attacker never gets a
  "correct-key" signal — the success oracle that makes guessing a weak passphrase
  viable is removed (Juels & Ristenpart, 2014). Construction is a base-`A`
  one-time-pad keyed by Argon2id + HKDF; no new dependencies. **By design this
  mode carries no authentication tag** (a tag would itself be a success oracle),
  so it does not detect tampering and is a specialised companion to — never a
  replacement for — the authenticated AEAD core. Only sound for uniform,
  low-entropy secrets, not arbitrary data. Covered by a "success-oracle" attack
  in the Security Lab.
- **Streaming AEAD exposed in the Python bindings**: `quipu.encrypt_stream` /
  `quipu.decrypt_stream` (optional `pepper` and `chunk_size`) wrap the STREAM
  construction. Output is raw `bytes` (a binary container), not symbols; a
  `chunk_size` outside the 4 KiB–16 MiB range or a failed authentication raises
  `ValueError` instead of aborting the interpreter.

### Security Lab
- **Consolidated red-team runner** (`examples/redteam.rs`): launches every
  adversarial surface at once — adaptive (leak, symmetric/streaming/triple-hybrid
  forgery, honey success-oracle) and deterministic (tamper, truncation,
  salt/nonce uniqueness, signature forgery) — with a single verdict, an
  antihacker-defense latch, and a `QUIPU_REDTEAM_SCALE` soak knob.
- **Honey parser fuzzer** (`lab::honey_fuzz`): feeds adversarial byte strings to
  `honey::decrypt` and proves it never panics (caught via `catch_unwind`) nor
  allocates unbounded — only a decoy or a structural error.

## [0.5.0] — 2026-07-04

### Added
- **Triple-hybrid signature mode (opt-in `slh` feature)**: Ed25519 + ML-DSA-87 +
  **SLH-DSA-SHA2-256s** (FIPS-205, stateless hash-based, via the `fips205` crate)
  combined with an **AND 3-of-3** combiner — a signature is valid only if all three
  verify, so it stays unforgeable as long as at least one of three independent
  families (elliptic curve, lattice, hash) survives. New `QSG3` container and
  `api::encode_signed_triple` / `decode_verified_triple`. High-assurance mode:
  signatures are ~34 KB and signing is slow, so it is opt-in, not the default. The
  double-hybrid mode and v0.4.x artifacts are unchanged. Covered by an adaptive
  3-of-3 forgery attack in the Security Lab.
- **Streaming AEAD for large data-at-rest**: `api::encrypt_stream` /
  `decrypt_stream` (and byte-slice `*_bytes` helpers) encrypt an `io::Read` to an
  `io::Write` in bounded memory using the STREAM construction (Tink-inspired) —
  fixed-size chunks under XChaCha20-Poly1305 with a per-file Argon2id+HKDF key and
  a `QST1` header bound as AAD. Resistant to truncation (final-chunk flag),
  reordering and duplication (per-chunk counter in the nonce), cross-file splicing
  (per-file key) and tampering. Covered by an adaptive forgery surface in the
  Security Lab. No new dependencies.

## [0.4.1] — 2026-07-02

### Security
- **Internal security audit remediation** (availability/robustness hardening;
  no confidentiality/integrity issue was found). Online OPRF server: per-connection
  read/write timeouts (anti-slowloris), a bounded worker-thread pool, and a
  rate limiter that expires entries and caps tracked IPs (bounded memory).
  Offline library: untrusted PNG decoding now enforces `image` size/allocation
  limits (anti decompression-bomb); `ecc::recover` rejects a degenerate parity
  byte; `decode_verified` uses checked arithmetic (no 32-bit length overflow);
  the unverified OPRF path is hidden from docs in favour of the verifiable VOPRF.

### Changed
- **`KdfParams` maximum memory lowered from 1 GiB to 256 MiB.** Decrypting an
  untrusted container runs Argon2 with the container's own parameters before the
  AEAD tag is checked, so the ceiling bounds a cost-amplification DoS. 256 MiB is
  4× the interactive default. **Compatibility:** artifacts encoded with
  `mem_kib > 256 MiB` (very unusual) can no longer be decoded.

## [0.4.0] — 2026-07-02

### Added
- **Supply-chain & side-channel credibility (Security Lab Fase 0)**: a dudect-style
  constant-time gate (Welch's t-test) in the offline timing bench; a CycloneDX SBOM
  and a `cargo-vet` dependency-review gate in CI; and sigstore/cosign keyless
  signatures for release artifacts, documented in `docs/RELEASES.md`.
- **Signed release**: the wheels, sdist and their `.sigstore` bundles are attached
  to the [v0.4.0 GitHub Release](https://github.com/isazajuancarlos/quipu/releases/tag/v0.4.0),
  verifiable with `cosign verify-blob --bundle` (keyless, GitHub OIDC identity);
  the PyPI wheels additionally carry PEP 740 provenance attestations. Verification
  steps are in [`docs/RELEASES.md`](docs/RELEASES.md).

### Changed (BREAKING — wire format)
- **Post-quantum primitives raised to NIST security category 5 (CNSA 2.0)**:
  the hybrid KEM now uses **ML-KEM-1024** (was ML-KEM-768) and the hybrid
  signature uses **ML-DSA-87** (was ML-DSA-65). This aligns Quipu with the NSA
  Commercial National Security Algorithm Suite 2.0 parameter levels. The classical
  halves (X25519, Ed25519), the X-Wing-style transcript binding, the AND signature
  combiner and the domain-separation labels are unchanged.
- **Consequence**: hybrid public/secret keys, encapsulations, verifying/signing
  keys and signatures are larger, and artifacts/keys produced by 0.3.x are **not
  interoperable** with 0.4.0. Sizes: ML-KEM ek/ct 1184/1088 → 1568/1568 B, dk
  2400 → 3168 B; ML-DSA vk 1952 → 2592 B, signature 3309 → 4627 B (hybrid
  signature 3373 → 4691 B). No security downgrade is possible: the recipient/signer
  key fixes the parameter level and cross-level bytes fail length validation.

## [0.3.0] — 2026-07-01

### Added
- **Quipu Security Lab — Etapa B (offline bench)**: timing / side-channel harness
  (surface 2: constant-time `ct_eq` and passphrase-independent `decode` timing)
  and an AI-accelerated password-guessing cost model (surface 3: verifies the
  Argon2id per-guess cost floor holds and that a ranked wordlist never cracks).
  Gated behind a new non-default `lab-offline` feature (implies `lab`, not run by
  CI) and shipped with an isolated `quipu-lab` OCI container (`--network none`,
  non-root, read-only, no real keys). Rust-only and reproducible; the container is
  documented as "ML-ready". Run with `bash lab/run.sh` or
  `cargo run --release --example securitylab_offline --features lab-offline`.
- **Python bindings for the hybrid signature mode**: `generate_signing_keypair`,
  `encode_signed` and `decode_verified` are now exposed to Python, reaching
  Rust/Python parity for the signature API. `quickstart.py` and the Python test
  suite cover the signed round-trip and rejection of wrong/tampered artifacts.
- **Quipu Security Lab (Etapa A)**: a self-hosted *adaptive* red-team behind a
  non-default `lab` Cargo feature (never compiled into the published crate or the
  PyPI wheel — "the weapon does not ship with the product"). A deterministic,
  seed-reproducible engine drives breach-guided attacks over two surfaces:
  ciphertext/format length-leak distinguishing (surface 1) and adaptive signature
  forgery — frankensignatures, key-substitution and region tampering (surface 4).
  Ships three anti-abuse locks: compile-time isolation, a tamper-evidence guard
  that fails CI if the antihacker defenses (`ct_eq`, KDF-param validation, `wipe`)
  are weakened, and a hash-chained findings corpus. Run with
  `cargo run --example securitylab --features lab`.

## [0.2.0] — 2026-07-01

### Added
- **Hybrid signature mode** (asymmetric authenticity): Ed25519 + ML-DSA-65
  (FIPS-204) combined with an **AND** verification combiner — a signature is valid
  only if *both* verify, so it stays unforgeable as long as at least one primitive
  survives. Signatures bind the signer's full verifying key and a
  `quipu/v3/sign` domain label into the signed preimage to prevent key
  substitution and cross-component mixing. New `pqsign` module and
  `api::encode_signed` / `api::decode_verified` (a signed-but-plaintext `QSG1`
  container: authenticity + non-repudiation, not confidentiality).
- **Red-team coverage**: hackerbot `forgery_attack` (tamper each symbol of a
  signed artifact; every mutation must fail verification).

### Security
- Signing keys are stored as 32-byte seeds and zeroized on drop; Ed25519 uses
  strict verification (rejects small-order keys and malleable signatures).
- Signature primitives are vetted third-party crates (`ed25519-dalek`, `ml-dsa`);
  zero `unsafe` in first-party code preserved.

## [0.1.0] — 2026-07-01

First public release. Published to crates.io (`quipu`) and PyPI
(`quipu-crypto`).

### Added
- **Symmetric mode** (passphrase): Argon2id + HKDF-SHA256 key derivation with
  NFKC normalization and optional pepper; XChaCha20-Poly1305 AEAD; 68-byte
  authenticated container header bound as AAD.
- **Hybrid post-quantum mode** (asymmetric): X25519 + ML-KEM-768 (FIPS-203)
  combined via HKDF with X-Wing-style transcript binding (recipient's full public
  key + encapsulation).
- **Verifiable online hardening mode**: VOPRF over ristretto255 with
  non-interactive DLEQ proofs (RFC 9497 style); the client cryptographically
  detects a dishonest hardening server. Includes a dependency-free TCP server.
- **Visual channels**: lossless PNG output, a native glyph alphabet, and a robust
  print channel with Reed-Solomon error correction.
- **Length hiding** via Padmé padding.
- **Defensive layers**: key zeroization (`zeroize`), constant-time comparison
  (`subtle`), KDF-parameter validation against malicious headers.
- **Internal tooling**: a red-team component ("hackerbot") and a test platform.
- **Bindings**: Python via PyO3 (abi3, CPython 3.9+); Rust `rlib` + C-ABI
  `cdylib`.
- **Docs**: internal pre-audit, threat model, licensing (dual AGPL + commercial),
  runnable Rust and Python quickstart examples.

### Security
- All cryptographic primitives are vetted third-party crates; zero `unsafe` in
  first-party code.
- Verified against Google Wycheproof AEAD vectors; Miri (no UB) and `cargo-fuzz`
  (no crashes) on the pure-logic and parsing modules; `cargo-audit` in CI.
- **Not yet independently audited** — see [`SECURITY.md`](SECURITY.md).

[Unreleased]: https://github.com/isazajuancarlos/quipu/compare/v0.11.0...HEAD
[0.11.1]: https://github.com/isazajuancarlos/quipu/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/isazajuancarlos/quipu/compare/v0.10.0...v0.11.0
[quipu-nucleo 0.1.1]: https://github.com/isazajuancarlos/quipu/compare/v0.10.0...nucleo-v0.1.1
[0.10.0]: https://github.com/isazajuancarlos/quipu/compare/v0.9.1...v0.10.0
[0.9.1]: https://github.com/isazajuancarlos/quipu/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/isazajuancarlos/quipu/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/isazajuancarlos/quipu/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/isazajuancarlos/quipu/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/isazajuancarlos/quipu/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/isazajuancarlos/quipu/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/isazajuancarlos/quipu/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/isazajuancarlos/quipu/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/isazajuancarlos/quipu/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/isazajuancarlos/quipu/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/isazajuancarlos/quipu/releases/tag/v0.1.0
