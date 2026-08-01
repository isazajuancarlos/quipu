# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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

[Unreleased]: https://github.com/isazajuancarlos/quipu/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/isazajuancarlos/quipu/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/isazajuancarlos/quipu/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/isazajuancarlos/quipu/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/isazajuancarlos/quipu/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/isazajuancarlos/quipu/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/isazajuancarlos/quipu/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/isazajuancarlos/quipu/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/isazajuancarlos/quipu/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/isazajuancarlos/quipu/releases/tag/v0.1.0
