<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza -->

# Teoría del caos y matemática clásica en Quipu

> Estudio pedido el **2026-08-16**. Medido sobre el árbol de trabajo en
> `dd23cce` (rama `estudio/matematica-y-caos`). Todo número de aquí trae el
> comando que lo produce.

**La determinación, antes del razonamiento:**

1. **La teoría del caos NO entra en el núcleo criptográfico.** No por prejuicio:
   por un historial medido de esquemas rotos y por tres modos de fallo que
   aparecen justo al discretizar. Además choca de frente con la filosofía
   declarada del proyecto —*nunca inventamos primitivas*—. Lo que el caos tenía
   de aprovechable entró en la criptografía en **1949**, con otro nombre.
2. **Donde la dinámica sí tiene algo que decir es en la FUENTE DE RUIDO**, y ahí
   encontró un hueco real y medido: `salud_de` implementa una de las dos pruebas
   continuas que exige la SP 800-90B, y una fuente en **ciclo corto pasa
   limpia**.
3. **La matemática clásica no es un adorno que se le pueda añadir a Quipu: ya es
   su esqueleto.** Está inventariada abajo, archivo por archivo. Y todavía tiene
   algo que dar: el códec base-N es **cuadrático**, con 512 KiB costando
   **51 segundos**, y la salida es un algoritmo clásico de conversión de base.

---

## 1. Teoría del caos: por qué no entra

### Qué es, en una línea

Un sistema determinista es *caótico* cuando cumple tres cosas a la vez:
**dependencia sensible de las condiciones iniciales** (Lyapunov positivo),
**transitividad topológica** (una órbita visita todo el espacio) y **órbitas
periódicas densas**. Poincaré lo encontró en el problema de los tres cuerpos
(1890) sin ponerle nombre; Lorenz lo redescubrió en 1963 truncando un decimal en
un modelo del clima; Li y Yorke le pusieron la palabra en 1975.

### Por qué parece criptografía

La analogía es tentadora y por eso hay literatura para llenar una biblioteca:

| Caos | Criptografía | ¿Es lo mismo? |
|---|---|---|
| dependencia sensible de la condición inicial | efecto avalancha | **no**: la avalancha se exige en UNA aplicación de la función, no en el límite asintótico de la órbita |
| condición inicial | clave | **no**: un real de precisión finita no es un espacio de claves de 256 bits |
| mezcla ergódica | difusión | **parcialmente** — y esa parte ya se usa, ver abajo |
| aperiodicidad | flujo de clave | **no**: sobre aritmética finita la órbita es periódica por definición |

### Los tres modos de fallo, que aparecen todos al discretizar

El caos vive en los reales. Una computadora no tiene reales.

1. **Degeneración de la dinámica.** Un mapa caótico en coma flotante tiene un
   espacio de estados finito, y su órbita cae en un ciclo cuya longitud típica
   va como la raíz del tamaño del espacio (paradoja del cumpleaños). En `f64`,
   ciclos de longitud ~2³² son corrientes. Un flujo de clave con periodo 2³² es
   un flujo de clave roto.
2. **Irreproducibilidad.** Si el descifrado tiene que recorrer la MISMA órbita,
   cualquier diferencia de redondeo entre plataformas —o entre `-O0` y `-O3`, o
   con FMA— desincroniza y el descifrado falla. Los esquemas que evitan esto
   cuantizando pierden justo la propiedad que invocaban.
3. **Independencia del texto claro.** En casi todos estos esquemas la órbita
   depende solo de la clave, no del mensaje: es un cifrado de flujo, y un único
   par claro/cifrado elegido entrega el flujo entero. Es un ataque de texto
   claro elegido de complejidad **1**.

La crítica canónica es Alvarez y Li, *«Some basic cryptographic requirements for
chaos-based cryptosystems»* (Int. J. Bifurcation and Chaos, 2006), y la lista de
esquemas rotos desde entonces —logístico, Chebyshev, Lorenz, Chua, gato de
Arnold— es larga y no ha parado de crecer.

### Por qué esto le toca a Quipu de cerca

Porque **Quipu renderiza a imagen**, y la «cifra caótica de imágenes» es
precisamente el género donde vive casi toda esa literatura rota: permutar los
píxeles con el gato de Arnold, difundir con un mapa logístico, publicar el
histograma plano y la correlación entre píxeles adyacentes como si eso fuera una
prueba de seguridad. **No lo es**: un histograma plano lo produce también un XOR
con una constante repetida.

Control negativo, con su aguja validada:

```bash
grep -rn -iE "\bchaos\b|\bcaos\b|logistic map|lorenz|arnold|cat map" \
  src crates/*/src docs/*.md README.md
# única coincidencia: crates/quipu-nucleo/src/bip39_english.txt:307:chaos
# (la palabra de la lista BIP-39, no un algoritmo)
```

Que el árbol esté limpio hoy no es garantía de mañana: es exactamente la
propuesta que aparece cuando alguien mira el modo de imagen y quiere «mejorarlo».
Este documento existe para que la respuesta ya esté escrita.

### Lo que sí sobrevivió, y entró hace 76 años

La parte utilizable del caos es la **teoría ergódica de las transformaciones
mezcladoras**, y no hace falta importarla: **Shannon ya la importó en 1949**. En
*Communication Theory of Secrecy Systems* describe la difusión con la imagen de
amasar una masa —estirar y plegar, que es literalmente la herradura de Smale— y
la llama *mixing transformation*, tomándola de la teoría ergódica de la época.

Lo que la criptografía hizo después con esa idea fue **cuantificarla**: el
criptoanálisis diferencial y lineal no dicen «esto mezcla mucho», dicen «la
probabilidad diferencial máxima sobre 8 rondas está acotada por 2⁻⁹⁶». Esa cota
es la versión rigurosa de la intuición caótica, y es la que sostiene el número de
rondas de ChaCha20 y las cotas de ML-KEM.

**Conclusión:** adoptar «caos» hoy sería sustituir un teorema por una metáfora.

---

## 2. Donde la dinámica SÍ tenía algo que decir: la fuente de ruido

Hay un sitio donde las preguntas de sistemas dinámicos son las correctas: **¿esta
secuencia viene de una fuente viva o de un sistema determinista degenerado?** Es
la pregunta de la SP 800-90B de NIST, y sus estimadores de min-entropía
(predictores de Markov, colisión, MultiMCW, LZ78Y) son la forma rigurosa de
«¿esta órbita es realmente impredecible?».

**Quipu ya hace pruebas continuas** —`src/aleatorio.rs`, `salud_de`— y eso está
bien puesto: van en cada extracción, no solo al arrancar. Pero la norma exige
**dos** pruebas continuas y Quipu tiene **una**:

| Prueba SP 800-90B | ¿está? | qué caza |
|---|---|---|
| *Repetition Count Test* | **sí** (`REPETICION_QUE_DELATA = 8`) | la fuente **muerta**: atascada en un valor |
| *Adaptive Proportion Test* | **no** | la fuente **sesgada o periódica**: un valor demasiado frecuente en una ventana |

El hueco no es teórico, y aquí es donde la teoría del caos aporta de verdad —
nombrando el modo de fallo, no proponiendo un cifrado. Una fuente atrapada en un
**ciclo corto** (`A5 5A A5 5A …`) tiene 1 bit de entropía por byte y **no tiene
jamás dos bytes iguales seguidos**, así que la cota de repetición no la ve.

Medido, no razonado:

```bash
cargo test --lib aleatorio::pruebas_salud
# aleatorio::pruebas_salud::un_ciclo_corto_pasa_limpio_por_la_cota_de_repeticion ... ok
```

La prueba `un_ciclo_corto_pasa_limpio_por_la_cota_de_repeticion` fija el
comportamiento de hoy (`None` sobre 4 KiB de periodo 2 y de periodo 3) y lleva
**su control dentro**: la misma longitud atascada de verdad sí se caza, así que
un `salud_de` que devolviera `None` siempre no pasaría.

**Matiz honesto sobre la gravedad:** Quipu no consume una fuente de ruido cruda,
consume el CSPRNG del sistema vía `getrandom`. Un `/dev/urandom` sano no entra en
ciclos cortos. El caso que esto cubre es el otro: un `seccomp`, un chroot roto,
una máquina virtual clonada o un stub de pruebas que devuelve éxito entregando
basura estructurada. Es defensa en profundidad sobre un fallo improbable y
catastrófico — que es justo el perfil de lo que merece una prueba barata (O(n),
una comparación por byte).

---

## 3. La matemática clásica ya es el esqueleto de Quipu

No hay que «añadirle» matemática antigua a Quipu. Hay que **contarla**, porque ya
está cargando peso. Inventario medido sobre el árbol:

| Dónde | Qué matemática | De cuándo | Qué sostiene |
|---|---|---|---|
| `quipu-nucleo/src/codec.rs` | numeración **posicional** y conversión de base | Babilonia (~2000 a. C.) sin cero; con cero, Brahmagupta (628) | el códec base-N: el valor de un símbolo **es su índice** |
| `quipu-nucleo/src/dictionary.rs` | separación entre **valor** e **identidad del signo** | la estructura del propio *quipu* inca | el codebook traduce índice → símbolo, y nada más |
| `quipu-nucleo/src/ecc.rs` | cuerpos de **Galois** GF(2⁸), interpolación polinómica, síndromes, **Forney**, búsqueda de raíces | Galois 1830; Reed–Solomon 1960; Forney 1965 | corrección de errores del canal de papel/foto |
| `src/shamir.rs` | interpolación de **Lagrange** en x=0 sobre GF(2⁸), esquema de **Horner** | Waring 1779 / Lagrange 1795; Horner ya en Qin Jiushao, 1247 | reparto de secretos k-de-n (`escrow`) |
| `src/shamir.rs:161` | inverso por **exponenciación**: `a²⁵⁴ = a⁻¹` en GF(2⁸) | Fermat 1640, demostrado por **Euler** 1736 | inversión en tiempo constante, sin tabla |
| `curve25519-dalek` (X25519, Ed25519, ristretto255) | **criterio de Euler** / residuos cuadráticos, raíz cuadrada para p ≡ 5 (mod 8) | Euler, mediados del s. XVIII; Legendre 1798 | `sqrt_ratio_i`, `invsqrt`, descompresión de puntos y Elligator |
| `curve25519-dalek/src/field.rs:283` | **pequeño teorema de Fermat**: `x^(p-2) = x⁻¹` | Fermat / Euler | inversión de cuerpo en tiempo constante |
| `ml-kem`, `ml-dsa` (NTT) | **ciclotomía** y raíces de la unidad; el NTT es un DFT sobre cuerpo finito y una descomposición **CRT** de `Z_q[X]/(Xⁿ+1)` | CRT: *Sunzi Suanjing*, s. III–V; ciclotomía: Gauss 1801; FFT: Gauss 1805, redescubierta por Cooley–Tukey 1965 | toda la multiplicación de polinomios post-cuántica |
| `ml-kem` (reducción de Barrett/Montgomery) | división euclídea con recíproco precalculado | Euclides, *Elementos* VII (~300 a. C.) | reducción modular sin dividir |
| `padme-frame` | logaritmos | Napier 1614 | cuantización de longitudes con sobrecoste acotado |

Comandos que lo comprueban:

```bash
grep -rn "Lagrange\|Horner\|a^254\|GF(2\^8)" src/shamir.rs
grep -rn "syndrome\|Forney\|error_locator" vendor/reed-solomon/src/decoder.rs
grep -rn "zeta\|Ntt\|barrett_reduce"        vendor/ml-kem/src/algebra.rs
sed -n '275,295p'                           vendor/curve25519-dalek/src/field.rs
```

### El detalle que da nombre al proyecto

El *quipu* inca es un **sistema posicional en base 10 con alfabeto de símbolos**:
la posición del nudo en la cuerda da el orden de magnitud, y el TIPO de nudo
—simple, largo, de ocho— da el dígito. Son exactamente las dos capas de esta
librería, y están separadas en el código igual que en el objeto:

- `codec.rs` → el valor, posicional;
- `dictionary.rs` → la identidad del signo, intercambiable.

Que la separación sea la misma no es casualidad de nombre: es la razón por la que
cambiar el alfabeto de símbolos no toca ni un bit del contenedor cifrado.

---

## 4. Euler, en concreto: dónde corre hoy

Juan preguntó por Euler. Corre en cada operación de Quipu, en tres sitios:

1. **Criterio de Euler (residuosidad cuadrática).** Ristretto255 necesita decidir
   si un elemento del cuerpo es un cuadrado y sacarle la raíz. `sqrt_ratio_i`
   (`field.rs:320`) lo resuelve con `pow_p58` = `x^((p-5)/8)`, la fórmula que
   solo vale para p ≡ 5 (mod 8) y cuya corrección se apoya en el criterio de
   Euler. **Se ejecuta en cada `hash_to_group` del VOPRF** —el `HashToGroup` de
   la RFC 9497 es `RistrettoPoint::from_uniform_bytes`, o sea dos mapas de
   Elligator 2— y en cada descompresión de un punto Ed25519.
2. **Teorema de Fermat–Euler.** La inversión de cuerpo es `x^(p-2)`, y el
   comentario del propio código lo dice: `x^(p-2)·x = x^(p-1) = 1 (mod p)`. Se
   usa así, y no con Euclides extendido, porque la exponenciación es de **tiempo
   constante** y el algoritmo de Euclides no lo es. Es un caso bonito: se prefiere
   el teorema más antiguo porque el más eficiente filtra por canal lateral.
3. **Raíces de la unidad.** El NTT de ML-KEM y ML-DSA es un DFT sobre `Z_q` con
   raíces `zeta` en orden de bits invertidos. La línea va de Euler (series
   trigonométricas y `e^{iθ}`) a Gauss (ciclotomía, 1801, y la FFT en 1805) y
   llega intacta a FIPS 203.

Lo que Euler NO aporta aquí: la función totiente `φ(n)` es el corazón de RSA, y
Quipu no usa RSA. Vale la pena decirlo para no forzar la conexión.

---

## 5. Lo que la matemática clásica todavía tenía que dar: el códec era cuadrático

Este es el hallazgo con consecuencias del estudio, y **el mismo día quedó
arreglado** — con el algoritmo clásico que el propio estudio señalaba.

`encode_base_n` convierte todo el mensaje a un único entero grande y lo divide
repetidamente. El código ya trae una optimización sensata —dividir por `n^k` en
vez de por `n`, sacando 9 dígitos por pasada en base 94— pero eso **divide la
constante, no cambia el orden**: la conversión de base sigue siendo O(m²) en el
número de limbos.

Medido (`cargo test --release -p quipu-nucleo --test escala_del_codec --
--ignored --nocapture`, ~90 s):

| Tamaño | encode | decode | factor al duplicar |
|---:|---:|---:|---:|
| 16 KiB | 49,2 ms | 13,5 ms | — |
| 32 KiB | 198,0 ms | 53,9 ms | ×4,0 |
| 64 KiB | 790,6 ms | 212,5 ms | ×4,0 |
| 128 KiB | 3 160,5 ms | 852,9 ms | ×4,0 |
| 256 KiB | 12 643,2 ms | 3 421,0 ms | ×4,0 |
| **512 KiB** | **50 698,8 ms** | 13 806,1 ms | ×4,0 |

Cuadrático de libro: cada duplicación multiplica por 4,0 exacto. Extrapolando,
1 MiB son ~3,4 minutos y 10 MiB son ~5,6 **horas**.

**Alcance del problema, acotado con su control.** Solo afecta al camino
simbólico —`api::encode`, `encode_to_recipient`, `encode_signed`— porque el
cifrado en flujo no pasa por aquí:

```bash
grep -n "codec::" src/stream.rs      # vacío: QST1 no toca el códec base-N
grep -rn "encode_base_n" src/api.rs  # 7 llamadas: es el camino normal
```

Y el camino de papel usa `encode_grupos`, que es lineal (3 bytes → 4 glifos) por
una razón distinta —localizar el daño para el corrector Reed-Solomon—, así que
tampoco sufre.

**El README ya documenta que `encode_to_recipient` carga el archivo entero en
memoria. No documenta que además el tiempo es cuadrático**, y de las dos, la que
muerde primero es esta: 10 MiB de memoria no son nada; 5,6 horas sí.

**La salida es un algoritmo clásico**, y por eso este hallazgo pertenece a este
estudio: la **conversión de base por divide y vencerás**. En vez de dividir el
número entero por `n^k` una y otra vez, se parte por `n^(d/2)` —cociente y resto,
cada uno con la mitad de los dígitos— y se recurre. El coste pasa de O(m²) a
O(M(m)·log m), donde M es el coste de multiplicar. Es lo que hace `mpn_get_str`
de GMP y está descrito en Brent y Zimmermann, *Modern Computer Arithmetic*, §1.7.
La aritmética que lo sostiene —Karatsuba y Toom–Cook— es división y conquista
sobre polinomios, la misma idea que el NTT.

### Hecho el mismo día, y medido

| | antes | después | |
|---|---:|---:|---:|
| 512 KiB | 50 698,8 ms | **456,7 ms** | **111×** |
| 10 MiB | ~5,6 h (extrapolado) | **41,4 s** (medido) | ~490× |
| factor al duplicar | ×4,00 | **×2,82** | cuadrático → `M(m)·log m` |

El ×2,82 no es un número redondo por casualidad: es lo que da `M(m)·log m` con la
multiplicación **Toom-3** de `num-bigint`.

**Lo que hubo que verificar ANTES de escribir una línea**, porque el algoritmo no
sirve solo: divide y vencerás únicamente compensa si la división de la librería
es subcuadrática. Con división escolar, `T(m) = 2·T(m/2) + O(m²)` sigue siendo
cuadrático y con **peor** constante que el bucle — habría sido una «mejora» que
empeora. `num-bigint` trae Karatsuba, Toom-3 y **Burnikel-Ziegler** (umbral 64
limbos), así que sí compensa. Queda escrito en el código como la propiedad a
re-verificar si algún día se cambia de librería.

**Y lo que costó de verdad no fue el algoritmo, fue el banco.** Las pruebas que
había —incluida una proptest contra la implementación ingenua, que es la
definición del formato— **pasaban igual con el árbol borrado**, porque todas
usaban mensajes cortos que se van por el camino viejo. Se añadieron cuatro
pruebas sobre entradas grandes, con un positivo de control que interroga al
predicado real de qué camino se toma.

Cinco mutantes para comprobar que el banco discrimina; **uno sobrevivió** y ese
fue el útil: borrar el relleno de ceros de la hoja no ponía en rojo nada, porque
una rama a cero solo cambia el resultado si está en MEDIO, y con datos
pseudoaleatorios nunca aparece un hueco de nueve dígitos seguidos a cero. Hubo
que fabricarlo. Los cinco mueren ahora.

El coste es superlineal todavía, así que el camino simbólico no es para archivos
arbitrariamente grandes; para eso está `encrypt_stream`, que no pasa por el
códec. Y el techo de **memoria no se movió**: la mejora es de tiempo, y la tabla
de potencias añade aproximadamente otro tanto del tamaño del mensaje.

---

## 6. Para qué sirve esto fuera del código

Desde que el código dejó de ser público, la prueba de profundidad técnica se
mudó al portafolio (directiva 11). Este documento es materia prima directa: la
matemática de Quipu se puede contar entera —de Sunzi a Gauss, de Euclides a
Lagrange— **sin enseñar una línea de código**, y con mediciones que se entienden
solas. La sección 5, en particular, es un artículo por sí misma: una biblioteca
de criptografía real, un cuello de botella cuadrático medido y un algoritmo de
conversión de base como solución.

Y la sección 1 tiene un segundo uso: es la respuesta preparada para el revisor,
el evaluador de subvención o el cliente que pregunte «¿y por qué no usan
criptografía caótica, que es más segura?».

---

## 7. Determinación

| | |
|---|---|
| **Teoría del caos en el núcleo** | **descartada**, con motivo escrito. No se reabre sin un hecho nuevo |
| **Teoría del caos como conocimiento** | útil: nombra el modo de fallo de la §2 y prepara la §1 para el portafolio |
| **Matemática clásica** | ya es el esqueleto; lo que faltaba era el inventario, y está hecho |
| **Hueco medido 1** | falta la *Adaptive Proportion Test* de la SP 800-90B → **tarea** |
| **Hueco medido 2** | `encode_base_n` era cuadrático → **ARREGLADO el 2026-08-16**: 111× a 512 KiB, con guardia contra la regresión |
| **Hueco medido 3** | el README no decía nada del coste en tiempo → **ARREGLADO**, en los dos idiomas |

Lo entregado: este documento, la prueba
`un_ciclo_corto_pasa_limpio_por_la_cota_de_repeticion`, el códec reescrito con
sus cinco pruebas y el guardia `escala_del_codec`. **Ningún cambio de
comportamiento observable**: los dígitos que salen son byte a byte los mismos, y
eso no es un detalle — el códec produce un artefacto FIRMADO que ya está guardado
en bases de datos de clientes.
