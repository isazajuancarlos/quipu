<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas
-->

# ¿El aprendizaje automático aporta algo a Quipu?

**Respuesta corta: no en el producto. Puede que sí en el laboratorio, y eso está
sin medir.**

Este documento cierra una investigación abierta con tres sondas —reconocer
glifos degradados, generar alfabetos, y modelar la distribución del secreto en
Honey Encryption—. Se cierra con números donde los hay y con el argumento
explícito donde no, para que la conclusión se pueda discutir en vez de heredar.

Fecha de la medición: **20 de julio de 2026**, contra `0.8.0`.

---

## 1. Reconocer glifos de una página fotografiada — **no aporta**

**La hipótesis era:** leer una hoja impresa y fotografiada es visión por
computador de manual, y una CNN pequeña supera a cualquier heurística.

**Lo que se midió** (`tests/glifos_degradados.rs`), sobre el alfabeto completo:

| degradación | posición fija | con registro |
|---|---:|---:|
| limpia | 100,0 % | 100,0 % |
| desplazada 1 px | 17,3 % | **100,0 %** |
| desplazada 2 px | 5,1 % | **100,0 %** |
| luz lateral 60 % | 82,7 % | **100,0 %** |
| sangrado de tinta | 95,9 % | 95,9 % |
| ruido ±90 sobre 255 | 100,0 % | 100,0 % |
| rotada 0,5° | 0,0 % | 11,2 % |

**Lo que dicen los números.** El clasificador que ya existe —vecino más cercano
en distancia de Hamming— acierta el 100 % con ruido de ±90. No estaba
limitado por su capacidad de clasificar. Lo que lo tumbaba era **un píxel de
desplazamiento**, porque `recognize` leía posiciones fijas.

**Por qué una red no lo arregla.** Si el recorte se toma de coordenadas
equivocadas, el error ya ocurrió *antes* de clasificar. Entrenar un
clasificador más listo sobre las entradas equivocadas no cambia nada. Lo que
faltaba no era aprendizaje: era un sistema de coordenadas.

**Resuelto sin modelo** en `src/glyphscan.rs`: umbral de Otsu, estimación de
inclinación, periodo de la rejilla por los huecos entre glifos, y remuestreo.
Determinista, sin dependencias nuevas, auditable leyéndolo.

**Lo que sigue abierto y tampoco es ML:** la rotación. La tira mide 18 px de
alto por más de mil de ancho, así que el paso de búsqueda de 0,25° ya desplaza
los extremos cuatro píxeles en vertical. Se resuelve estimando el ángulo por
ajuste de la línea base, que da respuesta continua en vez de a saltos.

---

## 2. Generar alfabetos de glifos con un modelo — **no aporta**

**La hipótesis era:** un modelo generativo produce muchos más candidatos, y
eligiendo entre más sale un alfabeto más separable.

Se puede comprobar sin entrenar nada, porque lo que hay que medir no es el
generador: es **dónde está el límite**.

**Primera medición** (`tests/glifos_separabilidad.rs`). Un glifo de 16×16 es un
vector de 256 bits, así que hay cota de Plotkin: 129 para 94 símbolos.

| candidatos | distancia mínima |
|---:|---:|
| 500 | 24 |
| 2 000 | 30 |
| 8 000 | 33 |
| 32 000 | 35 |
| *glifos aleatorios puros* | **115** |

Multiplicar por 64 el conjunto sube la distancia solo ×1,46. Pero el ruido puro
llega a 115 de 129: **el alfabeto de trazos deja 3,5× de separabilidad sin
usar**. El techo no era la geometría, contra lo que se suponía al empezar.

**Segunda medición**, y es la que decide:

| alfabeto | dist. mín. | tras sangrado | tras desenfoque |
|---|---:|---:|---:|
| trazos | 33 | **100,0 %** | 34,0 % |
| ruido puro | 115 | **12,8 %** | 88,3 % |

**La distancia de Hamming no predice la robustez.** El ruido gana por 3,5× en la
métrica y pierde por 8× en el papel. Y cada alfabeto sobrevive a una degradación
distinta: los trazos aguantan que la tinta se corra y desaparecen con el
desenfoque; el ruido al revés.

**Conclusión.** El cuello de botella no son los candidatos: es el **criterio de
selección**. `select_separable_subset` maximiza una distancia medida sobre el
glifo ideal, y lo que importa es la que queda después del canal. Un generador
alimentaría mejor a una métrica que mide lo que no es.

**Un intento de arreglo que falló, y se deja escrito.** Meter el canal dentro de
la huella concatenando las versiones degradadas da **peor** resultado: 26,6 %
contra 34,0 %. El error es de álgebra —Hamming sobre una concatenación es la
suma por canal y hacía falta el mínimo—. El criterio correcto no cabe en la
firma actual de `select_separable_subset`.

**Límite de esta conclusión.** El «no» vale **contra el criterio actual**. Si el
criterio se corrige (tarea abierta), los candidatos podrían volver a ser el
límite y la pregunta se reabre. No es un no definitivo.

---

## 3. Modelar la distribución del secreto en Honey Encryption — **no aporta, y es la peligrosa**

Esta se cierra **por argumento, no por medición**, y conviene que quede dicho.

Honey Encryption devuelve un secreto falso pero creíble ante cada contraseña
equivocada, de modo que un atacante no puede confirmar aciertos. Hoy modela el
secreto como `L` tokens de un alfabeto uniforme: sirve para un PIN o una frase
semilla, no para una contraseña humana.

Modelar esa distribución es, literalmente, un modelo de lenguaje. Y choca con
dos cosas:

1. **Determinismo exacto.** El codificador tiene que ser invertible y
   determinista bit a bit. Una red en coma flotante da resultados distintos
   según CPU, compilador y orden de operaciones: el contenedor cifrado en una
   máquina **no descifraría en otra**. Haría falta inferencia cuantizada solo
   con enteros y redondeo fijo, que es un proyecto en sí mismo.
2. **El fallo es de seguridad, no de comodidad.** Si la distribución del modelo
   no coincide con la real, los señuelos se vuelven distinguibles y la propiedad
   que justifica el modo entero desaparece. En los otros dos casos, equivocarse
   cuesta acierto; aquí cuesta la garantía.

---

## Lo que sí sería admisible

El repositorio ya tiene escrito el patrón correcto, en `src/glyphopt.rs`:

> la IA corre **fuera**, en tiempo de diseño; produce candidatos; un algoritmo
> **determinista** selecciona; solo viaja el artefacto final; el modelo **nunca**
> se ejecuta al descifrar.

Bajo ese patrón, la pregunta útil no es «¿usamos aprendizaje automático?» sino
**«¿hay artefactos que valga la pena generar así?»**. De los evaluados:

- **Alfabetos de glifos** — no, mientras el criterio de selección siga midiendo
  lo que no es.
- **Tablas de señuelos fijas para Honey** — esquiva el bloqueo del punto 3,
  porque en tiempo de ejecución no hay modelo sino tabla. Sin medir.
- **Distinguidores para el `lab`** — riesgo cero por construcción: el
  laboratorio nunca se embarca. Sin medir, y es la sonda que sigue viva.

Ese último merece un párrafo, porque reordena el planteamiento entero. Un
distinguidor es exactamente la pregunta *«¿puede un modelo notar la diferencia
entre estas dos salidas?»*. Si puede, hay una fuga. Si un adversario bien
entrenado **no puede**, eso es evidencia de indistinguibilidad expresable como
número.

**El valor del aprendizaje automático en Quipu está del lado del ataque, no del
producto.** En una biblioteca que se vende por rigor, un adversario automático
que busca y no encuentra vale más para quien firma la compra que cualquier
función nueva.

---

## Reproducir las mediciones

```bash
cargo test --release --test glifos_degradados    -- --nocapture
cargo test --release --test glifos_separabilidad -- --nocapture
```

Todas deterministas: PRNG propio con semilla fija, sin red, sin datos externos.
Los degradadores viven en `tests/` a propósito — son instrumentos de medida y no
tienen por qué viajar en la biblioteca.
