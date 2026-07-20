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

Fecha de la medición: **20 de julio de 2026**, contra `0.9.0`.

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

De sus dos bloqueos, uno se cierra por argumento y el otro **sí se midió**.

El primero no se puede medir con honestidad: el determinismo en coma flotante
falla *entre* máquinas, y aquí hay una CPU y un compilador. Un «me dio igual en
mi portátil» no probaría nada, y sería justo el error de medir lo fácil en vez
de lo que se afirma.

El segundo sí, y el número es contundente.

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

**Medido** (`tests/honey_distinguibilidad.rs`, 20 000 simulaciones por fila).
Secreto: un PIN de cuatro dígitos elegido como los elige una persona —años,
fechas, `ABAB`, escaleras—. Señuelos: uniformes, como los produce `honey` hoy.
El atacante ordena los candidatos por «cuánto parece humano»:

| señuelos | acierta al primero | por azar | ventaja | rango mediano |
|---:|---:|---:|---:|---:|
| 9 | 73,5 % | 10,00 % | **×7,3** | 1 |
| 99 | 27,3 % | 1,00 % | **×27,3** | 3 |
| 999 | 7,0 % | 0,10 % | **×69,8** | 23 |

*Control con secreto uniforme —el caso para el que `honey` está diseñado—:
ventaja ×1,47, es decir, nada. Sin ese control, los números de arriba podrían
ser un sesgo del experimento en vez de una propiedad del secreto.*

Dos lecturas:

- Con 999 señuelos, al atacante le basta probar **23 candidatos en vez de
  1 000**. La protección se reduce 43 veces.
- **La ventaja CRECE con el número de señuelos** (×7 → ×27 → ×70). Es lo
  contrario de lo que se busca: generar más señuelos debería proteger más, y
  como el filtro los elimina a todos por igual mientras el verdadero se queda,
  protege relativamente menos.

Y la medición es **cota inferior**: el modelo de plausibilidad está escrito de
memoria, no ajustado sobre datos. Un atacante real, con estadísticas de
filtraciones masivas, lo hace mejor.

**Conclusión.** Confirma lo que el módulo ya declaraba —`honey` no es para
secretos no uniformes— y le pone cifra. También fija el listón de la tabla de
señuelos estática (#91): tendría que llevar ese ×70 cerca de ×1.

---

## 4. Un adversario entrenado que intenta distinguir — **sí aporta, del lado del ataque**

Las tres sondas anteriores preguntaban si un modelo ayuda a *construir* algo de
Quipu. Esta le da la vuelta: ¿ayuda a *atacarlo*? Y ahí la respuesta es que sí,
como instrumento del laboratorio (`feature = "lab"`, que no se embarca).

Toda la criptografía simétrica descansa en una afirmación —*el ciphertext es
indistinguible del azar*— que `SPEC.md` justificaba citando XChaCha20-Poly1305 y
que **nadie había medido contra la implementación**. `src/lab/distinguidor.rs`
entrena un adversario a separar dos fuentes de bytes y reporta su acierto sobre
muestras que no vio, con el margen del azar en sigmas.

Es **regresión logística sobre doce rasgos** (monobit, sesgo por posición de
bit, chi² del histograma, repeticiones, correlación serial), **no una red
neuronal**, a propósito: un auditor tiene que poder leer al adversario. Sesenta
líneas se verifican mirándolas; unos pesos entrenados hay que aceptarlos de fe.

Lo medido:

| enfrentamiento | veredicto |
|---|---|
| ruido contra ruido *(control)* | 50,7 %, +0,3σ — **no distingue** |
| **fuga sembrada** (XOR de clave corta) | 100,0 %, +20σ — **DISTINGUE** |
| ciphertext de Quipu contra azar | **no distingue** |
| dos ciphertext de contenidos opuestos | **no distingue** |

Las dos primeras filas hacen válidas a las otras dos: un detector que nunca dice
«sí» no vale nada, y hay que enseñarle una fuga real para saber que su silencio
significa algo.

**Y aquí está el matiz que corrige un error mío.** Las dos filas de Quipu **no
son reproducibles**: la sal y el nonce salen del sistema, así que cada corrida ve
ciphertext nuevo. Citar «50,5 %» como si fuera *el* número —como hice al
principio— es confundir una tirada con la distribución. La afirmación correcta es
más fuerte y está medida sobre **100 rondas**: el sigma tiene **media +0,07 y
desviación 0,94, sin ninguna por encima de 3σ**. Es decir, una gaussiana estándar
—exactamente lo que debe ser cuando no hay nada que encontrar—. Por eso la prueba
exige mayoría de tres rondas antes de gritar «brecha»: con muestras frescas, un
umbral de 3σ da un rojo espurio una vez de cada mil, y una falsa alarma que dice
«fuga» en una librería de cripto es peor que no tener la prueba.

Que las muestras sean frescas no es un defecto que ocultar: es lo que convierte
**cada corrida del CI en un experimento nuevo** que vuelve a no encontrar nada,
en vez de repetir una respuesta congelada.

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
  laboratorio nunca se embarca. **Construido y medido: es el punto 4.**

Ese último reordena el planteamiento entero. Un
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
cargo test --release --test glifos_degradados      -- --nocapture
cargo test --release --test glifos_separabilidad   -- --nocapture
cargo test --release --test honey_distinguibilidad -- --nocapture
# El distinguidor (punto 4) vive tras la feature del laboratorio:
cargo test --release --features lab --lib distinguidor -- --nocapture
# Y la distribución de 100 rondas, que es un instrumento y no lo corre el CI:
cargo test --release --features lab --lib distribucion -- --ignored --nocapture
```

Los glifos y honey son **deterministas**: PRNG propio con semilla fija, sin red,
sin datos externos. **El distinguidor sobre Quipu no lo es** —la sal y el nonce
salen del sistema, a propósito (ver el punto 4)—; su veredicto se estabiliza por
mayoría de tres rondas, no por congelar la entrada.

Los degradadores viven en `tests/` a propósito — son instrumentos de medida y no
tienen por qué viajar en la biblioteca.
