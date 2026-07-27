<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas -->

# Las tres ramas

Modelo inspirado en Debian: **estable**, **testing** y **desarrollo**. Se adopta
el 2026-07-27, antes de empezar a añadir características, porque el problema que
resuelve ya existía.

## El problema que resuelve

Hasta hoy `main` era **dos cosas a la vez**: el trabajo más reciente y lo que
está publicado en crates.io, PyPI y npm. Esas dos cosas se separan en el
instante en que aterriza una característica después de un tag — y entonces no
hay ninguna rama que se pueda revisar para responder «¿qué me estoy instalando?».

Para una librería que vende auditabilidad, eso no es un detalle de flujo: es la
diferencia entre poder señalar el código publicado y tener que reconstruirlo a
partir de un tag.

## Las tres

| Rama | Qué es | Quién entra | ¿Puede estar roja? |
|---|---|---|---|
| **`estable`** | Lo **publicado**. Los tags `v*` se cortan aquí. Es la rama **por defecto**. | Solo `testing`, al publicar. Y las correcciones urgentes. | **Nunca** |
| **`testing`** | Candidata a la próxima versión: integrada y verde. | Ramas de característica, por PR. | **Nunca** |
| **`desarrollo`** | Trabajo en curso. | Empuje directo. | Sí, y no pasa nada |

### Por qué `estable` es la rama por defecto

Lo que ve quien llega al repositorio debe ser lo que puede instalar. En una
librería que vende confianza, la portada tiene que describir lo que da
`cargo add quipu`, no lo que habrá dentro de tres semanas.

`main` **se renombró** a `estable` el 2026-07-27. Se hizo en el momento con menos
coste posible: cero PR abiertos y solo dos referencias al nombre en todo el
repositorio. GitHub mantiene redirecciones para los enlaces antiguos.

Quien tenga un clon anterior:

```bash
git branch -m main estable
git fetch origin
git branch -u origin/estable estable
git remote set-head origin -a
```

## La protección muerde, y también a quien la puso

`estable` y `testing` tienen `enforce_admins` **activo** desde el 2026-07-27. Un
push directo se rechaza con `GH006`, sin excepción.

Se activó por un motivo concreto: dos horas después de montar este modelo, su
propio autor empujó directo a `testing` sin darse cuenta. Pasó porque la
protección permitía saltársela siendo administrador. La regla estaba escrita —
en este mismo archivo— y escribirla no bastó.

**El precio, dicho antes de que sorprenda:** si el CI se rompe, nadie puede
empujar el arreglo directo. Hay que desactivar la protección, arreglar y volver
a activarla. Es deliberado: una regla que se puede saltar cuando molesta no es
una regla, es una sugerencia.

## El recorrido

```
  rama de característica ──PR──►  testing  ──promoción──►  estable  ──tag──►  publicado
                                     ▲
        desarrollo ──────────────────┘
        (trabajo en curso, puede romperse)
```

1. Una característica nueva sale de `testing`, vive en su rama, y vuelve por PR.
2. Cuando `testing` está lista, se **promueve** a `estable`.
3. El tag se pone en `estable`, y **poner el tag es publicar**.

`desarrollo` es para lo que aún no merece un PR: pruebas de concepto, mediciones,
lo que se va a tirar. Nada baja de `desarrollo` a `estable` sin pasar por `testing`.

## La promoción no se hace a mano

Aquí está la parte que decide si esto sirve o se pudre. **En Debian, quien migra
paquetes de `unstable` a `testing` es un robot**, con reglas: diez días sin
fallos críticos, dependencias satisfacibles. Sin ese robot, `testing` es solo una
rama que alguien tiene que acordarse de fusionar — y acordarse no escala.

El robot de aquí es:

```bash
python3 herramientas/verificar.py promover --a testing   # desde una rama de trabajo
python3 herramientas/verificar.py promover --a estable   # publicar
```

Se niega si algo está en rojo, y también **si algo quedó sin comprobar**: meter
lo no verificado en el montón de lo aprobado es exactamente el error que este
repositorio lleva un mes persiguiendo.

Lo que exige cada salto:

| Promoción | Exige |
|---|---|
| → `testing` | suite completa, clippy, doctests, cargo-vet, coherencia de versiones |
| → `estable` | todo lo anterior **más** que la versión no esté ya publicada y que el árbol esté limpio |

## Lo que este modelo NO arregla

No convierte a `estable` en reproducible por sí sola: para eso hace falta la build
reproducible, que sigue pendiente (invariante I5). Y no sustituye a
`verificar.py publicado`, que es lo único que comprueba el **artefacto real** en
los índices — el `success` de un workflow ya mintió una vez.
