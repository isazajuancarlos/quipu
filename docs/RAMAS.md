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
| **`main`** | Lo **publicado**. Los tags `v*` se cortan aquí. | Solo `testing`, al publicar. Y las correcciones urgentes. | **Nunca** |
| **`testing`** | Candidata a la próxima versión: integrada y verde. | Ramas de característica, por PR. | **Nunca** |
| **`desarrollo`** | Trabajo en curso. | Empuje directo. | Sí, y no pasa nada |

### Por qué `main` es la estable y no se renombra

Podría haberse llamado `estable`. No se hace, y la razón no es la pereza:

- `main` es la rama **por defecto** del repositorio, y lo que ve quien llega es
  lo que debería poder instalar. En una librería que vende confianza, la portada
  tiene que describir lo que da `cargo add quipu`, no lo que habrá dentro de tres
  semanas.
- Renombrarla movería la base de todos los PR, los enlaces externos y la
  protección ya configurada con sus tres comprobaciones obligatorias.
- El nombre no aporta nada que el papel no aporte ya. Renombrar por simetría con
  Debian sería cambiar algo que funciona para que se parezca a un diagrama.

## El recorrido

```
  rama de característica ──PR──►  testing  ──promoción──►  main  ──tag──►  publicado
                                     ▲
        desarrollo ──────────────────┘
        (trabajo en curso, puede romperse)
```

1. Una característica nueva sale de `testing`, vive en su rama, y vuelve por PR.
2. Cuando `testing` está lista, se **promueve** a `main`.
3. El tag se pone en `main`, y **poner el tag es publicar**.

`desarrollo` es para lo que aún no merece un PR: pruebas de concepto, mediciones,
lo que se va a tirar. Nada baja de `desarrollo` a `main` sin pasar por `testing`.

## La promoción no se hace a mano

Aquí está la parte que decide si esto sirve o se pudre. **En Debian, quien migra
paquetes de `unstable` a `testing` es un robot**, con reglas: diez días sin
fallos críticos, dependencias satisfacibles. Sin ese robot, `testing` es solo una
rama que alguien tiene que acordarse de fusionar — y acordarse no escala.

El robot de aquí es:

```bash
python3 herramientas/verificar.py promover --a testing   # desde una rama de trabajo
python3 herramientas/verificar.py promover --a main      # publicar
```

Se niega si algo está en rojo, y también **si algo quedó sin comprobar**: meter
lo no verificado en el montón de lo aprobado es exactamente el error que este
repositorio lleva un mes persiguiendo.

Lo que exige cada salto:

| Promoción | Exige |
|---|---|
| → `testing` | suite completa, clippy, doctests, cargo-vet, coherencia de versiones |
| → `main` | todo lo anterior **más** que la versión no esté ya publicada y que el árbol esté limpio |

## Lo que este modelo NO arregla

No convierte a `main` en reproducible por sí sola: para eso hace falta la build
reproducible, que sigue pendiente (invariante I5). Y no sustituye a
`verificar.py publicado`, que es lo único que comprueba el **artefacto real** en
los índices — el `success` de un workflow ya mintió una vez.
