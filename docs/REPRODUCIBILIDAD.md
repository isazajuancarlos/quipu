<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas
-->

# Reconstruir los artefactos de Quipu (invariante I5)

Sirve para una sola cosa, y es la que importa: que **no tengas que creerte** que
la rueda de PyPI salió del código que hay en este repositorio. La reconstruyes y
comparas los bytes.

## La receta

```bash
git checkout "$TAG"        # el tag que quieras verificar; `git tag -l 'v*'` los lista

export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
export RUSTFLAGS="--remap-path-prefix=$HOME/.cargo/registry/src=/cargo \
                  --remap-path-prefix=$PWD=/build"

maturin build --release --out dist
sha256sum dist/*.whl
```

Compara ese sha256 con el de PyPI. Si coincide, el artefacto publicado es ese
código y no otro.

## Por qué hacen falta esas dos variables

Se midió el 2026-07-31, construyendo dos veces seguidas en la misma máquina y
comparando byte a byte:

| Artefacto | ¿Se reconstruye igual? | Qué lo impedía |
|---|---|---|
| `.crate` (fuente) | **Sí, y ya lo era** | nada — cargo normaliza las mtime a una época fija y uid/gid a 0/0 |
| `quipu.abi3.so` | **Sí, y ya lo era** | nada — el compilador ya era determinista |
| Rueda completa | **No** | dos campos del SBOM |

La sorpresa fue que el compilador nunca fue el problema. Lo único no
determinista de la rueda eran dos campos del SBOM CycloneDX que maturin escribe
en el `dist-info`: un `serialNumber` con un UUID aleatorio y un `timestamp` de
reloj de pared. El `RECORD` cambiaba solo porque hashea el SBOM.

- **`SOURCE_DATE_EPOCH`** fija esos dos campos. Se toma de la fecha del **commit**,
  no de `now`: así el artefacto se deriva del código y no del momento en que se
  construyó, que es exactamente lo que I5 promete.
- **`RUSTFLAGS` con `--remap-path-prefix`** quita las rutas absolutas de tu
  máquina. Sin él, el `.so` lleva dentro decenas de cadenas
  `/home/<tu-usuario>/.cargo/registry/...` —vienen de los metadatos de `panic`—
  y en otra máquina eso son otros bytes. Con el remap desaparecen todas.

`[profile.release] trim-paths = "all"` haría lo mismo de forma más limpia, pero
**no está estabilizado** en cargo 1.97.1 (comprobado, no supuesto: el manifiesto
se rechaza). Cuando se estabilice, sustituye al `RUSTFLAGS`.

## Qué está comprobado y qué no

Lo honesto por delante, porque una promesa de reproducibilidad que se pasa de
frenada es peor que no darla.

**Comprobado.** El CI reconstruye la rueda dos veces en el mismo commit y exige
el mismo sha256 (`rueda de Python`), y además verifica que el binario no lleve
rutas de la máquina que lo construyó. Los dos checks se probaron contra una rueda
deliberadamente construida sin el remap: ahí se ponen rojos. Un check que nunca
dice que no, no dice nada.

**No comprobado todavía.** Que la rueda **manylinux publicada** sea bit a bit
reconstruible. El CI construye con `maturin build` sobre `ubuntu-latest`, y
`release.yml` construye con `maturin-action` y `manylinux: auto`, o sea dentro de
un contenedor distinto. Lo que hay hoy caza el no-determinismo de origen —el
SBOM, las rutas, cualquier fuente que se cuele en el código—, pero demostrar lo
otro exige rehacer el artefacto publicado **en su mismo contenedor** y comparar.
Ese es el trabajo que le queda a I5.

Tampoco se ha verificado desde una segunda máquina física: aquí solo hay una. Lo
que sí se hizo fue neutralizar las dos entradas dependientes de la máquina que se
sabían presentes (rutas y reloj). Quedan fuera, y hay que fijarlas aparte, la
**versión exacta del compilador** y la del `manylinux` de destino.

## Si no te cuadran los bytes

No es necesariamente un ataque, y antes de dar la alarma conviene descartar lo
aburrido: distinta versión de `rustc`, distinta de `maturin`, o haber olvidado
alguna de las dos variables. Si tras igualar eso sigue sin cuadrar, escribe a la
dirección de `SECURITY.md`.
