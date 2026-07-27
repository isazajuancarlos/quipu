<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas -->

# Hoja de ruta

Estado al **2026-07-27**, tras el recorte a un solo binding. Todo lo que sigue
está medido contra el repositorio, los índices de paquetes y la producción; nada
citado de memoria.

Esta lista es **exclusiva de Quipu**. El índice general de pendientes mezcla seis
proyectos y no sirve para trabajar aquí.

## Dónde estamos

| | |
|---|---|
| Publicado en | crates.io y PyPI (la versión, en `Cargo.toml`) |
| Pruebas | 244 en verde, 0 fallidas · 883 sumando todas las combinaciones de features |
| `unsafe` de primera parte | **0** en todo el repositorio |
| Superficies publicadas | 2 — crates.io y PyPI |
| Sitios de versión | 4, verificados por el CI en 5 segundos |
| Servidor OPRF en producción | 9 comprobaciones, 0 fallos |
| Clientes de pago | **0** |

El código está sano. El negocio no ha arrancado. Esas dos frases mandan sobre el
orden de todo lo que viene.

## Lo primero, y no es código

Nada de lo demás importa hasta que el dinero pueda entrar.

### 1. `xiliux.com` sin HSTS ni `nosniff`

Es el sitio que cobra con PayPal. Sin HSTS, la primera petición de un cliente
nuevo viaja en claro, que es exactamente donde se intercepta; el `301` no la
protege. Además `HEAD /` devuelve 405, así que un monitor estándar reportaría
caída la página de pago.

Son dos líneas de nginx. Requiere acceso al VPS.

### 2. Probar el camino del dinero de punta a punta

`PAYPAL_ENV` cae a `sandbox` por defecto. Un pago real tiene que disparar el
aprovisionamiento contra `quipu-oprf-server` y entregar la clave al cliente.
Mientras eso no esté comprobado, mejorar el producto es pulir algo que no puede
cobrar.

### 3. Desbloquear la publicación antes de necesitarla

- **`quipu-nucleo` no está en crates.io** y `quipu` depende de él por
  `path` + `version`. La próxima publicación fallará. Es la misma trampa que ya
  ocurrió con `quipu-voprf`, repetida al extraer el núcleo. Confirmar con
  `cargo publish --dry-run -p quipu`.
- **La rueda de `quipu-voprf` va una versión por detrás** del crate: 0.2.1 en
  PyPI contra 0.2.2 en crates.io. Y es el paquete que se le indica al cliente
  del SaaS, o sea el que más manos ajenas toca.

Descubrir esto en mitad de un release es cómo se perdió la 0.9.0.

## Lo que hace vendible y financiable el producto

### 4. Build reproducible — invariante I5

El único de los siete invariantes que está señalado y sin herramienta *y* que
además vale dinero. Permite que cualquiera compruebe que la rueda de PyPI salió
del código publicado. Es lo que mira un financiador tipo OTF, y lo que convierte
«confía en mí» en «compruébalo».

### 5. Auditoría independiente

`docs/PRE_AUDIT.md` deja el terreno preparado: primitivas vetadas, cero `unsafe`
propio, modelo de amenaza escrito. El recorte de julio redujo lo que hay que
auditar — ya no hay ABI de C ni cuatro envoltorios.

## Los invariantes sin vigilancia

De los siete del modelo de amenaza, dos no tienen herramienta continua y tres la
tienen a medias. Todos vienen del mismo sitio: el plan que los nombraba se cerró
como entregado porque el *documento* se entregó, y el documento era un mapa.

| | Estado | Falta |
|---|---|---|
| **I1** Ningún observable depende del secreto | parcial | dudect sistemático sobre cada ruta con secreto |
| **I3** Entropía fresca y nonce único | primer trozo hecho | el banco de `tests/simulacion.rs` mide colisiones de sal y nonce en 800 cifrados; falta el detector continuo y la batería estadística del RNG |
| **I4** El fallo no revela nada | parcial | verificador de uniformidad de errores |
| **I5** Procedencia verificada | parcial | build reproducible (punto 4) |

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

**Medición pendiente antes de elegir:** degradar como degrada una fotocopiadora
y comparar a igual área de papel. Nunca se hizo, y es el dato que decide.

### 7. Cifrado con negación

Honey no generaliza —su señuelo está atado a la distribución del secreto— pero
un contenedor con negación sí. Tres hallazgos verificados fijan el diseño.
Ahora es más barato que antes: solo hay que exponerlo en un binding.

### 8. El laboratorio no manda sobre nada

El red-team adaptativo mide, y lo que mide no alimenta ningún parámetro del
producto. Inteligencia sin mando.

### 9. La calidad del señuelo de honey no se mide

Honey vale lo que valga su señuelo **menos** convincente, y hoy eso no tiene
número. Mientras no lo tenga, el modo no debe extenderse a más superficies.

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
gestión, no código. Y el modelo de tres ramas está descrito en
[`RAMAS.md`](RAMAS.md), pendiente de crearlas.
