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
| Pruebas | 270 en verde, 0 fallidas (`cargo test --workspace --all-targets`, 2026-07-31) · 883 sumando todas las combinaciones de features, medido antes y no vuelto a medir |
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

### 3. Desbloquear la publicación antes de necesitarla — **HECHO el 2026-07-27**

Los dos bloqueos que este punto describía están cerrados, y se comprueba en los
índices, no en el recuerdo:

- **`quipu-nucleo` ya está en crates.io**, así que la dependencia por
  `path` + `version` de `quipu` sobre él no volverá a tumbar un release.
- **La rueda de `quipu-voprf` alcanzó al crate**: misma versión en PyPI y en
  crates.io, y es el paquete que se le indica al cliente del SaaS.
- Queda fuera del índice el perfil `quipu-cnsa`, y no bloquea a nadie: no es
  dependencia de `quipu`.

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

**Medición pendiente antes de elegir:** degradar como degrada una fotocopiadora
y comparar a igual área de papel. Nunca se hizo, y es el dato que decide.

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
KDF, porque hacen falta para derivar la clave que la abriría. **Esa es la decisión
que bloquea el código**, y está planteada con recomendación en el §5 del diseño.

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
gestión, no código. Lo que sí es código —y no está decidido— es si ese perfil se
queda en cifrado simétrico o crece a firma y KEM: hoy implementa AES-256-GCM y
HKDF-SHA-384, y su README declara que ML-DSA-87 y ML-KEM-1024 no están.

El modelo de tres ramas está descrito en [`RAMAS.md`](RAMAS.md) y **ya no está
pendiente**: `estable`, `testing` y `desarrollo` existen, y las dos primeras
tienen `enforce_admins` activo.

Y una asimetría que había entre lo escrito y lo configurado, corregida el
2026-07-27: `RAMAS.md` promete que a `estable` se le exija «todo lo anterior
**más**», pero en GitHub `testing` requería el check «coherencia de versiones» y
`estable` no. La rama publicada tenía la puerta más floja que la candidata. Los
cuatro checks son ya los mismos en las dos. Se comprueba así, y no leyendo esta
frase:

```bash
gh api repos/isazajuancarlos/quipu/branches/estable/protection \
  -q '.required_status_checks.contexts'
```
