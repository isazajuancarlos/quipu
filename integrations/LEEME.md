<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# `integrations/` — aquí ya no hay ninguna integración, y es a propósito

Había una: `integrations/django`, un password hasher para Django que endurecía
las contraseñas con el OPRF de Quipu. Se retiró el **2026-08-17**, junto con
`examples/oprf_client.py`, que hacía lo mismo desde la línea de órdenes.

## Por qué

Los dos clientes importaban `quipu_voprf`, un binding PyO3 de Rust a Python que
se **retiró el 14 de agosto** al dejar Quipu en Rust puro (commit `c22afc9`,
−120 551 líneas: la rueda de PyO3 era la dependencia más pesada del árbol). Desde
ese día llamaban a funciones que ya no existen. Es decir: llevaban tres días
rotos.

Y no se vio antes porque **sus pruebas monkeypatcheaban la criptografía**: el
`conftest.py` sustituía `quipu_voprf` por un módulo de mentira en todas las
pruebas, así que pasaban en verde con la librería presente y con la librería
borrada. Nunca ejercitaron el producto. Lo encontró una auditoría el 17.

Se retiran en vez de reescribirse porque **nadie los consumía** —las ruedas de
PyPI están yanked desde el 10 de agosto, y el origen es local— y reescribirlos
metía una dependencia nueva por una vía hipotética. Mantener código roto «por si
acaso» es diseñar para el caso que no ha llegado.

## Si algún día hace falta un cliente en Python

La dirección está decidida: **Quipu se queda en Rust; un derivado que por su
finalidad deba ser Python se escribe en Python, no como binding PyO3.** Pero
«Python puro» tiene un límite medido el 2026-08-17: el cliente VOPRF necesita
operaciones sobre **ristretto255** (cegado, descegado, verificación de la prueba
DLEQ, todas en el cliente), y **no existe una librería de ristretto255 pura y
vetada en el ecosistema Python**. Las dos únicas vías son:

1. **`libsodium` del sistema** (con ristretto255, vía `pysodium`/`ctypes`) — es
   criptografía vetada, es un `pip install` normal, y es la vía correcta. El
   coste es un requisito de despliegue: el entorno tiene que traer
   libsodium ≥ 1.0.18.
2. Portar ristretto255 a Python — que viola la regla de oro de Quipu («nunca
   inventar primitivas»). Esta **no**.

O sea que cuando se escriba, será opción 1, y se validará byte a byte contra los
vectores del RFC 9497 que ya están en `crates/quipu-voprf/tests/rfc9497_vectors.rs`.

## Mientras tanto, el cliente de referencia es el de Rust

`crates/quipu-oprf-server/examples/client.rs` muestra el flujo completo —blind →
evaluate → finalize— y **ancla la clave pública fuera de banda**, que es la
propiedad que de verdad importa (verificar la prueba DLEQ contra una clave que da
el propio servidor no comprueba nada). El cliente de Django era, irónicamente, el
único que lo hacía bien; esa lección se conserva ahí.
