# quipu-oprf-server

Plano de datos del endurecimiento OPRF/VOPRF de Quipu: expone la primitiva
`voprf::Server` como una API HTTP autenticada por **API key** y medida por
**cuota mensual**. Separado del plano de control (pagos vía portafolio +
PayPal/Stripe), con el que solo comparte el **almacén de API keys**.

Diseño completo: [`docs/quipu-oprf-server-plan.md`](../../docs/quipu-oprf-server-plan.md).

> **Estado: beta.** M1–M4 implementados (almacén, servidor HTTP, admin, cliente).
> La activación comercial (GA) espera la auditoría externa.

## Construir y testear

```sh
cargo test -p quipu-oprf-server        # unitarios + integración e2e (Rust puro)
cargo build -p quipu-oprf-server --release
```

Requiere un compilador de C (SQLite se compila con `rusqlite` feature `bundled`).

### Capas de prueba

1. **Unitarios** (`src/*.rs`): keys, store (cuota/revocación/expiración), rate-limit,
   hex, planes.
2. **Integración e2e** (`tests/e2e.rs`): levanta el servidor en un hilo, emite una
   key y corre el cliente completo (blind → HTTP → finalize), comparando con un
   cálculo VOPRF independiente y comprobando el rechazo con clave pública errónea.
   Autocontenido: `cargo test -p quipu-oprf-server`, sin servidor previo.
3. **Cross-lenguaje** (`scripts/oprf-e2e.sh`, desde la raíz del repo): construye el
   C ABI + el servidor, lo arranca, emite una key y corre el cliente de **Rust,
   Python, Node y Go** contra él. Best-effort: salta el lenguaje cuyo toolchain
   falte. Los smoke tests offline del FFI están en `bindings/{go/oprf_test.go,
   node/test/oprf.test.mjs}`.

## Arrancar el servidor

```sh
export QUIPU_OPRF_DB=/var/lib/quipu/oprf.db
export QUIPU_OPRF_SEED=$(openssl rand -hex 32)          # PERSISTIR (ver abajo)
export QUIPU_OPRF_ADMIN_TOKEN=$(openssl rand -hex 32)   # para /admin
quipu-oprf-server serve 127.0.0.1:8787
```

- **El seed es crítico:** deriva la clave OPRF `k`. Si cambia, TODOS los secretos
  endurecidos de los clientes dejan de reproducirse. Guárdalo (chmod 600) y no lo
  rotes salvo incidente. Sin seed, el servidor usa una clave **efímera** (solo dev).
- TLS lo pone un proxy delante (ver `deploy/nginx.conf.example`). El servicio
  escucha solo en localhost.

## Endpoints

| Método | Ruta | Auth | Descripción |
|--------|------|------|-------------|
| GET  | `/healthz` | — | health check |
| GET  | `/v1/public-key` | — | `{"public_key":"<64hex>"}` para *pinning* |
| POST | `/v1/oprf/evaluate` | `Authorization: Bearer <key>` | body = punto cegado (64 hex) → `{"evaluation":"..","proof":".."}` |
| POST | `/admin/keys` | `X-Admin-Token` | form `email=..&plan=..` → emite key |
| POST | `/admin/keys/<prefix>/{activate,deactivate,revoke}` | `X-Admin-Token` | conmuta estado |

```sh
# Evaluación (lo que hace el cliente):
curl -s https://oprf.tudominio.com/v1/oprf/evaluate \
  -H "Authorization: Bearer quipu_live_..." \
  --data-binary "<punto-cegado-64-hex>"
```

## La costura con pagos (M3)

La pasarela vive en tu portafolio. Tras verificar un pago (PayPal/Stripe), el
backend del portafolio llama a `/admin/*` con `X-Admin-Token`:

```sh
# Alta / pago exitoso -> emitir key (devuelve la key UNA vez):
curl -s https://oprf.tudominio.com/admin/keys \
  -H "X-Admin-Token: $ADMIN" --data "email=cliente@empresa.com&plan=pro"

# Pago falla / cancela -> desactivar al instante:
curl -s -X POST https://oprf.tudominio.com/admin/keys/quipu_live_ab12cd34ef56/deactivate \
  -H "X-Admin-Token: $ADMIN"
```

`/admin/*` **no** debe exponerse a Internet: restríngelo a la IP del portafolio
(ver el bloque `location /admin/` del ejemplo de Nginx).

## CLI de administración (alternativa manual)

```sh
quipu-oprf-server init
quipu-oprf-server issue cliente@empresa.com pro   # imprime la API key UNA vez
quipu-oprf-server deactivate quipu_live_ab12cd34ef56
quipu-oprf-server activate   quipu_live_ab12cd34ef56
quipu-oprf-server revoke     quipu_live_ab12cd34ef56
```

Planes (evaluaciones/mes): `beta` 10 000 · `starter` 100 000 · `pro` 1 000 000.

## Cliente de referencia (M4)

```sh
QUIPU_OPRF_ADDR=127.0.0.1:8787 \
QUIPU_OPRF_API_KEY=quipu_live_... \
cargo run -p quipu-oprf-server --example client -- "mi-contraseña"
```

Hace el flujo verificable completo: `blind` → POST `/v1/oprf/evaluate` →
`finalize` (VERIFICA la prueba DLEQ contra la clave pública fijada) → secreto
endurecido. En producción, **fija** la clave pública fuera de banda
(`QUIPU_OPRF_PUBKEY`) en vez de pedirla al servidor.

## Instancia pública (beta)

```
endpoint    https://oprf.xiliux.com
clave pub   f84ef4132b8351921eda4f841ec2cf7aacb23fd3c93ac6118b48dfc4babaa16f
```

**Fija esa clave pública en tu cliente desde aquí, no desde `/v1/public-key`.**
Pedírsela al servidor anula la garantía: la prueba DLEQ solo demuestra que el
servidor usó la clave `k` correspondiente a la clave pública que TÚ fijaste. Un
servidor comprometido que además elige la clave contra la que se le verifica
puede responder lo que quiera sin ser detectado.

## Despliegue

- `deploy/quipu-oprf-server.service` — unidad systemd endurecida (sandbox,
  secretos vía `EnvironmentFile` con chmod 600).
- `deploy/nginx.conf.example` — TLS + rate-limit + protección de `/admin`.

## Seguridad

- Las keys se guardan como `prefix` + `SHA-256(secreto)`; comparación en tiempo
  constante. Robar la BD no da keys usables.
- **Blinding:** una brecha del VPS NO filtra contraseñas ni claves de clientes.
- Rate-limit de ráfaga (token bucket por key) + cuota mensual.
- La clave OPRF `k` vive solo en el VPS (seed protegido); reiniciar con el mismo
  seed no rompe los secretos endurecidos.
