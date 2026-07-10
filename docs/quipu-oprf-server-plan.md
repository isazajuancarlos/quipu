# Plan: `quipu-oprf-server`

Servicio de producción que expone el endurecimiento OPRF/VOPRF de Quipu como una
API autenticada y medida. Separa el **plano de datos** (este servidor) del
**plano de control** (pagos vía portafolio + PayPal/Stripe).

## Decisiones bloqueadas

- **Cobro:** suscripción + cuota mensual (planes con N evaluaciones/mes).
- **Ubicación:** `crates/quipu-oprf-server` — workspace member abierto (AGPL).
- **Arranque:** construir ahora en **beta / lista de espera**; activación
  comercial (GA) tras la auditoría externa.

## Principio rector

- La **primitiva OPRF/VOPRF** (`src/oprf.rs`, `src/voprf.rs`) NO se separa: cliente
  y servidor comparten la MISMA implementación auditada. Su matemática es pública;
  ahí no está la ventaja comercial.
- El **servidor desplegable** (auth, API keys, medición, TLS, ops) SÍ se separa a
  este crate, que depende de `quipu`. La lib cripto queda ligera (sin tokio/HTTP).
- La lib abierta conserva el TCP de referencia (`src/oprf_net.rs`) para que los
  self-hosters AGPL corran su propio servidor. Lo que vende el SaaS es lo
  gestionado (disponibilidad, medición, cero-ops, SLA) + la licencia comercial.

## La costura con pagos

Pagos y OPRF se tocan en UN solo punto: el **almacén de API keys**.

- Pagos (portafolio + webhook PayPal/Stripe) **escribe**: crea/activa/revoca keys.
- El servidor **lee**: valida la key en cada petición.

Se puede cambiar de pasarela sin tocar el servidor.

## Modelo de datos (SQLite)

```
customer(id, email, plan, created_at, provider_ref)
api_key(id, customer_id, prefix, key_hash, active, quota_monthly,
        expires_at, created_at, last_used_at, revoked_at)
usage(key_id, period, count)          -- period = "YYYY-MM"
```

- **Formato de key:** `quipu_live_<32B base58>`. Se muestra UNA vez.
- Se guarda **solo el hash** (SHA-256) + `prefix` (búsqueda O(1) sin exponer el
  secreto). Robar la BD no da keys usables.

### Ciclo de vida (disparado por webhook, no a mano)

| Evento de pago        | Acción en el almacén                       |
|-----------------------|--------------------------------------------|
| Alta / pago exitoso   | crear customer + api_key (`active=true`)   |
| Renovación            | reset `usage.count` del periodo            |
| Pago falla / cancela  | `api_key.active = false`                   |
| Rotación              | key nueva; `revoked_at` en la vieja        |

## Ciclo de una petición

```
Authorization: Bearer quipu_live_… + punto cegado (32B)
  1. prefix -> buscar api_key
  2. verificar hash
  3. active? no-expirada? usage < quota?     -> 401/403/429
  4. rate-limit de ráfaga (token bucket/key) -> 429
  5. voprf::Server::evaluate(blinded)        <- primitiva de la lib
  6. usage.count += 1 ; last_used_at = now
  -> evaluación (32B) + prueba DLEQ (VOPRF)
```

## Endpoints (HTTP tras TLS de proxy)

| Método | Ruta                  | Para qué                         | Auth    |
|--------|-----------------------|----------------------------------|---------|
| POST   | `/v1/oprf/evaluate`   | evaluación (hot path)            | API key |
| GET    | `/v1/public-key`      | clave pública para *pinning*     | pública |
| GET    | `/healthz`            | health check                     | interna |

Crear/revocar keys NO es endpoint público: lo hace el webhook o un CLI de admin
sobre el almacén (menos superficie de ataque).

## Rate-limit y medición (dos niveles)

- **Ráfaga** (anti-DoS): token bucket por key (p. ej. 10 req/s).
- **Cuota** (facturación): `usage.count` mensual vs `quota_monthly`; al 100% ->
  429 hasta el próximo periodo o upgrade.

Reemplaza el `max_requests` global crudo de `oprf::Server` por control por-key.

## Protección

**Se añade en el servidor:**
- API key obligatoria (hash en BD, nunca en claro).
- TLS en el proxy; solo `:443`; non-root; sandboxing systemd.
- Rate-limit ráfaga + cuota; logging sin secretos.

**Ya en la cripto (ventaja):**
- Blinding: brecha del VPS NO filtra contraseñas ni claves de clientes.
- Rate-limit = propósito del OPRF: mata el brute-force offline.
- DLEQ + clave pública fijada: el cliente detecta servidor suplantado.
- Custodia del **seed de `k`** (chmod 600 / secrets manager, nunca en git).
  `from_seed` garantiza que reiniciar no rompe secretos endurecidos.

**Rotación:** las API keys rotan libres; la clave OPRF `k` es de larga vida y no
se rota salvo incidente (rotarla rompería todos los secretos endurecidos).

## Stack técnico

| Pieza        | Elección                    | Por qué                              |
|--------------|-----------------------------|--------------------------------------|
| HTTP         | `tiny_http` (sync)          | lean, sin runtime async; QPS bajo    |
| Almacén      | `rusqlite` (SQLite)         | un VPS, poca escritura, cero-ops     |
| Hash de key  | `sha2` (ya en el árbol)     | sin sumar deps                       |
| Random       | `getrandom` (ya en árbol)   | keys y seed                          |

`tiny_http` + `rusqlite` mantienen el crate ligero; el tráfico está limitado por
diseño (rate-limit), así que no hace falta async. TLS lo pone Nginx/Caddy delante.

## Milestones

- **M1 ✅ Andamiaje + almacén de usuarios**: crate en el workspace, modelo de
  datos SQLite (`store.rs`), generación/verificación de API keys (`keys.rs`),
  CLI de admin, tests.
- **M2 ✅ Servidor HTTP** (`http.rs`): `/healthz`, `/v1/public-key`,
  `/v1/oprf/evaluate` con auth + rate-limit (`ratelimit.rs`) + medición sobre
  `voprf::Server`.
- **M3 ✅ Provisión**: endpoints `/admin/*` (la costura con la pasarela) + CLI de
  admin; despliegue systemd + Nginx en `deploy/`.
- **M4 ✅ Cliente de referencia + bindings**: `examples/client.rs` (Rust) y
  portado a **Python** (`quipu.voprf_blind/finalize` + `examples/oprf_client.py`),
  **Node** (`voprfBlind/voprfFinalize/oprfHarden` + `examples/oprf-client.mjs`) y
  **Go** (`VoprfBlind/VoprfFinalize/OprfHarden` en `bindings/go/oprf.go`). El C ABI
  expone `quipu_voprf_blind/finalize`; el core añade `BlindState::to_bytes/from_bytes`.

> Nota: implementado y autorevisado, pero **sin compilar en este entorno** (no
> hay `cargo`). Ejecutar `cargo test -p quipu-oprf-server` antes de desplegar.

## Fases de negocio

1. **Fase 0 (ahora):** M1–M4 en modo beta/lista de espera. Maquinaria lista sin
   prometer producción.
2. **Fase 1 (post-audit):** GA con SLA. Solo entonces se abre comercialmente.
