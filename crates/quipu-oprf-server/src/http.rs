// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Servidor HTTP (M2 + costura de admin M3).
//!
//! Endpoints públicos:
//!   GET  /healthz            -> "ok"
//!   GET  /v1/public-key      -> {"public_key":"<64hex>"}  (para *pinning*)
//!   POST /v1/oprf/evaluate   -> {"evaluation":"..","proof":".."}  (API key)
//!
//! Endpoints de admin (requieren cabecera `X-Admin-Token`, la costura con la
//! pasarela de pagos; deshabilitados si no se configura el token):
//!   POST /admin/keys                        (form: email, plan) -> emite key
//!   POST /admin/keys/<prefix>/activate
//!   POST /admin/keys/<prefix>/deactivate
//!   POST /admin/keys/<prefix>/revoke
//!
//! Servidor de un solo hilo: el tráfico está limitado por diseño (rate-limit +
//! cuota), así que serializar peticiones es correcto y evita compartir la
//! conexión SQLite (`Store` es `!Sync`). TLS lo pone un proxy (Nginx/Caddy).

use std::io::{self, Cursor};

use quipu::voprf;
use subtle::ConstantTimeEq;
use tiny_http::{Header, Method, Request, Response, Server};

use crate::hexutil::{from_hex_32, to_hex};
use crate::plans::quota_for;
use crate::ratelimit::RateLimiter;
use crate::store::{AuthResult, Store};

type Resp = Response<Cursor<Vec<u8>>>;

pub struct Config {
    pub addr: String,
    pub admin_token: Option<String>,
    pub rate_capacity: f64,
    pub rate_refill_per_sec: f64,
}

pub fn serve(store: Store, server_key: voprf::Server, cfg: Config) -> io::Result<()> {
    let http = Server::http(cfg.addr.as_str())
        .map_err(|e| io::Error::other(e.to_string()))?;
    let public_key_hex = to_hex(&server_key.public_key());
    let mut limiter = RateLimiter::new(cfg.rate_capacity, cfg.rate_refill_per_sec);

    eprintln!("quipu-oprf-server escuchando en http://{}", cfg.addr);
    eprintln!("clave pública (pinnear en el cliente): {public_key_hex}");
    if cfg.admin_token.is_none() {
        eprintln!("ℹ️  Sin QUIPU_OPRF_ADMIN_TOKEN: endpoints /admin deshabilitados.");
    }

    for mut request in http.incoming_requests() {
        let resp = route(
            &mut request,
            &store,
            &server_key,
            &public_key_hex,
            &cfg,
            &mut limiter,
        );
        let _ = request.respond(resp);
    }
    Ok(())
}

fn route(
    req: &mut Request,
    store: &Store,
    server_key: &voprf::Server,
    public_key_hex: &str,
    cfg: &Config,
    limiter: &mut RateLimiter,
) -> Resp {
    let method = req.method().clone();
    let path = req.url().split('?').next().unwrap_or("").to_string();

    match (&method, path.as_str()) {
        (Method::Get, "/healthz") => text(200, "ok"),
        (Method::Get, "/v1/public-key") => {
            json(200, format!("{{\"public_key\":\"{public_key_hex}\"}}"))
        }
        (Method::Post, "/v1/oprf/evaluate") => evaluate(req, store, server_key, limiter),
        (Method::Post, "/admin/keys") => admin_issue(req, store, cfg),
        (Method::Post, p) if p.starts_with("/admin/keys/") => {
            admin_action(req, cfg, store, p.to_string())
        }
        _ => text(404, "not found"),
    }
}

fn evaluate(
    req: &mut Request,
    store: &Store,
    server_key: &voprf::Server,
    limiter: &mut RateLimiter,
) -> Resp {
    let bearer = match header_value(req, "Authorization")
        .and_then(|v| v.strip_prefix("Bearer ").map(str::to_string))
    {
        Some(b) => b,
        None => return text(401, "falta Authorization: Bearer <api_key>"),
    };
    let mut body = String::new();
    if req.as_reader().read_to_string(&mut body).is_err() {
        return text(400, "cuerpo ilegible");
    }
    let blinded = match from_hex_32(body.trim()) {
        Some(b) => b,
        None => return text(400, "el cuerpo debe ser el punto cegado en 64 hex"),
    };

    match store.verify(&bearer) {
        Ok(AuthResult::Valid { key_id, .. }) => {
            if !limiter.allow(&key_id) {
                return text(429, "rate limit de ráfaga");
            }
            match server_key.blind_evaluate(&blinded) {
                Some((eval, proof)) => {
                    let _ = store.record_usage(&key_id);
                    json(
                        200,
                        format!(
                            "{{\"evaluation\":\"{}\",\"proof\":\"{}\"}}",
                            to_hex(&eval),
                            to_hex(&proof)
                        ),
                    )
                }
                None => text(400, "punto cegado inválido"),
            }
        }
        Ok(AuthResult::Unknown) => text(401, "api key inválida"),
        Ok(AuthResult::Inactive) => text(403, "api key inactiva"),
        Ok(AuthResult::Expired) => text(403, "api key expirada"),
        Ok(AuthResult::QuotaExceeded) => text(429, "cuota mensual agotada"),
        Err(_) => text(500, "error de almacén"),
    }
}

fn admin_issue(req: &mut Request, store: &Store, cfg: &Config) -> Resp {
    if !admin_ok(cfg, header_value(req, "X-Admin-Token").as_deref()) {
        return text(401, "no autorizado");
    }
    let mut body = String::new();
    if req.as_reader().read_to_string(&mut body).is_err() {
        return text(400, "cuerpo ilegible");
    }
    let email = match form_get(&body, "email") {
        Some(e) if !e.is_empty() => e,
        _ => return text(400, "falta email"),
    };
    let plan = form_get(&body, "plan").unwrap_or_else(|| "beta".to_string());
    let quota = match quota_for(&plan) {
        Some(q) => q,
        None => return text(400, "plan desconocido"),
    };
    let customer = match store.create_customer(&email, &plan) {
        Ok(c) => c,
        Err(_) => return text(500, "error creando cliente"),
    };
    match store.issue_key(&customer, quota, None) {
        Ok(k) => json(
            200,
            format!(
                "{{\"customer\":\"{customer}\",\"prefix\":\"{}\",\"api_key\":\"{}\"}}",
                k.prefix, k.secret
            ),
        ),
        Err(_) => text(500, "error emitiendo key"),
    }
}

fn admin_action(req: &mut Request, cfg: &Config, store: &Store, path: String) -> Resp {
    if !admin_ok(cfg, header_value(req, "X-Admin-Token").as_deref()) {
        return text(401, "no autorizado");
    }
    // path = /admin/keys/<prefix>/<action>
    let rest = path.trim_start_matches("/admin/keys/");
    let mut parts = rest.splitn(2, '/');
    let prefix = parts.next().unwrap_or("");
    let action = parts.next().unwrap_or("");
    let result = match action {
        "activate" => store.set_active(prefix, true),
        "deactivate" => store.set_active(prefix, false),
        "revoke" => store.revoke(prefix),
        _ => return text(404, "acción desconocida"),
    };
    match result {
        Ok(n) => json(200, format!("{{\"updated\":{n}}}")),
        Err(_) => text(500, "error de almacén"),
    }
}

fn admin_ok(cfg: &Config, presented: Option<&str>) -> bool {
    match (&cfg.admin_token, presented) {
        (Some(expected), Some(got)) => {
            expected.as_bytes().ct_eq(got.as_bytes()).unwrap_u8() == 1
        }
        _ => false, // sin token configurado -> admin deshabilitado
    }
}

fn header_value(req: &Request, name: &'static str) -> Option<String> {
    req.headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str().to_string())
}

fn form_get(body: &str, key: &str) -> Option<String> {
    for pair in body.split('&') {
        let mut it = pair.splitn(2, '=');
        if it.next() == Some(key) {
            return Some(it.next().unwrap_or("").to_string());
        }
    }
    None
}

fn text(status: u16, msg: &str) -> Resp {
    Response::from_string(msg.to_string()).with_status_code(status)
}

fn json(status: u16, body: String) -> Resp {
    let ct = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
    Response::from_string(body)
        .with_status_code(status)
        .with_header(ct)
}
