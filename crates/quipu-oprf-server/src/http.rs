// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

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
}

pub fn serve(store: Store, server_key: voprf::Server, cfg: Config) -> io::Result<()> {
    let http = Server::http(cfg.addr.as_str())
        .map_err(|e| io::Error::other(e.to_string()))?;
    let public_key_hex = to_hex(&server_key.public_key());
    let mut limiter = RateLimiter::new();

    // La dirección REAL, no la pedida. Con `:0` el sistema asigna un puerto
    // efímero y `cfg.addr` seguiría diciendo «127.0.0.1:0», que no sirve para
    // conectarse ni para saber dónde quedó el proceso. Se vio montando la
    // prueba de restauración del seed, que arranca en un puerto libre.
    let escuchando = http
        .server_addr()
        .to_ip()
        .map(|a| a.to_string())
        .unwrap_or_else(|| cfg.addr.clone());
    eprintln!("quipu-oprf-server escuchando en http://{escuchando}");
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

    // HEAD SE ENRUTA COMO GET.
    //
    // RFC 9110 §9.3.2: la respuesta a HEAD debe ser idéntica a la de GET salvo
    // por el cuerpo. Aquí no lo era: HEAD no encajaba en ninguna rama y caía al
    // 404 final, así que `HEAD /healthz` devolvía 404 mientras `GET /healthz`
    // devolvía 200.
    //
    // No es cosmético. HEAD es lo que usan los monitores de disponibilidad, así
    // que el servicio venía con su propia sonda mintiendo: un monitor estándar
    // lo habría dado por caído desde el primer día — o, peor, alguien habría
    // ajustado el monitor para aceptar el 404 y entonces no avisaría cuando se
    // cayera de verdad. Es el invariante I7: la superficie desplegada tiene que
    // poder responder por sí misma.
    //
    // Detectado el 2026-07-27 auditando producción con `verificar.py desplegado`.
    let ruta = if method == Method::Head {
        Method::Get
    } else {
        method
    };

    match (&ruta, path.as_str()) {
        (Method::Get, "/healthz") => text(200, "ok"),
        (Method::Get, "/v1/public-key") => {
            json(200, format!("{{\"public_key\":\"{public_key_hex}\"}}"))
        }
        (Method::Get, "/v1/plans") => json(200, plans_json()),
        (Method::Post, "/v1/oprf/evaluate") => evaluate(req, store, server_key, limiter),
        (Method::Post, "/admin/keys") => admin_issue(req, store, cfg),
        (Method::Post, p) if p.starts_with("/admin/keys/") => {
            admin_action(req, cfg, store, p.to_string())
        }
        _ => text(404, "not found"),
    }
}

/// Catálogo de planes tal como los aplica ESTE servidor.
///
/// Existe para que quien vende pueda comprobar que vende lo que aquí se
/// concede. El caso real: la web anunciaba 250 000 evaluaciones para `starter`
/// mientras el servidor otorgaba 100 000 — el 40 % de lo pagado, y como el SDK
/// falla cerrado, el cliente lo habría descubierto con sus usuarios sin poder
/// entrar. Publicarlo convierte un descuadre silencioso en algo comprobable.
///
/// Es información de producto, no secreta: son los límites que el cliente compra.
fn plans_json() -> String {
    let items: Vec<String> = crate::plans::PLANS
        .iter()
        .map(|p| {
            format!(
                "{{\"name\":\"{}\",\"quota_monthly\":{},\"rate_capacity\":{},\
                 \"rate_refill_per_sec\":{}}}",
                p.name, p.quota_monthly, p.rate_capacity, p.rate_refill_per_sec
            )
        })
        .collect();
    format!("{{\"plans\":[{}]}}", items.join(","))
}

/// Cuerpo máximo que este servidor materializa en memoria. 64 KiB son dos órdenes
/// de magnitud sobre cualquier cuerpo legítimo —un punto cegado en 64 hex, o un
/// form de alta `email`+`plan`—, así que no recorta nada real (directiva 21).
const MAX_CUERPO: u64 = 64 * 1024;

/// Lee el cuerpo con el tope de [`MAX_CUERPO`]. `None` si es ilegible o se pasa.
///
/// **Qué ACOTA y qué NO —medido con el concilio, no supuesto (D16):**
///
/// - Lo que garantiza: **la `String` que construimos nunca pasa de 64 KiB**. Esto
///   importa DE VERDAD para un cuerpo `Transfer-Encoding: chunked`, donde
///   `tiny_http` NO conoce la longitud y sin el `.take` un `read_to_string`
///   acumularía sin techo lo que el otro lado decida enviar.
/// - Lo que **NO** garantiza, y por qué NO se puede aquí: para un cuerpo con
///   `Content-Length`, `tiny_http` envuelve el socket en un `EqualReader` cuyo
///   `Drop` **drena el remanente declarado con una sola asignación**
///   (`vendor/tiny_http/.../equal_reader.rs`: `vec![0; content_length − leídos]`).
///   Un `Content-Length: 9e12` con cuerpo corto revienta el proceso al soltar el
///   `Request`, LEA LO QUE LEA este helper (leer menos deja MÁS por drenar). Eso
///   es de `tiny_http`, precede a este cambio, y **no es defendible desde el
///   handler**: el control contra un `Content-Length` declarado gigante es el
///   **`client_max_body_size 32k` de Nginx** (`despliegue/oprf.xiliux.com.nginx`),
///   que rechaza la cabecera en el borde. Es un control **REQUERIDO**, no un
///   extra —quien despliegue este binario directo lo debe replicar—.
///
/// Cuando corta por tamaño, DRENA el resto del cuerpo antes de devolver `None`.
/// Sin eso, el residuo queda en la conexión y en keep-alive corrompe la petición
/// SIGUIENTE (hallazgo del concilio con `chunked`, que no pasa por `EqualReader`
/// y por tanto no lo drena nadie). No se puede forzar `Connection: close` desde
/// aquí —`tiny_http` descarta esa cabecera de la respuesta (`response.rs`)—, así
/// que la vía es sincronizar la conexión consumiendo el residuo con memoria
/// acotada. Su coste en tiempo para un cuerpo enorme es clase tasa, acotada en el
/// borde por el mismo Nginx.
fn leer_cuerpo_acotado(req: &mut Request) -> Option<String> {
    use std::io::Read;
    let mut buf = Vec::new();
    let leidos = req.as_reader().take(MAX_CUERPO + 1).read_to_end(&mut buf).ok()?;
    if leidos as u64 > MAX_CUERPO {
        drenar(req); // sincroniza la conexión: el residuo no será la próxima petición
        return None;
    }
    String::from_utf8(buf).ok()
}

/// Descarta el resto del cuerpo en trozos de tamaño fijo (memoria acotada), para
/// que la conexión quede SINCRONIZADA tras rechazar un cuerpo demasiado grande.
fn drenar(req: &mut Request) {
    let mut basura = [0u8; 8192];
    let r = req.as_reader();
    while matches!(r.read(&mut basura), Ok(n) if n > 0) {}
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
    let body = match leer_cuerpo_acotado(req) {
        Some(b) => b,
        None => return text(400, "cuerpo ilegible o demasiado grande"),
    };
    let blinded = match from_hex_32(body.trim()) {
        Some(b) => b,
        None => return text(400, "el cuerpo debe ser el punto cegado en 64 hex"),
    };

    match store.verify(&bearer) {
        Ok(AuthResult::Valid { key_id, plan, .. }) => {
            // Los límites salen del PLAN de quien presenta la clave, no de una
            // constante global: quien paga más recibe más ráfaga. `limits_for`
            // cae a un valor conservador si el plan no se reconoce, para no
            // dejar sin servicio a un cliente que ya pagó.
            let limits = crate::plans::limits_for(&plan);
            if !limiter.allow(&key_id, limits.rate_capacity, limits.rate_refill_per_sec) {
                // Un segundo, y no es una cifra redonda al azar: el cubo se
                // rellena a `rate_refill_per_sec`. La vía más lenta NO es el
                // plan más pequeño que se vende —starter, 30 fichas/s— sino
                // `plans::FALLBACK`, a 10/s, que es lo que recibe una clave con
                // un plan ya desconocido. También ahí, pasado un segundo hay
                // ficha segura. (La justificación anterior nombraba el caso que
                // no manda; el número era correcto igual.)
                return text_retry(429, "rate limit de ráfaga", 1);
            }
            match server_key.blind_evaluate(&blinded) {
                Some((eval, proof)) => {
                    // LA CONTABILIDAD NO PUEDE FALLAR EN SILENCIO.
                    //
                    // Antes era `let _ = …`: si el `INSERT`/`UPDATE` fallaba
                    // —disco lleno, base bloqueada, o el sistema de ficheros
                    // remontado en solo-lectura tras un error de E/S, que es lo
                    // que hace ext4 y deja las LECTURAS funcionando— el servidor
                    // devolvía 200 con la evaluación y el contador no subía.
                    // Evaluaciones ilimitadas gratis, sin un registro, hasta que
                    // alguien mirara la factura.
                    //
                    // No se devuelve 500: castigar al cliente por un problema
                    // nuestro es peor. Lo que se hace es que «no se contabilizó»
                    // deje de ser indistinguible de «no hubo tráfico» — en esta
                    // unidad, stderr va al journal.
                    if let Err(e) = store.record_usage(&key_id) {
                        eprintln!(
                            "AVISO: no se pudo contabilizar el uso de la clave {key_id}: {e}. \
                             La evaluación SÍ se sirvió; el contador NO subió."
                        );
                    }
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
        // La cuota NO se arregla esperando un segundo: se arregla en el
        // cambio de mes, o subiendo de plan. Anunciar lo que de verdad falta
        // es lo que convierte el backoff en algo que termina.
        Ok(AuthResult::QuotaExceeded) => text_retry(
            429,
            "cuota mensual agotada",
            crate::store::segundos_hasta_el_siguiente_periodo(),
        ),
        Err(_) => text(500, "error de almacén"),
    }
}

fn admin_issue(req: &mut Request, store: &Store, cfg: &Config) -> Resp {
    if !admin_ok(cfg, header_value(req, "X-Admin-Token").as_deref()) {
        return text(401, "no autorizado");
    }
    let body = match leer_cuerpo_acotado(req) {
        Some(b) => b,
        None => return text(400, "cuerpo ilegible o demasiado grande"),
    };
    let email = match form_get(&body, "email") {
        Some(e) if !e.is_empty() => e,
        _ => return text(400, "falta email"),
    };
    // El plan es OBLIGATORIO: no se adivina. Antes caía por defecto a "beta",
    // que además ya no se vende. Suponer el plan de facturación cuando quien
    // llama no lo dice es el camino directo a emitir una clave con la cuota
    // equivocada, y el cliente no lo notaría hasta chocar con el límite — con
    // sus usuarios sin poder iniciar sesión, porque el SDK falla cerrado.
    let plan = match form_get(&body, "plan") {
        Some(p) if !p.is_empty() => p,
        _ => return text(400, "falta plan"),
    };
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
        // `updated: 0` en un `activate` significa que la key está REVOCADA y no
        // se resucita (I6). Se dice en voz alta en vez de devolver un 200 mudo:
        // quien opera tiene que enterarse de que su acción no surtió efecto, o
        // le dirá al cliente que ya está arreglado y no lo estará. Un aviso que
        // nadie ve equivale a no fallar.
        Ok(0) if action == "activate" => text(
            409,
            "esta key está revocada y no se reactiva: emite una nueva",
        ),
        Ok(n) => json(200, format!("{{\"updated\":{n}}}")),
        Err(_) => text(500, "error de almacén"),
    }
}

fn admin_ok(cfg: &Config, presented: Option<&str>) -> bool {
    match (&cfg.admin_token, presented) {
        (Some(expected), Some(got)) => {
            // D20: un secreto vacío (o de solo espacios) NO es un secreto. Defensa
            // en profundidad: aunque `main.rs` ya trata la env vacía/blanca como
            // `None`, alguien podría construir el `Config` con `Some("")` por otra
            // vía (otro binario, una prueba, un refactor). Sin este guard,
            // `"".ct_eq("") == 1` y un token admin vacío autorizaría a cualquiera
            // que PRESENTE la cabecera `X-Admin-Token` vacía. (Una cabecera
            // AUSENTE da `None` en `header_value` y cae en el brazo `_`, no aquí.)
            // Se rechaza ANTES de comparar; para el caso no-vacío se conserva la
            // comparación en tiempo constante. (Nota: `ct_eq` de slices ya difiere
            // por LONGITUD antes del bucle; la del token real es pública por
            // diseño, así que el guard no cambia esa propiedad.)
            if expected.trim().is_empty() {
                return false;
            }
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

/// Como `text`, pero con `Retry-After` en segundos.
///
/// Un 429 sin esa cabecera obliga al cliente a inventarse cuánto espera, y lo
/// que se inventa suele ser demasiado poco: el servidor recibe el martilleo que
/// el freno existe para evitar. Solo se usa donde el número es CALCULABLE —el
/// cubo de ráfaga se rellena en un segundo, la cuota en el cambio de mes—; no
/// hay un valor por defecto para el resto, a propósito.
fn text_retry(status: u16, msg: &str, segundos: i64) -> Resp {
    let h = Header::from_bytes(&b"Retry-After"[..], segundos.to_string().as_bytes())
        .expect("cabecera Retry-After bien formada");
    text(status, msg).with_header(h)
}


fn json(status: u16, body: String) -> Resp {
    let ct = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
    Response::from_string(body)
        .with_status_code(status)
        .with_header(ct)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_con(token: Option<&str>) -> Config {
        Config {
            addr: "127.0.0.1:0".to_string(),
            admin_token: token.map(str::to_string),
        }
    }

    /// D33 — caso ROJO: un token admin VACÍO nunca debe autorizar.
    ///
    /// Sin el guard de `admin_ok`, esto sería `true`, porque `"".ct_eq("") == 1`:
    /// un `Config` con `Some("")` abriría /admin a quien mande la cabecera vacía.
    /// El guard es lo único que lo distingue de un secreto real. Quitarlo pone
    /// este test en rojo (verificado), así que discrimina por la vía real.
    #[test]
    fn token_vacio_nunca_autoriza() {
        let cfg = cfg_con(Some(""));
        assert!(
            !admin_ok(&cfg, Some("")),
            "un expected vacío autorizó con presented vacío (ct_eq(\"\",\"\")==1): el guard no corrió"
        );
        // Y tampoco con cualquier otra cosa presentada.
        assert!(!admin_ok(&cfg, Some("lo-que-sea")));
        assert!(!admin_ok(&cfg, None));
    }

    /// D33 — control POSITIVO: con un secreto real, la puerta funciona.
    #[test]
    fn token_real_discrimina() {
        let cfg = cfg_con(Some("secreto-real"));
        assert!(admin_ok(&cfg, Some("secreto-real")), "el token correcto debe abrir");
        assert!(!admin_ok(&cfg, Some("otro")), "un token distinto no debe abrir");
        assert!(!admin_ok(&cfg, None), "sin token presentado no debe abrir");
    }

    /// Control de la otra rama: sin token configurado, /admin está deshabilitado.
    #[test]
    fn sin_token_configurado_deshabilitado() {
        let cfg = cfg_con(None);
        assert!(!admin_ok(&cfg, Some("lo-que-sea")));
        assert!(!admin_ok(&cfg, None));
    }
}
