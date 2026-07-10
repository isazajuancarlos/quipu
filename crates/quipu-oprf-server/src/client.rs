//! Cliente OPRF de referencia sobre HTTP EN CLARO (sin TLS).
//!
//! Sirve al ejemplo (`examples/client.rs`) y al test de integración. En
//! producción se usan los clientes nativos de las bindings (Py/Node/Go), que sí
//! manejan TLS; este es el flujo mínimo, dependency-free, para depurar y testear.

use std::io::{Read, Write};
use std::net::TcpStream;

use quipu::voprf;

use crate::hexutil::{from_hex, from_hex_32, to_hex};

/// Endurece `password` contra el servidor en `addr` (`host:puerto`, HTTP claro),
/// VERIFICANDO la prueba DLEQ contra `server_pub` (fijada). Devuelve el secreto
/// endurecido de 32 bytes, o `Err` si la prueba no valida o falla el transporte.
pub fn harden(
    addr: &str,
    api_key: &str,
    password: &[u8],
    server_pub: &[u8; 32],
) -> Result<[u8; 32], String> {
    let (state, blinded) = voprf::blind(password);
    let auth = format!("Bearer {api_key}");
    let (status, body) = request(
        addr,
        "POST",
        "/v1/oprf/evaluate",
        &[("Authorization", &auth), ("Content-Type", "text/plain")],
        Some(&to_hex(&blinded)),
    )?;
    if status != 200 {
        return Err(format!("evaluate HTTP {status}: {body}"));
    }
    let evaluated = from_hex_32(&field(&body, "evaluation")?).ok_or("evaluation inválida")?;
    let proof_vec = from_hex(&field(&body, "proof")?).ok_or("proof inválida")?;
    let proof: [u8; voprf::PROOF_LEN] = proof_vec
        .try_into()
        .map_err(|_| "longitud de proof inesperada".to_string())?;
    voprf::finalize(password, &state, &evaluated, &proof, server_pub)
        .ok_or_else(|| "prueba DLEQ inválida: servidor deshonesto o clave incorrecta".to_string())
}

/// Obtiene la clave pública del servidor (para pinnear). En producción, fíjala
/// fuera de banda en vez de pedirla.
pub fn fetch_public_key(addr: &str) -> Result<[u8; 32], String> {
    let (status, body) = request(addr, "GET", "/v1/public-key", &[], None)?;
    if status != 200 {
        return Err(format!("public-key HTTP {status}"));
    }
    from_hex_32(&field(&body, "public_key")?).ok_or_else(|| "clave pública inválida".to_string())
}

/// HTTP/1.1 mínimo con `Connection: close` sobre `TcpStream` (sin TLS).
fn request(
    addr: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> Result<(u16, String), String> {
    let mut stream = TcpStream::connect(addr).map_err(|e| format!("conectar {addr}: {e}"))?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(b) = body {
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("enviar: {e}"))?;

    let mut raw = String::new();
    stream
        .read_to_string(&mut raw)
        .map_err(|e| format!("leer: {e}"))?;
    let status = raw
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or("respuesta HTTP ilegible")?;
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    Ok((status, body))
}

/// Extrae el valor string de `"key":"..."` de un JSON simple (hex, sin escapes).
fn field(body: &str, key: &str) -> Result<String, String> {
    let pat = format!("\"{key}\":\"");
    let start = body
        .find(&pat)
        .ok_or_else(|| format!("falta el campo {key}"))?
        + pat.len();
    let rest = &body[start..];
    let end = rest.find('"').ok_or_else(|| format!("campo {key} sin cerrar"))?;
    Ok(rest[..end].to_string())
}
