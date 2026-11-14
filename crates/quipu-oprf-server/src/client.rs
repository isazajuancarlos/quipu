// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

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
) -> Result<[u8; voprf::OUTPUT_LEN], String> {
    // RFC 9497 §3.3.2: `blind` falla si la entrada mapea a la identidad.
    let (state, blinded) = voprf::blind(password).ok_or("entrada inválida para VOPRF")?;
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

/// Tope de espera de toda conversación con el servidor. Ver el porqué en
/// `quipu::oprf_net::TIMEOUT_POR_DEFECTO`: sin él, un servidor que acepta y calla
/// cuelga al cliente indefinidamente, y el cuelgue se ve igual que la lentitud.
const TOPE: std::time::Duration = std::time::Duration::from_secs(10);

/// Obtiene la clave pública del servidor. **Solo para ESTABLECER el ancla** —el
/// arranque del servicio, un guion de despliegue, una demo contra un servidor
/// que acabas de levantar tú—. En producción se fija fuera de banda: pedírsela
/// al servidor que se va a verificar con ella no comprueba nada.
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
    // TOPE EN LAS TRES FASES. Antes no había ninguno, y contra un peer que acepta
    // la conexión y no dice nada esto se quedaba dentro de `read_to_string` para
    // siempre — colgando también el propio banco de pruebas, que usa esta misma
    // función para esperar a que el servidor arranque. Una espera cuyo tope no
    // puede vencer no es un tope (directiva 39).
    // TODAS las direcciones, no la primera: `connect_timeout` exige una
    // resuelta, y quedarse con `.next()` rompe `localhost` en cuanto la
    // resolución devuelve el `::1` delante del `127.0.0.1` — que es lo normal.
    // Ver el comentario largo en `quipu::oprf_net::conectar_con`.
    let mut stream = None;
    let mut ultimo = String::new();
    for destino in std::net::ToSocketAddrs::to_socket_addrs(&addr)
        .map_err(|e| format!("resolver {addr}: {e}"))?
    {
        match TcpStream::connect_timeout(&destino, TOPE) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => ultimo = format!("{destino}: {e}"),
        }
    }
    let stream = stream.ok_or_else(|| format!("conectar {addr}: {ultimo}"))?;
    stream.set_read_timeout(Some(TOPE)).map_err(|e| format!("tope de lectura: {e}"))?;
    stream.set_write_timeout(Some(TOPE)).map_err(|e| format!("tope de escritura: {e}"))?;
    let mut stream = stream;
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

    // LECTURA CON TOPE DE TAMAÑO, y el motivo es de modelo de amenaza, no de
    // higiene: el peer de esta función es exactamente aquél del que el producto
    // desconfía —el servidor OPRF posiblemente deshonesto (T4)—, así que dejar
    // que decida cuánta memoria consume el cliente es regalarle el proceso. Un
    // `read_to_string` sin tope contra 100 MB de cuerpo mata al cliente por OOM.
    //
    // 64 KiB es dos órdenes de magnitud sobre la respuesta más grande que este
    // servidor produce (la lista de planes, ~600 bytes), así que no recorta nada
    // legítimo — que es la prueba que toda restricción tiene que pasar
    // (directiva 21).
    const MAX_RESPUESTA: u64 = 64 * 1024;
    let mut raw = String::new();
    let leidos = std::io::Read::by_ref(&mut stream)
        .take(MAX_RESPUESTA + 1)
        .read_to_string(&mut raw)
        .map_err(|e| format!("leer: {e}"))?;
    if leidos as u64 > MAX_RESPUESTA {
        return Err(format!(
            "el servidor mandó más de {MAX_RESPUESTA} bytes: se corta en vez de \
             acumular lo que el otro lado decida"
        ));
    }
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
