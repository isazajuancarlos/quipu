//! Cliente de referencia del servidor OPRF (M4).
//!
//! Flujo verificable: blind → POST /v1/oprf/evaluate → finalize (VERIFICA la
//! prueba DLEQ contra la clave pública fijada) → secreto endurecido. La lógica
//! vive en `quipu_oprf_server::client`; aquí solo se lee la configuración.
//!
//! Uso:
//!   QUIPU_OPRF_ADDR=127.0.0.1:8787 \
//!   QUIPU_OPRF_API_KEY=quipu_live_... \
//!   cargo run -p quipu-oprf-server --example client -- "mi-contraseña"
//!
//! En producción, FIJA (pin) la clave pública fuera de banda (QUIPU_OPRF_PUBKEY).

use quipu_oprf_server::client;
use quipu_oprf_server::hexutil::from_hex_32;

fn main() -> Result<(), String> {
    let addr = std::env::var("QUIPU_OPRF_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".to_string());
    let api_key = std::env::var("QUIPU_OPRF_API_KEY").map_err(|_| "falta QUIPU_OPRF_API_KEY")?;
    let password = std::env::args().nth(1).ok_or("uso: client <contraseña>")?;

    // Clave pública: fijada por env o (comodidad de demo) pedida al servidor.
    let server_pub = match std::env::var("QUIPU_OPRF_PUBKEY") {
        Ok(v) => from_hex_32(&v).ok_or("QUIPU_OPRF_PUBKEY inválida (64 hex)")?,
        Err(_) => client::fetch_public_key(&addr)?,
    };

    let hardened = client::harden(&addr, &api_key, password.as_bytes(), &server_pub)?;
    println!("secreto endurecido: {}", quipu_oprf_server::hexutil::to_hex(&hardened));
    Ok(())
}
