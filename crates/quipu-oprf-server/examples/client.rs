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

    // **LA CLAVE PÚBLICA SE FIJA FUERA DE BANDA, Y SIN ELLA NO SE ARRANCA.**
    //
    // Aquí había un `Err(_) => client::fetch_public_key(&addr)` como «comodidad
    // de demo», y esa comodidad vaciaba la única garantía que este producto
    // vende: descargar del MISMO servidor la clave con la que se va a verificar
    // su prueba DLEQ es confiar en él, o sea exactamente lo que el VOPRF existe
    // para no tener que hacer. Un servidor deshonesto —o un intermediario—
    // sirve su clave y su prueba, y el cliente valida encantado.
    //
    // Y no era una nota al pie: `scripts/oprf-e2e.sh` no exportaba
    // `QUIPU_OPRF_PUBKEY`, así que **el único extremo a extremo del producto
    // corría por este camino y salía verde** — un verde sobre la garantía
    // desactivada. Lo cazó la auditoría del 2026-08-17.
    //
    // Ahora falla ruidosamente y dice qué hacer (directiva 20). `fetch_public_key`
    // sigue existiendo para el arranque del servicio y para el guion de despliegue,
    // que es cuando SE ESTABLECE el ancla; no para usarla en su lugar.
    let server_pub = match std::env::var("QUIPU_OPRF_PUBKEY") {
        Ok(v) => from_hex_32(&v).ok_or("QUIPU_OPRF_PUBKEY inválida (64 hex)")?,
        Err(_) => {
            return Err(format!(
                "falta QUIPU_OPRF_PUBKEY.\n\
                 La clave pública del servidor se FIJA fuera de banda: sin ella, la prueba\n\
                 DLEQ se verificaría contra una clave que da el propio servidor, y eso no\n\
                 comprueba nada. Consíguela por un canal distinto del servicio y expórtala:\n\
                 \n    export QUIPU_OPRF_PUBKEY=<64 hex>\n\
                 \nSolo para una demo local contra un servidor que acabas de arrancar tú:\n\
                 \n    export QUIPU_OPRF_PUBKEY=$(curl -s http://{addr}/v1/public-key | tr -d '\"' )"
            ))
        }
    };

    let hardened = client::harden(&addr, &api_key, password.as_bytes(), &server_pub)?;
    println!("secreto endurecido: {}", quipu_oprf_server::hexutil::to_hex(&hardened));
    Ok(())
}
