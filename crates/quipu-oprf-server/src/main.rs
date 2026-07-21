// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! CLI del servidor OPRF.
//!
//! Administración (camino manual; en producción la pasarela usa /admin vía HTTP):
//!   QUIPU_OPRF_DB=oprf.db quipu-oprf-server init
//!   quipu-oprf-server issue <email> <starter|pro>          # imprime la key UNA vez
//!   quipu-oprf-server revoke <prefix>
//!   quipu-oprf-server deactivate <prefix>
//!   quipu-oprf-server activate <prefix>
//!
//! Servidor:
//!   QUIPU_OPRF_SEED=<64 hex>  QUIPU_OPRF_ADMIN_TOKEN=<secreto>  \
//!   quipu-oprf-server serve [addr]        # por defecto 127.0.0.1:8787

use std::process::ExitCode;

use quipu::voprf;
use quipu_oprf_server::hexutil::from_hex_32;
use quipu_oprf_server::http::{self, Config};
use quipu_oprf_server::plans::quota_for;
use quipu_oprf_server::store::Store;

fn db_path() -> String {
    std::env::var("QUIPU_OPRF_DB").unwrap_or_else(|_| "quipu-oprf.db".to_string())
}

/// `info` de `DeriveKeyPair` (RFC 9497 §3.2). Fijo y versionado: entra en la
/// derivación, así que cambiarlo cambia la clave para la misma semilla y
/// invalida todos los secretos endurecidos. No se toca.
const DERIVE_INFO: &[u8] = b"quipu-oprf-server-v1";

/// Carga la clave VOPRF desde el seed persistente. Sin seed => clave EFÍMERA
/// (solo dev): reiniciar rompería los secretos endurecidos de los clientes.
///
/// OJO: desde la migración a RFC 9497 la clave se deriva con `DeriveKeyPair`
/// (§3.2), no con el hash propio de antes. La MISMA semilla da una clave pública
/// DISTINTA de la que daba la versión anterior: cualquier clave fijada por un
/// cliente y cualquier secreto ya endurecido quedan invalidados. Se hizo con
/// cero clientes, que era la única ventana.
fn load_server_key() -> voprf::Server {
    if let Ok(hex) = std::env::var("QUIPU_OPRF_SEED") {
        match from_hex_32(hex.trim()) {
            Some(seed) => match voprf::Server::from_seed(&seed, DERIVE_INFO) {
                Some(s) => return s,
                // DeriveKeyPairError: 256 intentos dando escalar cero. No pasa
                // en la práctica, pero arrancar con clave efímera en silencio
                // sería peor que morir aquí.
                None => {
                    eprintln!("error: DeriveKeyPair falló con ese seed (¿seed degenerado?)");
                    std::process::exit(1);
                }
            },
            None => eprintln!("⚠️  QUIPU_OPRF_SEED inválido (esperaba 64 hex); ignorado."),
        }
    }
    eprintln!(
        "⚠️  Sin QUIPU_OPRF_SEED: clave EFÍMERA. Reiniciar romperá los secretos \
         endurecidos. Genera uno con: openssl rand -hex 32"
    );
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("RNG del sistema");
    voprf::Server::from_seed(&seed, DERIVE_INFO).expect("DeriveKeyPair con seed aleatorio")
}

fn usage() {
    eprintln!(
        "uso:\n  \
         init\n  \
         issue <email> <starter|pro>\n  \
         revoke <prefix>\n  \
         deactivate <prefix>\n  \
         activate <prefix>\n  \
         serve [addr]\n\
         (BD vía QUIPU_OPRF_DB; seed vía QUIPU_OPRF_SEED; admin vía QUIPU_OPRF_ADMIN_TOKEN)"
    );
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let store = Store::open(&db_path()).map_err(|e| format!("abrir BD: {e}"))?;

    match args.get(1).map(String::as_str) {
        Some("init") => {
            println!("Esquema listo en {}", db_path());
        }
        Some("issue") => {
            let email = args.get(2).ok_or("falta <email>")?;
            let plan = args.get(3).map(String::as_str).unwrap_or("starter");
            let quota = quota_for(plan).ok_or_else(|| format!("plan desconocido: {plan}"))?;
            let customer = store
                .create_customer(email, plan)
                .map_err(|e| format!("crear cliente: {e}"))?;
            let key = store
                .issue_key(&customer, quota, None)
                .map_err(|e| format!("emitir key: {e}"))?;
            println!("cliente : {customer}");
            println!("plan    : {plan} ({quota} evaluaciones/mes)");
            println!("prefix  : {}", key.prefix);
            println!("API KEY : {}", key.secret);
            eprintln!("\n⚠️  Guarda la API KEY ahora: NO se vuelve a mostrar.");
        }
        Some("revoke") => {
            let prefix = args.get(2).ok_or("falta <prefix>")?;
            let n = store.revoke(prefix).map_err(|e| format!("revocar: {e}"))?;
            println!("{n} key(s) revocada(s)");
        }
        Some("deactivate") => {
            let prefix = args.get(2).ok_or("falta <prefix>")?;
            let n = store
                .set_active(prefix, false)
                .map_err(|e| format!("desactivar: {e}"))?;
            println!("{n} key(s) desactivada(s)");
        }
        Some("activate") => {
            let prefix = args.get(2).ok_or("falta <prefix>")?;
            let n = store
                .set_active(prefix, true)
                .map_err(|e| format!("activar: {e}"))?;
            println!("{n} key(s) activada(s)");
        }
        Some("serve") => {
            let addr = args
                .get(2)
                .cloned()
                .or_else(|| std::env::var("QUIPU_OPRF_ADDR").ok())
                .unwrap_or_else(|| "127.0.0.1:8787".to_string());
            // Los límites de ráfaga ya no viven aquí: dependen del plan de cada
            // cliente y se leen de `plans::limits_for` en cada evaluación.
            let cfg = Config {
                addr,
                admin_token: std::env::var("QUIPU_OPRF_ADMIN_TOKEN").ok(),
            };
            http::serve(store, load_server_key(), cfg).map_err(|e| format!("servidor: {e}"))?;
        }
        _ => {
            usage();
            return Err("comando no reconocido".to_string());
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
