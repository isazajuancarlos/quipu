// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Transporte de red para el OPRF (std-only, sin dependencias).
//!
//! Protocolo binario mínimo sobre TCP:
//!   cliente -> servidor:  32 bytes (punto cegado)
//!   servidor -> cliente:  1 byte estado (1=ok, 0=denegado) + 32 bytes (eval)
//!
//! La POLÍTICA de rate-limit (p. ej. por IP) la decide quien llama a
//! `handle_connection` (el binario servidor); aquí solo va el protocolo.
//! En producción: poner detrás de TLS (nginx stream / stunnel) en el VPS.

use std::io::{Read, Write};
use std::net::TcpStream;

use crate::oprf::Server;
use crate::voprf;

/// Cliente SIN verificación (sin prueba DLEQ): no detecta un servidor
/// deshonesto. Prefiere [`evaluate_remote_verified`]. Oculto de la doc.
#[doc(hidden)]
pub fn evaluate_remote(addr: &str, blinded: &[u8; 32]) -> std::io::Result<Option<[u8; 32]>> {
    let mut stream = TcpStream::connect(addr)?;
    stream.write_all(blinded)?;
    stream.flush()?;

    let mut status = [0u8; 1];
    stream.read_exact(&mut status)?;
    let mut resp = [0u8; 32];
    stream.read_exact(&mut resp)?;
    Ok(if status[0] == 1 { Some(resp) } else { None })
}

/// Servidor SIN verificación (responde sin prueba DLEQ). Prefiere
/// [`handle_connection_verified`]. Oculto de la doc.
#[doc(hidden)]
pub fn handle_connection<S: Read + Write>(
    stream: &mut S,
    server: &Server,
    allowed: bool,
) -> std::io::Result<()> {
    let mut blinded = [0u8; 32];
    stream.read_exact(&mut blinded)?;

    let result = if allowed {
        server.evaluate_raw(&blinded)
    } else {
        None
    };
    match result {
        Some(ev) => {
            stream.write_all(&[1u8])?;
            stream.write_all(&ev)?;
        }
        None => {
            stream.write_all(&[0u8])?;
            stream.write_all(&[0u8; 32])?;
        }
    }
    stream.flush()
}

/// Longitud de la respuesta verificada: estado(1) + Z(32) + prueba(64).
const VERIFIED_RESP_LEN: usize = 1 + 32 + voprf::PROOF_LEN;

/// Cliente VERIFICADO: envía el punto cegado y recibe (evaluación, prueba DLEQ),
/// o `None` si el servidor denegó.
pub fn evaluate_remote_verified(
    addr: &str,
    blinded: &[u8; 32],
) -> std::io::Result<Option<([u8; 32], [u8; voprf::PROOF_LEN])>> {
    let mut stream = TcpStream::connect(addr)?;
    stream.write_all(blinded)?;
    stream.flush()?;

    let mut resp = [0u8; VERIFIED_RESP_LEN];
    stream.read_exact(&mut resp)?;
    if resp[0] != 1 {
        return Ok(None);
    }
    let mut z = [0u8; 32];
    z.copy_from_slice(&resp[1..33]);
    let mut proof = [0u8; voprf::PROOF_LEN];
    proof.copy_from_slice(&resp[33..]);
    Ok(Some((z, proof)))
}

/// Servidor VERIFICADO: atiende una conexión con un `voprf::Server`.
pub fn handle_connection_verified<S: Read + Write>(
    stream: &mut S,
    server: &voprf::Server,
    allowed: bool,
) -> std::io::Result<()> {
    let mut blinded = [0u8; 32];
    stream.read_exact(&mut blinded)?;

    let result = if allowed { server.blind_evaluate(&blinded) } else { None };
    match result {
        Some((z, proof)) => {
            stream.write_all(&[1u8])?;
            stream.write_all(&z)?;
            stream.write_all(&proof)?;
        }
        None => {
            stream.write_all(&[0u8])?;
            stream.write_all(&[0u8; 32])?;
            stream.write_all(&[0u8; voprf::PROOF_LEN])?;
        }
    }
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oprf;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn verified_network_oprf_round_trips_and_verifies() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = voprf::Server::new();
        let pubkey = server.public_key();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            handle_connection_verified(&mut stream, &server, true).unwrap();
        });

        let pw = b"passphrase";
        let (state, blinded) = voprf::blind(pw).unwrap();
        let (z, proof) = evaluate_remote_verified(&addr, &blinded).unwrap().unwrap();
        // El cliente VERIFICA la prueba contra la clave pública fijada.
        let out = voprf::finalize(pw, &state, &z, &proof, &pubkey);
        assert!(out.is_some());
        handle.join().unwrap();
    }

    #[test]
    fn network_oprf_is_consistent() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = thread::spawn(move || {
            let server = Server::new(1000);
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                handle_connection(&mut stream, &server, true).unwrap();
            }
        });

        let pw = b"passphrase del usuario";
        let (s1, b1) = oprf::blind(pw);
        let r1 = evaluate_remote(&addr, &b1).unwrap().unwrap();
        let o1 = oprf::finalize(pw, &s1, &r1).unwrap();

        let (s2, b2) = oprf::blind(pw);
        let r2 = evaluate_remote(&addr, &b2).unwrap().unwrap();
        let o2 = oprf::finalize(pw, &s2, &r2).unwrap();

        // Mismo password + mismo servidor -> mismo output endurecido, vía red.
        assert_eq!(o1, o2);
        handle.join().unwrap();
    }

    #[test]
    fn denied_request_returns_none() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = thread::spawn(move || {
            let server = Server::new(1000);
            let (mut stream, _) = listener.accept().unwrap();
            handle_connection(&mut stream, &server, false).unwrap(); // denegado
        });

        let (_s, b) = oprf::blind(b"x");
        assert_eq!(evaluate_remote(&addr, &b).unwrap(), None);
        handle.join().unwrap();
    }
}
