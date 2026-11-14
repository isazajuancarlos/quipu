// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

//! Transporte de red para el OPRF (std-only, sin dependencias).
//!
//! Protocolo binario mínimo sobre TCP:
//!   cliente -> servidor:  32 bytes (punto cegado)
//!   servidor -> cliente:  1 byte estado (1=ok, 0=denegado) + 32 bytes (eval)
//!
//! La POLÍTICA de rate-limit (p. ej. por IP) la decide quien llama a
//! `handle_connection` (el binario servidor); aquí solo va el protocolo.
//! En producción: poner detrás de TLS (nginx stream / stunnel) en el VPS.

// USO INTERNO DE LO OBSOLETO: este módulo ES la superficie marcada, o su
// transporte. Silenciarlo AQUÍ y solo aquí es lo que deja el aviso vivo
// para quien lo importe desde fuera, que es el único a quien va dirigido.
// Sin esto, `clippy -D warnings` rompería el CI por avisos que no son
// para nosotros.
#![allow(deprecated)]

use std::io::{Read, Write};
use std::net::TcpStream;

use crate::oprf::Server;
use crate::voprf;

/// **TOPE DE ESPERA de toda conversación con el servidor OPRF.**
///
/// Hasta el 2026-08-17 aquí no había NINGUNO —ni de conexión, ni de lectura, ni
/// de escritura—, y eso convierte a un servidor que acepta la conexión y **calla**
/// en un cuelgue indefinido de `decode_online`: el documento no se abre, no hay
/// error, y desde fuera se ve exactamente igual que un servidor lento. Es el modo
/// de fallo que no da la cara (directiva 39: toda espera se escribe con quién la
/// va a terminar y con un tope; aquí no la terminaba nadie).
///
/// No basta con el tope del kernel: ése cubre el `connect` contra una IP en
/// agujero negro (~130 s), y **no cubre en absoluto** al peer que sí acepta y
/// luego no habla, que es justo el caso del servidor deshonesto que el modelo de
/// amenaza T4 sí incluye.
///
/// **Diez segundos, y el número tiene motivo**: la operación del otro lado es una
/// multiplicación escalar en ristretto255 —microsegundos—, así que todo lo que
/// pase de un segundo ya es red. Diez deja sitio de sobra a un enlace malo sin
/// convertir un fallo en una espera que el usuario interpreta como trabajo.
///
/// Se puede cambiar con `QUIPU_OPRF_TIMEOUT_MS` para el que auto-hospede en un
/// enlace peor; un valor ilegible o cero NO desactiva el tope —cae al de por
/// defecto—, porque un tope que se puede apagar con una variable de entorno mal
/// escrita es un tope que un día no está.
pub const TIMEOUT_POR_DEFECTO: std::time::Duration = std::time::Duration::from_secs(10);

fn tope() -> std::time::Duration {
    match std::env::var("QUIPU_OPRF_TIMEOUT_MS").ok().and_then(|v| v.parse::<u64>().ok()) {
        Some(ms) if ms > 0 => std::time::Duration::from_millis(ms),
        _ => TIMEOUT_POR_DEFECTO,
    }
}

/// Conecta con tope en las TRES fases. Las tres, porque cada una cuelga por su
/// cuenta: `connect` contra un peer que no responde al SYN, `read` contra el que
/// acepta y calla, y `write` contra el que acepta y no lee (su ventana se llena
/// y el `write_all` se queda dentro).
fn conectar_con_tope(addr: &str) -> std::io::Result<TcpStream> {
    conectar_con(addr, tope())
}

/// La misma conexión con el tope EXPLÍCITO. Existe para que el banco pueda
/// medir el tope sin tocar una variable de entorno, que es estado global del
/// proceso y haría la prueba dependiente del orden en que corran las demás.
fn conectar_con(addr: &str, t: std::time::Duration) -> std::io::Result<TcpStream> {
    // **SE PRUEBAN TODAS LAS DIRECCIONES, NO LA PRIMERA.**
    //
    // `TcpStream::connect` recorre todo lo que devuelve `to_socket_addrs` y se
    // queda con la primera que conecte; `connect_timeout` exige UNA ya resuelta.
    // La primera versión de este tope hizo `.next()`, y con eso rompió el caso
    // más común del producto: `/etc/hosts` pone `::1 localhost` DESPUÉS de
    // `127.0.0.1 localhost`, `getaddrinfo` devuelve el IPv6 primero, y un
    // servidor que escuche en `127.0.0.1` deja de ser alcanzable POR NOMBRE.
    // Medido por la revisión de seguridad de este mismo cambio: `localhost:P`
    // resolvía a `[[::1]:P, 127.0.0.1:P]` y el `.next()` daba `Connection
    // refused`. Un arreglo de disponibilidad que rompía la disponibilidad.
    //
    // Se guarda el ÚLTIMO error y no el primero: es el de la dirección que más
    // lejos llegó, y es el que le sirve a quien lea el mensaje.
    let mut ultimo: Option<std::io::Error> = None;
    for destino in std::net::ToSocketAddrs::to_socket_addrs(&addr)? {
        match TcpStream::connect_timeout(&destino, t) {
            Ok(stream) => {
                stream.set_read_timeout(Some(t))?;
                stream.set_write_timeout(Some(t))?;
                return Ok(stream);
            }
            Err(e) => ultimo = Some(e),
        }
    }
    Err(ultimo.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "la dirección no resuelve a nada")
    }))
}

/// Cliente SIN verificación (sin prueba DLEQ): no detecta un servidor
/// deshonesto. Prefiere [`evaluate_remote_verified`]. Oculto de la doc.
#[doc(hidden)]
#[deprecated(
    since = "0.10.1",
    note = "no verifica la prueba DLEQ: un servidor deshonesto (T4) pasa desapercibido. Use `evaluate_remote_verified`."
)]
pub fn evaluate_remote(addr: &str, blinded: &[u8; 32]) -> std::io::Result<Option<[u8; 32]>> {
    let mut stream = conectar_con_tope(addr)?;
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
#[deprecated(
    since = "0.10.1",
    note = "sirve el protocolo SIN prueba DLEQ. Use `handle_connection_verified`."
)]
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
    evaluate_remote_verified_con_tope(addr, blinded, tope())
}

/// Igual que [`evaluate_remote_verified`], con el tope de espera explícito.
///
/// Pública porque quien auto-hospede en un enlace malo tiene derecho a subirlo
/// sin tocar una variable de entorno del proceso entero — y porque es lo que
/// hace medible el tope (ver `un_servidor_que_acepta_y_calla_no_cuelga`).
pub fn evaluate_remote_verified_con_tope(
    addr: &str,
    blinded: &[u8; 32],
    tope: std::time::Duration,
) -> std::io::Result<Option<([u8; 32], [u8; voprf::PROOF_LEN])>> {
    let mut stream = conectar_con(addr, tope)?;
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
// El arnés de `#[test]` genera código que referencia estos ítems desde
// FUERA del `allow` del módulo, así que hace falta aquí también.
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::oprf;
    use std::net::TcpListener;
    use std::thread;

    /// **CONECTAR POR NOMBRE FUNCIONA AUNQUE LA PRIMERA DIRECCIÓN NO ESCUCHE.**
    ///
    /// El tope de espera se introdujo el 2026-08-17 y su primera versión hizo
    /// `to_socket_addrs().next()`, porque `connect_timeout` exige una dirección
    /// ya resuelta. Eso cambió el comportamiento sin querer: `TcpStream::connect`
    /// recorre TODAS y se queda con la que conecte.
    ///
    /// El caso real, y es el más común del producto: `/etc/hosts` pone
    /// `::1 localhost` después de `127.0.0.1 localhost`, `getaddrinfo` devuelve
    /// el IPv6 primero, y un servidor que escuche en `127.0.0.1` —lo que hace
    /// este mismo banco— dejaba de ser alcanzable por `localhost`. Lo midió la
    /// revisión de seguridad del cambio: `Connection refused`.
    ///
    /// Esta prueba **solo mide algo donde `localhost` resuelva a más de una
    /// dirección**, así que lo dice en vez de callarlo: si resuelve a una, la
    /// prueba pasa por construcción y no discrimina. Ese aviso es el que separa
    /// «pasó» de «no había nada que probar» (directiva 30).
    #[test]
    fn conectar_por_nombre_prueba_todas_las_direcciones() {
        use std::net::ToSocketAddrs;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let puerto = listener.local_addr().unwrap().port();
        let server = voprf::Server::new();
        let hilo = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            handle_connection_verified(&mut s, &server, true).unwrap();
        });

        let nombre = format!("localhost:{puerto}");
        let cuantas = match nombre.to_socket_addrs() {
            Ok(it) => it.count(),
            Err(_) => {
                // Sin resolución de `localhost` no hay nada que medir. Se dice.
                eprintln!("SIN OBJETO: `localhost` no resuelve en esta máquina");
                drop(hilo);
                return;
            }
        };
        if cuantas < 2 {
            eprintln!(
                "SIN OBJETO: `localhost` resuelve a {cuantas} dirección; esta prueba solo \
                 discrimina cuando hay varias y la primera no escucha"
            );
            drop(hilo);
            return;
        }

        let (_state, blinded) = voprf::blind(b"contrasena").expect("cegar");
        let r = evaluate_remote_verified_con_tope(
            &nombre,
            &blinded,
            std::time::Duration::from_secs(2),
        );
        assert!(
            r.is_ok(),
            "no se pudo conectar a {nombre} con {cuantas} direcciones resueltas: {:?} — \
             se está probando solo la primera",
            r.err()
        );
        hilo.join().unwrap();
    }

    /// **UN SERVIDOR QUE ACEPTA Y CALLA NO PUEDE COLGAR AL CLIENTE.**
    ///
    /// Es la prueba del defecto T1 de la auditoría del 2026-08-17: hasta ese día
    /// no había ningún tope —ni de conexión, ni de lectura, ni de escritura— y
    /// este caso se quedaba dentro de `read_exact` **para siempre**. No daba
    /// error, no devolvía nada, y desde fuera se veía igual que un servidor
    /// lento: el modo de fallo que no da la cara.
    ///
    /// El servidor de mentira acepta la conexión y **no escribe nada**. No hace
    /// falta que duerma un tiempo concreto: se queda con el `TcpStream` vivo
    /// hasta que la prueba termina, que es exactamente el peor caso real.
    ///
    /// LA PAREJA VA ABAJO (`el_control_un_servidor_honesto_sigue_respondiendo`):
    /// sin ella, esto pasaría igual con un cliente que devolviera error siempre,
    /// que es la forma más fácil de «arreglar» un timeout y romper el producto.
    #[test]
    fn un_servidor_que_acepta_y_calla_no_cuelga() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        // El hilo se queda con la conexión ABIERTA y muda. `_guardado` importa:
        // soltar el `TcpStream` cerraría el socket y el cliente vería un EOF
        // limpio, o sea que la prueba mediría otra cosa —el camino que YA
        // funcionaba— en vez del cuelgue.
        let mudo = thread::spawn(move || {
            let (_guardado, _) = listener.accept().unwrap();
            thread::sleep(std::time::Duration::from_secs(30));
        });

        let tope = std::time::Duration::from_millis(300);
        let inicio = std::time::Instant::now();
        let r = evaluate_remote_verified_con_tope(&addr, &[7u8; 32], tope);
        let tardo = inicio.elapsed();

        assert!(r.is_err(), "un servidor mudo tiene que dar ERROR, no colgar ni devolver nada");
        assert!(
            tardo < std::time::Duration::from_secs(5),
            "tardó {tardo:?}: el tope de {tope:?} no se está aplicando"
        );
        drop(mudo);
    }

    /// **LA PAREJA**: con el MISMO tope corto y el mismo arnés, un servidor
    /// honesto sigue contestando. Sin este control, la prueba de arriba estaría
    /// verde con un cliente roto que fallara siempre.
    #[test]
    fn el_control_un_servidor_honesto_sigue_respondiendo() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = voprf::Server::new();
        let pubkey = server.public_key();
        let hilo = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            handle_connection_verified(&mut s, &server, true).unwrap();
        });

        let (state, blinded) = voprf::blind(b"contrasena").expect("cegar");
        let r = evaluate_remote_verified_con_tope(
            &addr,
            &blinded,
            std::time::Duration::from_millis(300),
        )
        .expect("el servidor honesto responde dentro del tope");
        let (z, proof) = r.expect("no deniega");
        assert!(
            voprf::finalize(b"contrasena", &state, &z, &proof, &pubkey).is_some(),
            "la prueba DLEQ del servidor honesto tiene que validar"
        );
        hilo.join().unwrap();
    }

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
