// SPDX-License-Identifier: AGPL-3.0-or-later
//! **Ráfaga, cuota y admin_ok contra el binario real** (simulación #A4.5).
//!
//! El código de `ratelimit.rs`, `plans.rs` y `store.rs` está bien probado en
//! unidad, pero **nada comprobaba que estuviera CABLEADO**: la auditoría del
//! 2026-08-17 midió que se podían borrar las cuatro líneas del limitador en
//! `http.rs` y las 15 pruebas del área seguían verdes. Y `admin_ok` —la barrera
//! entre internet y revocar las claves de todos— no la ejercitaba ninguna
//! prueba. Esto habla HTTP con el servidor de verdad.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use quipu_oprf_server::client;
use quipu_oprf_server::hexutil::to_hex;
use quipu_oprf_server::http::{self, Config};
use quipu_oprf_server::store::Store;
use quipu::voprf;

fn free_addr() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    format!("127.0.0.1:{port}")
}

fn wait_ready(addr: &str) {
    for _ in 0..100 {
        if client::fetch_public_key(addr).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("el servidor no arrancó en {addr}");
}

/// (status, cabeceras, cuerpo) de una petición cruda.
///
/// Las CABECERAS entraron el 2026-08-19 con el `Retry-After`: sin devolverlas,
/// la prueba de que el 429 lleva la cabecera no se puede escribir, y esa es
/// justamente la parte que sale al mundo.
fn peticion(addr: &str, raw: &str) -> (u16, String, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(raw.as_bytes()).unwrap();
    let mut buf = String::new();
    s.read_to_string(&mut buf).unwrap();
    let status = buf
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let (cabeceras, cuerpo) = match buf.split_once("\r\n\r\n") {
        Some((c, b)) => (c.to_string(), b.to_string()),
        None => (buf.clone(), String::new()),
    };
    (status, cabeceras, cuerpo)
}

/// El valor de `Retry-After`, o `None` si no viene. Case-insensitive porque el
/// nombre de una cabecera lo es, y creerse el caso exacto es la forma barata de
/// escribir una prueba que dice que sí a todo.
fn retry_after(cabeceras: &str) -> Option<i64> {
    cabeceras
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("retry-after:"))
        .and_then(|l| l.split_once(':'))
        .and_then(|(_, v)| v.trim().parse().ok())
}

fn evaluar(addr: &str, key: &str, blinded_hex: &str) -> (u16, String, String) {
    let raw = format!(
        "POST /v1/oprf/evaluate HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {key}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{blinded_hex}",
        blinded_hex.len()
    );
    peticion(addr, &raw)
}

fn blinded_valido() -> String {
    //  (RFC 9497), no el  deprecado —el camino sin
    // verificar—. Aquí solo hace falta un punto ristretto255 válido para que la
    // evaluación pase; el rate limit muerde antes de mirarlo.
    let (_state, blinded) = voprf::blind(b"una contrasena").expect("cegar");
    to_hex(&blinded)
}

#[test]
fn el_limitador_de_rafaga_esta_cableado_y_discrimina_por_plan() {
    let seed = [7u8; 32];
    let server_key = voprf::Server::from_seed(&seed, b"quipu-oprf-server-v1").unwrap();
    let store = Store::open_in_memory().unwrap();

    // Emite ANTES de mover el store al hilo: una key starter (capacity 60) y una
    // pro (capacity 200).
    let c_starter = store.create_customer("s@x", "starter").unwrap();
    let k_starter = store.issue_key(&c_starter, 1_000_000, None).unwrap().secret;
    let c_pro = store.create_customer("p@x", "pro").unwrap();
    let k_pro = store.issue_key(&c_pro, 1_000_000, None).unwrap().secret;

    let addr = free_addr();
    let cfg = Config { addr: addr.clone(), admin_token: None };
    thread::spawn(move || {
        let _ = http::serve(store, server_key, cfg);
    });
    wait_ready(&addr);
    let blinded = blinded_valido();

    // 200 POST rápidos con la key STARTER: la ráfaga tiene que morder.
    let mut ok = 0;
    let mut rafaga_429 = 0;
    let mut cuerpo_429 = String::new();
    let mut cabeceras_429 = String::new();
    for _ in 0..200 {
        let (st, cab, body) = evaluar(&addr, &k_starter, &blinded);
        match st {
            200 => ok += 1,
            429 => {
                rafaga_429 += 1;
                cuerpo_429 = body;
                cabeceras_429 = cab;
            }
            otro => panic!("status inesperado en la ráfaga: {otro} — {}", body),
        }
    }
    assert!(rafaga_429 > 0, "el limitador de ráfaga NO mordió: está desplegado y no hace nada");
    assert!(ok >= 60, "menos de la capacidad del bucket pasó ({ok}): algo frena de más");
    assert!(
        cuerpo_429.contains("ráfaga"),
        "la 429 no dice que es de ráfaga: {cuerpo_429}"
    );
    // Y sale con `Retry-After`. El cubo se rellena a 30 fichas/s en el plan más
    // pequeño, así que un segundo es un número que se cumple; sin la cabecera,
    // el cliente se lo inventa y casi siempre se lo inventa corto.
    assert_eq!(
        retry_after(&cabeceras_429),
        Some(1),
        "la 429 de ráfaga sin Retry-After (o con otro valor): {cabeceras_429}"
    );

    // EL DISCRIMINANTE: la misma ráfaga con la key PRO (capacity 200) NO puede
    // dar ni una 429. Sin esto, la prueba pasaría con un limitador que rechaza
    // siempre.
    let mut pro_429 = 0;
    for _ in 0..200 {
        let (st, _, _) = evaluar(&addr, &k_pro, &blinded);
        if st == 429 {
            pro_429 += 1;
        }
    }
    assert_eq!(pro_429, 0, "la key pro (capacity 200) recibió {pro_429} 429 en 200 peticiones");
}

#[test]
fn la_cuota_mensual_esta_cableada_y_se_distingue_de_la_rafaga() {
    let seed = [8u8; 32];
    let server_key = voprf::Server::from_seed(&seed, b"quipu-oprf-server-v1").unwrap();
    let store = Store::open_in_memory().unwrap();

    // Cuota de 3, capacity de sobra: la 4ª petición cae por CUOTA, no por ráfaga.
    let c = store.create_customer("q@x", "pro").unwrap();
    let key = store.issue_key(&c, 3, None).unwrap().secret;

    let addr = free_addr();
    let cfg = Config { addr: addr.clone(), admin_token: None };
    thread::spawn(move || {
        let _ = http::serve(store, server_key, cfg);
    });
    wait_ready(&addr);
    let blinded = blinded_valido();

    for i in 1..=3 {
        let (st, _, body) = evaluar(&addr, &key, &blinded);
        assert_eq!(st, 200, "la evaluación {i} de 3 tenía que pasar: {body}");
    }
    let (st, cab, body) = evaluar(&addr, &key, &blinded);
    assert_eq!(st, 429, "la 4ª evaluación tenía que caer por cuota");
    assert!(
        body.contains("cuota"),
        "la 429 de cuota tiene que DISTINGUIRSE de la de ráfaga por el cuerpo: {body}"
    );
    // EL DISCRIMINANTE DE LA CABECERA, y es el punto de haberla puesto: si el
    // `Retry-After` de esta respuesta fuera 1 —copiado del de ráfaga— el
    // cliente martillearía el servidor lo que queda de mes creyendo que hace lo
    // correcto.
    //
    // SE COMPARA CONTRA LA FUENTE, no contra un umbral. La primera versión
    // exigía `>= 3_600` «porque es lo mínimo que puede faltar para el día 1», y
    // eso era FALSO: lo mínimo es 1 segundo, y la prueba unitaria de al lado lo
    // dice. Ese umbral habría dado ROJO los últimos 3 599 segundos de CADA mes
    // —43 188 s al año, unas 12 horas— en la prueba que precisamente vigila que
    // la cuota no se confunda con la ráfaga: la alarma que resulta falsa dos
    // veces y a la tercera nadie mira. Lo cazó la revisión de seguridad del
    // 2026-08-19, no yo.
    //
    // El punto ciego que queda, dicho para que nadie lo descubra de sorpresa:
    // en el último segundo del mes la cuenta legítima vale 1, o sea lo mismo
    // que el valor de ráfaga, y ahí esta prueba no discrimina. Es un segundo al
    // mes, y la alternativa —inyectar el reloj— cambia la API del servidor por
    // un caso que no existe en producción.
    let espera = retry_after(&cab).expect("la 429 de cuota tiene que traer Retry-After");
    let esperado = quipu_oprf_server::store::segundos_hasta_el_siguiente_periodo();
    assert!(
        (espera - esperado).abs() <= 2,
        "el Retry-After de la cuota es {espera}s y lo que falta para el día 1 son \
         {esperado}s: la respuesta no está usando el periodo de facturación"
    );
}

#[test]
fn admin_ok_falla_cerrado_sin_token_y_exige_el_correcto_con_el() {
    let blinded = blinded_valido();
    let _ = &blinded;

    // --- servidor SIN admin_token: /admin queda deshabilitado, 401 siempre ---
    {
        let sk = voprf::Server::from_seed(&[1u8; 32], b"quipu-oprf-server-v1").unwrap();
        let store = Store::open_in_memory().unwrap();
        let addr = free_addr();
        let cfg = Config { addr: addr.clone(), admin_token: None };
        thread::spawn(move || {
            let _ = http::serve(store, sk, cfg);
        });
        wait_ready(&addr);
        let sin = peticion(&addr, &format!("POST /admin/keys HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"));
        assert_eq!(sin.0, 401, "sin admin_token configurado, /admin sin cabecera tiene que dar 401");
        let con = peticion(&addr, &format!("POST /admin/keys HTTP/1.1\r\nHost: {addr}\r\nX-Admin-Token: loquesea\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"));
        assert_eq!(con.0, 401, "sin admin_token configurado, NINGUNA cabecera abre /admin (falla cerrado)");
    }

    // --- servidor CON admin_token: solo el token correcto abre ---
    {
        let sk = voprf::Server::from_seed(&[2u8; 32], b"quipu-oprf-server-v1").unwrap();
        let store = Store::open_in_memory().unwrap();
        let addr = free_addr();
        let token = "un-token-de-admin-largo";
        let cfg = Config { addr: addr.clone(), admin_token: Some(token.to_string()) };
        thread::spawn(move || {
            let _ = http::serve(store, sk, cfg);
        });
        wait_ready(&addr);
        let body = "email=a@b.com&plan=starter";
        let base = |hdr: &str| format!(
            "POST /admin/keys HTTP/1.1\r\nHost: {addr}\r\n{hdr}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        assert_eq!(peticion(&addr, &base("")).0, 401, "sin cabecera → 401");
        assert_eq!(peticion(&addr, &base("X-Admin-Token: token-equivocado\r\n")).0, 401, "token equivocado → 401");
        let (st, _, resp) = peticion(&addr, &base(&format!("X-Admin-Token: {token}\r\n")));
        assert_eq!(st, 200, "el token correcto tiene que emitir la key: {resp}");
        assert!(resp.contains("quipu_live_"), "la respuesta con el token correcto no trae una key: {resp}");
    }
}

#[test]
fn un_cuerpo_gigante_se_corta_y_no_se_acumula() {
    // Defensa en profundidad contra OOM (auditoría 2026-09-27, patrón del incidente
    // OpenAI→Hugging Face: un canal de egreso/ingreso sin cota). El binario NO debe
    // depender de que Nginx corte el cuerpo delante: `evaluate` lee con tope y un
    // cuerpo enorme se rechaza ANTES de acumularlo. Discrimina del rechazo por hex
    // (mismo 400) mirando el MENSAJE: solo el tope dice "demasiado grande"; sin tope
    // el cuerpo llegaría a `from_hex_32` y el 400 diría "64 hex".
    let seed = [9u8; 32];
    let server_key = voprf::Server::from_seed(&seed, b"quipu-oprf-server-v1").unwrap();
    let store = Store::open_in_memory().unwrap();
    let c = store.create_customer("big@x", "starter").unwrap();
    let k = store.issue_key(&c, 1_000_000, None).unwrap().secret;

    let addr = free_addr();
    let cfg = Config { addr: addr.clone(), admin_token: None };
    thread::spawn(move || {
        let _ = http::serve(store, server_key, cfg);
    });
    wait_ready(&addr);

    // ROJO — 65 KiB, por encima del tope de 64 KiB: se corta por tamaño.
    let gigante = "a".repeat(65 * 1024);
    let (st, _cab, body) = evaluar(&addr, &k, &gigante);
    assert_eq!(st, 400, "un cuerpo gigante debe rechazarse, no acumularse (status {st})");
    assert!(
        body.contains("demasiado grande"),
        "el 400 no vino del tope de tamaño sino de otro sitio: {body:?}"
    );

    // VERDE — un punto cegado válido (64 hex) pasa el tope y se evalúa: la cota no
    // recorta lo legítimo (directiva 21).
    let (st_ok, _c2, b_ok) = evaluar(&addr, &k, &blinded_valido());
    assert_eq!(st_ok, 200, "un cuerpo legítimo NO debe chocar con el tope: {b_ok}");
}

#[test]
fn el_tope_de_cuerpo_tambien_protege_el_endpoint_de_admin() {
    // `sin-caso-rojo` marcó que el tope en /admin/keys no lo vigilaba ninguna
    // prueba (solo /v1/oprf/evaluate). Un `ok_or` sin caso rojo es indistinguible
    // de uno cableado mal (D33). El admin está tras token, pero el tope debe morder
    // ANTES de parsear el form, igual que en evaluate.
    let sk = voprf::Server::from_seed(&[3u8; 32], b"quipu-oprf-server-v1").unwrap();
    let store = Store::open_in_memory().unwrap();
    let addr = free_addr();
    let token = "un-token-de-admin-largo";
    let cfg = Config { addr: addr.clone(), admin_token: Some(token.to_string()) };
    thread::spawn(move || {
        let _ = http::serve(store, sk, cfg);
    });
    wait_ready(&addr);

    let peticion_admin = |cuerpo: &str| {
        let raw = format!(
            "POST /admin/keys HTTP/1.1\r\nHost: {addr}\r\nX-Admin-Token: {token}\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{cuerpo}",
            cuerpo.len()
        );
        peticion(&addr, &raw)
    };

    // ROJO — cuerpo gigante con token VÁLIDO: el tope muerde antes del form.
    let (st, _c, body) = peticion_admin(&"a".repeat(65 * 1024));
    assert_eq!(st, 400, "el admin con cuerpo gigante debe cortarse: {st}");
    assert!(body.contains("demasiado grande"), "no vino del tope: {body:?}");

    // VERDE — un form legítimo con token válido emite la key (no choca con el tope).
    let (st_ok, _c2, resp) = peticion_admin("email=a@b.com&plan=starter");
    assert_eq!(st_ok, 200, "un alta legítima no debe chocar con el tope: {resp}");
}

/// Lee UNA respuesta HTTP/1.1 de un socket keep-alive (cabeceras hasta `\r\n\r\n`,
/// luego el cuerpo según `Content-Length`). Devuelve (status, cuerpo).
fn una_respuesta(s: &mut TcpStream) -> (u16, String) {
    use std::io::Read;
    let mut datos = Vec::new();
    let mut byte = [0u8; 1];
    // Cabeceras: hasta el CRLFCRLF.
    while !datos.ends_with(b"\r\n\r\n") {
        match s.read(&mut byte) {
            Ok(0) | Err(_) => return (0, String::from_utf8_lossy(&datos).into_owned()),
            Ok(_) => datos.push(byte[0]),
        }
    }
    let cab = String::from_utf8_lossy(&datos).into_owned();
    let status = cab
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let n: usize = cab
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split_once(':'))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0);
    let mut cuerpo = vec![0u8; n];
    if n > 0 {
        let _ = s.read_exact(&mut cuerpo);
    }
    (status, String::from_utf8_lossy(&cuerpo).into_owned())
}

#[test]
fn un_cuerpo_chunked_gigante_no_desincroniza_la_conexion_keep_alive() {
    // Hallazgo del concilio (sonnet, conf 9): con Content-Length, `EqualReader::drop`
    // drena el residuo; con Transfer-Encoding: chunked NO hay EqualReader, así que al
    // cortar la lectura el resto del cuerpo quedaba en la conexión y —en keep-alive—
    // se interpretaba como la petición SIGUIENTE, corrompiéndola. `tiny_http` descarta
    // un `Connection: close` puesto a mano, así que el arreglo DRENA el residuo para
    // sincronizar la conexión. Se verifica la propiedad real: tras un cuerpo chunked
    // gigante en una conexión keep-alive, la petición SIGUIENTE en esa MISMA conexión
    // se atiende bien. (Mutante D33: quitar `drenar(req)` → la 2ª petición no llega
    // limpia y esta prueba cae, que es justo lo que sonnet midió sin el arreglo.)
    use std::io::Write;
    let sk = voprf::Server::from_seed(&[5u8; 32], b"quipu-oprf-server-v1").unwrap();
    let store = Store::open_in_memory().unwrap();
    let c = store.create_customer("chunk@x", "starter").unwrap();
    let k = store.issue_key(&c, 1_000_000, None).unwrap().secret;
    let addr = free_addr();
    let cfg = Config { addr: addr.clone(), admin_token: None };
    thread::spawn(move || {
        let _ = http::serve(store, sk, cfg);
    });
    wait_ready(&addr);

    let mut s = TcpStream::connect(&addr).unwrap();

    // 1ª petición: cuerpo chunked de 70 000 B en un chunk bien terminado (0\r\n\r\n).
    let datos = "a".repeat(70_000);
    let chunked = format!("{:x}\r\n{datos}\r\n0\r\n\r\n", datos.len());
    let req1 = format!(
        "POST /v1/oprf/evaluate HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {k}\r\n\
         Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n{chunked}"
    );
    s.write_all(req1.as_bytes()).unwrap();
    let (st1, _b1) = una_respuesta(&mut s);
    assert_eq!(st1, 400, "el cuerpo chunked gigante debe cortarse (400), fue {st1}");

    // 2ª petición en la MISMA conexión: un GET /healthz limpio DEBE dar 200 "ok".
    // Si el residuo no se drenó, tiny_http lo parsea como esta petición y la corrompe.
    let req2 = format!("GET /healthz HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    s.write_all(req2.as_bytes()).unwrap();
    let (st2, b2) = una_respuesta(&mut s);
    assert_eq!(st2, 200, "la petición SIGUIENTE en la misma conexión se corrompió (desync): {st2}");
    assert!(b2.contains("ok"), "healthz no respondió ok tras el cuerpo cortado: {b2:?}");
}
