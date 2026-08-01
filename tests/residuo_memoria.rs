// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! ¿Cuánto material sensible SOBREVIVE a la operación que lo usó? (T6)
//!
//! # Qué cierra, y por qué es cerrable
//!
//! `docs/THREAT_MODEL.md` T6 es el «atacante con acceso a la memoria del proceso
//! **DESPUÉS** de una operación»: volcado, imagen de swap, hibernación, cold
//! boot. El atacante presente MIENTRAS corre es R5 —endpoint comprometido— y ya
//! está declarado fuera de alcance. Son dos amenazas distintas, y confundirlas
//! lleva a la conclusión equivocada de que la brecha no se puede cerrar: contra
//! quien manda en el kernel en vivo, no; contra quien lee la memoria después, sí.
//!
//! Lo que faltaba no era una llamada del sistema —`mlock` protege del swap y de
//! nada más, al precio de meter `libc`— sino que «la zeroización es *best-effort*»
//! **no tenía número**. Esto se lo pone.
//!
//! # Cómo mide, y por qué DOS procesos
//!
//! El hijo hace la operación y se queda quieto; el padre lee `/proc/<hijo>/mem` y
//! cuenta apariciones del secreto. Solo `std`: en Linux la memoria de un proceso
//! es un fichero, así que no hace falta `libc` ni ptrace explícito (con
//! `yama/ptrace_scope=1` basta ser ancestro).
//!
//! Escanear la memoria del PROPIO proceso no vale, y no es una preferencia: el
//! buffer de lectura vive en el mismo montón que se lee, de modo que leer una
//! región DUPLICA dentro del buffer justo lo que se busca. Medido al intentarlo:
//! la misma situación daba 0, 17 o 33 según el orden del barrido. El instrumento
//! se contaba a sí mismo.
//!
//! # Por qué se busca una PORCIÓN DEL MEDIO
//!
//! Al liberar un trozo, el asignador escribe sus punteros sobre los **primeros 16
//! bytes**. Exigir que coincida el secreto entero daba «no hay residuo» con 240
//! de 256 bytes del secreto intactos en memoria liberada — que es el secreto
//! entero. Un falso negativo, y de los caros. Se busca un tramo interior, que la
//! metadata del asignador no toca.

// Linux por `/proc`, y `escrow` porque `shamir` y `firmar_con_comparticiones`
// viven tras ese feature — que es justamente el camino que T6 pone en duda.
#![cfg(all(target_os = "linux", feature = "escrow"))]

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::process::{Command, Stdio};

/// Semilla de firma reconocible: 64 bytes que no se parecen a nada que aparezca
/// por casualidad en memoria. No vale un relleno constante (`[0x42; 64]`): eso sí
/// sale por casualidad, y además ni siquiera parsea como clave.
fn semilla_canario() -> [u8; 64] {
    let mut s = [0u8; 64];
    let mut x: u32 = 0x9E37_79B9;
    for (i, b) in s.iter_mut().enumerate() {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *b = (x >> 24) as u8 ^ (i as u8).wrapping_mul(31);
    }
    s
}

/// El tramo que se busca: interior, para esquivar la metadata del asignador.
fn aguja() -> [u8; 32] {
    let s = semilla_canario();
    let mut a = [0u8; 32];
    a.copy_from_slice(&s[16..48]);
    a
}

/// Contraseña canario: larga y sin sentido, para que no aparezca por casualidad.
/// Se busca ENTERA, no un tramo: es texto y no lo asigna el montón como bloque
/// suelto necesariamente, pero sí es lo bastante rara.
const FRASE_CANARIO: &str = "canario-de-residuo-Xq7v2Lm9Pk4Rt8Wz3Nb6Hd1Fg5Js0Ay";

/// Salt fijo para que padre e hijo deriven exactamente la misma clave maestra.
/// En producción el salt es aleatorio; aquí se fija porque el padre tiene que
/// saber QUÉ buscar, y no es una debilidad del código sino del canario.
const SAL_FIJA: [u8; 16] = *b"sal-fija-de-test";

/// El contenido del volumen OCULTO en el escenario de negación.
///
/// Es la aguja que más pesa de todo este banco: en un módulo cuya única promesa
/// es que nadie pueda **probar** que hay un segundo volumen, este texto en una
/// imagen de swap o en un volcado **es esa prueba**. No es una fuga de
/// confidencialidad más — es la fuga que anula el formato entero.
///
/// Se elige largo y sin estructura repetida por lo mismo que el resto: un patrón
/// corto o constante sale por casualidad y produce falsos positivos.
#[cfg(all(feature = "negacion", feature = "lab"))]
const OCULTO_CANARIO: &[u8] =
    b"oculto-Zt4Nq8Vw1Yr6Bm3Xk9Lp2Hs7Dc0Gj5Af-el-que-no-debe-quedar-en-memoria";

/// Deja el canario en un marco de pila y vuelve, dejándolo atrás.
///
/// `inline(never)` para que el marco exista de verdad y no se funda con el del
/// llamante. Y el marco es GRANDE con el canario en su extremo profundo (índice
/// 0 es la dirección más baja, porque la pila crece hacia abajo): un canario a
/// 1,5 KiB de profundidad lo pisaba el propio `println!` del arnés antes de que
/// el padre llegara a mirar, y entonces la mitad «sucia» de la prueba salía
/// vacía y no probaba nada. Aquí queda a ~12 KiB: más hondo que lo que gasta la
/// E/S del arnés, y dentro del alcance del limpiador.
#[inline(never)]
fn plantar_en_la_pila(canario: &[u8; 32]) -> u8 {
    let mut marco = [0u8; 12 * 1024];
    marco[..32].copy_from_slice(canario);
    std::hint::black_box(&marco);
    marco[0]
}

/// Cuenta apariciones de `aguja` en la memoria escribible del proceso `pid`.
fn residuo(pid: u32, aguja: &[u8]) -> std::io::Result<usize> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    let mut mem = File::open(format!("/proc/{pid}/mem"))?;
    let mut hallazgos = 0usize;
    let mut buf: Vec<u8> = Vec::new();
    let mut ilegibles: Vec<String> = Vec::new();
    let mut donde: Vec<String> = Vec::new();
    let mut leidas = 0usize;

    for linea in maps.lines() {
        let mut campos = linea.split_whitespace();
        let (Some(rango), Some(perms)) = (campos.next(), campos.next()) else {
            continue;
        };
        // Solo lo escribible: ahí viven el montón y la pila.
        if !perms.starts_with("rw") {
            continue;
        }
        // Regiones especiales que no se pueden leer o no son datos del proceso.
        if linea.contains("[vvar]") || linea.contains("[vsyscall]") {
            continue;
        }
        let Some((a, b)) = rango.split_once('-') else {
            continue;
        };
        let (Ok(ini), Ok(fin)) = (u64::from_str_radix(a, 16), u64::from_str_radix(b, 16)) else {
            continue;
        };
        // Cota de cordura: una región absurda es un mapeo que no nos interesa.
        if fin <= ini || fin - ini > 256 * 1024 * 1024 {
            continue;
        }
        // SE LEE PÁGINA A PÁGINA, no la región de un tirón, y esto no es
        // eficiencia sino corrección. Una región puede tener páginas sin mapear
        // —la pila de un hilo son 2 MiB reservados de los que solo se ha tocado
        // una parte—, y un `read_exact` de toda la región falla en la primera de
        // ellas y descarta la región ENTERA. Medido: así se perdía justo la pila
        // del hilo donde vivía el canario, y el instrumento informaba «no hay
        // residuo» por no haber mirado.
        //
        // Las páginas legibles contiguas se acumulan en un tramo, y el tramo se
        // barre entero: si no, una coincidencia a caballo entre dos páginas se
        // perdería.
        const PAGINA: usize = 4096;
        let antes_de_la_region = hallazgos;
        buf.clear();
        let mut pagina = vec![0u8; PAGINA];
        let mut fallos_en_region = 0usize;
        let mut dir = ini;
        while dir < fin {
            let n = PAGINA.min((fin - dir) as usize);
            let ok = mem.seek(SeekFrom::Start(dir)).is_ok()
                && mem.read_exact(&mut pagina[..n]).is_ok();
            if ok {
                buf.extend_from_slice(&pagina[..n]);
            } else {
                fallos_en_region += 1;
                // Se corta el tramo: lo acumulado ya no es contiguo con lo que venga.
                if buf.len() >= aguja.len() {
                    hallazgos += buf.windows(aguja.len()).filter(|v| *v == aguja).count();
                }
                buf.clear();
            }
            dir += n as u64;
        }
        if buf.len() >= aguja.len() {
            hallazgos += buf.windows(aguja.len()).filter(|v| *v == aguja).count();
        }
        if fallos_en_region > 0 {
            ilegibles.push(format!("{linea}  ({fallos_en_region} páginas)"));
        }
        if hallazgos > antes_de_la_region {
            donde.push(format!(
                "{} en {}",
                hallazgos - antes_de_la_region,
                linea.trim()
            ));
        }
        leidas += 1;
    }

    // LAS REGIONES QUE NO SE PUDIERON LEER NO SE CALLAN. Un `continue` mudo aquí
    // convierte «no encontré el secreto» en «no miré donde estaba», y las dos
    // cosas devuelven cero. Con `QUIPU_RESIDUO_DEBUG` se ven.
    if std::env::var_os("QUIPU_RESIDUO_DEBUG").is_some() {
        eprintln!("[residuo] regiones leídas: {leidas}, ilegibles: {}", ilegibles.len());
        for l in &ilegibles {
            eprintln!("[residuo]   ilegible: {l}");
        }
        for d in &donde {
            eprintln!("[residuo]   HALLAZGO: {d}");
        }
    }
    Ok(hallazgos)
}

/// Parámetros baratos: lo que se mide es el residuo, no el coste del KDF.
fn params_baratos() -> quipu::kdf::KdfParams {
    quipu::kdf::KdfParams {
        mem_kib: 64,
        iterations: 1,
        parallelism: 1,
    }
}

/// Lanza el hijo en el escenario `escenario`, espera a que avise, mide `aguja` y
/// lo cierra.
fn medir_aguja(escenario: &str, aguja: &[u8]) -> usize {
    let exe = std::env::current_exe().expect("el binario de prueba tiene ruta");
    let mut hijo = Command::new(exe)
        .env("QUIPU_RESIDUO_ESCENARIO", escenario)
        // El hijo re-ejecuta ESTE binario de prueba; el filtro lo lleva al test
        // que hace de cuerpo del hijo y a ningún otro.
        .args(["cuerpo_del_hijo", "--exact", "--nocapture", "--ignored"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("se puede lanzar el proceso hijo");

    let mut salida = BufReader::new(hijo.stdout.take().expect("stdout tomado"));
    let mut linea = String::new();
    loop {
        linea.clear();
        if salida.read_line(&mut linea).expect("el hijo escribe") == 0 {
            panic!("el hijo terminó sin avisar de que estaba listo");
        }
        if linea.trim() == "LISTO" {
            break;
        }
    }

    let n = residuo(hijo.id(), aguja).expect("se puede leer la memoria del hijo");

    // Soltarlo y esperarlo: un hijo huérfano colgaría el CI.
    if let Some(mut e) = hijo.stdin.take() {
        let _ = e.write_all(b"\n");
    }
    let _ = hijo.wait();
    n
}

/// El caso habitual: la semilla de firma.
fn medir(escenario: &str) -> usize {
    medir_aguja(escenario, &aguja())
}

/// El cuerpo del hijo. Va `#[ignore]` para que no corra en la suite normal: solo
/// lo invoca `medir()` por su nombre exacto.
#[test]
#[ignore = "lo lanza el proceso padre; no es una prueba por sí misma"]
fn cuerpo_del_hijo() {
    let Ok(escenario) = std::env::var("QUIPU_RESIDUO_ESCENARIO") else {
        return;
    };
    // Una fuga deliberada, para comprobar que el instrumento DISCRIMINA. Vive
    // fuera del bloque de abajo para sobrevivir a propósito.
    let mut fuga: Option<Vec<u8>> = None;

    // Escenario de la PILA: comprueba el limpiador en aislamiento. Es la
    // salvaguarda nueva, y una salvaguarda sin una prueba que la vea fallar es
    // una creencia.
    if escenario.starts_with("pila") {
        // TODO EL CANARIO VIVE EN UN MARCO ANIDADO, y no es un capricho de
        // estilo: es lo que hace que este banco mida la librería y no a sí mismo.
        //
        // Antes el canario nacía en el marco de `cuerpo_del_hijo` y se limpiaba
        // con `canario.fill(0)`. En DEBUG bastaba; en RELEASE el compilador deja
        // una copia más en otro hueco del mismo marco que ese `fill` no toca, y
        // ese marco está POR ENCIMA del punto donde se llama al limpiador.
        //
        // `limpiar_pila` sobrescribe hacia ABAJO desde donde se la llama: no
        // puede tocar el marco vivo de quien la invoca, y nunca lo prometió. Así
        // que la prueba fallaba en release por una copia que el mecanismo no
        // podía alcanzar por construcción — el instrumento contándose a sí mismo,
        // igual que cuando se intentó escanear la memoria del propio proceso.
        //
        // MEDIDO el 2026-08-01, y es lo que separó «defecto» de «artefacto»: sin
        // limpiar quedaban 2 copias, a 19 648 B y a 7 008 B del final de la pila
        // (el final es la dirección alta: el marco MÁS SUPERFICIAL). Tras limpiar
        // sobrevivía justo la de 7 008 B, la superficial. Subir la profundidad
        // del limpiador de 64 KiB a 512 KiB no cambiaba nada, porque el problema
        // no estaba debajo. Con el canario dentro del marco anidado: CERO.
        #[inline(never)]
        fn plantar_y_quizas_limpiar(limpiar: bool) {
            let mut c = aguja();
            std::hint::black_box(plantar_en_la_pila(&c));
            c.fill(0);
            std::hint::black_box(&c);
            if limpiar {
                quipu::antihacker::limpiar_pila();
            }
        }
        plantar_y_quizas_limpiar(escenario == "pila-limpia");
        println!("LISTO");
        std::io::stdout().flush().ok();
        let mut s = String::new();
        std::io::stdin().read_line(&mut s).ok();
        return;
    }

    // Escenario del CIFRADO: la contraseña y la clave maestra que deriva de ella
    // atraviesan `encode`/`decode`, que es la superficie más ancha de la
    // librería. Si algo sobrevive ahí, importa más que en el camino de Shamir.
    if escenario.starts_with("cifrado") {
        use quipu::api::{decode, encode, Options};
        use quipu::dictionaries;

        let opts = Options {
            pepper: b"",
            kdf_params: params_baratos(),
            codebook_id: 0,
        };
        let dict = dictionaries::ascii94();
        let simbolos = encode(b"acta reservada", FRASE_CANARIO, &dict, &opts);
        let claro = decode(&simbolos, FRASE_CANARIO, &dict, b"").expect("descifra");
        assert_eq!(claro, b"acta reservada");
        std::hint::black_box(&simbolos);

        // Fuga deliberada EN ESTE ESCENARIO: una copia de la contraseña y otra de
        // la clave maestra, ambas en el MONTÓN (que es lo único que el escáner
        // barre; el literal `FRASE_CANARIO` vive en memoria de solo lectura y no
        // se vería nunca, así que sin esto un 0 no probaría nada).
        if escenario == "cifrado-con-fuga" {
            let mut v = FRASE_CANARIO.as_bytes().to_vec();
            v.extend_from_slice(&quipu::kdf::derive_master_key(
                FRASE_CANARIO,
                &SAL_FIJA,
                b"",
                &params_baratos(),
            ));
            fuga = Some(v);
        }

        println!("LISTO");
        std::io::stdout().flush().ok();
        let mut s = String::new();
        std::io::stdin().read_line(&mut s).ok();
        std::hint::black_box(&fuga);
        return;
    }

    #[cfg(all(feature = "negacion", feature = "lab"))]
    if escenario.starts_with("negacion") {
        use quipu::negacion::{abrir, crear, Perfil};

        // El claro del OCULTO es la aguja: en un módulo cuya única promesa es que
        // nadie pueda PROBAR que hay un segundo volumen, ese claro en el swap o
        // en un volcado ES esa prueba. Es lo que más pesa de todo este banco.
        let mut oculto = OCULTO_CANARIO.to_vec();
        let perfil = Perfil::de_laboratorio("residuo", params_baratos());
        let c = crear(
            2048,
            b"la lista de la compra",
            "clave-del-senuelo",
            Some((oculto.as_slice(), FRASE_CANARIO)),
            perfil,
        )
        .expect("crea");
        // EL BUFFER DE ENTRADA ES DEL LLAMANTE, y la librería no puede borrarlo:
        // le llega por referencia. Si se deja vivo, el banco cuenta UNA copia y
        // se la atribuye a `negacion` — el instrumento contándose a sí mismo,
        // que es el defecto que la cabecera de este archivo describe para el
        // escaneo del propio proceso. Medido: sin este `wipe` la prueba daba 1.
        quipu::antihacker::wipe(&mut oculto);
        let a = abrir(&c, FRASE_CANARIO, Some(perfil)).expect("abre el oculto");
        assert_eq!(a.datos, OCULTO_CANARIO);
        // `a.datos` es la copia que se le entrega al llamante: se borra a mano,
        // porque el residuo que se mide es el que deja la LIBRERÍA, no el que el
        // llamante decida conservar.
        let mut devueltos = a.datos;
        quipu::antihacker::wipe(&mut devueltos);
        std::hint::black_box(&c);

        // Fuga deliberada: si esto no se viera, los ceros de las pruebas no
        // probarían que no hay residuo — probarían que el escáner mira donde no es.
        if escenario == "negacion-con-fuga" {
            let mut v = OCULTO_CANARIO.to_vec();
            v.extend_from_slice(&quipu::kdf::derive_master_key(
                FRASE_CANARIO,
                &SAL_FIJA,
                b"",
                &params_baratos(),
            ));
            fuga = Some(v);
        }

        println!("LISTO");
        std::io::stdout().flush().ok();
        let mut s = String::new();
        std::io::stdin().read_line(&mut s).ok();
        std::hint::black_box(&fuga);
        return;
    }

    {
        use quipu::firmante::firmar_con_comparticiones;
        use quipu::{pqsign, shamir};

        // EL ARNÉS NO PUEDE TOCAR LA CLAVE, o mide su propio rastro. Montar el
        // escenario exige construir una `SigningKey` a partir de la semilla, y esa
        // construcción devuelve por valor: un MOVIMIENTO, y por tanto una copia en
        // el marco de quien la monta. Si eso ocurre en el marco del test, el padre
        // la cuenta y se la achaca a la librería. Medido: así salía 1 copia que no
        // era de Quipu.
        //
        // De modo que el montaje vive en su propio marco profundo, devuelve SOLO
        // las comparticiones —que no llevan el secreto en claro— y su rastro se
        // borra antes de llamar a lo que se quiere medir.
        #[inline(never)]
        fn montar_escenario() -> Vec<shamir::Share> {
            let mut semilla = semilla_canario();
            let sk = pqsign::SigningKey::from_bytes(&semilla).expect("64 bytes son dos semillas");
            let partes = shamir::split(&sk.to_bytes(), 3, 5).expect("reparto válido");
            semilla.fill(0);
            std::hint::black_box(&semilla);
            partes
        }

        let partes = montar_escenario();
        quipu::antihacker::limpiar_pila(); // el rastro del MONTAJE, no el de la librería

        if escenario == "con-fuga" {
            fuga = Some(semilla_canario().to_vec());
        }

        // Y ahora sí, el camino real que #131.2 pone en duda. Cualquier aparición
        // de la semilla a partir de aquí es de Quipu.
        let firma = firmar_con_comparticiones(&partes[..3], b"acta").expect("firma");
        assert_eq!(firma.len(), pqsign::SIGNATURE_LEN);
    }

    println!("LISTO");
    std::io::stdout().flush().ok();
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).ok();
    std::hint::black_box(&fuga);
}

/// EL INSTRUMENTO DISCRIMINA. Sin esto, un 0 en la prueba de abajo sería
/// indistinguible de un medidor averiado — que es exactamente cómo dos objetivos
/// de fuzz de este mismo repositorio estuvieron meses en verde sin fuzzear nada.
#[test]
fn el_medidor_de_residuo_ve_una_fuga_deliberada() {
    let n = medir("con-fuga");
    assert!(
        n > 0,
        "el medidor no vio una copia del secreto que se dejó VIVA a propósito: \
         está averiado, y cualquier 0 que devuelva no significa nada"
    );
}

/// Y el número que la taxonomía no tenía: cuántas copias del material
/// reconstruido sobreviven al camino real de firma con comparticiones.
#[test]
fn firmar_con_comparticiones_no_deja_residuo_en_memoria() {
    let n = medir("limpio");
    assert_eq!(
        n, 0,
        "quedan {n} copias de la semilla de firma en la memoria del proceso tras \
         `firmar_con_comparticiones`. T6 dice que la memoria se lee DESPUÉS de la \
         operación, así que cada copia es el secreto entero para quien tome un \
         volcado, una imagen de swap o un cold boot"
    );
}

/// EL LIMPIADOR DE PILA HACE LO QUE DICE, y se prueba en los dos sentidos.
///
/// `zeroize` no puede cubrir esto: en Rust mover un valor es un `memcpy` y `Drop`
/// solo corre en el destino final, así que las posiciones por las que el secreto
/// pasó al moverse quedan intactas. Esto es lo que las borra, y sin la mitad
/// «sucia» de esta prueba no habría forma de saber si borra algo o no hace nada.
#[test]
fn el_limpiador_de_pila_borra_lo_que_un_marco_dejo_atras() {
    let sucio = medir("pila-sucia");
    assert!(
        sucio > 0,
        "el canario plantado en un marco de pila no aparece ni SIN limpiar: la \
         prueba no está midiendo la pila, y su otra mitad no probaría nada"
    );
    let limpio = medir("pila-limpia");
    assert_eq!(
        limpio, 0,
        "tras `limpiar_pila()` siguen {limpio} copias del canario en la pila \
         (sin limpiar había {sucio})"
    );
}

/// El control del escenario de cifrado, y NO es redundante con el de arriba. El
/// literal `FRASE_CANARIO` vive en memoria de solo lectura, que este escáner no
/// barre; sin comprobar que una copia EN EL MONTÓN sí se ve, los dos ceros de
/// abajo serían indistinguibles de un escáner que mira donde no es.
#[test]
fn el_medidor_ve_una_fuga_deliberada_tambien_al_cifrar() {
    let clave = quipu::kdf::derive_master_key(FRASE_CANARIO, &SAL_FIJA, b"", &params_baratos());
    assert!(
        medir_aguja("cifrado-con-fuga", FRASE_CANARIO.as_bytes()) > 0,
        "el medidor no ve una copia de la CONTRASEÑA dejada viva en el montón"
    );
    assert!(
        medir_aguja("cifrado-con-fuga", &clave) > 0,
        "el medidor no ve una copia de la CLAVE MAESTRA dejada viva en el montón"
    );
}

/// EL CONTROL DEL ESCENARIO DE NEGACIÓN, y sin él las dos de abajo no valdrían.
///
/// El literal `OCULTO_CANARIO` vive en memoria de solo lectura, que este escáner
/// no barre. Si una copia EN EL MONTÓN tampoco se viera, un cero significaría
/// «el escáner mira donde no es», que es exactamente el cero falso que este
/// proyecto ya produjo cuatro veces.
#[cfg(all(feature = "negacion", feature = "lab"))]
#[test]
fn el_medidor_ve_una_fuga_deliberada_tambien_en_negacion() {
    let clave = quipu::kdf::derive_master_key(FRASE_CANARIO, &SAL_FIJA, b"", &params_baratos());
    assert!(
        medir_aguja("negacion-con-fuga", OCULTO_CANARIO) > 0,
        "el medidor no ve una copia del CLARO DEL OCULTO dejada viva en el montón"
    );
    assert!(
        medir_aguja("negacion-con-fuga", &clave) > 0,
        "el medidor no ve una copia de la CLAVE MAESTRA dejada viva en el montón"
    );
}

/// LO QUE ESTE MÓDULO NO PUEDE PERMITIRSE: que el claro del volumen oculto
/// sobreviva a la operación que lo escribió y lo leyó.
///
/// Hasta el 2026-08-01 `negacion.rs` no tenía **una sola** llamada de borrado,
/// mientras el módulo hermano `api.rs` limpiaba en cada paso. Lo halló la
/// revisión independiente; esto es lo que impide que vuelva.
#[cfg(all(feature = "negacion", feature = "lab"))]
#[test]
fn el_contenedor_con_negacion_no_deja_el_claro_del_oculto_en_memoria() {
    let n = medir_aguja("negacion", OCULTO_CANARIO);
    assert_eq!(
        n, 0,
        "quedan {n} copias del CLARO DEL VOLUMEN OCULTO en memoria tras crear y          abrir el contenedor — y ese residuo ES la prueba de que el segundo          volumen existe, que es justo lo que el formato existe para que no exista"
    );
}

/// Y la clave maestra que lo abre, por la misma razón.
#[cfg(all(feature = "negacion", feature = "lab"))]
#[test]
fn el_contenedor_con_negacion_no_deja_la_clave_maestra_en_memoria() {
    let clave = quipu::kdf::derive_master_key(FRASE_CANARIO, &SAL_FIJA, b"", &params_baratos());
    let n = medir_aguja("negacion", &clave);
    assert_eq!(n, 0, "quedan {n} copias de la clave maestra del volumen oculto");
}

/// La superficie ANCHA: la clave maestra que `encode`/`decode` derivan de la
/// contraseña. Es el secreto que más veces pasa por la librería, así que su
/// residuo pesa más que el del camino de custodia.
#[test]
fn el_cifrado_no_deja_la_clave_maestra_en_memoria() {
    let clave = quipu::kdf::derive_master_key(FRASE_CANARIO, &SAL_FIJA, b"", &params_baratos());
    let n = medir_aguja("cifrado", &clave);
    assert_eq!(
        n, 0,
        "quedan {n} copias de la clave maestra en memoria tras cifrar y descifrar"
    );
}

/// Y la CONTRASEÑA misma. Es la que el usuario reutiliza en otros sitios, así que
/// su residuo es el más caro de todos: no compromete un artefacto, compromete a
/// la persona.
#[test]
fn el_cifrado_no_deja_la_contrasena_en_memoria() {
    let n = medir_aguja("cifrado", FRASE_CANARIO.as_bytes());
    assert_eq!(
        n, 0,
        "quedan {n} copias de la CONTRASEÑA en memoria tras cifrar y descifrar"
    );
}
