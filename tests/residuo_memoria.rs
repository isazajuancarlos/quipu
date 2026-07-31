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

/// Cuenta apariciones de `aguja` en la memoria escribible del proceso `pid`.
fn residuo(pid: u32, aguja: &[u8]) -> std::io::Result<usize> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    let mut mem = File::open(format!("/proc/{pid}/mem"))?;
    let mut hallazgos = 0usize;
    let mut buf: Vec<u8> = Vec::new();

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
        buf.clear();
        buf.resize((fin - ini) as usize, 0);
        if mem.seek(SeekFrom::Start(ini)).is_err() {
            continue;
        }
        // Una región puede desaparecer entre leer maps y leerla: no es un fallo.
        if mem.read_exact(&mut buf).is_err() {
            continue;
        }
        hallazgos += buf.windows(aguja.len()).filter(|v| *v == aguja).count();
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

    {
        use quipu::firmante::firmar_con_comparticiones;
        use quipu::{pqsign, shamir};

        let semilla = semilla_canario();
        let sk = pqsign::SigningKey::from_bytes(&semilla).expect("64 bytes son dos semillas");

        // El camino real que #131.2 pone en duda: reconstruir por Shamir y firmar.
        let partes = shamir::split(&sk.to_bytes(), 3, 5).expect("reparto válido");
        let firma = firmar_con_comparticiones(&partes[..3], b"acta").expect("firma");
        assert_eq!(firma.len(), pqsign::SIGNATURE_LEN);

        if escenario == "con-fuga" {
            fuga = Some(semilla.to_vec());
        }
        // Todo lo demás se suelta aquí: `sk`, `partes`, `firma`, y la propia
        // `semilla` (que es un array en la pila y se sobreescribe abajo).
    }

    // La copia que el propio test tiene en la pila NO cuenta como residuo de la
    // librería: es del arnés. Se borra a mano para no contarla contra Quipu.
    let mut en_pila = semilla_canario();
    en_pila.fill(0);
    std::hint::black_box(&en_pila);

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
