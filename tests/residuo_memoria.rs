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

// Linux, por `/proc`. LOS FEATURES SE PIDEN POR ESCENARIO, no aquí, y esto no es
// higiene: el gate de archivo que había —`escrow`— decidía en qué pasadas del CI
// se medía el residuo, y la pasada de RELEASE (`cargo test --features slh
// --release`) no activa ese feature. Resultado: el archivo entero se saltaba en
// release, donde el optimizador incrusta funciones y mueve copias, y ahí la
// defensa NO funcionaba —1 copia del canario superviviente, 3 de la clave maestra,
// 3 de la de contenido— mientras en debug daba cero. Sin gate de archivo, cada
// escenario pide lo suyo y las mediciones corren en las cuatro pasadas.
#![cfg(target_os = "linux")]

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

/// El TEXTO EN CLARO del usuario, que es el secreto que más gente afecta: la
/// contraseña compromete a quien la reutiliza, pero el claro ES el documento.
/// 64 bytes con la misma pinta de azar que la semilla, y con OTRA constante para
/// que las dos agujas no se confundan entre sí.
fn mensaje_canario() -> [u8; 64] {
    let mut s = [0u8; 64];
    let mut x: u32 = 0x517C_C1B7;
    for (i, b) in s.iter_mut().enumerate() {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *b = (x >> 24) as u8 ^ (i as u8).wrapping_mul(17);
    }
    s
}

/// Tramo interior del mensaje, por lo mismo que `aguja()`: los primeros 16 bytes
/// de un bloque liberado se los come la metadata del asignador.
fn aguja_mensaje() -> [u8; 32] {
    let m = mensaje_canario();
    let mut a = [0u8; 32];
    a.copy_from_slice(&m[16..48]);
    a
}

/// Hexadecimal, para pasarle al hijo material sensible por el ENTORNO sin
/// plantárselo en memoria: el hexadecimal de una aguja no es la aguja, así que la
/// copia que el entorno deja no la cuenta el escáner. El hijo la convierte a
/// bytes en un marco profundo y borra ese marco antes de tocar la librería.
fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// `with_capacity` NO es cosmético: un `Vec` que crece reasignando deja por el
/// montón copias PARCIALES del secreto que nadie borra, y esas copias son del
/// arnés, no de la librería. Reservando de una vez no hay reasignación.
fn des_hex(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut v = Vec::with_capacity(b.len() / 2);
    for par in b.chunks_exact(2) {
        let t = std::str::from_utf8(par).expect("hexadecimal válido");
        v.push(u8::from_str_radix(t, 16).expect("hexadecimal válido"));
    }
    v
}

/// Contraseña canario: larga y sin sentido, para que no aparezca por casualidad.
/// Se busca ENTERA, no un tramo: es texto y no lo asigna el montón como bloque
/// suelto necesariamente, pero sí es lo bastante rara.
const FRASE_CANARIO: &str = "canario-de-residuo-Xq7v2Lm9Pk4Rt8Wz3Nb6Hd1Fg5Js0Ay";

// AQUÍ VIVÍA `SAL_FIJA`, y su desaparición es el arreglo, no una limpieza.
//
// Decía: «salt fijo para que padre e hijo deriven exactamente la misma clave
// maestra; en producción el salt es aleatorio, aquí se fija porque el padre
// tiene que saber QUÉ buscar». La primera mitad era verdad y la segunda era el
// fallo: la librería NUNCA deriva con esa sal —ni `encode` ni `negacion::crear`,
// que la toman del CSPRNG—, así que el padre buscaba una clave que el proceso
// medido no había construido jamás. Cero copias, y el cero no significaba nada.
//
// El camino de contraseña se arregló leyendo la sal REAL de la cabecera
// (`sobre_con_contrasena`). El de negación seguía con la sal fija hasta el
// 2026-08-03: ahora el hijo anuncia su contenedor y el padre deriva de ahí
// (`clave_maestra_del_oculto`), validando la clave contra el artefacto.

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
        // Dirección del primer byte de `buf`, para poder decir DÓNDE está cada
        // coincidencia y no solo cuántas hay: la profundidad dentro de la pila es
        // lo que dice si un limpiador la alcanza.
        let mut inicio_tramo = ini;
        let mut posiciones: Vec<u64> = Vec::new();
        while dir < fin {
            let n = PAGINA.min((fin - dir) as usize);
            let ok = mem.seek(SeekFrom::Start(dir)).is_ok()
                && mem.read_exact(&mut pagina[..n]).is_ok();
            if ok {
                buf.extend_from_slice(&pagina[..n]);
            } else {
                fallos_en_region += 1;
                // Se corta el tramo: lo acumulado ya no es contiguo con lo que venga.
                for (i, v) in buf.windows(aguja.len()).enumerate() {
                    if v == aguja {
                        hallazgos += 1;
                        posiciones.push(inicio_tramo + i as u64);
                    }
                }
                buf.clear();
                inicio_tramo = dir + n as u64;
            }
            dir += n as u64;
        }
        for (i, v) in buf.windows(aguja.len()).enumerate() {
            if v == aguja {
                hallazgos += 1;
                posiciones.push(inicio_tramo + i as u64);
            }
        }
        if fallos_en_region > 0 {
            ilegibles.push(format!("{linea}  ({fallos_en_region} páginas)"));
        }
        if hallazgos > antes_de_la_region {
            // La PROFUNDIDAD importa para diagnosticar: la pila crece hacia
            // abajo, así que la distancia al final de la región dice a cuántos
            // KiB por debajo del tope vive la copia — y eso es exactamente lo que
            // decide si un limpiador de 64 KiB la alcanza o no.
            let profundidades: Vec<String> = posiciones
                .iter()
                .map(|p| format!("{} KiB", (fin - p) / 1024))
                .collect();
            donde.push(format!(
                "{} en {}  (a {} del tope de la región)",
                hallazgos - antes_de_la_region,
                linea.trim(),
                profundidades.join(", ")
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

/// El sobre del camino híbrido, montado EN EL PADRE — cuya memoria nadie escanea.
///
/// # Por qué lo monta el padre y no el hijo
///
/// Las tres agujas de este camino (la clave secreta del destinatario, la clave de
/// contenido que sale de la decapsulación y el texto en claro) tienen que ser
/// conocidas por quien MIDE. El par de claves es aleatorio, así que si lo generase
/// el hijo el padre no sabría qué buscar; y hacer que el hijo se lo cuente sería
/// plantarle en memoria justo lo que se busca. Aquí el padre genera, cifra,
/// decapsula y le pasa al hijo el sobre y la clave EN HEXADECIMAL.
struct Sobre {
    simbolos: String,
    /// Los 96 bytes de la clave secreta: 32 de X25519 y 64 de la semilla ML-KEM.
    sk: Vec<u8>,
    /// No es secreta —viaja en la cabecera—, pero el hijo la necesita para poder
    /// decapsular en el escenario de control sin parsear el contenedor.
    encapsulacion: Vec<u8>,
    clave_contenido: [u8; 32],
}

impl Sobre {
    /// La aguja de la clave secreta va DENTRO de la semilla ML-KEM (bytes 32..96).
    /// A caballo entre las dos mitades no serviría: `SecretKey` las guarda en
    /// campos distintos, así que un tramo que las cruce no aparece contiguo en
    /// memoria ni con la clave viva, y un cero significaría «mal elegida la
    /// aguja», no «no hay residuo».
    fn aguja_clave_secreta(&self) -> [u8; 32] {
        let mut a = [0u8; 32];
        a.copy_from_slice(&self.sk[40..72]);
        a
    }
}

/// Monta el sobre y COMPRUEBA que la clave de contenido es la de verdad.
///
/// La comprobación no es adorno: para obtener esa clave hay que abrir la cabecera
/// `QPQ1` a mano (magic | versión | flags | nonce | encapsulación), y un
/// desplazamiento mal puesto daría 32 bytes que no son la clave de nadie. Como
/// esa aguja no aparecería nunca, la medición diría «cero residuo» sin haber
/// mirado nada. Descifrando el contenedor con ella y exigiendo el mensaje
/// canario, un formato que cambie rompe esta prueba EN VOZ ALTA (directiva 20).
fn sobre_para_el_destinatario() -> Sobre {
    use quipu::api::encode_to_recipient;
    use quipu::{cipher, codec, dictionaries, pqhybrid, prelayers};

    let dict = dictionaries::ascii94();
    let (pk, sk) = pqhybrid::generate_keypair().expect("hay entropía");
    let simbolos = encode_to_recipient(&mensaje_canario(), &pk, &dict).expect("cifra");

    let indices = dict.decode(&simbolos).expect("lo que acaba de escribir el dict");
    let blob = codec::decode_base_n(&indices, dict.base());
    const PREFIJO: usize = 4 + 1 + 1 + cipher::NONCE_LEN;
    assert_eq!(&blob[0..4], b"QPQ1", "el contenedor híbrido cambió de magic");
    let fin = PREFIJO + pqhybrid::ENCAPSULATION_LEN;
    let nonce: [u8; cipher::NONCE_LEN] = blob[6..PREFIJO].try_into().expect("24 bytes de nonce");
    let encapsulacion = blob[PREFIJO..fin].to_vec();
    let clave_contenido =
        pqhybrid::decapsulate(&sk, &encapsulacion).expect("la encapsulación es para esta clave");
    let padded = cipher::decrypt(&clave_contenido, &nonce, &blob[fin..], &blob[0..fin])
        .expect("la clave de contenido descifra el contenedor");
    assert_eq!(
        prelayers::unpad(&padded).expect("relleno Padmé válido"),
        mensaje_canario(),
        "la clave derivada no abre el sobre: el desplazamiento de la cabecera QPQ1 \
         está mal y la aguja no sería la clave de contenido real"
    );

    Sobre {
        simbolos,
        sk: sk.to_bytes().to_vec(),
        encapsulacion,
        clave_contenido,
    }
}

/// El sobre del camino de CONTRASEÑA, con la clave maestra REAL.
///
/// # Por qué no vale un salt fijo, y por qué esto es una corrección
///
/// Hasta esta prueba, el padre derivaba la clave maestra con un `SAL_FIJA` suyo y
/// buscaba ESA. Pero `encode` saca el salt del RNG en cada llamada, así que la
/// clave que buscaba no era la que la librería usó: era una clave que en el hijo
/// no existía más que en el escenario de fuga —donde se derivaba igual de mal—.
/// El control pasaba y la medición no medía nada. Un generador de ceros, y de los
/// que no se ven porque el verde es idéntico al verde de verdad.
///
/// Aquí el padre cifra, PARSEA la cabecera, deriva con el salt de verdad y
/// comprueba que esa clave abre el contenedor. Si el parseo se desalinea o el
/// `info` de la subclave cambia, esto rompe en voz alta en vez de medir humo.
struct SobreConContrasena {
    simbolos: String,
    salt: [u8; 16],
    clave_maestra: [u8; 32],
}

fn sobre_con_contrasena() -> SobreConContrasena {
    use quipu::api::{encode, Options};
    use quipu::{cipher, codec, container, dictionaries, kdf, prelayers};

    let dict = dictionaries::ascii94();
    let opts = Options {
        pepper: b"",
        kdf_params: params_baratos(),
        codebook_id: 0,
    };
    let simbolos = encode(&mensaje_canario(), FRASE_CANARIO, &dict, &opts);

    let indices = dict.decode(&simbolos).expect("lo que acaba de escribir el dict");
    let blob = codec::decode_base_n(&indices, dict.base());
    let (header, ciphertext) = container::parse(&blob).expect("contenedor válido");
    let params = kdf::KdfParams {
        mem_kib: header.kdf_mem_kib,
        iterations: header.kdf_iterations,
        parallelism: header.kdf_parallelism,
    };
    let clave_maestra = kdf::derive_master_key(FRASE_CANARIO, &header.salt, b"", &params);
    // La comprobación que convierte la aguja en la clave DE VERDAD: se deriva la
    // subclave de cifrado y se descifra el contenedor con ella.
    let subclave = kdf::derive_subkey(&clave_maestra, b"quipu/v1/cipher");
    let padded = cipher::decrypt(&subclave, &header.nonce, ciphertext, &header.to_bytes())
        .expect("la subclave derivada de la clave maestra descifra el contenedor");
    assert_eq!(
        prelayers::unpad(&padded).expect("relleno Padmé válido"),
        mensaje_canario(),
        "la clave maestra derivada no abre el contenedor: la aguja no es la clave \
         que usó la librería y cualquier cero sería humo"
    );

    SobreConContrasena {
        simbolos,
        salt: header.salt,
        clave_maestra,
    }
}

/// El contenedor del camino de STREAMING (`QST1`), cifrado por el padre.
///
/// Va con el trozo MÍNIMO que admite el formato (4 KiB) y un payload de 10 KiB a
/// propósito: con un solo trozo, el bucle por bloques —que es lo propio de este
/// camino, y donde vive su buffer intermedio— no daría una vuelta completa. Así
/// da tres, y el mensaje canario viaja dentro del relleno como viajaría un
/// secreto dentro de un archivo de verdad.
///
/// LO QUE ESTE CAMINO NO MIDE, y va escrito aquí para no prometer de más: la
/// clave que el streaming deriva de la contraseña. Su cabecera es privada, así
/// que el padre no puede sacar el salt sin reconstruir el formato a ciegas, y una
/// aguja mal derivada daría CERO sin haber mirado nada. Se mide lo que sí se
/// puede conocer: el texto en claro y la contraseña.
fn sobre_de_stream() -> String {
    use quipu::api::{decrypt_stream_bytes, encrypt_stream_bytes, StreamOptions};

    let opts = StreamOptions {
        pepper: b"",
        kdf_params: params_baratos(),
        chunk_size: 4096,
    };
    let mut datos = vec![0x5Au8; LARGO_STREAM];
    datos[5000..5064].copy_from_slice(&mensaje_canario());
    let blob = encrypt_stream_bytes(&datos, FRASE_CANARIO, &opts);
    assert_eq!(
        decrypt_stream_bytes(&blob, FRASE_CANARIO, b"").expect("descifra"),
        datos,
        "el contenedor de streaming no devuelve lo que se cifró"
    );
    hex(&blob)
}

/// Tamaño del payload del streaming: tres trozos de 4 KiB y pico.
const LARGO_STREAM: usize = 10 * 1024;

/// El mismo payload, en hexadecimal y SIN cifrar: es lo que se le pasa al hijo
/// cuando lo que se mide es la mitad que CIFRA.
fn claro_de_stream() -> String {
    let mut datos = vec![0x5Au8; LARGO_STREAM];
    datos[5000..5064].copy_from_slice(&mensaje_canario());
    hex(&datos)
}

/// El contenedor de HONEY, cifrado por el padre.
///
/// El secreto es una secuencia de tokens, y la aguja es su IMAGEN EN MEMORIA: un
/// `Vec<u16>` son dos bytes por token. Con un alfabeto de 65 535 símbolos los
/// tokens usan el rango entero y la imagen tiene pinta de azar, que es lo que
/// hace de canario; con `digits()` serían cuatro dígitos y aparecerían por
/// casualidad en cualquier parte.
///
/// Aquí tampoco se mide la clave derivada, por lo mismo que en el streaming.
#[cfg(feature = "honey")]
fn sobre_de_honey() -> (String, Vec<u16>) {
    use quipu::honey::{decrypt, encrypt, Alphabet, HoneyOptions};

    let alfabeto = Alphabet::new(u16::MAX).expect("65 535 símbolos");
    let m = mensaje_canario();
    // 32 tokens desde el mensaje canario: dos bytes cada uno, así que la imagen
    // en memoria del `Vec<u16>` es exactamente el mensaje.
    let tokens: Vec<u16> = m
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]) % u16::MAX)
        .collect();
    let opts = HoneyOptions {
        pepper: b"",
        kdf_params: params_baratos(),
    };
    let blob = encrypt(&tokens, alfabeto, FRASE_CANARIO, &opts).expect("cifra");
    assert_eq!(
        decrypt(&blob, FRASE_CANARIO, b"").expect("descifra"),
        tokens,
        "el contenedor honey no devuelve los tokens canario"
    );
    (hex(&blob), tokens)
}

/// La aguja de honey: la imagen en memoria de los tokens, que es lo que el
/// escáner puede encontrar. Se toma un tramo interior, como todas las demás.
#[cfg(feature = "honey")]
fn aguja_tokens(tokens: &[u16]) -> Vec<u8> {
    let imagen: Vec<u8> = tokens.iter().flat_map(|t| t.to_le_bytes()).collect();
    imagen[16..48].to_vec()
}

/// Lanza el hijo en el escenario `escenario`, espera a que avise, mide `aguja` y
/// lo cierra.
fn medir_aguja(escenario: &str, aguja: &[u8]) -> usize {
    medir_aguja_con(escenario, aguja, &[])
}

/// Igual, pasándole al hijo variables de entorno adicionales.
fn medir_aguja_con(escenario: &str, aguja: &[u8], entorno: &[(&str, &str)]) -> usize {
    medir_con_aguja_tardia(escenario, entorno, |_| aguja.to_vec())
}

/// Para cuando la aguja NO SE PUEDE SABER antes de arrancar al hijo.
///
/// Existe por el fallo que este mismo archivo documenta dos veces: medir buscando
/// una clave que el proceso **nunca derivó** da cero sin haber mirado nada. Pasó
/// con el camino de contraseña —el arnés derivaba con una sal fija suya mientras
/// `encode` la saca del CSPRNG— y seguía vivo en el de negación, donde
/// `negacion::crear` también toma la sal del CSPRNG y ningún perfil la fija.
///
/// El control no lo cazaba, y esa es la parte que hay que entender: la fuga
/// deliberada la planta el HIJO con esa misma sal inventada, así que el control
/// pasaba y la medición de al lado seguía siendo vacua. **Un control que planta
/// su propia aguja no valida la medición real.**
///
/// La solución es que el hijo ANUNCIE lo que hizo —una línea antes de `LISTO`— y
/// el padre derive la aguja de ahí.
fn medir_con_aguja_tardia(
    escenario: &str,
    entorno: &[(&str, &str)],
    aguja_de: impl FnOnce(&str) -> Vec<u8>,
) -> usize {
    let exe = std::env::current_exe().expect("el binario de prueba tiene ruta");
    let mut hijo = Command::new(exe)
        .envs(entorno.iter().copied())
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
    // Lo que el hijo anuncie antes de `LISTO`: hoy, el contenedor que acaba de
    // construir con su sal del CSPRNG.
    let mut anuncio = String::new();
    loop {
        linea.clear();
        if salida.read_line(&mut linea).expect("el hijo escribe") == 0 {
            panic!("el hijo terminó sin avisar de que estaba listo");
        }
        let l = linea.trim();
        if l == "LISTO" {
            break;
        }
        if let Some(resto) = l.strip_prefix("ANUNCIO ") {
            anuncio = resto.to_string();
        }
    }

    let aguja = aguja_de(&anuncio);
    let n = residuo(hijo.id(), &aguja).expect("se puede leer la memoria del hijo");

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

/// Corre un escenario del camino de contraseña con su sobre en el entorno.
fn medir_cifrado(escenario: &str, sobre: &SobreConContrasena, aguja: &[u8]) -> usize {
    let sal = hex(&sobre.salt);
    medir_aguja_con(
        escenario,
        aguja,
        &[
            ("QUIPU_RESIDUO_SIMBOLOS", &sobre.simbolos),
            ("QUIPU_RESIDUO_SAL", &sal),
        ],
    )
}

/// Corre un escenario que solo necesita un contenedor en el entorno (streaming y
/// honey: en los dos, el secreto viene DENTRO del contenedor).
fn medir_con_blob(escenario: &str, blob_hex: &str, aguja: &[u8]) -> usize {
    medir_aguja_con(escenario, aguja, &[("QUIPU_RESIDUO_BLOB", blob_hex)])
}

/// Corre un escenario del camino híbrido pasándole el sobre por el entorno.
fn medir_destinatario(escenario: &str, sobre: &Sobre, aguja: &[u8]) -> usize {
    let sk = hex(&sobre.sk);
    let enc = hex(&sobre.encapsulacion);
    medir_aguja_con(
        escenario,
        aguja,
        &[
            ("QUIPU_RESIDUO_SIMBOLOS", &sobre.simbolos),
            ("QUIPU_RESIDUO_SK", &sk),
            ("QUIPU_RESIDUO_ENCAPSULACION", &enc),
        ],
    )
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
        // El sobre lo trae el PADRE: es el único que puede conocer las tres agujas
        // sin plantárselas aquí. El salt viaja con él —no es secreto, va en claro
        // en la cabecera— y es lo que permite derivar la clave maestra DE VERDAD.
        let simbolos = std::env::var("QUIPU_RESIDUO_SIMBOLOS").expect("el padre pasa el sobre");
        let sal: [u8; 16] = des_hex(&std::env::var("QUIPU_RESIDUO_SAL").expect("el padre pasa el salt"))
            .try_into()
            .expect("16 bytes de salt");

        // Se cifra algo PROPIO para que `encode` también pase por aquí (la
        // contraseña la manejan los dos caminos), y se descifra el sobre del
        // padre, que es el que trae el mensaje canario.
        let propios = encode(b"acta reservada", FRASE_CANARIO, &dict, &opts);
        std::hint::black_box(&propios);

        // Fuga deliberada EN ESTE ESCENARIO: la contraseña, la clave maestra —la
        // que sale del salt REAL, no de uno inventado— y el texto en claro, las
        // tres en el MONTÓN, que es lo único que el escáner barre. El literal
        // `FRASE_CANARIO` vive en memoria de solo lectura y no se vería nunca,
        // así que sin esto un 0 no probaría nada.
        if escenario == "cifrado-con-fuga" {
            let mut v = FRASE_CANARIO.as_bytes().to_vec();
            v.extend_from_slice(&quipu::kdf::derive_master_key(
                FRASE_CANARIO,
                &sal,
                b"",
                &params_baratos(),
            ));
            v.extend_from_slice(&mensaje_canario());
            fuga = Some(v);
        }

        let mut claro = decode(&simbolos, FRASE_CANARIO, &dict, b"").expect("descifra");
        // El 64 va a mano: pedirle la longitud al canario lo construiría aquí y el
        // padre contaría esa copia como residuo de la librería.
        assert_eq!(claro.len(), 64, "no es el mensaje canario");
        // El llamante borra SU copia; lo que se mida después es lo que quedó
        // además de ella.
        quipu::antihacker::wipe(&mut claro);
        drop(claro);

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
        // EL PADRE NO PUEDE ADIVINAR LA SAL: `crear` la toma del CSPRNG y ningún
        // perfil la fija. Sin esta línea el padre derivaba la clave maestra con
        // una sal inventada y medía un cero que no significaba nada.
        println!("ANUNCIO {}", hex(&c));
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
        //
        // Se deriva con LA SAL DEL CONTENEDOR, no con una fija del arnés. Antes
        // era fija, y por eso el control pasaba mientras la medición de al lado
        // buscaba una clave que la librería jamás había derivado: el control
        // plantaba la aguja inventada que el padre esperaba, y los dos se daban
        // la razón sin tocar el código medido.
        if escenario == "negacion-con-fuga" {
            let sal: [u8; 16] = c[..16].try_into().expect("la sal va delante");
            let mut v = OCULTO_CANARIO.to_vec();
            v.extend_from_slice(&quipu::kdf::derive_master_key(
                FRASE_CANARIO,
                &sal,
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

    // Escenario del STREAMING (`QST1`): el camino de los archivos grandes, que no
    // tiene el texto en claro entero en un solo sitio sino trozo a trozo. Cada
    // vuelta del bucle es una oportunidad de dejar residuo, y son tres. Se mide en
    // las DOS direcciones, y esta es la de CIFRAR: quien cifra un archivo tiene su
    // contenido en memoria por trozos igual que quien lo descifra, y ahí el
    // llamante solo puede borrar el suyo. Aquí el padre pasa el CLARO en
    // hexadecimal —que no es la aguja— y el hijo lo convierte, cifra y borra su
    // copia; lo que quede es de la librería.
    if escenario.starts_with("stream-cifra") {
        use quipu::api::{encrypt_stream_bytes, StreamOptions};

        let opts = StreamOptions {
            pepper: b"",
            kdf_params: params_baratos(),
            chunk_size: 4096,
        };
        let mut datos = des_hex(&std::env::var("QUIPU_RESIDUO_BLOB").expect("el padre pasa el claro"));
        assert_eq!(datos.len(), LARGO_STREAM, "no es el payload del canario");

        if escenario == "stream-cifra-con-fuga" {
            fuga = Some(datos.clone());
        }

        let ct = encrypt_stream_bytes(&datos, FRASE_CANARIO, &opts);
        std::hint::black_box(&ct);
        quipu::antihacker::wipe(&mut datos);
        drop(datos);

        println!("LISTO");
        std::io::stdout().flush().ok();
        let mut s = String::new();
        std::io::stdin().read_line(&mut s).ok();
        std::hint::black_box(&fuga);
        return;
    }

    if escenario.starts_with("stream") {
        use quipu::api::decrypt_stream_bytes;

        let blob = des_hex(&std::env::var("QUIPU_RESIDUO_BLOB").expect("el padre pasa el sobre"));

        if escenario == "stream-con-fuga" {
            let mut v = FRASE_CANARIO.as_bytes().to_vec();
            v.extend_from_slice(&mensaje_canario());
            fuga = Some(v);
        }

        let mut claro = decrypt_stream_bytes(&blob, FRASE_CANARIO, b"").expect("descifra");
        assert_eq!(claro.len(), LARGO_STREAM, "no es el payload del canario");
        quipu::antihacker::wipe(&mut claro);
        drop(claro);

        println!("LISTO");
        std::io::stdout().flush().ok();
        let mut s = String::new();
        std::io::stdin().read_line(&mut s).ok();
        std::hint::black_box(&fuga);
        return;
    }

    // Escenario de HONEY: el secreto de baja entropía (un PIN, una frase
    // mnemónica). El contenedor no lleva tag a propósito, así que la contraseña
    // equivocada devuelve un señuelo en vez de un error — razón de más para medir
    // qué queda del secreto DE VERDAD cuando la contraseña es la buena.
    #[cfg(feature = "honey")]
    if escenario.starts_with("honey") {
        use quipu::honey::decrypt;

        let blob = des_hex(&std::env::var("QUIPU_RESIDUO_BLOB").expect("el padre pasa el sobre"));

        if escenario == "honey-con-fuga" {
            let mut v = FRASE_CANARIO.as_bytes().to_vec();
            // La imagen en memoria de los tokens, que es lo que el padre busca.
            v.extend(mensaje_canario().chunks_exact(2).flat_map(|p| {
                (u16::from_le_bytes([p[0], p[1]]) % u16::MAX).to_le_bytes()
            }));
            fuga = Some(v);
        }

        let mut tokens = decrypt(&blob, FRASE_CANARIO, b"").expect("descifra");
        assert_eq!(tokens.len(), 32, "no es el secreto canario");
        // El llamante borra su copia: `Vec<u16>` no se limpia solo.
        tokens.iter_mut().for_each(|t| *t = 0);
        std::hint::black_box(&tokens);
        drop(tokens);

        println!("LISTO");
        std::io::stdout().flush().ok();
        let mut s = String::new();
        std::io::stdin().read_line(&mut s).ok();
        std::hint::black_box(&fuga);
        return;
    }

    // Escenario del DESTINATARIO: el camino híbrido post-cuántico, donde una sola
    // operación toca TRES secretos de naturaleza distinta —la clave secreta de
    // larga vida, la clave de contenido efímera y el texto en claro—. La clave
    // secreta es la que más pesa: es lo único que el usuario no puede regenerar.
    if escenario.starts_with("destinatario") {
        use quipu::api::decode_as_recipient;
        use quipu::{dictionaries, pqhybrid};

        let dict = dictionaries::ascii94();
        let simbolos = std::env::var("QUIPU_RESIDUO_SIMBOLOS").expect("el padre pasa el sobre");
        let encapsulacion =
            des_hex(&std::env::var("QUIPU_RESIDUO_ENCAPSULACION").expect("el padre la pasa"));

        // EL ARNÉS NO PUEDE DEJAR SU PROPIO RASTRO DE LA CLAVE, por lo mismo que
        // en el escenario de Shamir: reconstruirla es un movimiento, y el
        // movimiento deja copias en el marco de quien la monta. Aquí el montaje
        // vive en su propio marco profundo, borra los bytes que usó y la pila se
        // limpia antes de llamar a la librería. Todo lo que aparezca a partir de
        // ahí es de Quipu.
        #[inline(never)]
        fn montar_destinatario() -> pqhybrid::SecretKey {
            let mut bytes =
                des_hex(&std::env::var("QUIPU_RESIDUO_SK").expect("el padre pasa la clave"));
            let sk = pqhybrid::SecretKey::from_bytes(&bytes).expect("96 bytes de clave secreta");
            bytes.fill(0);
            std::hint::black_box(&bytes);
            sk
        }
        let sk = montar_destinatario();
        quipu::antihacker::limpiar_pila();

        // Fuga deliberada EN ESTE ESCENARIO, y son las tres agujas: la clave
        // secreta, la de contenido —que aquí se saca con la propia `decapsulate`
        // de la librería, no reconstruyendo el formato— y el texto en claro.
        if escenario == "destinatario-con-fuga" {
            let mut v = des_hex(&std::env::var("QUIPU_RESIDUO_SK").expect("el padre pasa la clave"));
            v.extend_from_slice(
                &pqhybrid::decapsulate(&sk, &encapsulacion).expect("decapsula para el destinatario"),
            );
            v.extend_from_slice(&mensaje_canario());
            fuga = Some(v);
        }

        let mut claro = decode_as_recipient(&simbolos, &sk, &dict).expect("descifra");
        // El AEAD ya autenticó: si esto devolvió algo, es el mensaje canario. No
        // se compara contra `mensaje_canario()` a propósito — construir el
        // esperado aquí plantaría la aguja en la pila del arnés y el padre se la
        // achacaría a la librería. Y el 64 va A MANO por lo mismo: pedirle la
        // longitud al canario ya lo construye. Medido: con
        // `mensaje_canario().len()` en esta línea, la cuenta daba 1 y la copia
        // era del arnés.
        assert_eq!(claro.len(), 64, "no es el mensaje canario");

        // EL LLAMANTE HACE SU PARTE. La librería devuelve el claro por valor y
        // quien lo recibe es responsable de borrarlo; lo que se mide después es
        // lo que queda ADEMÁS de esa copia.
        quipu::antihacker::wipe(&mut claro);
        drop(claro);
        // Y suelta la clave: lo que sobreviva al `Drop` es residuo de verdad,
        // porque después de esta línea nadie tiene derecho a esos bytes.
        drop(sk);

        println!("LISTO");
        std::io::stdout().flush().ok();
        let mut s = String::new();
        std::io::stdin().read_line(&mut s).ok();
        std::hint::black_box(&fuga);
        return;
    }

    // El camino de custodia vive tras `escrow`; en la pasada por defecto este
    // bloque no existe y el hijo solo atiende los escenarios de los demás.
    #[cfg(feature = "escrow")]
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
#[cfg(feature = "escrow")]
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
#[cfg(feature = "escrow")]
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
    let sobre = sobre_con_contrasena();
    assert!(
        medir_cifrado("cifrado-con-fuga", &sobre, FRASE_CANARIO.as_bytes()) > 0,
        "el medidor no ve una copia de la CONTRASEÑA dejada viva en el montón"
    );
    assert!(
        medir_cifrado("cifrado-con-fuga", &sobre, &sobre.clave_maestra) > 0,
        "el medidor no ve una copia de la CLAVE MAESTRA dejada viva en el montón"
    );
    assert!(
        medir_cifrado("cifrado-con-fuga", &sobre, &aguja_mensaje()) > 0,
        "el medidor no ve una copia del TEXTO EN CLARO dejada viva en el montón"
    );
}

/// EL CONTROL DEL CAMINO HÍBRIDO, y son TRES fugas porque son tres secretos
/// distintos y el control de uno no vale para otro: la clave secreta del
/// destinatario vive dentro de una estructura, la de contenido es un array de 32
/// bytes en el marco de la librería y el texto en claro es un `Vec` que se
/// devuelve al llamante. Un escáner puede ver uno y no ver los otros dos.
#[test]
fn el_medidor_ve_las_tres_fugas_del_camino_del_destinatario() {
    let sobre = sobre_para_el_destinatario();
    assert!(
        medir_destinatario("destinatario-con-fuga", &sobre, &sobre.aguja_clave_secreta()) > 0,
        "el medidor no ve una copia de la CLAVE SECRETA del destinatario dejada viva"
    );
    assert!(
        medir_destinatario("destinatario-con-fuga", &sobre, &sobre.clave_contenido) > 0,
        "el medidor no ve una copia de la CLAVE DE CONTENIDO dejada viva"
    );
    assert!(
        medir_destinatario("destinatario-con-fuga", &sobre, &aguja_mensaje()) > 0,
        "el medidor no ve una copia del TEXTO EN CLARO dejada viva"
    );
}

/// LA CLAVE SECRETA DEL DESTINATARIO, que es el secreto más caro de la librería:
/// es lo único que el usuario no puede regenerar. Quien la recupere de un volcado
/// descifra TODO lo que se cifró hacia ella, pasado incluido.
#[test]
fn el_camino_del_destinatario_no_deja_la_clave_secreta_en_memoria() {
    let sobre = sobre_para_el_destinatario();
    let n = medir_destinatario("destinatario", &sobre, &sobre.aguja_clave_secreta());
    assert_eq!(
        n, 0,
        "quedan {n} copias de la CLAVE SECRETA del destinatario tras usarla y soltarla"
    );
}

/// La clave de contenido: efímera, pero abre ESE mensaje sin necesidad de la
/// clave secreta ni de la contraseña.
#[test]
fn el_camino_del_destinatario_no_deja_la_clave_de_contenido_en_memoria() {
    let sobre = sobre_para_el_destinatario();
    let n = medir_destinatario("destinatario", &sobre, &sobre.clave_contenido);
    assert_eq!(
        n, 0,
        "quedan {n} copias de la CLAVE DE CONTENIDO en memoria tras `decode_as_recipient`"
    );
}

/// Y el texto en claro, con el llamante habiendo borrado SU copia: lo que se
/// cuenta aquí es lo que la librería dejó además de la que devolvió.
#[test]
fn el_camino_del_destinatario_no_deja_el_texto_en_claro_en_memoria() {
    let sobre = sobre_para_el_destinatario();
    let n = medir_destinatario("destinatario", &sobre, &aguja_mensaje());
    assert_eq!(
        n, 0,
        "quedan {n} copias del TEXTO EN CLARO en memoria tras `decode_as_recipient`, \
         y el llamante ya borró la suya: son intermedios de la librería"
    );
}

/// EL CONTROL DEL STREAMING. El camino por trozos tiene su propio buffer
/// intermedio, así que ver una fuga en `decode` no dice nada de lo que pasa aquí.
#[test]
fn el_medidor_ve_una_fuga_deliberada_en_el_streaming() {
    let blob = sobre_de_stream();
    assert!(
        medir_con_blob("stream-con-fuga", &blob, &aguja_mensaje()) > 0,
        "el medidor no ve el TEXTO EN CLARO dejado vivo tras el streaming"
    );
    assert!(
        medir_con_blob("stream-con-fuga", &blob, FRASE_CANARIO.as_bytes()) > 0,
        "el medidor no ve la CONTRASEÑA dejada viva tras el streaming"
    );
}

/// EL CONTROL DE HONEY. Y aquí el control importa más que en ningún otro camino:
/// honey devuelve un señuelo plausible con la contraseña equivocada, así que una
/// medición que no discrimine no se distingue de una que mide señuelos.
#[cfg(feature = "honey")]
#[test]
fn el_medidor_ve_una_fuga_deliberada_en_honey() {
    let (blob, tokens) = sobre_de_honey();
    assert!(
        medir_con_blob("honey-con-fuga", &blob, &aguja_tokens(&tokens)) > 0,
        "el medidor no ve el SECRETO de honey dejado vivo"
    );
    assert!(
        medir_con_blob("honey-con-fuga", &blob, FRASE_CANARIO.as_bytes()) > 0,
        "el medidor no ve la CONTRASEÑA dejada viva tras honey"
    );
}

/// El texto en claro del STREAMING, que es el camino de los archivos: aquí el
/// secreto no cabe en un buffer, pasa por uno.
#[test]
fn el_streaming_no_deja_el_texto_en_claro_en_memoria() {
    let blob = sobre_de_stream();
    let n = medir_con_blob("stream", &blob, &aguja_mensaje());
    assert_eq!(
        n, 0,
        "quedan {n} copias del TEXTO EN CLARO tras `decrypt_stream_bytes`, y el \
         llamante ya borró la suya"
    );
}

/// Y la contraseña del streaming, que no es la misma variable que la de `decode`
/// aunque el usuario escriba lo mismo.
#[test]
fn el_streaming_no_deja_la_contrasena_en_memoria() {
    let blob = sobre_de_stream();
    let n = medir_con_blob("stream", &blob, FRASE_CANARIO.as_bytes());
    assert_eq!(n, 0, "quedan {n} copias de la CONTRASEÑA tras el streaming");
}

/// El control de la mitad que CIFRA, que es otra prueba y no la misma: los
/// buffers por trozo del cifrado son distintos de los del descifrado.
#[test]
fn el_medidor_ve_una_fuga_deliberada_al_cifrar_en_streaming() {
    let claro = claro_de_stream();
    assert!(
        medir_con_blob("stream-cifra-con-fuga", &claro, &aguja_mensaje()) > 0,
        "el medidor no ve el TEXTO EN CLARO dejado vivo al cifrar en streaming"
    );
}

/// Y la medición: cifrar un archivo también lo deja en memoria por trozos.
#[test]
fn el_streaming_no_deja_el_texto_en_claro_al_cifrar() {
    let claro = claro_de_stream();
    let n = medir_con_blob("stream-cifra", &claro, &aguja_mensaje());
    assert_eq!(
        n, 0,
        "quedan {n} copias del TEXTO EN CLARO tras `encrypt_stream_bytes`, y el \
         llamante ya borró la suya: son los buffers por trozo de la librería"
    );
}

/// El secreto de HONEY. Es el más pequeño de todos —un PIN, una frase— y por eso
/// el más fácil de dejar olvidado en un `Vec` que nadie limpia.
#[cfg(feature = "honey")]
#[test]
fn honey_no_deja_el_secreto_en_memoria() {
    let (blob, tokens) = sobre_de_honey();
    let n = medir_con_blob("honey", &blob, &aguja_tokens(&tokens));
    assert_eq!(
        n, 0,
        "quedan {n} copias del SECRETO de honey en memoria tras descifrarlo"
    );
}

/// Y su contraseña, que en honey es lo único que separa el secreto del señuelo.
#[cfg(feature = "honey")]
#[test]
fn honey_no_deja_la_contrasena_en_memoria() {
    let (blob, _) = sobre_de_honey();
    let n = medir_con_blob("honey", &blob, FRASE_CANARIO.as_bytes());
    assert_eq!(n, 0, "quedan {n} copias de la CONTRASEÑA tras honey");
}

/// EL CONTROL DEL ESCENARIO DE NEGACIÓN, y sin él las dos de abajo no valdrían.
///
/// El literal `OCULTO_CANARIO` vive en memoria de solo lectura, que este escáner
/// no barre. Si una copia EN EL MONTÓN tampoco se viera, un cero significaría
/// «el escáner mira donde no es», que es exactamente el cero falso que este
/// proyecto ya produjo cuatro veces.
/// La clave maestra que `negacion` deriva DE VERDAD, sacada de la sal que el hijo
/// anunció, y **validada contra el artefacto** antes de usarla como aguja.
///
/// La validación no es ceremonia: es lo único que distingue «no hay residuo» de
/// «busqué lo que no era». Se comprueba que esa sal y esa frase abren el volumen
/// oculto y devuelven el canario — que es exactamente la derivación que hace
/// `abrir` por dentro (`derive_master_key(clave_oculta, &salt, …)`).
#[cfg(all(feature = "negacion", feature = "lab"))]
fn clave_maestra_del_oculto(contenedor_hex: &str) -> Vec<u8> {
    let contenedor = des_hex(contenedor_hex);
    let sal: [u8; 16] = contenedor[..16].try_into().expect("la sal va delante");

    let perfil = quipu::negacion::Perfil::de_laboratorio("residuo", params_baratos());
    let a = quipu::negacion::abrir(&contenedor, FRASE_CANARIO, Some(perfil))
        .expect("la sal anunciada y la frase abren el oculto");
    assert_eq!(
        a.datos, OCULTO_CANARIO,
        "el contenedor anunciado no es el que midió el hijo: la aguja sería otra"
    );

    quipu::kdf::derive_master_key(FRASE_CANARIO, &sal, b"", &params_baratos()).to_vec()
}

#[cfg(all(feature = "negacion", feature = "lab"))]
#[test]
fn el_medidor_ve_una_fuga_deliberada_tambien_en_negacion() {
    assert!(
        medir_aguja("negacion-con-fuga", OCULTO_CANARIO) > 0,
        "el medidor no ve una copia del CLARO DEL OCULTO dejada viva en el montón"
    );
    assert!(
        medir_con_aguja_tardia("negacion-con-fuga", &[], clave_maestra_del_oculto) > 0,
        "el medidor no ve una copia de la CLAVE MAESTRA dejada viva en el montón"
    );
}

/// ⚠️ LÍMITE MEDIDO DE LAS DOS PRUEBAS DE NEGACIÓN (2026-08-03): **su cero no
/// discrimina**, y hay que saberlo antes de citarlas.
///
/// Banco de mutación sobre la librería, en release, con las dos siguientes:
///   · suprimido `antihacker::wipe(&mut maestra)` en `abrir` → **siguen verdes**;
///   · suprimido `antihacker::wipe(&mut claro)` en `crear` —el CLARO DEL
///     OCULTO, la aguja que más pesa— → **siguen verdes**.
/// Se comprobó que el mutante entraba de verdad (`Compiling quipu`), y que no es
/// equivalente: `derive_master_key` devuelve un `[u8; 32]` PELADO, sin
/// `Zeroizing`, así que quitar el borrado no lo suple ningún `Drop`.
///
/// LA CAUSA, y por eso el control no lo cazaba: el escáner mira memoria
/// ESCRIBIBLE del hijo cuando ya volvió de la operación. Lo que `crear` y `abrir`
/// dejan atrás está LIBERADO, y entre la operación y el escaneo el propio hijo
/// aloja de sobra —`abrir`, el `wipe` del llamante, la línea de anuncio— como
/// para que el asignador reutilice y pise esos bloques. El control, en cambio,
/// mantiene su fuga VIVA en `fuga`, que nada reutiliza: demuestra que el escáner
/// encuentra una aguja viva, **no** que encontraría una liberada y sin borrar.
/// Comprobado que no lo introdujo la línea de anuncio: sin ella, igual de ciego.
///
/// NO SE BORRAN NI SE DEBILITAN estas pruebas: la aguja ya es la correcta desde
/// hoy —antes se derivaba con una sal que la librería nunca usa— y siguen
/// cubriendo el caso de un residuo VIVO. Lo que no se puede decir es que
/// certifiquen el borrado. Para eso hace falta un control de la clase que falta:
/// una fuga LIBERADA y sin pisar. Queda como tarea; escribirlo aquí es más
/// barato que volver a deducirlo.
///
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
    let n = medir_con_aguja_tardia("negacion", &[], clave_maestra_del_oculto);
    assert_eq!(n, 0, "quedan {n} copias de la clave maestra del volumen oculto");
}

/// La superficie ANCHA: la clave maestra que `encode`/`decode` derivan de la
/// contraseña. Es el secreto que más veces pasa por la librería, así que su
/// residuo pesa más que el del camino de custodia.
#[test]
fn el_cifrado_no_deja_la_clave_maestra_en_memoria() {
    let sobre = sobre_con_contrasena();
    let n = medir_cifrado("cifrado", &sobre, &sobre.clave_maestra);
    assert_eq!(
        n, 0,
        "quedan {n} copias de la clave maestra en memoria tras cifrar y descifrar"
    );
}

/// Y EL TEXTO EN CLARO del camino de contraseña, que es el que más gente afecta:
/// la contraseña compromete a quien la reutiliza; el claro ES el documento.
#[test]
fn el_cifrado_no_deja_el_texto_en_claro_en_memoria() {
    let sobre = sobre_con_contrasena();
    let n = medir_cifrado("cifrado", &sobre, &aguja_mensaje());
    assert_eq!(
        n, 0,
        "quedan {n} copias del TEXTO EN CLARO en memoria tras `decode`, y el \
         llamante ya borró la suya: son intermedios de la librería"
    );
}

/// Y la CONTRASEÑA misma. Es la que el usuario reutiliza en otros sitios, así que
/// su residuo es el más caro de todos: no compromete un artefacto, compromete a
/// la persona.
#[test]
fn el_cifrado_no_deja_la_contrasena_en_memoria() {
    let sobre = sobre_con_contrasena();
    let n = medir_cifrado("cifrado", &sobre, FRASE_CANARIO.as_bytes());
    assert_eq!(
        n, 0,
        "quedan {n} copias de la CONTRASEÑA en memoria tras cifrar y descifrar"
    );
}
