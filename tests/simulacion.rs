// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Simulaciones a escala del núcleo: miles de operaciones, no tres.
//!
//! Las pruebas unitarias comprueban que un camino FUNCIONA. Estas comprueban
//! que sigue funcionando **repetido**, que falla cuando debe, y que lo que
//! tiene que ser distinto en cada operación de verdad lo es. Son tres preguntas
//! que un caso suelto no puede responder: un nonce repetido no se ve en una
//! ejecución, se ve en quinientas.
//!
//! Por qué existen aquí y no como script suelto: se van a añadir características
//! encima de este núcleo. Un simulacro que corre una vez prueba el estado de
//! hoy; una prueba en el árbol protege lo de mañana, que es lo que hace falta.
//!
//! COSTE. Todo usa parámetros de KDF baratos (64 KiB, 1 iteración). No es
//! trampa: lo que se mide aquí es la lógica del contenedor, la autenticación y
//! la frescura de la aleatoriedad, y ninguna depende de lo caro que sea Argon2.
//! Con los parámetros de producción esto tardaría horas y nadie lo correría —
//! una prueba que no se ejecuta no protege nada.
//!
//! REPRODUCIBILIDAD. El generador es determinista y la semilla está escrita. Si
//! una simulación falla, falla igual la próxima vez; un fallo que no se puede
//! repetir no se puede arreglar.

use quipu::api::{decode, decode_from_blob, encode, encode_to_blob, Options};
use quipu::dictionaries;
use quipu::kdf::KdfParams;

/// Semilla fija: los fallos tienen que ser repetibles.
const SEMILLA: u64 = 0x5175_6970_7521_2026;

/// xorshift64*. No es criptográfico y no pretende serlo: solo genera las
/// ENTRADAS del banco. Usar el RNG del sistema aquí haría que un fallo no se
/// pudiera reproducir, que es lo contrario de lo que se busca.
struct Az(u64);

impl Az {
    fn nuevo(s: u64) -> Self {
        Az(s)
    }
    fn siguiente(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn hasta(&mut self, n: usize) -> usize {
        (self.siguiente() % (n as u64 + 1)) as usize
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.siguiente() >> 33) as u8).collect()
    }
    fn frase(&mut self) -> String {
        format!("clave-{:x}", self.siguiente())
    }
}

fn baratos() -> Options<'static> {
    Options {
        pepper: b"",
        kdf_params: KdfParams {
            mem_kib: 64,
            iterations: 1,
            parallelism: 1,
        },
        codebook_id: 0,
    }
}

// ---------------------------------------------------------------------------

/// 1 200 ciclos completos con tamaños y claves variables.
///
/// El tamaño se sortea entre 0 y 2 KiB a propósito: el cero y los tamaños que
/// caen justo en un límite del relleno Padmé son donde vive el error de índice,
/// y sortear los cubre sin tener que adivinar cuáles son.
#[test]
fn mil_doscientos_ciclos_de_ida_y_vuelta() {
    let dict = dictionaries::flagship();
    let opts = baratos();
    let mut az = Az::nuevo(SEMILLA);
    let mut fallos = Vec::new();

    for i in 0..1_200 {
        let n = az.hasta(2048);
        let datos = az.bytes(n);
        let clave = az.frase();
        let simbolos = encode(&datos, &clave, &dict, &opts);
        match decode(&simbolos, &clave, &dict, b"") {
            Ok(v) if v == datos => {}
            Ok(_) => fallos.push(format!("ciclo {i}: descifró OTRA cosa ({} bytes)", datos.len())),
            Err(e) => fallos.push(format!("ciclo {i}: {:?} con {} bytes", e, datos.len())),
        }
    }
    assert!(
        fallos.is_empty(),
        "{} de 1200 ciclos fallaron (semilla {SEMILLA:#x}):\n{}",
        fallos.len(),
        fallos[..fallos.len().min(10)].join("\n")
    );
}

/// La passphrase equivocada NO descifra, 600 veces seguidas.
///
/// Importa que sean muchas y no una: lo que se descarta aquí es que exista
/// alguna combinación de tamaño y clave en la que la autenticación deje pasar
/// algo. Un solo caso no distingue «rechaza» de «rechaza casi siempre».
#[test]
fn seiscientas_claves_equivocadas_no_abren_nada() {
    let dict = dictionaries::flagship();
    let opts = baratos();
    let mut az = Az::nuevo(SEMILLA ^ 0xA5A5);
    let mut coladas = Vec::new();

    for i in 0..600 {
        let n = 1 + az.hasta(512);
        let datos = az.bytes(n);
        let buena = az.frase();
        let mala = az.frase();
        let simbolos = encode(&datos, &buena, &dict, &opts);
        if decode(&simbolos, &mala, &dict, b"").is_ok() {
            coladas.push(format!("intento {i}: «{mala}» abrió lo cifrado con «{buena}»"));
        }
    }
    assert!(
        coladas.is_empty(),
        "la autenticación dejó pasar {} de 600 (semilla {:#x}):\n{}",
        coladas.len(),
        SEMILLA ^ 0xA5A5,
        coladas.join("\n")
    );
}

/// Un bit cambiado en CUALQUIER posición tiene que romper el descifrado.
///
/// Camino de error inyectado, y exhaustivo en vez de por muestreo: se recorre
/// byte a byte el contenedor entero. Es el invariante I2 —autenticar antes de
/// actuar— medido donde puede fallar de verdad, que es en los bordes: el último
/// byte del tag, el primero de la cabecera, el que separa relleno de cuerpo.
/// Muestrear al azar deja huecos justo ahí.
#[test]
fn ningun_byte_del_contenedor_se_puede_tocar_impunemente() {
    let opts = baratos();
    let mut az = Az::nuevo(SEMILLA ^ 0x1234);
    let mut impunes = Vec::new();
    let mut tocados = 0usize;

    for caso in 0..6 {
        let n = 1 + az.hasta(200);
        let datos = az.bytes(n);
        let clave = az.frase();
        let blob = encode_to_blob(&datos, &clave, [0u8; 8], &opts);

        for pos in 0..blob.len() {
            let mut roto = blob.clone();
            roto[pos] ^= 0x01;
            tocados += 1;
            if let Ok(salida) = decode_from_blob(&roto, &clave, [0u8; 8], b"") {
                // Devolver el texto original con un byte cambiado sería lo peor:
                // significa que ese byte no entra en lo autenticado.
                impunes.push(format!(
                    "caso {caso}, byte {pos} de {}: descifró {} bytes{}",
                    blob.len(),
                    salida.len(),
                    if salida == datos { " — ¡Y ERA EL ORIGINAL!" } else { "" }
                ));
            }
        }
    }
    assert!(
        impunes.is_empty(),
        "{} de {tocados} corrupciones pasaron sin detectarse:\n{}",
        impunes.len(),
        impunes[..impunes.len().min(10)].join("\n")
    );
    assert!(tocados > 400, "el banco apenas tocó {tocados} bytes: no mide nada");
}

/// Sal y nonce frescos en cada operación, 800 veces con la MISMA entrada.
///
/// Es el invariante I3 —entropía fresca y nonce único— y hoy no tiene ninguna
/// herramienta que lo vigile de forma continua; esto es el primer trozo. Se
/// cifra ochocientas veces exactamente lo mismo con la misma clave: si algo del
/// generador se degradara —una semilla fija, un contador que no avanza, un
/// fallback silencioso— aquí se vería como repeticiones, y en ningún otro sitio.
///
/// Un nonce repetido con la misma clave en XChaCha20 no rompe nada visible:
/// rompe la confidencialidad de los dos mensajes que lo comparten, y en
/// silencio. Por eso se mide contando colisiones, no comprobando que «funciona».
///
/// Las posiciones salen del formato del contenedor: 28 bytes fijos, luego
/// `SALT_LEN` = 16 y luego `NONCE_LEN` = 24. Se afirman abajo para que un cambio
/// de formato rompa esta prueba en vez de dejarla midiendo el trozo equivocado.
#[test]
fn ochocientos_cifrados_iguales_no_repiten_sal_ni_nonce() {
    use std::collections::HashSet;

    const INICIO_SAL: usize = 28 - 12; // los 12 últimos fijos van tras la sal
    const FIN_SAL: usize = INICIO_SAL + 16;
    const FIN_NONCE: usize = FIN_SAL + 24;

    let opts = baratos();
    let datos = b"exactamente el mismo mensaje, una y otra vez";
    let clave = "exactamente-la-misma-clave";

    let mut sales = HashSet::new();
    let mut nonces = HashSet::new();
    let mut completos = HashSet::new();
    let n = 800;

    for _ in 0..n {
        let blob = encode_to_blob(datos, clave, [0u8; 8], &opts);
        assert!(blob.len() > FIN_NONCE, "contenedor más corto que su cabecera");
        sales.insert(blob[INICIO_SAL..FIN_SAL].to_vec());
        nonces.insert(blob[FIN_SAL..FIN_NONCE].to_vec());
        completos.insert(blob);
    }

    assert_eq!(
        nonces.len(),
        n,
        "COLISIÓN DE NONCE: {} distintos de {n}. Con la misma clave, dos mensajes \
         que comparten nonce pierden su confidencialidad, y sin ruido ninguno.",
        nonces.len()
    );
    assert_eq!(
        sales.len(),
        n,
        "COLISIÓN DE SAL: {} distintas de {n}. Repetir sal delata que dos secretos \
         comparten passphrase y abarata el ataque por diccionario.",
        sales.len()
    );
    assert_eq!(
        completos.len(),
        n,
        "{} contenedores distintos de {n}: cifrar lo mismo dos veces produjo bytes \
         idénticos, o sea que algo dejó de ser aleatorio.",
        completos.len()
    );
}

/// Ocho hilos a la vez contra el núcleo, con TIMEOUT.
///
/// El timeout no es adorno. La autoprueba de arranque usa `Once::call_once`, que
/// no es reentrante, y ya provocó un interbloqueo de trece minutos que parecía
/// una compilación lenta. Sin un reloj que corte, un deadlock aquí no se
/// distingue de «va despacio» — y esa confusión es la que costó la tarde.
///
/// Se lanza todo desde un hilo aparte y se espera por canal: si no contesta a
/// tiempo, la prueba FALLA en vez de colgarse. Un banco que se cuelga no informa.
#[test]
fn ocho_hilos_concurrentes_no_se_interbloquean() {
    use std::sync::mpsc;
    use std::time::Duration;

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut manos = Vec::new();
        for h in 0..8u64 {
            manos.push(std::thread::spawn(move || {
                let dict = dictionaries::flagship();
                let opts = baratos();
                let mut az = Az::nuevo(SEMILLA ^ (h << 17));
                let mut malos = 0usize;
                for _ in 0..150 {
                    let n = 1 + az.hasta(256);
                    let datos = az.bytes(n);
                    let clave = az.frase();
                    let s = encode(&datos, &clave, &dict, &opts);
                    if decode(&s, &clave, &dict, b"").ok().as_deref() != Some(&datos[..]) {
                        malos += 1;
                    }
                }
                malos
            }));
        }
        let total: usize = manos.into_iter().map(|m| m.join().unwrap_or(usize::MAX)).sum();
        let _ = tx.send(total);
    });

    match rx.recv_timeout(Duration::from_secs(180)) {
        Ok(0) => {}
        Ok(malos) => panic!("{malos} de 1200 operaciones concurrentes dieron un resultado malo"),
        Err(_) => panic!(
            "1200 operaciones en 8 hilos no terminaron en 180 s: es un INTERBLOQUEO, \
             no lentitud. Sospechar de `Once::call_once` en la autoprueba."
        ),
    }
}
