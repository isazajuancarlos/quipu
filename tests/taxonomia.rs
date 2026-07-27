// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Las sondas que le quedaban a `docs/ATAQUES_TAXONOMIA.md` y son construibles.
//!
//! | Familia | Lo que faltaba | Invariante |
//! |---|---|---|
//! | 6 · Protocolo | «sondas de downgrade/confusión explícitas» | I2 |
//! | 5 · Aleatoriedad | «detector de reúso de nonce a nivel de contenedor» | I3 |
//! | 5 · Aleatoriedad | «batería estadística sobre la salida del RNG» | I3 |
//! | 1 · Criptoanálisis | que el algoritmo y la versión del KDF no cambien solos | I5 |
//!
//! Lo que sigue faltando después de esto está dicho en el propio documento y no
//! se puede construir aquí: dudect sistemático y la generalización del
//! distinguidor necesitan instrumentación de MEDIDA, y el coste en GPU/ASIC
//! necesita hardware. Fingir que están sería peor que la ausencia.

use quipu::api::{decode_from_blob, encode_to_blob, Options};
use quipu::container::{MAGIC, VERSION};
use quipu::kdf::{self, KdfParams};

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

// ===========================================================================
// FAMILIA 6 — DOWNGRADE Y CONFUSIÓN DE ALGORITMO
// ===========================================================================

/// No hay negociación, y añadir un modo no debe reintroducirla.
///
/// La defensa de Quipu contra el downgrade es estructural y consiste en NO
/// TENER la característica: no se negocia el algoritmo, así que no hay nada que
/// forzar a la baja. El contenedor lleva `magic ‖ version` y rechaza lo que no
/// reconoce.
///
/// El documento pedía «documentar y probar que añadir un modo nunca reintroduce
/// negociación insegura», y esa es la parte sutil: esta prueba no defiende de un
/// ataque de hoy —hoy no hay superficie—, sino de una CARACTERÍSTICA FUTURA. Es
/// el `alg:none` de JWT: nadie lo diseñó como agujero, apareció al añadir
/// flexibilidad. Si mañana alguien añade un segundo cifrador y un byte que elija
/// entre los dos, esta prueba se pone roja y obliga a pensarlo.
#[test]
fn el_contenedor_no_negocia_ni_acepta_versiones_desconocidas() {
    let opts = baratos();
    let blob = encode_to_blob(b"contenido", "clave", [0u8; 8], &opts);

    // Control: intacto, abre.
    assert!(
        decode_from_blob(&blob, "clave", [0u8; 8], b"").is_ok(),
        "el control falló: la prueba no mediría nada"
    );

    // DOWNGRADE: una versión ANTERIOR no existe y no debe inventarse.
    let mut anterior = blob.clone();
    anterior[4] = VERSION - 1;
    assert!(
        decode_from_blob(&anterior, "clave", [0u8; 8], b"").is_err(),
        "el contenedor aceptó la versión {} — eso es una vía de downgrade",
        VERSION - 1
    );

    // Y una POSTERIOR tampoco: aceptarla sería adivinar un formato futuro.
    let mut posterior = blob.clone();
    posterior[4] = VERSION + 1;
    assert!(
        decode_from_blob(&posterior, "clave", [0u8; 8], b"").is_err(),
        "el contenedor aceptó una versión futura sin saber qué significa"
    );

    // CONFUSIÓN DE CONTENEDOR: otro magic no puede colarse.
    let mut ajeno = blob.clone();
    ajeno[0..4].copy_from_slice(b"XXXX");
    assert!(
        decode_from_blob(&ajeno, "clave", [0u8; 8], b"").is_err(),
        "el contenedor aceptó un magic ajeno"
    );

    assert_eq!(&blob[0..4], &MAGIC, "el magic dejó de estar al principio");
}

// ===========================================================================
// FAMILIA 5 — DETECTOR DE REÚSO DE NONCE
// ===========================================================================

/// Extrae el nonce de un contenedor. Formato: 28 fijos, 16 de sal, 24 de nonce.
fn nonce_de(blob: &[u8]) -> Option<Vec<u8>> {
    const INICIO: usize = 16 + 16; // los 12 últimos fijos van tras la sal
    const FIN: usize = INICIO + 24;
    (blob.len() > FIN).then(|| blob[INICIO..FIN].to_vec())
}

/// Busca nonces repetidos en un conjunto de contenedores.
///
/// Esto es lo que el documento pedía: un detector que un INTEGRADOR pueda correr
/// sobre lo que ha guardado. El riesgo no es que Quipu repita —usa el RNG del
/// sistema para cada nonce— sino que alguien serialice mal, copie un contenedor
/// y lo reescriba, o restaure una copia de seguridad sobre un cifrado nuevo.
///
/// Se devuelve la lista de índices que colisionan, no un booleano: quien lo
/// corra necesita saber CUÁLES para poder recifrarlos.
fn nonces_repetidos(blobs: &[Vec<u8>]) -> Vec<(usize, usize)> {
    use std::collections::HashMap;
    let mut visto: HashMap<Vec<u8>, usize> = HashMap::new();
    let mut choques = Vec::new();
    for (i, b) in blobs.iter().enumerate() {
        if let Some(n) = nonce_de(b) {
            match visto.get(&n) {
                Some(&j) => choques.push((j, i)),
                None => {
                    visto.insert(n, i);
                }
            }
        }
    }
    choques
}

/// El detector encuentra el reúso, y no lo inventa donde no lo hay.
///
/// Las dos mitades importan. Un detector que siempre dice «limpio» es inútil, y
/// uno que ve colisiones donde no las hay se desactiva a la semana.
///
/// Por qué un nonce repetido es grave y a la vez invisible: con XChaCha20, dos
/// mensajes bajo la misma clave y el mismo nonce comparten el flujo de cifrado.
/// Quien tenga los dos ciphertexts obtiene el XOR de los dos textos claros. No
/// hay error, no hay aviso, y los dos mensajes siguen descifrando bien para su
/// dueño. Por eso hay que buscarlo a propósito.
#[test]
fn el_detector_de_reuso_de_nonce_encuentra_lo_que_debe() {
    let opts = baratos();
    let corpus: Vec<Vec<u8>> = (0..40)
        .map(|i| encode_to_blob(format!("mensaje {i}").as_bytes(), "misma-clave", [0u8; 8], &opts))
        .collect();

    // Mitad 1: cuarenta cifrados legítimos, ninguna colisión.
    let limpio = nonces_repetidos(&corpus);
    assert!(
        limpio.is_empty(),
        "el detector ve {} colisión(es) en un corpus sano — daría falsos positivos: {:?}",
        limpio.len(),
        limpio
    );

    // Mitad 2: se simula el fallo del integrador —duplicar un contenedor— y el
    // detector TIENE que verlo.
    let mut sucio = corpus.clone();
    sucio.push(corpus[7].clone());
    let choques = nonces_repetidos(&sucio);
    assert_eq!(
        choques,
        vec![(7, 40)],
        "el detector no encontró el nonce duplicado que se sembró"
    );
}

// ===========================================================================
// FAMILIA 5 — BATERÍA ESTADÍSTICA SOBRE EL RNG
// ===========================================================================

/// Monobit y rachas sobre la salida real del RNG.
///
/// Es la batería que pedía el documento, en su forma mínima útil: las dos
/// pruebas de NIST SP 800-22 que cazan los fallos catastróficos —un RNG muerto
/// que devuelve ceros, uno sesgado, uno con periodo corto—. No pretende
/// sustituir a una batería completa: pretende que un generador roto no pase
/// callado, que es lo que le ocurrió a Debian en 2008.
///
/// EL UMBRAL ES DELIBERADAMENTE FLOJO: 5 sigma. Con el 0,01 habitual, esta
/// prueba fallaría una vez de cada cien ejecuciones sobre un RNG PERFECTO, y una
/// prueba que falla sin motivo se acaba ignorando — que es peor que no tenerla.
/// A 5 sigma, un falso positivo es de uno entre tres millones y medio, y sigue
/// cazando cualquier degradación real.
#[test]
fn el_rng_pasa_monobit_y_rachas() {
    const BYTES: usize = 16_384; // 131 072 bits
    let mut datos = vec![0u8; BYTES];
    quipu::aleatorio::llenar(&mut datos).expect("el RNG del sistema debe responder");

    let n = BYTES * 8;
    let unos: usize = datos.iter().map(|b| b.count_ones() as usize).sum();

    // --- MONOBIT: la proporción de unos tiene que rondar 1/2 --------------
    // s = |unos - ceros| / sqrt(n) es ~N(0,1) para un RNG ideal.
    let s = (unos as f64 * 2.0 - n as f64).abs() / (n as f64).sqrt();
    assert!(
        s < 5.0,
        "MONOBIT: {unos} unos de {n} bits, desviación {s:.2} sigma. Un RNG sano \
         da menos de 5. Sospechar de un generador sesgado o muerto."
    );

    // --- RACHAS: cuántas veces cambia el bit ------------------------------
    // Un generador con periodo corto o con estructura da muy pocas rachas; uno
    // que alterna mecánicamente da demasiadas. Las dos cosas son fallos.
    let bits: Vec<u8> = datos
        .iter()
        .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1))
        .collect();
    let rachas = 1 + bits.windows(2).filter(|p| p[0] != p[1]).count();
    let pi = unos as f64 / n as f64;
    let esperadas = 2.0 * n as f64 * pi * (1.0 - pi);
    let sigma = 2.0 * (n as f64).sqrt() * pi * (1.0 - pi);
    let z = (rachas as f64 - esperadas).abs() / sigma;
    assert!(
        z < 5.0,
        "RACHAS: {rachas} cambios de bit, esperados {esperadas:.0}, desviación \
         {z:.2} sigma. Menos rachas de la cuenta delata periodo corto; más, un \
         alternado mecánico."
    );

    // --- Y lo más básico, que es lo que falló en Debian -------------------
    assert!(
        datos.windows(64).all(|v| v.iter().any(|&b| b != 0)),
        "hay 64 bytes seguidos a cero: el RNG está muerto"
    );
    println!("RNG: {unos} unos de {n} bits ({s:.2}σ), {rachas} rachas ({z:.2}σ)");
}

// ===========================================================================
// FAMILIA 1 — EL ALGORITMO DEL KDF NO CAMBIA SOLO
// ===========================================================================

/// La clave maestra sale de Argon2**id**, versión 0x13, y de nada más.
///
/// Los vectores de RFC 9106 no encajan con el cableado de Quipu: usan `Secret` y
/// `Associated data`, que Quipu no pasa. Así que esta prueba fija lo que sí se
/// puede fijar y es lo que de verdad puede cambiar por descuido: **la variante y
/// la versión**.
///
/// No es circular. La prueba CONSTRUYE su propio Argon2 diciendo explícitamente
/// `Argon2id` y `V0x13`, y exige que `derive_master_key` coincida. Si alguien
/// cambiara la implementación a Argon2i —que resiste peor a un atacante con
/// GPU— o a la versión 0x10, el resultado dejaría de coincidir con esta
/// declaración independiente y la prueba se pondría roja.
///
/// Por qué importa la variante: Argon2**d** es rápido pero su acceso a memoria
/// depende del secreto, o sea un canal lateral; Argon2**i** lo evita pero
/// resiste peor al descifrado con hardware dedicado. **Argon2id** es el híbrido
/// que la RFC recomienda por defecto, y es el que este proyecto declara usar.
#[test]
fn la_clave_maestra_sale_de_argon2id_y_no_de_otra_cosa() {
    use argon2::{Algorithm, Argon2, Params, Version};

    let passphrase = "una passphrase cualquiera";
    let salt = [7u8; 16];
    let params = KdfParams {
        mem_kib: 64,
        iterations: 1,
        parallelism: 1,
    };
    let obtenido = kdf::derive_master_key(passphrase, &salt, b"", &params);

    // Declaración INDEPENDIENTE de lo que Quipu debe estar haciendo.
    let referencia = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(params.mem_kib, params.iterations, params.parallelism, Some(32)).unwrap(),
    );
    let mut esperado = [0u8; 32];
    referencia
        .hash_password_into(passphrase.as_bytes(), &salt, &mut esperado)
        .unwrap();

    assert_eq!(
        obtenido, esperado,
        "`derive_master_key` NO es Argon2id/V0x13 con esos parámetros: alguien \
         cambió la variante, la versión o el orden de los argumentos"
    );

    // Y que las otras variantes NO coincidan, o la prueba no distinguiría nada.
    for otra in [Algorithm::Argon2i, Algorithm::Argon2d] {
        let a = Argon2::new(
            otra,
            Version::V0x13,
            Params::new(params.mem_kib, params.iterations, params.parallelism, Some(32)).unwrap(),
        );
        let mut salida = [0u8; 32];
        a.hash_password_into(passphrase.as_bytes(), &salt, &mut salida)
            .unwrap();
        assert_ne!(
            obtenido, salida,
            "{otra:?} da el MISMO resultado que Argon2id: la prueba no discrimina"
        );
    }
}
