// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

//! Simulación #A4: degradación de coste del KDF sobre un contenedor AJENO.
//!
//! # Qué prueba, y qué NO probaba lo que había
//!
//! Los tres parámetros del KDF —`mem_kib`, `iterations`, `parallelism`— viajan
//! EN CLARO en la cabecera (12 bytes) tanto en el contenedor `QUIP`
//! (`api::encode_to_blob`) como en el `QST1` de streaming
//! (`stream::encrypt_stream_bytes`). Un atacante que tenga el contenedor puede
//! reescribir esos 12 bytes a su antojo: la pregunta de la auditoría del núcleo
//! es si el codec los DISTINGUE de verdad —si están atados a la clave y al
//! AEAD— o si un contenedor abriría igual con otros parámetros sanos.
//!
//! Lo que ya existía no responde eso. La única prueba de degradación del KDF
//! (`api::tests::decode_rejects_malicious_kdf_params_without_panic` y la
//! comprobación gemela de `stream`) usa valores INSANOS —`u32::MAX`—, que
//! `KdfParams::is_sane` rechaza en `decode_from_blob`/`StreamHeader::from_bytes`
//! ANTES de derivar clave o tocar el AEAD. O sea: prueba la barandilla
//! anti-DoS, no el atado. Falta el caso con valores SANOS pero DISTINTOS del
//! original, que es el que de verdad llega hasta el AEAD.
//!
//! # La aserción
//!
//! Para cada contenedor y cada tupla KDF sana distinta de la original: reescribir
//! los 12 bytes y descifrar con la contraseña CORRECTA tiene que FALLAR en el
//! AEAD (`DecodeError::Decrypt` / `StreamError::Decrypt`), nunca devolver `Ok`.
//! Cero descifrados sobre cientos de variantes.
//!
//! # El control positivo (directiva 33: un banco de solo-negativos no discrimina)
//!
//! Reescribir la tupla ORIGINAL encima de sí misma tiene que devolver `Ok` con
//! el claro EXACTO. Sin él, un `decode` que fallara siempre —clave mal derivada
//! por cualquier bug— pasaría el banco entero sin medir nada.
//!
//! # Coste: por qué la rejilla cara se barre UNA vez y la barata muchas
//!
//! Medido en perfil debug (el de `cargo test`): derivar a 8 KiB/1 iter cuesta
//! ~1 ms; a 64 MiB/3 iter, 134 ms; a 256 MiB/16 iter, 2,8 s. Barrer la rejilla
//! completa {8,64,1024,65536,262144}×{1,2,3,16}×{1,2,16} contra cada contenedor
//! serían minutos — el mismo motivo por el que `negacion_simulacion` usa un
//! perfil de laboratorio: **lo que se mide aquí no depende de lo caro que sea
//! Argon2id**. El atado a la clave y al AEAD es idéntico a 8 KiB y a 256 MiB.
//! Por eso:
//!   · la REJILLA DENSA (memorias baratas, cruza las fronteras de `is_sane`) se
//!     barre contra VARIOS contenedores → cientos de operaciones, segundos;
//!   · el TECHO DEL RANGO (64 y 256 MiB) se barre una vez por formato, para que
//!     los valores grandes que el atacante también podría escribir queden
//!     cubiertos sin volver el banco impracticable.
//!
//! Reproducible: PRNG determinista con semilla fija.

use quipu::api::{decode_from_blob, encode_to_blob, DecodeError, Options};
use quipu::kdf::KdfParams;
use quipu::stream::{decrypt_stream_bytes, encrypt_stream_bytes, StreamError, StreamOptions};

/// Semilla fija: un fallo tiene que repetirse igual en cualquier máquina.
const SEMILLA: u64 = 0x4B44_465F_4132_3671; // "KDF_A26q"

/// xorshift64*. No criptográfico: solo genera las ENTRADAS del banco de forma
/// determinista, como el resto de simulaciones del árbol.
struct Az(u64);
impl Az {
    fn nuevo(s: u64) -> Self {
        Az(s | 1)
    }
    fn siguiente(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.siguiente() >> 33) as u8).collect()
    }
    fn frase(&mut self) -> String {
        format!("clave-degradacion-{:x}", self.siguiente())
    }
}

/// Fingerprint del codebook. Se preserva intacta al reescribir SOLO los 12 bytes
/// del KDF, así que un fallo aquí es del AEAD, nunca `CodebookMismatch`.
const HUELLA: [u8; 8] = [0u8; 8];

/// Perfil base con el que se crean todos los contenedores. Forma «equilibrada»
/// (3 iteraciones, como `EQUILIBRADO`) pero memoria barata, para que el banco
/// corra en el paso por defecto de `cargo test`. NO está en ninguna rejilla, así
/// que toda variante es de verdad distinta y el control reescribe justo esto.
const BASE: KdfParams = KdfParams {
    mem_kib: 2048,
    iterations: 3,
    parallelism: 1,
};

// ── Offsets de los 12 bytes del KDF, LEÍDOS del código (no de memoria) ──────
//
// QUIP  (`container.rs`): magic(4)|version(1)|flags(1)|codebook_id(2)|
//   codebook_hash_prefix(8)|salt(16)|nonce(24)|kdf_mem(4)|kdf_iter(4)|kdf_par(4)
//   → los 12 bytes del KDF empiezan en el offset 56 (28 fijos + 16 salt + 24
//   nonce − 12), es decir HEADER_SIZE(68) − 12.
const OFF_KDF_QUIP: usize = 56;
//
// QST1 (`stream.rs`): magic(4)|version(1)|flags(1)|kdf_mem(4)|kdf_iter(4)|
//   kdf_par(4)|salt(16)|prefix(19)|chunk(4) → el KDF empieza en el offset 6.
const OFF_KDF_QST1: usize = 6;

fn escribir_kdf(blob: &mut [u8], off: usize, p: KdfParams) {
    blob[off..off + 4].copy_from_slice(&p.mem_kib.to_be_bytes());
    blob[off + 4..off + 8].copy_from_slice(&p.iterations.to_be_bytes());
    blob[off + 8..off + 12].copy_from_slice(&p.parallelism.to_be_bytes());
}

fn leer_kdf(blob: &[u8], off: usize) -> KdfParams {
    let rd = |o: usize| u32::from_be_bytes(blob[o..o + 4].try_into().expect("4 bytes"));
    KdfParams {
        mem_kib: rd(off),
        iterations: rd(off + 4),
        parallelism: rd(off + 8),
    }
}

/// Toda tupla sana de la rejilla `mems × iters × pars` distinta de `original`.
fn rejilla(mems: &[u32], iters: &[u32], pars: &[u32], original: KdfParams) -> Vec<KdfParams> {
    let mut v = Vec::new();
    for &m in mems {
        for &i in iters {
            for &p in pars {
                let k = KdfParams {
                    mem_kib: m,
                    iterations: i,
                    parallelism: p,
                };
                if k.is_sane() && k != original {
                    v.push(k);
                }
            }
        }
    }
    v
}

// ── Rejillas ────────────────────────────────────────────────────────────────

/// Densa y BARATA: cruza las tres fronteras de `is_sane` sobre `parallelism`
/// (mem=8 solo admite par=1; mem=64 hasta par=2; mem=1024 hasta par=16) y las
/// iteraciones extremas. Incluye la variante de DEGRADACIÓN real —8 KiB/1 iter—,
/// que es la que un atacante escribiría para abaratar la fuerza bruta.
fn rejilla_densa(original: KdfParams) -> Vec<KdfParams> {
    rejilla(&[8, 64, 1024], &[1, 2, 3, 16], &[1, 2, 16], original)
}

/// Techo del rango: 64 y 256 MiB, iteraciones mínima y máxima. Cara: se barre
/// una sola vez por formato.
fn rejilla_techo(original: KdfParams) -> Vec<KdfParams> {
    rejilla(&[65_536, 262_144], &[3, 16], &[1], original)
}

/// Descifra un contenedor QUIP tras reescribirle los 12 bytes del KDF a `p`.
fn intentar_quip(blob: &[u8], p: KdfParams, pass: &str) -> Result<Vec<u8>, DecodeError> {
    let mut roto = blob.to_vec();
    escribir_kdf(&mut roto, OFF_KDF_QUIP, p);
    decode_from_blob(&roto, pass, HUELLA, b"")
}

/// Descifra un contenedor QST1 tras reescribirle los 12 bytes del KDF a `p`.
fn intentar_qst1(blob: &[u8], p: KdfParams, pass: &str) -> Result<Vec<u8>, StreamError> {
    let mut roto = blob.to_vec();
    escribir_kdf(&mut roto, OFF_KDF_QST1, p);
    decrypt_stream_bytes(&roto, pass, b"")
}

#[test]
fn la_degradacion_del_kdf_no_abre_ningun_contenedor() {
    let mut az = Az::nuevo(SEMILLA);

    // Control de cobertura (directiva 30): la rejilla densa no puede salir vacía
    // ni «casi vacía», o el banco no mediría nada, y tiene que contener la
    // variante de degradación 8 KiB/1 iter — la que de verdad importa.
    let densa = rejilla_densa(BASE);
    assert!(
        densa.len() >= 20,
        "la rejilla densa colapsó a {} tuplas: no representa el problema",
        densa.len()
    );
    let degradacion = KdfParams {
        mem_kib: 8,
        iterations: 1,
        parallelism: 1,
    };
    assert!(
        densa.contains(&degradacion),
        "la rejilla densa no incluye la degradación real 8 KiB/1 iter"
    );
    let techo = rejilla_techo(BASE);
    assert!(!techo.is_empty(), "la rejilla del techo salió vacía");

    let mut aperturas_indebidas: Vec<String> = Vec::new();
    let mut variantes_probadas = 0usize;
    let mut controles = 0usize;

    // ── QUIP: varios contenedores, rejilla densa cada uno ──────────────────
    for caso in 0..4 {
        let n = 1 + (az.siguiente() as usize % 300);
        let datos = az.bytes(n);
        let pass = az.frase();
        let opts = Options {
            pepper: b"",
            kdf_params: BASE,
            codebook_id: 0,
        };
        let blob = encode_to_blob(&datos, &pass, HUELLA, &opts);

        // El offset tiene que apuntar EXACTO a los 12 bytes que escribió el
        // codificador: si no, reescribir la original no sería un no-op y el
        // control fallaría por la razón equivocada.
        assert_eq!(
            leer_kdf(&blob, OFF_KDF_QUIP),
            BASE,
            "QUIP caso {caso}: el offset del KDF no cae sobre los bytes del perfil base"
        );

        // CONTROL POSITIVO: reescribir la original abre y devuelve el claro.
        match intentar_quip(&blob, BASE, &pass) {
            Ok(claro) => assert_eq!(claro, datos, "QUIP caso {caso}: el control no devolvió el claro exacto"),
            Err(e) => panic!("QUIP caso {caso}: el control POSITIVO falló con {e:?} — el banco no discrimina"),
        }
        controles += 1;

        for &p in &densa {
            variantes_probadas += 1;
            match intentar_quip(&blob, p, &pass) {
                Ok(claro) => aperturas_indebidas.push(format!(
                    "QUIP caso {caso}: {p:?} ABRIÓ ({} bytes){}",
                    claro.len(),
                    if claro == datos { " — ¡Y ERA EL ORIGINAL!" } else { "" }
                )),
                // Sano pero distinto: la clave derivada cambia y el AAD (cabecera
                // entera) también, así que TIENE que caer en el AEAD, no antes.
                Err(DecodeError::Decrypt) => {}
                Err(otro) => aperturas_indebidas.push(format!(
                    "QUIP caso {caso}: {p:?} falló con {otro:?}, no en el AEAD (Decrypt)"
                )),
            }
        }
    }

    // ── QST1: varios contenedores, rejilla densa cada uno ──────────────────
    for caso in 0..4 {
        let n = 1 + (az.siguiente() as usize % 5000);
        let datos = az.bytes(n);
        let pass = az.frase();
        let opts = StreamOptions {
            pepper: b"",
            kdf_params: BASE,
            chunk_size: quipu::stream::DEFAULT_CHUNK_SIZE,
        };
        let blob = encrypt_stream_bytes(&datos, &pass, &opts);

        assert_eq!(
            leer_kdf(&blob, OFF_KDF_QST1),
            BASE,
            "QST1 caso {caso}: el offset del KDF no cae sobre los bytes del perfil base"
        );

        match intentar_qst1(&blob, BASE, &pass) {
            Ok(claro) => assert_eq!(claro, datos, "QST1 caso {caso}: el control no devolvió el claro exacto"),
            Err(e) => panic!("QST1 caso {caso}: el control POSITIVO falló con {e:?} — el banco no discrimina"),
        }
        controles += 1;

        for &p in &densa {
            variantes_probadas += 1;
            match intentar_qst1(&blob, p, &pass) {
                Ok(claro) => aperturas_indebidas.push(format!(
                    "QST1 caso {caso}: {p:?} ABRIÓ ({} bytes){}",
                    claro.len(),
                    if claro == datos { " — ¡Y ERA EL ORIGINAL!" } else { "" }
                )),
                Err(StreamError::Decrypt) => {}
                Err(otro) => aperturas_indebidas.push(format!(
                    "QST1 caso {caso}: {p:?} falló con {otro:?}, no en el AEAD (Decrypt)"
                )),
            }
        }
    }

    // ── Techo del rango: una vez por formato (64 y 256 MiB) ─────────────────
    {
        let datos = az.bytes(256);
        let pass = az.frase();
        let opts = Options {
            pepper: b"",
            kdf_params: BASE,
            codebook_id: 0,
        };
        let blob = encode_to_blob(&datos, &pass, HUELLA, &opts);
        for &p in &techo {
            variantes_probadas += 1;
            match intentar_quip(&blob, p, &pass) {
                Ok(claro) => aperturas_indebidas
                    .push(format!("QUIP techo: {p:?} ABRIÓ ({} bytes)", claro.len())),
                Err(DecodeError::Decrypt) => {}
                Err(otro) => aperturas_indebidas
                    .push(format!("QUIP techo: {p:?} falló con {otro:?}, no en el AEAD")),
            }
        }
    }
    {
        let datos = az.bytes(4096);
        let pass = az.frase();
        let opts = StreamOptions {
            pepper: b"",
            kdf_params: BASE,
            chunk_size: quipu::stream::DEFAULT_CHUNK_SIZE,
        };
        let blob = encrypt_stream_bytes(&datos, &pass, &opts);
        for &p in &techo {
            variantes_probadas += 1;
            match intentar_qst1(&blob, p, &pass) {
                Ok(claro) => aperturas_indebidas
                    .push(format!("QST1 techo: {p:?} ABRIÓ ({} bytes)", claro.len())),
                Err(StreamError::Decrypt) => {}
                Err(otro) => aperturas_indebidas
                    .push(format!("QST1 techo: {p:?} falló con {otro:?}, no en el AEAD")),
            }
        }
    }

    // Directiva 8: 100+ operaciones de verdad, no tres.
    assert!(
        variantes_probadas > 100,
        "solo se probaron {variantes_probadas} variantes: el banco no simula a escala"
    );
    assert_eq!(controles, 8, "faltan controles positivos");
    assert!(
        aperturas_indebidas.is_empty(),
        "{} de {variantes_probadas} variantes con KDF degradado ABRIERON el contenedor:\n{}",
        aperturas_indebidas.len(),
        aperturas_indebidas[..aperturas_indebidas.len().min(15)].join("\n")
    );
}
