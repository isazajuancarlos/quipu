// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Genera el corpus SEMILLA de los objetivos de fuzz que no pueden alcanzarse
//! por mutación ciega.
//!
//!   cargo run --release --example gen_semillas_fuzz
//!
//! POR QUÉ EXISTE. `parse_signed` y `parse_recipient` arrancaban sin corpus, y
//! eso no es un detalle de afinado: es la diferencia entre fuzzear y no fuzzear.
//! `decode_verified` rechaza por `TooShort` todo blob de menos de
//! `SIGNED_PREFIX + SIGNATURE_LEN` = 4701 bytes, y el `-max_len` por defecto de
//! libFuzzer es 4096. Sin una semilla larga, el objetivo NO PUEDE construir una
//! entrada que pase esa puerta, por muchas horas que corra — medido: 96.923
//! ejecuciones con la cobertura congelada desde la nº 5.
//!
//! Una semilla del tamaño real arregla las dos cosas a la vez: pasa la puerta, y
//! libFuzzer sube solo su `-max_len` al mayor de las unidades del corpus.
//!
//! QUÉ ESCRIBE. Blobs CRUDOS —el mismo dominio que consumen `parse_container` y
//! `unpad`, que es lo que hace que compartir corpus entre los cuatro signifique
//! algo (ver `fuzz/README.md`)—: un artefacto válido y las mutaciones de frontera
//! que un mutador ciego tardaría en encontrar y que son justo donde un índice mal
//! calculado desborda.
//!
//! NO BORRA NADA. Escribe ficheros con prefijo `semilla-`; lo que libFuzzer haya
//! descubierto por su cuenta (nombres sha1) se queda donde está. Regenerar es
//! idempotente: mismos nombres, mismo contenido.

use quipu::api::Options;
use quipu::codec;
use quipu::dictionaries;
use quipu::dictionary::Dictionary;
use quipu::kdf::KdfParams;
use quipu::{api, pqhybrid, pqsign, prelayers};
use std::path::{Path, PathBuf};

/// Deshace la representación en símbolos para recuperar el blob que ve el parser.
/// Usa solo API pública, así que por construcción es EXACTAMENTE lo que
/// `decode_verified` / `decode_as_recipient` reciben tras `dict.decode`.
fn blob_de(simbolos: &str, dict: &Dictionary) -> Vec<u8> {
    let indices = dict.decode(simbolos).expect("lo produjo el propio códec");
    codec::decode_base_n(&indices, dict.base())
}

fn escribir(dir: &Path, nombre: &str, bytes: &[u8]) {
    std::fs::create_dir_all(dir).expect("no se pudo crear el directorio del corpus");
    let ruta = dir.join(format!("semilla-{nombre}"));
    std::fs::write(&ruta, bytes).expect("no se pudo escribir la semilla");
    println!("  {} ({} B)", ruta.display(), bytes.len());
}

/// Mutaciones de frontera comunes a los dos contenedores: son las que castigan
/// el rebanado de campos de longitud fija, no el contenido.
/// Qué campos tiene REALMENTE el formato que se está sembrando.
///
/// Existe porque la primera versión de esto aplicaba las mismas mutaciones a los
/// cuatro objetivos y escribía en `unpad/` semillas llamadas `magic-roto` y
/// `version-desconocida`. `unpad` no tiene mágico ni versión: los bytes eran
/// entradas legítimas, pero el nombre decía algo distinto de lo que significaba, y
/// dentro de un año nadie sabría qué se creía estar probando (directiva 21).
struct Estructura {
    /// Mínimo que el parser exige antes de rebanar nada. `None` si no comprueba.
    minimo: Option<usize>,
    /// Offset del mágico, si el formato lleva.
    magic: Option<usize>,
    /// Offset del byte de versión, si lo lleva.
    version: Option<usize>,
    /// `(offset, ancho)` de un campo de longitud big-endian, si lo lleva. El
    /// ancho importa: el contenedor firmado declara la longitud en `u32` y el
    /// relleno de Padmé en `u64`. Escribir 4 bytes sobre un campo de 8 no es
    /// «longitud máxima», es otra cosa con ese nombre.
    largo: Option<(usize, usize)>,
    /// Cómo llamar al último tramo al voltearle un bit: «firma», «relleno»…
    cola: &'static str,
}

fn variantes(base: &[u8], e: &Estructura) -> Vec<(String, Vec<u8>)> {
    let mut v = Vec::new();
    v.push(("valido".into(), base.to_vec()));

    // Justo por debajo y justo por encima del mínimo que exige el parser: el par
    // que distingue «rechaza por corto» de «entra a rebanar».
    if let Some(m) = e.minimo
        && m > 0
        && base.len() > m
    {
        v.push(("minimo-menos-uno".into(), base[..m - 1].to_vec()));
        v.push(("minimo-exacto".into(), base[..m].to_vec()));
    }
    // Truncado a la mitad: el artefacto partido por el medio.
    v.push(("truncado-mitad".into(), base[..base.len() / 2].to_vec()));
    // Un byte menos: el último tramo queda incompleto por uno.
    v.push(("un-byte-menos".into(), base[..base.len() - 1].to_vec()));

    // Mágico y versión: los dos rechazos tempranos, para que el corpus los tenga
    // y no gaste ejecuciones redescubriéndolos. Solo si el formato los tiene.
    if let Some(off) = e.magic {
        let mut m = base.to_vec();
        m[off] ^= 0xFF;
        v.push(("magic-roto".into(), m));
    }
    if let Some(off) = e.version {
        let mut m = base.to_vec();
        m[off] = m[off].wrapping_add(1);
        v.push(("version-desconocida".into(), m));
    }

    // Campo de longitud declarado: los valores que hacen aritmética peligrosa.
    if let Some((off, ancho)) = e.largo {
        let tope = if ancho == 4 { u64::from(u32::MAX) } else { u64::MAX };
        for (nombre, valor) in [
            ("len-cero", 0u64),
            ("len-maximo", tope),
            ("len-casi-maximo", tope - 8),
        ] {
            let mut m = base.to_vec();
            let be = valor.to_be_bytes();
            // `to_be_bytes` de u64 da 8 bytes; para un campo de 4 se toman los
            // cuatro de menor peso, que son los que caben en el campo real.
            m[off..off + ancho].copy_from_slice(&be[8 - ancho..]);
            v.push((nombre.into(), m));
        }
    }

    // Un bit volteado en el último tramo: bien formado, no valida.
    let mut bit = base.to_vec();
    let ultimo = bit.len() - 1;
    bit[ultimo] ^= 0x01;
    v.push((format!("bit-en-{}", e.cola), bit));

    v
}

fn main() {
    let raiz = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus");
    let dict = dictionaries::flagship();
    let mensaje = b"semilla de fuzz: un mensaje de longitud media para el corpus";

    // ---- parse_signed ----
    // Blob = QSG1 | ver(1) | flags(1) | len(4 BE) | mensaje | firma(4691).
    // El campo de longitud vive en el offset 6.
    println!("parse_signed:");
    let (_vk, sk) = pqsign::generate_keypair();
    let firmado = api::encode_signed(mensaje, &sk, &dict);
    let blob = blob_de(&firmado, &dict);
    let minimo = 10 + pqsign::SIGNATURE_LEN;
    assert!(
        blob.len() >= minimo,
        "el artefacto real debe superar el mínimo del parser"
    );
    for (nombre, bytes) in variantes(
        &blob,
        &Estructura {
            minimo: Some(minimo),
            magic: Some(0),
            version: Some(4),
            largo: Some((6, 4)),
            cola: "la-firma",
        },
    ) {
        escribir(&raiz.join("parse_signed"), &nombre, &bytes);
    }

    // ---- parse_recipient ----
    // Blob = QPQ1 | ver(1) | flags(1) | nonce | encapsulación | ciphertext.
    // No lleva campo de longitud propio: la encapsulación es de tamaño fijo, así
    // que aquí no hay offset que mutar y se pasa `None` en vez de inventar uno.
    println!("parse_recipient:");
    let (pk, _sk) = pqhybrid::generate_keypair().expect("hay entropía");
    let hacia = api::encode_to_recipient(mensaje, &pk, &dict).expect("hay entropía");
    let blob = blob_de(&hacia, &dict);
    for (nombre, bytes) in variantes(
        &blob,
        &Estructura {
            minimo: None,
            magic: Some(0),
            version: Some(4),
            largo: None,
            cola: "el-ciphertext",
        },
    ) {
        escribir(&raiz.join("parse_recipient"), &nombre, &bytes);
    }

    // ---- parse_container ----
    // Blob = QUIP | ver | flags | codebook_id(2) | huella(8) | salt(16) |
    // nonce(24) | mem(4) | iter(4) | par(4) | ciphertext. Cabecera de 68 bytes.
    // No hay campo de longitud: el ciphertext es «lo que quede». Lo que sí hay son
    // los tres enteros del KDF (mem@56, iteraciones@60, paralelismo@64), y el que
    // se muta es `iterations` — un entero de 4 bytes que el parser lee y usa.
    println!("parse_container:");
    let opts = Options {
        pepper: b"",
        kdf_params: KdfParams {
            mem_kib: 64,
            iterations: 1,
            parallelism: 1,
        },
        codebook_id: 0,
    };
    let blob = api::encode_to_blob(mensaje, "semilla-de-fuzz", [0u8; 8], &opts);
    for (nombre, bytes) in variantes(
        &blob,
        &Estructura {
            minimo: Some(68),
            magic: Some(0),
            version: Some(4),
            largo: Some((60, 4)), // kdf_iterations
            cola: "el-ciphertext",
        },
    ) {
        escribir(&raiz.join("parse_container"), &nombre, &bytes);
    }

    // ---- unpad ----
    // El texto rellenado por Padmé: prefijo de longitud u64 BE en el offset 0,
    // luego los datos, luego el relleno. NO tiene mágico ni versión, y por eso no
    // se le inventan: una semilla llamada `magic-roto` en un formato sin mágico
    // es una mentira archivada.
    println!("unpad:");
    let relleno = prelayers::pad(mensaje);
    for (nombre, bytes) in variantes(
        &relleno,
        &Estructura {
            minimo: Some(8), // LEN_PREFIX: por debajo, `unpad` rechaza
            magic: None,
            version: None,
            largo: Some((0, 8)),
            cola: "el-relleno",
        },
    ) {
        escribir(&raiz.join("unpad"), &nombre, &bytes);
    }

    println!("\nListo. Los cuatro objetivos de la familia del blob quedan sembrados,");
    println!("y por eso el encadenado del CI tiene algo que encadenar: fuzz/corpus");
    println!("está en .gitignore, así que en una copia limpia no hay corpus ninguno.");
    println!("Se DERIVA, no se guarda — igual que la lista de objetivos.");
}
