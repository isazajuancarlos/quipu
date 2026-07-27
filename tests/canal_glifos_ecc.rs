//! Qué compra el Reed-Solomon en el canal de glifos.
//!
//! Hasta ahora el canal NO estaba protegido, mientras el canal PNG hermano sí
//! lo estaba con el mismo módulo `ecc`. La asimetría no tenía razón escrita en
//! ninguna parte. Consecuencia: UN glifo mal leído destruía la carga entera.
//!
//! Estas pruebas dañan la tira de glifos a propósito y miden cuánto aguanta.

use quipu::api::{decode_from_glyph_image, encode_to_glyph_image, Options};
use quipu::kdf::KdfParams;

/// KDF barato: estas pruebas miden el canal, no el coste de derivación.
fn opciones() -> Options<'static> {
    Options {
        kdf_params: KdfParams { mem_kib: 8, iterations: 1, parallelism: 1 },
        ..Options::default()
    }
}

const SECRETO: &[u8] = b"clave de custodia en papel: 32 bytes de entropia!";

/// Estropea `n` glifos poniendo su celda en blanco, como una mancha.
fn manchar(png: &[u8], n: usize) -> Vec<u8> {
    use image::{ImageFormat, Luma};
    const CELL: u32 = 18;
    let mut img = image::load_from_memory(png).unwrap().to_luma8();
    let total = img.width() / CELL;
    for k in 0..n as u32 {
        // Desde la PRIMERA celda: la cabecera ya lleva su propio bloque
        // Reed-Solomon, así que dañarla debe repararse como cualquier otra
        // parte. Antes había que saltársela y eso era el punto único de fallo.
        let celda = (k * total / n.max(1) as u32).min(total - 1);
        for y in 0..img.height() {
            for x in 0..CELL {
                img.put_pixel(celda * CELL + x, y, Luma([255]));
            }
        }
    }
    let mut out = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut out), ImageFormat::Png)
        .unwrap();
    out
}

#[test]
fn sin_dano_se_recupera() {
    let png = encode_to_glyph_image(SECRETO, "clave", &opciones());
    assert_eq!(
        decode_from_glyph_image(&png, "clave", b"").unwrap(),
        SECRETO
    );
}

#[test]
fn se_mide_cuantos_glifos_manchados_aguanta() {
    let png = encode_to_glyph_image(SECRETO, "clave", &opciones());
    let mut ultimo_ok = 0;
    for n in 1..=24 {
        let roto = manchar(&png, n);
        if decode_from_glyph_image(&roto, "clave", b"") .map(|v| v == SECRETO).unwrap_or(false) {
            ultimo_ok = n;
        } else {
            break;
        }
    }
    // Antes de conectar el ECC, UNO bastaba para perderlo todo.
    assert!(
        ultimo_ok >= 1,
        "no aguanta ni un glifo manchado: el ECC no está haciendo nada",
    );
    println!("aguanta {ultimo_ok} glifos manchados");
}

#[test]
fn con_dano_excesivo_falla_ruidosamente_y_no_devuelve_basura() {
    let png = encode_to_glyph_image(SECRETO, "clave", &opciones());
    let destrozado = manchar(&png, 60);
    // Lo que NO puede pasar es que devuelva bytes distintos como si fueran
    // buenos. O el secreto, o un error.
    match decode_from_glyph_image(&destrozado, "clave", b"") {
        Err(_) => {}
        Ok(v) => assert_eq!(v, SECRETO, "devolvió bytes que NO son el secreto"),
    }
}

/// Una mancha en la ESQUINA, no repartida.
///
/// Es el caso que preocupaba: ahí vivía la cabecera desnuda y un dedo con
/// tinta destruía el mensaje entero mientras el resto de la tira estaba
/// perfecta. Ahora la cabecera lleva su propio bloque Reed-Solomon.
fn manchar_seguidas(png: &[u8], desde: u32, n: u32) -> Vec<u8> {
    use image::{ImageFormat, Luma};
    const CELL: u32 = 18;
    let mut img = image::load_from_memory(png).unwrap().to_luma8();
    for c in desde..(desde + n).min(img.width() / CELL) {
        for y in 0..img.height() {
            for x in 0..CELL {
                img.put_pixel(c * CELL + x, y, Luma([255]));
            }
        }
    }
    let mut out = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut out), ImageFormat::Png).unwrap();
    out
}

#[test]
fn una_mancha_en_la_esquina_ya_no_lo_pierde_todo() {
    let png = encode_to_glyph_image(SECRETO, "clave", &opciones());
    let manchado = manchar_seguidas(&png, 0, 1);
    assert_eq!(
        decode_from_glyph_image(&manchado, "clave", b"").unwrap(),
        SECRETO,
        "un glifo borrado en la esquina sigue destruyendo el mensaje",
    );
}

#[test]
fn se_mide_la_mancha_seguida_que_aguanta_en_cada_extremo() {
    let png = encode_to_glyph_image(SECRETO, "clave", &opciones());
    let total = {
        let img = image::load_from_memory(&png).unwrap().to_luma8();
        img.width() / 18
    };
    for (nombre, desde) in [("esquina", 0u32), ("centro", total / 2), ("final", total - 6)] {
        let mut ok = 0;
        for n in 1..=8 {
            let roto = manchar_seguidas(&png, desde, n);
            if decode_from_glyph_image(&roto, "clave", b"").map(|v| v == SECRETO).unwrap_or(false) {
                ok = n;
            } else {
                break;
            }
        }
        println!("  mancha seguida en {nombre}: aguanta {ok} glifos");
        assert!(ok >= 1, "en {nombre} no aguanta ni uno");
    }
}
