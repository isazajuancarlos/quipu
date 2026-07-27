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

// ===========================================================================
// LA HUELLA DEL PORTADOR
//
// Responde «¿es esta la hoja que se emitió?» para compararla contra un sello
// externo. Sus tres propiedades SON el diseño, así que cada una tiene prueba.
// ===========================================================================

use quipu::api::huella_del_portador;

#[test]
fn la_misma_hoja_da_la_misma_huella() {
    let png = encode_to_glyph_image(SECRETO, "clave", &opciones());
    assert_eq!(
        huella_del_portador(&png).unwrap(),
        huella_del_portador(&png).unwrap()
    );
}

#[test]
fn no_hace_falta_la_clave_para_calcularla() {
    // La propiedad que permite a un perito verificar la hoja sin que nadie le
    // entregue el secreto. Y, sobre todo, la que impide que sea un oráculo:
    // no dice si una clave es correcta, que es lo que honey existe para negar.
    let png = encode_to_glyph_image(SECRETO, "clave-de-verdad", &opciones());
    let con_clave = huella_del_portador(&png).unwrap();

    // Se calcula igual sin conocerla, y descifrar con otra clave no la cambia.
    assert!(decode_from_glyph_image(&png, "clave-equivocada", b"").is_err());
    assert_eq!(huella_del_portador(&png).unwrap(), con_clave);
}

#[test]
fn una_hoja_manchada_pero_legible_da_la_misma_huella() {
    // Se calcula DESPUÉS de Reed-Solomon. Si se calculara sobre los píxeles,
    // cualquier mota la invalidaría y el control sería inservible en papel.
    let png = encode_to_glyph_image(SECRETO, "clave", &opciones());
    let limpia = huella_del_portador(&png).unwrap();
    let manchada = manchar(&png, 4);
    assert_eq!(
        huella_del_portador(&manchada).unwrap(),
        limpia,
        "una mancha reparable cambia la huella: el control no sirve en papel",
    );
}

#[test]
fn otra_hoja_da_otra_huella() {
    // Que discrimine: si diera siempre lo mismo, las de arriba no probarían nada.
    let a = encode_to_glyph_image(SECRETO, "clave", &opciones());
    let b = encode_to_glyph_image(b"un secreto distinto del primero", "clave", &opciones());
    assert_ne!(
        huella_del_portador(&a).unwrap(),
        huella_del_portador(&b).unwrap()
    );
}

#[test]
fn una_hoja_ilegible_no_da_huella() {
    let png = encode_to_glyph_image(SECRETO, "clave", &opciones());
    let destrozada = manchar_seguidas(&png, 0, 40);
    assert!(huella_del_portador(&destrozada).is_err());
}
