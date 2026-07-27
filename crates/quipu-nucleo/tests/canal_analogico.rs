//! Qué sobrevive el viaje por papel, MEDIDO.
//!
//! El canal de glifos se anunciaba como «analógico», pero `recognize` muestrea
//! en coordenadas fijas —`i * CELL + PAD`— y eso exige que la imagen sea
//! idéntica píxel a píxel a la que se renderizó. Ninguna imagen que haya pasado
//! por una impresora y un sensor lo es: cambia de tamaño, se inclina unos
//! grados, cambia el brillo y trae ruido.
//!
//! Estas pruebas no comprueban que el canal funcione: **miden qué le pasa**.
//! Las que describen una degradación todavía no soportada están marcadas como
//! fallo esperado con `should_panic`, para que el día que se implemente el
//! registro la prueba obligue a quitar la marca. Ver
//! [[principio-registrar-cerca-de-la-violacion]].
//!
//! Sin esta medición, «el canal analógico está a medias» es una frase; con
//! ella, es una lista de lo que falta.

use image::{GrayImage, ImageFormat, Luma};
use std::io::Cursor;

use quipu_nucleo::glyphfont;

/// Un mensaje de prueba: cubre todo el alfabeto y repite algunos.
fn indices() -> Vec<u32> {
    let font = glyphfont::standard();
    (0..font.base()).chain([0, 5, 93, 42]).collect()
}

fn a_png(img: &GrayImage) -> Vec<u8> {
    let mut out = Vec::new();
    img.write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
        .expect("codificación PNG");
    out
}

fn desde_png(png: &[u8]) -> GrayImage {
    image::load_from_memory(png).expect("PNG válido").to_luma8()
}

/// Cuántos símbolos se recuperan bien, de 0 a 1.
fn tasa(png: &[u8], esperado: &[u32]) -> f64 {
    match glyphfont::standard().recognize(png) {
        None => 0.0,
        Some(leidos) => {
            let aciertos = leidos
                .iter()
                .zip(esperado)
                .filter(|(a, b)| a == b)
                .count();
            aciertos as f64 / esperado.len() as f64
        }
    }
}

// ===========================================================================
// LO QUE SÍ FUNCIONA HOY
// ===========================================================================

#[test]
fn el_ida_y_vuelta_exacto_es_perfecto() {
    let esperado = indices();
    let png = glyphfont::standard().render(&esperado);
    assert_eq!(tasa(&png, &esperado), 1.0);
}

// ===========================================================================
// LO QUE NO — cada una es un requisito del canal analógico
// ===========================================================================

/// Escalar es lo MÍNIMO que hace un escáner: 300 ppp no da los mismos píxeles.
#[test]
#[should_panic(expected = "escala")]
fn sobrevive_a_un_escaneo_a_otra_resolucion() {
    let esperado = indices();
    let png = glyphfont::standard().render(&esperado);
    let img = desde_png(&png);
    let doble = image::imageops::resize(
        &img,
        img.width() * 2,
        img.height() * 2,
        image::imageops::FilterType::Nearest,
    );
    let t = tasa(&a_png(&doble), &esperado);
    assert!(t > 0.99, "escala x2: se recupera el {:.0} %", t * 100.0);
}

/// Una hoja sobre la mesa nunca queda a cero grados.
#[test]
#[should_panic(expected = "rotación")]
fn sobrevive_a_una_inclinacion_de_dos_grados() {
    let esperado = indices();
    let png = glyphfont::standard().render(&esperado);
    let img = desde_png(&png);
    let girada = rotar(&img, 2.0_f32.to_radians());
    let t = tasa(&a_png(&girada), &esperado);
    assert!(t > 0.99, "rotación 2°: se recupera el {:.0} %", t * 100.0);
}

/// El papel blanco no sale blanco: sale gris con sombra.
///
/// Esta prueba MIDE el punto de ruptura en vez de suponerlo. La primera
/// versión aplicaba un degradado hasta 0,55 y pasaba — porque el blanco caía a
/// 140, todavía por encima del umbral fijo de 128, así que no probaba nada.
/// Una sombra de móvil llega mucho más abajo.
#[test]
fn se_mide_hasta_donde_aguanta_la_sombra() {
    let esperado = indices();
    let png = glyphfont::standard().render(&esperado);
    let mut ultimo_bueno = 0.0_f32;
    let mut primer_fallo = None;

    for paso in 0..=10 {
        let minimo = 1.0 - paso as f32 * 0.1;   // de 1,0 a 0,0
        let mut img = desde_png(&png);
        let (w, h) = img.dimensions();
        for y in 0..h {
            for x in 0..w {
                let p = img.get_pixel(x, y).0[0] as f32;
                let factor = 1.0 - (1.0 - minimo) * (x as f32 / w as f32);
                img.put_pixel(x, y, Luma([(p * factor) as u8]));
            }
        }
        let t = tasa(&a_png(&img), &esperado);
        if t > 0.99 {
            ultimo_bueno = minimo;
        } else if primer_fallo.is_none() {
            primer_fallo = Some((minimo, t));
        }
    }

    let (rompe, tasa_rota) = primer_fallo.expect(
        "con el blanco a cero tendría que fallar; si no, la prueba no mide",
    );
    // MEDIDO: aguanta hasta un factor de 0,5 en el borde y rompe en 0,4.
    // `ultimo_bueno` es el factor MÁS BAJO que todavía se lee, así que menor es
    // mejor — la primera versión comparaba al revés y hacía fallar una medición
    // que era buena noticia.
    //
    // Que el umbral fijo de 128 llegue tan lejos tiene explicación: el
    // degradado solo hunde el borde derecho, y el reconocimiento compara
    // huellas completas por vecino más cercano, no píxeles sueltos. Aun así,
    // una sombra de móvil pasa de 0,4 sin esfuerzo.
    assert!(
        ultimo_bueno <= 0.6,
        "solo aguanta hasta {ultimo_bueno}: empeoró respecto de 0,5 medido",
    );
    assert!(
        rompe >= 0.3,
        "rompe en {rompe} (recupera {:.0} %), mucho antes de lo medido",
        tasa_rota * 100.0,
    );
}

/// Un margen alrededor: nadie recorta la hoja al píxel.
#[test]
#[should_panic(expected = "margen")]
fn sobrevive_a_un_margen_alrededor() {
    let esperado = indices();
    let png = glyphfont::standard().render(&esperado);
    let img = desde_png(&png);
    let (w, h) = img.dimensions();
    let m = 20;
    let mut con_margen = GrayImage::from_pixel(w + 2 * m, h + 2 * m, Luma([255]));
    image::imageops::overlay(&mut con_margen, &img, m as i64, m as i64);
    let t = tasa(&a_png(&con_margen), &esperado);
    assert!(t > 0.99, "margen: se recupera el {:.0} %", t * 100.0);
}

/// Giro exacto por bilineal, con fondo blanco.
fn rotar(img: &GrayImage, rad: f32) -> GrayImage {
    let (w, h) = img.dimensions();
    let (cx, cy) = (w as f32 / 2.0, h as f32 / 2.0);
    let (s, c) = rad.sin_cos();
    let mut out = GrayImage::from_pixel(w, h, Luma([255]));
    for y in 0..h {
        for x in 0..w {
            let (dx, dy) = (x as f32 - cx, y as f32 - cy);
            let sx = c * dx + s * dy + cx;
            let sy = -s * dx + c * dy + cy;
            if sx >= 0.0 && sy >= 0.0 && sx < w as f32 && sy < h as f32 {
                out.put_pixel(x, y, *img.get_pixel(sx as u32, sy as u32));
            }
        }
    }
    out
}

// ===========================================================================
// EL UMBRAL DE RECHAZO
//
// `recognize` devolvía SIEMPRE el glifo más cercano, estuviera a distancia 1 o
// a 200. Una foto de una pared producía una secuencia de índices perfectamente
// formada. Un canal que nunca dice «no sé» no distingue un dato de un ruido.
// ===========================================================================

/// El umbral está en el HUECO entre lo que hay que aceptar y lo que hay que
/// rechazar, medido — no en una fracción elegida por bonita.
///
///     desenfoque al 5,6 % de celda   margen mínimo = 20   <- aceptar
///     ruido tipo «foto de una pared» margen máximo =  7   <- rechazar
///
/// `d_min/2 = 16` cae dentro con holgura a los dos lados. El primer intento
/// puso `d_min/4 = 8`, a UN bit del ruido.
#[test]
fn el_margen_sale_del_alfabeto_y_cae_en_el_hueco_medido() {
    let f = glyphfont::standard();
    let d = f.distancia_minima();
    assert!(d >= 2, "alfabeto sin separación: d_min = {d}");
    assert_eq!(f.margen_minimo(), d / 2);
    assert!(
        (8..=19).contains(&f.margen_minimo()),
        "el margen {} se salió del hueco entre el ruido (7) y el desenfoque          aceptable (20): vuelve a medir las dos poblaciones antes de moverlo",
        f.margen_minimo(),
    );
}

#[test]
fn una_imagen_que_no_son_glifos_se_rechaza() {
    // Ruido determinista: nada que ver con el alfabeto.
    let (w, h) = (18 * 20, 18);
    let mut img = GrayImage::new(w, h);
    let mut x = 0x2545_F491_4F6C_DD1Du64;
    for p in img.pixels_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *p = Luma([(x & 0xFF) as u8]);
    }
    assert!(
        glyphfont::standard().recognize(&a_png(&img)).is_none(),
        "el ruido se leyó como glifos: el canal no puede decir «no sé»",
    );
}

#[test]
fn una_hoja_en_blanco_tampoco_es_un_mensaje() {
    let img = GrayImage::from_pixel(18 * 20, 18, Luma([255]));
    assert!(glyphfont::standard().recognize(&a_png(&img)).is_none());
}

#[test]
fn un_glifo_intacto_sigue_leyendose() {
    // Que discrimine: si rechazara todo, las dos de arriba no probarían nada.
    let esperado = indices();
    let png = glyphfont::standard().render(&esperado);
    assert_eq!(glyphfont::standard().recognize(&png).unwrap(), esperado);
}
