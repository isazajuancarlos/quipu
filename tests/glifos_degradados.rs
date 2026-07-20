// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Cuánto aguanta el canal visual cuando la página se imprime y se fotografía.
//!
//! `glyphfont::recognize` lee los píxeles en posiciones FIJAS —`i*CELL + PAD`—
//! y decide por vecino más cercano en Hamming. Eso presupone una imagen
//! perfecta: sin desplazamiento, sin rotación, sin escala, con el mismo umbral
//! de negro en toda la página. Un PNG recién generado la cumple; una foto no
//! cumple ninguna.
//!
//! Antes de discutir si hace falta una red, hay que saber DÓNDE se rompe lo que
//! hay. Este banco degrada la imagen de forma controlada y mide la tasa de
//! acierto. Sin la medición, «una CNN pequeña supera a cualquier heurística» es
//! una creencia: puede que la heurística que hay no sea la que se compara, sino
//! ninguna en absoluto.
//!
//! Vive en `tests/` a propósito: el degradador es un instrumento de medida y no
//! tiene por qué viajar en la biblioteca.

use image::{GrayImage, Luma};
use quipu::glyphfont;

/// Los índices de prueba: el alfabeto entero más algunos repetidos.
fn indices() -> Vec<u32> {
    let base = glyphfont::standard().base();
    (0..base).chain([0, 5, 42, base - 1]).collect()
}

fn png_a_gris(png: &[u8]) -> GrayImage {
    image::load_from_memory(png).expect("PNG válido").to_luma8()
}

fn gris_a_png(img: &GrayImage) -> Vec<u8> {
    let mut out = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
        .expect("codificación PNG");
    out
}

// --- Degradaciones -------------------------------------------------------
//
// Cada una imita algo que de verdad le pasa a una hoja: el escáner no la
// alinea, la cámara la toma torcida, la impresora sangra tinta, la luz entra
// por un lado.

/// Desplaza la imagen `dx`,`dy` píxeles. Es lo que hace un recorte a mano.
fn desplazar(img: &GrayImage, dx: i32, dy: i32) -> GrayImage {
    let (w, h) = img.dimensions();
    let mut out = GrayImage::from_pixel(w, h, Luma([255]));
    for y in 0..h as i32 {
        for x in 0..w as i32 {
            let (sx, sy) = (x - dx, y - dy);
            if sx >= 0 && sy >= 0 && (sx as u32) < w && (sy as u32) < h {
                out.put_pixel(x as u32, y as u32, *img.get_pixel(sx as u32, sy as u32));
            }
        }
    }
    out
}

/// Gira `grados` alrededor del centro, con vecino más cercano.
fn rotar(img: &GrayImage, grados: f32) -> GrayImage {
    let (w, h) = img.dimensions();
    let (cx, cy) = (w as f32 / 2.0, h as f32 / 2.0);
    let (s, c) = grados.to_radians().sin_cos();
    let mut out = GrayImage::from_pixel(w, h, Luma([255]));
    for y in 0..h {
        for x in 0..w {
            let (dx, dy) = (x as f32 - cx, y as f32 - cy);
            let sx = (c * dx + s * dy + cx).round();
            let sy = (-s * dx + c * dy + cy).round();
            if sx >= 0.0 && sy >= 0.0 && (sx as u32) < w && (sy as u32) < h {
                out.put_pixel(x, y, *img.get_pixel(sx as u32, sy as u32));
            }
        }
    }
    out
}

/// Iluminación desigual: la luz entra por la izquierda y se apaga a la derecha.
/// No cambia la forma de nada; cambia el UMBRAL con el que hay que leerla, que
/// es justo lo que `recognize` tiene fijo en 128.
fn iluminacion_lateral(img: &GrayImage, caida: f32) -> GrayImage {
    let (w, h) = img.dimensions();
    let mut out = img.clone();
    for y in 0..h {
        for x in 0..w {
            let f = 1.0 - caida * (x as f32 / w as f32);
            let v = img.get_pixel(x, y).0[0] as f32 * f;
            out.put_pixel(x, y, Luma([v.clamp(0.0, 255.0) as u8]));
        }
    }
    out
}

/// Sangrado de tinta: cada píxel negro tiñe a sus vecinos (dilatación).
fn sangrado(img: &GrayImage) -> GrayImage {
    let (w, h) = img.dimensions();
    let mut out = img.clone();
    for y in 0..h {
        for x in 0..w {
            let mut min = 255u8;
            for (ddx, ddy) in [(0i32, 0i32), (1, 0), (-1, 0), (0, 1), (0, -1)] {
                let (sx, sy) = (x as i32 + ddx, y as i32 + ddy);
                if sx >= 0 && sy >= 0 && (sx as u32) < w && (sy as u32) < h {
                    min = min.min(img.get_pixel(sx as u32, sy as u32).0[0]);
                }
            }
            out.put_pixel(x, y, Luma([min]));
        }
    }
    out
}

/// Ruido de sensor, determinista para que la medición sea repetible.
fn ruido(img: &GrayImage, amplitud: i32, semilla: u64) -> GrayImage {
    let mut estado = semilla | 1;
    let mut siguiente = || {
        estado ^= estado << 13;
        estado ^= estado >> 7;
        estado ^= estado << 17;
        estado
    };
    let mut out = img.clone();
    for p in out.pixels_mut() {
        let d = (siguiente() % (2 * amplitud as u64 + 1)) as i32 - amplitud;
        p.0[0] = (p.0[0] as i32 + d).clamp(0, 255) as u8;
    }
    out
}

// --- Medición ------------------------------------------------------------

/// Qué fracción de los glifos se reconoce bien tras aplicar `degradar`.
fn acierto(degradar: impl Fn(&GrayImage) -> GrayImage) -> f32 {
    let font = glyphfont::standard();
    let esperados = indices();
    let png = font.render(&esperados);
    let degradada = degradar(&png_a_gris(&png));
    match font.recognize(&gris_a_png(&degradada)) {
        None => 0.0,
        Some(leidos) => {
            if leidos.len() != esperados.len() {
                return 0.0;
            }
            let ok = leidos.iter().zip(&esperados).filter(|(a, b)| a == b).count();
            ok as f32 / esperados.len() as f32
        }
    }
}

#[test]
fn sobre_una_imagen_limpia_acierta_todo() {
    assert_eq!(acierto(|i| i.clone()), 1.0);
}

/// El banco completo, con el nombre de cada degradación y lo que se mide.
/// Se imprime siempre: el número importa más que el veredicto.
#[test]
fn banco_de_degradaciones() {
    let casos: Vec<(&str, Box<dyn Fn(&GrayImage) -> GrayImage>)> = vec![
        ("limpia", Box::new(|i: &GrayImage| i.clone())),
        ("desplazada 1 px", Box::new(|i: &GrayImage| desplazar(i, 1, 0))),
        ("desplazada 2 px", Box::new(|i: &GrayImage| desplazar(i, 2, 1))),
        ("rotada 0,5°", Box::new(|i: &GrayImage| rotar(i, 0.5))),
        ("rotada 2°", Box::new(|i: &GrayImage| rotar(i, 2.0))),
        ("luz lateral 40 %", Box::new(|i: &GrayImage| iluminacion_lateral(i, 0.4))),
        ("luz lateral 60 %", Box::new(|i: &GrayImage| iluminacion_lateral(i, 0.6))),
        ("sangrado de tinta", Box::new(sangrado)),
        ("ruido ±40", Box::new(|i: &GrayImage| ruido(i, 40, 0xC0FFEE))),
        ("ruido ±90", Box::new(|i: &GrayImage| ruido(i, 90, 0xC0FFEE))),
    ];

    println!("\n  degradación            acierto");
    println!("  ---------------------- -------");
    let mut resultados = Vec::new();
    for (nombre, f) in &casos {
        let a = acierto(|i| f(i));
        println!("  {nombre:<22} {:>6.1} %", a * 100.0);
        resultados.push((*nombre, a));
    }

    // Lo que se fija hoy es el ESTADO, no el objetivo: la imagen limpia se lee
    // entera y basta un píxel de desplazamiento para que no se lea nada. Cuando
    // el reconocedor mejore, estas dos aserciones fallarán y habrá que subirlas.
    let limpia = resultados[0].1;
    assert_eq!(limpia, 1.0, "el canal digital tiene que seguir siendo exacto");

    let desplazada = resultados[1].1;
    assert!(
        desplazada < 0.5,
        "el reconocedor ya tolera desplazamiento ({:.1} %): sube el umbral de \
         esta prueba y actualiza la tarea #26",
        desplazada * 100.0
    );
}
