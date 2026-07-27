// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Fuente de glifos nativa: genera de forma DETERMINISTA un alfabeto de 94
//! glifos optimizados por separabilidad (mismo enfoque que scripts/glyph_pipeline.py
//! pero en Rust), y permite:
//!   - render:    índices -> imagen PNG de glifos
//!   - recognize: imagen PNG -> índices (por vecino más cercano en Hamming)
//!
//! El round-trip es exacto sobre imágenes limpias (canal digital). Para canal
//! impreso/fotografiado, combinar con `ecc`.

use std::io::Cursor;
use std::sync::OnceLock;

use image::{GrayImage, ImageFormat, Luma};

use crate::glyphopt;

const SIZE: usize = 16; // lado del glifo en píxeles
const PAD: usize = 1;
const CELL: usize = SIZE + 2 * PAD;
const ALPHABET: usize = 94; // = símbolos ASCII imprimibles

type Bitmap = [[bool; SIZE]; SIZE];

/// PRNG determinista (xorshift64) para que el font sea siempre el mismo.
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn draw_line(bm: &mut Bitmap, mut x0: i32, mut y0: i32, x1: i32, y1: i32) {
    let dx = (x1 - x0).abs();
    let dy = -(y1 - y0).abs();
    let sx = if x0 < x1 { 1 } else { -1 };
    let sy = if y0 < y1 { 1 } else { -1 };
    let mut err = dx + dy;
    loop {
        if (0..SIZE as i32).contains(&x0) && (0..SIZE as i32).contains(&y0) {
            bm[y0 as usize][x0 as usize] = true;
        }
        if x0 == x1 && y0 == y1 {
            break;
        }
        let e2 = 2 * err;
        if e2 >= dy {
            err += dy;
            x0 += sx;
        }
        if e2 <= dx {
            err += dx;
            y0 += sy;
        }
    }
}

fn draw_circle(bm: &mut Bitmap, cx: i32, cy: i32, r: i32) {
    let (mut x, mut y, mut err) = (r, 0i32, 0i32);
    while x >= y {
        for (px, py) in [
            (cx + x, cy + y), (cx + y, cy + x), (cx - y, cy + x), (cx - x, cy + y),
            (cx - x, cy - y), (cx - y, cy - x), (cx + y, cy - x), (cx + x, cy - y),
        ] {
            if (0..SIZE as i32).contains(&px) && (0..SIZE as i32).contains(&py) {
                bm[py as usize][px as usize] = true;
            }
        }
        y += 1;
        err += 1 + 2 * y;
        if 2 * (err - x) + 1 > 0 {
            x -= 1;
            err += 1 - 2 * x;
        }
    }
}

fn fingerprint(bm: &Bitmap) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIZE * SIZE / 8);
    let mut byte = 0u8;
    let mut bits = 0;
    for row in bm.iter() {
        for &v in row.iter() {
            byte = (byte << 1) | v as u8;
            bits += 1;
            if bits == 8 {
                out.push(byte);
                byte = 0;
                bits = 0;
            }
        }
    }
    out
}

/// Genera el alfabeto determinista de 94 glifos.
fn build_font() -> (Vec<Bitmap>, Vec<Vec<u8>>) {
    let anchors: Vec<(i32, i32)> = [2, 6, 9, 13]
        .iter()
        .flat_map(|&x| [2, 6, 9, 13].iter().map(move |&y| (x, y)))
        .collect();

    let mut rng = Rng::new(0x00C0FFEE_D00DFACE);
    let mut seen = std::collections::HashSet::new();
    let mut cand_bm = Vec::new();
    let mut cand_fp = Vec::new();

    let mut attempts = 0;
    while cand_bm.len() < 2000 && attempts < 40000 {
        attempts += 1;
        let mut bm = [[false; SIZE]; SIZE];
        let nlines = 2 + rng.below(3);
        for _ in 0..nlines {
            let a = anchors[rng.below(anchors.len())];
            let b = anchors[rng.below(anchors.len())];
            if a != b {
                draw_line(&mut bm, a.0, a.1, b.0, b.1);
            }
        }
        if rng.below(10) < 4 {
            let c = [7, 8][rng.below(2)];
            let r = [3, 4, 5][rng.below(3)];
            draw_circle(&mut bm, c, c, r);
        }
        let filled: usize = bm.iter().flatten().filter(|&&v| v).count();
        if !(6..=120).contains(&filled) {
            continue;
        }
        let fp = fingerprint(&bm);
        if seen.insert(fp.clone()) {
            cand_bm.push(bm);
            cand_fp.push(fp);
        }
    }

    // El papel en blanco y el borrón negro son las dos texturas que este canal
    // encuentra SIEMPRE. Se pasan como huellas a evitar para que ningún glifo
    // del alfabeto se les parezca: una hoja vacía no puede ser un mensaje.
    let vacio = vec![0u8; SIZE * SIZE / 8];
    let lleno = vec![0xFFu8; SIZE * SIZE / 8];
    let idx = glyphopt::select_separable_subset_seeded(
        &cand_fp,
        ALPHABET,
        &[vacio, lleno],
    );
    let glyphs: Vec<Bitmap> = idx.iter().map(|&i| cand_bm[i]).collect();
    let fps: Vec<Vec<u8>> = idx.iter().map(|&i| cand_fp[i].clone()).collect();
    (glyphs, fps)
}

/// Alfabeto de glifos: bitmaps + huellas.
pub struct GlyphFont {
    glyphs: Vec<Bitmap>,
    fps: Vec<Vec<u8>>,
    /// MARGEN mínimo entre el glifo más cercano y el segundo, para aceptar la
    /// lectura. Se deriva del propio alfabeto al construirlo.
    margen: u32,
}

/// Devuelve el font estándar (construido una sola vez, determinista).
pub fn standard() -> &'static GlyphFont {
    static FONT: OnceLock<GlyphFont> = OnceLock::new();
    FONT.get_or_init(|| {
        let (glyphs, fps) = build_font();
        // POR QUÉ MARGEN Y NO DISTANCIA ABSOLUTA.
        //
        // El primer intento usó el radio clásico de decodificación,
        // (d_min-1)/2, que garantiza unicidad. Como criterio de RECHAZO resultó
        // demasiado estrecho: rompió `el_desenfoque_a_escala_realista`, una
        // medición que ya existía, tirando de 100 % a 0 % una lectura que el
        // vecino más cercano seguía acertando.
        //
        // La causa fue el modelo de ruido. Voltear N píxeles mueve la huella
        // exactamente N bits, y ahí el radio sobraba. Pero desenfocar y volver
        // a umbralizar DESPLAZA EL TRAZO ENTERO: voltea muchos más de 16 bits
        // mientras el glifo sigue siendo inconfundible.
        //
        // El margen mide otra cosa, y es la que importa: si el más cercano está
        // MUCHO más cerca que el segundo, la lectura es inequívoca aunque su
        // distancia absoluta sea grande. Y ante una foto de una pared todos los
        // candidatos quedan igual de lejos, el margen se desploma y se rechaza,
        // que es lo que se buscaba desde el principio.
        // El valor sale de medir las dos poblaciones que hay que separar
        // (2026-07-26, muestras de 40-98 celdas):
        //
        //     desenfoque al 5,6 % de celda   margen mínimo = 20   <- aceptar
        //     ruido tipo «foto de una pared» margen máximo =  7   <- rechazar
        //
        // Hay hueco limpio entre 7 y 20. d_min/2 = 16 cae dentro con holgura a
        // los dos lados; d_min/4 = 8 quedaba pegado al ruido, a un solo bit.
        let margen = glyphopt::min_pairwise_distance(&fps) / 2;
        GlyphFont { glyphs, fps, margen }
    })
}

impl GlyphFont {
    /// Tamaño del alfabeto (94).
    pub fn base(&self) -> u32 {
        self.glyphs.len() as u32
    }

    /// Distancia mínima entre dos glifos del alfabeto, en bits.
    pub fn distancia_minima(&self) -> u32 {
        glyphopt::min_pairwise_distance(&self.fps)
    }

    /// Vecino más cercano SIN rechazar nada. Para medir el alfabeto.
    ///
    /// La separabilidad del alfabeto y la regla de decisión son propiedades
    /// distintas, y mezclarlas confunde la medición: un banco que pregunta
    /// «¿cuántos glifos acierta con este desenfoque?» quiere la respuesta del
    /// clasificador, no la del criterio de confianza. Con rechazo todo-o-nada
    /// la respuesta es siempre 0 % en cuanto un solo glifo queda ambiguo, y
    /// eso no dice nada del alfabeto.
    ///
    /// No usar para leer de verdad: devuelve un glifo aunque la imagen sea una
    /// pared. Para eso están `recognize` y `recognize_marcando`.
    pub fn recognize_crudo(&self, png: &[u8]) -> Option<Vec<u32>> {
        let img = crate::render::decode_png_luma(png)?;
        let n = (img.width() as usize) / CELL;
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let ox = i * CELL + PAD;
            let mut bm = [[false; SIZE]; SIZE];
            for (y, row) in bm.iter_mut().enumerate() {
                for (x, cell) in row.iter_mut().enumerate() {
                    let px = img.get_pixel((ox + x) as u32, (PAD + y) as u32).0[0];
                    *cell = px < 128;
                }
            }
            let fp = fingerprint(&bm);
            out.push(
                self.fps
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, gfp)| glyphopt::hamming(&fp, gfp))
                    .map(|(j, _)| j as u32)?,
            );
        }
        Some(out)
    }

    /// El glifo más cercano y CUÁNTO le saca al segundo.
    ///
    /// Un margen grande es una lectura inequívoca; uno pequeño significa que
    /// dos símbolos compiten y no hay forma honesta de elegir.
    fn mejor_con_margen(&self, fp: &[u8]) -> Option<(u32, u32)> {
        let (mut d1, mut d2) = (u32::MAX, u32::MAX);
        let mut mejor = 0u32;
        for (j, gfp) in self.fps.iter().enumerate() {
            let d = glyphopt::hamming(fp, gfp);
            if d < d1 {
                d2 = d1;
                d1 = d;
                mejor = j as u32;
            } else if d < d2 {
                d2 = d;
            }
        }
        if d1 == u32::MAX {
            return None;
        }
        Some((mejor, d2.saturating_sub(d1)))
    }

    /// La huella de un glifo del alfabeto. Para diagnóstico y pruebas.
    pub fn huella(&self, i: usize) -> &[u8] {
        &self.fps[i]
    }

    /// Cuánto tiene que separarse el mejor candidato del segundo para creerle.
    pub fn margen_minimo(&self) -> u32 {
        self.margen
    }

    /// Pinta una secuencia de índices como una tira de glifos (PNG).
    pub fn render(&self, indices: &[u32]) -> Vec<u8> {
        let w = (indices.len().max(1) * CELL) as u32;
        let h = CELL as u32;
        let mut img = GrayImage::from_pixel(w, h, Luma([255]));
        for (i, &idx) in indices.iter().enumerate() {
            if let Some(bm) = self.glyphs.get(idx as usize) {
                let ox = i * CELL + PAD;
                for (y, row) in bm.iter().enumerate() {
                    for (x, &v) in row.iter().enumerate() {
                        if v {
                            img.put_pixel((ox + x) as u32, (PAD + y) as u32, Luma([0]));
                        }
                    }
                }
            }
        }
        let mut out = Vec::new();
        img.write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
            .expect("codificación PNG");
        out
    }

    /// Como [`GlyphFont::recognize`] pero MARCA los ilegibles en vez de
    /// abandonar la lectura entera.
    ///
    /// `recognize` devuelve `None` si un solo glifo cae fuera del radio, y eso
    /// es correcto para quien quiere todo o nada. Pero tira al suelo un
    /// mensaje que Reed-Solomon podría reparar: sería como negarse a leer un
    /// QR porque tiene una esquina manchada. Aquí cada posición vale por sí
    /// misma y el corrector decide.
    pub fn recognize_marcando(&self, png: &[u8]) -> Option<Vec<Option<u32>>> {
        let img = crate::render::decode_png_luma(png)?;
        let n = (img.width() as usize) / CELL;
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let ox = i * CELL + PAD;
            let mut bm = [[false; SIZE]; SIZE];
            for (y, row) in bm.iter_mut().enumerate() {
                for (x, cell) in row.iter_mut().enumerate() {
                    let px = img.get_pixel((ox + x) as u32, (PAD + y) as u32).0[0];
                    *cell = px < 128;
                }
            }
            let fp = fingerprint(&bm);
            let (idx, margen) = self.mejor_con_margen(&fp)?;
            out.push(if margen < self.margen { None } else { Some(idx) });
        }
        Some(out)
    }

    /// Reconoce los índices desde un PNG de glifos (vecino más cercano).
    pub fn recognize(&self, png: &[u8]) -> Option<Vec<u32>> {
        // Decodifica con límites de tamaño (anti bomba de descompresión), igual
        // que el canal PNG directo.
        let img = crate::render::decode_png_luma(png)?;
        let n = (img.width() as usize) / CELL;
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let ox = i * CELL + PAD;
            let mut bm = [[false; SIZE]; SIZE];
            for (y, row) in bm.iter_mut().enumerate() {
                for (x, cell) in row.iter_mut().enumerate() {
                    let px = img.get_pixel((ox + x) as u32, (PAD + y) as u32).0[0];
                    *cell = px < 128;
                }
            }
            let fp = fingerprint(&bm);
            let (idx, margen) = self.mejor_con_margen(&fp)?;

            // RECHAZO. Sin esto, `min_by_key` devolvía SIEMPRE el glifo más
            // cercano, estuviera a distancia 1 o a 200: una foto de una pared
            // producía una secuencia de índices perfectamente formada. Un canal
            // que nunca dice «no sé» no distingue un dato de un ruido, y eso es
            // lo que convierte una lectura fallida en un dato falso.
            //
            // Más allá del radio, la lectura no es inequívoca: podría estar más
            // cerca de otro símbolo del alfabeto. Ahí se abandona.
            if margen < self.margen {
                return None;
            }
            out.push(idx);
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn font_has_full_alphabet_and_is_separable() {
        let font = standard();
        assert_eq!(font.base(), ALPHABET as u32);
        // Glifos distintos: distancia mínima > 0.
        assert!(glyphopt::min_pairwise_distance(&font.fps) > 0);
    }

    #[test]
    fn render_recognize_round_trips_indices() {
        let font = standard();
        let indices: Vec<u32> = (0..font.base()).chain([0, 5, 93, 42]).collect();
        let png = font.render(&indices);
        assert_eq!(font.recognize(&png).unwrap(), indices);
    }
}
