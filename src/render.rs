//! Renderer visual: convierte bytes en una imagen PNG y de vuelta (sin pérdida).
//!
//! Es un canal de representación alternativo al diccionario textual: el dato
//! cifrado se "pinta" como píxeles en escala de grises (1 byte = 1 píxel). PNG
//! es lossless, así que el round-trip es exacto. Útil para canales visuales
//! (imprimir/fotografiar en versiones futuras con corrección de errores).

use std::io::Cursor;

use image::{GrayImage, ImageFormat, Luma};

/// Prefijo de longitud (u32 little-endian) al inicio del payload.
const LEN_PREFIX: usize = 4;

/// Convierte `data` en un PNG en escala de grises (imagen cuadrada).
pub fn bytes_to_png(data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(LEN_PREFIX + data.len());
    payload.extend_from_slice(&(data.len() as u32).to_le_bytes());
    payload.extend_from_slice(data);

    // Dimensiones lo más cuadradas posible.
    let total = payload.len().max(1);
    let width = (total as f64).sqrt().ceil() as u32;
    let width = width.max(1);
    let height = (total as u32).div_ceil(width);

    let mut img = GrayImage::new(width, height);
    let mut bytes = payload.iter();
    for y in 0..height {
        for x in 0..width {
            let v = bytes.next().copied().unwrap_or(0);
            img.put_pixel(x, y, Luma([v]));
        }
    }

    let mut out = Vec::new();
    img.write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
        .expect("codificación PNG");
    out
}

/// Recupera los bytes desde un PNG generado por [`bytes_to_png`].
pub fn png_to_bytes(png: &[u8]) -> Option<Vec<u8>> {
    let img = image::load_from_memory_with_format(png, ImageFormat::Png)
        .ok()?
        .to_luma8();
    let payload: Vec<u8> = img.pixels().map(|p| p.0[0]).collect();

    if payload.len() < LEN_PREFIX {
        return None;
    }
    let len = u32::from_le_bytes(payload[0..LEN_PREFIX].try_into().ok()?) as usize;
    let end = LEN_PREFIX.checked_add(len)?;
    if end > payload.len() {
        return None;
    }
    Some(payload[LEN_PREFIX..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_bytes_through_png() {
        let data = b"datos arbitrarios para pintar como imagen";
        let png = bytes_to_png(data);
        assert_eq!(png_to_bytes(&png).unwrap(), data);
    }

    #[test]
    fn round_trips_empty() {
        let png = bytes_to_png(b"");
        assert_eq!(png_to_bytes(&png).unwrap(), b"");
    }

    #[test]
    fn output_is_a_valid_png() {
        let png = bytes_to_png(b"hola");
        // Firma PNG.
        assert_eq!(&png[0..8], &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
    }

    #[test]
    fn rejects_garbage() {
        assert!(png_to_bytes(b"no soy un png").is_none());
    }
}
