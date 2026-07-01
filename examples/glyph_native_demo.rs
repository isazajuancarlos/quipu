//! Demo del modo de glifos nativo (Rust): cifra y pinta con el font propio.
use quipu::api::{decode_from_glyph_image, encode_to_glyph_image, Options};
use quipu::kdf::KdfParams;

fn main() {
    let opts = Options {
        pepper: b"",
        kdf_params: KdfParams { mem_kib: 512, iterations: 1, parallelism: 1 },
        codebook_id: 0,
    };
    let secret = b"Glifos nativos generados en Rust por Quipu.";
    let png = encode_to_glyph_image(secret, "clave", &opts);
    std::fs::write("/mnt/data/decod/glifos_nativos.png", &png).unwrap();
    let back = decode_from_glyph_image(&png, "clave", b"").unwrap();
    assert_eq!(back, secret);
    println!("Glifos nativos: {} bytes PNG, round-trip OK", png.len());
}
