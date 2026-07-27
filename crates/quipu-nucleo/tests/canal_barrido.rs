//! Barrido del canal: 100+ operaciones por nivel de ruido.
//!
//! El umbral de rechazo se probó contra ruido puro y contra una hoja en blanco
//! —los dos extremos—, y eso solo demuestra que discrimina lo obvio. La
//! pregunta operativa es otra: **¿a partir de cuánto ruido empieza a rechazar
//! lecturas BUENAS?** Si el radio es demasiado estrecho, la restricción hace
//! el canal menos usable justo en el caso para el que existe.
//!
//! Tres desenlaces, y el tercero es el que importa:
//!
//!   CORRECTO  se lee y acierta
//!   RECHAZO   dice «no sé»           <- honesto: el usuario reintenta
//!   FALSO     lee y se equivoca      <- el peligroso: dato falso que pasa
//!
//! Un canal puede empeorar de dos formas opuestas y hay que vigilar las dos.

use image::{GrayImage, ImageFormat, Luma};
use std::io::Cursor;

use quipu_nucleo::glyphfont;

const MUESTRAS: usize = 120; // por nivel de ruido

/// Xorshift determinista: mismas cifras en cada corrida.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

fn a_png(img: &GrayImage) -> Vec<u8> {
    let mut out = Vec::new();
    img.write_to(&mut Cursor::new(&mut out), ImageFormat::Png).unwrap();
    out
}

/// Voltea `flips` píxeles al azar dentro de cada celda de glifo.
fn ruido_por_celda(png: &[u8], flips: u32, rng: &mut Rng) -> Vec<u8> {
    const CELL: u32 = 18;
    let mut img = image::load_from_memory(png).unwrap().to_luma8();
    let celdas = img.width() / CELL;
    for c in 0..celdas {
        for _ in 0..flips {
            // Solo dentro del glifo (16x16), no en el borde de separación.
            let x = c * CELL + 1 + rng.below(16) as u32;
            let y = 1 + rng.below(16) as u32;
            let v = img.get_pixel(x, y).0[0];
            img.put_pixel(x, y, Luma([if v < 128 { 255 } else { 0 }]));
        }
    }
    a_png(&img)
}

struct Cuenta {
    correcto: usize,
    rechazo: usize,
    falso: usize,
}

fn barrer(flips: u32, semilla: u64) -> Cuenta {
    let font = glyphfont::standard();
    let mut rng = Rng(semilla);
    let mut c = Cuenta { correcto: 0, rechazo: 0, falso: 0 };

    for _ in 0..MUESTRAS {
        let esperado: Vec<u32> =
            (0..24).map(|_| rng.below(font.base() as u64) as u32).collect();
        let png = font.render(&esperado);
        let sucio = ruido_por_celda(&png, flips, &mut rng);
        match font.recognize(&sucio) {
            None => c.rechazo += 1,
            Some(v) if v == esperado => c.correcto += 1,
            Some(_) => c.falso += 1,
        }
    }
    c
}

#[test]
fn barrido_de_ruido_120_muestras_por_nivel() {
    println!("\n  flips  correcto  rechazo  FALSO   (de {MUESTRAS} por nivel)");
    let mut ultimo_perfecto = 0;
    let mut primer_falso = None;

    for flips in [0, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24, 32] {
        let c = barrer(flips, 0x9E37_79B9_7F4A_7C15 ^ flips as u64);
        println!(
            "  {flips:>5}  {:>8}  {:>7}  {:>5}",
            c.correcto, c.rechazo, c.falso
        );
        if c.correcto == MUESTRAS {
            ultimo_perfecto = flips;
        }
        if c.falso > 0 && primer_falso.is_none() {
            primer_falso = Some((flips, c.falso));
        }
    }

    // 1. El canal tiene que aguantar ruido REAL, no solo el caso limpio. Con
    //    menos de esto, el umbral estaría estorbando más de lo que protege.
    assert!(
        ultimo_perfecto >= 4,
        "solo aguanta {ultimo_perfecto} píxeles volteados por glifo sin un \
         fallo: el radio es demasiado estrecho para un escaneo real",
    );

    // 2. Y cuando falla, tiene que fallar DICIENDO que falla. Un falso —leer y
    //    equivocarse en silencio— es el desenlace que este umbral existe para
    //    evitar; si aparecen con poco ruido, no está cumpliendo su trabajo.
    if let Some((flips, n)) = primer_falso {
        assert!(
            flips >= 12,
            "con solo {flips} píxeles volteados ya devuelve {n} lecturas \
             falsas de {MUESTRAS}: prefiere equivocarse a callar",
        );
    }
}
