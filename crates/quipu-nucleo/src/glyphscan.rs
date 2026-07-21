// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Registro geométrico de una tira de glifos fotografiada o escaneada.
//!
//! # Por qué existe
//!
//! `glyphfont::recognize` lee los píxeles en posiciones fijas (`i*CELL + PAD`).
//! Medido con `tests/glifos_degradados.rs`, eso significa que:
//!
//! ```text
//! imagen limpia .............. 100 %
//! desplazada 1 píxel ......... 17 %
//! rotada medio grado ......... 14 %
//! ruido de sensor ±90 ........ 100 %
//! ```
//!
//! El clasificador —vecino más cercano en Hamming— aguanta el ruido de sobra.
//! Lo que no aguanta es que la rejilla se mueva: en cuanto lo hace, muestrea el
//! sitio equivocado y el error ocurre ANTES de clasificar. Por eso este módulo
//! no toca el clasificador: recupera la rejilla y le entrega celdas alineadas.
//!
//! # Por qué NO se inventa un símbolo tipo QR
//!
//! Sería lo obvio: añadir esquinas de localización al render. Se descartó por
//! tres razones, en este orden:
//!
//! 1. **Rompería lo ya emitido.** Una tira impresa el año pasado tiene que
//!    seguir leyéndose. Un formato nuevo la deja fuera para siempre, y el papel
//!    es justamente el soporte que se guarda diez años.
//! 2. **La información ya está en la imagen.** La tira es una rejilla de celdas
//!    cuadradas del mismo tamaño: eso fija el periodo, y el periodo fija la
//!    escala. Añadir marcas sería declarar un dato que se puede deducir.
//! 3. **Reinventar QR mal es peor que no hacerlo.** De un QR solo faltaría la
//!    parte geométrica; la corrección de errores ya la da `ecc` con
//!    Reed-Solomon, y lo criptográfico no viene del dibujo. Un símbolo propio a
//!    medio hacer tendría que competir con treinta años de decodificadores
//!    ajenos, y perdería.
//!
//! Si algún día hace falta leer una foto tomada de lado, con perspectiva real,
//! entonces sí harán falta marcas —cuatro puntos para una homografía— y será
//! un formato NUEVO conviviendo con este, no un reemplazo.
//!
//! # Qué hace y qué no
//!
//! Corrige desplazamiento, escala y rotación pequeña. **No** corrige
//! perspectiva: una foto en ángulo sigue fuera de alcance, y está declarado en
//! `SPEC.md`. Tampoco es un canal de seguridad: sigue siendo representación, y
//! el árbitro final es el tag AEAD. El peor fallo posible es «no descifra».

use image::GrayImage;

/// Ángulo máximo de inclinación que se busca, en grados. Más allá de esto no
/// es una hoja mal puesta: es una foto en ángulo, y eso pide perspectiva.
const INCLINACION_MAX: f32 = 3.0;
const INCLINACION_PASO: f32 = 0.25;

/// Proporción `CELL / SIZE` del render: 18/16. Es la constante que permite
/// deducir el periodo de la rejilla a partir de la altura de la tinta, y por
/// eso mismo hace innecesarias las marcas de registro.
const CELDA_SOBRE_TINTA: f32 = 18.0 / 16.0;

/// Umbral de Otsu: el corte que minimiza la varianza dentro de cada clase.
///
/// Sustituye al 128 fijo. La medición decía que el umbral fijo aguantaba bien,
/// así que esto no era urgente; se hace igual porque cuesta veinte líneas y
/// quita una constante que solo es correcta si nadie toca el brillo.
pub fn umbral_otsu(img: &GrayImage) -> u8 {
    let mut hist = [0u32; 256];
    for p in img.pixels() {
        hist[p.0[0] as usize] += 1;
    }
    let total: u32 = img.width() * img.height();
    let suma_total: u64 = hist.iter().enumerate().map(|(i, &n)| i as u64 * n as u64).sum();

    let (mut suma_fondo, mut peso_fondo) = (0u64, 0u32);
    let mut mejor_var = -1.0f64;
    // Se guarda el RANGO del máximo, no el primero que lo alcanza. En una
    // imagen de blanco y negro puros —que es justo la que produce el render—
    // todos los cortes entre 0 y 254 dan la misma varianza: quedarse con el
    // primero devuelve 0, que solo considera tinta el negro absoluto y deja el
    // umbral pegado al borde. El centro de la meseta es el corte con más
    // margen a cada lado, que es lo que se quiere cuando llega una foto.
    let (mut desde, mut hasta) = (128usize, 128usize);
    for (t, &n) in hist.iter().enumerate() {
        peso_fondo += n;
        if peso_fondo == 0 {
            continue;
        }
        let peso_frente = total - peso_fondo;
        if peso_frente == 0 {
            break;
        }
        suma_fondo += t as u64 * n as u64;
        let media_fondo = suma_fondo as f64 / peso_fondo as f64;
        let media_frente = (suma_total - suma_fondo) as f64 / peso_frente as f64;
        let var = peso_fondo as f64 * peso_frente as f64
            * (media_fondo - media_frente).powi(2);
        if var > mejor_var {
            mejor_var = var;
            desde = t;
            hasta = t;
        } else if var == mejor_var {
            hasta = t;
        }
    }
    ((desde + hasta) / 2) as u8
}

/// Máscara de tinta: `true` donde hay trazo.
fn binarizar(img: &GrayImage, umbral: u8) -> Vec<Vec<bool>> {
    (0..img.height())
        .map(|y| (0..img.width()).map(|x| img.get_pixel(x, y).0[0] <= umbral).collect())
        .collect()
}


/// Cuántas columnas quedan COMPLETAMENTE sin tinta dentro de la banda de la
/// tira. Es el criterio de enderezado.
///
/// El clásico —varianza del perfil de FILAS— es para una página con muchos
/// renglones. Aquí la tira tiene dieciocho píxeles de alto: hay tan pocas filas
/// que la varianza no distingue nada, y de hecho girar media hoja de grado una
/// tira YA RECTA subía la varianza por puro alias del vecino más cercano. El
/// corrector introducía la inclinación que debía quitar.
///
/// Lo que de verdad importa es otra cosa, y es medible: los huecos entre glifos
/// solo son columnas enteras vacías cuando la tira está recta. En cuanto se
/// tuerce, el trazo de un glifo invade la columna del hueco vecino y el hueco
/// desaparece. Se maximiza justo la propiedad de la que depende la etapa
/// siguiente, en vez de una que se le parece.
fn columnas_vacias(mask: &[Vec<bool>]) -> u32 {
    let Some((_, y0, _, y1)) = caja_de_tinta(mask) else {
        return 0;
    };
    let ancho = mask.first().map_or(0, |f| f.len());
    (0..ancho)
        .filter(|&x| !(y0..=y1).any(|y| mask[y][x]))
        .count() as u32
}

fn rotar(img: &GrayImage, grados: f32) -> GrayImage {
    if grados == 0.0 {
        return img.clone();
    }
    let (w, h) = img.dimensions();
    let (cx, cy) = (w as f32 / 2.0, h as f32 / 2.0);
    let (s, c) = grados.to_radians().sin_cos();
    let mut out = GrayImage::from_pixel(w, h, image::Luma([255]));
    for y in 0..h {
        for x in 0..w {
            let (dx, dy) = (x as f32 - cx, y as f32 - cy);
            let sx = c * dx + s * dy + cx;
            let sy = -s * dx + c * dy + cy;
            if sx >= 0.0 && sy >= 0.0 {
                let (sx, sy) = (sx.round() as u32, sy.round() as u32);
                if sx < w && sy < h {
                    out.put_pixel(x, y, *img.get_pixel(sx, sy));
                }
            }
        }
    }
    out
}

/// El ángulo que deja la tira más recta.
pub fn inclinacion(img: &GrayImage, umbral: u8) -> f32 {
    // Para cada ángulo: cuánta tinta sobrevive y cuántas columnas quedan
    // limpias. Hacen falta las DOS.
    let mut candidatos: Vec<(f32, u32, u32)> = Vec::new();
    let mut a = -INCLINACION_MAX;
    while a <= INCLINACION_MAX + 1e-6 {
        let mask = binarizar(&rotar(img, a), umbral);
        let tinta = mask.iter().flatten().filter(|&&v| v).count() as u32;
        candidatos.push((a, tinta, columnas_vacias(&mask)));
        a += INCLINACION_PASO;
    }

    // Maximizar columnas vacías A SECAS es una función objetivo degenerada:
    // girar mucho una tira larga empuja la tinta fuera de la banda, y una tira
    // medio borrada tiene muchísimas columnas limpias. Con eso, el estimador
    // elegía siempre el extremo del rango —3 grados— y arruinaba la lectura.
    //
    // Un giro es una transformación RÍGIDA: el ángulo correcto conserva la
    // tinta. Se descartan primero los ángulos que la pierden, y solo entre los
    // que la conservan se busca la rejilla más limpia.
    let tinta_max = candidatos.iter().map(|&(_, t, _)| t).max().unwrap_or(0);
    let umbral_tinta = (tinta_max as f64 * 0.999) as u32;
    let vivos: Vec<_> = candidatos.iter().filter(|&&(_, t, _)| t >= umbral_tinta).collect();
    let maximo = vivos.iter().map(|&&(_, _, v)| v).max().unwrap_or(0);
    // Con varios ángulos empatados —lo normal en una tira ya recta— se elige el
    // más cercano a cero. Sin este desempate, el orden de recorrido decidía, y
    // una tira perfecta salía girada medio grado.
    let angulo = vivos
        .iter()
        .filter(|&&&(_, _, v)| v == maximo)
        .min_by(|x, y| x.0.abs().partial_cmp(&y.0.abs()).unwrap())
        .map_or(0.0, |&&(a, _, _)| a);
    // Se devuelve el ángulo que hay que aplicar para CORREGIR, no el medido.
    -angulo
}

/// Caja que encierra toda la tinta: (x0, y0, x1, y1), extremos incluidos.
fn caja_de_tinta(mask: &[Vec<bool>]) -> Option<(usize, usize, usize, usize)> {
    let (mut x0, mut y0) = (usize::MAX, usize::MAX);
    let (mut x1, mut y1) = (0usize, 0usize);
    for (y, fila) in mask.iter().enumerate() {
        for (x, &v) in fila.iter().enumerate() {
            if v {
                x0 = x0.min(x);
                y0 = y0.min(y);
                x1 = x1.max(x);
                y1 = y1.max(y);
            }
        }
    }
    (x0 != usize::MAX).then_some((x0, y0, x1, y1))
}

/// La rejilla recuperada de una tira.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rejilla {
    /// Grados que hubo que girar para enderezarla.
    pub inclinacion: f32,
    /// Lado de la celda en píxeles de la imagen recibida.
    pub celda: f32,
    /// Coordenada del borde izquierdo de la primera celda.
    pub x0: f32,
    /// Borde superior de la fila de celdas.
    pub y0: f32,
    /// Cuántas celdas se detectaron.
    pub celdas: usize,
}

/// Recupera la rejilla de una imagen ya enderezada.
///
/// # El intento que falló, y por qué se deja escrito
///
/// La primera versión DEDUCÍA el periodo: si las celdas son cuadradas y la
/// proporción `CELL/SIZE` es fija, la altura de la tinta da la escala. Es
/// elegante y es falso: **la tinta no llena la celda**. Cada glifo ocupa lo que
/// ocupa —unos son dos trazos, otros llevan círculo—, así que la altura de la
/// tinta depende de QUÉ glifos hay, y el periodo salía distinto en cada tira.
/// La prueba lo cazó a la primera: contó seis celdas donde había cinco.
///
/// Lo que sí es invariante son los HUECOS. El render deja `PAD` en blanco a
/// cada lado, así que entre dos glifos hay una franja de columnas sin tinta,
/// y esas franjas caen exactamente en los bordes de celda, se dibuje lo que se
/// dibuje. El periodo se mide como la separación entre huecos.
fn rejilla_de(mask: &[Vec<bool>], inclinacion: f32) -> Option<Rejilla> {
    let (cx0, cy0, cx1, cy1) = caja_de_tinta(mask)?;

    // Columnas sin tinta dentro del alto de la tira.
    let ancho = mask.first()?.len();
    let vacia: Vec<bool> = (0..ancho)
        .map(|x| !(cy0..=cy1).any(|y| mask[y][x]))
        .collect();

    // Centro de cada franja vacía que quede ENTRE tinta: son los bordes de
    // celda. Las de los extremos no cuentan, que son el margen de la hoja.
    let mut bordes = Vec::new();
    let mut ini: Option<usize> = None;
    for (x, &esta_vacia) in vacia.iter().enumerate().take(cx1 + 1).skip(cx0) {
        match (esta_vacia, ini) {
            (true, None) => ini = Some(x),
            (false, Some(i)) => {
                // El hueco ocupa columnas enteras y su ancho es par (`2*PAD`),
                // así que su centro cae medio píxel ANTES del borde real de la
                // celda: un hueco en las columnas 17 y 18 tiene centro 17,5 y
                // el borde está en 18. Sin este medio píxel, todo el
                // remuestreo posterior sale corrido una columna.
                bordes.push((i + x - 1) as f32 / 2.0 + 0.5);
                ini = None;
            }
            _ => {}
        }
    }
    if bordes.is_empty() {
        // Un solo glifo, o la tinta se comió todos los huecos (sangrado
        // fuerte). Con un solo glifo el periodo es el ancho de la caja.
        let celda = (cx1 - cx0 + 1) as f32 * CELDA_SOBRE_TINTA;
        return (celda >= 4.0).then_some(Rejilla {
            inclinacion,
            celda,
            x0: cx0 as f32 - (celda - (cx1 - cx0 + 1) as f32) / 2.0,
            y0: cy0 as f32 - (celda - (cy1 - cy0 + 1) as f32) / 2.0,
            celdas: 1,
        });
    }

    // Periodo: mediana de las separaciones. Mediana y no media porque un glifo
    // con mucho blanco interior puede partir su propia celda en dos huecos, y
    // eso mete una separación corta que la media arrastraría.
    let mut saltos: Vec<f32> = bordes.windows(2).map(|p| p[1] - p[0]).collect();
    if saltos.is_empty() {
        saltos.push((cx1 - cx0 + 1) as f32 / 2.0);
    }
    saltos.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let celda = saltos[saltos.len() / 2];
    if celda < 4.0 {
        return None;
    }

    // El borde izquierdo de la primera celda: se retrocede desde el primer
    // borde detectado en múltiplos enteros del periodo.
    let pasos = ((bordes[0] - cx0 as f32) / celda).round().max(0.0);
    let x0 = bordes[0] - pasos * celda - celda;
    let x0 = if x0 < cx0 as f32 - celda { bordes[0] - pasos * celda } else { x0 };

    let celdas = (((cx1 as f32 - x0) / celda).ceil()).max(1.0) as usize;
    let margen_v = (celda - (cy1 - cy0 + 1) as f32) / 2.0;
    Some(Rejilla {
        inclinacion,
        celda,
        x0,
        y0: cy0 as f32 - margen_v.max(0.0),
        celdas,
    })
}

/// Normaliza una tira degradada: la endereza y devuelve una imagen con la
/// geometría EXACTA que espera `glyphfont::recognize`.
///
/// Se devuelve una imagen y no una lista de huellas a propósito: así el
/// clasificador que ya existe —y que la medición mostró que funciona bien— se
/// queda intacto, y este módulo solo responde de la geometría.
pub fn normalizar(img: &GrayImage, lado: usize, borde: usize) -> Option<(GrayImage, Rejilla)> {
    let umbral = umbral_otsu(img);
    let angulo = inclinacion(img, umbral);
    let recta = rotar(img, angulo);
    let mask = binarizar(&recta, umbral);
    let rejilla = rejilla_de(&mask, angulo)?;

    let paso = lado + 2 * borde;
    let mut out = GrayImage::from_pixel((rejilla.celdas * paso) as u32, paso as u32,
                                        image::Luma([255]));
    for i in 0..rejilla.celdas {
        for y in 0..lado {
            for x in 0..lado {
                // CENTRO del píxel destino llevado a coordenadas de origen, y
                // luego `floor` para dar con el píxel que lo contiene.
                //
                // Con `round` sobre la esquina se muestreaba la columna de al
                // lado —medio píxel de sesgo— y el acierto caía a cero incluso
                // sobre la imagen limpia. Es el error clásico de remuestreo:
                // confundir la posición de la esquina con la del centro.
                let escala = rejilla.celda / paso as f32;
                let fx = rejilla.x0 + i as f32 * rejilla.celda
                    + ((borde + x) as f32 + 0.5) * escala;
                let fy = rejilla.y0 + ((borde + y) as f32 + 0.5) * escala;
                if fx < 0.0 || fy < 0.0 {
                    continue;
                }
                let (sx, sy) = (fx.floor() as u32, fy.floor() as u32);
                if sx >= recta.width() || sy >= recta.height() {
                    continue;
                }
                // Se reescribe con el umbral ya calculado: el destino es la
                // imagen ideal, en blanco y negro puros.
                let v = if recta.get_pixel(sx, sy).0[0] <= umbral { 0 } else { 255 };
                out.put_pixel((i * paso + borde + x) as u32, (borde + y) as u32,
                              image::Luma([v]));
            }
        }
    }
    Some((out, rejilla))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tira_limpia() -> GrayImage {
        let font = crate::glyphfont::standard();
        let png = font.render(&[0, 1, 2, 3, 4]);
        image::load_from_memory(&png).unwrap().to_luma8()
    }

    #[test]
    fn otsu_separa_tinta_de_papel() {
        // La tira es blanco puro y negro puro: el corte cae en medio.
        let u = umbral_otsu(&tira_limpia());
        assert!((1..255).contains(&u), "umbral degenerado: {u}");
    }

    #[test]
    fn una_tira_recta_no_se_gira() {
        let img = tira_limpia();
        let u = umbral_otsu(&img);
        assert_eq!(inclinacion(&img, u), 0.0);
    }

    #[test]
    fn la_rejilla_cuenta_bien_las_celdas() {
        let (_, r) = normalizar(&tira_limpia(), 16, 1).unwrap();
        assert_eq!(r.celdas, 5);
        // El render usa CELL = 18; el periodo deducido tiene que rondarlo.
        assert!((r.celda - 18.0).abs() < 2.0, "celda deducida: {}", r.celda);
    }

    #[test]
    fn una_imagen_en_blanco_no_inventa_rejilla() {
        let blanca = GrayImage::from_pixel(90, 18, image::Luma([255]));
        assert!(normalizar(&blanca, 16, 1).is_none());
    }
}
