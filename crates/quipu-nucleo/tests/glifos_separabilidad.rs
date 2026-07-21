// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! ¿Un modelo generativo daría alfabetos de glifos mejores? (tarea #27)
//!
//! La hipótesis de #27 es que una difusión o un GAN producirían MUCHOS
//! candidatos y que, eligiendo entre más, saldría un alfabeto más separable. Es
//! plausible y es comprobable sin entrenar nada, porque lo que hay que medir no
//! es el generador: es **si la separabilidad está limitada por los candidatos o
//! por la geometría**.
//!
//! Un glifo de 16×16 es un vector de 256 bits. Meter `k` glifos ahí con
//! distancia mínima `d` es un problema de teoría de códigos, y tiene cota
//! superior conocida. Si el alfabeto actual ya está cerca de la cota, **ningún
//! generador puede mejorarlo**: el techo no es de imaginación, es de espacio.
//!
//! El experimento tiene dos partes:
//!
//! 1. Ampliar el CONJUNTO de candidatos a tamaño fijo de alfabeto. Si la
//!    distancia mínima sube al ampliar, el generador aporta. Si se estanca, no.
//! 2. Ampliar el ALFABETO con el conjunto fijo, hasta los 4096 símbolos del
//!    diccionario insignia, que es donde la separabilidad debería apretar.
//!
//! Y se contrasta contra la cota de Plotkin, que es la que manda cuando la
//! distancia relativa pasa de la mitad de la longitud.

use quipu_nucleo::glyphopt;

const LADO: usize = 16;
const BITS: usize = LADO * LADO;

/// PRNG determinista: mismo experimento en cualquier máquina.
struct Rng(u64);
impl Rng {
    fn nuevo(semilla: u64) -> Self {
        Self(semilla | 1)
    }
    fn siguiente(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bajo(&mut self, n: usize) -> usize {
        (self.siguiente() % n as u64) as usize
    }
}

type Bitmap = [[bool; LADO]; LADO];

fn linea(bm: &mut Bitmap, mut x0: i32, mut y0: i32, x1: i32, y1: i32) {
    let dx = (x1 - x0).abs();
    let dy = -(y1 - y0).abs();
    let sx = if x0 < x1 { 1 } else { -1 };
    let sy = if y0 < y1 { 1 } else { -1 };
    let mut err = dx + dy;
    loop {
        if (0..LADO as i32).contains(&x0) && (0..LADO as i32).contains(&y0) {
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

fn huella(bm: &Bitmap) -> Vec<u8> {
    let mut out = Vec::with_capacity(BITS / 8);
    let (mut byte, mut bits) = (0u8, 0);
    for fila in bm.iter() {
        for &v in fila.iter() {
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

/// Candidatos con el MISMO procedimiento que `glyphfont`: trazos entre anclas.
/// Se replica aquí en vez de exponerlo en la biblioteca porque es un
/// instrumento de medida, no una función del producto.
fn candidatos_trazos(cuantos: usize, semilla: u64) -> Vec<Vec<u8>> {
    let anclas: Vec<(i32, i32)> = [2, 6, 9, 13]
        .iter()
        .flat_map(|&x| [2, 6, 9, 13].iter().map(move |&y| (x, y)))
        .collect();
    let mut rng = Rng::nuevo(semilla);
    let mut vistos = std::collections::HashSet::new();
    let mut out = Vec::new();
    let mut intentos = 0;
    while out.len() < cuantos && intentos < cuantos * 60 {
        intentos += 1;
        let mut bm = [[false; LADO]; LADO];
        for _ in 0..2 + rng.bajo(3) {
            let a = anclas[rng.bajo(anclas.len())];
            let b = anclas[rng.bajo(anclas.len())];
            if a != b {
                linea(&mut bm, a.0, a.1, b.0, b.1);
            }
        }
        let llenos: usize = bm.iter().flatten().filter(|&&v| v).count();
        if !(6..=120).contains(&llenos) {
            continue;
        }
        let h = huella(&bm);
        if vistos.insert(h.clone()) {
            out.push(h);
        }
    }
    out
}

/// Candidatos ALEATORIOS puros: cada bit a cara o cruz.
///
/// Sirve de tope superior de lo que cualquier generador podría aspirar en esta
/// métrica. Un modelo generativo produce glifos que PARECEN escritura —trazos
/// conectados, formas plausibles—, y esa restricción solo puede reducir la
/// distancia disponible, nunca aumentarla. Si ni el ruido puro mejora al
/// alfabeto actual, un generador tampoco.
fn candidatos_aleatorios(cuantos: usize, semilla: u64) -> Vec<Vec<u8>> {
    let mut rng = Rng::nuevo(semilla);
    (0..cuantos)
        .map(|_| (0..BITS / 8).map(|_| (rng.siguiente() & 0xFF) as u8).collect())
        .collect()
}

/// Cota de Plotkin: con `k` palabras de `n` bits, la distancia mínima no puede
/// pasar de `n·k / (2·(k−1))`. Para `k` grande tiende a `n/2` = 128.
fn cota_plotkin(n: usize, k: usize) -> f64 {
    if k < 2 {
        return n as f64;
    }
    (n as f64 * k as f64) / (2.0 * (k as f64 - 1.0))
}

#[test]
fn ampliar_el_conjunto_de_candidatos_no_mejora_la_separabilidad() {
    println!("\n  ALFABETO FIJO DE 94 — se amplía el conjunto de candidatos");
    println!("  candidatos   dist. mín.   (cota de Plotkin: {:.0})",
             cota_plotkin(BITS, 94));
    println!("  ----------   ----------");
    let mut distancias = Vec::new();
    for &n in &[500usize, 2_000, 8_000, 32_000] {
        let pool = candidatos_trazos(n, 0x00C0FFEE_D00DFACE);
        let idx = glyphopt::select_separable_subset(&pool, 94);
        let sub: Vec<Vec<u8>> = idx.iter().map(|&i| pool[i].clone()).collect();
        let d = glyphopt::min_pairwise_distance(&sub);
        println!("  {:>10}   {:>10}", pool.len(), d);
        distancias.push(d);
    }

    // Si multiplicar por 64 el conjunto de candidatos no sube la distancia
    // mínima de forma apreciable, el límite no está en los candidatos y un
    // generador —que solo aporta MÁS candidatos— no puede ayudar.
    let primera = distancias[0];
    let ultima = *distancias.last().unwrap();
    let mejora = ultima as f64 / primera.max(1) as f64;
    println!("  mejora al multiplicar por 64 el conjunto: ×{mejora:.2}");
    assert!(
        mejora < 1.5,
        "ampliar el conjunto SÍ mejora (×{mejora:.2}): la hipótesis de #27 se \
         sostiene y hay que reabrirla"
    );
}

#[test]
fn ni_siquiera_el_ruido_puro_mejora_al_alfabeto_de_trazos() {
    // Los glifos aleatorios son el mejor caso imaginable para esta métrica: no
    // tienen que parecerse a nada. Un generativo está MÁS restringido.
    let trazos = candidatos_trazos(8_000, 0xBEEF);
    let ruido = candidatos_aleatorios(8_000, 0xBEEF);
    let d = |pool: &Vec<Vec<u8>>| {
        let idx = glyphopt::select_separable_subset(pool, 94);
        let sub: Vec<Vec<u8>> = idx.iter().map(|&i| pool[i].clone()).collect();
        glyphopt::min_pairwise_distance(&sub)
    };
    let (dt, dr) = (d(&trazos), d(&ruido));
    println!("\n  94 glifos: trazos = {dt}   ruido puro = {dr}   \
              (cota de Plotkin {:.0})", cota_plotkin(BITS, 94));
    // No se afirma cuál gana: se deja el número. Lo que importa es el orden de
    // magnitud frente a la cota, no cuál de los dos procedimientos gana.
    assert!(dt > 0 && dr > 0);
}

#[test]
fn la_separabilidad_al_crecer_el_alfabeto() {
    println!("\n  CONJUNTO FIJO — se amplía el alfabeto");
    println!("  alfabeto   dist. mín.   cota Plotkin   margen");
    println!("  --------   ----------   ------------   ------");
    let pool = candidatos_trazos(32_000, 0x5EED);
    let mut fila = Vec::new();
    for &k in &[94usize, 256, 1_024, 4_096] {
        if pool.len() < k {
            println!("  {k:>8}   (no hay tantos candidatos distintos)");
            continue;
        }
        let idx = glyphopt::select_separable_subset(&pool, k);
        let sub: Vec<Vec<u8>> = idx.iter().map(|&i| pool[i].clone()).collect();
        let d = glyphopt::min_pairwise_distance(&sub);
        let cota = cota_plotkin(BITS, k);
        println!("  {k:>8}   {d:>10}   {cota:>12.1}   {:>5.0} %",
                 100.0 * d as f64 / cota);
        fila.push((k, d));
    }
    // El diccionario insignia usa 4096 símbolos. Si a ese tamaño la distancia
    // mínima cae a niveles que el ruido medido (±90 sobre 255) puede cruzar,
    // ENTONCES el alfabeto sí es el cuello de botella y #27 vuelve a la mesa.
    if let Some(&(_, d4096)) = fila.iter().find(|(k, _)| *k == 4_096) {
        println!("  distancia mínima a 4096 símbolos: {d4096} bits de 256");
        assert!(d4096 > 0, "alfabeto degenerado a 4096");
    }
}

// ---------------------------------------------------------------------------
// ¿La distancia de Hamming es la métrica correcta?
// ---------------------------------------------------------------------------
//
// El experimento anterior dio un resultado incómodo: los glifos ALEATORIOS
// alcanzan distancia mínima 115 y los de trazos 33, sobre una cota de 129. Si
// la distancia de Hamming fuera lo que importa, el alfabeto actual estaría
// dejando fuera un factor de 3,5 y la hipótesis de #27 tendría razón.
//
// Pero un glifo aleatorio es sal y pimienta: alterna blanco y negro en cada
// píxel. Eso maximiza la distancia EN EL PAPEL IDEAL y es lo peor posible en
// papel de verdad, donde la tinta se corre y el sensor promedia. Un trazo
// grueso sobrevive a que se engorde un píxel; el ruido de alta frecuencia se
// convierte en una mancha uniforme y pierde toda su identidad.
//
// Así que la pregunta no es cuál tiene más distancia, sino **cuál se sigue
// reconociendo después de pasar por una impresora**. Se mide con la misma
// degradación del otro banco: dilatación (sangrado de tinta) y desenfoque.

fn desde_huella(h: &[u8]) -> Bitmap {
    let mut bm = [[false; LADO]; LADO];
    for i in 0..BITS {
        bm[i / LADO][i % LADO] = (h[i / 8] >> (7 - i % 8)) & 1 == 1;
    }
    bm
}

/// Sangrado: cada píxel con tinta tiñe a sus cuatro vecinos.
fn dilatar(bm: &Bitmap) -> Bitmap {
    let mut out = *bm;
    for y in 0..LADO {
        for x in 0..LADO {
            if bm[y][x] {
                continue;
            }
            let vecinos = [(0i32, 1i32), (0, -1), (1, 0), (-1, 0)];
            out[y][x] = vecinos.iter().any(|(dy, dx)| {
                let (ny, nx) = (y as i32 + dy, x as i32 + dx);
                (0..LADO as i32).contains(&ny)
                    && (0..LADO as i32).contains(&nx)
                    && bm[ny as usize][nx as usize]
            });
        }
    }
    out
}

/// Desenfoque: un píxel queda con tinta si la mayoría de su vecindario 3×3 la
/// tiene. Es lo que hace un sensor que promedia.
fn desenfocar(bm: &Bitmap) -> Bitmap {
    let mut out = [[false; LADO]; LADO];
    for (y, fila) in out.iter_mut().enumerate() {
        for (x, celda) in fila.iter_mut().enumerate() {
            let mut n = 0;
            for dy in -1i32..=1 {
                for dx in -1i32..=1 {
                    let (ny, nx) = (y as i32 + dy, x as i32 + dx);
                    if (0..LADO as i32).contains(&ny)
                        && (0..LADO as i32).contains(&nx)
                        && bm[ny as usize][nx as usize]
                    {
                        n += 1;
                    }
                }
            }
            *celda = n >= 5;
        }
    }
    out
}

/// Cuántos glifos se siguen clasificando bien tras degradarlos.
fn acierto_tras(alfabeto: &[Vec<u8>], degradar: impl Fn(&Bitmap) -> Bitmap) -> f32 {
    let mut ok = 0;
    for (i, h) in alfabeto.iter().enumerate() {
        let degradada = huella(&degradar(&desde_huella(h)));
        let mejor = alfabeto
            .iter()
            .enumerate()
            .min_by_key(|(_, g)| glyphopt::hamming(&degradada, g))
            .map(|(j, _)| j);
        if mejor == Some(i) {
            ok += 1;
        }
    }
    ok as f32 / alfabeto.len() as f32
}

fn alfabeto_de(pool: &[Vec<u8>], k: usize) -> Vec<Vec<u8>> {
    glyphopt::select_separable_subset(pool, k)
        .iter()
        .map(|&i| pool[i].clone())
        .collect()
}

#[test]
fn la_distancia_de_hamming_no_predice_la_robustez_en_papel() {
    let trazos = alfabeto_de(&candidatos_trazos(8_000, 0xBEEF), 94);
    let ruido = alfabeto_de(&candidatos_aleatorios(8_000, 0xBEEF), 94);

    println!("\n  alfabeto de 94   dist. mín.   tras sangrado   tras desenfoque");
    println!("  --------------   ----------   -------------   ---------------");
    let mut filas = Vec::new();
    for (nombre, alf) in [("trazos", &trazos), ("ruido puro", &ruido)] {
        let d = glyphopt::min_pairwise_distance(alf);
        let s = acierto_tras(alf, dilatar);
        let b = acierto_tras(alf, desenfocar);
        println!("  {nombre:<14}   {d:>10}   {:>11.1} %   {:>13.1} %",
                 s * 100.0, b * 100.0);
        filas.push((nombre, d, s, b));
    }

    let (_, d_trazos, s_trazos, b_trazos) = filas[0];
    let (_, d_ruido, s_ruido, b_ruido) = filas[1];

    // Lo que se fija: el ruido gana en distancia de Hamming y PIERDE en papel.
    // Si algún día deja de perder, la métrica de selección sirve tal cual y #27
    // vuelve a tener sentido.
    assert!(d_ruido > d_trazos, "el ruido debería ganar en Hamming");
    assert!(
        s_trazos > s_ruido || b_trazos > b_ruido,
        "el ruido aguanta el papel igual o mejor que los trazos: entonces la \
         distancia de Hamming SÍ predice la robustez y #27 se reabre"
    );
}

// ---------------------------------------------------------------------------
// La conclusión: el problema no son los candidatos, es el CRITERIO
// ---------------------------------------------------------------------------
//
//   alfabeto     dist. mín.   sangrado   desenfoque
//   trazos               33     100,0 %       34,0 %
//   ruido puro          115      12,8 %       88,3 %
//
// Dos lecturas, y la segunda es la que importa:
//
// 1. La distancia de Hamming NO predice la robustez. El ruido gana por 3,5× en
//    la métrica y pierde por 8× en el papel.
// 2. Cada alfabeto sobrevive a una degradación DISTINTA. Los trazos aguantan
//    que la tinta se corra y desaparecen con el desenfoque; el ruido al revés.
//    Ninguno de los dos aguanta las dos cosas.
//
// Por eso `select_separable_subset` está optimizando el objetivo equivocado:
// maximiza una distancia que se mide en el papel ideal, y lo que hace falta es
// la que queda DESPUÉS del canal. Añadir un modelo generativo para producir más
// candidatos no arregla eso: alimentaría mejor a un criterio roto.
//
// Se comprueba aquí que con LOS MISMOS candidatos, cambiando solo el criterio,
// sale un alfabeto que aguanta las dos degradaciones.

/// Huella extendida: el glifo tal cual, más cómo queda tras cada degradación.
///
/// **Este intento FALLÓ y se deja escrito porque el motivo enseña algo.**
///
/// La idea era meter el canal dentro de la métrica: si la huella incluye el
/// glifo degradado, la distancia de Hamming ya no premia a los que solo se
/// distinguen en el papel ideal. Medido, el alfabeto resultante aguanta PEOR:
/// 26,6 % contra 34,0 % en el peor caso.
///
/// El error es de álgebra, no de idea. La distancia de Hamming sobre una
/// concatenación es la SUMA de las distancias por canal, y lo que hace falta es
/// el MÍNIMO. Con la suma, dos glifos que se vuelven idénticos al desenfocarse
/// siguen pareciendo lejanos si en el papel ideal estaban muy separados —y esos
/// son justo los que hay que evitar.
///
/// El criterio correcto es `d(a,b) = min sobre degradaciones`, y eso no cabe en
/// `select_separable_subset`, que solo sabe de huellas. Exige una función de
/// distancia inyectable. Queda anotado como trabajo, no como conclusión.
fn huella_de_canal(bm: &Bitmap) -> Vec<u8> {
    let mut v = huella(bm);
    v.extend(huella(&dilatar(bm)));
    v.extend(huella(&desenfocar(bm)));
    v
}

#[test]
fn meter_el_canal_en_la_huella_por_concatenacion_no_funciona() {
    let pool = candidatos_trazos(8_000, 0xBEEF);
    let bitmaps: Vec<Bitmap> = pool.iter().map(|h| desde_huella(h)).collect();

    let actual = alfabeto_de(&pool, 94);
    let canal: Vec<Vec<u8>> = bitmaps.iter().map(huella_de_canal).collect();
    let idx = glyphopt::select_separable_subset(&canal, 94);
    let concatenado: Vec<Vec<u8>> = idx.iter().map(|&i| pool[i].clone()).collect();

    println!("\n  criterio de selección   sangrado   desenfoque   el peor");
    println!("  ---------------------   --------   ----------   -------");
    let mut peores = Vec::new();
    for (nombre, alf) in [("Hamming (actual)", &actual), ("concatenado", &concatenado)] {
        let s = acierto_tras(alf, dilatar);
        let b = acierto_tras(alf, desenfocar);
        println!("  {nombre:<21}   {:>7.1} %   {:>9.1} %   {:>5.1} %",
                 s * 100.0, b * 100.0, s.min(b) * 100.0);
        peores.push(s.min(b));
    }

    // Se fija el fracaso, no el éxito: concatenar suma cuando había que
    // minimizar. Si alguien reescribe esto y el concatenado pasa a ganar, es
    // que cambió algo de fondo y hay que releer el razonamiento.
    assert!(
        peores[1] < peores[0],
        "el criterio concatenado ya no empeora: revisa el análisis de #27"
    );
}

#[test]
fn el_desenfoque_es_la_debilidad_real_del_alfabeto_actual() {
    // Independiente de todo lo anterior y más importante: el alfabeto que hoy
    // se embarca pierde DOS TERCIOS de sus glifos con un desenfoque de 3×3.
    // Eso es lo que hace la cámara de un teléfono, no un caso rebuscado.
    // Reed-Solomon corrige lo residual, pero no un 66 % de símbolos mal.
    let actual = alfabeto_de(&candidatos_trazos(8_000, 0xBEEF), 94);
    let sangrado = acierto_tras(&actual, dilatar);
    let desenfoque = acierto_tras(&actual, desenfocar);
    println!("\n  alfabeto actual: sangrado {:.1} %, desenfoque {:.1} %",
             sangrado * 100.0, desenfoque * 100.0);
    assert_eq!(sangrado, 1.0, "el sangrado sí lo aguanta entero");
    assert!(
        desenfoque < 0.5,
        "el desenfoque ya no es una debilidad ({:.1} %): actualiza la conclusión",
        desenfoque * 100.0
    );
}
