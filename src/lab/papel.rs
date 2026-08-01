// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! ¿Qué sobrevive a una fotocopia, **a igual área de papel**?
//!
//! Es la medición que la hoja de ruta (§6) declara pendiente desde que se
//! eliminaron los glifos y el canal PNG: *«degradar como degrada una
//! fotocopiadora y comparar a igual área de papel. Nunca se hizo, y es el dato
//! que decide.»*
//!
//! # Qué se compara EXACTAMENTE, y qué NO
//!
//! No se compara «QR contra Base32». Eso mezclaría dos correcciones de errores
//! distintas —la interna del estándar QR y la nuestra— con dos densidades
//! distintas, y el resultado no diría cuál de los dos factores mandó.
//!
//! Se comparan los dos **portadores físicos** con la **misma** corrección de
//! errores, `quipu_nucleo::ecc` (Reed-Solomon sobre GF(256), la que ya está en
//! el árbol):
//!
//! - [`Matriz`] — módulos cuadrados de `lado` puntos, **1 bit por módulo**. Es
//!   el sustrato de un QR sin sus patrones de posición ni su RS propio.
//! - [`Texto`] — celdas de 6×8 puntos con un glifo de 5×7, **5 bits por celda**
//!   (alfabeto Base32 de la RFC 4648). Es el respaldo tecleable.
//!
//! Aislar así el sustrato es lo que permite responder la pregunta real: a igual
//! área, **¿gana la densidad o gana la robustez?** Y se responde **sin añadir
//! ninguna dependencia de QR**, que es una decisión de cadena de suministro que
//! conviene tomar después del dato y no antes.
//!
//! # Los límites, dichos antes que los números
//!
//! 1. El «punto» es el rasgo imprimible más pequeño, y **todo se mide en
//!    puntos**: no hay milímetros ni DPI aquí. Un resultado en puntos vale para
//!    cualquier resolución mientras las dos capas se impriman a la misma.
//! 2. El lector de [`Texto`] es **plantilla más cercana** entre los 32 glifos.
//!    Un humano lee mejor que eso —usa contexto— y un OCR real, peor en papel
//!    sucio. Es un modelo, y por eso el número que sale es *comparativo*, no una
//!    promesa de tasa de acierto absoluta.
//! 3. La fotocopiadora se modela como desenfoque de caja + umbral + motas de sal
//!    y pimienta, más una franja de tóner opcional para el error en ráfaga. No
//!    modela ni la deriva geométrica ni el moiré del medio tono.

use crate::lab::engine::Rng;
use quipu_nucleo::ecc;

/// Ancho del glifo en puntos.
pub const ANCHO_GLIFO: usize = 5;
/// Alto del glifo en puntos.
pub const ALTO_GLIFO: usize = 7;
/// Ancho de celda: el glifo más un punto de separación.
pub const ANCHO_CELDA: usize = ANCHO_GLIFO + 1;
/// Alto de celda: el glifo más un punto de separación.
pub const ALTO_CELDA: usize = ALTO_GLIFO + 1;

/// Fuente de puntos 5×7 para el alfabeto Base32 de la RFC 4648 (`A`-`Z`, `2`-`7`).
///
/// Se escribe entera y no se genera: unos glifos se parecen entre sí más que
/// otros —`8` y `B`, `0` y `O`— y ese parecido ES la medición. Una fuente
/// sintética de patrones máximamente separados daría un resultado bonito y
/// falso. (El alfabeto de la RFC ya excluye `0`, `1` y `8` justo por eso.)
const FUENTE: [[u8; ALTO_GLIFO]; 32] = [
    [0b01110, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001], // A
    [0b11110, 0b10001, 0b10001, 0b11110, 0b10001, 0b10001, 0b11110], // B
    [0b01110, 0b10001, 0b10000, 0b10000, 0b10000, 0b10001, 0b01110], // C
    [0b11110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b11110], // D
    [0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111], // E
    [0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b10000], // F
    [0b01110, 0b10001, 0b10000, 0b10111, 0b10001, 0b10001, 0b01111], // G
    [0b10001, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001], // H
    [0b01110, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110], // I
    [0b00111, 0b00010, 0b00010, 0b00010, 0b00010, 0b10010, 0b01100], // J
    [0b10001, 0b10010, 0b10100, 0b11000, 0b10100, 0b10010, 0b10001], // K
    [0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b11111], // L
    [0b10001, 0b11011, 0b10101, 0b10101, 0b10001, 0b10001, 0b10001], // M
    [0b10001, 0b11001, 0b10101, 0b10011, 0b10001, 0b10001, 0b10001], // N
    [0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110], // O
    [0b11110, 0b10001, 0b10001, 0b11110, 0b10000, 0b10000, 0b10000], // P
    [0b01110, 0b10001, 0b10001, 0b10001, 0b10101, 0b10010, 0b01101], // Q
    [0b11110, 0b10001, 0b10001, 0b11110, 0b10100, 0b10010, 0b10001], // R
    [0b01111, 0b10000, 0b10000, 0b01110, 0b00001, 0b00001, 0b11110], // S
    [0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100], // T
    [0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110], // U
    [0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01010, 0b00100], // V
    [0b10001, 0b10001, 0b10001, 0b10101, 0b10101, 0b11011, 0b10001], // W
    [0b10001, 0b10001, 0b01010, 0b00100, 0b01010, 0b10001, 0b10001], // X
    [0b10001, 0b10001, 0b01010, 0b00100, 0b00100, 0b00100, 0b00100], // Y
    [0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b10000, 0b11111], // Z
    [0b01110, 0b10001, 0b00001, 0b00010, 0b00100, 0b01000, 0b11111], // 2
    [0b11111, 0b00010, 0b00100, 0b00010, 0b00001, 0b10001, 0b01110], // 3
    [0b00010, 0b00110, 0b01010, 0b10010, 0b11111, 0b00010, 0b00010], // 4
    [0b11111, 0b10000, 0b11110, 0b00001, 0b00001, 0b10001, 0b01110], // 5
    [0b00110, 0b01000, 0b10000, 0b11110, 0b10001, 0b10001, 0b01110], // 6
    [0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b01000, 0b01000], // 7
];

/// Una hoja de puntos. `true` = tinta.
#[derive(Clone)]
pub struct Lienzo {
    /// Ancho en puntos.
    pub ancho: usize,
    /// Alto en puntos.
    pub alto: usize,
    px: Vec<bool>,
}

impl Lienzo {
    /// Hoja en blanco.
    pub fn nuevo(ancho: usize, alto: usize) -> Self {
        Self {
            ancho,
            alto,
            px: vec![false; ancho * alto],
        }
    }
    /// Tinta en `(x, y)`. Fuera de la hoja se ignora.
    pub fn poner(&mut self, x: usize, y: usize, tinta: bool) {
        if x < self.ancho && y < self.alto {
            self.px[y * self.ancho + x] = tinta;
        }
    }
    /// `true` si hay tinta. Fuera de la hoja, papel blanco.
    pub fn tinta(&self, x: usize, y: usize) -> bool {
        x < self.ancho && y < self.alto && self.px[y * self.ancho + x]
    }
    /// Área total en puntos. Es la unidad de «igual área de papel».
    pub fn area(&self) -> usize {
        self.ancho * self.alto
    }
}

/// El modelo de fotocopiadora.
#[derive(Debug, Clone, Copy)]
pub struct Fotocopia {
    /// Radio del desenfoque de caja, en puntos. 0 = sin desenfoque.
    pub desenfoque: usize,
    /// Fracción de tinta necesaria en la vecindad para que el punto salga negro.
    /// Bajo = la copia engorda los trazos; alto = los adelgaza y los rompe.
    pub umbral: f64,
    /// Probabilidad de que un punto cualquiera se invierta (sal y pimienta).
    pub mota: f64,
    /// Alto en puntos de una franja horizontal de tóner que borra todo a su
    /// paso. 0 = sin franja. Es el error en RÁFAGA, que es el que distingue a
    /// un códec con buena disposición de uno con mala.
    pub franja: usize,
}

impl Fotocopia {
    /// Una copia perfecta. Sirve de caso de control: si algo falla aquí, el
    /// fallo es del códec y no del canal.
    pub fn limpia() -> Self {
        Self {
            desenfoque: 0,
            umbral: 0.5,
            mota: 0.0,
            franja: 0,
        }
    }

    /// Pasa el lienzo por la fotocopiadora.
    pub fn aplicar(&self, entrada: &Lienzo, rng: &mut Rng) -> Lienzo {
        let mut salida = Lienzo::nuevo(entrada.ancho, entrada.alto);
        let r = self.desenfoque as isize;
        let lado = (2 * r + 1) as f64;
        let vecinos = lado * lado;

        for y in 0..entrada.alto {
            for x in 0..entrada.ancho {
                // Desenfoque de caja: la fotocopia promedia lo que hay alrededor.
                let mut suma = 0.0;
                for dy in -r..=r {
                    for dx in -r..=r {
                        let nx = x as isize + dx;
                        let ny = y as isize + dy;
                        if nx >= 0
                            && ny >= 0
                            && entrada.tinta(nx as usize, ny as usize)
                        {
                            suma += 1.0;
                        }
                    }
                }
                let mut negro = (suma / vecinos) >= self.umbral;

                // Motas: el polvo del cristal y el grano del tóner.
                if self.mota > 0.0 {
                    let sorteo = (rng.byte() as f64) / 255.0;
                    if sorteo < self.mota {
                        negro = !negro;
                    }
                }
                salida.poner(x, y, negro);
            }
        }

        // La franja de tóner: una banda que se lleva todo lo que cruza.
        if self.franja > 0 {
            let inicio = (rng.byte() as usize * entrada.alto) / 256;
            for y in inicio..(inicio + self.franja).min(entrada.alto) {
                for x in 0..entrada.ancho {
                    salida.poner(x, y, false);
                }
            }
        }
        salida
    }
}

/// Un portador: sabe cuánto le cabe en un área, imprimirlo y volver a leerlo.
pub trait Portador {
    /// Nombre para el informe.
    fn nombre(&self) -> String;
    /// Cuántos BYTES caben en una hoja de `ancho × alto` puntos, ya contando
    /// todo lo que el portador gasta en su propia estructura.
    fn capacidad_bytes(&self, ancho: usize, alto: usize) -> usize;
    /// Imprime. `datos` no puede pasar de [`Portador::capacidad_bytes`].
    fn imprimir(&self, datos: &[u8], ancho: usize, alto: usize) -> Lienzo;
    /// Lee. Devuelve exactamente tantos bytes como se imprimieron.
    fn leer(&self, hoja: &Lienzo, cuantos: usize) -> Vec<u8>;
}

/// Módulos cuadrados de `lado` puntos, un bit cada uno. El sustrato de un QR.
#[derive(Debug, Clone, Copy)]
pub struct Matriz {
    /// Lado del módulo en puntos. Es EL parámetro: sube la robustez y baja la
    /// densidad con el cuadrado.
    pub lado: usize,
}

impl Matriz {
    fn modulos(&self, ancho: usize, alto: usize) -> (usize, usize) {
        (ancho / self.lado, alto / self.lado)
    }
}

impl Portador for Matriz {
    fn nombre(&self) -> String {
        format!("matriz(lado={})", self.lado)
    }

    fn capacidad_bytes(&self, ancho: usize, alto: usize) -> usize {
        let (mx, my) = self.modulos(ancho, alto);
        mx * my / 8
    }

    fn imprimir(&self, datos: &[u8], ancho: usize, alto: usize) -> Lienzo {
        let mut hoja = Lienzo::nuevo(ancho, alto);
        let (mx, _) = self.modulos(ancho, alto);
        for (i, bit) in datos
            .iter()
            .flat_map(|b| (0..8).map(move |k| (b >> (7 - k)) & 1 == 1))
            .enumerate()
        {
            let (cx, cy) = (i % mx, i / mx);
            for dy in 0..self.lado {
                for dx in 0..self.lado {
                    hoja.poner(cx * self.lado + dx, cy * self.lado + dy, bit);
                }
            }
        }
        hoja
    }

    fn leer(&self, hoja: &Lienzo, cuantos: usize) -> Vec<u8> {
        let (mx, _) = self.modulos(hoja.ancho, hoja.alto);
        let mut bits = Vec::with_capacity(cuantos * 8);
        for i in 0..cuantos * 8 {
            let (cx, cy) = (i % mx, i / mx);
            // Voto por mayoría dentro del módulo: es lo que hace cualquier
            // lector real, y es donde un módulo grande gana al pequeño.
            let mut negros = 0usize;
            for dy in 0..self.lado {
                for dx in 0..self.lado {
                    if hoja.tinta(cx * self.lado + dx, cy * self.lado + dy) {
                        negros += 1;
                    }
                }
            }
            bits.push(negros * 2 > self.lado * self.lado);
        }
        bits.chunks(8)
            .map(|c| {
                c.iter()
                    .enumerate()
                    .fold(0u8, |a, (k, &b)| a | ((b as u8) << (7 - k)))
            })
            .collect()
    }
}

/// Celdas de texto con el alfabeto Base32: 5 bits por celda de 6×8 puntos del
/// glifo, cada punto dibujado como un cuadrado de `escala × escala`.
///
/// **`escala` existe porque sin ella la comparación estaba trucada.** La primera
/// corrida daba 100 % o 0 % sin nada en medio, y el texto se caía ya en la «1ª
/// copia». La causa no era el portador: un desenfoque de caja de radio 1 con
/// umbral 0,45 **borra todo trazo de menos de 3 puntos de ancho**, y el glifo
/// 5×7 tiene trazos de 1 punto por construcción. Se estaba comparando un
/// portador de rasgo 1 contra uno de rasgo 3, así que lo medido era cuál tenía
/// los trazos más gordos — no densidad contra robustez.
///
/// Con `escala` los dos portadores se pueden poner en el MISMO rasgo mínimo, que
/// es la variable que domina el canal, y entonces la comparación mide lo que
/// dice medir (directiva 16).
#[derive(Debug, Clone, Copy)]
pub struct Texto {
    /// Lado del punto del glifo, en puntos de papel. Equivale al `lado` de
    /// [`Matriz`]: es el rasgo mínimo imprimible del portador.
    pub escala: usize,
}

impl Default for Texto {
    fn default() -> Self {
        Self { escala: 1 }
    }
}

impl Texto {
    fn celdas(&self, ancho: usize, alto: usize) -> (usize, usize) {
        (
            ancho / (ANCHO_CELDA * self.escala),
            alto / (ALTO_CELDA * self.escala),
        )
    }
}

impl Portador for Texto {
    fn nombre(&self) -> String {
        format!("texto b32(esc={})", self.escala)
    }

    fn capacidad_bytes(&self, ancho: usize, alto: usize) -> usize {
        let (cx, cy) = self.celdas(ancho, alto);
        cx * cy * 5 / 8
    }

    fn imprimir(&self, datos: &[u8], ancho: usize, alto: usize) -> Lienzo {
        let mut hoja = Lienzo::nuevo(ancho, alto);
        let (cx, _) = self.celdas(ancho, alto);
        let e = self.escala;
        for (i, simbolo) in a_base32(datos).into_iter().enumerate() {
            let (col, fila) = (i % cx, i / cx);
            let glifo = &FUENTE[simbolo as usize];
            for (gy, renglon) in glifo.iter().enumerate() {
                for gx in 0..ANCHO_GLIFO {
                    let tinta = (renglon >> (ANCHO_GLIFO - 1 - gx)) & 1 == 1;
                    // Cada punto del glifo se dibuja como un cuadrado de e×e.
                    for sy in 0..e {
                        for sx in 0..e {
                            hoja.poner(
                                (col * ANCHO_CELDA + gx) * e + sx,
                                (fila * ALTO_CELDA + gy) * e + sy,
                                tinta,
                            );
                        }
                    }
                }
            }
        }
        hoja
    }

    fn leer(&self, hoja: &Lienzo, cuantos: usize) -> Vec<u8> {
        let (cx, _) = self.celdas(hoja.ancho, hoja.alto);
        let e = self.escala;
        let simbolos_necesarios = cuantos * 8 / 5 + 1;
        let mut simbolos = Vec::with_capacity(simbolos_necesarios);
        for i in 0..simbolos_necesarios {
            let (col, fila) = (i % cx, i / cx);
            // Plantilla más cercana por distancia de Hamming sobre el glifo,
            // con voto por mayoría dentro de cada punto escalado — que es lo
            // mismo que hace [`Matriz`] con sus módulos, para que ninguno de
            // los dos lea mejor que el otro por el lector y no por el sustrato.
            let mut mejor = (0u8, usize::MAX);
            for (s, glifo) in FUENTE.iter().enumerate() {
                let mut d = 0usize;
                for (gy, renglon) in glifo.iter().enumerate() {
                    for gx in 0..ANCHO_GLIFO {
                        let esperado = (renglon >> (ANCHO_GLIFO - 1 - gx)) & 1 == 1;
                        let mut negros = 0usize;
                        for sy in 0..e {
                            for sx in 0..e {
                                if hoja.tinta(
                                    (col * ANCHO_CELDA + gx) * e + sx,
                                    (fila * ALTO_CELDA + gy) * e + sy,
                                ) {
                                    negros += 1;
                                }
                            }
                        }
                        if (negros * 2 > e * e) != esperado {
                            d += 1;
                        }
                    }
                }
                if d < mejor.1 {
                    mejor = (s as u8, d);
                }
            }
            simbolos.push(mejor.0);
        }
        de_base32(&simbolos, cuantos)
    }
}

/// Bytes a símbolos de 5 bits.
fn a_base32(datos: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(datos.len() * 8 / 5 + 1);
    let (mut acc, mut bits) = (0u16, 0u32);
    for &b in datos {
        acc = (acc << 8) | b as u16;
        bits += 8;
        while bits >= 5 {
            out.push(((acc >> (bits - 5)) & 0x1f) as u8);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 0x1f) as u8);
    }
    out
}

/// Símbolos de 5 bits a bytes. Trunca a `cuantos`.
fn de_base32(simbolos: &[u8], cuantos: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(cuantos);
    let (mut acc, mut bits) = (0u16, 0u32);
    for &s in simbolos {
        acc = (acc << 5) | (s & 0x1f) as u16;
        bits += 5;
        if bits >= 8 {
            out.push(((acc >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
            if out.len() == cuantos {
                break;
            }
        }
    }
    out.resize(cuantos, 0);
    out
}

/// El resultado de una corrida: cuántas veces se recuperó el secreto ENTERO.
#[derive(Debug, Clone)]
pub struct Corrida {
    /// Qué portador.
    pub portador: String,
    /// Bytes de secreto que se metieron (ya descontada la paridad).
    pub carga_util: usize,
    /// Intentos.
    pub intentos: usize,
    /// Cuántos devolvieron el secreto EXACTO.
    pub exitos: usize,
}

impl Corrida {
    /// Fracción de recuperaciones íntegras.
    pub fn tasa(&self) -> f64 {
        self.exitos as f64 / self.intentos.max(1) as f64
    }
    /// `true` si al portador no le cabía NADA en esa área: la corrida no midió
    /// nada y su 100 % es el de recuperar el secreto vacío.
    ///
    /// Existe porque la primera tabla lo enseñó: `texto b32(esc=4)` marcaba
    /// 100 % en todas las columnas con `bytes = 0`. Un portador que no lleva
    /// nada nunca falla, y leído deprisa parecía el más robusto de todos.
    pub fn vacia(&self) -> bool {
        self.carga_util == 0
    }
    /// Se considera fiable a partir del 95 % **y solo si llevaba algo**.
    pub fn fiable(&self) -> bool {
        !self.vacia() && self.tasa() >= 0.95
    }
}

/// Imprime un secreto, lo pasa por la fotocopiadora y trata de recuperarlo,
/// `intentos` veces. La corrección de errores es la MISMA para los dos
/// portadores: eso es lo que aísla el sustrato.
///
/// `paridad_pct` es qué fracción de la capacidad se gasta en Reed-Solomon.
pub fn medir(
    portador: &dyn Portador,
    ancho: usize,
    alto: usize,
    paridad_pct: f64,
    copia: Fotocopia,
    intentos: usize,
    rng: &mut Rng,
) -> Corrida {
    let capacidad = portador.capacidad_bytes(ancho, alto);
    // La paridad de `ecc` es por bloque de 255. Se elige el byte de paridad que
    // deja la carga útil deseada, y luego se busca la carga que cabe de verdad
    // — `protect` añade cabecera y redondea por bloques, así que se comprueba
    // en vez de calcularlo a ojo (el cálculo a ojo ya nos costó un release).
    let paridad = ((255.0 * paridad_pct) as u8).clamp(2, 200);
    let mut carga = capacidad;
    while carga > 0 && ecc::protect(&vec![0u8; carga], paridad).len() > capacidad {
        carga -= 1;
    }
    let mut exitos = 0usize;
    for _ in 0..intentos {
        let secreto: Vec<u8> = (0..carga).map(|_| rng.byte()).collect();
        let protegido = ecc::protect(&secreto, paridad);
        let hoja = portador.imprimir(&protegido, ancho, alto);
        let copiada = copia.aplicar(&hoja, rng);
        let leido = portador.leer(&copiada, protegido.len());
        if ecc::recover(&leido).as_deref() == Some(secreto.as_slice()) {
            exitos += 1;
        }
    }
    Corrida {
        portador: portador.nombre(),
        carga_util: carga,
        intentos,
        exitos,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_ida_y_vuelta() {
        let datos: Vec<u8> = (0..100u16).map(|i| (i * 7) as u8).collect();
        let s = a_base32(&datos);
        assert_eq!(de_base32(&s, datos.len()), datos);
    }

    #[test]
    fn los_dos_portadores_van_y_vuelven_sin_degradar() {
        // El control. Si esto falla, lo que sigue mide un fallo del códec y no
        // del canal, y todo el experimento sería ruido con formato de tabla.
        let mut rng = Rng::seeded(1);
        for p in [
            &Matriz { lado: 2 } as &dyn Portador,
            &Matriz { lado: 3 },
            &Texto { escala: 1 },
            &Texto { escala: 3 },
        ] {
            let c = medir(p, 240, 240, 0.15, Fotocopia::limpia(), 5, &mut rng);
            assert_eq!(
                c.exitos, 5,
                "{} no sobrevive ni a una copia perfecta",
                c.portador
            );
            assert!(c.carga_util > 0, "{} no llevaba nada", c.portador);
        }
    }

    #[test]
    fn la_fotocopiadora_discrimina() {
        // Un canal que nunca rompe nada mediría el vacío. Con degradación
        // brutal los dos portadores tienen que caer.
        let mut rng = Rng::seeded(2);
        let brutal = Fotocopia {
            desenfoque: 3,
            umbral: 0.75,
            mota: 0.25,
            franja: 12,
        };
        for p in [&Matriz { lado: 2 } as &dyn Portador, &Texto { escala: 3 }] {
            let c = medir(p, 120, 120, 0.15, brutal, 5, &mut rng);
            assert_eq!(
                c.exitos, 0,
                "{} sobrevivió a una degradación brutal: el canal no degrada",
                c.portador
            );
        }
    }

    #[test]
    fn una_corrida_sin_carga_no_cuenta_como_fiable() {
        // El caso rojo del propio medidor: en un área diminuta al texto no le
        // cabe nada, recupera el secreto VACÍO siempre, y sin esta regla su
        // 100 % lo coronaría como el portador más robusto.
        let mut rng = Rng::seeded(3);
        let c = medir(
            &Texto { escala: 4 },
            120,
            120,
            0.15,
            Fotocopia::limpia(),
            3,
            &mut rng,
        );
        assert!(c.vacia(), "se esperaba que no cupiera nada");
        assert_eq!(c.tasa(), 1.0, "recuperar la nada siempre 'funciona'");
        assert!(!c.fiable(), "una corrida vacía NO puede contar como fiable");
    }

    #[test]
    fn el_area_es_la_misma_para_los_dos() {
        // «A igual área de papel» tiene que ser literal, no aproximado.
        let hoja_m = Matriz { lado: 2 }.imprimir(&[0u8; 10], 120, 120);
        let hoja_t = Texto { escala: 2 }.imprimir(&[0u8; 10], 120, 120);
        assert_eq!(hoja_m.area(), hoja_t.area());
        assert_eq!(hoja_m.area(), 120 * 120);
    }
}
