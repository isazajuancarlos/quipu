// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! ¿Cuánto se nota que un señuelo es falso cuando el secreto NO es uniforme?
//!
//! `honey` modela el secreto como `L` tokens de un alfabeto uniforme, y con eso
//! el señuelo es perfecto: cualquier passphrase equivocada produce una secuencia
//! uniforme, indistinguible de otra secuencia uniforme. El módulo lo declara sin
//! rodeos —«solo tiene sentido cuando toda decodificación es plausible»—.
//!
//! La tarea #28 preguntaba si se puede ir más allá, a secretos reales. Se cerró
//! por argumento: un modelo de la distribución en coma flotante rompe el
//! determinismo bit a bit que Honey exige, y si la distribución no coincide con
//! la real los señuelos se distinguen y falla la SEGURIDAD, no la comodidad.
//!
//! Esto NO reabre aquella conclusión. Mide otra cosa: **cuánta ventaja tiene hoy
//! un atacante** cuando el secreto protegido no es uniforme. Ese número es el
//! que tendría que cerrar una tabla de señuelos estática (tarea #91), y sin él
//! esa tarea se decidiría por intuición.
//!
//! # Qué se puede concluir y qué no
//!
//! El modelo de «PIN humano» de aquí es ESTRUCTURAL —repeticiones, escaleras,
//! fechas, `ABAB`— y está escrito de memoria, no ajustado sobre datos reales.
//! Es peor que el que tendría un atacante de verdad, que dispone de estadísticas
//! de filtraciones masivas.
//!
//! Por eso la medición solo vale **en una dirección**: si un modelo tosco ya da
//! ventaja grande, la conclusión es firme. Si no diera ninguna, no probaría
//! nada. Es una cota INFERIOR de lo que consigue un atacante.

/// PRNG determinista: el experimento da lo mismo en cualquier máquina.
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
    fn bajo(&mut self, n: u32) -> u32 {
        (self.siguiente() % n as u64) as u32
    }
}

type Pin = [u8; 4];

fn pin_de(n: u32) -> Pin {
    [
        (n / 1000 % 10) as u8,
        (n / 100 % 10) as u8,
        (n / 10 % 10) as u8,
        (n % 10) as u8,
    ]
}

// --- Modelo de cómo elige un humano ---------------------------------------
//
// No es una distribución ajustada: son los patrones que cualquiera reconoce.
// Se usa para DOS cosas distintas —generar el secreto «real» y puntuar la
// plausibilidad— a propósito, porque el atacante que se simula es el que conoce
// el mismo modelo. Un atacante con mejores estadísticas lo haría mejor.

/// Cuánto «parece elegido por una persona». Más alto, más plausible.
fn plausibilidad(p: Pin) -> u32 {
    let mut s: u32 = 0;

    // Todos iguales: 1111, 0000.
    if p.iter().all(|&d| d == p[0]) {
        s += 40;
    }
    // Escalera ascendente o descendente: 1234, 4321.
    let asc = (1..4).all(|i| p[i] == (p[i - 1] + 1) % 10);
    let desc = (1..4).all(|i| p[i - 1] == (p[i] + 1) % 10);
    if asc || desc {
        s += 35;
    }
    // Pares repetidos: 1212, 7878.
    if p[0] == p[2] && p[1] == p[3] {
        s += 25;
    }
    // Dobles: 1122, 5566.
    if p[0] == p[1] && p[2] == p[3] {
        s += 20;
    }
    // Capicúa: 1221.
    if p[0] == p[3] && p[1] == p[2] {
        s += 15;
    }
    // Año reciente: 19xx o 20xx.
    let n = p[0] as u32 * 1000 + p[1] as u32 * 100 + p[2] as u32 * 10 + p[3] as u32;
    if (1940..=2026).contains(&n) {
        s += 30;
    }
    // Día y mes: DDMM o MMDD válidos.
    let (a, b) = (p[0] * 10 + p[1], p[2] * 10 + p[3]);
    if (1..=12).contains(&a) && (1..=31).contains(&b) {
        s += 20;
    }
    if (1..=31).contains(&a) && (1..=12).contains(&b) {
        s += 20;
    }
    // Empieza por 0: la gente lo evita.
    if p[0] == 0 && n != 0 {
        s = s.saturating_sub(10);
    }
    s
}

/// Un PIN como lo elegiría una persona: casi siempre con patrón.
fn pin_humano(rng: &mut Rng) -> Pin {
    match rng.bajo(100) {
        0..=24 => {
            // Un año: cumpleaños o similar.
            let a = 1940 + rng.bajo(80);
            pin_de(a)
        }
        25..=44 => {
            // Fecha DDMM.
            let d = 1 + rng.bajo(28);
            let m = 1 + rng.bajo(12);
            pin_de(d * 100 + m)
        }
        45..=54 => {
            // Pares repetidos ABAB.
            let (a, b) = (rng.bajo(10) as u8, rng.bajo(10) as u8);
            [a, b, a, b]
        }
        55..=59 => {
            // Todos iguales.
            let d = rng.bajo(10) as u8;
            [d, d, d, d]
        }
        60..=64 => {
            // Escalera.
            let d = rng.bajo(10) as u8;
            [d, (d + 1) % 10, (d + 2) % 10, (d + 3) % 10]
        }
        _ => pin_de(rng.bajo(10_000)), // el resto, de verdad al azar
    }
}

/// Un señuelo tal como los produce `honey` hoy: uniforme sobre 10 000.
fn senuelo_uniforme(rng: &mut Rng) -> Pin {
    pin_de(rng.bajo(10_000))
}

// --- El experimento --------------------------------------------------------

struct Resultado {
    aciertos_primero: f64,
    rango_mediano: f64,
    azar: f64,
}

/// Simula al atacante: ante un secreto real escondido entre `n_senuelos`
/// señuelos, ordena todos por plausibilidad y mira dónde cae el verdadero.
fn simular(intentos: usize, n_senuelos: usize, semilla: u64) -> Resultado {
    let mut rng = Rng::nuevo(semilla);
    let mut primero = 0usize;
    let mut rangos = Vec::with_capacity(intentos);

    for _ in 0..intentos {
        let real = pin_humano(&mut rng);
        let objetivo = plausibilidad(real);

        // Cuántos señuelos parecen MÁS humanos que el secreto real. Ese es el
        // rango del verdadero en la lista que ordena el atacante.
        let mut mejores = 0usize;
        for _ in 0..n_senuelos {
            if plausibilidad(senuelo_uniforme(&mut rng)) > objetivo {
                mejores += 1;
            }
        }
        if mejores == 0 {
            primero += 1;
        }
        rangos.push(mejores + 1);
    }

    rangos.sort_unstable();
    Resultado {
        aciertos_primero: primero as f64 / intentos as f64,
        rango_mediano: rangos[rangos.len() / 2] as f64,
        azar: 1.0 / (n_senuelos + 1) as f64,
    }
}

#[test]
fn con_secretos_no_uniformes_los_senuelos_uniformes_se_distinguen() {
    println!("\n  señuelos   acierta al primero   por azar   ventaja   rango mediano");
    println!("  --------   ------------------   --------   -------   -------------");
    let mut ventajas = Vec::new();
    for &n in &[9usize, 99, 999] {
        let r = simular(20_000, n, 0xC0FFEE);
        let ventaja = r.aciertos_primero / r.azar;
        println!(
            "  {n:>8}   {:>17.1} %   {:>6.2} %   ×{ventaja:>6.1}   {:>13.0}",
            r.aciertos_primero * 100.0,
            r.azar * 100.0,
            r.rango_mediano
        );
        ventajas.push(ventaja);
    }

    // Lo que se afirma: con un modelo TOSCO, el atacante ya supera al azar por
    // un factor grande. Un atacante real, con estadísticas de filtraciones,
    // lo haría mejor. Es cota inferior.
    assert!(
        ventajas.iter().all(|&v| v > 3.0),
        "el modelo tosco NO da ventaja apreciable: entonces esta medición no \
         prueba nada y hay que rehacerla con datos reales antes de concluir"
    );
}

#[test]
fn con_secretos_uniformes_el_atacante_no_saca_nada() {
    // El control. Si el secreto SÍ es uniforme —el caso para el que `honey`
    // está diseñado— el mismo atacante no debe distinguir nada. Sin esta
    // prueba, la anterior podría estar midiendo un sesgo del experimento en vez
    // de una propiedad del secreto.
    let mut rng = Rng::nuevo(0xDECAF);
    let (intentos, n) = (20_000usize, 99usize);
    let mut primero = 0usize;
    for _ in 0..intentos {
        let real = senuelo_uniforme(&mut rng); // real TAMBIÉN uniforme
        let objetivo = plausibilidad(real);
        let mejores = (0..n)
            .filter(|_| plausibilidad(senuelo_uniforme(&mut rng)) > objetivo)
            .count();
        if mejores == 0 {
            primero += 1;
        }
    }
    let tasa = primero as f64 / intentos as f64;
    let azar = 1.0 / (n + 1) as f64;
    println!("\n  control (secreto uniforme): acierta al primero {:.2} %, \
              azar {:.2} %, ventaja ×{:.2}", tasa * 100.0, azar * 100.0, tasa / azar);
    // Se tolera hasta el doble del azar: los empates de puntuación favorecen
    // levemente al verdadero, y eso es del experimento, no del cifrado.
    assert!(
        tasa / azar < 2.0,
        "el atacante saca ventaja incluso con secretos uniformes ({:.2}×): el \
         experimento tiene un sesgo y el otro número no vale",
        tasa / azar
    );
}
