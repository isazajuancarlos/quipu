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

// ===========================================================================
// EL PEOR SEÑUELO (#108), medido sobre la librería y no sobre una simulación
// ===========================================================================
//
// Todo lo de arriba simula los señuelos: da por hecho que `honey` produce PINs
// uniformes y mide qué ventaja saca el atacante con eso. Es lo que el módulo
// declara, pero declarado no es medido — y lo que la ficha #108 pide es otra
// cosa además: no cuántos señuelos hay ni cómo se comportan EN PROMEDIO, sino
// **qué tan indistinguible es el PEOR**. Un promedio esconde exactamente lo que
// importa: basta con que uno desentone para que el atacante deje de buscar la
// salida y empiece a buscar la grieta.
//
// # «Desentonar» son DOS cosas, y solo una se mide aquí
//
// 1. ESTRUCTURAL —longitud rara, token fuera del alfabeto, error de «clave»—.
//    Eso ya lo mide el laboratorio (`lab::honey_attack`, que busca un oráculo de
//    éxito) y da CERO por construcción: el descifrado es aritmética modular
//    sobre una longitud fija, así que no puede producir un secreto mal formado.
// 2. DISTRIBUCIONAL —el señuelo está bien formado pero cae donde una persona no
//    caería—. Es lo que se mide aquí, y no tiene respuesta binaria: la
//    distribución real de PINs tiene soporte COMPLETO (una persona puede elegir
//    cualquiera de los 10 000), así que ningún señuelo es imposible. Lo que sí
//    se puede medir es la COLA: cuántos señuelos caen por debajo de lo que
//    elegiría el 5 % menos típico de las personas.
//
// # LA CONCLUSIÓN, y contradice la forma en que la ficha pedía el número
//
// «El peor señuelo» solo se puede medir cuando el espacio de secretos tiene
// ESTRUCTURA que un señuelo pueda violar: una frase que no esté en el
// diccionario, un día 32, un formato que no cierra. El honey de Quipu modela el
// secreto como `L` tokens uniformes de un alfabeto, y ahí **no hay nada que
// violar**: todo señuelo es un elemento válido del espacio, así que el peor es
// exactamente igual de convincente que el mejor. La métrica del mínimo no puede
// existir para este modo — no porque falte escribirla, sino porque el objeto que
// mediría no existe. Y una métrica que no puede dispararse nunca es un generador
// de ceros con otro nombre.
//
// Lo que sí existe y se mide aquí es la COLA: la distribución real de un secreto
// humano no es uniforme, así que los señuelos uniformes caen desproporcionadamente
// en la parte que una persona rara vez elige. La métrica es la RAZÓN entre la
// cola de los señuelos y la de los secretos reales — ×1 significa
// indistinguible—, y se mide sobre los señuelos que devuelve `honey::decrypt`,
// no sobre una simulación de lo que se supone que devuelve.
//
// El día que Quipu tenga un modo con codificador de distribución sobre un espacio
// con estructura, la métrica del mínimo pasa a tener objeto y es binaria:
// ¿existe UN señuelo que el validador del espacio rechace? Basta uno.

#[cfg(feature = "honey")]
fn opciones_honey() -> quipu::honey::HoneyOptions<'static> {
    quipu::honey::HoneyOptions {
        pepper: b"",
        // KDF barata: lo que se mide es la distribución de los señuelos, no el
        // coste de derivar. Con el coste real esta prueba tardaría minutos.
        kdf_params: quipu::kdf::KdfParams { mem_kib: 64, iterations: 1, parallelism: 1 },
    }
}

/// Señuelos DE VERDAD: se cifra un PIN y se descifra con `k` frases equivocadas.
/// Cada resultado es lo que vería un atacante que probó una contraseña y no
/// acertó — que es el objeto que esta ficha manda medir.
#[cfg(feature = "honey")]
fn senuelos_de_la_libreria(k: usize, semilla: u64) -> Vec<Pin> {
    let opts = opciones_honey();
    let blob = quipu::honey::encrypt_pin("1984", "la-frase-correcta-del-canario", &opts)
        .expect("cifra");
    let mut rng = Rng::nuevo(semilla);
    (0..k)
        .map(|_| {
            let frase = format!("equivocada-{:016x}", rng.siguiente());
            let s = quipu::honey::decrypt_pin(&blob, &frase, b"").expect("señuelo, no error");
            let d: Vec<u8> = s.bytes().map(|b| b - b'0').collect();
            [d[0], d[1], d[2], d[3]]
        })
        .collect()
}

/// El umbral: la plausibilidad del 5 % menos típico de lo que elige una persona.
///
/// OJO CON EL PERCENTIL EN UNA DISTRIBUCIÓN CON ÁTOMOS, que es lo que hace que
/// este umbral no se pueda usar a la ligera: más del 5 % de los PINs humanos
/// puntúan CERO —el 35 % de la distribución es «uno cualquiera», y un PIN sin
/// patrón vale cero—, así que el percentil 5 ES cero. La primera versión de esto
/// comparaba con `< umbral` y por tanto no contaba nunca nada: un generador de
/// ceros de manual, y además con un bucle de rechazo que no terminaba jamás.
/// Se compara con `<=` y se mide una RAZÓN, no una fracción suelta.
fn umbral_percentil_5(muestras: usize, semilla: u64, humano: bool) -> u32 {
    let mut rng = Rng::nuevo(semilla);
    let mut v: Vec<u32> = (0..muestras)
        .map(|_| {
            if humano {
                plausibilidad(pin_humano(&mut rng))
            } else {
                plausibilidad(senuelo_uniforme(&mut rng))
            }
        })
        .collect();
    v.sort_unstable();
    v[muestras / 20]
}

/// Qué fracción de una muestra cae en la cola (por debajo o igual al umbral).
fn cola(pins: &[Pin], umbral: u32) -> f64 {
    pins.iter().filter(|&&p| plausibilidad(p) <= umbral).count() as f64 / pins.len() as f64
}

/// LA MÉTRICA: cuántas VECES más señuelos caen en la cola de lo que caen
/// secretos reales. Uno significa «los señuelos se reparten como los secretos»;
/// más de uno, señuelos que desentonan y que el atacante puede posponer.
///
/// Es una razón y no una fracción porque la cola de referencia no vale 5 % — la
/// distribución tiene átomos y el percentil se apoya en uno—, así que la única
/// lectura honesta es contra la cola que tienen los secretos DE VERDAD.
fn veces_mas_en_la_cola(senuelos: &[Pin], reales: &[Pin], umbral: u32) -> f64 {
    let c_real = cola(reales, umbral);
    assert!(c_real > 0.0, "la cola de referencia es vacía: el umbral no sirve");
    cola(senuelos, umbral) / c_real
}

/// Una muestra de secretos como los elige una persona, para la referencia.
fn muestra_humana(n: usize, semilla: u64) -> Vec<Pin> {
    let mut rng = Rng::nuevo(semilla);
    (0..n).map(|_| pin_humano(&mut rng)).collect()
}

/// EL CONTROL, en los DOS sentidos, que es lo que hace que el número de abajo
/// signifique algo: la misma métrica tiene que dar ×1 cuando los señuelos vienen
/// de la MISMA distribución que los secretos, y subir cuando vienen de otra. Un
/// solo lado no probaría nada — una métrica que siempre dice «se distinguen» es
/// tan inútil como una que siempre dice que no.
#[test]
fn la_medida_de_la_cola_discrimina_en_los_dos_sentidos() {
    let umbral = umbral_percentil_5(20_000, 0xB0BA, true);
    let reales = muestra_humana(20_000, 0xB0BA);

    // (a) señuelos de la MISMA distribución que el secreto: tiene que dar ×1.
    let iguales = muestra_humana(2_000, 0x1234);
    let veces_iguales = veces_mas_en_la_cola(&iguales, &reales, umbral);

    // (b) señuelos uniformes, que es lo que produce honey hoy: tiene que subir.
    let mut rng = Rng::nuevo(0xFE0);
    let distintos: Vec<Pin> = (0..2_000).map(|_| senuelo_uniforme(&mut rng)).collect();
    let veces_distintos = veces_mas_en_la_cola(&distintos, &reales, umbral);

    println!(
        "\n  control: señuelos de la misma distribución ×{veces_iguales:.2} · \
         de otra ×{veces_distintos:.2}  (umbral {umbral}, cola real {:.0} %)",
        cola(&reales, umbral) * 100.0
    );
    assert!(
        (veces_iguales - 1.0).abs() < 0.15,
        "con señuelos de la MISMA distribución la métrica debería dar ×1 y da \
         ×{veces_iguales:.2}: el experimento tiene un sesgo propio"
    );
    assert!(
        veces_distintos > 2.0,
        "con señuelos de OTRA distribución la métrica no se mueve (×{veces_distintos:.2}): \
         no discrimina, y cualquier número sobre la librería sería humo"
    );
}

/// Y EL NÚMERO QUE LA FICHA PEDÍA, sobre los señuelos que produce la librería.
///
/// Se AFIRMA lo que el módulo declara —`honey` protege un espacio de secretos
/// UNIFORME, y ahí sus señuelos son indistinguibles por construcción— y se MIDE,
/// sin afirmar nada, la cola contra la distribución humana: esa es la limitación
/// que el módulo ya declara en prosa, aquí puesta en número.
#[cfg(feature = "honey")]
#[test]
fn el_peor_senuelo_de_la_libreria_no_cae_fuera_del_espacio_que_honey_declara() {
    let senuelos = senuelos_de_la_libreria(500, 0x5EED);

    // 1. Contra el espacio que honey declara (uniforme). Aquí sí se afirma.
    let umbral_u = umbral_percentil_5(20_000, 0xA11CE, false);
    let mut rng = Rng::nuevo(0xA11CE);
    let referencia_uniforme: Vec<Pin> = (0..20_000).map(|_| senuelo_uniforme(&mut rng)).collect();
    let veces_uniforme = veces_mas_en_la_cola(&senuelos, &referencia_uniforme, umbral_u);

    // 2. Contra cómo elige una persona: la limitación declarada, medida.
    let umbral_h = umbral_percentil_5(20_000, 0xB0BA, true);
    let reales = muestra_humana(20_000, 0xB0BA);
    let veces_humano = veces_mas_en_la_cola(&senuelos, &reales, umbral_h);

    let peor = senuelos.iter().map(|&s| plausibilidad(s)).min().unwrap();
    println!("\n  señuelos tomados de la librería      : {}", senuelos.len());
    println!("  peor señuelo (plausibilidad mínima)  : {peor}");
    println!("  cola contra el espacio UNIFORME      : ×{veces_uniforme:.2}  (1,00 = indistinguible)");
    println!("  cola contra la distribución HUMANA   : ×{veces_humano:.2}  (limitación declarada)");

    assert!(
        veces_uniforme < 1.5,
        "los señuelos de la librería caen ×{veces_uniforme:.2} más en la cola del \
         espacio UNIFORME que honey declara proteger. Ahí sí sería un fallo: es el \
         caso para el que el modo se diseñó"
    );
}
