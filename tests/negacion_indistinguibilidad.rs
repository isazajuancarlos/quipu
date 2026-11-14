// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

//! El banco del §8 de `docs/DISENO_NEGACION.md`: el frente de la sospecha **no
//! se da por cubierto por argumento, se mide**.
//!
//! Tres sondas, y las tres tienen que salir «no distingue»:
//!
//! 1. **Contenedor contra azar.** Si el distinguidor los separa, algo dentro del
//!    contenedor sigue hablando. Esta es la que fallaría con el formato `QUIP`
//!    de hoy y sus 28 bytes de estructura.
//! 2. **Con oculto contra sin oculto.** El frente de la prueba, y la razón por
//!    la que el relleno tiene que ser azar SIEMPRE.
//!
//! Y cada una trae su **caso rojo**: la misma sonda contra un contenedor
//! deliberadamente roto, donde el banco tiene que ponerse rojo. Un banco que
//! nunca dice que no, no dice nada — y esta librería ya tuvo un medidor que dio
//! cero falso cuatro veces.
//!
//! La sonda 3 (tiempo de fallo por dudect) vive aparte, en el banco offline:
//! necesita `lab-offline` y decenas de miles de mediciones.

#![cfg(all(feature = "negacion", feature = "lab"))]

use quipu::kdf::KdfParams;
use quipu::lab::distinguidor::{entrenar_y_evaluar, medir_repetido, posicion_mas_delatora};
use quipu::negacion::{crear, Perfil, TAMANO_MINIMO};

/// Tamaño de contenedor del banco. El mínimo basta: cuanto más pequeño, más
/// peso relativo tiene cualquier estructura que se colara, así que es el caso
/// más exigente para la sonda 1.
const S: usize = TAMANO_MINIMO;

/// Cuántos contenedores por población y ronda.
const MUESTRAS: usize = 150;

/// Coste de laboratorio: el formato es idéntico al de `V1`, solo cuesta menos
/// derivar. Lo que se mide son los BYTES del contenedor, y esos no dependen del
/// coste de Argon2id.
fn perfil() -> Perfil {
    Perfil::de_laboratorio(
        "banco",
        KdfParams {
            mem_kib: 64,
            iterations: 1,
            parallelism: 1,
        },
    )
}

/// PRNG determinista para las contraseñas y los contenidos: el banco tiene que
/// dar lo mismo en cualquier máquina. El azar que importa —salt y relleno— sale
/// del CSPRNG real dentro de `crear`.
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
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.siguiente() & 0xff) as u8).collect()
    }
}

/// Una población de contenedores. `con_oculto` decide si llevan volumen oculto.
fn poblacion(rng: &mut Rng, cuantos: usize, con_oculto: bool) -> Vec<Vec<u8>> {
    (0..cuantos)
        .map(|i| {
            let senuelo = rng.bytes(40);
            let clave_s = format!("senuelo-{i}-{}", rng.siguiente());
            let oculto_datos = rng.bytes(40);
            let clave_o = format!("oculto-{i}-{}", rng.siguiente());
            let oculto = if con_oculto {
                Some((oculto_datos.as_slice(), clave_o.as_str()))
            } else {
                None
            };
            crear(S, &senuelo, &clave_s, oculto, perfil()).expect("crear no debe fallar")
        })
        .collect()
}

/// Bytes del CSPRNG real, del mismo largo que un contenedor.
fn azar(cuantos: usize) -> Vec<Vec<u8>> {
    (0..cuantos)
        .map(|_| {
            let mut v = vec![0u8; S];
            quipu::aleatorio::llenar(&mut v).expect("hay entropía");
            v
        })
        .collect()
}

// --- Sonda 1: el contenedor contra el azar ---------------------------------

#[test]
fn sonda_1_un_contenedor_no_se_distingue_de_azar() {
    let mut rng = Rng::nuevo(0xC0FFEE);
    let vr = medir_repetido(|| {
        let a = poblacion(&mut rng, MUESTRAS, false);
        let b = azar(MUESTRAS);
        entrenar_y_evaluar(&a, &b)
    });
    assert!(
        !vr.distingue(),
        "el contenedor se distingue de azar: algo dentro sigue hablando. {:?}",
        vr.peor
    );
}

#[test]
fn sonda_1_discrimina_un_sesgo_global() {
    // El caso rojo DE ESTA SONDA, y el alcance importa: sus rasgos son agregados
    // de todo el blob, así que lo que tiene que cazar es un sesgo global. Se le
    // da uno grosero —ningún byte llega a 128— y ahí no puede fallar.
    let mut rng = Rng::nuevo(0xBADC0DE);
    let vr = medir_repetido(|| {
        let mut a = poblacion(&mut rng, MUESTRAS, false);
        for c in &mut a {
            for b in c.iter_mut() {
                *b &= 0x7f;
            }
        }
        let b = azar(MUESTRAS);
        entrenar_y_evaluar(&a, &b)
    });
    assert!(
        vr.distingue(),
        "la sonda agregada no vio un sesgo de bit entero: no discrimina. {:?}",
        vr.peor
    );
}

// --- Sonda 1b: ninguna POSICIÓN es predecible ------------------------------
//
// Esta sonda existe porque la de arriba NO puede contestar la pregunta del
// frente de la sospecha, y descubrirlo costó un caso rojo fallido: un mágico de
// 4 bytes en 1024 le dio 53 % de acierto, o sea nada. Sus doce rasgos son
// agregados de todo el blob y diluyen cualquier campo corto.
//
// La pregunta que sí es la del formato —«¿hay algún byte que siempre valga lo
// mismo?»— es posicional, y necesita una sonda posicional.

#[test]
fn sonda_1b_ninguna_posicion_del_contenedor_es_predecible() {
    let mut rng = Rng::nuevo(0x1D1D);
    let s = posicion_mas_delatora(&poblacion(&mut rng, MUESTRAS * 2, true));
    assert!(
        !s.delata(),
        "una posición del contenedor se puede predecir: eso es una cabecera hablando. {s}"
    );
}

#[test]
fn sonda_1b_discrimina_si_el_contenedor_grita_quipu() {
    // El caso rojo de verdad: el mágico `QUIP` estampado a mano, que es justo lo
    // que el formato nuevo existe para no tener. Si esta sonda no lo viera, su
    // verde no significaría nada.
    let mut rng = Rng::nuevo(0xBEEF);
    let mut pob = poblacion(&mut rng, MUESTRAS * 2, true);
    for c in &mut pob {
        c[..4].copy_from_slice(b"QUIP");
    }
    let s = posicion_mas_delatora(&pob);
    assert!(
        s.delata(),
        "la sonda posicional no vio un mágico en claro: no discrimina. {s}"
    );
    assert!(s.posicion < 4, "y tiene que señalar DÓNDE está: {s}");
}

#[test]
fn sonda_1b_tampoco_delata_al_azar_puro() {
    // El otro lado del filo: si el umbral fuera demasiado bajo, esta sonda
    // acusaría a cualquier cosa y su rojo tampoco significaría nada.
    let s = posicion_mas_delatora(&azar(MUESTRAS * 2));
    assert!(!s.delata(), "acusa al azar puro: el umbral está mal. {s}");
}

// --- Sonda 2: con volumen oculto contra sin él -----------------------------

#[test]
fn sonda_2_con_oculto_no_se_distingue_de_sin_oculto() {
    let mut rng = Rng::nuevo(0x5EED);
    let vr = medir_repetido(|| {
        let a = poblacion(&mut rng, MUESTRAS, true);
        let b = poblacion(&mut rng, MUESTRAS, false);
        entrenar_y_evaluar(&a, &b)
    });
    assert!(
        !vr.distingue(),
        "se distingue un contenedor con volumen oculto de uno sin él: la negación no existe. {:?}",
        vr.peor
    );
}

#[test]
fn sonda_2_discrimina_si_el_relleno_dejara_de_ser_azar() {
    // El caso rojo, y es exactamente el requisito 2 de #118: si la región del
    // oculto se rellenara con ceros cuando no hay oculto —en vez de con azar—,
    // el hueco delataría. Se simula poniendo la segunda mitad a cero.
    let mut rng = Rng::nuevo(0xF00D);
    let vr = medir_repetido(|| {
        let a = poblacion(&mut rng, MUESTRAS, true);
        let mut b = poblacion(&mut rng, MUESTRAS, false);
        for c in &mut b {
            let mitad = 16 + (S - 16) / 2;
            c[mitad..].fill(0);
        }
        entrenar_y_evaluar(&a, &b)
    });
    assert!(
        vr.distingue(),
        "la sonda no vio una región de ceros donde debía haber azar: no discrimina. {:?}",
        vr.peor
    );
}

// --- Sonda posicional de DOS poblaciones (N-SIM-1) --------------------------
//
// Las sondas 1 y 2 de arriba usan rasgos AGREGADOS (doce, sobre todo el blob),
// así que una fuga de UN BIT en UNA posición, condicionada a que exista el
// volumen oculto, se diluye 8192:1 y no la ven. La auditoría del 2026-08-17 lo
// midió: «indistinguible por construcción» es la promesa más fuerte del
// repositorio, y la sostenía el instrumento más débil.
//
// Esta sonda mira CELDA A CELDA: por cada bit del contenedor, compara la
// frecuencia entre la clase CON oculto y la clase SIN oculto. Dos estadísticos,
// porque ninguno domina al otro: MAX (fugas puntuales) y CHI2 (fugas difusas
// repartidas). Y trae su CONTROL POSITIVO —una fuga sintética inyectada— sin el
// cual sería un banco de solo-negativos sobre un artefacto hoy limpio, que no
// discrimina.

const CELDAS: usize = S * 8; // 8192

/// Frecuencia de cada bit puesto a 1, sobre una población.
fn frecuencias(pob: &[Vec<u8>]) -> Vec<f64> {
    let n = pob.len() as f64;
    let mut cuenta = vec![0u32; CELDAS];
    for c in pob {
        for (byte_i, &b) in c.iter().enumerate() {
            for bit in 0..8 {
                if (b >> bit) & 1 == 1 {
                    cuenta[byte_i * 8 + bit] += 1;
                }
            }
        }
    }
    cuenta.iter().map(|&k| k as f64 / n).collect()
}

/// (MAX |z|, CHI2) de la diferencia de proporciones celda a celda.
///
/// Bajo la hipótesis de indistinguibilidad, cada `z` ~ N(0,1) y CHI2 ~ χ²(8192).
fn estadisticos(a: &[Vec<u8>], b: &[Vec<u8>]) -> (f64, f64) {
    let n = a.len().min(b.len()) as f64;
    let fa = frecuencias(a);
    let fb = frecuencias(b);
    // var(p_A − p_B) ≈ 0.25/n + 0.25/n = 0.5/n para p ≈ 0.5.
    let sigma = (0.5 / n).sqrt();
    let mut maxz = 0.0f64;
    let mut chi2 = 0.0f64;
    for i in 0..CELDAS {
        let z = (fa[i] - fb[i]) / sigma;
        maxz = maxz.max(z.abs());
        chi2 += z * z;
    }
    (maxz, chi2)
}

// n por clase. 500 da, para una fuga DETERMINISTA de 1 bit, z ≈ 0.5·√(2·500) ≈
// 15.8 — muy por encima del umbral. Para una fuga sutil el suelo detectable es
// ~9 puntos porcentuales; se dice, no se esconde.
const N_POR_CLASE: usize = 500;

// **Los umbrales son CONSERVADORES a propósito, y aquí está el porqué.** Con
// α = 0.01 cada corrida tendría ~1,5 % de falso ROJO —el negativo es aleatorio
// de verdad, porque el salt y el relleno salen del CSPRNG real dentro de
// `crear`—, y un banco de seguridad que se pone rojo 1 de cada 70 corridas
// entrena a re-lanzarlo sin mirar (directiva 23). Se suben para que el falso
// positivo sea DESPRECIABLE, y no cuesta poder: la fuga que la sonda tiene que
// cazar da z ≈ 15,8 (ver el control positivo), a años luz de cualquiera de los
// dos umbrales, así que subirlos no afloja la detección, solo silencia el ruido.
//
// MAX: P(|Z|>6) ≈ 2e-9, y ×8192 ≈ 1,6e-5. CHI2: 8192 + 3,9·√(2·8192) ≈ 8700,
// cola ≈ 5e-5. Falso rojo combinado por debajo de 1 en 10 000 corridas.
const UMBRAL_MAX: f64 = 6.0;
const UMBRAL_CHI2: f64 = 8700.0;

#[test]
fn la_sonda_posicional_no_distingue_con_oculto_de_sin_oculto() {
    let mut rng = Rng::nuevo(0x5150_2026_0817);
    let con = poblacion(&mut rng, N_POR_CLASE, true);
    let sin = poblacion(&mut rng, N_POR_CLASE, false);

    let (maxz, chi2) = estadisticos(&con, &sin);
    assert!(
        maxz < UMBRAL_MAX,
        "una posición delata la existencia del volumen oculto: MAX |z| = {maxz:.2} ≥ {UMBRAL_MAX}"
    );
    assert!(
        chi2 < UMBRAL_CHI2,
        "el conjunto de posiciones delata el volumen oculto de forma difusa: CHI2 = {chi2:.0} ≥ {UMBRAL_CHI2}"
    );

    // **EL CONTROL POSITIVO DEL INSTRUMENTO.** Sin esto, lo de arriba pasaría
    // con un estadístico que devolviera siempre cero. Se toma la clase CON
    // oculto y se le fuerza el bit alto del byte 20 —exactamente la fuga R1 que
    // la auditoría describió, `fuera[16+D] &= 0x7F`— y se exige que AHORA sí se
    // detecte, en esa celda y no en otra.
    let mut con_fuga = con;
    for c in con_fuga.iter_mut() {
        c[20] &= 0x7f;
    }
    let (maxz_f, _) = estadisticos(&con_fuga, &sin);
    assert!(
        maxz_f >= UMBRAL_MAX,
        "el instrumento NO ve una fuga de 1 bit inyectada (MAX |z| = {maxz_f:.2}): no discrimina, \
         así que su verde de arriba no prueba nada"
    );
    // Y que la delatora sea la celda que tocamos (byte 20, bit 7 = celda 167),
    // no un falso positivo en otra parte.
    let fa = frecuencias(&con_fuga);
    let fb = frecuencias(&sin);
    let sigma = (0.5 / N_POR_CLASE as f64).sqrt();
    let delatora = (0..CELDAS)
        .max_by(|&i, &j| {
            ((fa[i] - fb[i]) / sigma).abs().partial_cmp(&((fa[j] - fb[j]) / sigma).abs()).unwrap()
        })
        .unwrap();
    assert_eq!(delatora, 20 * 8 + 7, "la celda más delatora no es la que se tocó");
}
