// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Superficie 2 (banco offline): harness de timing / canales laterales.
//!
//! Mide tiempos de operaciones sensibles y compara distribuciones para detectar
//! variación dependiente del secreto. La IA del atacante solo AMPLIFICA fugas que
//! ya existan; si no hay diferencia de tiempo, no hay traza que aprender. Ruidoso
//! y dependiente de la máquina: vive fuera del CI, dentro del contenedor.

use crate::antihacker::ct_eq;
use crate::api::{decode, encode, Options};
use crate::dictionaries;
use crate::kdf::KdfParams;
use std::time::{Duration, Instant};

/// Mediana del tiempo de `op` sobre `samples` repeticiones.
pub fn median_time(samples: usize, mut op: impl FnMut()) -> Duration {
    let n = samples.max(1);
    let mut times = Vec::with_capacity(n);
    for _ in 0..n {
        let t = Instant::now();
        op();
        times.push(t.elapsed());
    }
    times.sort_unstable();
    times[times.len() / 2]
}

/// Umbral dudect: `|t|` por encima de esto indica variación de tiempo dependiente
/// del secreto (criterio del test dudect de Reparaz et al.).
pub const DUDECT_T_THRESHOLD: f64 = 10.0;

/// Media y varianza muestral (denominador n-1) de `x`.
fn mean_var(x: &[f64]) -> (f64, f64) {
    let n = x.len() as f64;
    let mean = x.iter().sum::<f64>() / n;
    let var = x.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1.0);
    (mean, var)
}

/// t de Welch entre dos muestras de tiempos. Devuelve `0.0` si alguna muestra
/// tiene menos de 2 elementos; `±INFINITY` si la varianza combinada es 0 pero
/// las medias difieren (fuga determinista).
pub fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    if a.len() < 2 || b.len() < 2 {
        return 0.0;
    }
    let (ma, va) = mean_var(a);
    let (mb, vb) = mean_var(b);
    let denom = (va / a.len() as f64 + vb / b.len() as f64).sqrt();
    let diff = ma - mb;
    if denom == 0.0 {
        return if diff == 0.0 { 0.0 } else { f64::INFINITY * diff.signum() };
    }
    diff / denom
}

/// Comparación de tiempos entre dos clases de entrada.
pub struct TimingReport {
    /// Nombre de la comparación.
    pub name: &'static str,
    /// Mediana de la clase A.
    pub a: Duration,
    /// Mediana de la clase B.
    pub b: Duration,
}

impl TimingReport {
    /// Razón b/a (1.0 = idénticos). Evita división por cero.
    pub fn ratio(&self) -> f64 {
        let a = self.a.as_secs_f64().max(1e-12);
        self.b.as_secs_f64() / a
    }

    /// `true` si la razón está dentro de `[lo, hi]` (sin fuga gruesa de timing).
    pub fn within(&self, lo: f64, hi: f64) -> bool {
        let r = self.ratio();
        r >= lo && r <= hi
    }
}

/// Compara el tiempo de `ct_eq` cuando los buffers difieren en el PRIMER byte vs
/// en el ÚLTIMO. Una comparación en tiempo constante no debe distinguirlos.
pub fn ct_eq_timing(samples: usize) -> TimingReport {
    let base = [0x5Au8; 64];
    let mut diff_first = base;
    diff_first[0] ^= 0xFF;
    let mut diff_last = base;
    diff_last[63] ^= 0xFF;

    let a = median_time(samples, || {
        std::hint::black_box(ct_eq(&base, std::hint::black_box(&diff_first)));
    });
    let b = median_time(samples, || {
        std::hint::black_box(ct_eq(&base, std::hint::black_box(&diff_last)));
    });
    TimingReport {
        name: "ct_eq/first-vs-last-diff",
        a,
        b,
    }
}

/// Compara el tiempo de `decode` con la passphrase CORRECTA vs una INCORRECTA.
/// Ambas ejecutan la derivación Argon2id completa, que domina el coste, así que
/// no debe filtrarse por timing si la passphrase acertó.
pub fn decode_timing(samples: usize) -> TimingReport {
    let dict = dictionaries::ascii94();
    // Coste moderado: suficiente para que Argon2 domine, ágil para el banco.
    let opts = Options {
        pepper: b"",
        kdf_params: KdfParams {
            mem_kib: 8 * 1024,
            iterations: 2,
            parallelism: 1,
        },
        codebook_id: 0,
    };
    let secret = b"contenido protegido para el banco de timing";
    let sym = encode(secret, "passphrase-correcta", &dict, &opts);

    let a = median_time(samples, || {
        std::hint::black_box(decode(&sym, "passphrase-correcta", &dict, b"").is_ok());
    });
    let b = median_time(samples, || {
        std::hint::black_box(decode(&sym, "passphrase-incorrecta", &dict, b"").is_ok());
    });
    TimingReport {
        name: "decode/correct-vs-wrong-pass",
        a,
        b,
    }
}

/// Veredicto dudect: t de Welch entre dos clases de tiempos y decisión
/// constant-time.
pub struct DudectReport {
    /// Nombre de la operación evaluada.
    pub name: &'static str,
    /// t de Welch entre las dos clases.
    pub t: f64,
    /// Nº de muestras por clase (la menor de las dos).
    pub n: usize,
}

impl DudectReport {
    /// Construye el reporte a partir de dos muestras de tiempos ya recogidas.
    pub fn from_classes(name: &'static str, a: &[f64], b: &[f64]) -> Self {
        DudectReport {
            name,
            t: welch_t(a, b),
            n: a.len().min(b.len()),
        }
    }

    /// `true` si `|t|` no supera `threshold` (sin fuga detectable).
    pub fn is_constant_time(&self, threshold: f64) -> bool {
        self.t.abs() <= threshold
    }
}

/// Muestrea dos clases de tiempos **intercaladas** (A,B,A,B,…) en un único
/// bucle. Así la deriva del sistema (escalado de frecuencia de CPU, planificación,
/// calentamiento de caché) afecta a ambas clases por igual dentro de cada
/// iteración y se cancela en la diferencia de medias — requisito del método
/// dudect. Muestrear cada clase en un bucle separado (como en el bench de
/// `decode`, donde ambas clases son la *misma* operación) deja que un offset
/// sistemático entre bucles infle `|t|` de forma espuria.
fn sample_two_classes_interleaved(
    samples: usize,
    mut op_a: impl FnMut(),
    mut op_b: impl FnMut(),
) -> (Vec<f64>, Vec<f64>) {
    let n = samples.max(2);
    let mut a = Vec::with_capacity(n);
    let mut b = Vec::with_capacity(n);
    for _ in 0..n {
        let ta = Instant::now();
        op_a();
        a.push(ta.elapsed().as_nanos() as f64);
        let tb = Instant::now();
        op_b();
        b.push(tb.elapsed().as_nanos() as f64);
    }
    (a, b)
}

/// dudect sobre `ct_eq`: la clase A difiere en el PRIMER byte, la B en el ÚLTIMO.
/// Una comparación en tiempo constante no debe distinguir ambas clases. Las dos
/// clases se muestrean intercaladas para que la deriva del sistema no produzca
/// un veredicto de fuga espurio.
pub fn dudect_ct_eq(samples: usize) -> DudectReport {
    let base = [0x5Au8; 64];
    let mut diff_first = base;
    diff_first[0] ^= 0xFF;
    let mut diff_last = base;
    diff_last[63] ^= 0xFF;

    let (a, b) = sample_two_classes_interleaved(
        samples,
        || {
            std::hint::black_box(ct_eq(
                std::hint::black_box(&base),
                std::hint::black_box(&diff_first),
            ));
        },
        || {
            std::hint::black_box(ct_eq(
                std::hint::black_box(&base),
                std::hint::black_box(&diff_last),
            ));
        },
    );
    DudectReport::from_classes("dudect/ct_eq", &a, &b)
}

// --- Superficie post-cuántica ------------------------------------------------
//
// Qué se mide aquí y qué NO, que es la parte que se suele hacer mal:
//
// - `decapsulate` SÍ: toma la clave secreta. Es el único punto del modo
//   asimétrico donde un tiempo dependiente del secreto es explotable.
// - La VERIFICACIÓN de firma NO: la clave de verificación, el mensaje y la firma
//   son todos públicos. Una diferencia de tiempo ahí no revela ningún secreto,
//   así que medirla daría una cifra bonita y ninguna información.
// - El FIRMADO ML-DSA tampoco: usa muestreo por rechazo, y el número de
//   iteraciones varía POR ESPECIFICACIÓN con la aleatoriedad muestreada. Un
//   veredicto dudect ahí reportaría como fuga una propiedad documentada del
//   algoritmo, no un defecto de esta implementación.

/// dudect sobre `pqhybrid::decapsulate`: encapsulación VÁLIDA frente a CORRUPTA.
///
/// ML-KEM usa rechazo implícito: una encapsulación inválida no falla, devuelve
/// una clave de contenido distinta. Ese rechazo **debe ser indistinguible en
/// tiempo** del caso válido. Si no lo fuera, un atacante que pueda someter
/// ciphertexts al destinatario y medir obtiene un oráculo de validez — la puerta
/// de entrada a un ataque de texto cifrado elegido contra el KEM.
///
/// El par de claves se genera UNA vez, fuera del bucle: generar claves es órdenes
/// de magnitud más caro que decapsular y ahogaría la señal.
pub fn dudect_decapsulate_valid_vs_corrupt(samples: usize) -> DudectReport {
    // `expect` y no un camino permisivo: sin entropía del sistema, una medición
    // de canal lateral no es una medición peor, es un número sin significado.
    // Mejor caerse aquí que publicar una cifra inventada (directiva 20).
    let (pk, sk) = crate::pqhybrid::generate_keypair().expect("el laboratorio exige entropía");
    let (_key, valida) = crate::pqhybrid::encapsulate(&pk).expect("el laboratorio exige entropía");

    // Corrompe la parte ML-KEM, no la X25519: es el rechazo implícito de ML-KEM
    // lo que se está midiendo.
    let mut corrupta = valida.clone();
    let ultimo = corrupta.len() - 1;
    corrupta[ultimo] ^= 0x01;

    let (a, b) = sample_two_classes_interleaved(
        samples,
        || {
            std::hint::black_box(crate::pqhybrid::decapsulate(
                std::hint::black_box(&sk),
                std::hint::black_box(&valida),
            ));
        },
        || {
            std::hint::black_box(crate::pqhybrid::decapsulate(
                std::hint::black_box(&sk),
                std::hint::black_box(&corrupta),
            ));
        },
    );
    DudectReport::from_classes("dudect/decapsulate-valida-vs-corrupta", &a, &b)
}

/// dudect sobre `pqhybrid::decapsulate` con DOS claves secretas distintas sobre
/// la misma encapsulación.
///
/// Detecta tiempo dependiente de la CLAVE, que es la fuga más directa: si
/// decapsular con `sk1` tarda sistemáticamente distinto que con `sk2`, el tiempo
/// está correlacionado con el material secreto.
pub fn dudect_decapsulate_two_keys(samples: usize) -> DudectReport {
    let (pk, sk1) = crate::pqhybrid::generate_keypair().expect("el laboratorio exige entropía");
    let (_pk2, sk2) = crate::pqhybrid::generate_keypair().expect("el laboratorio exige entropía");
    let (_key, enc) = crate::pqhybrid::encapsulate(&pk).expect("el laboratorio exige entropía");

    let (a, b) = sample_two_classes_interleaved(
        samples,
        || {
            std::hint::black_box(crate::pqhybrid::decapsulate(
                std::hint::black_box(&sk1),
                std::hint::black_box(&enc),
            ));
        },
        || {
            std::hint::black_box(crate::pqhybrid::decapsulate(
                std::hint::black_box(&sk2),
                std::hint::black_box(&enc),
            ));
        },
    );
    DudectReport::from_classes("dudect/decapsulate-dos-claves", &a, &b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn median_time_measures_something() {
        let d = median_time(16, || {
            std::hint::black_box((0..100).sum::<u64>());
        });
        assert!(d >= Duration::ZERO);
    }

    #[test]
    fn ratio_and_within_work() {
        let r = TimingReport {
            name: "t",
            a: Duration::from_micros(100),
            b: Duration::from_micros(110),
        };
        assert!(r.within(0.5, 2.0));
        assert!((r.ratio() - 1.1).abs() < 0.01);
    }

    #[test]
    fn ct_eq_shows_no_gross_timing_leak() {
        let report = ct_eq_timing(2000);
        // Tolerancia amplia (ruido de máquina); solo detecta fugas GRUESAS.
        assert!(
            report.within(0.5, 2.0),
            "ct_eq no debería depender de dónde difieren los bytes: ratio={}",
            report.ratio()
        );
    }

    #[test]
    fn decode_time_independent_of_passphrase_correctness() {
        let report = decode_timing(24);
        assert!(
            report.within(0.5, 2.0),
            "decode con pass correcta vs incorrecta debe costar ~lo mismo (Argon2 domina): ratio={}",
            report.ratio()
        );
    }

    #[test]
    fn welch_t_is_zero_for_identical_samples() {
        assert_eq!(welch_t(&[1.0, 2.0, 3.0, 4.0], &[1.0, 2.0, 3.0, 4.0]), 0.0);
    }

    #[test]
    fn welch_t_is_antisymmetric() {
        let a = [2.0, 4.0, 6.0];
        let b = [1.0, 2.0, 3.0];
        assert!((welch_t(&a, &b) + welch_t(&b, &a)).abs() < 1e-12);
    }

    #[test]
    fn welch_t_known_value() {
        // a: mean 6, var 10 (n-1); b: mean 3, var 2.5; denom = sqrt(2 + 0.5).
        let a = [2.0, 4.0, 6.0, 8.0, 10.0];
        let b = [1.0, 2.0, 3.0, 4.0, 5.0];
        assert!((welch_t(&a, &b) - 1.897366).abs() < 1e-4);
    }

    #[test]
    fn welch_t_handles_too_small_samples() {
        assert_eq!(welch_t(&[1.0], &[1.0, 2.0]), 0.0);
    }

    #[test]
    fn welch_t_infinite_for_zero_variance_different_means() {
        // Zero variance in both classes but different means = deterministic leak.
        assert_eq!(welch_t(&[5.0, 5.0], &[3.0, 3.0]), f64::INFINITY);
        assert_eq!(welch_t(&[3.0, 3.0], &[5.0, 5.0]), f64::NEG_INFINITY);
        // Zero variance AND equal means = no leak.
        assert_eq!(welch_t(&[4.0, 4.0], &[4.0, 4.0]), 0.0);
    }

    #[test]
    fn dudect_verdict_constant_time_for_similar_classes() {
        // Dos clases con misma distribución (media 10, varianza pequeña) -> t≈0.
        let a: Vec<f64> = (0..100).map(|i| if i % 2 == 0 { 9.0 } else { 11.0 }).collect();
        let b = a.clone();
        let r = DudectReport::from_classes("t", &a, &b);
        assert!(r.is_constant_time(DUDECT_T_THRESHOLD), "t={}", r.t);
    }

    #[test]
    fn dudect_verdict_flags_leaky_classes() {
        // Clases con medias muy separadas (10 vs 30) -> |t| enorme -> fuga.
        let a: Vec<f64> = (0..100).map(|i| if i % 2 == 0 { 9.0 } else { 11.0 }).collect();
        let b: Vec<f64> = (0..100).map(|i| if i % 2 == 0 { 29.0 } else { 31.0 }).collect();
        let r = DudectReport::from_classes("t", &a, &b);
        assert!(!r.is_constant_time(DUDECT_T_THRESHOLD), "t={}", r.t);
    }

    #[test]
    fn interleaved_sampling_runs_both_classes_equally() {
        // El muestreo intercalado ejecuta cada clase exactamente `samples` veces
        // y devuelve vectores de igual longitud (base para que la deriva se
        // cancele: una medición de A y una de B por iteración).
        let mut count_a = 0usize;
        let mut count_b = 0usize;
        let (a, b) = sample_two_classes_interleaved(
            32,
            || count_a += 1,
            || count_b += 1,
        );
        assert_eq!(a.len(), 32);
        assert_eq!(b.len(), 32);
        assert_eq!(count_a, 32);
        assert_eq!(count_b, 32);
    }
}
