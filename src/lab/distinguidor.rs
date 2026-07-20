// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Superficie 6: **un adversario entrenado que intenta distinguir**.
//!
//! # Qué pregunta responde
//!
//! Toda la criptografía simétrica de Quipu descansa en una afirmación:
//! *el ciphertext es indistinguible del azar*. Se dice en `SPEC.md`, se
//! justifica citando XChaCha20-Poly1305, y hasta ahora **nadie lo había
//! medido**.
//!
//! Este módulo entrena un adversario a separar dos fuentes de bytes y devuelve
//! su acierto sobre muestras que no vio al entrenar. La lectura es directa:
//!
//! - **50 %** — no distingue. Es lo que se espera y es la evidencia que se
//!   reporta.
//! - **muy por encima de 50 %** — hay estructura filtrándose. Brecha.
//!
//! # Por qué esto vale, y a quién
//!
//! No es una función para el cliente: es **evidencia para el auditor**.
//! Convierte «creemos que no hay fuga» en «entrenamos un adversario para
//! encontrarla, no pudo, y aquí está la cifra con su margen». Ante un comité de
//! seguridad eso pesa más que cualquier función nueva.
//!
//! # Por qué NO es una red neuronal
//!
//! La tentación era usar aprendizaje automático de verdad. Se descartó por dos
//! razones, y la segunda es la que manda:
//!
//! 1. Para separar dos distribuciones de bytes, una regresión logística sobre
//!    rasgos estadísticos alcanza lo mismo que una red pequeña. Si hay sesgo,
//!    aparece en los momentos de primer y segundo orden.
//! 2. **Un auditor tiene que poder leer al adversario.** Un modelo con pesos
//!    entrenados es una caja que hay que aceptar de fe; sesenta líneas de
//!    regresión logística se verifican mirándolas. En una librería que se vende
//!    por auditable, un resultado comprobable vale más que uno sofisticado.
//!
//! Si algún día un adversario simple encontrara algo, entonces sí valdría la
//! pena traer artillería. Empezar por la artillería es empezar por el final.
//!
//! # Riesgo: ninguno
//!
//! Vive tras `feature = "lab"`, que no se compila en release ni en la rueda de
//! PyPI. El arma no viaja con el producto. Si el adversario se equivoca, lo peor
//! que pasa es que se buscó una fuga que no existía.

use crate::lab::engine::Rng;

/// Cuántos rasgos se extraen de cada muestra.
const RASGOS: usize = 12;
/// Vueltas de descenso por gradiente. Suficientes para converger en un problema
/// de doce dimensiones, y fijas para que la medición sea reproducible.
const EPOCAS: usize = 300;
const TASA: f64 = 0.5;

/// Rasgos estadísticos de una secuencia de bytes.
///
/// Se eligen porque son donde asoma el sesgo cuando un cifrador está roto: si
/// la salida no es uniforme, se nota en la frecuencia de los bytes, en el
/// equilibrio de los bits, o en que las cosas se repiten más de lo que deberían.
fn rasgos(muestra: &[u8]) -> [f64; RASGOS] {
    let n = muestra.len().max(1) as f64;

    // 0: proporción global de bits a uno. Debe rondar 0,5.
    let unos: u32 = muestra.iter().map(|b| b.count_ones()).sum();
    let monobit = unos as f64 / (n * 8.0);

    // 1..8: proporción de unos en CADA posición de bit. Un cifrador roto suele
    // sesgar unas posiciones y no otras, y el monobit global lo promedia.
    let mut por_bit = [0.0f64; 8];
    for b in muestra {
        for (i, p) in por_bit.iter_mut().enumerate() {
            *p += ((b >> i) & 1) as f64;
        }
    }
    for p in por_bit.iter_mut() {
        *p /= n;
    }

    // 9: desviación del histograma de bytes respecto a la uniforme (chi²
    // normalizado). Detecta que unos valores salgan más que otros.
    let mut hist = [0u32; 256];
    for &b in muestra {
        hist[b as usize] += 1;
    }
    let esperado = n / 256.0;
    let chi2: f64 = hist
        .iter()
        .map(|&c| {
            let d = c as f64 - esperado;
            d * d / esperado.max(1e-9)
        })
        .sum::<f64>()
        / 255.0;

    // 10: bytes consecutivos iguales. En azar, 1/256.
    let repes = muestra.windows(2).filter(|w| w[0] == w[1]).count() as f64
        / (muestra.len().max(2) - 1) as f64;

    // 11: correlación serial entre byte y siguiente, normalizada a [-1, 1].
    // Caza cualquier estructura de flujo con periodo corto.
    let media = muestra.iter().map(|&b| b as f64).sum::<f64>() / n;
    let (mut num, mut den) = (0.0f64, 0.0f64);
    for w in muestra.windows(2) {
        num += (w[0] as f64 - media) * (w[1] as f64 - media);
    }
    for &b in muestra {
        den += (b as f64 - media) * (b as f64 - media);
    }
    let serial = if den > 0.0 { num / den } else { 0.0 };

    let mut out = [0.0f64; RASGOS];
    out[0] = monobit;
    out[1..9].copy_from_slice(&por_bit);
    out[9] = chi2;
    out[10] = repes;
    out[11] = serial;
    out
}

/// Un adversario entrenado, con su acierto y el margen del azar.
#[derive(Debug, Clone, PartialEq)]
pub struct Veredicto {
    /// Acierto sobre las muestras que NO vio al entrenar, en [0, 1].
    pub acierto: f64,
    /// Muestras usadas para evaluar.
    pub evaluadas: usize,
    /// Una desviación típica del acierto bajo la hipótesis de que no distingue
    /// nada. Sirve para saber si un 53 % es señal o es ruido de muestreo.
    pub sigma: f64,
}

impl Veredicto {
    /// A cuántas sigmas del azar está el acierto observado.
    ///
    /// Es el número que se reporta. Por debajo de 3 no hay evidencia de fuga
    /// con este tamaño de muestra — que NO es lo mismo que demostrar que no la
    /// hay, y conviene no confundirlo al citarlo.
    pub fn sigmas(&self) -> f64 {
        if self.sigma <= 0.0 {
            return 0.0;
        }
        (self.acierto - 0.5) / self.sigma
    }

    /// Si el adversario encontró algo con este tamaño de muestra.
    ///
    /// Tres sigmas: el umbral habitual para no perseguir fantasmas. Con 400
    /// muestras de evaluación, sigma ronda el 2,5 %, así que hace falta pasar
    /// del 57 % para que cuente.
    pub fn distingue(&self) -> bool {
        self.sigmas() >= 3.0
    }
}

impl core::fmt::Display for Veredicto {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:.1} % de acierto sobre {} muestras ({:+.1}σ del azar) — {}",
            self.acierto * 100.0,
            self.evaluadas,
            self.sigmas(),
            if self.distingue() { "DISTINGUE" } else { "no distingue" }
        )
    }
}

/// Entrena un adversario a separar `a` de `b` y lo evalúa con muestras nuevas.
///
/// Regresión logística por descenso por gradiente, con los rasgos normalizados
/// por media y desviación del conjunto de entrenamiento. Determinista: mismas
/// entradas, mismo veredicto, en cualquier máquina.
pub fn entrenar_y_evaluar(a: &[Vec<u8>], b: &[Vec<u8>]) -> Veredicto {
    let n = a.len().min(b.len());
    if n < 4 {
        return Veredicto { acierto: 0.5, evaluadas: 0, sigma: 0.0 };
    }
    let corte = n / 2; // mitad para entrenar, mitad para evaluar

    let extraer = |v: &[Vec<u8>], desde: usize, hasta: usize| -> Vec<[f64; RASGOS]> {
        v[desde..hasta].iter().map(|m| rasgos(m)).collect()
    };
    let (tr_a, tr_b) = (extraer(a, 0, corte), extraer(b, 0, corte));
    let (ev_a, ev_b) = (extraer(a, corte, n), extraer(b, corte, n));

    // Normalización: sin ella, el chi² (que va en decenas) aplasta a los
    // rasgos que van en [0, 1] y el descenso no converge.
    let mut media = [0.0f64; RASGOS];
    let mut desv = [0.0f64; RASGOS];
    let total = (tr_a.len() + tr_b.len()) as f64;
    for x in tr_a.iter().chain(tr_b.iter()) {
        for i in 0..RASGOS {
            media[i] += x[i] / total;
        }
    }
    for x in tr_a.iter().chain(tr_b.iter()) {
        for i in 0..RASGOS {
            desv[i] += (x[i] - media[i]).powi(2) / total;
        }
    }
    for d in desv.iter_mut() {
        *d = d.sqrt().max(1e-9);
    }
    let normalizar = |x: &[f64; RASGOS]| -> [f64; RASGOS] {
        let mut o = [0.0f64; RASGOS];
        for i in 0..RASGOS {
            o[i] = (x[i] - media[i]) / desv[i];
        }
        o
    };

    let mut pesos = [0.0f64; RASGOS];
    let mut sesgo = 0.0f64;
    let sigmoide = |z: f64| 1.0 / (1.0 + (-z).exp());

    for _ in 0..EPOCAS {
        let mut grad = [0.0f64; RASGOS];
        let mut grad_sesgo = 0.0f64;
        for (conjunto, etiqueta) in [(&tr_a, 1.0f64), (&tr_b, 0.0f64)] {
            for x in conjunto {
                let x = normalizar(x);
                let z: f64 = x.iter().zip(&pesos).map(|(a, b)| a * b).sum::<f64>() + sesgo;
                let err = sigmoide(z) - etiqueta;
                for i in 0..RASGOS {
                    grad[i] += err * x[i] / total;
                }
                grad_sesgo += err / total;
            }
        }
        for i in 0..RASGOS {
            pesos[i] -= TASA * grad[i];
        }
        sesgo -= TASA * grad_sesgo;
    }

    let predice = |x: &[f64; RASGOS]| -> bool {
        let x = normalizar(x);
        let z: f64 = x.iter().zip(&pesos).map(|(a, b)| a * b).sum::<f64>() + sesgo;
        z > 0.0
    };
    let aciertos = ev_a.iter().filter(|x| predice(x)).count()
        + ev_b.iter().filter(|x| !predice(x)).count();
    let evaluadas = ev_a.len() + ev_b.len();

    Veredicto {
        acierto: aciertos as f64 / evaluadas.max(1) as f64,
        evaluadas,
        // Bajo la hipótesis nula el acierto es binomial(n, 1/2).
        sigma: if evaluadas > 0 {
            (0.25 / evaluadas as f64).sqrt()
        } else {
            0.0
        },
    }
}

/// Muestras de bytes del PRNG del laboratorio. Es el «azar» de referencia.
pub fn muestras_pseudoaleatorias(rng: &mut Rng, cuantas: usize, largo: usize) -> Vec<Vec<u8>> {
    (0..cuantas)
        .map(|_| (0..largo).map(|_| rng.byte()).collect())
        .collect()
}

/// Muestras de un cifrador ROTO a propósito: XOR con una clave corta que se
/// repite.
///
/// Existe para probar que el adversario **discrimina**. Un detector que nunca
/// dice «sí» no vale nada, y no hay forma de saber que dice «no» por buenas
/// razones si nunca se le enseña algo que sí tiene fuga.
pub fn muestras_con_fuga_sembrada(rng: &mut Rng, cuantas: usize, largo: usize) -> Vec<Vec<u8>> {
    (0..cuantas)
        .map(|_| {
            // Texto claro realista: mucho espacio y letras minúsculas, que es
            // lo que hace visible el XOR de clave corta.
            let claro: Vec<u8> = (0..largo)
                .map(|_| if rng.below(5) == 0 { b' ' } else { b'a' + (rng.byte() % 26) })
                .collect();
            let clave = [rng.byte(), rng.byte(), rng.byte()];
            claro
                .iter()
                .enumerate()
                .map(|(i, c)| c ^ clave[i % clave.len()])
                .collect()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_distingue_ruido_de_ruido() {
        // Control. Dos fuentes idénticas: si el adversario «encontrara» algo
        // aquí, estaría sobreajustando y todos los demás números sobrarían.
        let mut rng = Rng::seeded(0xC0FFEE);
        let a = muestras_pseudoaleatorias(&mut rng, 400, 256);
        let b = muestras_pseudoaleatorias(&mut rng, 400, 256);
        let v = entrenar_y_evaluar(&a, &b);
        println!("  ruido contra ruido: {v}");
        assert!(!v.distingue(), "sobreajuste: {v}");
    }

    #[test]
    fn si_distingue_una_fuga_sembrada() {
        // La prueba que hace válido al detector. Un XOR con clave de tres bytes
        // sobre texto en claro deja estructura evidente; si el adversario no la
        // encuentra, tampoco sirve su silencio en los demás casos.
        let mut rng = Rng::seeded(0xBADC0DE);
        let rotos = muestras_con_fuga_sembrada(&mut rng, 400, 256);
        let azar = muestras_pseudoaleatorias(&mut rng, 400, 256);
        let v = entrenar_y_evaluar(&rotos, &azar);
        println!("  fuga sembrada:      {v}");
        assert!(v.distingue(), "el detector NO caza una fuga evidente: {v}");
        assert!(v.acierto > 0.9, "acierto pobre ante una fuga obvia: {v}");
    }

    #[test]
    fn el_veredicto_reporta_su_propio_margen() {
        // Sin sigma, un 53 % parece un hallazgo y es ruido de muestreo. El
        // número que se cita hacia fuera tiene que llevar su margen pegado.
        let v = Veredicto { acierto: 0.53, evaluadas: 400, sigma: (0.25f64 / 400.0).sqrt() };
        assert!(!v.distingue());
        assert!(v.sigmas() < 3.0);
        assert!(v.to_string().contains("no distingue"));
    }
}

// ---------------------------------------------------------------------------
// Aplicado a Quipu
// ---------------------------------------------------------------------------

/// Muestras del ciphertext REAL de Quipu, sin cabecera.
///
/// Se recorta el contenedor: la cabecera lleva magic, versión y parámetros de
/// KDF en claro, y **es pública por diseño** (Kerckhoffs). Incluirla haría que
/// el adversario acertara el 100 % por leer `"QUIP"`, que no es una fuga sino
/// el formato. Lo que se mide es si el CIPHERTEXT filtra algo.
pub fn muestras_de_ciphertext(rng: &mut Rng, cuantas: usize, largo: usize) -> Vec<Vec<u8>> {
    use crate::api::{encode_to_blob, Options};
    use crate::kdf::KdfParams;

    // Cabecera simétrica: 68 bytes fijos (SPEC §3.2).
    const CABECERA: usize = 68;
    let opts = Options {
        pepper: b"",
        // KDF barata: no afecta a la distribución del ciphertext y hace
        // viable generar cientos de muestras.
        kdf_params: KdfParams { mem_kib: 64, iterations: 1, parallelism: 1 },
        ..Default::default()
    };
    (0..cuantas)
        .map(|_| {
            // Texto claro MUY estructurado a propósito: si el cifrado filtrara
            // contenido, esto es lo que más fácil se lo pondría.
            let claro: Vec<u8> = (0..largo).map(|i| if i % 3 == 0 { b'A' } else { b' ' }).collect();
            let clave = format!("clave-{}", rng.next_u64());
            let blob = encode_to_blob(&claro, &clave, [0u8; 8], &opts);
            blob[CABECERA.min(blob.len())..].to_vec()
        })
        .collect()
}

#[cfg(test)]
mod pruebas_sobre_quipu {
    use super::*;

    #[test]
    fn el_ciphertext_de_quipu_es_indistinguible_del_azar() {
        // LA MEDICIÓN. `SPEC.md` afirma que el ciphertext es indistinguible del
        // azar; hasta ahora se justificaba citando XChaCha20-Poly1305 y nadie
        // lo había comprobado contra la implementación.
        //
        // Se le pone fácil al adversario: todos los textos claros son la misma
        // cadena repetitiva, así que cualquier dependencia del contenido
        // saltaría.
        let mut rng = Rng::seeded(0x0DDBA11);
        let cifrado = muestras_de_ciphertext(&mut rng, 200, 256);
        let azar = muestras_pseudoaleatorias(&mut rng, 200, 256);
        let v = entrenar_y_evaluar(&cifrado, &azar);
        println!("\n  ciphertext contra azar: {v}");
        assert!(
            !v.distingue(),
            "el adversario SEPARA el ciphertext del azar: {v}. Es una brecha, \
             no un ajuste de umbral"
        );
    }

    #[test]
    fn dos_ciphertexts_de_claros_distintos_son_indistinguibles() {
        // La otra mitad: no basta con parecerse al azar, dos cifrados de
        // contenidos MUY distintos tienen que parecerse entre sí. Si no, el
        // ciphertext filtra qué se cifró.
        let mut rng = Rng::seeded(0xFEEDFACE);
        let ceros = {
            use crate::api::{encode_to_blob, Options};
            use crate::kdf::KdfParams;
            let opts = Options {
                pepper: b"",
                kdf_params: KdfParams { mem_kib: 64, iterations: 1, parallelism: 1 },
                ..Default::default()
            };
            (0..200)
                .map(|_| {
                    let clave = format!("k{}", rng.next_u64());
                    encode_to_blob(&[0u8; 256], &clave, [0u8; 8], &opts)[68..].to_vec()
                })
                .collect::<Vec<_>>()
        };
        let estructurado = muestras_de_ciphertext(&mut rng, 200, 256);
        let v = entrenar_y_evaluar(&ceros, &estructurado);
        println!("  ceros contra texto:     {v}");
        assert!(!v.distingue(), "el ciphertext filtra el contenido: {v}");
    }
}
