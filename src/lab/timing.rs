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

/// dudect sobre el RECHAZO: ¿tarda distinto fallar por una causa que por otra?
///
/// Cierra la mitad que `tests/invariantes.rs` dejó abierta a propósito. Aquella
/// prueba demuestra que seis caminos de fallo devuelven el MISMO error; esta
/// pregunta lo que aquella no puede: si tardan lo mismo. Un mensaje idéntico con
/// tiempos distintos sigue siendo un oráculo — el atacante deja de leer el error
/// y mira el reloj.
///
/// # Qué se compara, y por qué justo eso
///
/// Clase A: **passphrase equivocada**, cabecera intacta.
/// Clase B: **tag alterado**, passphrase correcta.
///
/// Las dos pagan Argon2id entero y fallan en la verificación AEAD. Si el tiempo
/// las separa, el atacante sabe si acertó la contraseña aunque el error no se lo
/// diga, y eso convierte una búsqueda en dos.
///
/// # La comparación que NO se hace, y es la parte importante
///
/// Hay un tercer camino con una diferencia de tiempo enorme: un contenedor con
/// parámetros KDF absurdos se rechaza en microsegundos porque `is_sane()` corta
/// ANTES de derivar la clave, mientras los otros dos pagan Argon2 completo.
/// Mismo error, tiempos que difieren en órdenes de magnitud.
///
/// **No es un oráculo, y medirlo como si lo fuera sería un hallazgo falso.** Lo
/// que ese tiempo revela es que la cabecera traía basura — un dato que el
/// atacante puso él mismo y ya conoce. I4 exige que el fallo no revele nada
/// SOBRE EL SECRETO; no que todos los rechazos del mundo tarden igual. Confundir
/// las dos cosas llenaría el informe de falsos positivos y acabaría con alguien
/// desactivando la sonda.
///
/// # Por qué con parámetros KDF BARATOS
///
/// Con los de producción, Argon2id domina el tiempo y taparía cualquier
/// diferencia del AEAD: la medición saldría limpia por el motivo equivocado.
/// Con parámetros baratos, una diferencia de unas pocas instrucciones sí es
/// visible. Es la condición MÁS exigente, no la más cómoda: si aquí no aparece,
/// en producción tampoco.
pub fn dudect_rechazo_por_causa(samples: usize) -> DudectReport {
    use crate::api::{decode_from_blob, encode_to_blob, Options};
    use crate::kdf::KdfParams;

    let opts = Options {
        pepper: b"",
        kdf_params: KdfParams { mem_kib: 64, iterations: 1, parallelism: 1 },
        codebook_id: 0,
    };
    let clave = "la-passphrase-correcta";
    let blob = encode_to_blob(b"contenido de la medicion", clave, [0u8; 8], &opts);

    // Clase B: mismo contenedor con el último byte del tag volteado.
    let mut con_tag_roto = blob.clone();
    let ultimo = con_tag_roto.len() - 1;
    con_tag_roto[ultimo] ^= 0x01;

    let (a, b) = sample_two_classes_interleaved(
        samples,
        || {
            std::hint::black_box(decode_from_blob(
                std::hint::black_box(&blob),
                std::hint::black_box("passphrase-equivocada"),
                [0u8; 8],
                b"",
            ))
            .ok();
        },
        || {
            std::hint::black_box(decode_from_blob(
                std::hint::black_box(&con_tag_roto),
                std::hint::black_box(clave),
                [0u8; 8],
                b"",
            ))
            .ok();
        },
    );
    DudectReport::from_classes("dudect/rechazo-passphrase-vs-tag", &a, &b)
}

/// Cuánto puede diferir la mediana de las dos clases antes de sospechar.
///
/// AQUÍ NO SIRVE WELCH-t, Y ENTENDER POR QUÉ COSTÓ TRES INTENTOS. La t crece con
/// la raíz del número de muestras para CUALQUIER diferencia sistemática real, y
/// aquí hay dos reales a la vez: la del cortocircuito, que es la que se busca, y
/// el residuo de Ed25519 tardando distinto al verificar una firma válida que una
/// inválida — inevitable, porque para probar el combinador `ed_ok` TIENE que
/// diferir entre clases. Con más muestras las dos cruzan cualquier umbral fijo;
/// la t no las separa nunca.
///
/// Lo que sí las separa es el TAMAÑO DEL EFECTO: el cortocircuito se ahorra una
/// verificación ML-DSA entera, que son tres cuartos de milisegundo, mientras el
/// residuo de Ed25519 son unos microsegundos. Medido en esta máquina, cinco
/// rondas de cada:
///
///   sin cortocircuito   diferencia de medianas entre 0,6 % y 1,3 %
///   con cortocircuito   entre 79,6 % y 80,1 %
///
/// Sesenta veces de separación, y las dos distribuciones estrechas. El umbral en
/// el 20 % queda holgado por los dos lados.
pub const CORTOCIRCUITO_DIFERENCIA_MAXIMA: f64 = 0.20;

/// Diferencia relativa entre las medianas de dos series de tiempos.
///
/// Mediana y no media: un pico del planificador arrastra la media y no toca la
/// mediana, y en una máquina compartida esos picos son la norma.
fn diferencia_de_medianas(a: &[f64], b: &[f64]) -> f64 {
    let mediana = |v: &[f64]| {
        let mut s = v.to_vec();
        s.sort_by(f64::total_cmp);
        s[s.len() / 2]
    };
    let (ma, mb) = (mediana(a), mediana(b));
    if mb <= 0.0 {
        return 0.0;
    }
    (ma - mb).abs() / mb
}

/// dudect sobre la VERIFICACIÓN de firma: ¿delata el tiempo qué mitad falló?
///
/// # La defensa que vigila
///
/// `VerifyingKey::verify` calcula `ed_ok` y `ml_ok` como dos `let` SEPARADOS y
/// solo después hace `ed_ok && ml_ok`. Las dos mitades se verifican siempre,
/// pase lo que pase con la primera. Eso es correcto y es fácil de romper: basta
/// con que alguien «optimice» a `self.ed.verify(..).is_ok() && self.ml.verify(..)`
/// para que Rust cortocircuite y la mitad post-cuántica deje de calcularse
/// cuando la clásica ya falló.
///
/// # Por qué ese cortocircuito sería una fuga
///
/// ML-DSA-87 es órdenes de magnitud más lenta que Ed25519. Con cortocircuito,
/// una firma con la mitad clásica rota se rechazaría casi al instante, y una con
/// la clásica buena y la post-cuántica rota tardaría lo que tarda ML-DSA. Un
/// falsificador mide el reloj y sabe si acertó la mitad Ed25519 — y entonces
/// puede atacar las dos mitades POR SEPARADO en vez de a la vez, que es
/// exactamente lo que el combinador AND existe para impedir. Dos búsquedas de
/// una dimensión en lugar de una de dos.
///
/// # Lo que NO se mide, y por qué
///
/// La FIRMA en sí no se mide contra dos claves distintas, y la tentación era
/// grande. ML-DSA usa muestreo por rechazo: el bucle de firma se repite hasta
/// dar con una firma válida, y el número de vueltas varía. Dos claves distintas
/// darían tiempos distintos SIEMPRE, y dudect lo marcaría como fuga.
///
/// Sería un hallazgo falso: es una propiedad documentada del algoritmo, no un
/// defecto de Quipu, y FIPS 204 la asume. Medirlo llenaría el informe de ruido
/// y acabaría con alguien desactivando la sonda — el mismo razonamiento que
/// dejó fuera el rechazo por parámetros KDF absurdos.
pub fn dudect_verificacion_no_cortocircuita(samples: usize) -> f64 {
    let (vk, sk) = crate::pqsign::generate_keypair();
    let mensaje = b"mensaje que alguien querria falsificar";
    let firma = sk.sign(mensaje);

    // LAS DOS CLASES ROMPEN LA MITAD POST-CUÁNTICA. Es la parte que hay que
    // hacer bien, y el primer intento la hizo mal.
    //
    // La comparación evidente —una clase con la mitad clásica rota, otra con la
    // post-cuántica rota— NO mide el cortocircuito: mide el tiempo de ML-DSA
    // verificando una firma VÁLIDA contra una INVÁLIDA, que legítimamente
    // difiere porque rechazar puede cortar antes. Medido: |t| de 184, y el
    // código NO cortocircuita. Habría sido un hallazgo falso sobre una defensa
    // que está bien puesta.
    //
    // Para aislar el combinador, ML-DSA tiene que hacer EL MISMO trabajo en las
    // dos clases: fallar. Lo único que cambia es si la mitad clásica pasó antes.
    // Con cortocircuito, la clase donde Ed25519 ya falló se saltaría ML-DSA
    // entera y sería mucho más rápida. Sin él, las dos pagan lo mismo.
    let ultimo = firma.len() - 1;

    // Clase A: las DOS rotas. Con cortocircuito, ML-DSA ni se ejecuta.
    //
    // SE TOCA `S`, NO `R`, y esto costó una medición entera. Una firma Ed25519
    // es `R ‖ S`: 32 bytes de punto y 32 de escalar. Voltear un byte de `R`
    // puede dejarlo fuera de la curva, y entonces `verify_strict` rechaza al
    // instante sin hacer el trabajo — pero solo A VECES, según la clave que
    // toque. Medido: con `R` roto, la clase A tardaba la mitad que la B en dos
    // corridas de tres y lo mismo en la otra. Una clase que cambia de coste
    // según el sorteo no es una clase.
    //
    // Volteando el byte BAJO de `S`, el escalar sigue siendo canónico, la
    // verificación se hace entera y falla al final. Coste estable, que es lo
    // que una medición necesita.
    let mut ambas_rotas = firma.clone();
    ambas_rotas[crate::pqsign::ED25519_SIG_LEN / 2] ^= 0x01;
    ambas_rotas[ultimo] ^= 0x01;

    // Clase B: solo la post-cuántica rota. Ed25519 valida, así que ML-DSA se
    // ejecuta sí o sí.
    let mut ml_rota = firma.clone();
    ml_rota[ultimo] ^= 0x01;

    let (a, b) = sample_two_classes_interleaved(
        samples,
        || {
            std::hint::black_box(
                std::hint::black_box(&vk).verify(std::hint::black_box(mensaje), std::hint::black_box(&ambas_rotas)),
            );
        },
        || {
            std::hint::black_box(
                std::hint::black_box(&vk).verify(std::hint::black_box(mensaje), std::hint::black_box(&ml_rota)),
            );
        },
    );
    let _ = DudectReport::from_classes("dudect/verificacion-sin-cortocircuito", &a, &b);
    diferencia_de_medianas(&a, &b)
}

/// dudect sobre `derive_subkey`: ¿depende el tiempo de la CLAVE MAESTRA?
///
/// Es la ruta con secreto que faltaba por cubrir. HKDF-SHA256 hace un número
/// fijo de operaciones sea cual sea el contenido de la clave, así que el tiempo
/// no debería moverse — pero eso es una afirmación sobre la implementación de
/// `hkdf`, y las afirmaciones sin medir son las que este proyecto lleva un día
/// corrigiendo.
///
/// Si el tiempo dependiera de la maestra, un atacante con acceso a la máquina
/// podría ir acotándola sin verla: es la fuga más directa que existe, porque el
/// observable está correlacionado con el material secreto mismo y no con una
/// consecuencia suya.
///
/// Las dos maestras son ARBITRARIAS y muy distintas entre sí —todo ceros contra
/// todo unos— a propósito: si hubiera dependencia del contenido, ese par es
/// donde más se notaría. Un par de claves aleatorias podría, por azar, ser
/// parecido en lo que sea que importe.
pub fn dudect_derive_subkey_dos_maestras(samples: usize) -> DudectReport {
    let maestra_a = [0x00u8; crate::kdf::KEY_LEN];
    let maestra_b = [0xFFu8; crate::kdf::KEY_LEN];
    let info = b"quipu/subclave/medicion";

    let (a, b) = sample_two_classes_interleaved(
        samples,
        || {
            std::hint::black_box(crate::kdf::derive_subkey(
                std::hint::black_box(&maestra_a),
                std::hint::black_box(info),
            ));
        },
        || {
            std::hint::black_box(crate::kdf::derive_subkey(
                std::hint::black_box(&maestra_b),
                std::hint::black_box(info),
            ));
        },
    );
    DudectReport::from_classes("dudect/derive-subkey-dos-maestras", &a, &b)
}

/// Sonda 3 del §8 de `docs/DISENO_NEGACION.md`: **abrir el señuelo y abrir el
/// volumen oculto tienen que costar lo mismo**.
///
/// Si el oculto tardara distinto, el reloj sería el campo que todo el formato
/// existe para no tener: bastaría cronometrar a quien abre para saber cuál de
/// los dos volúmenes tiene. Es la razón por la que [`crate::negacion`] prueba
/// SIEMPRE las dos regiones aunque la primera acierte.
///
/// El perfil es de laboratorio a propósito: con el coste real de `Perfil::V1`
/// (256 MiB) cada muestra tardaría cientos de milisegundos y el Argon2id común
/// a las dos clases ahogaría la diferencia que se busca medir. Con el coste
/// bajo, lo que domina es justo lo que se quiere comparar.
#[cfg(feature = "negacion")]
pub fn dudect_negacion_senuelo_vs_oculto(samples: usize) -> DudectReport {
    use crate::negacion::{abrir, crear, Perfil};

    let perfil = Perfil::de_laboratorio(
        "medicion",
        crate::kdf::KdfParams { mem_kib: 64, iterations: 1, parallelism: 1 },
    );
    let contenedor = crear(
        4096,
        b"lo que se entrega",
        "clave-del-senuelo",
        Some((b"lo que no".as_slice(), "clave-del-oculto")),
        perfil,
    )
    .expect("el contenedor de la medición se crea");

    let (a, b) = sample_two_classes_interleaved(
        samples,
        || {
            std::hint::black_box(abrir(
                std::hint::black_box(&contenedor),
                std::hint::black_box("clave-del-senuelo"),
                Some(perfil),
            ))
            .ok();
        },
        || {
            std::hint::black_box(abrir(
                std::hint::black_box(&contenedor),
                std::hint::black_box("clave-del-oculto"),
                Some(perfil),
            ))
            .ok();
        },
    );
    DudectReport::from_classes("dudect/negacion-senuelo-vs-oculto", &a, &b)
}

/// La otra mitad de la sonda 3: **acertar y fallar cuestan lo mismo**, con un
/// perfil dado.
///
/// Esta propiedad es más débil que la de arriba y conviene no exagerarla: el
/// adversario ya ve si la contraseña abrió o no, porque recibe el contenido. Se
/// mide igualmente porque una diferencia grande aquí delataría que el camino de
/// fallo corta antes, y de ahí a filtrar CUÁL región falló hay un paso.
#[cfg(feature = "negacion")]
pub fn dudect_negacion_acierto_vs_fallo(samples: usize) -> DudectReport {
    use crate::negacion::{abrir, crear, Perfil};

    let perfil = Perfil::de_laboratorio(
        "medicion",
        crate::kdf::KdfParams { mem_kib: 64, iterations: 1, parallelism: 1 },
    );
    let contenedor = crear(4096, b"lo que se entrega", "buena", None, perfil)
        .expect("el contenedor de la medición se crea");

    let (a, b) = sample_two_classes_interleaved(
        samples,
        || {
            std::hint::black_box(abrir(
                std::hint::black_box(&contenedor),
                std::hint::black_box("buena"),
                Some(perfil),
            ))
            .ok();
        },
        || {
            std::hint::black_box(abrir(
                std::hint::black_box(&contenedor),
                std::hint::black_box("malaa"),
                Some(perfil),
            ))
            .ok();
        },
    );
    DudectReport::from_classes("dudect/negacion-acierto-vs-fallo", &a, &b)
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
    fn el_rechazo_no_delata_su_causa_por_el_tiempo() {
        // TRES RONDAS, MAYORÍA PARA ACUSAR. Es el mismo criterio que
        // `distinguidor::medir_repetido` y por la misma razón: la medición no es
        // reproducible —cada corrida pide sal y nonce nuevos, y el planificador
        // del sistema mete ruido— así que un umbral fijo cruza por azar de vez
        // en cuando. Una prueba cuyo mensaje de fallo dice «oráculo de tiempo»
        // no puede saltar por una migración de CPU.
        //
        // Con 2 de 3 la falsa alarma es despreciable, y NO esconde nada: una
        // fuga real da |t| enorme en las tres rondas, no en una.
        let mut ts = Vec::new();
        for _ in 0..3 {
            ts.push(dudect_rechazo_por_causa(300).t.abs());
        }
        let acusan = ts.iter().filter(|t| **t > DUDECT_T_THRESHOLD).count();
        assert!(
            acusan < 2,
            "el tiempo de rechazo DELATA la causa: |t| = {ts:?} con umbral {DUDECT_T_THRESHOLD}. \
             Fallar por passphrase y fallar por tag tardan distinto, así que el atacante \
             sabe si acertó la contraseña aunque el error no se lo diga."
        );
    }

    #[test]
    fn la_verificacion_no_delata_que_mitad_fallo() {
        // Tres rondas, mayoría para acusar: mismo criterio que el resto del
        // banco de tiempos, y por la misma razón.
        let ds: Vec<f64> = (0..3)
            .map(|_| dudect_verificacion_no_cortocircuita(120))
            .collect();
        let acusan = ds
            .iter()
            .filter(|d| **d > CORTOCIRCUITO_DIFERENCIA_MAXIMA)
            .count();
        assert!(
            acusan < 2,
            "la verificación CORTOCIRCUITA: diferencia de medianas {:?} con umbral \
             {:.0} %. Si la mitad clásica falla y ML-DSA deja de ejecutarse, un \
             falsificador mide el reloj y sabe cuál de las dos acertó — y entonces \
             ataca las dos por separado, que es justo lo que el combinador AND \
             existe para impedir.",
            ds.iter().map(|d| format!("{:.1}%", d * 100.0)).collect::<Vec<_>>(),
            CORTOCIRCUITO_DIFERENCIA_MAXIMA * 100.0
        );
    }

    #[test]
    fn derivar_una_subclave_no_depende_de_la_maestra() {
        let ts: Vec<f64> = (0..3)
            .map(|_| dudect_derive_subkey_dos_maestras(3000).t.abs())
            .collect();
        let acusan = ts.iter().filter(|t| **t > DUDECT_T_THRESHOLD).count();
        assert!(
            acusan < 2,
            "el tiempo de `derive_subkey` DEPENDE de la clave maestra: |t| = {ts:?}. \
             Es la fuga más directa que existe: el observable está correlacionado \
             con el material secreto mismo."
        );
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
