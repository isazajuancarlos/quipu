// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Banco de indistinguibilidad: I1 e I4 bajo UN vocabulario, sobre TRES señales.
//!
//! # Qué unifica y por qué
//!
//! `docs/ATAQUES_TAXONOMIA.md` (familia 2 y 4, y el punto 1 de «qué construir»)
//! pedía generalizar el distinguidor. El problema no era de potencia sino de
//! DIALECTO: hoy hay dos mecanismos que responden la MISMA pregunta —«¿algún
//! observable depende del secreto?» (I1), «¿el fallo revela algo?» (I4)— con
//! vocabularios incompatibles:
//!
//! - [`crate::lab::distinguidor`] entrena una regresión logística sobre rasgos
//!   estadísticos y reporta en **σ** (para bytes: ciphertext, y aquí también
//!   errores serializados).
//! - [`crate::lab::timing`] corre dudect y reporta una **t de Welch**.
//!
//! Un auditor recibía dos informes que no se pueden poner en la misma tabla.
//! Este módulo los pone: un [`Veredicto`] común al que ambos se CONVIERTEN, y un
//! conductor ([`evaluar_banco`]) que acepta cualquier [`Sonda`] —sea de tiempo,
//! de ciphertext o de error— y devuelve un solo informe comparable.
//!
//! # Lo que NO hace, a propósito (directiva 1)
//!
//! No reescribe el distinguidor ni dudect, ni inventa un estadístico nuevo. Cada
//! uno conserva su regla de decisión ya afinada —la mayoría 2-de-3 del
//! distinguidor, el umbral |t| = 10 de dudect—. Unifica cómo se LEE el veredicto,
//! no cómo se mide. Poner las dos escalas juntas es legítimo porque ambas son
//! «distancia al null en desviaciones típicas»: bajo la hipótesis de que no hay
//! fuga, la t de Welch es aproximadamente normal estándar, igual que las σ del
//! distinguidor. Lo que cambia entre señales es el UMBRAL, no la unidad — y por
//! eso el umbral viaja dentro del veredicto.
//!
//! # El adversario y su adaptación
//!
//! Para las señales de bytes, la adaptación es la que ya tiene el distinguidor:
//! la regresión logística REENFOCA sus pesos sobre el rasgo que más fuga, y
//! `medir_repetido` vuelve a muestrear en cada ronda. No se añade un motor de
//! consultas adaptativas arbitrarias: en el laboratorio el atacante controla las
//! dos clases (es autosabotaje), así que la potencia está en entrenar sobre la
//! diferencia, no en elegir qué preguntar.
//!
//! # La garantía de que DISCRIMINA (directiva 8)
//!
//! Un banco que siempre dijera «indistinguible» no valdría nada. Por eso cada
//! señal tiene, en las pruebas, su **fuga sembrada** —un canal deliberado— que el
//! banco DEBE marcar como `Fuga`, además del null que debe dar `Indistinguible`.
//! Sin el primero, el silencio del segundo no es evidencia de nada.
//!
//! # Riesgo: ninguno
//!
//! Vive tras `feature = "lab-offline"`: no se compila en release ni en la rueda
//! de PyPI. El arma no viaja con el producto.

use crate::lab::distinguidor::VeredictoRepetido;
// El puente hacia dudect necesita el módulo `timing`, que vive tras `lab-offline`.
// El resto del banco (bytes, conductor) no mide tiempo y está disponible con `lab`.
#[cfg(feature = "lab-offline")]
use crate::lab::timing::{DudectReport, DUDECT_T_THRESHOLD};

/// La señal donde se busca dependencia del secreto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Senal {
    /// Cuánto tarda una operación (I1 por temporización).
    Tiempo,
    /// Los bytes del ciphertext (I1 por estructura en la salida).
    Ciphertext,
    /// Los bytes de un error o su mensaje (I4: el fallo no revela nada).
    Error,
}

impl core::fmt::Display for Senal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Senal::Tiempo => "tiempo",
            Senal::Ciphertext => "ciphertext",
            Senal::Error => "error",
        })
    }
}

/// El veredicto, en el mismo vocabulario para las tres señales.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resultado {
    /// Ningún observable separó las clases por encima del umbral de su señal.
    Indistinguible,
    /// Un observable SÍ las separó: hay dependencia del secreto. Brecha.
    Fuga,
    /// No hubo muestras suficientes para concluir. NO es un aprobado — es el
    /// «no lo miré» que un banco honesto tiene que poder decir.
    NoConcluyente,
}

impl core::fmt::Display for Resultado {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Resultado::Indistinguible => "INDISTINGUIBLE",
            Resultado::Fuga => "FUGA",
            Resultado::NoConcluyente => "SIN CONCLUIR",
        })
    }
}

/// Un veredicto de indistinguibilidad, común a cualquier señal.
///
/// `sigmas` y `umbral` van en la misma unidad (desviaciones típicas del null),
/// pero el umbral es el propio de la señal: 3 para el distinguidor de bytes, 10
/// para dudect. `sigmas / umbral >= 1` es lo que hace comparables dos señales
/// distintas al ordenarlas.
#[derive(Debug, Clone)]
pub struct Veredicto {
    /// Qué propiedad se probó (p. ej. «ct_eq» o «ciphertext vs azar»).
    pub propiedad: &'static str,
    /// Sobre qué señal.
    pub senal: Senal,
    /// Con qué estadístico se midió.
    pub estadistico: &'static str,
    /// Distancia al null en σ (|t| de Welch, o σ del distinguidor).
    pub sigmas: f64,
    /// El umbral de ESTA señal por encima del cual cuenta como fuga.
    pub umbral: f64,
    /// Muestras que respaldan la medición.
    pub muestras: usize,
    /// El veredicto ya decidido por la regla de decisión de su señal.
    pub resultado: Resultado,
}

impl Veredicto {
    /// `true` solo si el resultado es `Fuga`.
    pub fn distingue(&self) -> bool {
        matches!(self.resultado, Resultado::Fuga)
    }

    /// `true` si se pudo concluir algo (aprobado o brecha), `false` si faltaron
    /// muestras. Un `false` aquí nunca es un aprobado.
    pub fn concluyente(&self) -> bool {
        !matches!(self.resultado, Resultado::NoConcluyente)
    }

    /// Cuán cerca del umbral quedó, normalizado: `>= 1.0` es fuga. Es lo que
    /// hace comparable una señal de tiempo con una de bytes pese a umbrales
    /// distintos.
    pub fn holgura(&self) -> f64 {
        if self.umbral <= 0.0 {
            return 0.0;
        }
        self.sigmas / self.umbral
    }
}

impl core::fmt::Display for Veredicto {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} [{}, {}]: {:.1}σ / umbral {:.0} sobre {} muestras — {}",
            self.propiedad,
            self.senal,
            self.estadistico,
            self.sigmas,
            self.umbral,
            self.muestras,
            self.resultado
        )
    }
}

/// dudect → vocabulario común. La `t` de Welch ES la distancia al null en σ.
///
/// Se pide un mínimo de muestras: con pocas, `|t|` es ruido y afirmar
/// «indistinguible» sería mentir por falta de datos, no por ausencia de fuga.
#[cfg(feature = "lab-offline")]
impl From<&DudectReport> for Veredicto {
    fn from(r: &DudectReport) -> Self {
        const MINIMO_FIABLE: usize = 200;
        let sigmas = r.t.abs();
        let resultado = if r.n < MINIMO_FIABLE {
            Resultado::NoConcluyente
        } else if sigmas > DUDECT_T_THRESHOLD {
            Resultado::Fuga
        } else {
            Resultado::Indistinguible
        };
        Veredicto {
            propiedad: r.name,
            senal: Senal::Tiempo,
            estadistico: "Welch-t (dudect)",
            sigmas,
            umbral: DUDECT_T_THRESHOLD,
            muestras: r.n,
            resultado,
        }
    }
}

/// El distinguidor de bytes → vocabulario común, conservando su regla de mayoría.
///
/// El `resultado` sale de [`VeredictoRepetido::distingue`] (dos de tres rondas),
/// NO de comparar `sigmas` con `umbral` a pelo: la mayoría existe para bajar la
/// falsa alarma de una-de-mil a una-de-un-millón, y saltársela aquí la anularía.
/// El `sigmas` que se reporta es el de la ronda más acusadora, para que el número
/// visible sea el peor caso.
pub fn desde_bytes(propiedad: &'static str, senal: Senal, vr: &VeredictoRepetido) -> Veredicto {
    let resultado = if vr.peor.evaluadas == 0 {
        Resultado::NoConcluyente
    } else if vr.distingue() {
        Resultado::Fuga
    } else {
        Resultado::Indistinguible
    };
    Veredicto {
        propiedad,
        senal,
        estadistico: "regresion logistica (mayoria 2/3)",
        sigmas: vr.peor.sigmas(),
        umbral: 3.0,
        muestras: vr.peor.evaluadas,
        resultado,
    }
}

/// Cualquier cosa que sepa producir un [`Veredicto`]. El conductor no distingue
/// una sonda de tiempo de una de bytes: solo le pide su veredicto.
pub trait Sonda {
    /// Mide y emite el veredicto en el vocabulario común.
    fn evaluar(&mut self) -> Veredicto;
}

/// El informe de una corrida del banco: un veredicto por sonda, leíbles juntos.
#[derive(Debug, Clone)]
pub struct InformeDelBanco {
    /// Un veredicto por sonda, en el orden en que se corrieron.
    pub veredictos: Vec<Veredicto>,
}

impl InformeDelBanco {
    /// `true` si alguna sonda encontró fuga.
    pub fn hay_fuga(&self) -> bool {
        self.veredictos.iter().any(Veredicto::distingue)
    }

    /// `true` si alguna sonda no pudo concluir. Un banco con huecos NO es un
    /// aprobado: el silencio por falta de datos se lee, no se esconde.
    pub fn hay_inconcluso(&self) -> bool {
        self.veredictos.iter().any(|v| !v.concluyente())
    }

    /// La sonda que más cerca quedó de su umbral (la que hay que mirar primero).
    pub fn peor(&self) -> Option<&Veredicto> {
        self.veredictos
            .iter()
            .max_by(|a, b| a.holgura().total_cmp(&b.holgura()))
    }

    /// Aprobado limpio: ni fuga ni huecos. Lo demás NO es aprobado.
    pub fn limpio(&self) -> bool {
        !self.veredictos.is_empty() && !self.hay_fuga() && !self.hay_inconcluso()
    }
}

impl core::fmt::Display for InformeDelBanco {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for v in &self.veredictos {
            writeln!(f, "  {v}")?;
        }
        let fugas = self.veredictos.iter().filter(|v| v.distingue()).count();
        let huecos = self.veredictos.iter().filter(|v| !v.concluyente()).count();
        write!(
            f,
            "banco: {} sondas · {fugas} con fuga · {huecos} sin concluir",
            self.veredictos.len()
        )
    }
}

/// Corre un banco de sondas y devuelve un informe único, comparable entre
/// señales. No fusiona ni promedia: cada sonda conserva su veredicto, y el
/// informe solo los ordena y los suma.
pub fn evaluar_banco(sondas: &mut [&mut dyn Sonda]) -> InformeDelBanco {
    InformeDelBanco {
        veredictos: sondas.iter_mut().map(|s| s.evaluar()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::distinguidor::{
        entrenar_y_evaluar, medir_repetido, muestras_con_fuga_sembrada,
        muestras_pseudoaleatorias,
    };
    use crate::lab::engine::Rng;
    #[cfg(feature = "lab-offline")]
    use crate::lab::timing::DudectReport;

    // --- La conversión desde dudect discrimina (señal: TIEMPO) --------------

    #[cfg(feature = "lab-offline")]
    #[test]
    fn tiempo_null_es_indistinguible_y_fuga_sembrada_es_fuga() {
        // No se mide tiempo real aquí (eso ya lo prueba `timing.rs` y sería
        // flaky): se prueba que el VOCABULARIO traduce bien dos distribuciones
        // conocidas. Null: dos clases del mismo reloj. Fuga: una desplazada, que
        // es lo que hace una rama dependiente del secreto.
        let mut rng = Rng::seeded(0x71_3E);
        let base: Vec<f64> = (0..500).map(|_| 100.0 + rng.below(10) as f64).collect();
        let igual: Vec<f64> = (0..500).map(|_| 100.0 + rng.below(10) as f64).collect();
        let null: Veredicto = (&DudectReport::from_classes("ct_eq (null)", &base, &igual)).into();
        println!("  {null}");
        assert_eq!(null.senal, Senal::Tiempo);
        assert_eq!(
            null.resultado,
            Resultado::Indistinguible,
            "dos clases del mismo reloj no deben separarse: {null}"
        );

        // Fuga sembrada: la clase B tarda sistemáticamente más (rama secreta).
        let lento: Vec<f64> = (0..500).map(|_| 140.0 + rng.below(10) as f64).collect();
        let fuga: Veredicto = (&DudectReport::from_classes("rama secreta", &base, &lento)).into();
        println!("  {fuga}");
        assert!(
            fuga.distingue(),
            "una rama dependiente del secreto DEBE marcarse como fuga: {fuga}"
        );
    }

    #[cfg(feature = "lab-offline")]
    #[test]
    fn tiempo_con_pocas_muestras_no_concluye() {
        // Con poquísimas muestras, |t| es ruido: afirmar «indistinguible» sería
        // mentir por falta de datos. Tiene que salir SIN CONCLUIR.
        let a = [100.0, 101.0, 99.0];
        let b = [130.0, 131.0, 129.0];
        let v: Veredicto = (&DudectReport::from_classes("pocas", &a, &b)).into();
        assert_eq!(v.resultado, Resultado::NoConcluyente, "{v}");
        assert!(!v.concluyente());
    }

    // --- La conversión desde el distinguidor discrimina (señal: CIPHERTEXT) --

    #[test]
    fn ciphertext_null_es_indistinguible_y_fuga_sembrada_es_fuga() {
        let mut rng = Rng::seeded(0xC1_9E_47);
        // Null: azar contra azar. Debe quedar indistinguible.
        let null = desde_bytes(
            "azar vs azar",
            Senal::Ciphertext,
            &medir_repetido(|| {
                let a = muestras_pseudoaleatorias(&mut rng, 300, 256);
                let b = muestras_pseudoaleatorias(&mut rng, 300, 256);
                entrenar_y_evaluar(&a, &b)
            }),
        );
        println!("  {null}");
        assert_eq!(null.senal, Senal::Ciphertext);
        assert_eq!(null.resultado, Resultado::Indistinguible, "{null}");

        // Fuga: XOR con clave corta contra azar. Debe marcarse.
        let fuga = desde_bytes(
            "xor-repetido vs azar",
            Senal::Ciphertext,
            &medir_repetido(|| {
                let rotos = muestras_con_fuga_sembrada(&mut rng, 300, 256);
                let azar = muestras_pseudoaleatorias(&mut rng, 300, 256);
                entrenar_y_evaluar(&rotos, &azar)
            }),
        );
        println!("  {fuga}");
        assert!(fuga.distingue(), "el XOR de clave corta DEBE delatarse: {fuga}");
    }

    // --- La MISMA maquinaria sobre la señal de ERROR (I4) -------------------

    #[test]
    fn error_uniforme_es_indistinguible_y_error_que_delata_la_causa_es_fuga() {
        // I4 bajo el mismo vocabulario: un error se serializa a bytes y se le
        // pasa al distinguidor. Si dos causas producen el MISMO error, el
        // adversario no las separa; si el error embebe la causa, sí.
        let repetir = |s: &[u8], n: usize| -> Vec<Vec<u8>> { (0..n).map(|_| s.to_vec()).collect() };

        // Null: las dos causas dan un error byte-idéntico (lo que exige I4).
        let mensaje = b"error: no se pudo descifrar";
        let a_null = repetir(mensaje, 300);
        let b_null = repetir(mensaje, 300);
        let null = desde_bytes(
            "error uniforme por causa",
            Senal::Error,
            &medir_repetido(|| entrenar_y_evaluar(&a_null, &b_null)),
        );
        println!("  {null}");
        assert_eq!(null.senal, Senal::Error);
        assert_eq!(
            null.resultado,
            Resultado::Indistinguible,
            "dos errores idénticos no pueden separarse: {null}"
        );

        // Fuga sembrada: el error embebe la causa (el fallo clásico de I4).
        let a_fuga = repetir(b"error: passphrase incorrecta", 300);
        let b_fuga = repetir(b"error: etiqueta AEAD invalida", 300);
        let fuga = desde_bytes(
            "error que delata la causa",
            Senal::Error,
            &medir_repetido(|| entrenar_y_evaluar(&a_fuga, &b_fuga)),
        );
        println!("  {fuga}");
        assert!(
            fuga.distingue(),
            "un error que nombra la causa DEBE marcarse como fuga: {fuga}"
        );
    }

    // --- El conductor: un banco de sondas, un informe comparable ------------

    /// Sonda de prueba que devuelve un veredicto fijo, para probar el conductor
    /// sin pagar el coste de una medición real.
    struct SondaFija(Veredicto);
    impl Sonda for SondaFija {
        fn evaluar(&mut self) -> Veredicto {
            self.0.clone()
        }
    }

    fn v(senal: Senal, sigmas: f64, umbral: f64, resultado: Resultado) -> Veredicto {
        Veredicto {
            propiedad: "prueba",
            senal,
            estadistico: "fijo",
            sigmas,
            umbral,
            muestras: 500,
            resultado,
        }
    }

    #[test]
    fn el_banco_junta_tres_senales_y_reporta_limpio() {
        let mut t = SondaFija(v(Senal::Tiempo, 2.0, 10.0, Resultado::Indistinguible));
        let mut c = SondaFija(v(Senal::Ciphertext, 1.0, 3.0, Resultado::Indistinguible));
        let mut e = SondaFija(v(Senal::Error, 0.5, 3.0, Resultado::Indistinguible));
        let informe = evaluar_banco(&mut [&mut t, &mut c, &mut e]);
        println!("{informe}");
        assert_eq!(informe.veredictos.len(), 3);
        assert!(informe.limpio(), "sin fuga ni huecos debe ser limpio");
        assert!(!informe.hay_fuga());
    }

    #[test]
    fn el_banco_marca_la_fuga_y_senala_la_peor() {
        // Una fuga de tiempo (11σ sobre umbral 10) y una de ciphertext más
        // grave (9σ sobre umbral 3 = holgura 3). La «peor» debe ser la de más
        // holgura, no la de más sigmas — es lo que hace comparables las señales.
        let mut t = SondaFija(v(Senal::Tiempo, 11.0, 10.0, Resultado::Fuga));
        let mut c = SondaFija(v(Senal::Ciphertext, 9.0, 3.0, Resultado::Fuga));
        let informe = evaluar_banco(&mut [&mut t, &mut c]);
        assert!(informe.hay_fuga());
        assert!(!informe.limpio());
        let peor = informe.peor().expect("hay veredictos");
        assert_eq!(
            peor.senal,
            Senal::Ciphertext,
            "la peor es la de más holgura (3.0), no la de más sigmas (11)"
        );
    }

    #[test]
    fn un_hueco_no_es_un_aprobado() {
        // Un SIN CONCLUIR contamina el informe: no es limpio, aunque no haya
        // fuga. Es la regla del verificador aplicada al banco.
        let mut t = SondaFija(v(Senal::Tiempo, 0.0, 10.0, Resultado::NoConcluyente));
        let mut c = SondaFija(v(Senal::Ciphertext, 1.0, 3.0, Resultado::Indistinguible));
        let informe = evaluar_banco(&mut [&mut t, &mut c]);
        assert!(informe.hay_inconcluso());
        assert!(!informe.limpio(), "un hueco no puede pasar por aprobado");
        assert!(!informe.hay_fuga());
    }
}
