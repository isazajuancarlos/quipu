// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

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
