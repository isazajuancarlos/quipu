// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Simulación del contenedor con negación (directiva 8): más de cien
//! operaciones, concurrencia con timeout, camino de error inyectado, y la
//! prueba de que **discrimina** — porque un banco que nunca dice que no, no
//! dice nada.

//! # Por qué exige también `lab`
//!
//! Una simulación de verdad son 120 contenedores y 104 aperturas concurrentes, y
//! con el coste real de `Perfil::V1` —256 MiB por derivación— eso son ocho hilos
//! pidiendo 2 GB a la vez y varios minutos. En el CI eso no es rigor, es un job
//! que alguien acaba desactivando.
//!
//! `lab` es lo que da acceso a un perfil barato, y **el formato es idéntico**: lo
//! único que cambia es lo que tarda Argon2id, que no es lo que aquí se mide. La
//! alternativa —dejar la prueba con el perfil real y bajarla a tres iteraciones—
//! sería una simulación que no simula, con el verde de una que sí.

#![cfg(all(feature = "negacion", feature = "lab"))]

use quipu::kdf::KdfParams;
use quipu::negacion::{abrir, crear, NegacionError, Perfil, Volumen, TAMANO_MINIMO};
use std::sync::mpsc;
use std::time::Duration;

/// Cuántos contenedores completos por corrida.
const OPERACIONES: usize = 120;
const S: usize = 2048;

/// PRNG determinista: la simulación da lo mismo en cualquier máquina.
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
    fn entre(&mut self, lo: usize, hi: usize) -> usize {
        lo + (self.siguiente() as usize) % (hi - lo)
    }
}

/// Perfil barato de laboratorio. El formato es idéntico al de `Perfil::V1`.
fn perfil_de_trabajo() -> Perfil {
    Perfil::de_laboratorio(
        "simulacion",
        KdfParams {
            mem_kib: 64,
            iterations: 1,
            parallelism: 1,
        },
    )
}

const REPETICIONES: usize = OPERACIONES;

#[test]
fn ciento_veinte_contenedores_abren_los_dos_volumenes() {
    let mut rng = Rng::nuevo(0xA11CE);
    let p = perfil_de_trabajo();
    let mut abiertos = 0usize;

    for i in 0..REPETICIONES {
        let (n_s, n_o) = (rng.entre(1, 300), rng.entre(1, 300));
        let senuelo = rng.bytes(n_s);
        let oculto = rng.bytes(n_o);
        let cs = format!("senuelo-{i}");
        let co = format!("oculto-{i}");

        let c = crear(S, &senuelo, &cs, Some((oculto.as_slice(), &co)), p)
            .unwrap_or_else(|e| panic!("crear falló en la iteración {i}: {e}"));
        assert_eq!(c.len(), S, "el tamaño lo declara el usuario, no el contenido");

        let a = abrir(&c, &cs, Some(p)).expect("el señuelo abre");
        assert_eq!(a.volumen, Volumen::Senuelo);
        assert_eq!(a.datos, senuelo, "el señuelo no volvió íntegro");

        let b = abrir(&c, &co, Some(p)).expect("el oculto abre");
        assert_eq!(b.volumen, Volumen::Oculto);
        assert_eq!(b.datos, oculto, "el oculto no volvió íntegro");

        abiertos += 2;
    }
    assert_eq!(abiertos, REPETICIONES * 2);
}

#[test]
fn el_camino_de_error_inyectado_falla_siempre_y_en_todas_las_regiones() {
    // Esta es la mitad que DISCRIMINA. Si la de arriba pasara y esta también
    // pasara «sin querer» —porque abrir devolviera algo ante un contenedor
    // corrupto— la primera no probaría nada.
    let mut rng = Rng::nuevo(0xDEAD);
    let p = perfil_de_trabajo();
    let mut inyecciones = 0usize;

    for i in 0..REPETICIONES {
        let senuelo = rng.bytes(64);
        let oculto = rng.bytes(64);
        let (cs, co) = (format!("s-{i}"), format!("o-{i}"));
        let base = crear(S, &senuelo, &cs, Some((oculto.as_slice(), &co)), p).expect("crear");

        // Un byte cualquiera del contenedor, incluido el salt.
        let pos = rng.entre(0, S);
        let mut roto = base.clone();
        roto[pos] ^= 1 << (rng.entre(0, 8) as u32);

        // Con el salt tocado no abre NINGUNO; con una región tocada, esa no
        // abre. En ningún caso puede devolver datos alterados como si nada.
        for (clave, esperado) in [(&cs, Volumen::Senuelo), (&co, Volumen::Oculto)] {
            match abrir(&roto, clave, Some(p)) {
                Err(NegacionError::NoAbre) => {}
                Err(otro) => panic!("error inesperado en la iteración {i}: {otro}"),
                Ok(a) => {
                    // Solo es admisible que abra la región que NO se tocó, y en
                    // ese caso los datos tienen que ser exactamente los suyos.
                    assert_eq!(a.volumen, esperado, "abrió la región equivocada");
                    let intactos = if esperado == Volumen::Senuelo {
                        &senuelo
                    } else {
                        &oculto
                    };
                    assert_eq!(
                        &a.datos, intactos,
                        "devolvió datos ALTERADOS en vez de fallar (iteración {i}, byte {pos})"
                    );
                }
            }
        }
        inyecciones += 1;
    }
    assert_eq!(inyecciones, REPETICIONES);
}

#[test]
fn una_region_corrompida_no_arrastra_a_la_otra() {
    // Precisión sobre lo anterior: tocar la región del señuelo deja el oculto
    // intacto y al revés. Si el AEAD de una cubriera bytes de la otra, aquí se
    // vería — y el §4 del diseño prohíbe expresamente ese solape.
    let p = perfil_de_trabajo();
    let (senuelo, oculto) = (b"lo entregable".as_slice(), b"lo verdadero".as_slice());
    let base = crear(S, senuelo, "a", Some((oculto, "b")), p).expect("crear");
    let mitad = 16 + (S - 16) / 2;

    let mut toca_senuelo = base.clone();
    toca_senuelo[20] ^= 0x01;
    assert!(abrir(&toca_senuelo, "a", Some(p)).is_err());
    assert_eq!(
        abrir(&toca_senuelo, "b", Some(p)).expect("el oculto sobrevive").datos,
        oculto
    );

    let mut toca_oculto = base;
    toca_oculto[mitad + 20] ^= 0x01;
    assert!(abrir(&toca_oculto, "b", Some(p)).is_err());
    assert_eq!(
        abrir(&toca_oculto, "a", Some(p)).expect("el señuelo sobrevive").datos,
        senuelo
    );
}

#[test]
fn cien_aperturas_concurrentes_no_se_pisan_ni_se_cuelgan() {
    // Con timeout, y no por ceremonia: sin él un interbloqueo parecería una
    // compilación lenta. Es la trampa que ya costó trece minutos en `selftest`.
    let p = perfil_de_trabajo();
    let contenedor = crear(
        TAMANO_MINIMO * 4,
        b"lo entregable",
        "clave-a",
        Some((b"lo verdadero".as_slice(), "clave-b")),
        p,
    )
    .expect("crear");

    const HILOS: usize = 8;
    const POR_HILO: usize = 13; // 8 × 13 = 104 aperturas
    let (tx, rx) = mpsc::channel();

    for h in 0..HILOS {
        let tx = tx.clone();
        let c = contenedor.clone();
        std::thread::spawn(move || {
            let mut bien = 0usize;
            for i in 0..POR_HILO {
                // Alterna las tres clases: señuelo, oculto y equivocada. Cada
                // una tiene UN resultado correcto, y la equivocada lo tiene
                // igual que las otras dos: fallar.
                let correcto = match (h + i) % 3 {
                    0 => abrir(&c, "clave-a", Some(p))
                        .is_ok_and(|a| a.volumen == Volumen::Senuelo),
                    1 => abrir(&c, "clave-b", Some(p))
                        .is_ok_and(|a| a.volumen == Volumen::Oculto),
                    _ => abrir(&c, "clave-equivocada", Some(p))
                        == Err(NegacionError::NoAbre),
                };
                if correcto {
                    bien += 1;
                }
            }
            let _ = tx.send(bien);
        });
    }
    drop(tx);

    let mut total = 0usize;
    for _ in 0..HILOS {
        total += rx
            .recv_timeout(Duration::from_secs(60))
            .expect("un hilo no respondió en 60 s: interbloqueo, no lentitud");
    }
    assert_eq!(
        total,
        HILOS * POR_HILO,
        "alguna apertura concurrente dio un resultado distinto al de la secuencial"
    );
}

#[test]
fn el_perfil_equivocado_no_abre_aunque_la_contrasena_sea_la_buena() {
    // La pista del §5.3 tiene que ser NECESARIA: si un perfil cualquiera abriera,
    // los parámetros no estarían de verdad fuera del contenedor.
    let p = perfil_de_trabajo();
    let c = crear(S, b"contenido", "la buena", None, p).expect("crear");
    let otro = Perfil::V1;
    if otro.params() != p.params() {
        assert_eq!(
            abrir(&c, "la buena", Some(otro)).unwrap_err(),
            NegacionError::NoAbre,
            "abrió con un perfil que no es el suyo: los parámetros no están fuera"
        );
    }
}
