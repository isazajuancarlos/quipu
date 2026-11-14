// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

//! Vigila que `encode_base_n` siga siendo SUBCUADRÁTICO.
//!
//! Va `#[ignore]` a propósito: tarda ~30 s y mide coste, no corrección. Se corre
//! a mano al tocar el códec o al cambiar de librería de enteros grandes:
//!
//! ```text
//! cargo test --release -p quipu-nucleo --test escala_del_codec -- --ignored --nocapture
//! ```
//!
//! # Por qué existe
//!
//! Hasta el 2026-08-16 el códec era cuadrático y **nadie lo sabía**: pasaba
//! todas las pruebas de corrección, porque una implementación lenta da
//! exactamente los mismos dígitos que una rápida. 512 KiB costaban 50,7 s y
//! 10 MiB habrían costado unas 5,6 horas.
//!
//! La deriva de coste no se ve en un banco de corrección; hace falta medirla, y
//! hace falta que el número tenga un techo. Este banco es ese techo.
//!
//! # Lo que mide, y su control
//!
//! Al duplicar el tamaño de la entrada, el tiempo se multiplica por un factor
//! constante que delata el orden:
//!
//! | factor al duplicar | qué significa |
//! |---|---|
//! | ~2,0 | lineal |
//! | **~2,8** | lo de hoy: `M(m)·log m` con la multiplicación Toom-3 de `num-bigint` |
//! | ~4,0 | **cuadrático** — la regresión que este banco existe para cazar |
//!
//! El techo está en 3,4: deja sitio de sobra al ruido de una máquina cargada y
//! sigue muy por debajo del 4,0 de la regresión. Y se exige sobre la MEDIA de
//! los factores, no sobre cada uno, porque una medida suelta puede irse por un
//! planificador que no cooperó.
//!
//! **Esto solo se sostiene si la división de la librería es subcuadrática.**
//! `num-bigint` trae Burnikel-Ziegler; si algún día se cambia de librería, este
//! banco se pondrá rojo, que es exactamente lo que tiene que pasar.

use std::time::Instant;

/// Cuánto puede crecer el tiempo al duplicar la entrada antes de que lo
/// llamemos regresión. Cuadrático sería 4,0.
const FACTOR_MAXIMO: f64 = 3.4;

/// Una sola medida por encima de esto ya no es ruido: se corta ahí mismo en vez
/// de gastar veinte minutos en confirmar lo evidente.
const FACTOR_CLARAMENTE_CUADRATICO: f64 = 3.7;

#[test]
#[ignore = "mide coste, no corrección; ~30 s"]
fn el_codec_base_n_es_subcuadratico() {
    let mut previo: Option<f64> = None;
    let mut factores = Vec::new();

    for kb in [64usize, 128, 256, 512, 1024, 2048] {
        // Datos no comprimibles pero deterministas: el coste no puede depender
        // de qué máquina corre el banco.
        let data: Vec<u8> = (0..kb * 1024).map(|i| (i * 131 % 256) as u8).collect();

        let t = Instant::now();
        let indices = quipu_nucleo::codec::encode_base_n(&data, 94);
        let codificar = t.elapsed().as_secs_f64() * 1000.0;

        let t = Instant::now();
        let vuelta = quipu_nucleo::codec::decode_base_n(&indices, 94);
        let descodificar = t.elapsed().as_secs_f64() * 1000.0;

        // El control de que se mide el camino real y no un no-op.
        assert_eq!(vuelta, data, "el codec tiene que ser reversible");

        if let Some(p) = previo {
            let factor = codificar / p;
            factores.push(factor);
            println!("{kb:>5} KiB  encode {codificar:>9.1} ms  decode {descodificar:>9.1} ms  x{factor:.2}");
            // ABORTO TEMPRANO. Sin esto, un códec que volviera a ser cuadrático
            // tardaría ~20 minutos en llegar al veredicto — y el banco se
            // abandonaría por lento en vez de leerse en rojo. Comprobado el
            // 2026-08-16 corriendo el guardia contra el códec viejo: se cortó
            // por tiempo con x3,98 / x4,00 / x3,98 ya en pantalla.
            assert!(
                factor < FACTOR_CLARAMENTE_CUADRATICO,
                "x{factor:.2} al pasar de {} a {kb} KiB: esto es cuadrático, y seguir midiendo \
                 cuesta minutos. Cuadrático es x4,0; subcuadrático con Toom-3 es x2,8.",
                kb / 2
            );
        } else {
            println!("{kb:>5} KiB  encode {codificar:>9.1} ms  decode {descodificar:>9.1} ms");
        }
        previo = Some(codificar);
    }

    let medio = factores.iter().sum::<f64>() / factores.len() as f64;
    println!("factor medio al duplicar: x{medio:.2}  (techo {FACTOR_MAXIMO})");
    assert!(
        medio < FACTOR_MAXIMO,
        "el códec volvió a ser cuadrático: factor medio x{medio:.2} >= {FACTOR_MAXIMO}. \
         Cuadrático es x4,0; subcuadrático con Toom-3 es x2,8."
    );
}
