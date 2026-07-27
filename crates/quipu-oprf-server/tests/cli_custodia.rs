// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! La CLI `custodia-seed`, ejercitada como la usaría el operador.
//!
//! `restauracion_del_seed.rs` prueba que el SERVICIO restaurado sirve la misma
//! clave. Esto prueba lo otro: que el comando con el que se llega hasta ahí
//! hace lo que dice — incluido negarse cuando debe. Es la herramienta que solo
//! se toca el día del desastre, así que la única forma de que funcione ese día
//! es que el CI la ejecute todos los días.
#![cfg(feature = "custodia")]

use std::io::Write;
use std::process::{Command, Stdio};

/// Ejecuta la CLI con `entrada` por stdin. Devuelve (éxito, stdout, stderr).
fn correr(args: &[&str], entrada: &str) -> (bool, String, String) {
    let bin = env!("CARGO_BIN_EXE_custodia-seed");
    let mut hijo = Command::new(bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("lanzar custodia-seed");
    hijo.stdin
        .as_mut()
        .expect("stdin")
        .write_all(entrada.as_bytes())
        .expect("escribir");
    let salida = hijo.wait_with_output().expect("esperar");
    (
        salida.status.success(),
        String::from_utf8_lossy(&salida.stdout).to_string(),
        String::from_utf8_lossy(&salida.stderr).to_string(),
    )
}

/// Seeds de prueba, deterministas y evidentemente falsos.
const SEED: &str = "3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c";
const OTRO: &str = "7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e";

/// Líneas de la salida de `repartir` que no son comentario: la primera es la
/// clave pública, el resto son comparticiones.
fn util(salida: &str) -> Vec<String> {
    salida
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

#[test]
fn el_ciclo_de_la_cli_devuelve_el_mismo_seed() {
    let (ok, out, _) = correr(&["repartir", "--umbral", "2", "--partes", "3"], SEED);
    assert!(ok, "repartir falló");
    let v = util(&out);
    assert_eq!(v.len(), 4, "esperaba clave pública + 3 comparticiones");
    let (publica, partes) = (&v[0], &v[1..]);

    // Cualquier PAR reconstruye: las tres combinaciones, no solo una.
    for (a, b) in [(0, 1), (0, 2), (1, 2)] {
        let entrada = format!("{}\n{}\n", partes[a], partes[b]);
        let (ok, seed, _) = correr(
            &["restaurar", "--clave-publica", publica, "--mostrar-seed"],
            &entrada,
        );
        assert!(ok, "restaurar con ({a},{b}) falló");
        assert_eq!(seed.trim(), SEED, "el par ({a},{b}) devolvió otro seed");
    }
}

#[test]
fn sin_la_bandera_comprueba_pero_no_entrega_el_seed() {
    let (_, out, _) = correr(&["repartir", "--umbral", "2", "--partes", "3"], SEED);
    let v = util(&out);
    let entrada = format!("{}\n{}\n", v[1], v[2]);

    let (ok, stdout, stderr) = correr(&["restaurar", "--clave-publica", &v[0]], &entrada);
    assert!(ok);
    assert!(stderr.contains('✓'), "debía confirmar que sirven");
    assert!(
        !stdout.contains(SEED),
        "sin --mostrar-seed el seed NO puede salir por stdout"
    );
}

/// EL CASO QUE DA VALOR AL RESTO: comparticiones perfectamente válidas, de otro
/// reparto. Reconstruyen sin error y derivan otra clave. Si la CLI las
/// aceptara, diría «restaurado» ante el material equivocado.
#[test]
fn comparticiones_de_otro_seed_se_rechazan() {
    let (_, mias, _) = correr(&["repartir", "--umbral", "2", "--partes", "3"], SEED);
    let (_, ajenas, _) = correr(&["repartir", "--umbral", "2", "--partes", "3"], OTRO);
    let (publica, otras) = (util(&mias)[0].clone(), util(&ajenas));

    let entrada = format!("{}\n{}\n", otras[1], otras[2]);
    let (ok, stdout, stderr) = correr(
        &["restaurar", "--clave-publica", &publica, "--mostrar-seed"],
        &entrada,
    );
    assert!(!ok, "tenía que fallar");
    assert!(stdout.trim().is_empty(), "no puede entregar ningún seed");
    assert!(
        stderr.contains("OTRA clave"),
        "el motivo tiene que ser explícito: {stderr}"
    );
}

#[test]
fn por_debajo_del_umbral_no_reconstruye() {
    let (_, out, _) = correr(&["repartir", "--umbral", "3", "--partes", "5"], SEED);
    let v = util(&out);
    let entrada = format!("{}\n{}\n", v[1], v[2]); // dos, hacen falta tres
    let (ok, _, stderr) = correr(&["restaurar", "--clave-publica", &v[0]], &entrada);
    assert!(!ok);
    assert!(stderr.contains("reconstruir"), "stderr: {stderr}");
}

#[test]
fn los_parametros_imposibles_se_rechazan() {
    // Umbral 1 sería una copia entera con pasos de más.
    let (ok, _, _) = correr(&["repartir", "--umbral", "1", "--partes", "3"], SEED);
    assert!(!ok, "umbral 1 no puede aceptarse");

    // Más umbral que partes: nunca se podría reconstruir.
    let (ok, _, _) = correr(&["repartir", "--umbral", "4", "--partes", "3"], SEED);
    assert!(!ok, "umbral > partes no puede aceptarse");

    // Seed de longitud equivocada.
    let (ok, _, stderr) = correr(&["repartir", "--umbral", "2", "--partes", "3"], "3c3c3c");
    assert!(!ok);
    assert!(stderr.contains("64"), "stderr: {stderr}");
}

/// La salida de `repartir` se pega tal cual en `restaurar`, comentarios
/// incluidos. Si el parser no los tolerara, el operador tendría que editar a
/// mano justo el día en que menos conviene tocar nada.
#[test]
fn la_salida_de_repartir_se_puede_pegar_entera() {
    let (_, out, _) = correr(&["repartir", "--umbral", "2", "--partes", "3"], SEED);
    let publica = util(&out)[0].clone();

    // Se le pasa TODO menos la línea de la clave pública, que no es una parte.
    let entrada: String = out
        .lines()
        .filter(|l| l.trim() != publica)
        .collect::<Vec<_>>()
        .join("\n");

    let (ok, seed, _) = correr(
        &["restaurar", "--clave-publica", &publica, "--mostrar-seed"],
        &entrada,
    );
    assert!(ok, "pegar la salida entera tiene que funcionar");
    assert_eq!(seed.trim(), SEED);
}
