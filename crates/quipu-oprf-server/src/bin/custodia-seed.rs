// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! `custodia-seed`: repartir y restaurar el seed VOPRF por umbral.
//!
//! Compilar solo con la feature: `cargo build -p quipu-oprf-server --features custodia`
//!
//! # Por qué el material entra por stdin y nunca por argumentos
//!
//! Un argumento de línea de comandos es **público en la máquina**: aparece en
//! `ps aux` para cualquier usuario mientras el proceso vive, y queda escrito en
//! el historial del shell para siempre. Un seed que pasa una sola vez por ahí
//! hay que considerarlo comprometido. Por stdin no toca ninguna de las dos
//! cosas, y permite encadenar sin que el valor aparezca escrito:
//!
//! ```text
//! # En el VPS, sin que el seed salga de la máquina:
//! printenv QUIPU_OPRF_SEED | custodia-seed repartir --umbral 2 --partes 3
//!
//! # Restaurar: una compartición por línea, fin con Ctrl-D.
//! custodia-seed restaurar --clave-publica <64hex>
//! ```
//!
//! # Lo que este programa NUNCA hace
//!
//! No escribe en disco, no abre la red y **no vuelve a imprimir el seed**: ni
//! al repartir ni al restaurar. Al restaurar dice si el material reconstruye la
//! clave pública esperada, que es lo único que hay que saber; el seed se pone
//! en el entorno del servicio, no se lee por pantalla.

use std::io::{IsTerminal, Read, Write};
use std::process::ExitCode;

use quipu_oprf_server::custodia::{
    clave_publica_de, repartir, verificar_restauracion, SEED_LEN,
};
use quipu_oprf_server::hexutil::{from_hex, from_hex_32, to_hex};
use quipu::shamir::Share;

fn uso() -> ExitCode {
    eprintln!(
        "\
custodia-seed — reparte y restaura el seed VOPRF por umbral (Shamir k-de-n)

  repartir  --umbral K --partes N     el seed entra por STDIN (64 hex)
  restaurar --clave-publica <64hex>   las comparticiones entran por STDIN,
                                      una por línea, fin con Ctrl-D
            [--mostrar-seed]          sin la bandera solo COMPRUEBA que el
                                      material sirve; con ella lo devuelve

El seed NUNCA se pasa como argumento: `ps` lo mostraría a cualquiera y el
historial del shell lo guardaría. Ejemplo en el servidor:

  printenv QUIPU_OPRF_SEED | custodia-seed repartir --umbral 2 --partes 3"
    );
    ExitCode::from(2)
}

/// Lee stdin entero. Se niega si es una terminal: sin esto, el programa
/// parecería colgado y el operador pegaría el seed a mano en una sesión que lo
/// guarda todo.
fn leer_stdin(que: &str) -> Result<String, ExitCode> {
    if std::io::stdin().is_terminal() {
        eprintln!(
            "error: {que} debe llegar por una tubería, no tecleado.\n\
             Escribirlo en la terminal lo deja en el historial del shell."
        );
        return Err(ExitCode::from(2));
    }
    let mut s = String::new();
    if std::io::stdin().read_to_string(&mut s).is_err() {
        eprintln!("error: no se pudo leer stdin");
        return Err(ExitCode::FAILURE);
    }
    Ok(s)
}

fn valor<'a>(args: &'a [String], nombre: &str) -> Option<&'a str> {
    let i = args.iter().position(|a| a == nombre)?;
    args.get(i + 1).map(|s| s.as_str())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("repartir") => cmd_repartir(&args),
        Some("restaurar") => cmd_restaurar(&args),
        _ => uso(),
    }
}

fn cmd_repartir(args: &[String]) -> ExitCode {
    let umbral: u8 = match valor(args, "--umbral").and_then(|v| v.parse().ok()) {
        Some(v) => v,
        None => return uso(),
    };
    let partes: u8 = match valor(args, "--partes").and_then(|v| v.parse().ok()) {
        Some(v) => v,
        None => return uso(),
    };

    let crudo = match leer_stdin("el seed") {
        Ok(s) => s,
        Err(c) => return c,
    };
    let seed = match from_hex_32(crudo.trim()) {
        Some(s) => s,
        None => {
            eprintln!("error: el seed debe ser exactamente 64 dígitos hex");
            return ExitCode::FAILURE;
        }
    };

    let publica = match clave_publica_de(&seed) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let comparticiones = match repartir(&seed, umbral, partes) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    // NO SE ENTREGA UN RESPALDO SIN PROBARLO.
    //
    // Reconstruir aquí mismo con un subconjunto del tamaño del umbral, y
    // comprobar que deriva la misma clave pública, es la diferencia entre dar
    // comparticiones y dar comparticiones que sirven. Sin esto el operador se
    // enteraría el día del desastre, que es el único día en que no se puede
    // arreglar.
    let subconjunto: Vec<Share> = comparticiones
        .iter()
        .take(umbral as usize)
        .cloned()
        .collect();
    if let Err(e) = verificar_restauracion(&subconjunto, &publica) {
        eprintln!("error: el reparto NO se pudo verificar y no se entrega: {e}");
        return ExitCode::FAILURE;
    }

    let salida = std::io::stdout();
    let mut w = salida.lock();
    let _ = writeln!(w, "# clave pública (ANÓTALA: verifica cualquier restauración futura)");
    let _ = writeln!(w, "{}", to_hex(&publica));
    let _ = writeln!(w, "# {partes} comparticiones, hacen falta {umbral}");
    let _ = writeln!(w, "# reparto VERIFICADO: {umbral} de ellas reconstruyen esta clave");
    for (i, c) in comparticiones.iter().enumerate() {
        let _ = writeln!(w, "{}", to_hex(&c.to_bytes()));
        let _ = writeln!(w, "#  ^ compartición {} de {partes}", i + 1);
    }
    eprintln!(
        "\n⚠️  Cada compartición va a un SITIO DISTINTO, y ninguna al VPS.\n\
         Con {umbral}-de-{partes}, perder un sitio no cuesta nada y comprometer uno tampoco.\n\
         Borra el scrollback de esta terminal cuando las hayas movido."
    );
    ExitCode::SUCCESS
}

fn cmd_restaurar(args: &[String]) -> ExitCode {
    let esperada = match valor(args, "--clave-publica").and_then(from_hex_32) {
        Some(p) => p,
        None => {
            eprintln!("error: --clave-publica debe ser 64 dígitos hex");
            return uso();
        }
    };

    let crudo = match leer_stdin("las comparticiones") {
        Ok(s) => s,
        Err(c) => return c,
    };

    let mut partes: Vec<Share> = Vec::new();
    for (n, linea) in crudo.lines().enumerate() {
        let l = linea.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let bytes = match from_hex(l) {
            Some(b) => b,
            None => {
                eprintln!("error: la línea {} no es hex válido", n + 1);
                return ExitCode::FAILURE;
            }
        };
        match Share::from_bytes(&bytes) {
            Ok(s) => partes.push(s),
            Err(e) => {
                eprintln!("error: la línea {} no es una compartición ({e:?})", n + 1);
                return ExitCode::FAILURE;
            }
        }
    }

    if partes.is_empty() {
        eprintln!("error: no llegó ninguna compartición");
        return ExitCode::FAILURE;
    }

    // POR DEFECTO NO IMPRIME EL SEED, PERO TIENE QUE PODER HACERLO.
    //
    // El primer diseño no lo imprimía nunca, y eso lo dejaba inútil justo el
    // día para el que existe: quien restaura tras perder el VPS necesita el
    // seed para levantar el servicio nuevo. Una restricción hay que probarla
    // contra la operación legítima, no solo contra el atacante.
    //
    // Así que el camino permisivo existe y **lo pide el llamante**: sin
    // `--mostrar-seed` esto es una comprobación (¿sirven mis comparticiones?);
    // con la bandera es una restauración de verdad.
    let mostrar = args.iter().any(|a| a == "--mostrar-seed");

    match verificar_restauracion(&partes, &esperada) {
        Ok(seed) => {
            eprintln!(
                "✓ {} comparticiones reconstruyen el seed, y deriva la clave pública esperada.",
                partes.len()
            );
            debug_assert_eq!(seed.len(), SEED_LEN);
            if mostrar {
                // A stdout y sin nada más, para poder redirigirlo a un fichero
                // o a una variable sin que se mezcle con los avisos.
                let salida = std::io::stdout();
                let mut w = salida.lock();
                let _ = writeln!(w, "{}", to_hex(&seed));
                eprintln!(
                    "\n⚠️  El seed acaba de salir por stdout. Si esto fue a una terminal,\n\
                     está en tu scrollback y probablemente en el historial: bórralos.\n\
                     Lo normal es redirigirlo, no leerlo."
                );
            } else {
                eprintln!(
                    "  El seed no se imprime. Para restaurar el servicio de verdad,\n\
                     repite con --mostrar-seed y redirige la salida."
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("✗ {e}");
            ExitCode::FAILURE
        }
    }
}
