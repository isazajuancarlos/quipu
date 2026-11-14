// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

//! El ancla de `docs/AUDITORIA_PEGAMENTO.md`: si el pegamento cambia, el
//! veredicto CADUCA — y se entera alguien.
//!
//! # Por qué existe
//!
//! Una auditoría dice lo que un código hace **en el momento en que se leyó**. El
//! 2026-08-17 se leyó el camino ejecutable de `aead`, `inout`, `cipher` y
//! `crypto-common` y el veredicto fue limpio: `forbid(unsafe_code)` en tres de
//! los cuatro, cero I/O, cero `static`, cero `build.rs`, y en `inout` los 30
//! `unsafe` son vistas de punteros sobre el búfer del llamante.
//!
//! Nada de eso sigue siendo cierto por haberlo sido. Un `cargo update`, un
//! `vendor` regenerado o un parche a mano cambian el artefacto sin tocar una
//! línea nuestra, y entonces el documento pasa a describir un código que ya no
//! está — que es la peor forma de salvaguarda: la que dice que miró.
//!
//! Un veredicto sin SHA es un dato que caduca sin avisar (directiva 31). Esto le
//! pone el SHA, y lo convierte en un rojo.
//!
//! # Qué hacer cuando se ponga rojo
//!
//! **No** actualizar el número. Volver a leer lo que cambió, actualizar
//! `docs/AUDITORIA_PEGAMENTO.md` con la fecha nueva, y ENTONCES el número.
//! Cambiar solo el número es firmar sin leer.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Huella del árbol auditado de cada paquete, con la fecha de lectura.
///
/// Cubre los `.rs` y los `.toml` del crate vendorizado: el `Cargo.toml` entra
/// porque una feature nueva o una dependencia nueva cambian lo que se ejecuta
/// aunque no se toque una línea de código.
/// # LA VERSIÓN VA EN EL ANCLA, y hasta el 2026-08-17 no iba
///
/// Anclaba un NOMBRE DE DIRECTORIO de `vendor/`, y `vendor/` aloja cinco pares
/// de versiones conviviendo (`crypto-common` y `crypto-common-0.1.7`,
/// `block-buffer` y `block-buffer-0.10.4`, y tres más). El día que el camino
/// AEAD se resolviera a una versión que no fuese la que se quedó con el nombre a
/// secas, la huella habría seguido verde midiendo un árbol que ya no compila
/// nadie. Caía del lado seguro por cómo nombra `cargo vendor`, o sea por
/// accidente.
///
/// Ahora la versión es parte del ancla y se comprueba contra el `Cargo.toml`
/// vendorizado. Un `cargo update` que cambie de versión pone esto rojo, que es
/// lo que tiene que pasar: la auditoría se hizo sobre un código concreto.
const AUDITADOS: &[(&str, &str, &str)] = &[
    // Auditados el 2026-08-17. Ver docs/AUDITORIA_PEGAMENTO.md.
    //
    // REGENERADOS ESE MISMO DÍA por un cambio del ALGORITMO —se añadió la
    // longitud delante de cada campo para que la huella sea inyectiva—, no del
    // contenido: se comprobó antes de tocar nada que los cuatro árboles seguían
    // dando las huellas viejas, o sea que el pegamento no se había movido. Es la
    // única razón legítima para cambiar estos números sin releer el código.
    ("aead", "0.6.1", "cb1a79d62159c4803a4725763f0e874d9ae4ded744dcb7b2396296cbc294ae49"),
    ("inout", "0.2.2", "43e01d54a7840984912cd2b72742e6927d1a98f63fedf7fc532c0a4606448d6f"),
    ("cipher", "0.5.2", "23a3e21998851cea6d6beeaf53a2c4a2a9f7d119de653b6684b5fd21777cac69"),
    ("crypto-common", "0.2.2", "2c321c9551d3ce450999a19dd109a472d67bbe50f7becf95efb57be46c519b1d"),
];

fn raiz() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Recorre el árbol en orden estable y mete la RUTA en el hash además del
/// contenido: sin la ruta, renombrar un archivo o mover código de uno a otro
/// daría la misma huella.
fn huella(base: &Path) -> (String, usize) {
    let mut archivos: Vec<PathBuf> = Vec::new();
    let mut pila = vec![base.to_path_buf()];
    while let Some(d) = pila.pop() {
        for e in std::fs::read_dir(&d).unwrap_or_else(|e| panic!("no se puede leer {d:?}: {e}")) {
            let p = e.expect("entrada de directorio").path();
            if p.is_dir() {
                pila.push(p);
            } else if matches!(p.extension().and_then(|x| x.to_str()), Some("rs" | "toml")) {
                archivos.push(p);
            }
        }
    }
    archivos.sort();
    let mut h = Sha256::new();
    for p in &archivos {
        let rel = p.strip_prefix(base).expect("bajo la base");
        let ruta = rel.to_string_lossy();
        let datos = std::fs::read(p).expect("archivo legible");
        // LA LONGITUD ANTES DE CADA CAMPO, y no es adorno. Concatenar
        // `ruta ‖ contenido` sin marco NO es inyectivo: el árbol
        // `{a.rs: "src/b.rs" + C}` y el árbol `{a.rs: "", b.rs: C}` producen el
        // mismo flujo y por tanto la misma huella. Hoy no hay ningún archivo del
        // pegamento cuyo contenido empiece por la ruta del siguiente, así que no
        // es explotable — pero es el MISMO argumento que `blindaje::material`
        // aplica con rigor tres archivos más allá, y lo señaló la revisión de
        // seguridad al ver que aquí no se había aplicado. Cuesta dos líneas.
        h.update((ruta.len() as u64).to_be_bytes());
        h.update(ruta.as_bytes());
        h.update((datos.len() as u64).to_be_bytes());
        h.update(&datos);
    }
    let d = h.finalize();
    let mut hex = String::with_capacity(64);
    for b in d {
        hex.push_str(&format!("{b:02x}"));
    }
    (hex, archivos.len())
}

/// CONTROL DEL INSTRUMENTO, y va primero por lo de siempre: si el recorrido no
/// encontrara archivos, la huella sería la del vacío —siempre la misma— y la
/// prueba de abajo pasaría a base de comparar dos constantes. «Limpio» y «no
/// miró» tienen que verse distinto (directiva 30).
#[test]
fn el_recorrido_encuentra_de_verdad_los_arboles() {
    // LA CARDINALIDAD, PRIMERO. El banco de mutación del 2026-08-17 encontró que
    // vaciar `AUDITADOS` —o quitarle una entrada— dejaba las DOS pruebas de este
    // archivo en verde: el control itera sobre la misma lista que controla, así
    // que con la lista vacía el bucle no corre y la parte que sí discrimina (el
    // árbol temporal) pasa igual. El ancla quedaba completamente desactivada y
    // nada se ponía rojo.
    //
    // Es el caso puro del control que comparte bucle con lo controlado. Se cierra
    // fijando QUÉ tiene que haber, no solo comprobando lo que hay.
    const ESPERADOS: &[&str] = &["aead", "inout", "cipher", "crypto-common"];
    let nombres: Vec<&str> = AUDITADOS.iter().map(|(n, _, _)| *n).collect();
    assert_eq!(
        nombres, ESPERADOS,
        "la lista de paquetes auditados cambió: si fue a propósito, actualiza \
         docs/AUDITORIA_PEGAMENTO.md y ESPERADOS; si no, alguien desactivó el ancla"
    );

    for (paquete, _, _) in AUDITADOS {
        let base = raiz().join("vendor").join(paquete);
        assert!(base.is_dir(), "no está vendorizado «{paquete}»: {base:?}");
        let (_, n) = huella(&base);
        assert!(n >= 3, "solo {n} archivos en «{paquete}»: el recorrido está roto");
    }

    // Y que la huella DISCRIMINA: cambiar un byte tiene que cambiarla. Se prueba
    // sobre un árbol de usar y tirar, no sobre el vendorizado.
    let tmp = std::env::temp_dir().join(format!("quipu-huella-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("src")).expect("crea el temporal");
    for n in ["a.rs", "b.rs", "c.rs"] {
        std::fs::write(tmp.join("src").join(n), b"fn x() {}").expect("escribe");
    }
    let (antes, _) = huella(&tmp);
    std::fs::write(tmp.join("src").join("b.rs"), b"fn x() { }").expect("escribe");
    let (despues, _) = huella(&tmp);
    assert_ne!(antes, despues, "la huella no cambia al cambiar un byte: no sirve de ancla");
    // Y el renombrado, que es lo que la ruta dentro del hash está ahí para ver.
    std::fs::rename(tmp.join("src/b.rs"), tmp.join("src/z.rs")).expect("renombra");
    let (renombrado, _) = huella(&tmp);
    assert_ne!(despues, renombrado, "renombrar un archivo no mueve la huella");
    let _ = std::fs::remove_dir_all(&tmp);
}

/// **EL ANCLA SE CONTRASTA CON UNA IMPLEMENTACIÓN AJENA**, porque si no es
/// circular.
///
/// La huella se calcula con `sha2`, que sale del mismo `vendor/` que esta prueba
/// vigila. Un `sha2` comprometido puede devolver la huella esperada para
/// cualquier contenido — la salvaguarda se estaría comprobando a sí misma. Lo
/// señaló la revisión del 2026-08-17 y no es paranoia de manual: el modelo de
/// amenaza declarado de este repositorio es exactamente «una versión maliciosa
/// del crate».
///
/// `sha256sum` de coreutils es una implementación **independiente**, fuera del
/// árbol vendorizado y fuera del proceso. Si las dos coinciden, `sha2` no está
/// mintiendo sobre estos bytes.
///
/// Se salta —diciéndolo— si `sha256sum` no está: no todos los sistemas lo traen,
/// y un requisito que no se puede cumplir se convierte en una prueba que se
/// desactiva (directiva 23).
#[test]
fn la_huella_coincide_con_una_implementacion_independiente() {
    use std::process::Command;
    if Command::new("sha256sum").arg("--version").output().is_err() {
        eprintln!(
            "AVISO: `sha256sum` no está; la huella queda comprobada SOLO con el \
             `sha2` del propio vendor/, que es circular. No es un aprobado."
        );
        return;
    }

    // Se contrasta sobre UN archivo concreto y no sobre el árbol entero: lo que
    // se quiere saber es si `sha2` calcula SHA-256 de verdad, y para eso basta
    // un artefacto. Reimplementar aquí el recorrido en `sh` sería duplicar la
    // parte que ya tiene su propio control.
    let archivo = raiz().join("vendor").join("aead").join("src").join("lib.rs");
    let datos = std::fs::read(&archivo).expect("el lib.rs de aead está vendorizado");

    let mut h = Sha256::new();
    h.update(&datos);
    let nuestra: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();

    let salida = Command::new("sha256sum")
        .arg(&archivo)
        .output()
        .expect("sha256sum responde");
    let ajena = String::from_utf8_lossy(&salida.stdout)
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string();

    assert_eq!(
        nuestra, ajena,
        "el SHA-256 del crate `sha2` NO coincide con el de coreutils sobre el mismo \
         archivo. O el vendorizado está manipulado, o lo está el sistema — en los \
         dos casos, el ancla de la auditoría no vale nada"
    );

    // CONTROL: y que la comparación DISCRIMINA. Sobre otro archivo las dos tienen
    // que diferir, o esto pasaría igual comparando dos constantes.
    let otro = raiz().join("vendor").join("inout").join("src").join("lib.rs");
    let salida2 = Command::new("sha256sum").arg(&otro).output().expect("responde");
    let ajena2 = String::from_utf8_lossy(&salida2.stdout)
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string();
    assert_ne!(ajena, ajena2, "el control: dos archivos distintos, huellas distintas");
}

/// **EL ANCLA.** El pegamento auditado es byte a byte el que se auditó.
#[test]
fn el_pegamento_es_el_que_se_audito() {
    let mut movidos = Vec::new();
    for (paquete, version, esperada) in AUDITADOS {
        // LA VERSIÓN, comprobada contra el manifiesto vendorizado: sin esto el
        // ancla mide un nombre de directorio y no un artefacto.
        let manifiesto = std::fs::read_to_string(raiz().join("vendor").join(paquete).join("Cargo.toml"))
            .unwrap_or_else(|e| panic!("no se puede leer el Cargo.toml de {paquete}: {e}"));
        let declarada = manifiesto
            .lines()
            .find_map(|l| l.strip_prefix("version = "))
            .map(|v| v.trim().trim_matches('"').to_string())
            .unwrap_or_default();
        assert_eq!(
            &declarada, version,
            "«{paquete}» vendorizado es la versión {declarada} y se auditó la {version}: \
             el veredicto de docs/AUDITORIA_PEGAMENTO.md no describe este código"
        );
        let (actual, n) = huella(&raiz().join("vendor").join(paquete));
        if &actual != esperada {
            movidos.push(format!("  {paquete} ({n} archivos)\n    auditado: {esperada}\n    ahora:    {actual}"));
        }
    }
    assert!(
        movidos.is_empty(),
        "el pegamento compartido CAMBIÓ desde la auditoría del 2026-08-17:\n{}\n\n\
         El veredicto de docs/AUDITORIA_PEGAMENTO.md ya no describe este código, y \
         `blindaje` apoya en él su promesa de AND. Vuelve a leer lo que cambió, \
         actualiza el documento con la fecha nueva y SOLO ENTONCES la huella. \
         Cambiar el número a secas es firmar sin leer.",
        movidos.join("\n")
    );
}
