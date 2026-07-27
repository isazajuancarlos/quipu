// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! La superficie que Quipu ofrece a Python, y lo que NO debe ofrecer.
//!
//! Este archivo se llamaba `paridad.rs` y comprobaba que cinco bindings
//! —Python, Node, Go, C y Rust— expusieran las mismas capacidades. Desde 0.10
//! hay **un solo binding**, así que «paridad» dejaría de significar nada: un
//! binding no puede divergir de sí mismo. Mantener el nombre habría sido
//! exactamente el defecto que este repositorio lleva un mes corrigiendo — una
//! portada que promete lo que no hay.
//!
//! Lo que sí sigue teniendo sentido, y por eso el archivo no se borra:
//!
//!   1. Que Python no PIERDA una capacidad. Fue así como se descubrió que le
//!      faltaba `version()`, que los otros cuatro sí daban.
//!   2. Que no reexponga el VOPRF, por una razón de licencia que no se ve
//!      leyendo el código.
//!   3. Que nada quede tras una feature que la rueda no enciende — código que
//!      parece una característica y no llega a nadie.
//!
//! QUÉ MIDE EXACTAMENTE. Lee `src/python.rs` COMO TEXTO y comprueba que cada
//! capacidad está REGISTRADA en el módulo. No ejecuta nada: no dice que la
//! función sea correcta. De eso responden `tests/vectors.rs`, el banco de
//! `tests/simulacion.rs` y las pruebas de `tests/python/`, que sí corren contra
//! la rueda construida. Lo que caza esto es que alguien quite una línea del
//! `#[pymodule]` y nadie se entere hasta que un usuario la eche en falta.

use std::path::Path;

fn fuente(rel: &str) -> String {
    let ruta = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&ruta).unwrap_or_else(|e| panic!("no se pudo leer {rel}: {e}"))
}

/// El núcleo canónico: lo que un usuario de Python tiene garantizado.
///
/// Se busca en el `wrap_pyfunction!` del `#[pymodule]`, que es lo que de verdad
/// mete la función en el módulo. Que la `fn` exista más arriba no basta: sin
/// registrar, `import quipu` no la ve.
const NUCLEO: &[(&str, &str)] = &[
    ("version", "versión de la librería nativa"),
    ("encode", "cifrar con passphrase"),
    ("decode", "descifrar con passphrase"),
    ("generate_keypair", "generar par de claves (KEM híbrido)"),
    ("encode_to_recipient", "cifrar para un destinatario"),
    ("decode_as_recipient", "descifrar como destinatario"),
    ("generate_signing_keypair", "generar par de claves de firma"),
    ("encode_signed", "firmar"),
    ("decode_verified", "verificar firma"),
    ("encrypt_stream", "cifrar en flujo"),
    ("decrypt_stream", "descifrar en flujo"),
];

#[test]
fn python_expone_el_nucleo_canonico() {
    let python = fuente("src/python.rs");
    let faltan: Vec<&str> = NUCLEO
        .iter()
        .filter(|(f, _)| !python.contains(&format!("wrap_pyfunction!({f}, m)")))
        .map(|(_, que)| *que)
        .collect();

    assert!(
        faltan.is_empty(),
        "el módulo `quipu` de Python ya no registra: {}\n\n\
         O se vuelve a añadir al `#[pymodule]`, o se saca del núcleo en este \
         archivo con la razón escrita. Lo que no vale es que una capacidad \
         desaparezca de la rueda sin que nadie lo note.",
        faltan.join(", ")
    );
}

/// Lo que Python declara tras una feature tiene que ir en la rueda.
///
/// Las features del binding se deciden en DOS archivos que no se hablan:
/// `src/python.rs` pone el `#[cfg(feature = "X")]` y `pyproject.toml` dice con
/// cuáles construye maturin. Cuando divergen no falla nada: el código compila
/// —el CI lo cubre con `--all-features`—, la rueda se publica, y lo que queda es
/// una función que ningún usuario puede llamar. Ni error, ni aviso, ni prueba
/// roja. Solo una característica que existe en la fuente y no en el producto.
///
/// Pasó con `honey_encrypt_pin`/`honey_decrypt_pin`: vivían tras `honey`, que la
/// rueda nunca encendió. Quien leyera la fuente concluiría que Python tiene
/// honey, y honey es precisamente donde una suposición equivocada hace daño,
/// porque no autentica. Se borraron; esta prueba impide que vuelvan a entrar así.
///
/// La regla es asimétrica a propósito: no exige que la rueda lleve todas las
/// features del crate —`lab` y `slh` no tienen por qué—, sino que **nada de lo
/// que este binding declara quede fuera de ella**.
#[test]
fn ninguna_feature_del_binding_de_python_queda_fuera_de_la_rueda() {
    let python = fuente("src/python.rs");
    let pyproject = fuente("pyproject.toml");

    let linea = pyproject
        .lines()
        .find(|l| l.trim_start().starts_with("features"))
        .expect("pyproject.toml debe declarar [tool.maturin] features");

    let mut declaradas: Vec<&str> = Vec::new();
    let mut resto = python.as_str();
    while let Some(i) = resto.find("#[cfg(feature = \"") {
        resto = &resto[i + "#[cfg(feature = \"".len()..];
        if let Some(j) = resto.find('"') {
            declaradas.push(&resto[..j]);
        }
    }
    declaradas.sort_unstable();
    declaradas.dedup();

    let fuera: Vec<&str> = declaradas
        .iter()
        .copied()
        .filter(|f| !linea.contains(&format!("\"{f}\"")))
        .collect();

    assert!(
        fuera.is_empty(),
        "src/python.rs declara código tras {:?}, pero la rueda no enciende esa(s) \
         feature(s):\n  {}\n\n\
         Ese código NO llega a quien hace `pip install`: compila en el CI bajo \
         --all-features y nadie puede llamarlo. O se añade la feature a \
         `[tool.maturin] features` en pyproject.toml, o se borra el binding.",
        fuera,
        linea.trim()
    );
}

/// El VOPRF no puede colarse en el núcleo AGPL de Python.
///
/// No es una regla de estilo, es la que sostiene el negocio del servicio OPRF.
/// El cliente VOPRF vive en `crates/quipu-voprf`, que es **Apache-2.0**, para
/// que quien contrata el SaaS pueda llamarlo desde su servidor de autenticación
/// sin que la AGPL del códec alcance ese servidor. Exponerlo también desde
/// `quipu` daría dos formas de hacer lo mismo, y la de aquí es la que arrastra
/// la licencia contagiosa —además de ML-KEM, ML-DSA y el códec entero, que ese
/// cliente no necesita.
///
/// Se quitó antes de publicar 0.8.0 (ver `src/python.rs` y `LICENSING.md` §0).
/// Esta prueba existe porque el motivo no se ve desde fuera: alguien que mire la
/// superficie verá un hueco en Python y querrá «arreglarlo». Este es el cartel
/// que dice que no.
///
/// Desde 0.10 importa MÁS que antes: al desaparecer los envoltorios de Node, Go
/// y C —que sí llevaban el VOPRF dentro del paquete AGPL, y por eso mismo eran
/// un problema—, Python es el único camino, y tiene que seguir siendo el limpio.
#[test]
fn python_no_reexpone_el_voprf_del_nucleo_agpl() {
    let python = fuente("src/python.rs");

    // Y LOS EJEMPLOS TAMPOCO PUEDEN PROMETERLO.
    //
    // `examples/oprf_client.py` llamaba a `quipu.voprf_blind(...)` — una función
    // que este módulo no expone desde 0.8.0. El ejemplo reventaba con
    // AttributeError en su primera línea útil, y llevaba así desde entonces sin
    // que nadie lo notara: ningún workflow ejecuta los ejemplos de Python.
    //
    // Peor que estar roto: enseñaba el camino equivocado. Quien lo copiara
    // acabaría enlazando el núcleo AGPL desde su servidor de autenticación, que
    // es exactamente lo que `quipu-voprf` (Apache-2.0) existe para evitar. Un
    // ejemplo es documentación ejecutable, y esta mentía.
    for ejemplo in ["examples/oprf_client.py", "examples/quickstart.py"] {
        let texto = fuente(ejemplo);
        assert!(
            !texto.contains("quipu.voprf_"),
            "{ejemplo} llama a `quipu.voprf_*`, que el módulo de Python NO expone. \
             El paquete correcto es `quipu_voprf` (Apache-2.0): enlazar el núcleo \
             AGPL desde el servidor de auth del cliente es justo lo que la \
             separación evita."
        );
    }

    for prohibido in ["wrap_pyfunction!(voprf_blind", "wrap_pyfunction!(voprf_finalize"] {
        assert!(
            !python.contains(prohibido),
            "«{prohibido}» está registrado en el módulo `quipu` de Python.\n\
             El VOPRF de Python vive en el paquete `quipu-voprf` (Apache-2.0). \
             Exponerlo desde este crate mete la AGPL en el servidor de auth del \
             cliente, que es justo lo que la separación existe para impedir."
        );
    }
}
