// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! El NÚCLEO CANÓNICO: lo que todo binding debe exponer, en todos los lenguajes.
//!
//! Principio: quien usa Quipu desde Python, Node, Go o C tiene que poder hacer
//! lo mismo. Hoy no era del todo cierto y, peor, nadie se enteraba: la matriz de
//! características vivía escrita a mano en una lista de pendientes, y al
//! releerla una semana después estaba mal en CUATRO celdas — dos huecos que ya
//! no existían, uno que era una decisión deliberada mal apuntada como hueco, y
//! uno real que no figuraba (Python no tenía `version()`). Una matriz en prosa
//! no puede vigilar código que cambia; esta prueba sí.
//!
//! QUÉ MIDE EXACTAMENTE, Y QUÉ NO. Lee las fuentes de los bindings COMO TEXTO y
//! comprueba que cada capacidad está DECLARADA en los cinco. No ejecuta nada:
//! no dice que la función sea correcta, ni que los cinco produzcan los mismos
//! bytes. De eso responden los vectores de interoperabilidad (`tests/vectors.rs`
//! y `bindings/go/interop_test.go`). Lo que caza esta prueba es el fallo que de
//! verdad ocurrió: un binding creciendo por su cuenta y quedándose sin algo que
//! los otros sí dan.
//!
//! Leer texto —y no compilar cada binding— es deliberado: así corre en el job
//! normal del CI, sin toolchain de Node, de Go ni de Python. Una prueba que solo
//! corre donde están instalados los cuatro es una prueba que no corre.
//!
//! DÓNDE SE BUSCA CADA UNO, y por qué ahí:
//!   - Python: en el `wrap_pyfunction!` del `#[pymodule]`, que es lo que de
//!     verdad mete la función en el módulo. Que la `fn` exista más arriba no
//!     basta: sin registrar, `import quipu` no la ve.
//!   - Node: en los DOS archivos. `index.d.ts` es la promesa a TypeScript y
//!     `src/index.js` lo que se ejecuta; si solo se mira uno, un `.d.ts` que
//!     miente pasa desapercibido, y mentir sobre el tipo es peor que faltar.
//!   - Go y C: la declaración de la función.

use std::path::{Path, PathBuf};

fn raiz() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn fuente(rel: &str) -> String {
    let ruta = raiz().join(rel);
    std::fs::read_to_string(&ruta).unwrap_or_else(|e| panic!("no se pudo leer {rel}: {e}"))
}

/// Una capacidad del núcleo, con el nombre que le toca en cada lenguaje.
///
/// Los nombres NO coinciden entre bindings y esta prueba no pretende
/// unificarlos: Python dice `encode_signed`/`decode_verified` donde Node dice
/// `sign`/`verify`, y C antepone `quipu_`. Renombrar una API pública ya
/// publicada rompe a quien la usa, y el precio de eso es mayor que el de la
/// incoherencia. Lo que sí se exige es que la CAPACIDAD esté, con el nombre que
/// tenga. La divergencia de nombres queda registrada aquí, a la vista, en vez de
/// en la cabeza de alguien.
struct Capacidad {
    que: &'static str,
    python: &'static str,
    node: &'static str,
    go: &'static str,
    c: &'static str,
}

const NUCLEO: &[Capacidad] = &[
    Capacidad {
        que: "versión de la librería nativa",
        python: "version",
        node: "version",
        go: "Version",
        c: "quipu_version",
    },
    Capacidad {
        que: "cifrar con passphrase",
        python: "encode",
        node: "encode",
        go: "Encode",
        c: "quipu_encode",
    },
    Capacidad {
        que: "descifrar con passphrase",
        python: "decode",
        node: "decode",
        go: "Decode",
        c: "quipu_decode",
    },
    Capacidad {
        que: "generar par de claves (KEM híbrido)",
        python: "generate_keypair",
        node: "generateKeypair",
        go: "GenerateKeypair",
        c: "quipu_generate_keypair",
    },
    Capacidad {
        que: "cifrar para un destinatario",
        python: "encode_to_recipient",
        node: "encryptToRecipient",
        go: "EncryptToRecipient",
        c: "quipu_encrypt_to_recipient",
    },
    Capacidad {
        que: "descifrar como destinatario",
        python: "decode_as_recipient",
        node: "decryptAsRecipient",
        go: "DecryptAsRecipient",
        c: "quipu_decrypt_as_recipient",
    },
    Capacidad {
        que: "generar par de claves de firma",
        python: "generate_signing_keypair",
        node: "generateSigningKeypair",
        go: "GenerateSigningKeypair",
        c: "quipu_generate_signing_keypair",
    },
    Capacidad {
        que: "firmar",
        python: "encode_signed",
        node: "sign",
        go: "Sign",
        c: "quipu_sign",
    },
    Capacidad {
        que: "verificar firma",
        python: "decode_verified",
        node: "verify",
        go: "Verify",
        c: "quipu_verify",
    },
    Capacidad {
        que: "cifrar en flujo",
        python: "encrypt_stream",
        node: "encryptStream",
        go: "EncryptStream",
        c: "quipu_encrypt_stream",
    },
    Capacidad {
        que: "descifrar en flujo",
        python: "decrypt_stream",
        node: "decryptStream",
        go: "DecryptStream",
        c: "quipu_decrypt_stream",
    },
];

#[test]
fn el_nucleo_canonico_esta_en_los_cinco_bindings() {
    let python = fuente("src/python.rs");
    let node_dts = fuente("bindings/node/index.d.ts");
    let node_js = fuente("bindings/node/src/index.js");
    let go = fuente("bindings/go/quipu.go");
    let c = fuente("bindings/c/include/quipu.h");

    let mut faltan = Vec::new();
    for cap in NUCLEO {
        // El paréntesis es parte del patrón a propósito: sin él, buscar `sign`
        // lo encontraría dentro de `generate_signing_keypair` y la prueba diría
        // que sí está cuando no.
        let comprobaciones: [(&str, bool); 5] = [
            (
                "Python",
                python.contains(&format!("wrap_pyfunction!({}, m)", cap.python)),
            ),
            (
                "Node (index.d.ts)",
                node_dts.contains(&format!("export declare function {}(", cap.node)),
            ),
            (
                "Node (src/index.js)",
                node_js.contains(&format!("export function {}(", cap.node))
                    || node_js.contains(&format!("export async function {}(", cap.node)),
            ),
            ("Go", go.contains(&format!("func {}(", cap.go))),
            ("C", c.contains(&format!("{}(", cap.c))),
        ];
        for (lenguaje, hay) in comprobaciones {
            if !hay {
                faltan.push(format!("  {lenguaje:<20} no expone «{}»", cap.que));
            }
        }
    }

    assert!(
        faltan.is_empty(),
        "el núcleo canónico no está completo en todos los bindings:\n{}\n\n\
         O se añade la capacidad al binding que falta, o se saca del núcleo en \
         este archivo — con la razón escrita. Lo que no vale es dejar que un \
         lenguaje se quede atrás sin que nadie lo note.",
        faltan.join("\n")
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
/// La regla es simétrica a propósito: no exige que la rueda lleve todas las
/// features del crate —`lab` y `slh` no tienen por qué—, sino que **nada de lo
/// que este binding declara quede fuera de ella**. Añadir una capacidad a Python
/// obliga a encenderla en `pyproject.toml` en el mismo commit, que es cuando
/// alguien está mirando.
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
/// matriz de paridad verá un hueco en Python y querrá «arreglarlo». Este es el
/// cartel que dice que no.
#[test]
fn python_no_reexpone_el_voprf_del_nucleo_agpl() {
    let python = fuente("src/python.rs");
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
