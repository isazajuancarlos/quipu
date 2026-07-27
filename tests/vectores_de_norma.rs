// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Vectores de una NORMA EXTERNA, no de Quipu.
//!
//! `docs/ATAQUES_TAXONOMIA.md`, familia 1, pedía «un chequeo que ligue cada
//! primitiva a su vector de referencia y falle si la implementación deja de
//! conformar (no solo *es consistente consigo misma*)».
//!
//! Esa distinción es el corazón de este archivo. `tests/vectors.rs` compara
//! contra `quipu_vectors.json`, que **lo genera el propio Quipu**: prueba que la
//! implementación no cambió, no que sea correcta. Si Quipu llamara a Argon2i en
//! vez de Argon2id, o pasara `salt` e `info` en el orden equivocado, el
//! contenedor seguiría abriéndose con la misma librería y el banco entero
//! seguiría verde. Coherente consigo misma, y equivocada.
//!
//! LO QUE SE PRUEBA AQUÍ ES EL CABLEADO, no la primitiva. `hkdf` y
//! `ed25519-dalek` ya traen sus propios vectores; repetirlos no aportaría nada.
//! Lo que nadie comprueba es que **Quipu los use como manda la norma**, y ahí es
//! donde vive el error que este proyecto puede cometer.
//!
//! Los vectores vienen del crate `wycheproof` (Google), que los trae vendorizados
//! y firmados por su origen. NO se escriben a mano: un vector transcrito de
//! memoria con un byte cambiado haría «arreglar» el código para que encaje con
//! algo falso — el peor desenlace posible en una librería criptográfica.

use quipu::kdf;

/// El HKDF de Quipu conforma con la RFC 5869, no solo consigo mismo.
///
/// `kdf::derive_subkey(master, info)` es exactamente
/// `HKDF-SHA256(ikm = master, salt = vacío, info)` truncado a 32 bytes. Así que
/// todo vector de Wycheproof con sal vacía y 32 bytes de salida tiene que
/// reproducirse llamando a la función real de Quipu, no a la librería por debajo.
///
/// Qué caza que ninguna otra prueba caza:
///   - que alguien cambie el hash (el documento de la taxonomía llegó a decir
///     SHA-512 cuando el código usa SHA-256 — el error existe y es fácil);
///   - que se inviertan `salt` e `info`, que es el fallo clásico de HKDF;
///   - que una subida de la dependencia `hkdf` cambie el comportamiento.
#[test]
fn el_hkdf_de_quipu_conforma_con_la_rfc_5869() {
    use wycheproof::hkdf::{TestName, TestSet};

    let set = TestSet::load(TestName::HkdfSha256).expect("cargar vectores HKDF-SHA256");
    let mut comprobados = 0usize;
    let mut tamanos = std::collections::BTreeSet::new();
    let mut fallos = Vec::new();

    for grupo in &set.test_groups {
        for t in &grupo.tests {
            // Quipu fija sal VACÍA y una clave maestra de 32 bytes; el tamaño de
            // salida sí es libre. Solo esos vectores prueban el cableado real —
            // el resto probaría la librería, que ya se prueba sola.
            if !t.salt.is_empty() || t.ikm.len() != kdf::KEY_LEN {
                continue;
            }
            let mut master = [0u8; kdf::KEY_LEN];
            master.copy_from_slice(&t.ikm);

            let mut obtenido = vec![0u8; t.size];
            kdf::derive_stream(&master, &t.info, &mut obtenido);
            comprobados += 1;
            tamanos.insert(t.size);
            if obtenido.as_slice() != t.okm.as_slice() {
                fallos.push(format!(
                    "tcId {} ({} B): esperado {:02x?}…, obtenido {:02x?}…",
                    t.tc_id, t.size,
                    &t.okm[..8.min(t.okm.len())],
                    &obtenido[..8.min(obtenido.len())]
                ));
            }

            // Y `derive_subkey` tiene que coincidir con `derive_stream` de 32
            // bytes. Son dos puertas a la misma derivación; que se separen sería
            // un error silencioso — nada las obliga a coincidir salvo esto.
            if t.size == kdf::KEY_LEN {
                let corta = kdf::derive_subkey(&master, &t.info);
                if corta.as_slice() != obtenido.as_slice() {
                    fallos.push(format!(
                        "tcId {}: `derive_subkey` y `derive_stream` NO coinciden",
                        t.tc_id
                    ));
                }
            }
        }
    }

    assert!(
        fallos.is_empty(),
        "el HKDF de Quipu NO conforma con la norma en {} vector(es):\n  {}",
        fallos.len(),
        fallos.join("\n  ")
    );
    // Sin este límite, filtrar de más dejaría cero vectores y la prueba pasaría
    // sin comprobar nada: un aprobado por ausencia de datos. Ya pasó al escribir
    // esta prueba — el primer filtro exigía además salida de 32 B y dejó UN solo
    // vector, y el banco se negó a llamar a eso una comprobación.
    assert!(
        comprobados >= 5 && tamanos.len() >= 3,
        "{comprobados} vectores en {} tamaño(s): el filtro descartó demasiado y \
         esto no está midiendo nada",
        tamanos.len()
    );
    println!("HKDF-SHA256 contra Wycheproof: {comprobados} vectores conformes en {} tamaños", tamanos.len());
}

/// La firma clásica de la mitad híbrida sigue conformando con la RFC 8032.
///
/// Aquí lo probado NO es el cableado de Quipu —su firma va sobre una preimagen
/// propia que ata la clave pública y una etiqueta de dominio, así que no encaja
/// en un vector de Ed25519 puro— sino la **procedencia**: que la dependencia
/// que Quipu vendió como Ed25519 conforme siga siéndolo.
///
/// Es I5, no I1: cubre el escenario de la familia 10 —una actualización de
/// dependencia que cambia el comportamiento— antes de que llegue a un usuario.
/// Sin esto, una subida de `ed25519-dalek` que rompiera la conformidad pasaría
/// en verde, porque el resto del banco solo comprueba que Quipu se entiende
/// consigo mismo.
#[test]
fn la_mitad_ed25519_conforma_con_la_rfc_8032() {
    use ed25519_dalek::{Signature, VerifyingKey};
    use wycheproof::eddsa::{TestName, TestSet};
    use wycheproof::TestResult;

    let set = TestSet::load(TestName::Ed25519).expect("cargar vectores Ed25519");
    let mut aceptados = 0usize;
    let mut rechazados = 0usize;
    let mut fallos = Vec::new();

    for grupo in &set.test_groups {
        let vk_bytes: [u8; 32] = match grupo.key.pk.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => continue,
        };
        let vk = match VerifyingKey::from_bytes(&vk_bytes) {
            Ok(v) => v,
            Err(_) => continue,
        };
        for t in &grupo.tests {
            let sig_bytes: [u8; 64] = match t.sig.as_slice().try_into() {
                Ok(b) => b,
                // Una firma de longitud distinta no puede ser válida; Wycheproof
                // las incluye a propósito.
                Err(_) => {
                    if t.result == TestResult::Valid {
                        fallos.push(format!("tcId {}: firma válida con longitud rara", t.tc_id));
                    }
                    rechazados += 1;
                    continue;
                }
            };
            let sig = Signature::from_bytes(&sig_bytes);
            let ok = vk.verify_strict(&t.msg, &sig).is_ok();
            match (t.result, ok) {
                (TestResult::Valid, true) => aceptados += 1,
                (TestResult::Invalid, false) => rechazados += 1,
                // `Acceptable` son casos donde la norma deja margen: no se
                // exige nada, y forzar un veredicto sería inventarlo.
                (TestResult::Acceptable, _) => {}
                (esperado, obtenido) => fallos.push(format!(
                    "tcId {}: la norma dice {esperado:?} y obtuvimos {}",
                    t.tc_id,
                    if obtenido { "válida" } else { "inválida" }
                )),
            }
        }
    }

    assert!(
        fallos.is_empty(),
        "Ed25519 dejó de conformar con la norma en {} caso(s):\n  {}",
        fallos.len(),
        fallos[..fallos.len().min(8)].join("\n  ")
    );
    assert!(
        aceptados > 0 && rechazados > 0,
        "el banco necesita casos válidos Y inválidos para discriminar; hubo \
         {aceptados} aceptados y {rechazados} rechazados"
    );
    println!("Ed25519 contra Wycheproof: {aceptados} válidas aceptadas, {rechazados} inválidas rechazadas");
}
