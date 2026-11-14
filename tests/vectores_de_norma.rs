// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

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

/// La dependencia `argon2` conforma con el vector Argon2id del RFC 9106 §5.3.
///
/// `wycheproof` no trae Argon2id, así que este vector es la excepción a «los
/// vectores vienen de un crate vendorizado»: se toma del RFC 9106 (fuente
/// normativa) y se contrasta contra el `tests/kat.rs` del propio crate `argon2`
/// —dos orígenes independientes—. NO se transcribe de memoria: si un byte
/// estuviera mal, este test fallaría, y la respuesta correcta es INVESTIGAR, no
/// ajustar los bytes al código.
///
/// Prueba la PROCEDENCIA, como su hermana de Ed25519: que la dependencia que
/// Quipu vendió como Argon2id siga computando Argon2id. Una subida de `argon2`
/// que regresara —el mismo tipo de canal lateral de división en tiempo variable
/// que RustSec persiguió en `ml-dsa` (RUSTSEC-2025-0144)— rompería esto y el CI
/// se pondría rojo antes de publicar.
///
/// Usa el vector completo del RFC, con `secret` (K) y `associated data` (X), que
/// `derive_master_key` no expone; por eso este test va contra el crate, y el de
/// abajo contra el cableado de Quipu.
#[test]
fn argon2id_conforma_con_la_rfc_9106() {
    use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};

    // RFC 9106 §5.3 — entradas.
    let password = [0x01u8; 32];
    let salt = [0x02u8; 16];
    let secret = [0x03u8; 8];
    let ad = [0x04u8; 12];
    let params = ParamsBuilder::new()
        .m_cost(32) // 32 KiB
        .t_cost(3)
        .p_cost(4)
        .output_len(32)
        .data(AssociatedData::new(&ad).expect("AD de 12 bytes válida"))
        .build()
        .expect("params Argon2id del RFC 9106 válidos");
    let ctx = Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params)
        .expect("contexto Argon2id con secreto válido");
    let mut out = [0u8; 32];
    ctx.hash_password_into(&password, &salt, &mut out)
        .expect("hashing Argon2id no debe fallar con entradas válidas");

    // RFC 9106 §5.3 — Tag[32].
    let esperado: [u8; 32] = [
        0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, //
        0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9, //
        0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, //
        0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59, //
    ];
    assert_eq!(
        out, esperado,
        "argon2 dejó de conformar con el vector Argon2id del RFC 9106 §5.3"
    );
}

/// `derive_master_key` usa Argon2**id** V0x13 sobre `(NFKC(pass) ‖ pepper, salt)`.
///
/// Este SÍ es el cableado de Quipu, que es lo que este archivo existe para cazar.
/// El test de arriba prueba que la primitiva es correcta; este prueba que Quipu
/// la usa como manda la norma, y discrimina tres errores que una prueba de
/// consistencia-consigo-mismo no vería:
///   - que el algoritmo sea Argon2id y no Argon2i (el `assert_ne!` lo exige);
///   - que la versión sea 0x13 (la del RFC), no la 0x10 antigua;
///   - que el material derivado sea la passphrase normalizada seguida del pepper,
///     con el salt en su sitio (no invertido con el material).
#[test]
fn derive_master_key_es_argon2id_v0x13_y_no_argon2i() {
    use argon2::{Algorithm, Argon2, Params, Version};

    let salt = [7u8; kdf::SALT_LEN];
    // Coste bajo: este test comprueba el CABLEADO, no el coste. Producción usa 64 MiB.
    let cheap = kdf::KdfParams {
        mem_kib: 64,
        iterations: 1,
        parallelism: 1,
    };
    let obtenido = kdf::derive_master_key("clave", &salt, b"pimienta", &cheap);

    // Cómputo directo. "clave" es ASCII, así que NFKC("clave") == "clave", y el
    // material es la passphrase normalizada seguida del pepper.
    let material = b"clavepimienta";
    let directo = |alg| {
        let p = Params::new(64, 1, 1, Some(kdf::KEY_LEN)).expect("params válidos");
        let mut o = [0u8; kdf::KEY_LEN];
        Argon2::new(alg, Version::V0x13, p)
            .hash_password_into(material, &salt, &mut o)
            .expect("derivación válida");
        o
    };

    assert_eq!(
        obtenido,
        directo(Algorithm::Argon2id),
        "derive_master_key debe ser Argon2id V0x13 sobre (NFKC(pass) ‖ pepper, salt)"
    );
    assert_ne!(
        obtenido,
        directo(Algorithm::Argon2i),
        "y NO Argon2i: sin este assert el test no discriminaría el algoritmo"
    );
}

/// Decodifica hex (mayúsculas o minúsculas). Los vectores ACVP vienen como cadena
/// hex; no se transcriben, se parsean del JSON vendorizado, así que el único
/// riesgo aquí es un decodificador mal escrito — y este falla ruidoso.
fn hex_a_bytes(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex de longitud impar");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("dígito hex válido"))
        .collect()
}

/// ML-KEM-1024 conforma con el vector de keyGen de NIST (FIPS 203 / ACVP).
///
/// PROCEDENCIA de la primitiva insignia: que el crate `ml-kem` derive la clave de
/// encapsulación FIPS-correcta a partir de la semilla del vector. Es lo que
/// faltaba de la familia 1 de la taxonomía; wycheproof NO trae ML-KEM, así que el
/// vector viene de NIST ACVP-Server, vendorizado en `tests/vectors/` y parseado
/// del JSON — NO transcrito a mano (el `ek` son 1568 bytes).
///
/// FIPS 203: la semilla de keygen es `d ‖ z` (64 bytes); `DecapsulationKey::
/// from_seed` la parte con `seed.split()` en ese orden. Se afirma la `ek`
/// derivada, que es la parte NO trivial de la keygen (K-PKE); el `dk` es
/// `ek ‖ H(ek) ‖ z`, así que una `ek` correcta cubre la derivación.
///
/// Cazaría una subida regresiva de `ml-kem` —el tipo de fallo que RustSec
/// persiguió en la familia PQ— antes de que llegara a una release.
#[test]
fn ml_kem_1024_conforma_con_el_vector_acvp_de_nist() {
    use ml_kem::{DecapsulationKey, KeyExport, MlKem1024, Seed};

    let v: serde_json::Value =
        serde_json::from_str(include_str!("vectors/acvp_mlkem1024_keygen.json"))
            .expect("vector ACVP ML-KEM legible");
    let d = hex_a_bytes(v["d"].as_str().expect("campo d"));
    let z = hex_a_bytes(v["z"].as_str().expect("campo z"));
    let ek_esperado = hex_a_bytes(v["ek"].as_str().expect("campo ek"));

    let mut semilla = d;
    semilla.extend_from_slice(&z); // d ‖ z, FIPS 203
    let seed = Seed::try_from(semilla.as_slice()).expect("semilla de 64 bytes");

    let dk = DecapsulationKey::<MlKem1024>::from_seed(seed);
    let ek = dk.encapsulation_key().to_bytes();

    assert_eq!(
        ek.as_slice(),
        ek_esperado.as_slice(),
        "ml-kem dejó de derivar la ek FIPS del vector ACVP ML-KEM-1024 keyGen tc {}",
        v["tcId"]
    );
    println!(
        "ML-KEM-1024 contra ACVP tc {}: ek de {} bytes conforme",
        v["tcId"],
        ek.as_slice().len()
    );
}

/// ML-DSA-87 conforma con el vector de keyGen de NIST (FIPS 204 / ACVP).
///
/// La otra primitiva insignia: que `ml-dsa` derive la clave de verificación
/// FIPS-correcta desde la semilla `ξ` de 32 bytes del vector. Mismo encuadre que
/// ML-KEM: vector de NIST ACVP-Server, vendorizado y parseado, no transcrito (la
/// `pk` son 2592 bytes).
#[test]
fn ml_dsa_87_conforma_con_el_vector_acvp_de_nist() {
    use ml_dsa::{Keypair, MlDsa87, Seed, SigningKey};

    let v: serde_json::Value =
        serde_json::from_str(include_str!("vectors/acvp_mldsa87_keygen.json"))
            .expect("vector ACVP ML-DSA legible");
    let semilla = hex_a_bytes(v["seed"].as_str().expect("campo seed"));
    let pk_esperado = hex_a_bytes(v["pk"].as_str().expect("campo pk"));

    let xi = Seed::try_from(semilla.as_slice()).expect("semilla ξ de 32 bytes");
    let sk = SigningKey::<MlDsa87>::from_seed(&xi);
    let pk = sk.verifying_key().encode();

    assert_eq!(
        pk.as_slice(),
        pk_esperado.as_slice(),
        "ml-dsa dejó de derivar la pk FIPS del vector ACVP ML-DSA-87 keyGen tc {}",
        v["tcId"]
    );
    println!(
        "ML-DSA-87 contra ACVP tc {}: pk de {} bytes conforme",
        v["tcId"],
        pk.as_slice().len()
    );
}

/// ML-DSA-87 **sigVer** conforma con los vectores de NIST (FIPS 204 / ACVP): la
/// VERIFICACIÓN de firma —el camino que quipu USA en la firma triple— acepta una firma
/// válida y RECHAZA una manipulada. El control D33 viene en los propios vectores de NIST
/// (un caso `testPassed:true` y uno `false` por «modified message»), no fabricado.
/// Vectores de `usnistgov/ACVP-Server` (tgId 5: interfaz external, prehash pure),
/// vendorizados y parseados, no transcritos.
#[test]
fn ml_dsa_87_verifica_los_vectores_acvp_sigver_de_nist() {
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa87, Signature, VerifyingKey};

    let v: serde_json::Value =
        serde_json::from_str(include_str!("vectors/acvp_mldsa87_sigver.json"))
            .expect("vector ACVP ML-DSA sigVer legible");
    let casos = v["casos"].as_array().expect("casos");
    assert_eq!(casos.len(), 2, "un caso válido y uno inválido (control D33 de NIST)");

    for caso in casos {
        let pk = hex_a_bytes(caso["pk"].as_str().expect("pk"));
        let msg = hex_a_bytes(caso["message"].as_str().expect("message"));
        let ctx = hex_a_bytes(caso["context"].as_str().unwrap_or(""));
        let firma = hex_a_bytes(caso["signature"].as_str().expect("signature"));
        let esperado = caso["testPassed"].as_bool().expect("testPassed");

        let epk = EncodedVerifyingKey::<MlDsa87>::try_from(pk.as_slice())
            .expect("pk del tamaño de ML-DSA-87");
        let vk = VerifyingKey::<MlDsa87>::decode(&epk);
        // Una firma mal formada no decodifica → no verifica (mismo veredicto que un rechazo).
        let ok = match EncodedSignature::<MlDsa87>::try_from(firma.as_slice())
            .ok()
            .and_then(|e| Signature::<MlDsa87>::decode(&e))
        {
            Some(sig) => vk.verify_with_context(&msg, &ctx, &sig),
            None => false,
        };
        assert_eq!(
            ok, esperado,
            "ACVP sigVer tc {}: verify={ok} pero NIST dice testPassed={esperado} ({})",
            caso["tcId"], caso["reason"]
        );
    }
    println!("ML-DSA-87 sigVer: 2 vectores ACVP de NIST conformes (válido acepta, manipulado rechaza)");
}

/// ML-DSA-87 **sigGen** conforma BYTE A BYTE con el vector de NIST (FIPS 204 / ACVP): la
/// FIRMA determinista (`sign_deterministic`, la variante external/pure que usa la firma triple
/// de quipu) reproduce EXACTAMENTE la firma de NIST a partir del `sk` del vector.
///
/// SUBIDO A KAT EXACTO el 2026-11-01: hasta `ml-dsa 0.1.1` esto era «firmar y auto-verificar»
/// porque el crate no exponía cómo reconstruir la clave desde el `sk` CODIFICADO del vector
/// (solo `from_seed`, y el vector no trae la semilla). `ml-dsa 0.1.2` añadió
/// `ExpandedSigningKey::from_expanded(&ExpandedSigningKeyBytes)` —el decode que faltaba—, así
/// que ahora se firma el mensaje del vector y se casa la firma byte a byte.
/// Vector: `usnistgov/ACVP-Server` sigGen tgId 5 (external, pure, deterministic), vendorizado.
/// Control D33: la misma clave sobre un mensaje MUTADO no reproduce la firma del vector.
#[test]
fn ml_dsa_87_firma_siggen_conforma_con_el_vector_acvp_de_nist() {
    use ml_dsa::{ExpandedSigningKey, ExpandedSigningKeyBytes, MlDsa87};

    let v: serde_json::Value =
        serde_json::from_str(include_str!("vectors/acvp_mldsa87_siggen.json"))
            .expect("vector ACVP ML-DSA sigGen legible");
    let sk_bytes = hex_a_bytes(v["sk"].as_str().expect("sk"));
    let msg = hex_a_bytes(v["message"].as_str().expect("message"));
    let ctx = hex_a_bytes(v["context"].as_str().unwrap_or(""));
    let sig_esperada = hex_a_bytes(v["signature"].as_str().expect("signature"));

    let enc = ExpandedSigningKeyBytes::<MlDsa87>::try_from(sk_bytes.as_slice())
        .expect("sk del tamaño expandido de ML-DSA-87 (4896 B)");
    // `from_expanded` está `#[deprecated]` (ml-dsa prefiere `from_seed` para el camino normal),
    // pero el vector ACVP sigGen da el `sk` CODIFICADO, no la semilla: es el único camino para
    // cargar la clave EXTERNA del vector, que es justo lo que un KAT necesita.
    #[allow(deprecated)]
    let esk = ExpandedSigningKey::<MlDsa87>::from_expanded(&enc);

    let firma = esk
        .sign_deterministic(&msg, &ctx)
        .expect("firma determinista external/pure");
    assert_eq!(
        firma.encode().as_slice(),
        sig_esperada.as_slice(),
        "ACVP sigGen tc {}: la firma determinista NO casa byte a byte con NIST",
        v["tcId"]
    );

    // Control D33: la MISMA clave sobre un mensaje mutado NO puede reproducir la firma del vector.
    let mut msg_mutado = msg;
    msg_mutado[0] ^= 1;
    let firma_otra = esk
        .sign_deterministic(&msg_mutado, &ctx)
        .expect("firma del mensaje mutado");
    assert_ne!(
        firma_otra.encode().as_slice(),
        sig_esperada.as_slice(),
        "control D33: un mensaje distinto no puede dar la firma del vector"
    );
    println!(
        "ML-DSA-87 sigGen: firma determinista conforme BYTE A BYTE con NIST ACVP tc {}",
        v["tcId"]
    );
}

// ---------------------------------------------------------------------------
// ML-KEM encaps/decaps (FIPS 203 / ACVP encapDecap) + keyGen ML-KEM-768.
//
// El keyGen de ML-KEM-1024 (arriba) prueba la DERIVACIÓN de clave. Esto completa
// las DOS operaciones que un KEM hace en caliente —y que X-Wing-768 usa en cada
// sobre— más el keyGen del tamaño 768:
//   - encaps (AFT): desde `ek` y la moneda `m`, produce ciphertext `c` y secreto
//     `k`. Se afirman AMBOS contra NIST: un `c` correcto con `k` mal (o al revés)
//     no pasa.
//   - decaps (VAL): desde la `dk` expandida y `c`, recupera `k`.
//
// ML-KEM-768 es el que va DENTRO de X-Wing (draft-connolly): su conformidad es la
// del sobre híbrido. 1024 es el del núcleo `pqhybrid`. Antes solo se cubría
// keyGen-1024; esto cierra la familia 1 de la taxonomía en ambos tamaños.
//
// PROCEDENCIA: NIST ACVP-Server (usnistgov/ACVP-Server), grupos
// `ML-KEM-encapDecap-FIPS203` y `ML-KEM-keyGen-FIPS203`, vendorizados en
// `tests/vectors/` y parseados del JSON — NO transcritos.
//
// El patrón de API (Key::try_from + KeyInit::new para la ek; ExpandedDecapsulationKey
// + from_expanded_bytes para la dk expandida de ACVP; Ciphertext::try_from) es el
// MISMO que usan `src/xwing.rs` y `src/pqhybrid.rs` — la costura real, no una de
// arnés (D33).

/// Carga los casos de prueba de un archivo de vectores (un array JSON) y falla
/// ruidoso si quedó vacío: un archivo vacío haría pasar la prueba en falso (D30).
fn casos_acvp(json: &str) -> Vec<serde_json::Value> {
    let v: serde_json::Value = serde_json::from_str(json).expect("vector ACVP legible");
    let a = v.as_array().expect("el vector es un array de casos").clone();
    assert!(!a.is_empty(), "archivo de vectores vacío: la prueba pasaría en falso");
    a
}

/// keyGen de ML-KEM-768 (mismo encuadre que el de 1024): afirma la `ek` derivada
/// desde la semilla `d ‖ z` del vector ACVP.
#[test]
fn ml_kem_768_conforma_keygen_acvp() {
    use ml_kem::{DecapsulationKey, KeyExport, MlKem768, Seed};
    let casos = casos_acvp(include_str!("vectors/acvp_mlkem768_keygen.json"));
    for c in &casos {
        let mut semilla = hex_a_bytes(c["d"].as_str().expect("campo d"));
        semilla.extend_from_slice(&hex_a_bytes(c["z"].as_str().expect("campo z")));
        let seed = Seed::try_from(semilla.as_slice()).expect("semilla de 64 bytes");
        let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
        let ek = dk.encapsulation_key().to_bytes();
        assert_eq!(
            ek.as_slice(),
            hex_a_bytes(c["ek"].as_str().expect("campo ek")).as_slice(),
            "ML-KEM-768 dejó de derivar la ek FIPS del vector ACVP keyGen tc {}",
            c["tcId"]
        );
    }
    println!("ML-KEM-768 keyGen contra ACVP: {} tcs conformes", casos.len());
}

/// encaps (AFT): genera el par de pruebas por tamaño. Afirma `c` Y `k` contra
/// NIST, y trae su CONTROL (D33): mutar `m` debe cambiar `k` por la vía real.
macro_rules! prueba_encaps_acvp {
    ($nombre:ident, $param:ty, $archivo:literal, $etiqueta:literal) => {
        #[test]
        fn $nombre() {
            use ml_kem::{B32, Key};
            type Ek = ml_kem::EncapsulationKey<$param>;
            let casos = casos_acvp(include_str!($archivo));
            for c in &casos {
                let ek_b = hex_a_bytes(c["ek"].as_str().expect("campo ek"));
                let m_b = hex_a_bytes(c["m"].as_str().expect("campo m"));
                let c_esp = hex_a_bytes(c["c"].as_str().expect("campo c"));
                let k_esp = hex_a_bytes(c["k"].as_str().expect("campo k"));
                let encoded = Key::<Ek>::try_from(ek_b.as_slice()).expect("ek de tamaño válido");
                let ek = Ek::new(&encoded).expect("ek válida");
                let m = B32::try_from(m_b.as_slice()).expect("m de 32 bytes");
                let (ct, k) = ek.encapsulate_deterministic(&m);
                assert_eq!(ct.as_slice(), c_esp.as_slice(),
                    "{} dejó de producir el ciphertext ACVP en encaps tc {}", $etiqueta, c["tcId"]);
                assert_eq!(k.as_slice(), k_esp.as_slice(),
                    "{} dejó de producir el secreto ACVP en encaps tc {}", $etiqueta, c["tcId"]);
            }
            // CONTROL (D33): mutar la moneda `m` DEBE cambiar `k`; si no, la prueba
            // no discriminaría un cómputo equivocado.
            {
                let c0 = &casos[0];
                let ek_b = hex_a_bytes(c0["ek"].as_str().unwrap());
                let mut m_b = hex_a_bytes(c0["m"].as_str().unwrap());
                let k_esp = hex_a_bytes(c0["k"].as_str().unwrap());
                m_b[0] ^= 0x01;
                let encoded = Key::<Ek>::try_from(ek_b.as_slice()).unwrap();
                let ek = Ek::new(&encoded).unwrap();
                let m = B32::try_from(m_b.as_slice()).unwrap();
                let (_ct, k) = ek.encapsulate_deterministic(&m);
                assert_ne!(k.as_slice(), k_esp.as_slice(),
                    "{} CONTROL: una `m` mutada produjo el mismo `k` — la prueba no discrimina", $etiqueta);
            }
            println!("{} encaps contra ACVP: {} tcs conformes (+control)", $etiqueta, casos.len());
        }
    };
}
prueba_encaps_acvp!(ml_kem_768_conforma_encaps_acvp, ml_kem::MlKem768, "vectors/acvp_mlkem768_encap.json", "ML-KEM-768");
prueba_encaps_acvp!(ml_kem_1024_conforma_encaps_acvp, ml_kem::MlKem1024, "vectors/acvp_mlkem1024_encap.json", "ML-KEM-1024");

/// decaps (VAL): genera el par de pruebas por tamaño. Carga la `dk` EXPANDIDA de
/// ACVP y afirma el `k` recuperado. CONTROL (D33): mutar `c` debe cambiar `k`
/// (rechazo implícito de ML-KEM: una `c` corrupta da otro secreto).
macro_rules! prueba_decaps_acvp {
    ($nombre:ident, $param:ty, $archivo:literal, $etiqueta:literal) => {
        // La `dk` de un vector ACVP-VAL viene EXPANDIDA (no como semilla), así que
        // hay que cargarla con `ExpandedKeyEncoding::from_expanded_bytes`, que
        // `ml-kem` 0.3 marcó deprecada. Es la MISMA vía que usa `src/pqhybrid.rs`
        // para leer claves antiguas; el allow cubre el `use` del trait y la llamada.
        #[test]
        #[allow(deprecated)]
        fn $nombre() {
            use ml_kem::kem::Decapsulate;
            use ml_kem::{DecapsulationKey, ExpandedDecapsulationKey, ExpandedKeyEncoding};
            let casos = casos_acvp(include_str!($archivo));
            for c in &casos {
                let dk_b = hex_a_bytes(c["dk"].as_str().expect("campo dk"));
                let c_b = hex_a_bytes(c["c"].as_str().expect("campo c"));
                let k_esp = hex_a_bytes(c["k"].as_str().expect("campo k"));
                let exp = ExpandedDecapsulationKey::<$param>::try_from(dk_b.as_slice())
                    .expect("dk expandida de tamaño válido");
                #[allow(deprecated)]
                let dk = DecapsulationKey::<$param>::from_expanded_bytes(&exp).expect("dk desde expandida");
                let ct = ml_kem::Ciphertext::<$param>::try_from(c_b.as_slice()).expect("ciphertext válido");
                let k = dk.decapsulate(&ct);
                assert_eq!(k.as_slice(), k_esp.as_slice(),
                    "{} dejó de recuperar el secreto ACVP en decaps tc {}", $etiqueta, c["tcId"]);
            }
            // CONTROL (D33): mutar el ciphertext DEBE cambiar `k`.
            {
                let c0 = &casos[0];
                let dk_b = hex_a_bytes(c0["dk"].as_str().unwrap());
                let mut c_b = hex_a_bytes(c0["c"].as_str().unwrap());
                let k_esp = hex_a_bytes(c0["k"].as_str().unwrap());
                c_b[0] ^= 0x01;
                let exp = ExpandedDecapsulationKey::<$param>::try_from(dk_b.as_slice()).unwrap();
                #[allow(deprecated)]
                let dk = DecapsulationKey::<$param>::from_expanded_bytes(&exp).unwrap();
                let ct = ml_kem::Ciphertext::<$param>::try_from(c_b.as_slice()).unwrap();
                let k = dk.decapsulate(&ct);
                assert_ne!(k.as_slice(), k_esp.as_slice(),
                    "{} CONTROL: una `c` mutada produjo el mismo `k` — la prueba no discrimina", $etiqueta);
            }
            println!("{} decaps contra ACVP: {} tcs conformes (+control)", $etiqueta, casos.len());
        }
    };
}
prueba_decaps_acvp!(ml_kem_768_conforma_decaps_acvp, ml_kem::MlKem768, "vectors/acvp_mlkem768_decap.json", "ML-KEM-768");
prueba_decaps_acvp!(ml_kem_1024_conforma_decaps_acvp, ml_kem::MlKem1024, "vectors/acvp_mlkem1024_decap.json", "ML-KEM-1024");
