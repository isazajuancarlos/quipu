// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! N9: los contenedores de una misma persona no deben AGRUPARSE por su
//! metadato en claro.
//!
//! # Por qué esta simulación, si ya hay pruebas unitarias
//!
//! Los dos cambios que cierran N9 —la escalera canónica del KDF y el
//! `codebook_id` escrito siempre en cero— llegaron con pruebas unitarias
//! buenas, y ninguna de las dos puede sostener la afirmación que hacen.
//!
//! `la_escalera_colapsa_la_huella_de_configuracion` compara **las constantes de
//! la API**: cuenta las huellas de `KdfParams::canonicos()`. Que la escalera
//! tenga tres peldaños no dice nada sobre lo que `encode` acaba escribiendo en
//! un contenedor — mide el catálogo, no el producto.
//!
//! Y la afirmación es de POBLACIÓN: «todo el que use `EQUILIBRADO` se ve
//! igual», «el campo deja de agrupar los archivos de un mismo dueño». Una
//! afirmación sobre un conjunto no se verifica con un elemento del conjunto,
//! por muchos asertos que se le pongan. Hace falta escribir muchos contenedores,
//! de muchos autores distintos, y mirar si el metadato los separa.
//!
//! # Qué mide EXACTAMENTE
//!
//! Los bytes de cabecera que (a) viajan en claro y (b) son ESTABLES entre los
//! contenedores de un mismo autor. Según `quipu_nucleo::container`:
//!
//! ```text
//! magic(4) version(1) flags(1) codebook_id(2) huella(8) salt(16) nonce(24)
//! kdf_mem_kib(4) kdf_iterations(4) kdf_parallelism(4)
//! ```
//!
//! De ahí se toman `flags`, `codebook_id` y los doce del KDF. **El salt y el
//! nonce quedan fuera a propósito**: son frescos en cada operación, así que no
//! agrupan nada y meterlos daría 126 huellas distintas y un verde falso — la
//! medida diría «no hay agrupamiento» por la razón equivocada.
//!
//! La huella del alfabeto (bytes 8..16) también queda fuera, y esa exclusión SÍ
//! es una limitación declarada y no una simplificación: quien use un alfabeto
//! propio se distingue por ella. No es lo que estos dos cambios prometieron
//! arreglar, y confundirlo sería medir otra cosa (directiva 16).
//!
//! # El coste, medido, y por qué NO se recorta la población
//!
//! Es la prueba más lenta del árbol: **90 s en debug, 7,9 s en release**
//! (2026-08-02, 126 contenedores en 13 hilos). El grueso es Argon2id, que en
//! debug sale ~11× inflado — el mismo factor que casi rebaja el KDF una vez.
//!
//! Remedido a solas el 2026-08-03: **93,45 s debug / 6,43 s release**, o sea que
//! la cifra de arriba se sostiene. Pero DENTRO de la pasada completa
//! (`cargo test --workspace --all-targets`) el mismo binario tardó **132,89 s**
//! — un 42 % más, por contención de CPU con el resto de la suite. Es el número
//! que hay que usar para presupuestar el CI: medir la prueba aislada subestima
//! lo que va a costar donde de verdad corre (directiva 16).
//!
//! La tentación evidente es encoger la población, y **es justo lo que no se
//! puede hacer**: la afirmación que aquí se verifica es que el metadato no
//! separa a MUCHOS autores. Con tres personas el aserto «ninguna huella
//! identifica a un autor» se cumple por casualidad aritmética, no porque el
//! mecanismo funcione. Si hay que abaratarla, se quitan contenedores de
//! `FUERTE` —que cuesta 2,47 s cada uno y aporta el 37 % del tiempo con el 5 %
//! de las muestras—, nunca personas.
//!
//! # Probado que DISCRIMINA (2026-08-02)
//!
//! Con `codebook_id: opts.codebook_id` reintroducido en `encode_to_blob`:
//! «13 huellas distintas para 13 autores», rojo. Con el Associated Data
//! sustituido por una constante: rojo en el camino de error. Sin esos dos
//! rojos, el verde de aquí no significaría nada.

use std::collections::{HashMap, HashSet};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use quipu::api::{self, Options};
use quipu::dictionary::HuellaDeCodebook;
use quipu::kdf::KdfParams;

/// Desplazamientos de la cabecera del perfil `quipu` (SALT=16, NONCE=24).
const FLAGS: usize = 5;
const CODEBOOK_ID: std::ops::Range<usize> = 6..8;
const KDF: std::ops::Range<usize> = 56..68;
const HEADER_SIZE: usize = 68;

/// Los bytes en claro y estables de la cabecera. Ver el encabezado del archivo.
fn huella_de_metadato(blob: &[u8]) -> Vec<u8> {
    assert!(blob.len() >= HEADER_SIZE, "blob más corto que una cabecera");
    let mut h = Vec::with_capacity(15);
    h.push(blob[FLAGS]);
    h.extend_from_slice(&blob[CODEBOOK_ID]);
    h.extend_from_slice(&blob[KDF]);
    h
}

/// Una persona con su configuración: frase, pepper, el `codebook_id` que PIDE
/// y el peldaño que eligió.
struct Persona {
    id: u16,
    frase: String,
    pepper: Vec<u8>,
    peldano: KdfParams,
    cuantos: usize,
}

/// El reparto de la población.
///
/// No es uniforme, y el motivo es el coste medido en release el 2026-08-02:
/// `LIGERO` 235 ms, `EQUILIBRADO` 399 ms, `FUERTE` 2,47 s por operación. Un
/// reparto a partes iguales lo dominaría `FUERTE` y la prueba tardaría minutos
/// sin medir nada más. Lo que la afirmación necesita es MUCHOS autores y que
/// **cada peldaño lo compartan al menos dos**, no simetría.
fn poblacion() -> Vec<Persona> {
    let mut v = Vec::new();
    let mut id = 1u16;
    for (peldano, personas, cuantos) in [
        (KdfParams::LIGERO, 8usize, 12usize),
        (KdfParams::EQUILIBRADO, 3, 8),
        (KdfParams::FUERTE, 2, 3),
    ] {
        for _ in 0..personas {
            v.push(Persona {
                id,
                frase: format!("la frase larga y distinta de la persona {id}"),
                // El pepper es un secreto que vive FUERA del dato: cambia la
                // clave y NO debe aparecer en la cabecera. Se varía justamente
                // para comprobar que no se filtra por ahí.
                pepper: format!("pepper-{id}").into_bytes(),
                peldano,
                cuantos,
            });
            id += 1;
        }
    }
    v
}

/// Escribe los contenedores de toda la población, en paralelo y con plazo.
///
/// Sin `recv_timeout` un interbloqueo se ve igual que una compilación lenta —
/// la trampa de `Once::call_once` costó 13 minutos de eso.
fn escribir_poblacion() -> Vec<(u16, Vec<u8>)> {
    let dict = quipu::dictionaries::ascii94();
    let huella_dict = dict.fingerprint();
    let personas = poblacion();
    let total: usize = personas.iter().map(|p| p.cuantos).sum();
    assert!(total >= 100, "la directiva 8 pide 100+ operaciones, hay {total}");

    let (tx, rx) = mpsc::channel();
    let mut hilos = Vec::new();
    for p in personas {
        let tx = tx.clone();
        hilos.push(thread::spawn(move || {
            for n in 0..p.cuantos {
                let opts = Options {
                    pepper: &p.pepper,
                    kdf_params: p.peldano,
                    // CADA PERSONA PIDE UN VALOR DISTINTO Y NO NULO. Es el
                    // corazón de la prueba: si `encode` respetara la petición,
                    // este campo sería un identificador de autor perfecto.
                    codebook_id: p.id,
                };
                let dato = format!("documento {n} de la persona {}", p.id);
                let blob = api::encode_to_blob(dato.as_bytes(), &p.frase, huella_dict, &opts);
                tx.send((p.id, blob)).expect("el receptor sigue vivo");
            }
        }));
    }
    drop(tx);

    let mut salida = Vec::with_capacity(total);
    for _ in 0..total {
        salida.push(
            rx.recv_timeout(Duration::from_secs(600))
                .expect("un hilo se colgó o murió: interbloqueo, no lentitud"),
        );
    }
    for h in hilos {
        h.join().expect("un hilo entró en pánico");
    }
    salida
}

/// Cuántas personas hay detrás de cada huella observable.
fn autores_por_huella(muestras: &[(u16, Vec<u8>)]) -> HashMap<Vec<u8>, HashSet<u16>> {
    let mut m: HashMap<Vec<u8>, HashSet<u16>> = HashMap::new();
    for (id, blob) in muestras {
        m.entry(huella_de_metadato(blob)).or_default().insert(*id);
    }
    m
}

#[test]
fn el_metadato_en_claro_no_separa_a_los_autores() {
    let muestras = escribir_poblacion();
    let personas: HashSet<u16> = muestras.iter().map(|(id, _)| *id).collect();
    let por_huella = autores_por_huella(&muestras);

    // 1. La escalera colapsa: como mucho tres huellas, se escriba lo que se
    //    escriba, y NO una por persona.
    assert!(
        por_huella.len() <= 3,
        "{} huellas distintas para {} autores: la escalera no está colapsando \
         lo que se ESCRIBE (solo lo que se ofrece)",
        por_huella.len(),
        personas.len()
    );

    // 2. Ninguna huella identifica a un autor. Es la afirmación de N9 dicha
    //    como se puede medir: compartir huella con alguien es lo que impide
    //    que agrupe.
    for (h, autores) in &por_huella {
        assert!(
            autores.len() >= 2,
            "la huella {h:02x?} la escribe UN SOLO autor ({autores:?}): eso es \
             exactamente el agrupamiento que N9 dice haber cerrado"
        );
    }

    // 3. `codebook_id` sale en cero AUNQUE cada persona pidiera el suyo.
    for (id, blob) in &muestras {
        assert_eq!(
            &blob[CODEBOOK_ID],
            &[0, 0],
            "la persona {id} pidió codebook_id={id} y se coló en la cabecera"
        );
        assert_eq!(blob[FLAGS], 0, "flags dejó de ser cero sin decidirlo nadie");
    }
}

/// El caso rojo que valida el MEDIDOR.
///
/// Sin esto, `el_metadato_en_claro_no_separa_a_los_autores` podría estar
/// pasando porque `huella_de_metadato` mira los bytes equivocados y devuelve
/// siempre lo mismo — un generador de ceros aprueba cualquier cosa. Aquí se le
/// da a la MISMA función la forma que tenían las cabeceras ANTES del colapso
/// (parámetros a mano + `codebook_id` por autor) y se exige que sí los separe.
#[test]
fn el_medidor_detecta_el_agrupamiento_cuando_existe() {
    let mut muestras: Vec<(u16, Vec<u8>)> = Vec::new();
    for id in 1u16..=12 {
        for _ in 0..5 {
            let mut blob = vec![0u8; HEADER_SIZE];
            blob[FLAGS] = 0;
            blob[CODEBOOK_ID].clone_from_slice(&id.to_be_bytes());
            // Ajuste «a gusto de cada uno», que es lo que la escalera retiró.
            let mem: u32 = 32_768 + u32::from(id) * 1_024;
            let iters: u32 = 2 + u32::from(id % 4);
            let par: u32 = 1 + u32::from(id % 3);
            blob[KDF.start..KDF.start + 4].clone_from_slice(&mem.to_be_bytes());
            blob[KDF.start + 4..KDF.start + 8].clone_from_slice(&iters.to_be_bytes());
            blob[KDF.start + 8..KDF.end].clone_from_slice(&par.to_be_bytes());
            // Salt y nonce frescos: si el medidor los mirara, cada contenedor
            // sería único y el agrupamiento quedaría oculto.
            muestras.push((id, blob));
        }
    }

    let por_huella = autores_por_huella(&muestras);
    assert_eq!(
        por_huella.len(),
        12,
        "el medidor NO distingue doce configuraciones distintas: entonces el \
         verde de la otra prueba no significa nada"
    );
    for autores in por_huella.values() {
        assert_eq!(autores.len(), 1, "cada huella de antes delataba a su autor");
    }
}

/// Camino de error inyectado: el metadato está AUTENTICADO.
///
/// Que el metadato ya no agrupe sirve de poco si un atacante puede reescribirlo
/// en tránsito. La cabecera entera es el Associated Data del AEAD, así que
/// tocar un solo bit de los parámetros del KDF tiene que hacer fallar el
/// descifrado — sin pánico y sin abrirse.
#[test]
fn tocar_el_metadato_rompe_el_descifrado_sin_reventar() {
    let dict = quipu::dictionaries::ascii94();
    let opts = Options {
        pepper: b"pimienta",
        kdf_params: KdfParams::LIGERO,
        codebook_id: 0,
    };
    let bueno = api::encode_to_blob(b"secreto", "una frase de prueba", dict.fingerprint(), &opts);
    assert!(
        api::decode_from_blob(&bueno, "una frase de prueba", dict.fingerprint(), b"pimienta")
            .is_ok(),
        "el contenedor intacto tiene que abrirse, o la prueba mide otra cosa"
    );

    for i in [FLAGS, CODEBOOK_ID.start, KDF.start, KDF.end - 1] {
        let mut malo = bueno.clone();
        malo[i] ^= 0x01;
        let r = api::decode_from_blob(
            &malo,
            "una frase de prueba",
            dict.fingerprint(),
            b"pimienta",
        );
        assert!(
            r.is_err(),
            "el byte {i} de metadato se alteró y el contenedor se abrió igual: \
             la cabecera no está atada al ciphertext"
        );
    }
}

/// La medida se hace sobre el blob; el producto que sale al mundo es la cadena
/// de símbolos. Esta prueba comprueba que no son dos caminos distintos —si
/// `encode` escribiera una cabecera diferente de `encode_to_blob`, todo lo
/// anterior estaría midiendo una puerta lateral.
#[test]
fn el_camino_de_simbolos_escribe_la_misma_cabecera() {
    let dict = quipu::dictionaries::ascii94();
    let opts = Options {
        pepper: b"",
        kdf_params: KdfParams::LIGERO,
        codebook_id: 0xBEEF,
    };
    let simbolos = api::encode(b"secreto", "una frase de prueba", &dict, &opts);
    let indices = dict.decode(&simbolos).expect("los símbolos son del alfabeto");
    let blob = quipu::codec::decode_base_n(&indices, dict.base());

    assert_eq!(&blob[CODEBOOK_ID], &[0, 0], "el camino de símbolos sí coló el codebook_id");
    assert_eq!(
        &blob[KDF],
        &{
            let mut v = Vec::new();
            v.extend_from_slice(&KdfParams::LIGERO.mem_kib.to_be_bytes());
            v.extend_from_slice(&KdfParams::LIGERO.iterations.to_be_bytes());
            v.extend_from_slice(&KdfParams::LIGERO.parallelism.to_be_bytes());
            v
        }[..],
        "los dos caminos escriben parámetros distintos"
    );
}
