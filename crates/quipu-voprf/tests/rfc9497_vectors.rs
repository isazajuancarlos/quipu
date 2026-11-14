//! Vectores oficiales de RFC 9497, Apendice A.1.2 (VOPRF, ristretto255-SHA512).
//!
//! Copiados literalmente del texto de la RFC (rfc-editor.org), no reconstruidos:
//! un vector inventado que "pasa" es peor que no tener vector.
//!
//! Estos tests son lo que separa "conforme a RFC 9497" de "inspirado en". Si
//! fallan, la implementacion NO es conforme y no debe decir que lo es.

use curve25519_dalek::Scalar;
use quipu_voprf::rfc9497::{
    blind_with, derive_key_pair, finalize, BlindState, Server, OUTPUT_LEN, PROOF_LEN,
};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn arr32(s: &str) -> [u8; 32] {
    hex(s).try_into().unwrap()
}

fn scalar(s: &str) -> Scalar {
    // Los escalares de la RFC estan en little-endian canonico.
    Option::<Scalar>::from(Scalar::from_canonical_bytes(arr32(s))).expect("escalar canonico")
}

const SEED: &str = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3";
const KEY_INFO: &str = "74657374206b6579"; // "test key"
const SK_SM: &str = "e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909";
const PK_SM: &str = "c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e";

struct Vector {
    input: &'static str,
    blind: &'static str,
    blinded_element: &'static str,
    evaluation_element: &'static str,
    proof: &'static str,
    proof_random_scalar: &'static str,
    output: &'static str,
}

// A.1.2.1 y A.1.2.2 (lote 1). El vector 3 es de lote 2: nuestro API no expone
// lotes, asi que queda fuera de alcance y se dice en vez de fingir cobertura.
const VECTORS: &[Vector] = &[
    Vector {
        input: "00",
        blind: "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
        blinded_element: "863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945",
        evaluation_element: "aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e",
        proof: "ddef93772692e535d1a53903db24367355cc2cc78de93b3be5a8ffcc6985dd066d4346421d17bf5117a2a1ff0fcb2a759f58a539dfbe857a40bce4cf49ec600d",
        proof_random_scalar: "222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e",
        output: "b58cfbe118e0cb94d79b5fd6a6dafb98764dff49c14e1770b566e42402da1a7da4d8527693914139caee5bd03903af43a491351d23b430948dd50cde10d32b3c",
    },
    Vector {
        input: "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
        blind: "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
        blinded_element: "cc0b2a350101881d8a4cba4c80241d74fb7dcbfde4a61fde2f91443c2bf9ef0c",
        evaluation_element: "60a59a57208d48aca71e9e850d22674b611f752bed48b36f7a91b372bd7ad468",
        proof: "401a0da6264f8cf45bb2f5264bc31e109155600babb3cd4e5af7d181a2c9dc0a67154fabf031fd936051dec80b0b6ae29c9503493dde7393b722eafdf5a50b02",
        proof_random_scalar: "222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e",
        output: "8a9a2f3c7f085b65933594309041fc1898d42d0858e59f90814ae90571a6df60356f4610bf816f27afdd84f47719e480906d27ecd994985890e5f539e7ea74b6",
    },
];

/// DeriveKeyPair (§3.2). El DST es "DeriveKeyPair" || contextString, SIN guion:
/// si te lo pones, sale otra clave y este test lo caza.
#[test]
fn derive_key_pair_reproduce_el_vector() {
    let sk = derive_key_pair(&hex(SEED), &hex(KEY_INFO)).expect("DeriveKeyPair");
    assert_eq!(
        hex_de(sk.as_bytes()),
        SK_SM,
        "la clave secreta derivada no coincide con skSm de la RFC"
    );
    let server = Server::from_scalar(sk);
    assert_eq!(
        hex_de(&server.public_key()),
        PK_SM,
        "la clave publica no coincide con pkSm de la RFC"
    );
}

#[test]
fn blind_reproduce_los_vectores() {
    for (i, v) in VECTORS.iter().enumerate() {
        let (_, blinded) = blind_with(&hex(v.input), scalar(v.blind)).expect("blind");
        assert_eq!(
            hex_de(&blinded),
            v.blinded_element,
            "vector {}: BlindedElement no coincide (hash_to_group mal)",
            i + 1
        );
    }
}

#[test]
fn blind_evaluate_y_prueba_reproducen_los_vectores() {
    let sk = derive_key_pair(&hex(SEED), &hex(KEY_INFO)).unwrap();
    let server = Server::from_scalar(sk);
    for (i, v) in VECTORS.iter().enumerate() {
        let (evaluated, proof) = server
            .blind_evaluate_with_randomness(&arr32(v.blinded_element), scalar(v.proof_random_scalar))
            .expect("blind_evaluate");
        assert_eq!(
            hex_de(&evaluated),
            v.evaluation_element,
            "vector {}: EvaluationElement no coincide",
            i + 1
        );
        assert_eq!(
            hex_de(&proof),
            v.proof,
            "vector {}: la prueba DLEQ no coincide (transcripcion mal)",
            i + 1
        );
    }
}

/// El de verdad: el flujo entero contra los vectores. Si esto pasa, somos
/// interoperables con cualquier otra implementacion de RFC 9497.
#[test]
fn finalize_reproduce_la_salida_de_los_vectores() {
    for (i, v) in VECTORS.iter().enumerate() {
        let (state, _) = blind_with(&hex(v.input), scalar(v.blind)).unwrap();
        let out = finalize(
            &hex(v.input),
            &state,
            &arr32(v.evaluation_element),
            &hex(v.proof).try_into().unwrap(),
            &arr32(PK_SM),
        )
        .expect("finalize: la prueba de la RFC debe validar");
        assert_eq!(
            hex_de(&out),
            v.output,
            "vector {}: Output no coincide",
            i + 1
        );
        assert_eq!(out.len(), OUTPUT_LEN);
    }
}

/// Una prueba valida para OTRA clave publica no debe validar. Es el ataque que
/// la DLEQ existe para parar.
#[test]
fn finalize_rechaza_una_clave_publica_distinta() {
    let v = &VECTORS[0];
    let (state, _) = blind_with(&hex(v.input), scalar(v.blind)).unwrap();
    let otra = Server::from_scalar(scalar(
        "222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e",
    ))
    .public_key();
    assert!(
        finalize(
            &hex(v.input),
            &state,
            &arr32(v.evaluation_element),
            &hex(v.proof).try_into().unwrap(),
            &otra,
        )
        .is_none(),
        "una prueba contra otra clave NO debe validar"
    );
}

#[test]
fn finalize_rechaza_una_prueba_manipulada() {
    let v = &VECTORS[0];
    let (state, _) = blind_with(&hex(v.input), scalar(v.blind)).unwrap();
    let mut proof: [u8; PROOF_LEN] = hex(v.proof).try_into().unwrap();
    proof[0] ^= 1;
    assert!(
        finalize(
            &hex(v.input),
            &state,
            &arr32(v.evaluation_element),
            &proof,
            &arr32(PK_SM),
        )
        .is_none(),
        "una prueba con un bit cambiado NO debe validar"
    );
}

#[test]
fn el_estado_sobrevive_a_la_serializacion() {
    let v = &VECTORS[0];
    let (state, _) = blind_with(&hex(v.input), scalar(v.blind)).unwrap();
    let round = BlindState::from_bytes(&state.to_bytes()).expect("deserializa");
    let out = finalize(
        &hex(v.input),
        &round,
        &arr32(v.evaluation_element),
        &hex(v.proof).try_into().unwrap(),
        &arr32(PK_SM),
    )
    .expect("finalize tras serializar");
    assert_eq!(hex_de(&out), v.output);
}

fn hex_de(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
