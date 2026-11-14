//! Known-answer tests de interoperabilidad. Cargan `tests/vectors/quipu_vectors.json`
//! (generado por `examples/gen_vectors.rs`) y verifican que la implementación lo
//! reproduce. Los vectores deterministas se recomputan BYTE A BYTE (congelan el
//! formato); los congelados se comprueban en la dirección descifrado/verificación.
//!
//! Si un cambio de formato es intencionado, regenera con:
//!   cargo run --example gen_vectors --features honey

use quipu::api::{decode_as_recipient, decode_from_blob, decode_verified};
use quipu::dictionaries::ascii94;
use quipu::kdf::{self, KdfParams, SALT_LEN};
use quipu::stream::decrypt_stream_bytes;
use quipu::{cipher, container, pqhybrid, pqsign, prelayers};
use serde_json::Value;

const VJSON: &str = include_str!("vectors/quipu_vectors.json");
const CIPHER_SUBKEY_INFO: &[u8] = b"quipu/v1/cipher";

fn doc() -> Value {
    serde_json::from_str(VJSON).expect("JSON de vectores válido")
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn u32v(v: &Value, k: &str) -> u32 {
    v[k].as_u64().expect("u64") as u32
}

fn params_of(v: &Value) -> KdfParams {
    KdfParams {
        mem_kib: u32v(v, "mem_kib"),
        iterations: u32v(v, "iterations"),
        parallelism: u32v(v, "parallelism"),
    }
}

fn arr<'a>(d: &'a Value, group: &str, name: &str) -> &'a Vec<Value> {
    d[group][name].as_array().expect("array de vectores")
}

fn salt16(hexs: &str) -> [u8; SALT_LEN] {
    from_hex(hexs).try_into().expect("16 bytes de salt")
}

#[test]
fn kdf_master_key_vectors() {
    let d = doc();
    for v in arr(&d, "deterministic", "kdf_master") {
        let got = kdf::derive_master_key(
            v["passphrase"].as_str().unwrap(),
            &salt16(v["salt_hex"].as_str().unwrap()),
            &from_hex(v["pepper_hex"].as_str().unwrap()),
            &params_of(v),
        );
        assert_eq!(hex(&got), v["master_key_hex"].as_str().unwrap(), "{}", v["desc"]);
    }
}

#[test]
fn kdf_subkey_vectors() {
    let d = doc();
    for v in arr(&d, "deterministic", "kdf_subkey") {
        let master: [u8; 32] = from_hex(v["master_hex"].as_str().unwrap()).try_into().unwrap();
        let got = kdf::derive_subkey(&master, v["info_utf8"].as_str().unwrap().as_bytes());
        assert_eq!(hex(&got), v["subkey_hex"].as_str().unwrap(), "{}", v["desc"]);
    }
}

#[test]
fn aead_vectors_roundtrip_and_match() {
    let d = doc();
    for v in arr(&d, "deterministic", "aead_xchacha20poly1305") {
        let key: [u8; 32] = from_hex(v["key_hex"].as_str().unwrap()).try_into().unwrap();
        let nonce: [u8; 24] = from_hex(v["nonce_hex"].as_str().unwrap()).try_into().unwrap();
        let aad = from_hex(v["aad_hex"].as_str().unwrap());
        let pt = from_hex(v["plaintext_hex"].as_str().unwrap());
        let ct = cipher::encrypt(&key, &nonce, &pt, &aad);
        assert_eq!(hex(&ct), v["ciphertext_hex"].as_str().unwrap(), "{}", v["desc"]);
        assert_eq!(cipher::decrypt(&key, &nonce, &ct, &aad).unwrap(), pt);
    }
}

#[test]
fn padme_vectors() {
    let d = doc();
    for v in arr(&d, "deterministic", "padme") {
        let data = from_hex(v["data_hex"].as_str().unwrap());
        let padded = prelayers::pad(&data);
        assert_eq!(hex(&padded), v["padded_hex"].as_str().unwrap(), "{}", v["desc"]);
        assert_eq!(prelayers::unpad(&padded).unwrap(), data);
    }
}

#[test]
fn symmetric_container_is_byte_exact() {
    let d = doc();
    for v in arr(&d, "deterministic", "container_symmetric") {
        let pw = v["passphrase"].as_str().unwrap();
        let salt = salt16(v["salt_hex"].as_str().unwrap());
        let nonce: [u8; 24] = from_hex(v["nonce_hex"].as_str().unwrap()).try_into().unwrap();
        let pepper = from_hex(v["pepper_hex"].as_str().unwrap());
        let params = params_of(v);
        let fp: [u8; 8] = from_hex(v["fingerprint_hex"].as_str().unwrap()).try_into().unwrap();
        let pt = from_hex(v["plaintext_hex"].as_str().unwrap());

        // Reconstrucción byte a byte según la SPEC.
        let master = kdf::derive_master_key(pw, &salt, &pepper, &params);
        let cipher_key = kdf::derive_subkey(&master, CIPHER_SUBKEY_INFO);
        let padded = prelayers::pad(&pt);
        let header = container::Header {
            version: container::VERSION,
            flags: 0,
            codebook_id: u32v(v, "codebook_id") as u16,
            codebook_hash_prefix: fp,
            salt,
            nonce,
            kdf_mem_kib: params.mem_kib,
            kdf_iterations: params.iterations,
            kdf_parallelism: params.parallelism,
        };
        let aad = header.to_bytes();
        let ct = cipher::encrypt(&cipher_key, &nonce, &padded, &aad);
        let blob = container::serialize(&header, &ct);

        assert_eq!(hex(&blob), v["blob_hex"].as_str().unwrap(), "formato QUIP: {}", v["desc"]);
        // Y descifra a su texto.
        assert_eq!(decode_from_blob(&blob, pw, fp, &pepper).unwrap(), pt);
    }
}

#[cfg(feature = "honey")]
#[test]
fn honey_container_is_byte_exact_and_decoys() {
    use quipu::honey;
    const HONEY_INFO: &[u8] = b"quipu-honey-v1/pad";
    let d = doc();
    for v in arr(&d, "deterministic", "honey") {
        let pw = v["passphrase"].as_str().unwrap();
        let salt = salt16(v["salt_hex"].as_str().unwrap());
        let pepper = from_hex(v["pepper_hex"].as_str().unwrap());
        let params = params_of(v);
        let alphabet = u32v(v, "alphabet") as u16;
        let tokens: Vec<u16> = v["tokens"].as_array().unwrap().iter().map(|t| t.as_u64().unwrap() as u16).collect();

        // Reconstrucción byte a byte del contenedor QHNY.
        let master = kdf::derive_master_key(pw, &salt, &pepper, &params);
        let mut buf = vec![0u8; tokens.len() * 8];
        kdf::derive_stream(&master, HONEY_INFO, &mut buf);
        let a = alphabet as u64;
        let mut blob = Vec::new();
        blob.extend_from_slice(b"QHNY");
        blob.push(1);
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&params.mem_kib.to_be_bytes());
        blob.extend_from_slice(&params.iterations.to_be_bytes());
        blob.extend_from_slice(&params.parallelism.to_be_bytes());
        blob.extend_from_slice(&alphabet.to_be_bytes());
        blob.extend_from_slice(&(tokens.len() as u32).to_be_bytes());
        for (i, &t) in tokens.iter().enumerate() {
            let k = (u64::from_be_bytes(buf[i * 8..i * 8 + 8].try_into().unwrap()) % a) as u16;
            let c = ((t as u32 + k as u32) % alphabet as u32) as u16;
            blob.extend_from_slice(&c.to_be_bytes());
        }
        assert_eq!(hex(&blob), v["blob_hex"].as_str().unwrap(), "formato QHNY: {}", v["desc"]);

        // La clave correcta recupera el secreto; la equivocada, el señuelo fijado.
        assert_eq!(honey::decrypt(&blob, pw, &pepper).unwrap(), tokens);
        let decoy_pw = v["decoy_passphrase"].as_str().unwrap();
        let decoy: Vec<u16> = v["decoy_tokens"].as_array().unwrap().iter().map(|t| t.as_u64().unwrap() as u16).collect();
        assert_eq!(honey::decrypt(&blob, decoy_pw, &pepper).unwrap(), decoy, "señuelo determinista");
    }
}

#[test]
fn streaming_decode_vectors() {
    let d = doc();
    for v in arr(&d, "frozen", "streaming_decode") {
        let blob = from_hex(v["blob_hex"].as_str().unwrap());
        let pt = from_hex(v["plaintext_hex"].as_str().unwrap());
        let pepper = from_hex(v["pepper_hex"].as_str().unwrap());
        let got = decrypt_stream_bytes(&blob, v["passphrase"].as_str().unwrap(), &pepper).unwrap();
        assert_eq!(got, pt, "{}", v["desc"]);
    }
}

#[test]
fn recipient_decode_vectors() {
    let d = doc();
    let dict = ascii94();
    for v in arr(&d, "frozen", "recipient_decode") {
        let sk = pqhybrid::SecretKey::from_bytes(&from_hex(v["secret_key_hex"].as_str().unwrap()))
            .expect("clave secreta válida");
        let pt = from_hex(v["plaintext_hex"].as_str().unwrap());
        let got = decode_as_recipient(v["symbols"].as_str().unwrap(), &sk, &dict).unwrap();
        assert_eq!(got, pt, "{}", v["desc"]);
    }
}

#[test]
fn signed_verify_vectors() {
    let d = doc();
    let dict = ascii94();
    for v in arr(&d, "frozen", "signed_verify") {
        let vk = pqsign::VerifyingKey::from_bytes(&from_hex(v["verifying_key_hex"].as_str().unwrap()))
            .expect("clave de verificación válida");
        let msg = from_hex(v["message_hex"].as_str().unwrap());
        let got = decode_verified(v["symbols"].as_str().unwrap(), &vk, &dict).unwrap();
        assert_eq!(got, msg, "{}", v["desc"]);
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
