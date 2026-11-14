//! Genera los vectores de interoperabilidad (known-answer tests) en
//! `tests/vectors/quipu_vectors.json`. Ejecutar tras un cambio INTENCIONADO de
//! formato:
//!
//!   cargo run --example gen_vectors --features honey
//!
//! Dos clases de vector:
//!   - **deterministas**: salt/nonce fijos -> salida byte a byte reproducible
//!     (KDF, AEAD, Padmé, contenedor simétrico `QUIP`, honey `QHNY`). Congelan
//!     el formato: cualquier cambio accidental rompe el test.
//!   - **congelados** (dirección descifrado): streaming, post-cuántico y firma
//!     usan aleatoriedad interna, así que se captura un artefacto y se fija el
//!     par (blob -> texto). El test verifica que el descifrado/verificación
//!     reproduce el resultado.
//!
//! Los parámetros Argon2id de los vectores son BARATOS a propósito (para que el
//! test corra rápido); el KAT fija el algoritmo, no el coste.

use quipu::api::{
    decode_from_blob, decode_as_recipient, decode_verified, encode_signed, encode_to_recipient,
};
use quipu::dictionaries::ascii94;
use quipu::kdf::{self, KdfParams, SALT_LEN};
use quipu::stream::{decrypt_stream_bytes, encrypt_stream_bytes, StreamOptions};
use quipu::{cipher, container, honey, pqhybrid, pqsign, prelayers};
use serde_json::json;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Coste barato para KATs (el algoritmo es lo que se fija, no el coste).
fn cheap() -> KdfParams {
    KdfParams {
        mem_kib: 64,
        iterations: 1,
        parallelism: 1,
    }
}

const CIPHER_SUBKEY_INFO: &[u8] = b"quipu/v1/cipher";
const HONEY_INFO: &[u8] = b"quipu-honey-v1/pad";

/// Construye un contenedor simétrico `QUIP` de forma determinista (salt/nonce
/// fijos), replicando la composición documentada en la SPEC.
#[allow(clippy::too_many_arguments)] // construir el contenedor necesita todos sus campos
fn build_symmetric(
    pt: &[u8],
    pw: &str,
    salt: [u8; SALT_LEN],
    nonce: [u8; 24],
    pepper: &[u8],
    params: &KdfParams,
    codebook_id: u16,
    fingerprint: [u8; 8],
) -> Vec<u8> {
    let master = kdf::derive_master_key(pw, &salt, pepper, params);
    let cipher_key = kdf::derive_subkey(&master, CIPHER_SUBKEY_INFO);
    let padded = prelayers::pad(pt);
    let header = container::Header {
        version: container::VERSION,
        flags: 0,
        codebook_id,
        codebook_hash_prefix: fingerprint,
        salt,
        nonce,
        kdf_mem_kib: params.mem_kib,
        kdf_iterations: params.iterations,
        kdf_parallelism: params.parallelism,
    };
    let aad = header.to_bytes();
    let ct = cipher::encrypt(&cipher_key, &nonce, &padded, &aad);
    container::serialize(&header, &ct)
}

/// Construye un contenedor honey `QHNY` de forma determinista (salt fijo).
fn build_honey(
    tokens: &[u16],
    alphabet: u16,
    pw: &str,
    salt: [u8; SALT_LEN],
    pepper: &[u8],
    params: &KdfParams,
) -> Vec<u8> {
    let master = kdf::derive_master_key(pw, &salt, pepper, params);
    let mut buf = vec![0u8; tokens.len() * 8];
    kdf::derive_stream(&master, HONEY_INFO, &mut buf);
    let a = alphabet as u64;
    let mut out = Vec::new();
    out.extend_from_slice(b"QHNY");
    out.push(1);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&params.mem_kib.to_be_bytes());
    out.extend_from_slice(&params.iterations.to_be_bytes());
    out.extend_from_slice(&params.parallelism.to_be_bytes());
    out.extend_from_slice(&alphabet.to_be_bytes());
    out.extend_from_slice(&(tokens.len() as u32).to_be_bytes());
    for (i, &t) in tokens.iter().enumerate() {
        let k = (u64::from_be_bytes(buf[i * 8..i * 8 + 8].try_into().unwrap()) % a) as u16;
        let c = ((t as u32 + k as u32) % alphabet as u32) as u16;
        out.extend_from_slice(&c.to_be_bytes());
    }
    out
}

fn main() {
    let salt: [u8; SALT_LEN] = std::array::from_fn(|i| (i as u8) + 1); // 01..10
    let nonce: [u8; 24] = std::array::from_fn(|i| (i as u8) + 0x20); // 20..37
    let params = cheap();
    let dict = ascii94();

    // ---- deterministas: KDF ----
    let master = kdf::derive_master_key("correct horse", &salt, b"", &params);
    let master_pep = kdf::derive_master_key("correct horse", &salt, b"pepper-app", &params);
    let kdf_vectors = json!([
        {
            "desc": "Argon2id maestro, sin pepper",
            "passphrase": "correct horse", "salt_hex": hex(&salt), "pepper_hex": "",
            "mem_kib": params.mem_kib, "iterations": params.iterations, "parallelism": params.parallelism,
            "master_key_hex": hex(&master)
        },
        {
            "desc": "Argon2id maestro, con pepper",
            "passphrase": "correct horse", "salt_hex": hex(&salt), "pepper_hex": hex(b"pepper-app"),
            "mem_kib": params.mem_kib, "iterations": params.iterations, "parallelism": params.parallelism,
            "master_key_hex": hex(&master_pep)
        }
    ]);

    // ---- deterministas: HKDF subkey ----
    let subkey = kdf::derive_subkey(&master, CIPHER_SUBKEY_INFO);
    let subkey_vectors = json!([
        {
            "desc": "HKDF-SHA256 subclave de cifrado",
            "master_hex": hex(&master), "info_utf8": "quipu/v1/cipher", "subkey_hex": hex(&subkey)
        }
    ]);

    // ---- deterministas: AEAD XChaCha20-Poly1305 ----
    let aead_key: [u8; 32] = std::array::from_fn(|i| (i as u8) ^ 0x5a);
    let aead_pt = b"XChaCha20-Poly1305 known-answer";
    let aead_aad = b"cabecera-como-AAD";
    let aead_ct = cipher::encrypt(&aead_key, &nonce, aead_pt, aead_aad);
    let aead_vectors = json!([
        {
            "desc": "XChaCha20-Poly1305, con AAD",
            "key_hex": hex(&aead_key), "nonce_hex": hex(&nonce), "aad_hex": hex(aead_aad),
            "plaintext_hex": hex(aead_pt), "ciphertext_hex": hex(&aead_ct)
        }
    ]);

    // ---- deterministas: Padmé ----
    let padme_vectors = json!([
        { "desc": "vacío", "data_hex": "", "padded_hex": hex(&prelayers::pad(b"")) },
        { "desc": "corto", "data_hex": hex(b"hola"), "padded_hex": hex(&prelayers::pad(b"hola")) },
        { "desc": "300 bytes", "data_hex": hex(&vec![7u8; 300]), "padded_hex": hex(&prelayers::pad(&vec![7u8; 300])) }
    ]);

    // ---- deterministas: contenedor simétrico QUIP ----
    let sym_pt = b"mensaje simetrico de known-answer";
    let fp = [0u8; 8];
    let sym_blob = build_symmetric(sym_pt, "correct horse", salt, nonce, b"", &params, 0, fp);
    assert_eq!(
        decode_from_blob(&sym_blob, "correct horse", fp, b"").unwrap(),
        sym_pt,
        "el vector simétrico debe descifrar a su texto"
    );
    let sym_vectors = json!([
        {
            "desc": "contenedor QUIP simétrico determinista",
            "passphrase": "correct horse", "salt_hex": hex(&salt), "nonce_hex": hex(&nonce),
            "pepper_hex": "", "mem_kib": params.mem_kib, "iterations": params.iterations,
            "parallelism": params.parallelism, "codebook_id": 0, "fingerprint_hex": hex(&fp),
            "plaintext_hex": hex(sym_pt), "blob_hex": hex(&sym_blob)
        }
    ]);

    // ---- deterministas: honey QHNY ----
    let honey_tokens: Vec<u16> = vec![4, 9, 1, 3];
    let honey_blob = build_honey(&honey_tokens, 10, "clave-honey", salt, b"", &params);
    let real = honey::decrypt(&honey_blob, "clave-honey", b"").unwrap();
    assert_eq!(real, honey_tokens, "honey debe recuperar el secreto real");
    let decoy = honey::decrypt(&honey_blob, "clave-equivocada", b"").unwrap();
    let honey_vectors = json!([
        {
            "desc": "honey QHNY (PIN) determinista + señuelo",
            "passphrase": "clave-honey", "salt_hex": hex(&salt), "pepper_hex": "",
            "mem_kib": params.mem_kib, "iterations": params.iterations, "parallelism": params.parallelism,
            "alphabet": 10, "tokens": honey_tokens, "blob_hex": hex(&honey_blob),
            "decoy_passphrase": "clave-equivocada", "decoy_tokens": decoy
        }
    ]);

    // ---- congelado: streaming (dirección descifrado) ----
    let stream_pt = b"datos en reposo a traves del modo streaming AEAD";
    let sopts = StreamOptions {
        pepper: b"",
        kdf_params: cheap(),
        chunk_size: 4096,
    };
    let stream_blob = encrypt_stream_bytes(stream_pt, "clave-stream", &sopts);
    assert_eq!(
        decrypt_stream_bytes(&stream_blob, "clave-stream", b"").unwrap(),
        stream_pt
    );
    let stream_vectors = json!([
        {
            "desc": "contenedor QST1 (streaming), dirección descifrado",
            "passphrase": "clave-stream", "pepper_hex": "",
            "blob_hex": hex(&stream_blob), "plaintext_hex": hex(stream_pt)
        }
    ]);

    // ---- congelado: post-cuántico (dirección descifrado) ----
    let (pk, sk) = pqhybrid::generate_keypair().expect("el sistema debe dar entropia");
    let pq_pt = b"secreto post-cuantico X25519+ML-KEM-1024";
    let pq_symbols = encode_to_recipient(pq_pt, &pk, &dict).expect("el sistema debe dar entropia");
    assert_eq!(decode_as_recipient(&pq_symbols, &sk, &dict).unwrap(), pq_pt);
    let pq_vectors = json!([
        {
            "desc": "contenedor post-cuántico (símbolos ASCII-94), dirección descifrado",
            "secret_key_hex": hex(&sk.to_bytes()), "symbols": pq_symbols, "plaintext_hex": hex(pq_pt)
        }
    ]);

    // ---- congelado: firma híbrida (dirección verificación) ----
    let (vk, ssk) = pqsign::generate_keypair();
    let sig_pt = b"acta firmada Ed25519+ML-DSA-87";
    let sig_symbols = encode_signed(sig_pt, &ssk, &dict);
    assert_eq!(decode_verified(&sig_symbols, &vk, &dict).unwrap(), sig_pt);
    let sig_vectors = json!([
        {
            "desc": "contenedor firmado (símbolos ASCII-94), dirección verificación",
            "verifying_key_hex": hex(&vk.to_bytes()), "symbols": sig_symbols, "message_hex": hex(sig_pt)
        }
    ]);

    let doc = json!({
        "format": "quipu-interop-vectors",
        "version": 1,
        "note": "Known-answer test vectors. Deterministic entries pin the format byte-for-byte; frozen entries pin the decode/verify direction. Argon2id cost is intentionally cheap for fast tests.",
        "deterministic": {
            "kdf_master": kdf_vectors,
            "kdf_subkey": subkey_vectors,
            "aead_xchacha20poly1305": aead_vectors,
            "padme": padme_vectors,
            "container_symmetric": sym_vectors,
            "honey": honey_vectors
        },
        "frozen": {
            "streaming_decode": stream_vectors,
            "recipient_decode": pq_vectors,
            "signed_verify": sig_vectors
        }
    });

    let dir = format!("{}/tests/vectors", env!("CARGO_MANIFEST_DIR"));
    std::fs::create_dir_all(&dir).expect("crear tests/vectors");
    let path = format!("{dir}/quipu_vectors.json");
    let s = serde_json::to_string_pretty(&doc).expect("serializar JSON");
    std::fs::write(&path, s + "\n").expect("escribir vectores");
    println!("Vectores escritos en {path}");
}
