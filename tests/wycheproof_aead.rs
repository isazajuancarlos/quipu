//! Vectores Wycheproof (Google) contra nuestro envoltorio AEAD
//! XChaCha20-Poly1305 (`quipu::cipher`). Verifica interoperabilidad y ausencia
//! de fallos conocidos (tags mal validados, nonces/ct manipulados, etc.).

use quipu::cipher::{decrypt, encrypt};
use wycheproof::aead::{TestName, TestSet};
use wycheproof::TestResult;

#[test]
fn xchacha20poly1305_wycheproof_vectors() {
    let set = TestSet::load(TestName::XChaCha20Poly1305).expect("cargar vectores Wycheproof");
    let mut checked = 0usize;

    for group in set.test_groups {
        for tc in group.tests {
            // Nuestro cipher es 32B clave / 24B nonce.
            if tc.key.len() != 32 || tc.nonce.len() != 24 {
                continue;
            }
            let key: [u8; 32] = tc.key[..].try_into().unwrap();
            let nonce: [u8; 24] = tc.nonce[..].try_into().unwrap();
            let mut combined = tc.ct.to_vec();
            combined.extend_from_slice(&tc.tag);

            let got = decrypt(&key, &nonce, &combined, &tc.aad);
            match tc.result {
                TestResult::Valid => {
                    assert_eq!(
                        got.as_deref(),
                        Ok(&tc.pt[..]),
                        "descifrado válido falló, tcId {}",
                        tc.tc_id
                    );
                    // Y el cifrado reproduce ct||tag exactamente.
                    assert_eq!(
                        encrypt(&key, &nonce, &tc.pt, &tc.aad),
                        combined,
                        "cifrado no reproduce el vector, tcId {}",
                        tc.tc_id
                    );
                }
                TestResult::Invalid => {
                    assert!(
                        got.is_err(),
                        "un vector inválido fue ACEPTADO, tcId {}",
                        tc.tc_id
                    );
                }
                // "Acceptable": comportamiento definido por la implementación.
                TestResult::Acceptable => {}
            }
            checked += 1;
        }
    }

    assert!(checked > 0, "no se ejecutó ningún vector");
    println!("Wycheproof XChaCha20-Poly1305: {checked} vectores verificados");
}
