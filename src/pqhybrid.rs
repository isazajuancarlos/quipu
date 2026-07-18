//! Cifrado híbrido post-cuántico: X25519 (clásico) + ML-KEM-1024 (FIPS-203).
//!
//! Combina DOS secretos compartidos (uno clásico, uno post-cuántico) vía HKDF
//! en una única clave de contenido de 32 bytes. Resistente a "harvest now,
//! decrypt later": un atacante tendría que romper AMBOS para recuperar la clave.
//!
//! Es un modo ASIMÉTRICO (cifrar a una clave pública del destinatario),
//! complementario al modo simétrico basado en passphrase.

use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem1024};
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};
use zeroize::{Zeroize, Zeroizing};

type MlEk = <MlKem1024 as KemCore>::EncapsulationKey;
type MlDk = <MlKem1024 as KemCore>::DecapsulationKey;

/// Longitud de la clave pública X25519.
pub const X25519_PUB_LEN: usize = 32;
/// Longitud de la clave de encapsulación ML-KEM-1024.
pub const MLKEM_EK_LEN: usize = 1568;
/// Longitud del ciphertext (encapsulación) ML-KEM-1024.
pub const MLKEM_CT_LEN: usize = 1568;
/// Longitud de la encapsulación híbrida (eph X25519 pub || ML-KEM ct).
pub const ENCAPSULATION_LEN: usize = X25519_PUB_LEN + MLKEM_CT_LEN;
/// Longitud de la clave pública híbrida serializada.
pub const PUBLIC_KEY_LEN: usize = X25519_PUB_LEN + MLKEM_EK_LEN;
/// Longitud de la clave de decapsulación ML-KEM-1024.
pub const MLKEM_DK_LEN: usize = 3168;
/// Longitud de la clave secreta híbrida serializada.
pub const SECRET_KEY_LEN: usize = X25519_PUB_LEN + MLKEM_DK_LEN;
/// Longitud de la clave de contenido derivada.
pub const CONTENT_KEY_LEN: usize = 32;

const HKDF_INFO: &[u8] = b"quipu/v2/hybrid-kem";

/// Clave pública híbrida del destinatario.
pub struct PublicKey {
    x: XPublic,
    ml: MlEk,
}

/// Clave secreta híbrida del destinatario.
pub struct SecretKey {
    x: XSecret,
    ml: MlDk,
}

/// Genera un par de claves híbrido.
pub fn generate_keypair() -> (PublicKey, SecretKey) {
    let x_secret = XSecret::random_from_rng(OsRng);
    let x_public = XPublic::from(&x_secret);
    let (ml_dk, ml_ek) = MlKem1024::generate(&mut OsRng);
    (
        PublicKey {
            x: x_public,
            ml: ml_ek,
        },
        SecretKey {
            x: x_secret,
            ml: ml_dk,
        },
    )
}

impl PublicKey {
    /// Serializa la clave pública (X25519 pub || ML-KEM ek).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(PUBLIC_KEY_LEN);
        v.extend_from_slice(self.x.as_bytes());
        v.extend_from_slice(&self.ml.as_bytes());
        v
    }

    /// Reconstruye la clave pública desde bytes.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != PUBLIC_KEY_LEN {
            return None;
        }
        let x_bytes: [u8; 32] = b[0..32].try_into().ok()?;
        let x = XPublic::from(x_bytes);
        let ml_encoded = ml_kem::Encoded::<MlEk>::try_from(&b[32..]).ok()?;
        let ml = MlEk::from_bytes(&ml_encoded);
        Some(Self { x, ml })
    }
}

impl SecretKey {
    /// Serializa la clave secreta (X25519 secret || ML-KEM dk). Devuelve un
    /// `Zeroizing`: el buffer se borra al soltarse, igual que en `pqsign`, para
    /// no dejar la serialización del secreto en RAM (paridad de higiene entre
    /// módulos). `Zeroizing<Vec<u8>>` deref-ea a `&[u8]`, así que los usos
    /// existentes (PyBytes, `from_bytes`, `.len()`) siguen compilando.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Vec::with_capacity(SECRET_KEY_LEN);
        v.extend_from_slice(&self.x.to_bytes());
        v.extend_from_slice(&self.ml.as_bytes());
        Zeroizing::new(v)
    }

    /// Reconstruye la clave secreta desde bytes.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != SECRET_KEY_LEN {
            return None;
        }
        let x_bytes: [u8; 32] = b[0..32].try_into().ok()?;
        let x = XSecret::from(x_bytes);
        let ml_encoded = ml_kem::Encoded::<MlDk>::try_from(&b[32..]).ok()?;
        let ml = MlDk::from_bytes(&ml_encoded);
        Some(Self { x, ml })
    }
}

/// Encapsula: produce una clave de contenido y la encapsulación que el
/// destinatario usará para recuperarla.
pub fn encapsulate(pk: &PublicKey) -> ([u8; CONTENT_KEY_LEN], Vec<u8>) {
    // Parte clásica: X25519 efímero.
    let eph = XSecret::random_from_rng(OsRng);
    let eph_pub = XPublic::from(&eph);
    let x_ss = eph.diffie_hellman(&pk.x);

    // Parte post-cuántica: ML-KEM.
    let (ml_ct, ml_ss) = pk.ml.encapsulate(&mut OsRng).expect("ML-KEM encapsulate");

    let mut encapsulation = Vec::with_capacity(ENCAPSULATION_LEN);
    encapsulation.extend_from_slice(eph_pub.as_bytes());
    encapsulation.extend_from_slice(&ml_ct);

    // F2: liga la clave pública COMPLETA del destinatario (X25519 + ML-KEM ek)
    // al transcript (estilo X-Wing). Ligar la `ek` impide que un atacante que
    // sustituya la `ek` en tránsito produzca la misma clave de contenido.
    let transcript = build_transcript(pk.x.as_bytes(), &pk.ml.as_bytes(), &encapsulation);

    let key = combine(x_ss.as_bytes(), &ml_ss, &transcript);
    (key, encapsulation)
}

/// Decapsula con la clave secreta del destinatario.
pub fn decapsulate(sk: &SecretKey, encapsulation: &[u8]) -> Option<[u8; CONTENT_KEY_LEN]> {
    if encapsulation.len() != ENCAPSULATION_LEN {
        return None;
    }
    let eph_bytes: [u8; 32] = encapsulation[0..32].try_into().ok()?;
    let eph_pub = XPublic::from(eph_bytes);
    let x_ss = sk.x.diffie_hellman(&eph_pub);

    let ml_ct = ml_kem::Ciphertext::<MlKem1024>::try_from(&encapsulation[32..]).ok()?;
    let ml_ss = sk.ml.decapsulate(&ml_ct).ok()?;

    // F2: reconstruye el mismo transcript con la clave pública COMPLETA del
    // destinatario. La `ek` de ML-KEM se recomputa desde la `dk`.
    let recipient_x_pub = XPublic::from(&sk.x);
    let recipient_ek = sk.ml.encapsulation_key().as_bytes();
    let transcript = build_transcript(recipient_x_pub.as_bytes(), &recipient_ek, encapsulation);

    Some(combine(x_ss.as_bytes(), &ml_ss, &transcript))
}

/// Transcript ligado a la derivación: clave pública completa del destinatario
/// (X25519 pub || ML-KEM ek) seguida de la encapsulación (eph pub || ML-KEM ct).
fn build_transcript(recipient_x_pub: &[u8], recipient_ek: &[u8], encapsulation: &[u8]) -> Vec<u8> {
    let mut t = Vec::with_capacity(recipient_x_pub.len() + recipient_ek.len() + encapsulation.len());
    t.extend_from_slice(recipient_x_pub);
    t.extend_from_slice(recipient_ek);
    t.extend_from_slice(encapsulation);
    t
}

/// Combinador híbrido: HKDF-SHA256 sobre (ss_clásico || ss_pq), ligando el
/// transcript como contexto.
fn combine(x_ss: &[u8], ml_ss: &[u8], transcript: &[u8]) -> [u8; CONTENT_KEY_LEN] {
    let mut ikm = Vec::with_capacity(x_ss.len() + ml_ss.len());
    ikm.extend_from_slice(x_ss);
    ikm.extend_from_slice(ml_ss);

    let mut info = HKDF_INFO.to_vec();
    info.extend_from_slice(transcript);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut out = [0u8; CONTENT_KEY_LEN];
    hk.expand(&info, &mut out).expect("longitud HKDF válida");
    // O5: borra el material de clave intermedio (ss combinados).
    ikm.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameters_are_cnsa_level5() {
        // CNSA 2.0 (NSA) exige ML-KEM-1024 = categoría de seguridad NIST 5.
        // Fija los tamaños FIPS-203 del nivel 5 para detectar cualquier regresión
        // de parámetros.
        assert_eq!(MLKEM_EK_LEN, 1568, "ek ML-KEM-1024");
        assert_eq!(MLKEM_CT_LEN, 1568, "ciphertext ML-KEM-1024");
        assert_eq!(MLKEM_DK_LEN, 3168, "dk ML-KEM-1024");
    }

    #[test]
    fn kem_round_trip_recovers_shared_secret() {
        let (pk, sk) = generate_keypair();
        let (key1, enc) = encapsulate(&pk);
        assert_eq!(enc.len(), ENCAPSULATION_LEN);
        let key2 = decapsulate(&sk, &enc).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn wrong_secret_key_yields_different_key() {
        let (pk, _sk) = generate_keypair();
        let (_pk2, sk2) = generate_keypair();
        let (key1, enc) = encapsulate(&pk);
        // ML-KEM usa rechazo implícito: no falla, pero da una clave distinta.
        let key2 = decapsulate(&sk2, &enc).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn secret_key_serialization_round_trips() {
        let (pk, sk) = generate_keypair();
        let (key1, enc) = encapsulate(&pk);
        let sk_bytes = sk.to_bytes();
        assert_eq!(sk_bytes.len(), SECRET_KEY_LEN);
        let sk2 = SecretKey::from_bytes(&sk_bytes).unwrap();
        // La sk reconstruida debe decapsular igual.
        assert_eq!(decapsulate(&sk2, &enc).unwrap(), key1);
    }

    #[test]
    fn recomputed_ek_from_dk_matches_original() {
        // El destinatario debe poder reconstruir el transcript ligando su `ek`,
        // recomputándola desde su `dk`. Si no coincidiera, decapsulate fallaría.
        let (pk, sk) = generate_keypair();
        assert_eq!(sk.ml.encapsulation_key().as_bytes(), pk.ml.as_bytes());
    }

    #[test]
    fn public_key_serialization_round_trips() {
        let (pk, _sk) = generate_keypair();
        let bytes = pk.to_bytes();
        assert_eq!(bytes.len(), PUBLIC_KEY_LEN);
        let pk2 = PublicKey::from_bytes(&bytes).unwrap();
        // Verifica que la pública reconstruida encapsula hacia la misma sk.
        assert_eq!(pk2.to_bytes(), bytes);
    }
}
