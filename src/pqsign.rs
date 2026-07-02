//! Firma digital híbrida post-cuántica: Ed25519 (clásico) + ML-DSA-87 (FIPS-204).
//!
//! Combina DOS firmas independientes (una clásica, una post-cuántica) sobre el
//! mismo mensaje. La firma híbrida se considera válida SÓLO si AMBAS verifican
//! (combinador "AND"): así es infalsificable mientras sobreviva AL MENOS UNA de
//! las dos primitivas. Cubre dos riesgos: que un cuántico rompa Ed25519 en el
//! futuro, y que ML-DSA (esquema joven) resulte tener un fallo clásico.
//!
//! Da AUTENTICIDAD, INTEGRIDAD y NO-REPUDIO verificables por terceros. NO da
//! confidencialidad (eso es el modo de cifrado). Encaja en "datos en reposo":
//! documentos, respaldos o artefactos firmados.
//!
//! Filosofía Quipu: no inventamos la primitiva. Reutilizamos crates vetados
//! (`ed25519-dalek`, `ml-dsa`); lo propio es el FORMATO, el binding de dominio
//! y la composición híbrida.

use ed25519_dalek::{
    Signature as EdSignature, Signer as _, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey,
};
use ml_dsa::signature::{Keypair as _, Signer as _, Verifier as _};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa87, Seed, Signature as MlSignature,
    SigningKey as MlSigningKey, VerifyingKey as MlVerifyingKey,
};
use zeroize::Zeroizing;

/// Longitud de la clave pública Ed25519.
pub const ED25519_PUB_LEN: usize = 32;
/// Longitud de la firma Ed25519.
pub const ED25519_SIG_LEN: usize = 64;
/// Longitud de la semilla/clave secreta Ed25519.
pub const ED25519_SEED_LEN: usize = 32;
/// Longitud de la clave de verificación ML-DSA-87.
pub const MLDSA_VK_LEN: usize = 2592;
/// Longitud de la firma ML-DSA-87.
pub const MLDSA_SIG_LEN: usize = 4627;
/// Longitud de la semilla de la clave de firma ML-DSA-87 (reconstruye la clave).
pub const MLDSA_SEED_LEN: usize = 32;

/// Longitud de la clave de verificación híbrida serializada (Ed25519 || ML-DSA).
pub const VERIFYING_KEY_LEN: usize = ED25519_PUB_LEN + MLDSA_VK_LEN; // 2624
/// Longitud de la clave de firma híbrida serializada (Ed25519 seed || ML-DSA seed).
/// ¡Material sensible!
pub const SIGNING_KEY_LEN: usize = ED25519_SEED_LEN + MLDSA_SEED_LEN; // 64
/// Longitud de la firma híbrida (Ed25519 || ML-DSA).
pub const SIGNATURE_LEN: usize = ED25519_SIG_LEN + MLDSA_SIG_LEN; // 4691

/// Etiqueta de dominio: ata la firma a Quipu y a esta versión del esquema.
const SIGN_CONTEXT: &[u8] = b"quipu/v3/sign";

/// Clave de verificación híbrida (pública). Publicable/fijable en el verificador.
pub struct VerifyingKey {
    ed: EdVerifyingKey,
    ml: MlVerifyingKey<MlDsa87>,
}

/// Clave de firma híbrida (secreta). Guarda semillas de 32 bytes por lado; el
/// material se borra al soltarse (`Zeroizing`).
pub struct SigningKey {
    ed_seed: Zeroizing<[u8; ED25519_SEED_LEN]>,
    ml_seed: Zeroizing<[u8; MLDSA_SEED_LEN]>,
}

/// Genera un par de claves de firma híbrido.
pub fn generate_keypair() -> (VerifyingKey, SigningKey) {
    let mut ed_seed = [0u8; ED25519_SEED_LEN];
    let mut ml_seed = [0u8; MLDSA_SEED_LEN];
    getrandom::getrandom(&mut ed_seed).expect("RNG del sistema");
    getrandom::getrandom(&mut ml_seed).expect("RNG del sistema");
    let sk = SigningKey {
        ed_seed: Zeroizing::new(ed_seed),
        ml_seed: Zeroizing::new(ml_seed),
    };
    let vk = sk.verifying_key();
    (vk, sk)
}

/// Reconstruye la clave de firma ML-DSA desde su semilla.
fn ml_signing_key(seed: &[u8; MLDSA_SEED_LEN]) -> MlSigningKey<MlDsa87> {
    let s = Seed::try_from(&seed[..]).expect("semilla ML-DSA de 32 bytes");
    MlSigningKey::<MlDsa87>::from_seed(&s)
}

impl SigningKey {
    /// Deriva la clave de verificación (pública) correspondiente.
    pub fn verifying_key(&self) -> VerifyingKey {
        let ed = EdSigningKey::from_bytes(&self.ed_seed).verifying_key();
        let ml = ml_signing_key(&self.ml_seed).verifying_key();
        VerifyingKey { ed, ml }
    }

    /// Firma `message` de forma híbrida. La firma ata la clave pública COMPLETA
    /// del firmante y una etiqueta de dominio, impidiendo sustitución de clave y
    /// mezcla de componentes entre pares de claves distintos.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let vk = self.verifying_key();
        let preimage = build_preimage(&vk.to_bytes(), message);

        let ed_sig = EdSigningKey::from_bytes(&self.ed_seed).sign(&preimage);
        let ml_sig = ml_signing_key(&self.ml_seed).sign(&preimage);

        let mut out = Vec::with_capacity(SIGNATURE_LEN);
        out.extend_from_slice(&ed_sig.to_bytes());
        out.extend_from_slice(ml_sig.encode().as_slice());
        out
    }

    /// Serializa la clave de firma (Ed25519 seed || ML-DSA seed). ¡Sensible!
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Vec::with_capacity(SIGNING_KEY_LEN);
        v.extend_from_slice(self.ed_seed.as_ref());
        v.extend_from_slice(self.ml_seed.as_ref());
        Zeroizing::new(v)
    }

    /// Reconstruye la clave de firma desde bytes.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != SIGNING_KEY_LEN {
            return None;
        }
        let ed_seed: [u8; ED25519_SEED_LEN] = b[0..ED25519_SEED_LEN].try_into().ok()?;
        let ml_seed: [u8; MLDSA_SEED_LEN] = b[ED25519_SEED_LEN..].try_into().ok()?;
        Some(SigningKey {
            ed_seed: Zeroizing::new(ed_seed),
            ml_seed: Zeroizing::new(ml_seed),
        })
    }
}

impl VerifyingKey {
    /// Verifica una firma híbrida sobre `message`. Devuelve `true` sólo si AMBAS
    /// firmas (Ed25519 y ML-DSA) validan contra el mensaje ligado al dominio.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        if signature.len() != SIGNATURE_LEN {
            return false;
        }
        let preimage = build_preimage(&self.to_bytes(), message);

        // Parte clásica.
        let ed_sig_bytes: [u8; ED25519_SIG_LEN] = match signature[0..ED25519_SIG_LEN].try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let ed_sig = EdSignature::from_bytes(&ed_sig_bytes);
        // `verify_strict` rechaza claves de orden pequeño y maleabilidad.
        let ed_ok = self.ed.verify_strict(&preimage, &ed_sig).is_ok();

        // Parte post-cuántica.
        let ml_sig_bytes = &signature[ED25519_SIG_LEN..];
        let ml_ok = match EncodedSignature::<MlDsa87>::try_from(ml_sig_bytes) {
            Ok(enc) => match MlSignature::<MlDsa87>::decode(&enc) {
                Some(sig) => self.ml.verify(&preimage, &sig).is_ok(),
                None => false,
            },
            Err(_) => false,
        };

        // Combinador AND: ambas deben validar.
        ed_ok && ml_ok
    }

    /// Serializa la clave de verificación (Ed25519 pub || ML-DSA vk).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(VERIFYING_KEY_LEN);
        v.extend_from_slice(self.ed.as_bytes());
        v.extend_from_slice(self.ml.encode().as_slice());
        v
    }

    /// Reconstruye la clave de verificación desde bytes.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != VERIFYING_KEY_LEN {
            return None;
        }
        let ed_bytes: [u8; ED25519_PUB_LEN] = b[0..ED25519_PUB_LEN].try_into().ok()?;
        let ed = EdVerifyingKey::from_bytes(&ed_bytes).ok()?;
        let ml_enc = EncodedVerifyingKey::<MlDsa87>::try_from(&b[ED25519_PUB_LEN..]).ok()?;
        let ml = MlVerifyingKey::<MlDsa87>::decode(&ml_enc);
        Some(VerifyingKey { ed, ml })
    }
}

/// Preimagen firmada: etiqueta de dominio || clave pública completa || mensaje.
fn build_preimage(vk_bytes: &[u8], message: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(SIGN_CONTEXT.len() + vk_bytes.len() + message.len());
    p.extend_from_slice(SIGN_CONTEXT);
    p.extend_from_slice(vk_bytes);
    p.extend_from_slice(message);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameters_are_cnsa_level5() {
        // CNSA 2.0 (NSA) exige ML-DSA-87 = categoría de seguridad NIST 5.
        // Fija los tamaños FIPS-204 del nivel 5 para detectar regresiones.
        assert_eq!(MLDSA_VK_LEN, 2592, "vk ML-DSA-87");
        assert_eq!(MLDSA_SIG_LEN, 4627, "firma ML-DSA-87");
    }

    #[test]
    fn sign_verify_round_trips() {
        let (vk, sk) = generate_keypair();
        let msg = b"documento firmado";
        let sig = sk.sign(msg);
        assert_eq!(sig.len(), SIGNATURE_LEN);
        assert!(vk.verify(msg, &sig));
    }

    #[test]
    fn tampered_message_fails() {
        let (vk, sk) = generate_keypair();
        let sig = sk.sign(b"pagar 100");
        assert!(!vk.verify(b"pagar 900", &sig));
    }

    #[test]
    fn tampered_signature_fails() {
        let (vk, sk) = generate_keypair();
        let msg = b"mensaje";
        let mut sig = sk.sign(msg);
        // Voltea un bit de la mitad clásica.
        sig[0] ^= 0x01;
        assert!(!vk.verify(msg, &sig));
        // Voltea un bit de la mitad post-cuántica.
        let mut sig2 = sk.sign(msg);
        sig2[ED25519_SIG_LEN + 10] ^= 0x01;
        assert!(!vk.verify(msg, &sig2));
    }

    #[test]
    fn wrong_key_fails() {
        let (_vk, sk) = generate_keypair();
        let (vk2, _sk2) = generate_keypair();
        let msg = b"mensaje";
        let sig = sk.sign(msg);
        // Firmada por sk, verificada con otra clave pública -> rechazo.
        assert!(!vk2.verify(msg, &sig));
    }

    #[test]
    fn and_combiner_rejects_swapped_component() {
        // Sustituir la mitad ML-DSA por la de OTRA firma (mismo mensaje, otra
        // clave) debe fallar: el AND exige que AMBAS validen bajo la MISMA vk.
        let (vk, sk) = generate_keypair();
        let (_vk2, sk2) = generate_keypair();
        let msg = b"mensaje";
        let sig = sk.sign(msg);
        let other = sk2.sign(msg);
        let mut frankensig = Vec::with_capacity(SIGNATURE_LEN);
        frankensig.extend_from_slice(&sig[0..ED25519_SIG_LEN]); // Ed25519 de sk
        frankensig.extend_from_slice(&other[ED25519_SIG_LEN..]); // ML-DSA de sk2
        assert!(!vk.verify(msg, &frankensig));
    }

    #[test]
    fn signing_key_serialization_round_trips() {
        let (vk, sk) = generate_keypair();
        let bytes = sk.to_bytes();
        assert_eq!(bytes.len(), SIGNING_KEY_LEN);
        let sk2 = SigningKey::from_bytes(&bytes).unwrap();
        let msg = b"mensaje";
        assert!(vk.verify(msg, &sk2.sign(msg)));
    }

    #[test]
    fn verifying_key_serialization_round_trips() {
        let (vk, sk) = generate_keypair();
        let bytes = vk.to_bytes();
        assert_eq!(bytes.len(), VERIFYING_KEY_LEN);
        let vk2 = VerifyingKey::from_bytes(&bytes).unwrap();
        let msg = b"mensaje";
        assert!(vk2.verify(msg, &sk.sign(msg)));
    }

    #[test]
    fn signatures_are_deterministic_but_bind_message() {
        // Ed25519 y el modo por defecto de ML-DSA son deterministas: misma clave
        // + mismo mensaje -> misma firma. Distinto mensaje -> firma distinta.
        let (_vk, sk) = generate_keypair();
        assert_eq!(sk.sign(b"a"), sk.sign(b"a"));
        assert_ne!(sk.sign(b"a"), sk.sign(b"b"));
    }

    #[test]
    fn wrong_length_signature_rejected() {
        let (vk, sk) = generate_keypair();
        let mut sig = sk.sign(b"m");
        sig.truncate(SIGNATURE_LEN - 1);
        assert!(!vk.verify(b"m", &sig));
    }
}
