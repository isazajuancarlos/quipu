// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

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
//!
//! # Modo triple-híbrido (feature `slh`, opt-in)
//!
//! Con la feature no-default `slh` se añade **SLH-DSA-SHA2-256s** (FIPS-205,
//! hash-based *stateless*, vía el crate `fips205`), combinando
//! Ed25519 + ML-DSA-87 + SLH-DSA con **AND 3-de-3**: infalsificable mientras
//! sobreviva al menos una de tres familias (curva, retículo, hash). La firma pesa
//! ~34 KB y firmar es lento: es un modo de **alta garantía** para artefactos de
//! altísimo valor, no el por defecto. Contenedor `QSG3` vía
//! `api::encode_signed_triple` / `api::decode_verified_triple`.

use ed25519_dalek::{
    Signature as EdSignature, Signer as _, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey,
};
use ml_dsa::signature::{Keypair as _, Verifier as _};
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
///
/// Dispara la autoprueba de arranque una vez por proceso: ninguna clave debe
/// nacer de un módulo roto. Se engancha aquí, y no en el camino caliente,
/// porque generar claves ya es caro y raro — 12 ms una sola vez no se notan.
pub fn generate_keypair() -> (VerifyingKey, SigningKey) {
    crate::selftest::ensure();
    generate_keypair_unchecked()
}

/// Igual que [`generate_keypair`] pero **sin** disparar la autoprueba.
///
/// Existe solo para que `selftest` pueda generar claves DENTRO de la propia
/// autoprueba: `Once::call_once` no es reentrante, así que llamar a la versión
/// pública desde ahí bloquearía la hebra para siempre esperando una
/// inicialización que ella misma está haciendo.
pub(crate) fn generate_keypair_unchecked() -> (VerifyingKey, SigningKey) {
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

// ---------------------------------------------------------------------------
// Fase 1: firma triple-híbrida (Ed25519 + ML-DSA-87 + SLH-DSA-SHA2-256s).
// Opt-in tras la feature `slh`. Aditivo: el modo doble de arriba no cambia.
// ---------------------------------------------------------------------------
// SLH-DSA-SHA2-256s vía el crate `fips205` (implementación FIPS-205 pura,
// sin dependencia de la crate `signature` → sin choque con ed25519/ml-dsa).
#[cfg(feature = "slh")]
use fips205::slh_dsa_sha2_256s;
#[cfg(feature = "slh")]
use fips205::traits::{SerDes as _, Signer as _, Verifier as _};

/// Longitud de la clave pública SLH-DSA-SHA2-256s.
#[cfg(feature = "slh")]
pub const SLH_PUB_LEN: usize = slh_dsa_sha2_256s::PK_LEN; // 64
/// Longitud de la clave secreta SLH-DSA-SHA2-256s (serializada).
#[cfg(feature = "slh")]
pub const SLH_SECRET_LEN: usize = slh_dsa_sha2_256s::SK_LEN; // 128
/// Longitud de la firma SLH-DSA-SHA2-256s.
#[cfg(feature = "slh")]
pub const SLH_SIG_LEN: usize = slh_dsa_sha2_256s::SIG_LEN; // 29792

/// Contexto FIPS-205 (vacío): todo el binding de dominio va en la preimagen.
#[cfg(feature = "slh")]
const SLH_CTX: &[u8] = b"";

/// Clave de verificación triple serializada (Ed25519 || ML-DSA || SLH-DSA).
#[cfg(feature = "slh")]
pub const TRIPLE_VERIFYING_KEY_LEN: usize = ED25519_PUB_LEN + MLDSA_VK_LEN + SLH_PUB_LEN; // 2688
/// Clave de firma triple serializada (Ed25519 seed || ML-DSA seed || SLH sk). ¡Sensible!
#[cfg(feature = "slh")]
pub const TRIPLE_SIGNING_KEY_LEN: usize = ED25519_SEED_LEN + MLDSA_SEED_LEN + SLH_SECRET_LEN; // 192
/// Firma triple (Ed25519 || ML-DSA || SLH-DSA).
#[cfg(feature = "slh")]
pub const TRIPLE_SIGNATURE_LEN: usize = ED25519_SIG_LEN + MLDSA_SIG_LEN + SLH_SIG_LEN; // 34483

/// Etiqueta de dominio del modo triple. Distinta de `quipu/v3/sign`.
#[cfg(feature = "slh")]
const SIGN_TRIPLE_CONTEXT: &[u8] = b"quipu/v4/sign-triple";

/// Clave de verificación triple-híbrida (pública).
#[cfg(feature = "slh")]
pub struct TripleVerifyingKey {
    ed: EdVerifyingKey,
    ml: MlVerifyingKey<MlDsa87>,
    slh: slh_dsa_sha2_256s::PublicKey,
}

/// Clave de firma triple-híbrida (secreta). Ed25519/ML-DSA como semillas de 32 B;
/// SLH-DSA como sus bytes de clave secreta (la API no expone keygen desde semilla
/// de 32 B). Todo el material se borra al soltarse.
#[cfg(feature = "slh")]
pub struct TripleSigningKey {
    ed_seed: Zeroizing<[u8; ED25519_SEED_LEN]>,
    ml_seed: Zeroizing<[u8; MLDSA_SEED_LEN]>,
    slh_sk: Zeroizing<[u8; SLH_SECRET_LEN]>,
}

/// Genera un par de claves triple-híbrido.
#[cfg(feature = "slh")]
pub fn generate_triple_keypair() -> (TripleVerifyingKey, TripleSigningKey) {
    let mut ed_seed = [0u8; ED25519_SEED_LEN];
    let mut ml_seed = [0u8; MLDSA_SEED_LEN];
    getrandom::getrandom(&mut ed_seed).expect("RNG del sistema");
    getrandom::getrandom(&mut ml_seed).expect("RNG del sistema");

    let (_slh_pk, slh_priv) = slh_dsa_sha2_256s::try_keygen().expect("keygen SLH-DSA");
    let slh_sk = slh_priv.into_bytes();

    let sk = TripleSigningKey {
        ed_seed: Zeroizing::new(ed_seed),
        ml_seed: Zeroizing::new(ml_seed),
        slh_sk: Zeroizing::new(slh_sk),
    };
    let vk = sk.verifying_key();
    (vk, sk)
}

/// Reconstruye la clave secreta SLH-DSA desde sus bytes serializados.
#[cfg(feature = "slh")]
fn slh_signing_key(sk_bytes: &[u8; SLH_SECRET_LEN]) -> slh_dsa_sha2_256s::PrivateKey {
    slh_dsa_sha2_256s::PrivateKey::try_from_bytes(sk_bytes).expect("clave secreta SLH de 128 bytes")
}

#[cfg(feature = "slh")]
impl TripleSigningKey {
    /// Deriva la clave de verificación (pública) correspondiente.
    pub fn verifying_key(&self) -> TripleVerifyingKey {
        let ed = EdSigningKey::from_bytes(&self.ed_seed).verifying_key();
        let ml = ml_signing_key(&self.ml_seed).verifying_key();
        let slh = slh_signing_key(&self.slh_sk).get_public_key();
        TripleVerifyingKey { ed, ml, slh }
    }

    /// Firma `message` con las tres primitivas sobre la misma preimagen.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let vk = self.verifying_key();
        let preimage = build_triple_preimage(&vk.to_bytes(), message);

        let ed_sig = EdSigningKey::from_bytes(&self.ed_seed).sign(&preimage);
        let ml_sig = ml_signing_key(&self.ml_seed).sign(&preimage);
        let slh_sig = slh_signing_key(&self.slh_sk)
            .try_sign(&preimage, SLH_CTX, false)
            .expect("firma SLH-DSA determinista");

        let mut out = Vec::with_capacity(TRIPLE_SIGNATURE_LEN);
        out.extend_from_slice(&ed_sig.to_bytes());
        out.extend_from_slice(ml_sig.encode().as_slice());
        out.extend_from_slice(&slh_sig);
        out
    }

    /// Serializa la clave de firma (ed seed || ml seed || slh sk). ¡Sensible!
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Vec::with_capacity(TRIPLE_SIGNING_KEY_LEN);
        v.extend_from_slice(self.ed_seed.as_ref());
        v.extend_from_slice(self.ml_seed.as_ref());
        v.extend_from_slice(self.slh_sk.as_ref());
        Zeroizing::new(v)
    }

    /// Reconstruye la clave de firma desde bytes.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != TRIPLE_SIGNING_KEY_LEN {
            return None;
        }
        let ed_seed: [u8; ED25519_SEED_LEN] = b[0..ED25519_SEED_LEN].try_into().ok()?;
        let ml_start = ED25519_SEED_LEN;
        let ml_seed: [u8; MLDSA_SEED_LEN] =
            b[ml_start..ml_start + MLDSA_SEED_LEN].try_into().ok()?;
        let slh_start = ml_start + MLDSA_SEED_LEN;
        let slh_sk: [u8; SLH_SECRET_LEN] = b[slh_start..].try_into().ok()?;
        Some(TripleSigningKey {
            ed_seed: Zeroizing::new(ed_seed),
            ml_seed: Zeroizing::new(ml_seed),
            slh_sk: Zeroizing::new(slh_sk),
        })
    }
}

#[cfg(feature = "slh")]
impl TripleVerifyingKey {
    /// Verifica una firma triple. `true` sólo si las TRES validan (AND 3-de-3).
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        if signature.len() != TRIPLE_SIGNATURE_LEN {
            return false;
        }
        let preimage = build_triple_preimage(&self.to_bytes(), message);

        let (ed_sig_bytes, rest) = signature.split_at(ED25519_SIG_LEN);
        let (ml_sig_bytes, slh_sig_bytes) = rest.split_at(MLDSA_SIG_LEN);

        // Ed25519 (verify_strict rechaza orden pequeño y maleabilidad).
        let ed_arr: [u8; ED25519_SIG_LEN] = match ed_sig_bytes.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let ed_ok = self
            .ed
            .verify_strict(&preimage, &EdSignature::from_bytes(&ed_arr))
            .is_ok();

        // ML-DSA-87.
        let ml_ok = match EncodedSignature::<MlDsa87>::try_from(ml_sig_bytes) {
            Ok(enc) => match MlSignature::<MlDsa87>::decode(&enc) {
                Some(sig) => self.ml.verify(&preimage, &sig).is_ok(),
                None => false,
            },
            Err(_) => false,
        };

        // SLH-DSA-256s.
        let slh_arr: &[u8; SLH_SIG_LEN] = match slh_sig_bytes.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let slh_ok = self.slh.verify(&preimage, slh_arr, SLH_CTX);

        ed_ok && ml_ok && slh_ok
    }

    /// Serializa la clave de verificación (Ed25519 pub || ML-DSA vk || SLH vk).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(TRIPLE_VERIFYING_KEY_LEN);
        v.extend_from_slice(self.ed.as_bytes());
        v.extend_from_slice(self.ml.encode().as_slice());
        v.extend_from_slice(&self.slh.clone().into_bytes());
        v
    }

    /// Reconstruye la clave de verificación desde bytes.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != TRIPLE_VERIFYING_KEY_LEN {
            return None;
        }
        let ed_bytes: [u8; ED25519_PUB_LEN] = b[0..ED25519_PUB_LEN].try_into().ok()?;
        let ed = EdVerifyingKey::from_bytes(&ed_bytes).ok()?;
        let ml_start = ED25519_PUB_LEN;
        let ml_enc =
            EncodedVerifyingKey::<MlDsa87>::try_from(&b[ml_start..ml_start + MLDSA_VK_LEN]).ok()?;
        let ml = MlVerifyingKey::<MlDsa87>::decode(&ml_enc);
        let slh_start = ml_start + MLDSA_VK_LEN;
        let slh_bytes: [u8; SLH_PUB_LEN] = b[slh_start..].try_into().ok()?;
        let slh = slh_dsa_sha2_256s::PublicKey::try_from_bytes(&slh_bytes).ok()?;
        Some(TripleVerifyingKey { ed, ml, slh })
    }
}

/// Preimagen triple: etiqueta de dominio || clave pública triple completa || mensaje.
#[cfg(feature = "slh")]
fn build_triple_preimage(vk_bytes: &[u8], message: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(SIGN_TRIPLE_CONTEXT.len() + vk_bytes.len() + message.len());
    p.extend_from_slice(SIGN_TRIPLE_CONTEXT);
    p.extend_from_slice(vk_bytes);
    p.extend_from_slice(message);
    p
}

#[cfg(all(test, feature = "slh"))]
mod triple_spike {
    use super::*;

    #[test]
    fn slh_dsa_256s_sizes_and_roundtrip() {
        // Bloquea la API y los tamaños del param set antes de componer.
        assert_eq!(SLH_PUB_LEN, 64, "SLH pk len");
        assert_eq!(SLH_SECRET_LEN, 128, "SLH sk len");
        assert_eq!(SLH_SIG_LEN, 29_792, "SLH sig len");

        let (pk, sk) = slh_dsa_sha2_256s::try_keygen().unwrap();
        // Firma determinista (hedged=false) para reflejar Ed25519/ML-DSA.
        let sig = sk.try_sign(b"spike", SLH_CTX, false).unwrap();

        // Round-trip de serialización de clave pública y verificación.
        let pk_bytes = pk.into_bytes();
        assert_eq!(pk_bytes.len(), SLH_PUB_LEN);
        let pk2 = slh_dsa_sha2_256s::PublicKey::try_from_bytes(&pk_bytes).unwrap();
        assert!(pk2.verify(b"spike", &sig, SLH_CTX));
        assert!(!pk2.verify(b"otro", &sig, SLH_CTX));

        let sk_bytes = sk.into_bytes();
        assert_eq!(sk_bytes.len(), SLH_SECRET_LEN);
    }
}

#[cfg(all(test, feature = "slh"))]
mod triple_tests {
    use super::*;

    #[test]
    fn triple_sign_verify_round_trips() {
        let (vk, sk) = generate_triple_keypair();
        let msg = b"documento de altisimo valor";
        let sig = sk.sign(msg);
        assert_eq!(sig.len(), TRIPLE_SIGNATURE_LEN);
        assert!(vk.verify(msg, &sig));
    }

    #[test]
    fn triple_parameters_are_level5() {
        assert_eq!(SLH_SIG_LEN, 29_792);
        assert_eq!(TRIPLE_VERIFYING_KEY_LEN, 2_688);
        assert_eq!(TRIPLE_SIGNING_KEY_LEN, 192);
        assert_eq!(TRIPLE_SIGNATURE_LEN, 34_483);
    }

    #[test]
    fn triple_tampered_message_fails() {
        let (vk, sk) = generate_triple_keypair();
        let sig = sk.sign(b"pagar 100");
        assert!(!vk.verify(b"pagar 900", &sig));
    }

    #[test]
    fn triple_tampered_signature_fails() {
        let (vk, sk) = generate_triple_keypair();
        let msg = b"mensaje";
        // Voltear un bit en CADA uno de los tres componentes por separado.
        for pos in [0, ED25519_SIG_LEN + 10, ED25519_SIG_LEN + MLDSA_SIG_LEN + 10] {
            let mut sig = sk.sign(msg);
            sig[pos] ^= 0x01;
            assert!(!vk.verify(msg, &sig), "flip en offset {pos} debio fallar");
        }
    }

    #[test]
    fn triple_wrong_key_fails() {
        let (_vk, sk) = generate_triple_keypair();
        let (vk2, _sk2) = generate_triple_keypair();
        let sig = sk.sign(b"mensaje");
        assert!(!vk2.verify(b"mensaje", &sig));
    }

    #[test]
    fn triple_and_combiner_rejects_swapped_component() {
        // Sustituir CADA componente por el de otra firma (misma msg, otra clave)
        // debe fallar: el AND 3-de-3 exige que los tres validen bajo la MISMA vk.
        let (vk, sk) = generate_triple_keypair();
        let (_vk2, sk2) = generate_triple_keypair();
        let msg = b"mensaje";
        let sig = sk.sign(msg);
        let other = sk2.sign(msg);

        let ed_end = ED25519_SIG_LEN;
        let ml_end = ED25519_SIG_LEN + MLDSA_SIG_LEN;

        // (a) Ed25519 de sk2, resto de sk.
        let mut a = other[..ed_end].to_vec();
        a.extend_from_slice(&sig[ed_end..]);
        assert!(!vk.verify(msg, &a), "swap Ed25519");

        // (b) ML-DSA de sk2, resto de sk.
        let mut b = sig[..ed_end].to_vec();
        b.extend_from_slice(&other[ed_end..ml_end]);
        b.extend_from_slice(&sig[ml_end..]);
        assert!(!vk.verify(msg, &b), "swap ML-DSA");

        // (c) SLH-DSA de sk2, resto de sk.
        let mut c = sig[..ml_end].to_vec();
        c.extend_from_slice(&other[ml_end..]);
        assert!(!vk.verify(msg, &c), "swap SLH-DSA");
    }

    #[test]
    fn triple_signing_key_serialization_round_trips() {
        let (vk, sk) = generate_triple_keypair();
        let bytes = sk.to_bytes();
        assert_eq!(bytes.len(), TRIPLE_SIGNING_KEY_LEN);
        let sk2 = TripleSigningKey::from_bytes(&bytes).unwrap();
        assert!(vk.verify(b"m", &sk2.sign(b"m")));
    }

    #[test]
    fn triple_verifying_key_serialization_round_trips() {
        let (vk, sk) = generate_triple_keypair();
        let bytes = vk.to_bytes();
        assert_eq!(bytes.len(), TRIPLE_VERIFYING_KEY_LEN);
        let vk2 = TripleVerifyingKey::from_bytes(&bytes).unwrap();
        assert!(vk2.verify(b"m", &sk.sign(b"m")));
    }

    #[test]
    fn triple_wrong_length_signature_rejected() {
        let (vk, sk) = generate_triple_keypair();
        let mut sig = sk.sign(b"m");
        sig.truncate(TRIPLE_SIGNATURE_LEN - 1);
        assert!(!vk.verify(b"m", &sig));
    }

    #[test]
    fn triple_signatures_are_deterministic_but_bind_message() {
        let (_vk, sk) = generate_triple_keypair();
        assert_eq!(sk.sign(b"a"), sk.sign(b"a"));
        assert_ne!(sk.sign(b"a"), sk.sign(b"b"));
    }
}
