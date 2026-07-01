//! VOPRF: OPRF VERIFICABLE sobre ristretto255 (estilo RFC 9497).
//!
//! Mejora sobre `oprf`: el servidor publica una clave pública `Y = k·G` y, con
//! cada evaluación, adjunta una prueba DLEQ (Chaum-Pedersen no interactiva) de
//! que usó la MISMA `k` de `Y`, sin revelarla. El cliente VERIFICA la prueba
//! contra la clave pública fijada (pinned) antes de usar el resultado.
//!
//! Cierra el hallazgo F1: un servidor malicioso ya no puede dar respuestas
//! falsas sin ser detectado.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{RistrettoPoint, Scalar};
use sha2::{Digest, Sha512};

const OPRF_DOMAIN: &[u8] = b"quipu/v2/voprf";
const DLEQ_DOMAIN: &[u8] = b"quipu/v2/voprf-dleq";

/// Longitud de la prueba DLEQ serializada (c ‖ s).
pub const PROOF_LEN: usize = 64;

fn random_scalar() -> Scalar {
    let mut b = [0u8; 64];
    getrandom::getrandom(&mut b).expect("RNG del sistema");
    Scalar::from_bytes_mod_order_wide(&b)
}

/// Servidor VOPRF: guarda la clave secreta y expone la pública.
pub struct Server {
    key: Scalar,
}

/// Estado del cliente entre el cegado y la finalización.
pub struct BlindState {
    r_inv: Scalar,
    blinded: [u8; 32],
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    /// Servidor con clave aleatoria.
    pub fn new() -> Self {
        Self {
            key: random_scalar(),
        }
    }

    /// Servidor con clave determinista derivada de `seed` (persistible).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(b"quipu/v2/voprf-server-key");
        hasher.update(seed);
        let wide: [u8; 64] = hasher.finalize().into();
        Self {
            key: Scalar::from_bytes_mod_order_wide(&wide),
        }
    }

    /// Clave pública `Y = k·G` (a fijar/pinnear en el cliente).
    pub fn public_key(&self) -> [u8; 32] {
        (self.key * RISTRETTO_BASEPOINT_POINT).compress().to_bytes()
    }

    /// Evalúa un punto cegado y adjunta la prueba DLEQ.
    pub fn evaluate(&self, blinded: &[u8; 32]) -> Option<([u8; 32], [u8; PROOF_LEN])> {
        let b = CompressedRistretto::from_slice(blinded).ok()?.decompress()?;
        let z = self.key * b;
        let y = self.key * RISTRETTO_BASEPOINT_POINT;
        let proof = dleq_prove(self.key, y, b, z);
        Some((z.compress().to_bytes(), proof))
    }
}

/// Ciega la `password`.
pub fn blind(password: &[u8]) -> (BlindState, [u8; 32]) {
    let h = hash_to_curve(password);
    let r = random_scalar();
    let blinded = (r * h).compress().to_bytes();
    (
        BlindState {
            r_inv: r.invert(),
            blinded,
        },
        blinded,
    )
}

/// Verifica la prueba y, si es válida, obtiene PRF_k(password). `None` si la
/// prueba no valida contra `server_pub` (servidor deshonesto o clave incorrecta).
pub fn finalize(
    password: &[u8],
    state: &BlindState,
    evaluated: &[u8; 32],
    proof: &[u8; PROOF_LEN],
    server_pub: &[u8; 32],
) -> Option<[u8; 32]> {
    let z = CompressedRistretto::from_slice(evaluated).ok()?.decompress()?;
    let y = CompressedRistretto::from_slice(server_pub).ok()?.decompress()?;
    let b = CompressedRistretto::from_slice(&state.blinded)
        .ok()?
        .decompress()?;

    // Verificabilidad: la prueba debe validar contra la clave pública fijada.
    if !dleq_verify(y, b, z, proof) {
        return None;
    }

    let unblinded = state.r_inv * z; // = k · H(password)
    let mut hasher = Sha512::new();
    hasher.update(OPRF_DOMAIN);
    hasher.update((password.len() as u64).to_be_bytes());
    hasher.update(password);
    hasher.update(unblinded.compress().to_bytes());
    let out: [u8; 64] = hasher.finalize().into();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    Some(key)
}

fn hash_to_curve(password: &[u8]) -> RistrettoPoint {
    let mut buf = OPRF_DOMAIN.to_vec();
    buf.extend_from_slice(password);
    RistrettoPoint::hash_from_bytes::<Sha512>(&buf)
}

/// Prueba DLEQ (Chaum-Pedersen): demuestra log_G(Y) == log_B(Z) == k.
fn dleq_prove(k: Scalar, y: RistrettoPoint, b: RistrettoPoint, z: RistrettoPoint) -> [u8; PROOF_LEN] {
    let t = random_scalar();
    let a1 = t * RISTRETTO_BASEPOINT_POINT;
    let a2 = t * b;
    let c = dleq_challenge(y, b, z, a1, a2);
    let s = t + c * k;

    let mut proof = [0u8; PROOF_LEN];
    proof[..32].copy_from_slice(&c.to_bytes());
    proof[32..].copy_from_slice(&s.to_bytes());
    proof
}

fn dleq_verify(y: RistrettoPoint, b: RistrettoPoint, z: RistrettoPoint, proof: &[u8; PROOF_LEN]) -> bool {
    let Some(c) = parse_scalar(&proof[..32]) else {
        return false;
    };
    let Some(s) = parse_scalar(&proof[32..]) else {
        return false;
    };
    let a1 = s * RISTRETTO_BASEPOINT_POINT - c * y;
    let a2 = s * b - c * z;
    dleq_challenge(y, b, z, a1, a2) == c
}

fn dleq_challenge(
    y: RistrettoPoint,
    b: RistrettoPoint,
    z: RistrettoPoint,
    a1: RistrettoPoint,
    a2: RistrettoPoint,
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(DLEQ_DOMAIN);
    hasher.update(RISTRETTO_BASEPOINT_POINT.compress().to_bytes());
    for p in [y, b, z, a1, a2] {
        hasher.update(p.compress().to_bytes());
    }
    let wide: [u8; 64] = hasher.finalize().into();
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn parse_scalar(bytes: &[u8]) -> Option<Scalar> {
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Option::from(Scalar::from_canonical_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn voprf_round_trip_with_valid_proof_is_deterministic() {
        let server = Server::new();
        let pk = server.public_key();
        let pw = b"passphrase del usuario";

        let (st1, b1) = blind(pw);
        let (z1, p1) = server.evaluate(&b1).unwrap();
        let o1 = finalize(pw, &st1, &z1, &p1, &pk).unwrap();

        let (st2, b2) = blind(pw);
        let (z2, p2) = server.evaluate(&b2).unwrap();
        let o2 = finalize(pw, &st2, &z2, &p2, &pk).unwrap();

        assert_eq!(o1, o2);
    }

    #[test]
    fn rejects_forged_proof() {
        let server = Server::new();
        let pk = server.public_key();
        let (st, b) = blind(b"x");
        let (z, mut proof) = server.evaluate(&b).unwrap();
        proof[0] ^= 0x01; // falsifica la prueba
        assert!(finalize(b"x", &st, &z, &proof, &pk).is_none());
    }

    #[test]
    fn rejects_wrong_server_pubkey() {
        let server = Server::new();
        let impostor = Server::new();
        let (st, b) = blind(b"x");
        let (z, proof) = server.evaluate(&b).unwrap();
        // Verificada contra la clave del impostor -> rechazada.
        assert!(finalize(b"x", &st, &z, &proof, &impostor.public_key()).is_none());
    }

    #[test]
    fn rejects_tampered_evaluation() {
        let server = Server::new();
        let pk = server.public_key();
        let (st, b) = blind(b"x");
        let (mut z, proof) = server.evaluate(&b).unwrap();
        z[0] ^= 0x01; // altera la evaluación
        assert!(finalize(b"x", &st, &z, &proof, &pk).is_none());
    }

    #[test]
    fn from_seed_is_deterministic() {
        let seed = [9u8; 32];
        let s1 = Server::from_seed(&seed);
        let s2 = Server::from_seed(&seed);
        assert_eq!(s1.public_key(), s2.public_key());
    }
}
