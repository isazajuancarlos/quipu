// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! VOPRF conforme a **RFC 9497**, ciphersuite `ristretto255-SHA512`, modo VOPRF.
//!
//! Reemplaza la construccion propia anterior (`quipu/v2/voprf`), que estaba
//! *inspirada* en la RFC pero no era conforme: dominio propio, `hash_to_curve`
//! sin `expand_message_xmd` y transcripcion DLEQ propia. Consecuencias de
//! aquello: no interoperaba con nadie y no heredaba el analisis de seguridad de
//! la RFC. Ahora si: se verifica contra los vectores oficiales del Apendice
//! A.1.2 (ver `tests/rfc9497_vectors.rs`).
//!
//! Este cambio ROMPE el formato en cable: el dominio esta horneado en cada
//! secreto endurecido y, como la clave `k`, no rota nunca. Se hizo con cero
//! clientes, que era la unica ventana posible.
//!
//! Referencias de seccion: RFC 9497 §2.2 (pruebas), §3.2 (DeriveKeyPair),
//! §3.3.2 (protocolo VOPRF), §4.1 (ciphersuite ristretto255-SHA512).

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::traits::Identity;
use curve25519_dalek::{RistrettoPoint, Scalar};
use sha2::{Digest, Sha512};

/// `contextString = "OPRFV1-" || I2OSP(mode, 1) || "-" || identifier`  (§3.1).
/// Modo VOPRF = 0x01 (§3.1, tabla de modos).
const CONTEXT_STRING: &[u8] = b"OPRFV1-\x01-ristretto255-SHA512";

/// Longitud de la prueba serializada: dos escalares (c ‖ s).
pub const PROOF_LEN: usize = 64;
/// Longitud de la salida: `Hash` es SHA-512, asi que 64 B (§4.1).
///
/// OJO: la construccion anterior devolvia 32 B. La RFC devuelve el hash
/// completo; truncarlo habria hecho fallar los vectores oficiales.
pub const OUTPUT_LEN: usize = 64;

fn i2osp2(n: usize) -> [u8; 2] {
    (n as u16).to_be_bytes()
}

/// `expand_message_xmd` con SHA-512 (RFC 9380 §5.3.1), para len_in_bytes = 64.
///
/// Con SHA-512 (b_in_bytes = 64) y 64 bytes de salida, ell = 1: solo hacen falta
/// b_0 y b_1. s_in_bytes = 128 es el tamano de bloque de SHA-512.
fn expand_message_xmd_64(msg: &[u8], dst: &[u8]) -> [u8; 64] {
    assert!(dst.len() <= 255, "DST demasiado largo para expand_message_xmd");

    // DST_prime = DST || I2OSP(len(DST), 1)
    let mut dst_prime = dst.to_vec();
    dst_prime.push(dst.len() as u8);

    // msg_prime = Z_pad || msg || I2OSP(len_in_bytes, 2) || I2OSP(0, 1) || DST_prime
    let mut h = Sha512::new();
    h.update([0u8; 128]); // Z_pad = I2OSP(0, s_in_bytes)
    h.update(msg);
    h.update(i2osp2(64)); // l_i_b_str
    h.update([0u8]);
    h.update(&dst_prime);
    let b_0 = h.finalize();

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let mut h = Sha512::new();
    h.update(b_0);
    h.update([1u8]);
    h.update(&dst_prime);
    let b_1 = h.finalize();

    let mut out = [0u8; 64];
    out.copy_from_slice(&b_1);
    out
}

fn dst_with(prefix: &[u8]) -> Vec<u8> {
    let mut d = prefix.to_vec();
    d.extend_from_slice(CONTEXT_STRING);
    d
}

/// `HashToGroup`: hash_to_ristretto255 con `expand_message_xmd`/SHA-512 y
/// DST = "HashToGroup-" || contextString (§4.1).
fn hash_to_group(msg: &[u8]) -> RistrettoPoint {
    let u = expand_message_xmd_64(msg, &dst_with(b"HashToGroup-"));
    RistrettoPoint::from_uniform_bytes(&u)
}

/// `HashToScalar` con un DST explicito: `uniform_bytes` interpretado como entero
/// de 512 bits en **little-endian**, reducido mod el orden (§4.1).
/// `Scalar::from_bytes_mod_order_wide` es exactamente eso.
fn hash_to_scalar_dst(msg: &[u8], dst: &[u8]) -> Scalar {
    let u = expand_message_xmd_64(msg, dst);
    Scalar::from_bytes_mod_order_wide(&u)
}

fn hash_to_scalar(msg: &[u8]) -> Scalar {
    hash_to_scalar_dst(msg, &dst_with(b"HashToScalar-"))
}

fn random_scalar() -> Scalar {
    let mut b = [0u8; 64];
    getrandom::fill(&mut b).expect("RNG del sistema");
    Scalar::from_bytes_mod_order_wide(&b)
}

/// `DeriveKeyPair(seed, info)` (§3.2). Devuelve la clave secreta.
///
/// OJO: el DST es `"DeriveKeyPair" || contextString`, **sin guion** — al
/// contrario que HashToGroup-/HashToScalar-/Seed-. No es un descuido: es lo que
/// dice la RFC, y equivocarse aqui da una clave distinta en silencio.
pub fn derive_key_pair(seed: &[u8], info: &[u8]) -> Option<Scalar> {
    let dst = dst_with(b"DeriveKeyPair");
    let mut derive_input = seed.to_vec();
    derive_input.extend_from_slice(&i2osp2(info.len()));
    derive_input.extend_from_slice(info);

    for counter in 0u16..=255 {
        let mut msg = derive_input.clone();
        msg.push(counter as u8);
        let sk = hash_to_scalar_dst(&msg, &dst);
        if sk != Scalar::ZERO {
            return Some(sk);
        }
    }
    None // DeriveKeyPairError
}

/// Estado del cliente entre `blind` y `finalize`: el escalar de cegado y el
/// elemento cegado. El elemento hace falta para verificar la prueba (es la `C`
/// de VerifyProof), asi que no basta con guardar el escalar.
pub struct BlindState {
    blind: Scalar,
    blinded: RistrettoPoint,
}

impl BlindState {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(self.blind.as_bytes());
        out[32..].copy_from_slice(self.blinded.compress().as_bytes());
        out
    }

    pub fn from_bytes(b: &[u8; 64]) -> Option<Self> {
        let mut s = [0u8; 32];
        s.copy_from_slice(&b[..32]);
        let blind = Option::<Scalar>::from(Scalar::from_canonical_bytes(s))?;
        let blinded = CompressedRistretto::from_slice(&b[32..]).ok()?.decompress()?;
        Some(Self { blind, blinded })
    }
}

/// Servidor VOPRF: guarda `k` y expone `Y = k·G`.
pub struct Server {
    key: Scalar,
}

impl Server {
    /// Deriva la clave desde una semilla, via `DeriveKeyPair` de la RFC (§3.2).
    pub fn from_seed(seed: &[u8], info: &[u8]) -> Option<Self> {
        derive_key_pair(seed, info).map(|key| Self { key })
    }

    /// Construye desde un escalar ya derivado (para los vectores de prueba).
    pub fn from_scalar(key: Scalar) -> Self {
        Self { key }
    }

    /// Servidor con clave EFIMERA (semilla aleatoria). Para tests y dev: al
    /// reiniciar, la clave cambia y todo secreto endurecido queda invalidado.
    ///
    /// Hay `Default` (lo pide clippy), pero preferir `new()` o, en produccion,
    /// `from_seed`: una clave efimera no es un "por defecto" razonable para un
    /// servicio que promete secretos estables.
    pub fn new() -> Self {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("RNG del sistema");
        Self::from_seed(&seed, b"quipu-voprf-ephemeral").expect("DeriveKeyPair con seed aleatorio")
    }

    pub fn public_key(&self) -> [u8; 32] {
        (self.key * RISTRETTO_BASEPOINT_POINT).compress().to_bytes()
    }

    /// `BlindEvaluate` (§3.3.2): `Z = k·B` mas la prueba DLEQ.
    ///
    /// Devuelve `None` si `blinded` no decodifica o es el elemento identidad
    /// (§3.3: la RFC EXIGE rechazar la identidad recibida por la red).
    pub fn blind_evaluate(&self, blinded: &[u8; 32]) -> Option<([u8; 32], [u8; PROOF_LEN])> {
        let b = CompressedRistretto::from_slice(blinded).ok()?.decompress()?;
        if b == RistrettoPoint::identity() {
            return None;
        }
        let z = self.key * b;
        let proof = self.generate_proof(b, z, random_scalar());
        Some((z.compress().to_bytes(), proof))
    }

    /// Igual que `blind_evaluate` pero con la aleatoriedad de la prueba fijada.
    /// Solo para los vectores oficiales, que traen `ProofRandomScalar`.
    #[doc(hidden)]
    pub fn blind_evaluate_with_randomness(
        &self,
        blinded: &[u8; 32],
        r: Scalar,
    ) -> Option<([u8; 32], [u8; PROOF_LEN])> {
        let b = CompressedRistretto::from_slice(blinded).ok()?.decompress()?;
        if b == RistrettoPoint::identity() {
            return None;
        }
        let z = self.key * b;
        Some((z.compress().to_bytes(), self.generate_proof(b, z, r)))
    }

    /// `GenerateProof(k, A, B, C, D)` con A = G, B = pkS (§2.2.1), lote de 1.
    fn generate_proof(&self, c_elem: RistrettoPoint, d_elem: RistrettoPoint, r: Scalar) -> [u8; PROOF_LEN] {
        let pk = self.key * RISTRETTO_BASEPOINT_POINT;
        // ComputeCompositesFast: igual que ComputeComposites pero Z = k·M.
        let m = compute_composites_m(pk, &[c_elem], &[d_elem]);
        let z = self.key * m;

        let t2 = r * RISTRETTO_BASEPOINT_POINT;
        let t3 = r * m;

        let c = challenge(pk, m, z, t2, t3);
        let s = r - c * self.key;

        let mut proof = [0u8; PROOF_LEN];
        proof[..32].copy_from_slice(c.as_bytes());
        proof[32..].copy_from_slice(s.as_bytes());
        proof
    }
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

/// Parte comun de ComputeComposites / ComputeCompositesFast: calcula `M`.
/// El servidor obtiene `Z = k·M`; el cliente lo acumula desde `D` (§2.2.1/§2.2.2).
fn compute_composites_m(pk: RistrettoPoint, c: &[RistrettoPoint], d: &[RistrettoPoint]) -> RistrettoPoint {
    let seed = composites_seed(pk);
    let mut m = RistrettoPoint::identity();
    for (i, (ci, di)) in c.iter().zip(d.iter()).enumerate() {
        let di_scalar = composite_scalar(&seed, i, *ci, *di);
        m += di_scalar * ci;
    }
    m
}

/// `ComputeComposites(B, C, D)` del lado cliente: sin `k`, acumula `Z` desde `D`.
fn compute_composites(
    pk: RistrettoPoint,
    c: &[RistrettoPoint],
    d: &[RistrettoPoint],
) -> (RistrettoPoint, RistrettoPoint) {
    let seed = composites_seed(pk);
    let mut m = RistrettoPoint::identity();
    let mut z = RistrettoPoint::identity();
    for (i, (ci, di)) in c.iter().zip(d.iter()).enumerate() {
        let di_scalar = composite_scalar(&seed, i, *ci, *di);
        m += di_scalar * ci;
        z += di_scalar * di;
    }
    (m, z)
}

fn composites_seed(pk: RistrettoPoint) -> [u8; 64] {
    let bm = pk.compress();
    let seed_dst = dst_with(b"Seed-");
    let mut h = Sha512::new();
    h.update(i2osp2(32));
    h.update(bm.as_bytes());
    h.update(i2osp2(seed_dst.len()));
    h.update(&seed_dst);
    let out = h.finalize();
    let mut seed = [0u8; 64];
    seed.copy_from_slice(&out);
    seed
}

fn composite_scalar(seed: &[u8; 64], i: usize, ci: RistrettoPoint, di: RistrettoPoint) -> Scalar {
    let ci_b = ci.compress();
    let di_b = di.compress();
    let mut t = Vec::with_capacity(64 + 2 + 2 + 2 + 32 + 2 + 32 + 9);
    t.extend_from_slice(&i2osp2(64));
    t.extend_from_slice(seed);
    t.extend_from_slice(&i2osp2(i));
    t.extend_from_slice(&i2osp2(32));
    t.extend_from_slice(ci_b.as_bytes());
    t.extend_from_slice(&i2osp2(32));
    t.extend_from_slice(di_b.as_bytes());
    // "Composite" va SIN prefijo de longitud (§2.2.1). Ponerselo da otro escalar.
    t.extend_from_slice(b"Composite");
    hash_to_scalar(&t)
}

/// `challengeTranscript` de §2.2.1/§2.2.2. "Challenge" va SIN prefijo de longitud.
fn challenge(
    pk: RistrettoPoint,
    m: RistrettoPoint,
    z: RistrettoPoint,
    t2: RistrettoPoint,
    t3: RistrettoPoint,
) -> Scalar {
    let mut t = Vec::with_capacity(5 * 34 + 9);
    for p in [pk, m, z, t2, t3] {
        t.extend_from_slice(&i2osp2(32));
        t.extend_from_slice(p.compress().as_bytes());
    }
    t.extend_from_slice(b"Challenge");
    hash_to_scalar(&t)
}

/// `Blind(input)` (§3.3.2).
///
/// `None` si la entrada mapea al elemento identidad (`InvalidInputError`).
/// Es astronomicamente improbable, pero la RFC obliga a comprobarlo.
pub fn blind(input: &[u8]) -> Option<(BlindState, [u8; 32])> {
    let p = hash_to_group(input);
    if p == RistrettoPoint::identity() {
        return None;
    }
    let r = random_scalar();
    let blinded = r * p;
    let bytes = blinded.compress().to_bytes();
    Some((BlindState { blind: r, blinded }, bytes))
}

/// Igual que `blind` con el escalar de cegado fijado. Solo para los vectores.
#[doc(hidden)]
pub fn blind_with(input: &[u8], r: Scalar) -> Option<(BlindState, [u8; 32])> {
    let p = hash_to_group(input);
    if p == RistrettoPoint::identity() {
        return None;
    }
    let blinded = r * p;
    let bytes = blinded.compress().to_bytes();
    Some((BlindState { blind: r, blinded }, bytes))
}

/// `VerifyProof(A, B, C, D, proof)` (§2.2.2), lote de 1.
fn verify_proof(
    pk: RistrettoPoint,
    c_elem: RistrettoPoint,
    d_elem: RistrettoPoint,
    proof: &[u8; PROOF_LEN],
) -> bool {
    let mut cb = [0u8; 32];
    cb.copy_from_slice(&proof[..32]);
    let mut sb = [0u8; 32];
    sb.copy_from_slice(&proof[32..]);
    let (c, s) = match (
        Option::<Scalar>::from(Scalar::from_canonical_bytes(cb)),
        Option::<Scalar>::from(Scalar::from_canonical_bytes(sb)),
    ) {
        (Some(c), Some(s)) => (c, s),
        _ => return false,
    };

    let (m, z) = compute_composites(pk, &[c_elem], &[d_elem]);
    let t2 = s * RISTRETTO_BASEPOINT_POINT + c * pk;
    let t3 = s * m + c * z;
    let expected = challenge(pk, m, z, t2, t3);
    // Comparacion de escalares: `Scalar` implementa ConstantTimeEq via PartialEq
    // de dalek, que ya es en tiempo constante.
    expected == c
}

/// `Finalize` del modo VOPRF (§3.3.2): VERIFICA la prueba contra `server_pub`
/// (fijada) y, solo si valida, devuelve la salida de 64 B.
///
/// `None` = la prueba no valida. Nunca devuelve una salida sin verificar: ese
/// era el sentido de todo el diseno.
pub fn finalize(
    input: &[u8],
    state: &BlindState,
    evaluated: &[u8; 32],
    proof: &[u8; PROOF_LEN],
    server_pub: &[u8; 32],
) -> Option<[u8; OUTPUT_LEN]> {
    let pk = CompressedRistretto::from_slice(server_pub).ok()?.decompress()?;
    let z = CompressedRistretto::from_slice(evaluated).ok()?.decompress()?;
    if z == RistrettoPoint::identity() || pk == RistrettoPoint::identity() {
        return None;
    }
    if !verify_proof(pk, state.blinded, z, proof) {
        return None;
    }

    let n = state.blind.invert() * z;
    let unblinded = n.compress();

    let mut h = Sha512::new();
    h.update(i2osp2(input.len()));
    h.update(input);
    h.update(i2osp2(32));
    h.update(unblinded.as_bytes());
    // "Finalize" va SIN prefijo de longitud (§3.3.2).
    h.update(b"Finalize");
    let out = h.finalize();

    let mut secret = [0u8; OUTPUT_LEN];
    secret.copy_from_slice(&out);
    Some(secret)
}
