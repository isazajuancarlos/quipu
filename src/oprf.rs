// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! OPRF (Oblivious Pseudo-Random Function) sobre ristretto255.
//!
//! Modo online: endurece una passphrase de forma que adivinarla requiere
//! consultar a un SERVIDOR que limita la tasa (antibot/rate-limit REAL).
//!
//!   - El cliente "ciega" su passphrase: el servidor nunca la ve.
//!   - El servidor evalúa con su clave secreta `k` y limita el nº de consultas.
//!   - El cliente "desciega" y obtiene PRF_k(passphrase), sin aprender `k`.
//!
//! El output OPRF alimenta luego al KDF (p. ej. como pepper), convirtiendo el
//! fuerza bruta OFFLINE (intentos ilimitados) en ONLINE (limitado por servidor).

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{RistrettoPoint, Scalar};
use sha2::{Digest, Sha256, Sha512};

const OPRF_DOMAIN: &[u8] = b"quipu/v2/oprf";

fn random_scalar() -> Scalar {
    let mut b = [0u8; 64];
    crate::aleatorio::llenar(&mut b).expect("RNG del sistema");
    Scalar::from_bytes_mod_order_wide(&b)
}

/// Servidor OPRF: guarda la clave secreta y limita el nº de evaluaciones.
pub struct Server {
    key: Scalar,
    remaining: u32,
}

/// Estado del cliente entre el cegado y la finalización.
pub struct BlindState {
    r_inv: Scalar,
}

impl Server {
    /// Crea un servidor con clave aleatoria y un presupuesto de `max_requests`
    /// evaluaciones (el rate-limit).
    pub fn new(max_requests: u32) -> Self {
        Self {
            key: random_scalar(),
            remaining: max_requests,
        }
    }

    /// Crea un servidor con clave DETERMINISTA derivada de `seed` (32 bytes).
    /// Imprescindible para persistir/recargar la clave: la misma semilla da la
    /// misma clave, así reiniciar el servidor NO rompe los secretos endurecidos.
    pub fn from_seed(seed: &[u8; 32], max_requests: u32) -> Self {
        // Expande la semilla a 64 bytes y reduce a escalar (determinista).
        let mut hasher = Sha512::new();
        hasher.update(b"quipu/v2/oprf-server-key");
        hasher.update(seed);
        let wide: [u8; 64] = hasher.finalize().into();
        Self {
            key: Scalar::from_bytes_mod_order_wide(&wide),
            remaining: max_requests,
        }
    }

    /// Evalúa un punto cegado. Devuelve `None` si se agotó el presupuesto.
    pub fn evaluate(&mut self, blinded: &[u8; 32]) -> Option<[u8; 32]> {
        if self.remaining == 0 {
            return None; // rate-limit agotado
        }
        let out = self.evaluate_raw(blinded)?;
        self.remaining -= 1; // solo descuenta si el punto era válido
        Some(out)
    }

    /// Evalúa SIN consumir presupuesto. Para servidores de red que limitan por
    /// otra vía (p. ej. por IP). Devuelve `None` solo si el punto es inválido.
    pub fn evaluate_raw(&self, blinded: &[u8; 32]) -> Option<[u8; 32]> {
        let point = CompressedRistretto::from_slice(blinded).ok()?.decompress()?;
        Some((self.key * point).compress().to_bytes())
    }
}

/// Ciega la `password`: produce el estado y el punto cegado a enviar al servidor.
pub fn blind(password: &[u8]) -> (BlindState, [u8; 32]) {
    let h = RistrettoPoint::hash_from_bytes::<Sha512>(password);
    let r = random_scalar();
    let blinded = r * h;
    (
        BlindState { r_inv: r.invert() },
        blinded.compress().to_bytes(),
    )
}

/// Finaliza: combina la respuesta del servidor para obtener PRF_k(password).
pub fn finalize(password: &[u8], state: &BlindState, evaluated: &[u8; 32]) -> Option<[u8; 32]> {
    let ev = CompressedRistretto::from_slice(evaluated)
        .ok()?
        .decompress()?;
    // Desciega: r^-1 * (k * r * H) = k * H(password).
    let unblinded = state.r_inv * ev;

    let mut hasher = Sha256::new();
    hasher.update(OPRF_DOMAIN);
    hasher.update((password.len() as u64).to_be_bytes());
    hasher.update(password);
    hasher.update(unblinded.compress().to_bytes());
    Some(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oprf_output_is_deterministic_in_password_and_key() {
        let mut server = Server::new(100);
        let pw = b"passphrase del usuario";

        let (s1, b1) = blind(pw);
        let e1 = server.evaluate(&b1).unwrap();
        let o1 = finalize(pw, &s1, &e1).unwrap();

        let (s2, b2) = blind(pw);
        assert_ne!(b1, b2, "el cegado debe ser aleatorio");
        let e2 = server.evaluate(&b2).unwrap();
        let o2 = finalize(pw, &s2, &e2).unwrap();

        assert_eq!(o1, o2, "mismo password+clave -> mismo output OPRF");
    }

    #[test]
    fn different_passwords_yield_different_outputs() {
        let mut server = Server::new(100);
        let (sa, ba) = blind(b"password-A");
        let ea = server.evaluate(&ba).unwrap();
        let oa = finalize(b"password-A", &sa, &ea).unwrap();
        let (sb, bb) = blind(b"password-B");
        let eb = server.evaluate(&bb).unwrap();
        let ob = finalize(b"password-B", &sb, &eb).unwrap();
        assert_ne!(oa, ob);
    }

    #[test]
    fn from_seed_is_deterministic() {
        let seed = [42u8; 32];
        let s1 = Server::from_seed(&seed, 10);
        let s2 = Server::from_seed(&seed, 10);
        let (_st, b) = blind(b"x");
        // Misma semilla -> misma clave -> misma evaluación.
        assert_eq!(s1.evaluate_raw(&b), s2.evaluate_raw(&b));
    }

    #[test]
    fn evaluate_raw_ignores_budget() {
        let server = Server::new(0); // presupuesto agotado
        let (_s, b) = blind(b"x");
        // evaluate_raw funciona igual (el rate-limit se hace por otra vía).
        assert!(server.evaluate_raw(&b).is_some());
    }

    #[test]
    fn server_enforces_rate_limit() {
        let mut server = Server::new(2);
        let (_s, b) = blind(b"x");
        assert!(server.evaluate(&b).is_some());
        assert!(server.evaluate(&b).is_some());
        assert!(server.evaluate(&b).is_none(), "presupuesto agotado");
    }
}
