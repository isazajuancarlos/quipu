//! Antihacker: endurecimiento defensivo (defensa en profundidad).
//!
//! NO es seguridad por oscuridad: son defensas estándar y públicas que reducen
//! la superficie de ataque alrededor del cifrado.
//!
//!   - `wipe`: borrado seguro de claves/buffers sensibles (anti volcado de memoria).
//!   - `ct_eq`: comparación en tiempo constante (anti ataques de temporización).
//!
//! Políticas aplicadas en `api` (ver sección 12 del plan):
//!   - error de descifrado ÚNICO (sin oráculos que revelen qué comprobación falló);
//!   - sin salida parcial hasta que el tag AEAD valida;
//!   - coste Argon2id como antibot offline.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Borra de forma segura el contenido de `buf` (lo pone a cero sin que el
/// compilador pueda optimizar el borrado).
pub fn wipe(buf: &mut [u8]) {
    buf.zeroize();
}

/// Compara dos secuencias en tiempo constante (no termina antes ante el primer
/// byte distinto). Devuelve `true` si son iguales.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipe_zeroes_the_buffer() {
        let mut secret = [0xAAu8; 32];
        wipe(&mut secret);
        assert_eq!(secret, [0u8; 32]);
    }

    #[test]
    fn ct_eq_matches_equality() {
        assert!(ct_eq(b"clave-igual", b"clave-igual"));
        assert!(!ct_eq(b"clave-igual", b"clave-otra!"));
        assert!(!ct_eq(b"corta", b"mas-larga"));
    }
}
