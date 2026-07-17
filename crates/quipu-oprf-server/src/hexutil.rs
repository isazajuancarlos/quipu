//! Codificación/decodificación hex, sin dependencias.
//!
//! El transporte usa hex por simplicidad y depurabilidad: el punto cegado, la
//! evaluación y la prueba viajan como cadenas hex sobre HTTP.

pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decodifica exactamente 32 bytes (64 caracteres hex). `None` si no encaja.
pub fn from_hex_32(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (hexval(b[2 * i])? << 4) | hexval(b[2 * i + 1])?;
    }
    Some(out)
}

/// Decodifica un número par de caracteres hex a bytes. `None` si no encaja.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        out.push((hexval(b[i])? << 4) | hexval(b[i + 1])?);
        i += 2;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let bytes: [u8; 32] = core::array::from_fn(|i| i as u8);
        let hex = to_hex(&bytes);
        assert_eq!(hex.len(), 64);
        assert_eq!(from_hex_32(&hex), Some(bytes));
    }

    #[test]
    fn rejects_bad() {
        assert_eq!(from_hex_32("zz"), None);
        assert_eq!(from_hex_32(&"a".repeat(63)), None);
        assert_eq!(from_hex_32(&"g".repeat(64)), None);
    }
}
