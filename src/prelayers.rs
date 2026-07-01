//! Precapas del lado del DATO, aplicadas al plaintext antes de cifrar.
//!
//! Padding Padmé (Nikitin et al., PURBs): cuantiza la longitud para que el
//! tamaño del ciphertext filtre lo mínimo sobre el contenido. El overhead se
//! mantiene acotado (~12% como mucho).
//!
//! Formato del bloque con padding:
//!   [ len: u64 big-endian (8 bytes) | data | ceros hasta padme(8 + data.len()) ]

/// Errores de las precapas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrelayerError {
    /// El bloque con padding es más corto que el prefijo de longitud.
    TooShort,
    /// La longitud declarada no cabe en el bloque.
    InvalidLength,
}

/// Tamaño del prefijo de longitud.
const LEN_PREFIX: usize = 8;

/// Longitud objetivo Padmé para una longitud `l` (>= l).
fn padme(l: usize) -> usize {
    if l < 2 {
        return l;
    }
    let e = (usize::BITS - 1 - l.leading_zeros()) as usize; // floor(log2(l))
    let s = (usize::BITS - e.leading_zeros()) as usize; // bit_length(e)
    let last_bits = e.saturating_sub(s);
    let mask = (1usize << last_bits) - 1;
    (l + mask) & !mask
}

/// Aplica el padding Padmé reversible a `data`.
pub fn pad(data: &[u8]) -> Vec<u8> {
    let content_len = LEN_PREFIX + data.len();
    let target = padme(content_len);

    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(&(data.len() as u64).to_be_bytes());
    out.extend_from_slice(data);
    out.resize(target, 0); // ceros hasta la longitud Padmé
    out
}

/// Quita el padding aplicado por [`pad`].
pub fn unpad(padded: &[u8]) -> Result<Vec<u8>, PrelayerError> {
    if padded.len() < LEN_PREFIX {
        return Err(PrelayerError::TooShort);
    }
    let len = u64::from_be_bytes(padded[0..LEN_PREFIX].try_into().expect("8 bytes")) as usize;
    let end = LEN_PREFIX.checked_add(len).ok_or(PrelayerError::InvalidLength)?;
    if end > padded.len() {
        return Err(PrelayerError::InvalidLength);
    }
    Ok(padded[LEN_PREFIX..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn pad_then_unpad_round_trips() {
        let data = b"contenido de longitud variable";
        let padded = pad(data);
        assert_eq!(unpad(&padded).unwrap(), data);
    }

    proptest! {
        #[test]
        fn round_trips_any_data(data in proptest::collection::vec(any::<u8>(), 0..300)) {
            let padded = pad(&data);
            prop_assert_eq!(unpad(&padded).unwrap(), data);
        }

        /// El padding nunca encoge y el overhead se mantiene acotado (< 13%).
        #[test]
        fn padding_overhead_is_bounded(data in proptest::collection::vec(any::<u8>(), 1..5000)) {
            let padded_len = pad(&data).len();
            let content = data.len() + LEN_PREFIX;
            prop_assert!(padded_len >= content);
            prop_assert!((padded_len as f64) < (content as f64) * 1.13);
        }
    }
}
