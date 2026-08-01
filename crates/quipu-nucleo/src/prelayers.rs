// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Precapas del lado del DATO, aplicadas al plaintext antes de cifrar.
//!
//! # Este módulo es hoy un ENVOLTORIO de [`padme_frame`]
//!
//! El padding Padmé vivía aquí, y el 2026-08-01 se extrajo a su propio crate
//! con licencia **MIT OR Apache-2.0**. La extracción a `quipu-nucleo` ya había
//! ocurrido antes y **no servía de nada**: de las 961 líneas de este crate,
//! Padmé es lo único que sirve fuera de Quipu, y con la AGPL nadie lo enlaza
//! por un padding de 90 líneas. Lo que daba valor era la licencia, no el
//! directorio.
//!
//! Se conserva este módulo, con los mismos nombres y la misma firma, para que
//! ningún consumidor de `quipu` ni de `quipu-nucleo` tenga que cambiar nada.
//!
//! Formato del bloque con padding (lo define ahora `padme-frame`):
//!   [ len: u64 big-endian (8 bytes) | data | ceros hasta padme(8 + data.len()) ]

/// Errores de las precapas.
///
/// Se mantiene como tipo propio —en vez de reexportar `padme_frame::UnpadError`—
/// porque es parte de la API pública de `quipu` desde la 0.10.0 y cambiarlo
/// rompería a quien haga `match` sobre él. La conversión es total.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrelayerError {
    /// El bloque con padding es más corto que el prefijo de longitud.
    TooShort,
    /// La longitud declarada no cabe en el bloque.
    InvalidLength,
}

impl From<padme_frame::UnpadError> for PrelayerError {
    fn from(e: padme_frame::UnpadError) -> Self {
        match e {
            padme_frame::UnpadError::TooShort { .. } => Self::TooShort,
            padme_frame::UnpadError::InvalidLength { .. } => Self::InvalidLength,
        }
    }
}

/// Aplica el padding Padmé reversible a `data`.
#[must_use]
pub fn pad(data: &[u8]) -> Vec<u8> {
    padme_frame::pad(data)
}

/// Quita el padding aplicado por [`pad`].
///
/// Devuelve un `Vec` propio, no un préstamo: `padme_frame::unpad` presta del
/// bloque —que es mejor API— pero los consumidores de Quipu esperan propiedad
/// desde la 0.10.0, y esa firma no se cambia por comodidad.
pub fn unpad(padded: &[u8]) -> Result<Vec<u8>, PrelayerError> {
    padme_frame::unpad(padded)
        .map(<[u8]>::to_vec)
        .map_err(PrelayerError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// El envoltorio no cambia el COMPORTAMIENTO, que es lo único que este
    /// módulo tiene que seguir garantizando tras la extracción.
    #[test]
    fn el_envoltorio_conserva_la_ida_y_vuelta() {
        for n in [0usize, 1, 8, 31, 100, 1000] {
            let d: Vec<u8> = (0..n).map(|i| (i * 31 + 7) as u8).collect();
            assert_eq!(unpad(&pad(&d)).unwrap(), d, "falló con {n} bytes");
        }
    }

    /// Y los errores siguen siendo los de siempre, con los mismos nombres.
    #[test]
    fn los_errores_se_traducen_sin_perder_el_caso() {
        assert_eq!(unpad(&[0u8; 3]), Err(PrelayerError::TooShort));
        let mut hostil = 99u64.to_be_bytes().to_vec();
        hostil.extend_from_slice(b"corto");
        assert_eq!(unpad(&hostil), Err(PrelayerError::InvalidLength));
    }
}
