// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza Arenas

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Padmé padding con un marco de longitud autodescriptivo.
//!
//! # Qué problema resuelve
//!
//! El tamaño de un archivo cifrado habla. Dos ficheros de 1 024 y 1 031 bytes se
//! distinguen aunque su contenido sea indescifrable, y esa diferencia basta a
//! menudo para identificar de cuál se trata. **Padmé** cuantiza la longitud a un
//! conjunto pequeño de valores posibles, con un sobrecoste acotado —bastante por
//! debajo del 13 %—, de modo que muchos tamaños distintos colapsen en el mismo.
//!
//! Descrito en Nikitin et al., *«Reducing Metadata Leakage from Encrypted Files
//! and Communication with PURBs»*, PoPETs 2019(4).
//!
//! # Qué añade sobre implementar solo la aritmética
//!
//! Padmé, a secas, es una función de longitud: dado `l`, devuelve a cuánto hay
//! que rellenar. Eso son ocho líneas y ya existe en el ecosistema.
//!
//! **Lo que falta después es el marco**, y es donde viven los fallos: para poder
//! QUITAR el relleno hay que saber dónde acababan los datos, así que hace falta
//! un prefijo de longitud, decidir su tamaño y su orden de bytes, y validar ese
//! prefijo cuando llega de fuera —porque un prefijo hostil que declare más
//! longitud de la que hay es un desbordamiento esperando a ocurrir—.
//!
//! Este crate trae esas dos mitades juntas y probadas:
//!
//! ```text
//! [ largo: u64 big-endian (8 bytes) | datos | ceros hasta padme(8 + datos.len()) ]
//! ```
//!
//! # Lo que NO hace, y conviene saberlo antes de usarlo
//!
//! - **No cifra ni autentica.** El relleno va en claro y quien lo reciba puede
//!   cambiarlo. Esto se aplica al texto en claro ANTES de cifrar; la integridad
//!   la pone el AEAD de encima.
//! - **No oculta el tamaño, lo CUANTIZA.** Padmé deja la longitud verdadera
//!   dentro de una ventana de aproximadamente ±0,8 % en todo el rango. Para
//!   cargas pequeñas la ventana es de pocos bytes: un dato de 1 a 24 bytes
//!   comparte longitud con apenas otra. Si necesita un conjunto de tamaños
//!   observables verdaderamente pequeño, lo que quiere es una escalera —
//!   potencias de dos, por ejemplo—, que cuesta mucho más relleno y esconde
//!   mucho más.
//! - **No es de tiempo constante.** No lo necesita: no toca material secreto,
//!   solo longitudes que ya son públicas.
//!
//! # Ejemplo
//!
//! ```
//! use padme_frame::{pad, unpad};
//!
//! let secreto = b"31 bytes que no quiero que midan";
//! let relleno = pad(secreto);
//! assert!(relleno.len() >= secreto.len() + 8);
//! assert_eq!(unpad(&relleno).unwrap(), secreto);
//! ```

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

/// Tamaño del prefijo de longitud, en bytes.
///
/// Ocho, y no cuatro: cuatro limitarían la carga a 4 GiB, y el ahorro serían
/// cuatro bytes sobre un formato cuyo sobrecoste ya está dominado por el
/// relleno. Un límite que se alcanza es peor que cuatro bytes de más.
pub const LEN_PREFIX: usize = 8;

/// Por qué no se pudo quitar el relleno.
///
/// Los dos casos son de ENTRADA HOSTIL O CORRUPTA, no de uso incorrecto: quien
/// llama a [`unpad`] con la salida de [`pad`] no puede verlos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnpadError {
    /// El bloque no llega ni al prefijo de longitud.
    TooShort {
        /// Bytes que llegaron.
        got: usize,
        /// Bytes que hacen falta como mínimo.
        need: usize,
    },
    /// El prefijo declara más datos de los que el bloque contiene.
    ///
    /// Es la comprobación que impide leer fuera del bloque con un prefijo
    /// fabricado, y por eso [`unpad`] valida antes de indexar.
    InvalidLength {
        /// Lo que el prefijo declaraba.
        declared: u64,
        /// Lo que de verdad había disponible.
        available: usize,
    },
}

impl fmt::Display for UnpadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { got, need } => {
                write!(f, "el bloque mide {got} bytes y el prefijo de longitud necesita {need}")
            }
            Self::InvalidLength { declared, available } => write!(
                f,
                "el prefijo declara {declared} bytes de datos y solo hay {available}"
            ),
        }
    }
}

impl core::error::Error for UnpadError {}

/// La longitud Padmé para `l`: el siguiente valor del conjunto cuantizado.
///
/// Nunca devuelve menos que `l`. Expuesta a propósito para quien quiera
/// reservar de antemano o medir el sobrecoste sin construir el bloque.
///
/// ```
/// # use padme_frame::padded_len;
/// assert_eq!(padded_len(0), 0);
/// assert_eq!(padded_len(1), 1);
/// assert!(padded_len(1000) >= 1000);
/// ```
#[must_use]
pub const fn padded_len(l: usize) -> usize {
    if l < 2 {
        return l;
    }
    // floor(log2(l)) y el número de bits que ocupa ese exponente.
    let e = (usize::BITS - 1 - l.leading_zeros()) as usize;
    let s = (usize::BITS - e.leading_zeros()) as usize;
    let last_bits = e.saturating_sub(s);
    let mask = (1usize << last_bits) - 1;
    (l + mask) & !mask
}

/// Envuelve `data` en el marco y lo rellena hasta la longitud Padmé.
///
/// La salida siempre mide al menos `LEN_PREFIX + data.len()`.
#[must_use]
pub fn pad(data: &[u8]) -> Vec<u8> {
    let content = LEN_PREFIX + data.len();
    let target = padded_len(content);

    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(&(data.len() as u64).to_be_bytes());
    out.extend_from_slice(data);
    out.resize(target, 0);
    out
}

/// Devuelve los datos que [`pad`] envolvió, **sin copiarlos**.
///
/// Presta un tramo del bloque original. Si necesita la propiedad, `.to_vec()`.
///
/// # Errores
///
/// Ver [`UnpadError`]: bloque más corto que el prefijo, o prefijo que declara
/// más de lo que hay. Ninguno de los dos puede darse sobre la salida de [`pad`].
pub fn unpad(padded: &[u8]) -> Result<&[u8], UnpadError> {
    if padded.len() < LEN_PREFIX {
        return Err(UnpadError::TooShort {
            got: padded.len(),
            need: LEN_PREFIX,
        });
    }
    let (cabecera, cuerpo) = padded.split_at(LEN_PREFIX);
    let declared = u64::from_be_bytes(cabecera.try_into().expect("LEN_PREFIX bytes"));
    // `usize::try_from` y no `as usize`: en un objetivo de 32 bits un `as`
    // truncaría el u64 y una longitud imposible pasaría por válida.
    let len = usize::try_from(declared).map_err(|_| UnpadError::InvalidLength {
        declared,
        available: cuerpo.len(),
    })?;
    cuerpo.get(..len).ok_or(UnpadError::InvalidLength {
        declared,
        available: cuerpo.len(),
    })
}

#[cfg(test)]
mod pruebas {
    extern crate std;
    use super::*;
    use proptest::prelude::*;
    use std::vec;

    #[test]
    fn va_y_vuelve() {
        for n in [0usize, 1, 7, 8, 9, 31, 32, 100, 1000, 5000] {
            let d: vec::Vec<u8> = (0..n).map(|i| (i * 31 + 7) as u8).collect();
            let p = pad(&d);
            assert!(p.len() >= LEN_PREFIX + n, "el marco encogió con {n} bytes");
            assert_eq!(unpad(&p).unwrap(), &d[..], "no volvió con {n} bytes");
        }
    }

    /// EL MOTIVO POR EL QUE ESTE CRATE EXISTE Y NO BASTA LA ARITMÉTICA.
    ///
    /// Un prefijo fabricado que declare más datos de los que hay es lo que en
    /// una implementación descuidada lee fuera del bloque. Se prueba en todo el
    /// rango, incluido `u64::MAX`, que en un objetivo de 32 bits truncaría si
    /// alguien usara `as usize` en vez de `try_from`.
    #[test]
    fn un_prefijo_hostil_no_lee_fuera_del_bloque() {
        let cuerpo = b"doce bytes..";
        for declarado in [13u64, 100, u32::MAX as u64, u64::MAX, u64::MAX - 1] {
            let mut malo = declarado.to_be_bytes().to_vec();
            malo.extend_from_slice(cuerpo);
            match unpad(&malo) {
                Err(UnpadError::InvalidLength { declared, available }) => {
                    assert_eq!(declared, declarado);
                    assert_eq!(available, cuerpo.len());
                }
                otro => panic!("un prefijo de {declarado} tenía que rechazarse, dio {otro:?}"),
            }
        }
        // Y el gemelo: un prefijo HONESTO sí pasa, o la regla rechazaría todo.
        let mut bueno = (cuerpo.len() as u64).to_be_bytes().to_vec();
        bueno.extend_from_slice(cuerpo);
        assert_eq!(unpad(&bueno).unwrap(), cuerpo);
    }

    #[test]
    fn un_bloque_mas_corto_que_el_prefijo_se_rechaza() {
        let ceros = [0u8; LEN_PREFIX];
        for n in 0..LEN_PREFIX {
            assert!(
                matches!(unpad(&ceros[..n]), Err(UnpadError::TooShort { .. })),
                "un bloque de {n} bytes tenía que rechazarse por corto"
            );
        }
        // El borde justo: ocho bytes que declaran cero datos es válido y vacío.
        assert_eq!(unpad(&[0u8; LEN_PREFIX]).unwrap(), b"");
    }

    /// La cifra que la documentación promete, comprobada en vez de citada.
    #[test]
    fn el_sobrecoste_se_mantiene_acotado() {
        let mut peor = 0.0f64;
        let mut peor_en = 0usize;
        for n in 1..20_000usize {
            let contenido = n + LEN_PREFIX;
            let ov = (padded_len(contenido) - contenido) as f64 / contenido as f64;
            if ov > peor {
                peor = ov;
                peor_en = n;
            }
        }
        assert!(
            peor < 0.13,
            "el sobrecoste llegó al {:.2}% con {peor_en} bytes; la documentación promete menos del 13%",
            peor * 100.0
        );
    }

    /// Padmé cuantiza: muchas longitudes distintas tienen que colapsar en la
    /// misma. Si no colapsaran, el relleno no serviría de nada — y esa es la
    /// mitad que una prueba de ida y vuelta no puede ver.
    #[test]
    fn muchas_longitudes_colapsan_en_pocos_tamanos() {
        use std::collections::HashSet;
        let observables: HashSet<usize> = (1..100_000usize).map(padded_len).collect();
        // MEDIDO, no supuesto: 99 999 longitudes colapsan en 189 tamaños. La
        // primera versión de esta prueba exigía «> 200» a ojo y falló — Padmé
        // colapsa MÁS de lo que yo había estimado, que es buena noticia y mala
        // prueba. Las cotas van holgadas alrededor del número real para que
        // detecten un cambio de comportamiento sin romperse por un byte.
        assert!(
            (150..250).contains(&observables.len()),
            "99 999 longitudes producen {} tamaños observables; se midieron 189. \
             Muchos más significa que dejó de cuantizar; muchos menos, que el \
             sobrecoste se disparó (lo cubre `el_sobrecoste_se_mantiene_acotado`)",
            observables.len()
        );
    }

    proptest! {
        #[test]
        fn va_y_vuelve_con_cualquier_dato(d in proptest::collection::vec(any::<u8>(), 0..2000)) {
            // `let` obligatorio: `unpad` PRESTA del bloque, así que el bloque
            // tiene que sobrevivir al préstamo. Que el compilador lo exija es
            // la ventaja de devolver un tramo en vez de una copia.
            let bloque = pad(&d);
            prop_assert_eq!(unpad(&bloque).unwrap(), &d[..]);
        }

        /// `unpad` NUNCA entra en pánico, venga lo que venga.
        #[test]
        fn unpad_no_entra_en_panico_con_nada(b in proptest::collection::vec(any::<u8>(), 0..500)) {
            let _ = unpad(&b);
        }

        #[test]
        fn padded_len_nunca_encoge(l in 0usize..1_000_000) {
            prop_assert!(padded_len(l) >= l);
        }
    }
}
