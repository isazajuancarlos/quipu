// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Custodia del *seed* VOPRF por umbral (Shamir k-de-n).
//!
//! # Por qué existe
//!
//! El seed es **el único dato irreversible del servicio**. Todo lo demás se
//! reconstruye: la base de datos se reemite, el token de admin se regenera, el
//! proceso se reinicia. El seed no — y perderlo no significa «reemitir keys»,
//! significa que lo que los clientes derivaron **no vuelve**, porque
//! `decode_online` consulta al servidor igual que `encode_online`.
//!
//! Guardar una copia entera en otro sitio cambia un punto único de FALLO por
//! dos puntos únicos de COMPROMISO. Shamir k-de-n evita las dos cosas: hacen
//! falta `k` comparticiones para reconstruir, y `k-1` no revelan **nada** —no
//! «casi nada»: nada, es la propiedad de seguridad perfecta del esquema—.
//!
//! # El criterio de una restauración correcta
//!
//! No es «el fichero se recuperó». Es que **la clave pública derivada sea
//! idéntica a la que el servicio venía publicando**. Un seed que se restaura
//! íntegro pero produce otra clave pública es indistinguible de haberlo
//! perdido, y es peor: el servicio arranca y responde 200 mientras invalida a
//! todo el mundo. Por eso [`verificar_restauracion`] compara claves públicas y
//! no bytes de seed.
//!
//! # Qué NO hace este módulo
//!
//! No toca disco ni red, y **nunca imprime el seed ni las comparticiones**. Es
//! deliberado: quien las escribe decide dónde van y con qué protección. La
//! herramienta que las mueve es el operador, no este código.

use quipu::shamir::{self, Share, ShamirError};
use zeroize::Zeroizing;

use crate::DERIVE_INFO;

/// Longitud del seed VOPRF, en bytes. 64 dígitos hex.
pub const SEED_LEN: usize = 32;

/// Qué puede salir mal al custodiar o restaurar.
#[derive(Debug, PartialEq, Eq)]
pub enum CustodiaError {
    /// El seed no mide [`SEED_LEN`] bytes.
    SeedLongitudInvalida { esperado: usize, recibido: usize },
    /// Parámetros de reparto imposibles (umbral 0, o más umbral que partes).
    Parametros,
    /// Las comparticiones no reconstruyen (faltan, o vienen de repartos
    /// distintos).
    Reconstruccion(ShamirError),
    /// Se reconstruyó algo, pero no deriva la clave pública esperada.
    ///
    /// Es el caso que importa: el resultado PARECE bueno y no lo es.
    ClavePublicaDistinta,
    /// `DeriveKeyPair` falló con ese material.
    Derivacion,
}

impl std::fmt::Display for CustodiaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SeedLongitudInvalida { esperado, recibido } => write!(
                f,
                "el seed debe medir {esperado} bytes ({} dígitos hex); recibidos {recibido}",
                esperado * 2
            ),
            Self::Parametros => write!(f, "parámetros de reparto inválidos"),
            Self::Reconstruccion(e) => write!(f, "no se pudo reconstruir: {e:?}"),
            Self::ClavePublicaDistinta => write!(
                f,
                "se reconstruyó un seed, pero deriva OTRA clave pública: \
                 restaurarlo invalidaría todo lo que los clientes derivaron"
            ),
            Self::Derivacion => write!(f, "DeriveKeyPair falló con ese seed"),
        }
    }
}

impl std::error::Error for CustodiaError {}

/// Clave pública que un seed produce para este servicio.
///
/// Es la huella con la que se verifica una restauración, y **no es secreta**:
/// el servidor la publica para que los clientes la fijen.
pub fn clave_publica_de(seed: &[u8]) -> Result<[u8; 32], CustodiaError> {
    if seed.len() != SEED_LEN {
        return Err(CustodiaError::SeedLongitudInvalida {
            esperado: SEED_LEN,
            recibido: seed.len(),
        });
    }
    quipu::voprf::Server::from_seed(seed, DERIVE_INFO)
        .map(|s| s.public_key())
        .ok_or(CustodiaError::Derivacion)
}

/// Reparte el seed en `partes` comparticiones, de las que hacen falta `umbral`.
///
/// No decide por ti el reparto: 2-de-3 y 3-de-5 son los que tienen sentido para
/// una persona sola con varios sitios de custodia. Un umbral de 1 lo rechaza
/// Shamir, y está bien que lo haga — sería una copia entera con pasos extra.
pub fn repartir(seed: &[u8], umbral: u8, partes: u8) -> Result<Vec<Share>, CustodiaError> {
    if seed.len() != SEED_LEN {
        return Err(CustodiaError::SeedLongitudInvalida {
            esperado: SEED_LEN,
            recibido: seed.len(),
        });
    }
    shamir::split(seed, umbral, partes).map_err(|e| match e {
        ShamirError::BadParameters => CustodiaError::Parametros,
        otro => CustodiaError::Reconstruccion(otro),
    })
}

/// Reconstruye el seed desde `k` comparticiones. No verifica nada por sí sola:
/// para eso está [`verificar_restauracion`], que es la que hay que usar.
pub fn reconstruir(partes: &[Share]) -> Result<Zeroizing<Vec<u8>>, CustodiaError> {
    shamir::combine(partes).map_err(CustodiaError::Reconstruccion)
}

/// **La función que convierte un respaldo en un respaldo probado.**
///
/// Reconstruye desde las comparticiones y exige que la clave pública resultante
/// sea `esperada`. Devuelve el seed solo si coincide.
///
/// Un respaldo que nadie ha restaurado no es un respaldo, y comprobar que «el
/// fichero está ahí» no prueba nada: lo que hay que probar es que el servicio
/// levantado con él sigue siendo el MISMO servicio para sus clientes.
pub fn verificar_restauracion(
    partes: &[Share],
    esperada: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, CustodiaError> {
    let seed = reconstruir(partes)?;
    let obtenida = clave_publica_de(&seed)?;
    // Comparación en tiempo constante no hace falta: la clave pública no es
    // secreta y ambos lados los tiene ya quien ejecuta esto.
    if &obtenida != esperada {
        return Err(CustodiaError::ClavePublicaDistinta);
    }
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_de_prueba() -> [u8; SEED_LEN] {
        // Determinista y evidentemente falso: nunca un seed real en el código.
        let mut s = [0u8; SEED_LEN];
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        s
    }

    #[test]
    fn el_ciclo_completo_devuelve_la_misma_clave_publica() {
        let seed = seed_de_prueba();
        let esperada = clave_publica_de(&seed).unwrap();

        let partes = repartir(&seed, 2, 3).unwrap();
        assert_eq!(partes.len(), 3);

        // Cualquier par de las tres reconstruye: es la propiedad que hace útil
        // el reparto, y se comprueba en las TRES combinaciones, no en una.
        for (a, b) in [(0, 1), (0, 2), (1, 2)] {
            let subconjunto = [partes[a].clone(), partes[b].clone()];
            let seed2 = verificar_restauracion(&subconjunto, &esperada).unwrap();
            assert_eq!(&seed2[..], &seed[..], "par ({a},{b}) no reconstruyó el seed");
        }
    }

    #[test]
    fn con_menos_del_umbral_no_se_reconstruye() {
        let seed = seed_de_prueba();
        let esperada = clave_publica_de(&seed).unwrap();
        let partes = repartir(&seed, 3, 5).unwrap();

        // Dos de cinco con umbral tres: tiene que negarse, no aproximarse.
        let dos = [partes[0].clone(), partes[1].clone()];
        assert!(matches!(
            verificar_restauracion(&dos, &esperada),
            Err(CustodiaError::Reconstruccion(_))
        ));
    }

    /// LA PRUEBA QUE DA VALOR A TODO LO DEMÁS.
    ///
    /// Un seed distinto se reconstruye perfectamente y produce otra clave
    /// pública. Si `verificar_restauracion` no lo cazara, el procedimiento
    /// entero sería teatro: diría «restaurado» ante el material equivocado.
    #[test]
    fn un_seed_ajeno_se_reconstruye_pero_no_pasa_la_verificacion() {
        let seed = seed_de_prueba();
        let esperada = clave_publica_de(&seed).unwrap();

        let mut otro = seed_de_prueba();
        otro[0] ^= 0x01; // un solo bit
        let partes_ajenas = repartir(&otro, 2, 3).unwrap();

        // Reconstruir SÍ funciona: el reparto es válido, el secreto es otro.
        let reconstruido = reconstruir(&partes_ajenas).unwrap();
        assert_eq!(&reconstruido[..], &otro[..]);

        // Y la verificación lo rechaza, que es lo único que importa.
        assert_eq!(
            verificar_restauracion(&partes_ajenas, &esperada),
            Err(CustodiaError::ClavePublicaDistinta)
        );
    }

    #[test]
    fn las_comparticiones_sobreviven_a_ir_y_volver_de_bytes() {
        // Es como viajan de verdad: a un papel, a un gestor de contraseñas, a
        // un sobre. Si el ida y vuelta perdiera un byte, el respaldo fallaría
        // el día que hace falta y no antes.
        let seed = seed_de_prueba();
        let esperada = clave_publica_de(&seed).unwrap();
        let partes = repartir(&seed, 2, 3).unwrap();

        let serializadas: Vec<Vec<u8>> = partes.iter().map(|p| p.to_bytes().to_vec()).collect();
        let devueltas: Vec<Share> = serializadas
            .iter()
            .map(|b| Share::from_bytes(b).unwrap())
            .collect();

        verificar_restauracion(&devueltas[0..2], &esperada).unwrap();
    }

    #[test]
    fn un_seed_de_longitud_equivocada_se_rechaza_antes_de_repartir() {
        assert!(matches!(
            repartir(&[0u8; 31], 2, 3),
            Err(CustodiaError::SeedLongitudInvalida {
                esperado: 32,
                recibido: 31
            })
        ));
    }
}
