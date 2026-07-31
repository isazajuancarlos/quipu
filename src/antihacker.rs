// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

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

use std::collections::HashMap;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::cipher::NONCE_LEN;
use crate::container;

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

/// Busca reúso de nonce en un conjunto de contenedores de Quipu.
///
/// Devuelve los PARES `(primero, repetido)` de índices cuyos nonces coinciden —
/// no un booleano— porque quien lo corre necesita saber CUÁLES recifrar, y un
/// detector que solo dijera «hay un problema» sin señalar dónde se desactiva a
/// la semana.
///
/// # Por qué esto es una herramienta pública y no una prueba
///
/// Quipu **nunca** repite un nonce: cada uno sale del RNG del sistema en el
/// momento de cifrar. El riesgo no está en la librería sino en cómo la usa el
/// integrador —serializar mal, copiar un contenedor, restaurar un respaldo sobre
/// un cifrado nuevo—, y ese almacén Quipu no lo ve. Esta función le da al
/// integrador el detector para correrlo sobre su propio almacén (es la «vacuna»
/// que sí se abre, a diferencia del laboratorio ofensivo tras `feature = "lab"`).
///
/// # Por qué el reúso de nonce es grave y a la vez invisible
///
/// Con XChaCha20, dos mensajes bajo la misma clave y el mismo nonce comparten el
/// flujo de cifrado: su XOR entrega el XOR de los dos textos claros, **sin error
/// ni aviso**. No hay excepción que lo delate; por eso hace falta buscarlo a
/// propósito.
///
/// # Qué NO cuenta como colisión
///
/// Un blob que no parsea como contenedor de Quipu se **ignora**: no tiene nonce
/// que comparar. Se prefiere ignorarlo a inventar una colisión — un falso
/// positivo aquí manda a recifrar datos sanos.
///
/// Nonces distintos bajo claves distintas tampoco son colisión: el peligro es el
/// mismo nonce, y el nonce extendido de 192 bits hace la coincidencia por azar
/// despreciable, así que un par encontrado es casi con certeza un error de
/// manejo, no mala suerte.
pub fn nonces_repetidos(contenedores: &[impl AsRef<[u8]>]) -> Vec<(usize, usize)> {
    let mut visto: HashMap<[u8; NONCE_LEN], usize> = HashMap::new();
    let mut pares = Vec::new();
    for (i, c) in contenedores.iter().enumerate() {
        // Se parsea con el parser real del contenedor, no cortando bytes a mano:
        // así un blob ilegible cae en `Err` y se ignora, en vez de leerse un
        // «nonce» de una posición que no lo es.
        if let Ok((cabecera, _)) = container::parse(c.as_ref()) {
            match visto.get(&cabecera.nonce) {
                Some(&primero) => pares.push((primero, i)),
                None => {
                    visto.insert(cabecera.nonce, i);
                }
            }
        }
    }
    pares
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

    fn opciones_baratas() -> crate::api::Options<'static> {
        use crate::kdf::KdfParams;
        crate::api::Options {
            pepper: b"",
            // KDF barata: la prueba mira el nonce, no el coste.
            kdf_params: KdfParams { mem_kib: 64, iterations: 1, parallelism: 1 },
            ..Default::default()
        }
    }

    fn corpus_sano(n: usize) -> Vec<Vec<u8>> {
        use crate::api::encode_to_blob;
        let opts = opciones_baratas();
        (0..n)
            .map(|i| encode_to_blob(format!("mensaje {i}").as_bytes(), "clave", [0u8; 8], &opts))
            .collect()
    }

    #[test]
    fn nonces_repetidos_no_inventa_sobre_contenedores_sanos() {
        // Cada contenedor toma su nonce del RNG: no debe haber colisiones. Un
        // falso positivo aquí manda a recifrar datos intactos.
        let corpus = corpus_sano(16);
        assert!(
            nonces_repetidos(&corpus).is_empty(),
            "falsos positivos sobre 16 contenedores sanos"
        );
    }

    #[test]
    fn nonces_repetidos_encuentra_el_duplicado_sembrado() {
        // El escenario real: se restaura una copia de un contenedor ya cifrado.
        // Comparte nonce con el original y hay que detectarlo.
        let mut almacen = corpus_sano(8);
        let copia = almacen[3].clone();
        almacen.push(copia); // índice 8 == copia del 3
        let choques = nonces_repetidos(&almacen);
        assert_eq!(
            choques,
            vec![(3, 8)],
            "no encontró el nonce duplicado sembrado, o inventó pares: {choques:?}"
        );
    }

    #[test]
    fn nonces_repetidos_ignora_lo_que_no_es_contenedor() {
        // Un blob ilegible no tiene nonce que comparar: se ignora, no cuenta como
        // colisión ni revienta.
        let basura: Vec<Vec<u8>> = vec![b"no soy un contenedor".to_vec(), vec![0u8; 10], Vec::new()];
        assert!(
            nonces_repetidos(&basura).is_empty(),
            "un blob que no parsea no debe producir colisiones"
        );
    }
}
