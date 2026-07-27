// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Optimización de alfabetos de glifos por separabilidad (la base algorítmica
//! de los "glifos por IA").
//!
//! Un modelo generativo (difusión/GAN) produciría MUCHOS glifos candidatos;
//! este módulo elige el subconjunto cuya distancia mínima entre pares es máxima
//! (problema de empaquetamiento / max-min diversity). Trabaja sobre "huellas"
//! de glifo: vectores de bytes (p. ej. un bitmap reducido del glifo).
//!
//! Mayor distancia mínima => menos confusiones bajo ruido => alfabeto más robusto.

/// Distancia de Hamming entre dos huellas de igual longitud.
pub fn hamming(a: &[u8], b: &[u8]) -> u32 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .sum()
}

/// Distancia mínima entre cualquier par de huellas (la métrica de separabilidad).
pub fn min_pairwise_distance(fingerprints: &[Vec<u8>]) -> u32 {
    let mut min = u32::MAX;
    for i in 0..fingerprints.len() {
        for j in (i + 1)..fingerprints.len() {
            min = min.min(hamming(&fingerprints[i], &fingerprints[j]));
        }
    }
    if min == u32::MAX { 0 } else { min }
}

/// Selecciona `k` huellas maximizando (greedy) la distancia mínima entre las
/// elegidas (farthest-point sampling). Devuelve los índices seleccionados.
pub fn select_separable_subset(fingerprints: &[Vec<u8>], k: usize) -> Vec<usize> {
    select_separable_subset_seeded(fingerprints, k, &[])
}

/// Como [`select_separable_subset`], pero además se aparta de `evitar`.
///
/// `evitar` son huellas que NO forman parte del alfabeto y de las que sin
/// embargo hay que mantenerse lejos. Existe por un caso concreto y muy común:
/// una hoja en blanco es una huella de ceros, y si el alfabeto contiene un
/// glifo con poca tinta, el papel vacío cae dentro de su radio de
/// decodificación y se lee como un mensaje. Lo mismo un borrón, que es unos.
///
/// La alternativa era endurecer el umbral del lector, y habría sido tapar con
/// un mecanismo lo que otro dejó mal: el umbral estaba bien calculado; lo que
/// estaba mal era admitir en el alfabeto un símbolo que se parece a la nada.
///
/// Es la misma idea que la restricción de complejidad de AprilTag —descartar
/// palabras de código que la textura natural imita—, aplicada al caso que este
/// canal encuentra siempre: papel.
pub fn select_separable_subset_seeded(
    fingerprints: &[Vec<u8>],
    k: usize,
    evitar: &[Vec<u8>],
) -> Vec<usize> {
    let n = fingerprints.len();
    let k = k.min(n);
    if k == 0 {
        return Vec::new();
    }

    // Farthest-point incremental: `mind[c]` = distancia mínima del candidato `c`
    // al conjunto ya elegido. Se actualiza solo contra el último añadido -> O(k·n·m).
    let mut mind: Vec<u32> = vec![u32::MAX; n];
    for e in evitar {
        for (i, fp) in fingerprints.iter().enumerate() {
            mind[i] = mind[i].min(hamming(fp, e));
        }
    }

    // La primera elección: con `evitar`, el candidato MÁS lejano de lo que hay
    // que rehuir; sin él, el primero, como siempre.
    let primero = if evitar.is_empty() {
        0
    } else {
        (0..n).max_by_key(|&i| mind[i]).unwrap_or(0)
    };

    let mut selected = vec![false; n];
    selected[primero] = true;
    let mut chosen = vec![primero];
    for (i, fp) in fingerprints.iter().enumerate() {
        mind[i] = mind[i].min(hamming(fp, &fingerprints[primero]));
    }

    while chosen.len() < k {
        // Candidato no elegido con mayor distancia al conjunto.
        let mut best = None;
        let mut best_dist = 0u32;
        for (c, &sel) in selected.iter().enumerate() {
            if sel {
                continue;
            }
            if best.is_none() || mind[c] > best_dist {
                best = Some(c);
                best_dist = mind[c];
            }
        }
        let Some(b) = best else { break };
        selected[b] = true;
        chosen.push(b);
        // Actualiza las distancias mínimas contra el recién añadido.
        for (c, &sel) in selected.iter().enumerate() {
            if !sel {
                let d = hamming(&fingerprints[c], &fingerprints[b]);
                if d < mind[c] {
                    mind[c] = d;
                }
            }
        }
    }
    chosen
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hamming_counts_differing_bits() {
        assert_eq!(hamming(&[0b0000_0000], &[0b0000_0000]), 0);
        assert_eq!(hamming(&[0b0000_1111], &[0b0000_0000]), 4);
        assert_eq!(hamming(&[0xFF, 0x00], &[0x00, 0x00]), 8);
    }

    #[test]
    fn min_pairwise_distance_finds_closest_pair() {
        let fps = vec![
            vec![0b0000_0000u8],
            vec![0b0000_0001u8], // a 1 del primero
            vec![0b1111_1111u8],
        ];
        assert_eq!(min_pairwise_distance(&fps), 1);
    }

    #[test]
    fn selects_the_most_separable_subset() {
        // A y A' son casi idénticos; un subconjunto bueno los evita.
        let fps = vec![
            vec![0b0000_0000u8], // A
            vec![0b0000_0001u8], // A' (casi dup de A)
            vec![0b1111_1111u8], // B
            vec![0b0000_1111u8], // C
        ];
        let chosen = select_separable_subset(&fps, 2);
        assert_eq!(chosen.len(), 2);
        let subset: Vec<Vec<u8>> = chosen.iter().map(|&i| fps[i].clone()).collect();
        // El subconjunto elegido debe ser mucho más separable que [A, A'].
        assert!(min_pairwise_distance(&subset) >= 4);
    }
}
