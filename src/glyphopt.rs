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
    let n = fingerprints.len();
    let k = k.min(n);
    if k == 0 {
        return Vec::new();
    }

    // Farthest-point incremental: `mind[c]` = distancia mínima del candidato `c`
    // al conjunto ya elegido. Se actualiza solo contra el último añadido -> O(k·n·m).
    let mut selected = vec![false; n];
    selected[0] = true;
    let mut chosen = vec![0usize];
    let mut mind: Vec<u32> = (0..n)
        .map(|i| hamming(&fingerprints[i], &fingerprints[0]))
        .collect();

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
