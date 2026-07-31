// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Codec base-N: convierte una secuencia de bytes en una secuencia de índices
//! de símbolo (0..N) y viceversa, de forma totalmente reversible.
//!
//! El "valor binario" de un símbolo es su índice (codificación posicional): el
//! codebook (capa superior) solo traduce índice -> identidad de símbolo.
//!
//! Para preservar bytes cero a la izquierda y la entrada vacía, se antepone un
//! marcador 0x01 antes de interpretar los bytes como un entero grande.

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{ToPrimitive, Zero};

/// El mayor `k` tal que `n^k` cabe en un `u64`, junto con ese `n^k`.
///
/// Existe para no dividir el entero grande una vez POR DÍGITO. Cada división de
/// un número de `m` limbos cuesta O(m), y hay O(m) dígitos: sacarlos de uno en
/// uno hace el codificado CUADRÁTICO. Dividiendo por `n^k` se sacan `k` dígitos
/// por pasada —el resto cabe en un `u64` y se desmenuza con aritmética de
/// máquina, que no toca memoria—, así que el coste se divide por `k` (9 en la
/// base 94 por defecto). La salida es EXACTAMENTE la misma; solo cambia cuántas
/// veces se paga la división grande.
fn paso_maximo(n: u64) -> (u64, u32) {
    let mut paso = n;
    let mut k = 1;
    while let Some(p) = paso.checked_mul(n) {
        paso = p;
        k += 1;
    }
    (paso, k)
}

/// Codifica `data` a una secuencia de índices en base `n` (orden big-endian:
/// el dígito más significativo primero).
///
/// # Pánico
///
/// Con `n < 2`. Una base de 0 o 1 no representa nada, y la versión anterior de
/// esta función se quedaba dando vueltas para siempre en vez de decirlo
/// (directiva 20: ante un dato imposible, fallar de forma ruidosa).
pub fn encode_base_n(data: &[u8], n: u32) -> Vec<u32> {
    assert!(n >= 2, "una base de {n} no codifica nada: se exige n >= 2");

    // Marcador 0x01 al frente: preserva ceros a la izquierda y la entrada vacía.
    let mut buf = Vec::with_capacity(data.len() + 1);
    buf.push(1u8);
    buf.extend_from_slice(data);

    let n = u64::from(n);
    let (paso, k) = paso_maximo(n);
    let paso_grande = BigUint::from(paso);

    let mut value = BigUint::from_bytes_be(&buf);
    let mut digits = Vec::new();
    while value >= paso_grande {
        let (cociente, resto) = value.div_rem(&paso_grande);
        // `k` dígitos COMPLETOS: aquí los ceros de relleno sí van, porque
        // llevan detrás un bloque más significativo.
        let mut resto = resto.to_u64().expect("el resto es menor que n^k, que cabe en u64");
        for _ in 0..k {
            digits.push((resto % n) as u32);
            resto /= n;
        }
        value = cociente;
    }
    // El bloque más significativo, este sí sin ceros a la izquierda.
    let mut resto = value.to_u64().expect("value < n^k, que cabe en u64");
    while !resto.is_zero() {
        digits.push((resto % n) as u32);
        resto /= n;
    }

    digits.reverse(); // little-endian -> big-endian
    digits
}

/// Operación inversa de [`encode_base_n`].
pub fn decode_base_n(indices: &[u32], n: u32) -> Vec<u8> {
    let base = BigUint::from(n);
    let mut value = BigUint::zero();
    for &d in indices {
        value = value * &base + BigUint::from(d);
    }
    let bytes = value.to_bytes_be();
    // Quita el marcador 0x01 inicial.
    bytes[1..].to_vec()
}

// ===========================================================================
// CODIFICACIÓN POR GRUPOS, PARA QUE EL DAÑO SEA LOCAL
// ===========================================================================
//
// `encode_base_n` convierte el mensaje entero como UN número. Eso no tiene
// localidad: un glifo mal leído no cambia un byte, cambia el número y con él
// todos los bytes que siguen. Reed-Solomon corrige errores dispersos, así que
// detrás de esa transformación no puede hacer nada — medido el 2026-07-26: el
// canal protegido no aguantaba ni un glifo dañado.
//
// Aquí el mapeo es local y de tamaño fijo:
//
//     3 bytes  <->  4 glifos      94^4 = 78 074 896  >=  2^24 = 16 777 216
//
// Un glifo dañado corrompe EXACTAMENTE 3 bytes, que es lo que el corrector
// espera. Y como solo el 21,5 % del espacio de 4 glifos corresponde a un valor
// de 3 bytes, el 78,5 % de las corrupciones se detecta aquí mismo: el grupo da
// un valor imposible. Ese detector local es lo que compra el 8,4 % de densidad
// que la proporción 3:4 no aprovecha.

/// Bytes por grupo.
pub const GRUPO_BYTES: usize = 3;
/// Glifos por grupo.
pub const GRUPO_DIGITOS: usize = 4;

/// Codifica en grupos de 3 bytes -> 4 dígitos base `n`.
///
/// Rellena con ceros hasta un múltiplo de 3. El relleno es inofensivo: quien
/// llama —`ecc::recover`— conoce la longitud real por su propia cabecera y
/// descarta la cola.
pub fn encode_grupos(data: &[u8], n: u32) -> Vec<u32> {
    let base = n as u64;
    let mut out = Vec::with_capacity(data.len().div_ceil(GRUPO_BYTES) * GRUPO_DIGITOS);
    for trozo in data.chunks(GRUPO_BYTES) {
        let mut v = 0u64;
        for i in 0..GRUPO_BYTES {
            v = (v << 8) | *trozo.get(i).unwrap_or(&0) as u64;
        }
        let mut digitos = [0u32; GRUPO_DIGITOS];
        for d in digitos.iter_mut().rev() {
            *d = (v % base) as u32;
            v /= base;
        }
        out.extend_from_slice(&digitos);
    }
    out
}

/// Operación inversa. Devuelve también qué grupos vinieron corruptos.
///
/// Un grupo cuyo valor no cabe en 3 bytes es imposible: no lo produjo
/// `encode_grupos`. Se devuelve como ceros y se anota su posición, para que el
/// corrector sepa dónde mirar en vez de tratarlo como dato bueno.
pub fn decode_grupos(indices: &[Option<u32>], n: u32) -> (Vec<u8>, Vec<usize>) {
    let base = n as u64;
    let mut out = Vec::with_capacity(indices.len() / GRUPO_DIGITOS * GRUPO_BYTES);
    let mut corruptos = Vec::new();

    for (g, grupo) in indices.chunks(GRUPO_DIGITOS).enumerate() {
        if grupo.len() < GRUPO_DIGITOS {
            // Cola incompleta: no la produjo el codificador. Se descarta en vez
            // de rellenarla, que sería inventar bytes.
            corruptos.push(g);
            break;
        }
        // Una posición ilegible contamina su grupo entero: no se puede
        // reconstruir el valor sin ella. Se marca y Reed-Solomon lo repara.
        if grupo.iter().any(|d| d.is_none()) {
            corruptos.push(g);
            out.extend_from_slice(&[0u8; GRUPO_BYTES]);
            continue;
        }
        let mut v = 0u64;
        for d in grupo.iter().flatten() {
            // Un índice fuera del alfabeto solo puede venir de una lectura
            // rota. Se satura para no desbordar y el grupo cae como corrupto.
            v = v.saturating_mul(base).saturating_add((*d).min(n - 1) as u64);
        }
        if v > 0x00FF_FFFF {
            corruptos.push(g);
            out.extend_from_slice(&[0u8; GRUPO_BYTES]);
            continue;
        }
        out.push((v >> 16) as u8);
        out.push((v >> 8) as u8);
        out.push(v as u8);
    }
    (out, corruptos)
}


#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn round_trips_simple_bytes() {
        let data = b"hello";
        let encoded = encode_base_n(data, 94);
        let decoded = decode_base_n(&encoded, 94);
        assert_eq!(decoded, data);
    }

    #[test]
    fn round_trips_empty_input() {
        let data = b"";
        let encoded = encode_base_n(data, 94);
        let decoded = decode_base_n(&encoded, 94);
        assert_eq!(decoded, data);
    }

    #[test]
    fn round_trips_leading_zero_bytes() {
        // El marcador 0x01 debe preservar los ceros a la izquierda.
        let data = &[0u8, 0, 0, 42];
        let encoded = encode_base_n(data, 94);
        let decoded = decode_base_n(&encoded, 94);
        assert_eq!(decoded, data);
    }

    proptest! {
        #[test]
        fn round_trips_any_bytes_any_base(
            data in proptest::collection::vec(any::<u8>(), 0..256),
            n in 2u32..=4096,
        ) {
            let encoded = encode_base_n(&data, n);
            // Todo índice debe estar en el rango [0, n).
            prop_assert!(encoded.iter().all(|&d| d < n));
            let decoded = decode_base_n(&encoded, n);
            prop_assert_eq!(decoded, data);
        }
    }

    // =======================================================================
    // QUE LA SALIDA NO CAMBIE
    // =======================================================================
    //
    // Las pruebas de ida y vuelta de arriba NO bastan para proteger el formato:
    // pasan igual si se cambia la codificación entera, mientras siga siendo
    // consistente consigo misma. Y este formato es el de un artefacto FIRMADO
    // que ya está guardado en bases de datos de clientes: cambiarlo invalida
    // firmas emitidas. Lo que sigue lo fija de dos maneras independientes.

    /// La implementación ingenua —un dígito por división— tal como estuvo hasta
    /// el 2026-07-31. Es la DEFINICIÓN del formato; la versión rápida solo puede
    /// diferir en el tiempo que tarda.
    fn encode_base_n_ingenuo(data: &[u8], n: u32) -> Vec<u32> {
        let mut buf = Vec::with_capacity(data.len() + 1);
        buf.push(1u8);
        buf.extend_from_slice(data);

        let base = BigUint::from(n);
        let mut value = BigUint::from_bytes_be(&buf);
        let mut digits = Vec::new();
        while !value.is_zero() {
            let rem = &value % &base;
            digits.push(rem.to_u32().expect("rem < n cabe en u32"));
            value /= &base;
        }
        digits.reverse();
        digits
    }

    proptest! {
        /// La versión rápida produce EXACTAMENTE los mismos dígitos que la
        /// ingenua, para cualquier entrada y cualquier base.
        #[test]
        fn la_version_rapida_da_los_mismos_digitos_que_la_ingenua(
            data in proptest::collection::vec(any::<u8>(), 0..512),
            n in 2u32..=4096,
        ) {
            prop_assert_eq!(encode_base_n(&data, n), encode_base_n_ingenuo(&data, n));
        }
    }

    /// Vectores tomados de la implementación ingenua ANTES de acelerarla. Si el
    /// oráculo de arriba se tocara alguna vez, estos siguen sujetando el formato.
    #[test]
    fn los_vectores_de_referencia_no_se_mueven() {
        assert_eq!(encode_base_n(b"quipu", 94), vec![2, 28, 20, 22, 35, 86, 69]);
        assert_eq!(encode_base_n(&[0u8, 0, 0, 42], 94), vec![55, 1, 1, 91, 84]);
        assert_eq!(encode_base_n(b"", 94), vec![1]);
        assert_eq!(encode_base_n(&[255u8; 8], 2), vec![1; 65]);
        assert_eq!(encode_base_n(&[1u8, 2, 3], 4096), vec![1, 16, 515]);

        // Un caso largo, donde el paso por bloques sí entra en juego (79 dígitos
        // = 8 bloques de 9 más un bloque parcial de 7).
        let largo: Vec<u8> = (0..64).map(|i| (i * 7 % 251) as u8).collect();
        let e = encode_base_n(&largo, 94);
        assert_eq!(e.len(), 79);
        assert_eq!(&e[..8], &[1, 63, 22, 42, 28, 2, 71, 12]);
        assert_eq!(&e[e.len() - 8..], &[18, 6, 42, 45, 73, 30, 87, 12]);
        assert_eq!(e.iter().map(|&d| u64::from(d)).sum::<u64>(), 3530);
    }

    /// El bloque más significativo NO lleva ceros de relleno, pero los bloques
    /// interiores SÍ. Es el único sitio donde el paso por bloques puede
    /// desviarse del dígito a dígito, así que se prueba a propósito: se buscan
    /// entradas cuyo dígito más significativo caiga justo en un cambio de bloque.
    #[test]
    fn los_ceros_de_relleno_van_dentro_pero_no_delante() {
        for largo in 1..40usize {
            let data = vec![0u8; largo];
            let rapido = encode_base_n(&data, 94);
            assert_eq!(rapido, encode_base_n_ingenuo(&data, 94), "con {largo} ceros");
            assert_ne!(rapido[0], 0, "el dígito más significativo nunca es cero ({largo} ceros)");
        }
    }

    #[test]
    #[should_panic(expected = "no codifica nada")]
    fn una_base_de_uno_falla_en_vez_de_colgarse() {
        // Antes esto se quedaba dando vueltas para siempre: value % 1 == 0 y
        // value / 1 == value, así que el bucle no terminaba nunca.
        encode_base_n(b"lo que sea", 1);
    }
}

