// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! La extracción de Padmé a este crate NO cambió el formato.
//!
//! # Por qué hace falta esta prueba, si ya hay una del envoltorio
//!
//! `quipu_nucleo::prelayers` conserva una prueba de ida y vuelta tras la
//! extracción, y esa prueba **saldría verde igual si el algoritmo hubiera
//! cambiado**: `pad` y `unpad` son consistentes entre sí por construcción, así
//! que se comprueban el uno al otro y nunca al formato. Lo que hay que demostrar
//! es otra cosa —que lo que produce este crate es byte a byte lo que producía
//! `quipu-nucleo 0.1.1`—, y para eso hace falta un segundo testigo que no
//! dependa del primero.
//!
//! Ese testigo es una **copia literal** del código publicado en la 0.1.1,
//! transcrita de `origin/estable:crates/quipu-nucleo/src/prelayers.rs`. Se
//! congela aquí a propósito: si alguien toca `padded_len` creyendo que solo
//! reordena una expresión, esto se pone rojo.
//!
//! Padmé no es una comprobación de corrección sino de PRIVACIDAD —cuantiza la
//! longitud para que el tamaño del ciphertext filtre lo mínimo—, y por eso una
//! divergencia no rompería nada visible: los datos seguirían abriéndose, y solo
//! cambiaría cuánto filtra el tamaño. Un fallo que no se cae es el que hay que
//! atar con una prueba.
//!
//! Comprobado que DISCRIMINA (2026-08-02): con `last_bits` alterado en un solo
//! `saturating_sub(1)`, los dos primeros casos se ponen rojos en `l=9`.

/// Copia LITERAL de `padme()` tal como estaba en
/// `crates/quipu-nucleo/src/prelayers.rs` en origin/estable (0.1.1).
fn padme_0_1_1(l: usize) -> usize {
    if l < 2 {
        return l;
    }
    let e = (usize::BITS - 1 - l.leading_zeros()) as usize;
    let s = (usize::BITS - e.leading_zeros()) as usize;
    let last_bits = e.saturating_sub(s);
    let mask = (1usize << last_bits) - 1;
    (l + mask) & !mask
}

/// Copia LITERAL de `pad()` de 0.1.1.
fn pad_0_1_1(data: &[u8]) -> Vec<u8> {
    const LEN_PREFIX: usize = 8;
    let content_len = LEN_PREFIX + data.len();
    let target = padme_0_1_1(content_len);
    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(&(data.len() as u64).to_be_bytes());
    out.extend_from_slice(data);
    out.resize(target, 0);
    out
}

#[test]
fn padded_len_identico_al_de_0_1_1() {
    for l in 0usize..200_000 {
        assert_eq!(
            padme_frame::padded_len(l),
            padme_0_1_1(l),
            "padded_len divergió en l={l}"
        );
    }
}

#[test]
fn el_bloque_sale_byte_a_byte_igual_al_de_0_1_1() {
    for n in 0usize..4_000 {
        let d: Vec<u8> = (0..n).map(|i| (i * 31 + 7) as u8).collect();
        assert_eq!(padme_frame::pad(&d), pad_0_1_1(&d), "el bloque divergió con {n} bytes");
    }
}

#[test]
fn lo_que_empaquetó_0_1_1_lo_abre_el_crate_nuevo() {
    for n in [0usize, 1, 7, 8, 9, 63, 255, 1000, 3999] {
        let d: Vec<u8> = (0..n).map(|i| (i * 17 + 3) as u8).collect();
        assert_eq!(padme_frame::unpad(&pad_0_1_1(&d)).unwrap(), &d[..], "no abrió con {n}");
    }
}
