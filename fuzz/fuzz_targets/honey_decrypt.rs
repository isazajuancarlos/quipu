#![no_main]
//! Fuzz del parser honey: bytes arbitrarios nunca deben provocar panic ni
//! asignar memoria sin cota. Solo puede salir `Ok(señuelo)` o un error
//! estructural.
//!
//! `honey::decrypt` deriva la clave con Argon2id usando los parámetros del
//! contenedor. Para que el fuzzing mida el PARSER y no el coste del KDF, si la
//! entrada tiene forma de contenedor honey le fijamos parámetros baratos; el
//! camino de parámetros absurdos (`is_sane`) ya lo cubre el lab.

use libfuzzer_sys::fuzz_target;
use quipu::honey;

fuzz_target!(|data: &[u8]| {
    let mut v = data.to_vec();
    // Disposición: magic(4) ver(1) salt(16) | mem(4) iter(4) par(4) ...
    let off = 5 + 16;
    if v.len() >= off + 12 && &v[0..4] == b"QHNY" {
        v[off..off + 4].copy_from_slice(&64u32.to_be_bytes()); // mem_kib barato
        v[off + 4..off + 8].copy_from_slice(&1u32.to_be_bytes()); // iterations
        v[off + 8..off + 12].copy_from_slice(&1u32.to_be_bytes()); // parallelism
    }
    let _ = honey::decrypt(&v, "clave-fuzz", b"");
});
