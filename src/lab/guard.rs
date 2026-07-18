// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Candado de TAMPER-EVIDENCE: verifica que las defensas antihacker siguen
//! PRESENTES y EFECTIVAS. Si alguien borra o debilita `ct_eq`, la validación de
//! parámetros KDF o `wipe`, estos meta-tests fallan (CI en rojo). Las defensas no
//! se pueden apagar en silencio.

use crate::antihacker::{ct_eq, wipe};
use crate::kdf::KdfParams;

/// La comparación en tiempo constante sigue distinguiendo iguales de distintos y
/// no acepta longitudes distintas.
pub fn guard_ct_eq() -> bool {
    ct_eq(b"clave-secreta", b"clave-secreta")
        && !ct_eq(b"clave-secreta", b"clave-secretX")
        && !ct_eq(b"corta", b"mas-larga")
}

/// La validación de parámetros KDF sigue bloqueando parámetros maliciosos
/// (regresión del DoS por agotamiento de memoria de Argon2) y admite los sanos.
pub fn guard_kdf_validation() -> bool {
    let sane = KdfParams::default().is_sane();
    let malicious = KdfParams {
        mem_kib: u32::MAX,
        iterations: u32::MAX,
        parallelism: u32::MAX,
    };
    sane && !malicious.is_sane()
}

/// El borrado de memoria sigue dejando el buffer en ceros.
pub fn guard_wipe() -> bool {
    let mut buf = [0xAAu8; 32];
    wipe(&mut buf);
    buf.iter().all(|&b| b == 0)
}

/// `true` si TODAS las defensas siguen intactas y efectivas.
pub fn all_defenses_intact() -> bool {
    guard_ct_eq() && guard_kdf_validation() && guard_wipe()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_still_discriminates() {
        assert!(guard_ct_eq());
    }

    #[test]
    fn kdf_validation_still_rejects_malicious_params() {
        assert!(guard_kdf_validation());
    }

    #[test]
    fn wipe_still_zeroes_memory() {
        assert!(guard_wipe());
    }

    #[test]
    fn all_defenses_report_intact() {
        assert!(all_defenses_intact());
    }
}
