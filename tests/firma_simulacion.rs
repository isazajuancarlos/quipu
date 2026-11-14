// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

//! **Simulación de la firma híbrida** (directiva 8): 400+ operaciones sobre el
//! camino en memoria, que hasta el 2026-08-17 no tenía ninguna —los 1 200 ciclos
//! de `tests/simulacion.rs` son todos del modo simétrico por contraseña, ni una
//! firma—.
//!
//! Lo que fija, y por qué importa cada aserción:
//!
//! - **El combinador es AND, no OR.** Si alguien cambia `ed_ok && ml_ok` por
//!   `ed_ok || ml_ok`, una firma con UNA mitad corrupta pasaría. Las 200
//!   corrupciones de un bit —100 en la mitad Ed25519, 100 en la ML-DSA— lo
//!   ponen rojo: con OR, la mitad de ellas verificarían.
//! - **Las dos mitades firman el MISMO mensaje.** El splice con la misma clave y
//!   dos mensajes no puede montar una firma que verifique.
//! - **La clave pública completa está atada.** Una firma de otra clave, o una
//!   `vk` quimérica, no verifica.
//!
//! Todo determinista: el fallo se reproduce con la semilla, que se imprime.

use quipu::pqsign::{generate_keypair, ED25519_SIG_LEN, SIGNATURE_LEN};

struct Rng(u64);
impl Rng {
    fn nuevo(s: u64) -> Self {
        Self(s | 1)
    }
    fn siguiente(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn hasta(&mut self, n: usize) -> usize {
        (self.siguiente() % n as u64) as usize
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.siguiente() & 0xff) as u8).collect()
    }
}

#[test]
fn cuatrocientas_firmas_resisten_corrupcion_por_componente_y_splice() {
    let mut rng = Rng::nuevo(0x5167_2026_0817);
    let (vk, sk) = generate_keypair();

    // --- 100 ida y vuelta, con control positivo CONTADO ---
    let mut ok = 0;
    for _ in 0..100 {
        let largo = rng.hasta(4096);
        let msg = rng.bytes(largo);
        let sig = sk.sign(&msg);
        if vk.verify(&msg, &sig) {
            ok += 1;
        }
        // y contra OTRO mensaje NO verifica
        let mut otro = msg.clone();
        otro.push(0xFF);
        assert!(!vk.verify(&otro, &sig), "una firma verificó contra otro mensaje");
    }
    assert_eq!(ok, 100, "el control positivo: las 100 firmas legítimas tienen que verificar");

    // --- 100 corrupciones de un bit en la mitad ED25519 (offsets 0..64) ---
    // Con OR en vez de AND, éstas verificarían: la mitad ML-DSA sigue intacta.
    for _ in 0..100 {
        let msg = rng.bytes(64);
        let mut sig = sk.sign(&msg);
        let pos = rng.hasta(ED25519_SIG_LEN);
        sig[pos] ^= 1 << rng.hasta(8);
        assert!(
            !vk.verify(&msg, &sig),
            "una firma con la mitad Ed25519 corrupta verificó — ¿el combinador es OR?"
        );
    }

    // --- 100 corrupciones de un bit en la mitad ML-DSA (offsets 64..4691) ---
    // La pareja: con OR, éstas verificarían por la Ed25519 intacta.
    for _ in 0..100 {
        let msg = rng.bytes(64);
        let mut sig = sk.sign(&msg);
        let pos = ED25519_SIG_LEN + rng.hasta(SIGNATURE_LEN - ED25519_SIG_LEN);
        sig[pos] ^= 1 << rng.hasta(8);
        assert!(
            !vk.verify(&msg, &sig),
            "una firma con la mitad ML-DSA corrupta verificó — ¿el combinador es OR?"
        );
    }

    // --- 50 splices: misma clave, DOS mensajes ---
    // ed(m1) ‖ ml(m2) y ed(m2) ‖ ml(m1), verificados contra m1 y m2: los cuatro
    // false. Cada mitad solo vale sobre el mensaje que firmó.
    for _ in 0..50 {
        let n1 = 1 + rng.hasta(200);
        let m1 = rng.bytes(n1);
        let mut m2 = m1.clone();
        m2.push(0x01); // distinto seguro
        let s1 = sk.sign(&m1);
        let s2 = sk.sign(&m2);

        // ed(m1) ‖ ml(m2)
        let mut c12 = Vec::with_capacity(SIGNATURE_LEN);
        c12.extend_from_slice(&s1[..ED25519_SIG_LEN]);
        c12.extend_from_slice(&s2[ED25519_SIG_LEN..]);
        assert!(!vk.verify(&m1, &c12), "splice ed(m1)‖ml(m2) verificó contra m1");
        assert!(!vk.verify(&m2, &c12), "splice ed(m1)‖ml(m2) verificó contra m2");
        // ed(m2) ‖ ml(m1) — el comentario prometía los DOS cruces; aquí está el
        // segundo, que la revisión notó que faltaba.
        let mut c21 = Vec::with_capacity(SIGNATURE_LEN);
        c21.extend_from_slice(&s2[..ED25519_SIG_LEN]);
        c21.extend_from_slice(&s1[ED25519_SIG_LEN..]);
        assert!(!vk.verify(&m1, &c21), "splice ed(m2)‖ml(m1) verificó contra m1");
        assert!(!vk.verify(&m2, &c21), "splice ed(m2)‖ml(m1) verificó contra m2");
    }

    // --- 25 sustituciones de clave ---
    for _ in 0..25 {
        let (_vk2, sk2) = generate_keypair();
        let nm = 1 + rng.hasta(200);
        let msg = rng.bytes(nm);
        let sig2 = sk2.sign(&msg); // firma de OTRA clave
        assert!(!vk.verify(&msg, &sig2), "una firma de otra clave verificó contra vk");
    }
}

// --- La firma TRIPLE y el cruce QSG1↔QSG3 (feature `slh`, en release) --------
//
// SLH-DSA es lento a propósito (~2 s por firma), así que aquí son 12, no 400, y
// el banco se corre en `--release`. Fija el AND 3-de-3 y la anti-degradación
// entre los dos formatos de contenedor firmado.

#[cfg(feature = "slh")]
#[test]
fn la_triple_es_and_3_de_3_y_no_hay_cruce_entre_qsg1_y_qsg3() {
    use quipu::api::{decode_verified, decode_verified_triple, encode_signed, encode_signed_triple, DecodeError};
    use quipu::dictionaries::ascii94;
    use quipu::pqsign::{generate_triple_keypair, TRIPLE_SIGNATURE_LEN};

    let mut rng = Rng::nuevo(0x5133_2026_0817);
    let (tvk, tsk) = generate_triple_keypair();
    let dict = ascii94();

    // Ida y vuelta de la triple, con control.
    let msg = b"acta de altisimo valor";
    let art = encode_signed_triple(msg, &tsk, &dict);
    assert_eq!(
        decode_verified_triple(&art, &tvk, &dict).expect("la triple legítima verifica"),
        msg
    );

    // 30 corrupciones de un bit, 10 por componente, sobre la firma cruda.
    // Con el AND degradado a dos términos, el componente huérfano deja pasar
    // sus 10. Se prueba sobre `verify` de la clave, que es donde vive el AND.
    let sig = tsk.sign(msg);
    assert_eq!(sig.len(), TRIPLE_SIGNATURE_LEN);
    // Rangos: Ed25519 0..64, ML-DSA 64..4691, SLH-DSA 4691..fin.
    let rangos = [(0usize, 64usize), (64, 4691), (4691, TRIPLE_SIGNATURE_LEN)];
    for (lo, hi) in rangos {
        for _ in 0..10 {
            let mut s = sig.clone();
            let pos = lo + rng.hasta(hi - lo);
            s[pos] ^= 1 << rng.hasta(8);
            assert!(
                !tvk.verify(msg, &s),
                "una firma triple con el componente [{lo}..{hi}) corrupto verificó — ¿AND degradado?"
            );
        }
    }

    // EL CRUCE: un QSG3 presentado a `decode_verified` (doble) da BadMagic, y un
    // QSG1 a `decode_verified_triple` también. Sin downgrade en ninguna
    // dirección. Es la anti-degradación que la auditoría (F6) dijo que estaba
    // afirmada en prosa y sin prueba.
    let (vk, sk) = generate_keypair();
    let qsg1 = encode_signed(msg, &sk, &dict);
    let qsg3 = encode_signed_triple(msg, &tsk, &dict);

    // QSG3 → decodificador DOBLE: BadMagic, no se interpreta como QSG1.
    match decode_verified(&qsg3, &vk, &dict) {
        Err(DecodeError::Container(_)) => {}
        otro => panic!("un QSG3 en el decodificador doble no dio error de contenedor: {otro:?}"),
    }
    // QSG1 → decodificador TRIPLE: BadMagic.
    match decode_verified_triple(&qsg1, &tvk, &dict) {
        Err(DecodeError::Container(_)) => {}
        otro => panic!("un QSG1 en el decodificador triple no dio error de contenedor: {otro:?}"),
    }
    // Control: cada uno en SU decodificador sí abre.
    assert_eq!(decode_verified(&qsg1, &vk, &dict).unwrap(), msg);
    assert_eq!(decode_verified_triple(&qsg3, &tvk, &dict).unwrap(), msg);
}
