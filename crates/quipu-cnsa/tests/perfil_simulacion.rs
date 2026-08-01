// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Simulación a escala del perfil CNSA 2.0: firma ML-DSA-87 y canal ML-KEM-1024.
//!
//! POR QUÉ EXISTE. Las pruebas unitarias del crate comprueban que un camino
//! FUNCIONA. Eso no dice nada de lo que aquí importa: que siga funcionando
//! repetido cien veces, que **rechace** lo que tiene que rechazar, y que lo que
//! debe ser distinto en cada operación de verdad lo sea. Un par de claves que
//! se repite no se ve en una ejecución; se ve en quinientas.
//!
//! Los módulos `firma` y `destinatario` entraron el 2026-07-31 y hasta el
//! 2026-08-01 este crate no tenía ni un archivo en `tests/`.
//!
//! LAS CUATRO EXIGENCIAS de la directiva 8, y dónde está cada una:
//!   1. 100+ operaciones          → `OPERACIONES`, en los cuatro bancos.
//!   2. concurrencia CON TIMEOUT  → `bajo_concurrencia_no_se_cruzan_las_claves`
//!      (`mpsc` + `recv_timeout`: sin él, un interbloqueo parece lentitud).
//!   3. camino de error INYECTADO → los bancos `..._rechaza_...`.
//!   4. que DISCRIMINE            → cada banco cuenta los rechazos y exige que
//!      sean TODOS. Un verificador que dijera «sí» siempre pasaría los bancos
//!      de aceptación y solo estos lo delatan.
//!
//! REPRODUCIBILIDAD. Las entradas salen de un generador determinista con la
//! semilla escrita; el material de clave, no — ese tiene que venir del CSPRNG o
//! no estaríamos midiendo lo que se despliega.

use quipu_cnsa::{destinatario, firma};
use std::sync::mpsc;
use std::time::Duration;

/// Cuántas veces se repite cada banco. Cien es el mínimo de la directiva 8.
const OPERACIONES: usize = 120;

/// Ninguna prueba puede colgarse en silencio: un interbloqueo sin plazo es
/// indistinguible de una compilación lenta, y ya costó trece minutos una vez.
const PLAZO: Duration = Duration::from_secs(120);

/// xorshift64*. Genera las ENTRADAS, nunca material de clave.
struct Az(u64);

impl Az {
    fn nuevo(s: u64) -> Self {
        Az(s)
    }
    fn siguiente(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.siguiente() >> 33) as u8).collect()
    }
    fn hasta(&mut self, n: usize) -> usize {
        (self.siguiente() % n as u64) as usize
    }
}

// ===========================================================================
// FIRMA — ML-DSA-87
// ===========================================================================

#[test]
fn cien_firmas_verifican_con_su_clave_y_con_ninguna_otra() {
    let mut az = Az::nuevo(0x4649_524D_4131_3131);
    let (vk_a, sk_a) = firma::generar_par().expect("entropía");
    let (vk_b, _sk_b) = firma::generar_par().expect("entropía");

    let mut propias = 0usize;
    let mut ajenas_rechazadas = 0usize;

    for i in 0..OPERACIONES {
        let n = 1 + az.hasta(512);
        let mensaje = az.bytes(n);
        let f = sk_a.firmar(&mensaje);
        assert_eq!(f.len(), firma::SIGNATURE_LEN, "largo de la firma {i}");

        if vk_a.verificar(&mensaje, &f) {
            propias += 1;
        }
        // LA MITAD QUE DISCRIMINA. Sin esto, un `verificar` que devolviera
        // `true` siempre pasaría la línea de arriba con nota.
        if !vk_b.verificar(&mensaje, &f) {
            ajenas_rechazadas += 1;
        }
    }

    assert_eq!(propias, OPERACIONES, "alguna firma no verificó con SU clave");
    assert_eq!(
        ajenas_rechazadas, OPERACIONES,
        "una clave AJENA aceptó una firma que no era suya"
    );
}

#[test]
fn la_firma_corrompida_se_rechaza_byte_a_byte() {
    let (vk, sk) = firma::generar_par().expect("entropía");
    let mensaje = b"el acta que se sella no se puede tocar despues";
    let buena = sk.firmar(mensaje);
    assert!(vk.verificar(mensaje, &buena), "la buena tiene que valer");

    // Se recorren posiciones repartidas por TODA la firma: un verificador que
    // solo mirase la cabecera pasaría un banco que solo tocara el principio.
    let mut probadas = 0usize;
    let mut rechazadas = 0usize;
    for pos in (0..buena.len()).step_by(buena.len() / OPERACIONES.min(buena.len())) {
        let mut mala = buena.clone();
        mala[pos] ^= 0x01;
        probadas += 1;
        if !vk.verificar(mensaje, &mala) {
            rechazadas += 1;
        }
    }
    assert!(probadas >= 100, "solo se probaron {probadas} posiciones");
    assert_eq!(rechazadas, probadas, "alguna firma con un bit cambiado coló");
}

#[test]
fn el_mensaje_cambiado_invalida_la_firma() {
    let mut az = Az::nuevo(0x4D45_4E53_414A_4531);
    let (vk, sk) = firma::generar_par().expect("entropía");
    let mut rechazadas = 0usize;

    for _ in 0..OPERACIONES {
        let n = 32 + az.hasta(256);
        let mensaje = az.bytes(n);
        let f = sk.firmar(&mensaje);
        let mut otro = mensaje.clone();
        let pos = az.hasta(otro.len());
        otro[pos] ^= 0x80;
        if !vk.verificar(&otro, &f) {
            rechazadas += 1;
        }
    }
    assert_eq!(rechazadas, OPERACIONES, "una firma valió para otro mensaje");
}

/// Una firma de largo distinto del de la norma no puede colar por accidente.
#[test]
fn una_firma_de_largo_ajeno_se_rechaza() {
    let (vk, sk) = firma::generar_par().expect("entropía");
    let mensaje = b"cualquiera";
    let buena = sk.firmar(mensaje);

    for recorte in [0usize, 1, 16, firma::SIGNATURE_LEN / 2, firma::SIGNATURE_LEN - 1] {
        assert!(
            !vk.verificar(mensaje, &buena[..recorte]),
            "una firma de {recorte} bytes tenía que rechazarse"
        );
    }
    let mut larga = buena.clone();
    larga.push(0);
    assert!(!vk.verificar(mensaje, &larga), "una firma con un byte de más coló");
}

/// Las claves salen del CSPRNG: cien pares tienen que ser cien pares distintos.
/// Un generador atascado devolvería siempre el mismo y ninguna prueba de
/// «firma y verifica» lo notaría.
#[test]
fn cien_pares_de_claves_son_todos_distintos() {
    let mut vistas = std::collections::HashSet::new();
    for i in 0..OPERACIONES {
        let (vk, _sk) = firma::generar_par().expect("entropía");
        assert!(
            vistas.insert(vk.a_bytes()),
            "el par {i} repitió una clave de verificación ya vista"
        );
    }
    assert_eq!(vistas.len(), OPERACIONES);
}

// ===========================================================================
// DESTINATARIO — ML-KEM-1024 + AES-256-GCM
// ===========================================================================

#[test]
fn cien_mensajes_abren_con_su_clave_y_con_ninguna_otra() {
    let mut az = Az::nuevo(0x4B45_4D31_3032_3431);
    let (pk_a, sk_a) = destinatario::generar_par().expect("entropía");
    let (_pk_b, sk_b) = destinatario::generar_par().expect("entropía");

    let mut abiertos = 0usize;
    let mut ajenos_rechazados = 0usize;

    for i in 0..OPERACIONES {
        let n = 1 + az.hasta(1024);
        let mensaje = az.bytes(n);
        let blob = destinatario::cifrar_para(&pk_a, &mensaje).expect("entropía");

        match destinatario::descifrar(&sk_a, &blob) {
            Ok(claro) => {
                assert_eq!(claro, mensaje, "el mensaje {i} volvió cambiado");
                abiertos += 1;
            }
            Err(e) => panic!("el destinatario legítimo no pudo abrir el {i}: {e:?}"),
        }
        // LA MITAD QUE DISCRIMINA.
        if destinatario::descifrar(&sk_b, &blob).is_err() {
            ajenos_rechazados += 1;
        }
    }

    assert_eq!(abiertos, OPERACIONES);
    assert_eq!(
        ajenos_rechazados, OPERACIONES,
        "una clave AJENA abrió un mensaje que no era para ella"
    );
}

/// El mismo mensaje cifrado cien veces tiene que dar cien blobs distintos. Si
/// se repitieran, el canal filtraría que dos mensajes son iguales — y con
/// AES-GCM un nonce repetido es una rotura, no una molestia.
#[test]
fn cien_cifrados_del_mismo_mensaje_no_se_repiten() {
    let (pk, _sk) = destinatario::generar_par().expect("entropía");
    let mensaje = b"identico cada vez, a proposito";
    let mut vistos = std::collections::HashSet::new();

    for i in 0..OPERACIONES {
        let blob = destinatario::cifrar_para(&pk, mensaje).expect("entropía");
        assert!(vistos.insert(blob), "el cifrado {i} repitió un blob anterior");
    }
    assert_eq!(vistos.len(), OPERACIONES);
}

#[test]
fn el_blob_corrompido_se_rechaza_en_todas_sus_partes() {
    let (pk, sk) = destinatario::generar_par().expect("entropía");
    let mensaje = b"carga util que no se puede tocar";
    let bueno = destinatario::cifrar_para(&pk, mensaje).expect("entropía");
    assert!(destinatario::descifrar(&sk, &bueno).is_ok());

    // Se recorre TODO el blob —encapsulación, nonce y ciphertext— porque un
    // AEAD que solo autenticara el final pasaría un banco que solo tocara el
    // final. Es la lección de la cascada: fijar cada prueba a SU parte.
    let paso = (bueno.len() / OPERACIONES).max(1);
    let mut probadas = 0usize;
    let mut rechazadas = 0usize;
    for pos in (0..bueno.len()).step_by(paso) {
        let mut malo = bueno.clone();
        malo[pos] ^= 0x01;
        probadas += 1;
        if destinatario::descifrar(&sk, &malo).is_err() {
            rechazadas += 1;
        }
    }
    assert!(probadas >= 100, "solo se probaron {probadas} posiciones");
    assert_eq!(rechazadas, probadas, "un blob con un bit cambiado se abrió");
}

#[test]
fn un_blob_truncado_o_vacio_no_abre_ni_se_cuelga() {
    let (pk, sk) = destinatario::generar_par().expect("entropía");
    let bueno = destinatario::cifrar_para(&pk, b"algo").expect("entropía");

    for n in [0usize, 1, 16, destinatario::ENCAPSULATION_LEN - 1, bueno.len() - 1] {
        assert!(
            destinatario::descifrar(&sk, &bueno[..n]).is_err(),
            "un blob de {n} bytes tenía que rechazarse"
        );
    }
}

// ===========================================================================
// CONCURRENCIA — con plazo, que es lo que la vuelve una prueba y no una espera
// ===========================================================================

/// Cien operaciones a la vez, en dos docenas de hilos, con claves distintas por
/// hilo. Lo que se busca no es velocidad: es que ningún estado compartido
/// escondido cruce el material de un hilo con el de otro.
///
/// EL PLAZO NO ES DECORACIÓN. Sin `recv_timeout`, un interbloqueo aquí se ve
/// exactamente igual que una compilación lenta — que es como se perdieron trece
/// minutos con `Once::call_once` y por qué existen las variantes `_unchecked`.
#[test]
fn bajo_concurrencia_no_se_cruzan_las_claves() {
    const HILOS: usize = 12;
    const POR_HILO: usize = 10;

    let (tx, rx) = mpsc::channel::<Result<usize, String>>();
    for h in 0..HILOS {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let resultado = (|| -> Result<usize, String> {
                let mut az = Az::nuevo(0x4849_4C4F_0000_0000u64.wrapping_add(h as u64));
                let (vk, sk) = firma::generar_par().map_err(|e| format!("{e:?}"))?;
                let (pk, ks) = destinatario::generar_par().map_err(|e| format!("{e:?}"))?;
                let mut hechas = 0usize;
                for i in 0..POR_HILO {
                    let n = 1 + az.hasta(256);
                    let m = az.bytes(n);

                    let f = sk.firmar(&m);
                    if !vk.verificar(&m, &f) {
                        return Err(format!("hilo {h}, op {i}: la firma no verificó"));
                    }

                    let blob = destinatario::cifrar_para(&pk, &m).map_err(|e| format!("{e:?}"))?;
                    let claro = destinatario::descifrar(&ks, &blob)
                        .map_err(|e| format!("hilo {h}, op {i}: no abrió: {e:?}"))?;
                    if claro != m {
                        return Err(format!("hilo {h}, op {i}: volvió cambiado"));
                    }
                    hechas += 1;
                }
                Ok(hechas)
            })();
            let _ = tx.send(resultado);
        });
    }
    drop(tx);

    let mut total = 0usize;
    for _ in 0..HILOS {
        match rx.recv_timeout(PLAZO) {
            Ok(Ok(n)) => total += n,
            Ok(Err(e)) => panic!("{e}"),
            Err(_) => panic!(
                "PLAZO AGOTADO ({PLAZO:?}): un hilo no contestó. Sin este plazo \
                 el interbloqueo se vería como una compilación lenta."
            ),
        }
    }
    assert_eq!(total, HILOS * POR_HILO, "faltaron operaciones");
    assert!(total >= 100, "la directiva 8 pide 100+, hubo {total}");
}
