// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! La prueba que sostiene la frase de venta del custodio PKCS#11: **firmar
//! dentro del dispositivo y verificar con el verificador puro de siempre**.
//!
//! No corre por defecto. Necesita un módulo PKCS#11 real con ML-DSA-87 y
//! Ed25519, y se activa con dos variables de entorno:
//!
//! ```text
//! QUIPU_PKCS11_MODULE=/ruta/a/libkryoptic_pkcs11.so \
//! KRYOPTIC_CONF=/tmp/token.sql \
//!   cargo test --features hsm --test hsm_pkcs11 -- --nocapture
//! ```
//!
//! El CI la corre en un contenedor `fedora:43`, que trae kryoptic con `pqc`.
//! Fuera de ahí, se salta con un aviso — nunca falla por ausencia del token,
//! porque eso escondería un fallo real bajo un «no había HSM».

#![cfg(feature = "hsm")]

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, MlDsaParameterSetType};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use quipu::firmante::pkcs11::CustodioPkcs11;
use quipu::firmante::{firmar, Custodio};

/// El contexto PKCS#11 es un singleton del proceso: `C_Initialize` solo puede
/// llamarse una vez por librería cargada. Se comparte entre todas las pruebas,
/// que es además como se usa en producción — la app inicializa el módulo una vez.
fn contexto(modulo: &str) -> &'static Pkcs11 {
    use std::sync::OnceLock;
    static CTX: OnceLock<Pkcs11> = OnceLock::new();
    CTX.get_or_init(|| {
        let p = Pkcs11::new(modulo).expect("cargar el módulo PKCS#11");
        p.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .expect("initialize");
        p
    })
}

/// Levanta un token limpio y devuelve un custodio listo para firmar, con dos
/// pares de claves recién generados DENTRO del token.
fn preparar(modulo: &str) -> CustodioPkcs11 {
    let p = contexto(modulo);
    let slot = *p.get_all_slots().expect("slots").first().expect("al menos un slot");

    let so = AuthPin::new("12345678".into());
    p.init_token(slot, &so, "quipu-hsm-test").expect("init_token");

    let s = p.open_rw_session(slot).expect("abrir sesión RW");
    s.login(UserType::So, Some(&so)).expect("login SO");
    let user = AuthPin::new("87654321".into());
    s.init_pin(&user).expect("init_pin");
    s.logout().ok();
    s.login(UserType::User, Some(&user)).expect("login usuario");

    // Ed25519. EcParams = OID DER de la curva (1.3.101.112).
    let ed_oid = [0x06u8, 0x03, 0x2b, 0x65, 0x70];
    let (ed_pub, ed_priv) = s
        .generate_key_pair(
            &Mechanism::EccEdwardsKeyPairGen,
            &[
                Attribute::EcParams(ed_oid.to_vec()),
                Attribute::Verify(true),
                Attribute::Token(true),
            ],
            &[Attribute::Sign(true), Attribute::Token(true), Attribute::Private(true)],
        )
        .expect("generar Ed25519 en el token");

    // ML-DSA-87.
    let (ml_pub, ml_priv) = s
        .generate_key_pair(
            &Mechanism::MlDsaKeyPairGen,
            &[
                Attribute::ParameterSet(MlDsaParameterSetType::ML_DSA_87.into()),
                Attribute::Verify(true),
                Attribute::Token(true),
            ],
            &[Attribute::Sign(true), Attribute::Token(true), Attribute::Private(true)],
        )
        .expect("generar ML-DSA-87 en el token");

    CustodioPkcs11::nuevo(s, ed_priv, ed_pub, ml_priv, ml_pub)
        .expect("construir el custodio")
}

fn modulo() -> Option<String> {
    match std::env::var("QUIPU_PKCS11_MODULE") {
        Ok(m) if !m.is_empty() => Some(m),
        _ => {
            eprintln!(
                "SALTADA: define QUIPU_PKCS11_MODULE con la ruta a un módulo PKCS#11 \
                 (ML-DSA-87 + Ed25519) para correr esta prueba."
            );
            None
        }
    }
}

/// EL núcleo: la firma hecha dentro del dispositivo la acepta el verificador de
/// Quipu, que no sabe que hubo un HSM de por medio.
#[test]
fn firma_en_el_dispositivo_verifica_con_el_verificador_puro() {
    let Some(m) = modulo() else { return };
    let custodio = preparar(&m);

    let mensaje = b"acta con validez juridica, firmada en el HSM";
    let firma = firmar(&custodio, mensaje).expect("firmar con el custodio PKCS#11");

    let vk = custodio.clave_de_verificacion().expect("clave de verificación");
    assert!(vk.verify(mensaje, &firma), "el verificador puro rechazó una firma del HSM");
    assert!(
        !vk.verify(b"un mensaje distinto", &firma),
        "verificó un mensaje que no se firmó"
    );
}

/// El formato es el de siempre: 4691 bytes (64 de Ed25519 + 4627 de ML-DSA-87).
/// Si esto cambiara, una firma del HSM no sería intercambiable con una hecha en
/// memoria, que es justo lo que el trait promete.
#[test]
fn la_firma_del_dispositivo_tiene_el_tamano_de_quipu() {
    let Some(m) = modulo() else { return };
    let custodio = preparar(&m);
    let firma = firmar(&custodio, b"x").expect("firmar");
    assert_eq!(firma.len(), quipu::pqsign::SIGNATURE_LEN, "la firma no mide 4691");
}

/// Dos firmas del mismo mensaje verifican las dos. La mitad ML-DSA se pide con
/// hedge preferido (aleatorizado), así que pueden diferir en bytes; lo que NO
/// puede es que una deje de verificar.
#[test]
fn dos_firmas_del_mismo_mensaje_verifican_ambas() {
    let Some(m) = modulo() else { return };
    let custodio = preparar(&m);
    let mensaje = b"idempotencia de verificacion, no de bytes";
    let a = firmar(&custodio, mensaje).expect("firma A");
    let b = firmar(&custodio, mensaje).expect("firma B");
    let vk = custodio.clave_de_verificacion().unwrap();
    assert!(vk.verify(mensaje, &a) && vk.verify(mensaje, &b), "una de las dos no verifica");
}
