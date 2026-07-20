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

// ===================== Soak de la directiva 8 =====================
//
// 100+ operaciones, concurrencia con timeout, camino de error inyectado, y
// prueba de que DISCRIMINA. El modelo de concurrencia no es una elección: el
// contexto `Pkcs11` es `Arc` y se comparte; la `Session` es `Send` pero NO
// `Sync`, así que cada hilo abre y posee la SUYA. Es como lo usaría un servicio.

use std::sync::mpsc;
use std::time::Duration;

/// Crea el token y DOS claves persistentes etiquetadas, una sola vez. Las
/// devuelve por etiqueta para que cada hilo las encuentre por su cuenta.
fn preparar_etiquetado(modulo: &str) -> (&'static Pkcs11, cryptoki::slot::Slot) {
    let p = contexto(modulo);
    let slot = *p.get_all_slots().expect("slots").first().expect("un slot");
    let so = AuthPin::new("12345678".into());
    p.init_token(slot, &so, "quipu-soak").expect("init_token");
    let s = p.open_rw_session(slot).expect("sesión RW");
    s.login(UserType::So, Some(&so)).expect("login SO");
    let user = AuthPin::new("87654321".into());
    s.init_pin(&user).expect("init_pin");
    s.logout().ok();
    s.login(UserType::User, Some(&user)).expect("login usuario");

    let ed_oid = [0x06u8, 0x03, 0x2b, 0x65, 0x70];
    s.generate_key_pair(
        &Mechanism::EccEdwardsKeyPairGen,
        &[Attribute::EcParams(ed_oid.to_vec()), Attribute::Verify(true),
          Attribute::Token(true), Attribute::Label(b"soak-ed".to_vec())],
        &[Attribute::Sign(true), Attribute::Token(true), Attribute::Private(true),
          Attribute::Label(b"soak-ed".to_vec())],
    ).expect("Ed25519");
    s.generate_key_pair(
        &Mechanism::MlDsaKeyPairGen,
        &[Attribute::ParameterSet(MlDsaParameterSetType::ML_DSA_87.into()),
          Attribute::Verify(true), Attribute::Token(true), Attribute::Label(b"soak-ml".to_vec())],
        &[Attribute::Sign(true), Attribute::Token(true), Attribute::Private(true),
          Attribute::Label(b"soak-ml".to_vec())],
    ).expect("ML-DSA-87");
    (p, slot)
}

/// Un hilo abre su propia sesión, firma `n` mensajes distintos y verifica cada
/// uno. Devuelve cuántas firmas verificaron.
///
/// NO hace login: en PKCS#11 el login es por APLICACIÓN, no por sesión —una
/// sesión guardiana lo mantiene vivo y esta lo hereda—. Volver a autenticar
/// daría `CKR_USER_ALREADY_LOGGED_IN`.
fn hilo_firmante(p: &'static Pkcs11, slot: cryptoki::slot::Slot, hilo: usize, n: usize) -> usize {
    let s = p.open_rw_session(slot).expect("sesión del hilo");
    let custodio = CustodioPkcs11::por_etiqueta(s, "soak-ed", "soak-ml").expect("custodio por etiqueta");
    let vk = custodio.clave_de_verificacion().expect("vk");
    let mut ok = 0;
    for i in 0..n {
        let mensaje = format!("soak hilo {hilo} op {i}");
        let firma = firmar(&custodio, mensaje.as_bytes()).expect("firmar bajo carga");
        // Verifica el mensaje propio (discrimina) y RECHAZA otro.
        assert!(vk.verify(mensaje.as_bytes(), &firma), "no verificó bajo carga");
        assert!(!vk.verify(b"mensaje ajeno", &firma), "verificó un mensaje que no era");
        ok += 1;
    }
    ok
}

/// El soak. 8 hilos x 16 firmas = 128 operaciones concurrentes, con timeout.
#[test]
fn soak_directiva8_concurrente_con_timeout() {
    let Some(m) = modulo() else { return };
    const HILOS: usize = 8;
    const POR_HILO: usize = 16; // 128 operaciones, > 100

    // Todo el soak corre en un hilo aparte con timeout: sin él, un deadlock del
    // token parecería una compilación lenta (trampa documentada del proyecto).
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let (p, slot) = preparar_etiquetado(&m);
        // Sesión guardiana: mantiene el login de aplicación vivo mientras los
        // hilos trabajan. Los hilos heredan ese login sin re-autenticar.
        let guardiana = p.open_rw_session(slot).expect("sesión guardiana");
        guardiana
            .login(UserType::User, Some(&AuthPin::new("87654321".into())))
            .expect("login guardiana");

        let manijas: Vec<_> = (0..HILOS)
            .map(|h| std::thread::spawn(move || hilo_firmante(p, slot, h, POR_HILO)))
            .collect();
        // join devuelve Err si un hilo entró en pánico; se propaga como total 0
        // para que el assert de abajo lo cace, sin abortar el hilo guardián.
        let total: usize = manijas
            .into_iter()
            .map(|h| h.join().unwrap_or(0))
            .sum();
        drop(guardiana); // el login se suelta cuando ya nadie firma
        tx.send(total).ok();
    });

    match rx.recv_timeout(Duration::from_secs(120)) {
        Ok(total) => assert_eq!(total, HILOS * POR_HILO, "faltaron firmas: {total} de {}", HILOS * POR_HILO),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("el soak no terminó en 120 s: posible deadlock del token")
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("un hilo del soak entró en pánico (canal cortado antes de enviar)")
        }
    }
}

/// Camino de error INYECTADO contra el dispositivo real: sin login, PKCS#11 no
/// expone las claves privadas, así que construir el custodio DEBE fallar en vez
/// de acabar firmando con una clave que no está. Es un error permanente
/// (hay que autenticarse; reintentar la misma llamada no lo arregla).
///
/// La discriminación transitorio/permanente en sí —qué códigos de error mapean
/// a qué variante— está probada aparte, a nivel unitario, en `firmante` con
/// mocks; aquí se comprueba que un error de dispositivo de verdad SUBE como
/// error y no se traga.
#[test]
fn error_de_dispositivo_sube_en_vez_de_firmar_a_ciegas() {
    let Some(m) = modulo() else { return };
    let (p, slot) = preparar_etiquetado(&m);

    // Sesión SIN login: las claves privadas no son visibles.
    let s = p.open_rw_session(slot).expect("sesión");
    match CustodioPkcs11::por_etiqueta(s, "soak-ed", "soak-ml") {
        Err(e) => {
            // Cualquiera de las dos variantes de error es correcta; lo que NO
            // puede es construirse y luego firmar con nada.
            eprintln!("sin login, construir el custodio falla como debe: {e}");
        }
        Ok(custodio) => {
            // Si el módulo dejó ver las claves sin login, al menos firmar debe
            // fallar; jamás debe producir una firma silenciosa.
            match firmar(&custodio, b"sin autenticar") {
                Err(e) => eprintln!("sin login, firmar falla como debe: {e}"),
                Ok(_) => panic!("firmó sin autenticación: no discrimina el fallo"),
            }
        }
    }
}
