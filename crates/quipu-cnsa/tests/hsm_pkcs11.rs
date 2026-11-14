// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

//! La prueba que sostiene la frase de venta del custodio PKCS#11 de este
//! perfil: **firmar dentro del dispositivo y verificar con el verificador puro
//! de siempre**, sin que el verificador sepa que hubo un HSM de por medio.
//!
//! Es la directiva 28 aplicada a un módulo que, si no se cruza la frontera,
//! solo se sabe que compila: un backend PKCS#11 que nunca habló con un módulo
//! PKCS#11 no está probado, está escrito.
//!
//! No corre por defecto. Necesita un módulo PKCS#11 real con ML-DSA-87, y se
//! activa con dos variables de entorno:
//!
//! ```text
//! QUIPU_PKCS11_MODULE=/usr/lib64/pkcs11/libkryoptic_pkcs11.so \
//! KRYOPTIC_CONF=/tmp/token-cnsa.sql \
//!   cargo test -p quipu-cnsa --features hsm --test hsm_pkcs11 -- --test-threads=1
//! ```
//!
//! Fuera de ahí se salta con un aviso — nunca falla por ausencia del token,
//! porque eso escondería un fallo real bajo un «no había HSM». Y por lo mismo
//! **el aviso se imprime**: un cero silencioso y un verde real se ven igual
//! (directiva 30).
//!
//! `--test-threads=1` no es cosmético: `C_Initialize` del módulo es un
//! singleton del proceso.

#![cfg(feature = "hsm")]

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, MlDsaParameterSetType};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use quipu_cnsa::firma::SIGNATURE_LEN;
use quipu_cnsa::firmante::pkcs11::CustodioPkcs11;
use quipu_cnsa::firmante::{firmar, Custodio};

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

/// Cerrojo de proceso: **el banco se serializa solo, no por bandera**.
///
/// `preparar` llama a `init_token`, que BORRA el token entero, así que dos
/// pruebas a la vez se destruyen las claves mutuamente. La versión anterior lo
/// resolvía pidiendo `--test-threads=1` en la línea de órdenes, y eso es una
/// salvaguarda que vive FUERA del artefacto: correr el banco de la forma normal
/// —`cargo test -p quipu-cnsa --features hsm`, sin banderas— daba **8 fallos de
/// 9** con el código perfectamente sano. Medido el 2026-08-13, después de que la
/// revisión de seguridad avisara de que la bandera era la única barandilla.
///
/// Con el cerrojo, el banco es correcto con cualquier número de hilos. La
/// bandera del CI se queda porque no estorba, pero ya no sostiene nada.
///
/// `unwrap_or_else(into_inner)`: si una prueba entra en pánico con el cerrojo en
/// la mano, las demás tienen que poder seguir y fallar por lo suyo, no heredar
/// un envenenamiento que no dice nada del código medido.
fn cerrojo() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn modulo() -> Option<String> {
    match std::env::var("QUIPU_PKCS11_MODULE") {
        Ok(m) if !m.is_empty() => {
            // LA VARIABLE PUESTA Y EL MÓDULO AUSENTE es el caso que más
            // engaña: el CI apunta a `/usr/lib64/pkcs11/…` y en una máquina
            // sin kryoptic eso entraba en pánico dentro de `preparar` con
            // «construir el custodio», que no dice cuál es el problema.
            assert!(
                std::path::Path::new(&m).exists(),
                "QUIPU_PKCS11_MODULE apunta a un módulo que NO EXISTE: {m}\n\
                 Instala kryoptic o apunta la variable al módulo PKCS#11 real."
            );
            Some(m)
        }
        _ => {
            eprintln!(
                "SALTADA: define QUIPU_PKCS11_MODULE con la ruta a un módulo PKCS#11 \
                 con ML-DSA-87 para correr esta prueba."
            );
            None
        }
    }
}

/// Levanta un token limpio, genera el par ML-DSA-87 DENTRO y devuelve el
/// custodio y su slot. La etiqueta se pone siempre, para que las pruebas que
/// buscan por nombre no necesiten otro token.
fn preparar(modulo: &str) -> (&'static Pkcs11, cryptoki::slot::Slot, CustodioPkcs11) {
    let p = contexto(modulo);
    let slot = *p.get_all_slots().expect("slots").first().expect("al menos un slot");

    let so = AuthPin::new("12345678".into());
    p.init_token(slot, &so, "quipu-cnsa-hsm").expect("init_token");

    let s = p.open_rw_session(slot).expect("abrir sesión RW");
    s.login(UserType::So, Some(&so)).expect("login SO");
    let user = AuthPin::new("87654321".into());
    s.init_pin(&user).expect("init_pin");
    s.logout().ok();
    s.login(UserType::User, Some(&user)).expect("login usuario");

    let (publica, privada) = s
        .generate_key_pair(
            &Mechanism::MlDsaKeyPairGen,
            &[
                Attribute::ParameterSet(MlDsaParameterSetType::ML_DSA_87.into()),
                Attribute::Verify(true),
                Attribute::Token(true),
                Attribute::Label(b"cnsa-firma".to_vec()),
            ],
            &[
                Attribute::Sign(true),
                Attribute::Token(true),
                Attribute::Private(true),
                // EXPLÍCITOS, y no por costumbre: `CustodioPkcs11::nuevo`
                // comprueba `CKA_SENSITIVE` contra el dispositivo y se niega a
                // firmar si es falso. Si esto no estuviera, el banco entero
                // estaría ejerciendo una clave que el crate rechaza — y la
                // frase «no sale del dispositivo» se probaría sobre una clave
                // que sí sale.
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Label(b"cnsa-firma".to_vec()),
            ],
        )
        .expect("generar ML-DSA-87 en el token");

    let custodio = CustodioPkcs11::nuevo(s, privada, publica).expect("construir el custodio");
    (p, slot, custodio)
}

/// EL núcleo, y con su pareja: la firma hecha dentro del dispositivo la acepta
/// el verificador de este crate, y RECHAZA un mensaje que no se firmó. Con solo
/// la primera mitad pasaría igual un verificador que diga que sí a todo.
#[test]
#[ignore = "necesita un módulo PKCS#11 real (QUIPU_PKCS11_MODULE); el carril `hsm` del CI la corre con --include-ignored"]
fn firma_en_el_dispositivo_verifica_con_el_verificador_puro() {
    let _cerrojo = cerrojo();
    let Some(m) = modulo() else { return };
    let (_, _, custodio) = preparar(&m);

    let mensaje = b"acta con validez juridica, firmada en el HSM";
    let firma = firmar(&custodio, mensaje).expect("firmar con el custodio PKCS#11");

    let vk = custodio.clave_de_verificacion().expect("clave de verificación");
    assert!(
        vk.verificar(mensaje, &firma),
        "el verificador puro rechazó una firma del HSM"
    );
    assert!(
        !vk.verificar(b"un mensaje distinto", &firma),
        "verificó un mensaje que no se firmó"
    );
}

/// El formato es el del perfil: 4627 bytes de ML-DSA-87 pura, sin mitad
/// clásica, y **verificable por una clave publicada aparte**.
///
/// Antes esta prueba solo miraba `firma.len() == SIGNATURE_LEN`, y era
/// tautológica: `firmar` ya devuelve `Err(LongitudInesperada)` si la longitud no
/// es 4627, así que el `expect` de arriba se habría estrellado primero. No
/// existía estado del mundo en que la aserción fallara. Lo señaló la revisión
/// de seguridad del 2026-08-13.
///
/// Lo que sí discrimina: que la firma del dispositivo la acepte una
/// `VerifyingKey` reconstruida **desde bytes**, sin el custodio de por medio.
/// Es lo que de verdad significa «intercambiable con una hecha en memoria».
#[test]
#[ignore = "necesita un módulo PKCS#11 real (QUIPU_PKCS11_MODULE); el carril `hsm` del CI la corre con --include-ignored"]
fn la_firma_del_dispositivo_es_intercambiable_con_una_de_memoria() {
    let _cerrojo = cerrojo();
    let Some(m) = modulo() else { return };
    let (_, _, custodio) = preparar(&m);
    let firma = firmar(&custodio, b"x").expect("firmar");
    assert_eq!(firma.len(), SIGNATURE_LEN, "la firma no mide 4627");

    let vk_publicada = quipu_cnsa::firma::VerifyingKey::desde_bytes(
        &custodio.clave_de_verificacion().unwrap().a_bytes(),
    )
    .expect("clave publicada");
    assert!(vk_publicada.verificar(b"x", &firma));
    // LA PAREJA: la misma clave rechaza una firma de la longitud correcta que
    // no es suya. Sin esto, un verificador que dijera que sí a todo pasaría.
    let (_, sk_ajena) = quipu_cnsa::firma::generar_par().unwrap();
    assert!(!vk_publicada.verificar(b"x", &sk_ajena.firmar(b"x")));
}

/// La clave pública que el dispositivo entrega es una ML-DSA-87 de verdad: va y
/// vuelve por el serializador del crate sin perder nada, y la firma sigue
/// verificando con la copia reconstruida. Es lo que permite publicar la clave
/// de un HSM como se publica cualquier otra.
#[test]
#[ignore = "necesita un módulo PKCS#11 real (QUIPU_PKCS11_MODULE); el carril `hsm` del CI la corre con --include-ignored"]
fn la_clave_publica_del_token_va_y_vuelve_por_el_serializador() {
    let _cerrojo = cerrojo();
    let Some(m) = modulo() else { return };
    let (_, _, custodio) = preparar(&m);
    let vk = custodio.clave_de_verificacion().unwrap();
    let bytes = vk.a_bytes();
    assert_eq!(bytes.len(), quipu_cnsa::firma::VERIFYING_KEY_LEN);

    let recuperada =
        quipu_cnsa::firma::VerifyingKey::desde_bytes(&bytes).expect("la clave del token es válida");
    let firma = firmar(&custodio, b"publicada aparte").expect("firmar");
    assert!(recuperada.verificar(b"publicada aparte", &firma));
}

/// Dos firmas del mismo mensaje verifican las dos. La firma se pide con hedge
/// preferido (aleatorizada), así que pueden diferir byte a byte —al revés que
/// el camino en memoria, que es determinista—; lo que NO puede es que una deje
/// de verificar.
#[test]
#[ignore = "necesita un módulo PKCS#11 real (QUIPU_PKCS11_MODULE); el carril `hsm` del CI la corre con --include-ignored"]
fn dos_firmas_del_mismo_mensaje_verifican_ambas() {
    let _cerrojo = cerrojo();
    let Some(m) = modulo() else { return };
    let (_, _, custodio) = preparar(&m);
    let mensaje = b"idempotencia de verificacion, no de bytes";
    let a = firmar(&custodio, mensaje).expect("firma A");
    let b = firmar(&custodio, mensaje).expect("firma B");
    let vk = custodio.clave_de_verificacion().unwrap();
    assert!(
        vk.verificar(mensaje, &a) && vk.verificar(mensaje, &b),
        "una de las dos no verifica"
    );

    // DICE QUÉ MUNDO VIO, en vez de dar los dos por buenos en silencio.
    // `HedgeType::Preferred` permite legítimamente que el dispositivo firme
    // determinista, así que un `assert_ne!` sería falsear la norma; pero callar
    // deja SIN MEDIR la propiedad sobre la que descansa el argumento de
    // seguridad de la cabecera de `pkcs11.rs` —que la firma del HSM es
    // aleatorizada y por eso resiste la inyección de fallos—. Lo señaló la
    // revisión de seguridad del 2026-08-13.
    if a == b {
        eprintln!(
            "AVISO: este dispositivo IGNORA el hedge y firma determinista.              La mitigación contra inyección de fallos que documenta `pkcs11.rs`              NO está activa aquí."
        );
    } else {
        eprintln!("el dispositivo honra el hedge: dos firmas distintas del mismo mensaje");
    }
}

/// Buscar por etiqueta encuentra la MISMA clave que los manejadores crudos: es
/// el camino cómodo del integrador y no puede llevar a otra identidad.
#[test]
#[ignore = "necesita un módulo PKCS#11 real (QUIPU_PKCS11_MODULE); el carril `hsm` del CI la corre con --include-ignored"]
fn por_etiqueta_encuentra_la_misma_clave() {
    let _cerrojo = cerrojo();
    let Some(m) = modulo() else { return };
    let (p, slot, custodio) = preparar(&m);
    let esperada = custodio.clave_de_verificacion().unwrap().a_bytes();

    let s = p.open_rw_session(slot).expect("otra sesión");
    let por_nombre = CustodioPkcs11::por_etiqueta(s, "cnsa-firma").expect("por etiqueta");
    assert_eq!(
        por_nombre.clave_de_verificacion().unwrap().a_bytes(),
        esperada
    );

    // LA PAREJA: una etiqueta que no existe no devuelve «la primera que haya».
    let s2 = p.open_rw_session(slot).expect("otra sesión más");
    assert!(
        CustodioPkcs11::por_etiqueta(s2, "no-existe-esta-etiqueta").is_err(),
        "una etiqueta inexistente devolvió un custodio"
    );
}

/// La rama que impide «firmar con la que no era»: dos claves con la MISMA
/// etiqueta tienen que dar error, no la primera que aparezca.
///
/// El banco cubría el caso 0 (etiqueta inexistente) y no el caso n > 1, que es
/// el de consecuencia de identidad — lo señaló la revisión de seguridad.
#[test]
#[ignore = "necesita un módulo PKCS#11 real (QUIPU_PKCS11_MODULE); el carril `hsm` del CI la corre con --include-ignored"]
fn una_etiqueta_ambigua_se_niega_en_vez_de_elegir() {
    let _cerrojo = cerrojo();
    let Some(m) = modulo() else { return };
    let (p, slot, custodio) = preparar(&m);

    // Segunda clave con la MISMA etiqueta, en la sesión ya autenticada.
    let s = p.open_rw_session(slot).expect("sesión");
    s.generate_key_pair(
        &Mechanism::MlDsaKeyPairGen,
        &[
            Attribute::ParameterSet(MlDsaParameterSetType::ML_DSA_87.into()),
            Attribute::Verify(true),
            Attribute::Token(true),
            Attribute::Label(b"cnsa-firma".to_vec()),
        ],
        &[
            Attribute::Sign(true),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Label(b"cnsa-firma".to_vec()),
        ],
    )
    .expect("segunda clave con la misma etiqueta");

    let s2 = p.open_rw_session(slot).expect("otra sesión");
    match CustodioPkcs11::por_etiqueta(s2, "cnsa-firma") {
        Err(e) => eprintln!("etiqueta ambigua rechazada como debe: {e}"),
        Ok(_) => panic!("con dos claves de la misma etiqueta eligió una: puede firmar con la que no era"),
    }
    drop(custodio);
}

/// **La promesa del README, medida contra el dispositivo.** Una clave con
/// `CKA_SENSITIVE = false` se puede leer EN CLARO del token, así que «la clave
/// no sale del dispositivo» sería falso — y el custodio tiene que negarse a
/// construirse sobre ella.
///
/// Es la pareja de todo el banco: las demás pruebas usan claves con
/// `Sensitive(true)` y pasan; ésta usa la misma receta cambiando ESE bit y tiene
/// que fallar. Sin ella, la comprobación podría estar diciendo que sí a todo.
#[test]
#[ignore = "necesita un módulo PKCS#11 real (QUIPU_PKCS11_MODULE); el carril `hsm` del CI la corre con --include-ignored"]
fn una_clave_no_sensible_se_rechaza_al_construir() {
    let _cerrojo = cerrojo();
    let Some(m) = modulo() else { return };
    let (p, slot, custodio) = preparar(&m);
    drop(custodio);

    let s = p.open_rw_session(slot).expect("sesión");
    s.login(UserType::User, Some(&AuthPin::new("87654321".into()))).ok();
    let (publica, privada) = s
        .generate_key_pair(
            &Mechanism::MlDsaKeyPairGen,
            &[
                Attribute::ParameterSet(MlDsaParameterSetType::ML_DSA_87.into()),
                Attribute::Verify(true),
                Attribute::Token(true),
                Attribute::Label(b"cnsa-floja".to_vec()),
            ],
            &[
                Attribute::Sign(true),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(false), // ← el único cambio
                Attribute::Extractable(true),
                Attribute::Label(b"cnsa-floja".to_vec()),
            ],
        )
        .expect("generar una clave NO custodiada");

    match CustodioPkcs11::nuevo(s, privada, publica) {
        Err(e) => {
            let t = e.to_string();
            assert!(
                t.contains("CKA_SENSITIVE"),
                "falló, pero por otro motivo: {t}"
            );
            eprintln!("clave no custodiada rechazada como debe: {t}");
        }
        Ok(_) => panic!(
            "construyó un custodio sobre una clave cuyo valor privado se lee en claro:              la frase «no sale del dispositivo» sería falsa"
        ),
    }
}

// ===================== Soak de la directiva 8 =====================
//
// 128 operaciones, concurrencia con timeout y camino de error inyectado. El
// modelo de concurrencia no es una elección: el contexto `Pkcs11` es `Arc` y se
// comparte; la `Session` es `Send` pero NO `Sync`, así que cada hilo abre y
// posee la SUYA. Es como lo usaría un servicio.

use std::sync::mpsc;
use std::time::Duration;

/// Un hilo abre su propia sesión, firma `n` mensajes distintos y verifica cada
/// uno. Devuelve cuántas firmas verificaron.
///
/// NO hace login: en PKCS#11 el login es por APLICACIÓN, no por sesión —una
/// sesión guardiana lo mantiene vivo y esta lo hereda—. Volver a autenticar
/// daría `CKR_USER_ALREADY_LOGGED_IN`.
fn hilo_firmante(p: &'static Pkcs11, slot: cryptoki::slot::Slot, hilo: usize, n: usize) -> usize {
    let s = p.open_rw_session(slot).expect("sesión del hilo");
    let custodio = CustodioPkcs11::por_etiqueta(s, "cnsa-firma").expect("custodio por etiqueta");
    let vk = custodio.clave_de_verificacion().expect("vk");
    let mut ok = 0;
    for i in 0..n {
        let mensaje = format!("soak hilo {hilo} op {i}");
        let firma = firmar(&custodio, mensaje.as_bytes()).expect("firmar bajo carga");
        // Verifica el mensaje propio (discrimina) y RECHAZA otro.
        assert!(vk.verificar(mensaje.as_bytes(), &firma), "no verificó bajo carga");
        assert!(
            !vk.verificar(b"mensaje ajeno", &firma),
            "verificó un mensaje que no era"
        );
        ok += 1;
    }
    ok
}

/// El soak. 8 hilos x 16 firmas = 128 operaciones concurrentes, con timeout.
#[test]
#[ignore = "necesita un módulo PKCS#11 real (QUIPU_PKCS11_MODULE); el carril `hsm` del CI la corre con --include-ignored"]
fn soak_directiva8_concurrente_con_timeout() {
    let _cerrojo = cerrojo();
    let Some(m) = modulo() else { return };
    const HILOS: usize = 8;
    const POR_HILO: usize = 16; // 128 operaciones, > 100

    // Todo el soak corre en un hilo aparte con timeout: sin él, un deadlock del
    // token parecería una compilación lenta (trampa documentada del proyecto).
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let (p, slot, _custodio) = preparar(&m);
        // Sesión guardiana: mantiene el login de aplicación vivo mientras los
        // hilos trabajan. Los hilos heredan ese login sin re-autenticar.
        let guardiana = p.open_rw_session(slot).expect("sesión guardiana");
        guardiana
            .login(UserType::User, Some(&AuthPin::new("87654321".into())))
            .ok();

        // El `collect` NO es prescindible pese a lo que diga needless_collect:
        // materializa TODAS las manijas antes de empezar a hacer join, para que
        // los hilos corran en paralelo. Encadenar el iterador spawnearía y
        // uniría uno a uno, serializándolos y anulando la prueba de concurrencia.
        #[allow(clippy::needless_collect)]
        let manijas: Vec<_> = (0..HILOS)
            .map(|h| std::thread::spawn(move || hilo_firmante(p, slot, h, POR_HILO)))
            .collect();
        // join devuelve Err si un hilo entró en pánico; se propaga como 0 para
        // que el assert de abajo lo cace, sin abortar el hilo guardián.
        let total: usize = manijas.into_iter().map(|h| h.join().unwrap_or(0)).sum();
        drop(guardiana); // el login se suelta cuando ya nadie firma
        tx.send(total).ok();
    });

    match rx.recv_timeout(Duration::from_secs(180)) {
        Ok(total) => assert_eq!(
            total,
            HILOS * POR_HILO,
            "faltaron firmas: {total} de {}",
            HILOS * POR_HILO
        ),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("el soak no terminó en 180 s: posible deadlock del token")
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("un hilo del soak entró en pánico (canal cortado antes de enviar)")
        }
    }
}

/// Camino de error INYECTADO contra el dispositivo real: sin login, PKCS#11 no
/// expone las claves privadas, así que construir el custodio DEBE fallar en vez
/// de acabar firmando con una clave que no está. Es un error permanente —hay
/// que autenticarse, y reintentar la misma llamada no lo arregla—.
///
/// **EL `drop` NO ES LIMPIEZA: es lo que hace que esta prueba discrimine.** La
/// primera versión no lo tenía y el caso rojo salió VERDE firmando 4627 bytes
/// «sin autenticar», porque en PKCS#11 el login es por APLICACIÓN y no por
/// sesión: mientras la sesión de `preparar` siguiera viva —y la tenía el
/// custodio— cualquier sesión nueva heredaba su login. O sea que la prueba
/// creía haber quitado la autenticación y no había quitado nada. Soltando el
/// custodio se cierra su sesión, con ella se cae el login de la aplicación, y
/// entonces la sesión de abajo sí está a ciegas de verdad (directiva 33: el
/// caso rojo tiene que fallar por la MISMA vía que el fallo real).
#[test]
#[ignore = "necesita un módulo PKCS#11 real (QUIPU_PKCS11_MODULE); el carril `hsm` del CI la corre con --include-ignored"]
fn error_de_dispositivo_sube_en_vez_de_firmar_a_ciegas() {
    let _cerrojo = cerrojo();
    let Some(m) = modulo() else { return };
    let (p, slot, custodio) = preparar(&m);
    drop(custodio);

    // Sesión SIN login: las claves privadas no son visibles.
    let s = p.open_rw_session(slot).expect("sesión");
    match CustodioPkcs11::por_etiqueta(s, "cnsa-firma") {
        Err(e) => eprintln!("sin login, construir el custodio falla como debe: {e}"),
        Ok(custodio) => {
            // Si el módulo dejó ver la clave sin login, al menos firmar debe
            // fallar; jamás debe producir una firma silenciosa.
            match firmar(&custodio, b"sin autenticar") {
                Err(e) => eprintln!("sin login, firmar falla como debe: {e}"),
                Ok(f) => panic!(
                    "firmó {} bytes sin autenticación: el custodio no puede firmar a ciegas",
                    f.len()
                ),
            }
        }
    }
}
