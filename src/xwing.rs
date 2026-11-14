// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

//! **X-Wing-768**: KEM híbrido PQ/T **wire-compatible** con
//! `draft-connolly-cfrg-xwing-kem` (verificado contra **draft-10**, 2026-03-02,
//! *Informational*). X25519 + ML-KEM-768, combinador `SHA3-256`.
//!
//! # Qué es, y en qué se DIFERENCIA del canal a destinatario del núcleo
//!
//! El modo asimétrico de quipu ([`crate::pqhybrid`], `encode_to_recipient`) es
//! **X-Wing-*style* pero NO interoperable**: usa ML-KEM-**1024** (CNSA 2.0, nivel
//! 5) y un combinador `HKDF-SHA256` con transcript propio. Este módulo es lo
//! contrario: la construcción **exacta** del estándar —ML-KEM-**768** y el
//! combinador `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label)`— para
//! **interoperar** byte a byte con otras implementaciones de X-Wing.
//!
//! No es un «modo» del contenedor de quipu (no entra por `api.rs`) **a
//! propósito**: el valor de interoperabilidad vive en la frontera del KEM —el
//! secreto compartido de 32 bytes—, no en envolverlo en el contenedor propio de
//! quipu, que ninguna otra herramienta sabe leer. Quien quiera interoperar toma
//! el `ss` de aquí y lo mete en su propio AEAD.
//!
//! **No inventa criptografía** (regla del proyecto): compone primitivas ya
//! vendorizadas —`ml-kem` (`MlKem768`), `x25519-dalek` y `sha3`—.
//!
//! # Modelo de amenaza / notas
//!
//! - La clave secreta ES una **semilla uniforme de 32 bytes** (no se deriva de
//!   una frase); de ella se expanden con SHAKE256 las dos mitades. Igual que en
//!   X-Wing: `sk` es la semilla, y `pk` se recomputa de ella.
//! - `ss_M` de ML-KEM usa **rechazo implícito**: una `ct` corrupta no falla,
//!   produce un secreto distinto (y el AEAD de arriba será quien lo detecte).
//! - Resistente a *harvest-now-decrypt-later*: romper `ss` exige romper **las
//!   dos** mitades (X25519 y ML-KEM-768).

use crate::aleatorio::{self, SinEntropia};
use ml_kem::kem::Decapsulate;
use ml_kem::{B32, Kem, Key, KeyExport, KeyInit, MlKem768};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Shake256};
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};
use zeroize::{Zeroize, Zeroizing};

type MlEk = <MlKem768 as Kem>::EncapsulationKey;
type MlDk = <MlKem768 as Kem>::DecapsulationKey;

/// Etiqueta de dominio de X-Wing (§5.3 del draft): los 6 bytes ASCII `\.//^\`.
pub const XWING_LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

/// Longitud de la semilla secreta (la `sk` de X-Wing).
pub const SECRET_SEED_LEN: usize = 32;
/// Longitud de la clave de encapsulación de ML-KEM-768.
const MLKEM768_EK_LEN: usize = 1184;
/// Longitud del ciphertext de ML-KEM-768.
const MLKEM768_CT_LEN: usize = 1088;
/// Longitud de una clave pública/ciphertext X25519.
const X25519_LEN: usize = 32;
/// Longitud de la clave pública X-Wing (`pk_M ‖ pk_X`).
pub const PUBLIC_KEY_LEN: usize = MLKEM768_EK_LEN + X25519_LEN; // 1216
/// Longitud del ciphertext X-Wing (`ct_M ‖ ct_X`).
pub const CIPHERTEXT_LEN: usize = MLKEM768_CT_LEN + X25519_LEN; // 1120
/// Longitud del secreto compartido.
pub const SHARED_SECRET_LEN: usize = 32;
/// Longitud de la aleatoriedad de encapsulación derandomizada (`m ‖ ek_X`).
pub const ENCAPS_SEED_LEN: usize = 64;

/// Errores de X-Wing que NO son falta de entropía (parseo de material).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XWingError {
    /// La entropía del sistema no alcanzó (solo en los caminos aleatorios).
    SinEntropia,
    /// La clave pública no mide [`PUBLIC_KEY_LEN`] o su mitad ML-KEM no decodifica.
    ClavePublicaInvalida,
    /// El ciphertext no mide [`CIPHERTEXT_LEN`] o su mitad ML-KEM no decodifica.
    CiphertextInvalido,
}

impl From<SinEntropia> for XWingError {
    fn from(_: SinEntropia) -> Self {
        XWingError::SinEntropia
    }
}

/// Expande la semilla secreta en sus dos mitades (SHAKE256 → 96 bytes):
/// `[0:64]` es la semilla `(d ‖ z)` de ML-KEM-768 y `[64:96]` el escalar X25519.
/// Devuelve también `pk_X`, que el combinador liga.
fn expandir(seed: &[u8; SECRET_SEED_LEN]) -> (MlDk, XSecret, [u8; X25519_LEN]) {
    let mut xof = Shake256::default();
    xof.update(seed);
    let mut lector = xof.finalize_xof();
    let mut expandida = Zeroizing::new([0u8; 96]);
    lector.read(&mut expandida[..]);

    // ML-KEM-768.KeyGen(expanded[0:64]): la semilla (d ‖ z) de 64 bytes. Esa copia
    // que `try_from` saca de `expandida` es la dk ML-KEM ENTERA (material secreto),
    // y no la cubre `limpiar_pila()` en el camino de keygen; se borra a mano tras
    // construir la clave.
    let mut semilla_ml = Key::<MlDk>::try_from(&expandida[0..64])
        .expect("64 bytes es la longitud exacta de la semilla de MlKem768");
    let ml_dk = MlDk::new(&semilla_ml);
    Zeroize::zeroize(&mut semilla_ml[..]);

    // El escalar X25519 es secreto: la copia plana va en `Zeroizing`. Higiene T6,
    // paridad con `pqhybrid`. NOTA HONESTA: `XSecret::from(*skx)` deref-copia el
    // escalar a un temporal de pila (el `XSecret` resultante SÍ se borra al soltarse
    // —`x25519-dalek` es ZeroizeOnDrop—, el temporal no); anclar esto a cero exige
    // un caso de `residuo_memoria` para `xwing`, aún no escrito.
    let mut skx = Zeroizing::new([0u8; X25519_LEN]);
    skx.copy_from_slice(&expandida[64..96]);
    let x_secret = XSecret::from(*skx);
    let pk_x = *XPublic::from(&x_secret).as_bytes();
    (ml_dk, x_secret, pk_x)
}

/// El combinador de X-Wing (§5.3): `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label)`.
fn combinar(
    ss_m: &[u8],
    ss_x: &[u8; 32],
    ct_x: &[u8; 32],
    pk_x: &[u8; 32],
) -> [u8; SHARED_SECRET_LEN] {
    let salida = Sha3_256::new()
        .chain_update(ss_m)
        .chain_update(ss_x)
        .chain_update(ct_x)
        .chain_update(pk_x)
        .chain_update(XWING_LABEL)
        .finalize();
    let mut ss = [0u8; SHARED_SECRET_LEN];
    ss.copy_from_slice(&salida);
    ss
}

/// Recomputa la clave pública X-Wing a partir de la semilla secreta.
pub fn clave_publica_desde_semilla(seed: &[u8; SECRET_SEED_LEN]) -> [u8; PUBLIC_KEY_LEN] {
    let (ml_dk, _x_secret, pk_x) = expandir(seed);
    let ek = ml_dk.encapsulation_key().to_bytes();
    let mut pk = [0u8; PUBLIC_KEY_LEN];
    pk[0..MLKEM768_EK_LEN].copy_from_slice(&ek);
    pk[MLKEM768_EK_LEN..].copy_from_slice(&pk_x);
    pk
}

/// Genera un par de claves X-Wing: `(sk_seed, pk)`. La semilla sale del sistema
/// (uniforme), y `pk` se deriva de ella.
pub fn generar_par() -> Result<(Zeroizing<[u8; SECRET_SEED_LEN]>, [u8; PUBLIC_KEY_LEN]), SinEntropia>
{
    let seed = Zeroizing::new(aleatorio::bytes::<SECRET_SEED_LEN>()?);
    let pk = clave_publica_desde_semilla(&seed);
    Ok((seed, pk))
}

/// Encapsula hacia `pk` con aleatoriedad **explícita** `eseed` (`m ‖ ek_X`).
///
/// Camino determinista, **solo para las pruebas de vectores (KAT)**. Es
/// `pub(crate)` a propósito y NO forma parte de la API pública: reutilizar un
/// `eseed` entre dos encapsulaciones rompe la confidencialidad de las dos (mismo
/// `m` → mismo `ss_M`; mismo `ek_X` → mismo `ss_X`), así que exponer la
/// aleatoriedad al llamante es un footgun. Fuera del crate se usa [`encapsular`],
/// que la toma del sistema.
pub(crate) fn encapsular_derand(
    pk: &[u8],
    eseed: &[u8; ENCAPS_SEED_LEN],
) -> Result<([u8; SHARED_SECRET_LEN], [u8; CIPHERTEXT_LEN]), XWingError> {
    if pk.len() != PUBLIC_KEY_LEN {
        return Err(XWingError::ClavePublicaInvalida);
    }
    let ek_encoded =
        Key::<MlEk>::try_from(&pk[0..MLKEM768_EK_LEN]).map_err(|_| XWingError::ClavePublicaInvalida)?;
    let ml_ek = MlEk::new(&ek_encoded).map_err(|_| XWingError::ClavePublicaInvalida)?;
    let pk_x_bytes: [u8; 32] = pk[MLKEM768_EK_LEN..]
        .try_into()
        .map_err(|_| XWingError::ClavePublicaInvalida)?;
    let pk_x = XPublic::from(pk_x_bytes);

    // ML-KEM-768.EncapsDerand(pk_M, eseed[0:32]). `m` es aleatoriedad secreta
    // (con `pk` recomputa `ss_M`); se borra en cuanto ML-KEM la consume.
    let mut m = B32::try_from(&eseed[0..32]).expect("32 bytes es B32");
    let (ml_ct, mut ml_ss) = ml_ek.encapsulate_deterministic(&m);
    Zeroize::zeroize(&mut m[..]);

    // X25519 efímero: ek_X = eseed[32:64]. ct_X = X25519(ek_X, base). El escalar
    // efímero es secreto y vive en el marco PROPIO de esta función, que
    // `limpiar_pila()` no puede pisar (barre por debajo de quien la llama); por
    // eso la copia plana va en `Zeroizing` y se borra al soltarla (higiene T6).
    let mut ekx = Zeroizing::new([0u8; X25519_LEN]);
    ekx.copy_from_slice(&eseed[32..64]);
    let eph = XSecret::from(*ekx);
    let ct_x = *XPublic::from(&eph).as_bytes();
    let ss_x = eph.diffie_hellman(&pk_x);

    let ss = combinar(ml_ss.as_slice(), ss_x.as_bytes(), &ct_x, &pk_x_bytes);
    // `ml_ss` es el secreto compartido de ML-KEM en claro: se borra tras combinar.
    Zeroize::zeroize(&mut ml_ss[..]);

    let mut ct = [0u8; CIPHERTEXT_LEN];
    ct[0..MLKEM768_CT_LEN].copy_from_slice(&ml_ct);
    ct[MLKEM768_CT_LEN..].copy_from_slice(&ct_x);

    crate::antihacker::limpiar_pila();
    Ok((ss, ct))
}

/// Encapsula hacia `pk`, tomando la aleatoriedad del sistema. Enruta por
/// [`encapsular_derand`] para no duplicar el camino criptográfico (un solo
/// sitio que auditar).
pub fn encapsular(
    pk: &[u8],
) -> Result<([u8; SHARED_SECRET_LEN], [u8; CIPHERTEXT_LEN]), XWingError> {
    let eseed = Zeroizing::new(aleatorio::bytes::<ENCAPS_SEED_LEN>()?);
    encapsular_derand(pk, &eseed)
}

/// Decapsula con la semilla secreta del destinatario. Rechazo implícito: una
/// `ct` corrupta produce un secreto distinto en vez de fallar.
pub fn decapsular(
    seed: &[u8; SECRET_SEED_LEN],
    ct: &[u8],
) -> Result<[u8; SHARED_SECRET_LEN], XWingError> {
    if ct.len() != CIPHERTEXT_LEN {
        return Err(XWingError::CiphertextInvalido);
    }
    let (ml_dk, x_secret, pk_x_bytes) = expandir(seed);

    let ml_ct = ml_kem::Ciphertext::<MlKem768>::try_from(&ct[0..MLKEM768_CT_LEN])
        .map_err(|_| XWingError::CiphertextInvalido)?;
    let mut ml_ss = ml_dk.decapsulate(&ml_ct);

    let ct_x_bytes: [u8; 32] = ct[MLKEM768_CT_LEN..]
        .try_into()
        .map_err(|_| XWingError::CiphertextInvalido)?;
    let ct_x = XPublic::from(ct_x_bytes);
    let ss_x = x_secret.diffie_hellman(&ct_x);

    let ss = combinar(ml_ss.as_slice(), ss_x.as_bytes(), &ct_x_bytes, &pk_x_bytes);
    // `ml_ss` (secreto compartido de ML-KEM en claro) se borra tras combinar.
    Zeroize::zeroize(&mut ml_ss[..]);
    crate::antihacker::limpiar_pila();
    Ok(ss)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Parsea hex de los vectores (solo pruebas).
    fn hx(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// **KAT de conformidad** (Apéndice C del draft-10, primer vector).
    ///
    /// Se anclan los TRES artefactos del cable, no solo el secreto:
    /// - `pk` (1216 B) y `ct` (1120 B) completos contra los vectores de referencia
    ///   → esto fija la CODIFICACIÓN en el cable (orden `pk_M‖pk_X`, `ct_M‖ct_X`),
    ///   que el `ss` por sí solo NO ancla (el `ss` solo depende de los campos
    ///   extraídos, no de cómo se empaquetan los blobs). Sin este anclaje, un
    ///   intercambio simétrico del orden pasaría el KAT en verde y rompería la
    ///   interoperabilidad —el único propósito del módulo— (directiva 33).
    /// - `ss` (32 B) → ancla expansión de semilla + ML-KEM-768 + X25519 +
    ///   combinador + etiqueta.
    ///
    /// Los tres son artefactos de la referencia (IETF), no algo que yo fabrique
    /// (directiva 30/31). Los hex viven en `tests/vectors/` para no inflar la fuente.
    #[test]
    fn kat_apendice_c_primer_vector() {
        let seed: [u8; 32] = hx("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
            .try_into()
            .unwrap();
        let eseed: [u8; 64] = hx(
            "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2\
             35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2",
        )
        .try_into()
        .unwrap();
        let ss_esperado =
            hx("d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384");
        // Vectores del cable (Apéndice C, primer vector), bajados de la IETF.
        let pk_esperado = hx(include_str!("../tests/vectors/xwing_appendix_c_v1_pk.hex"));
        let ct_esperado = hx(include_str!("../tests/vectors/xwing_appendix_c_v1_ct.hex"));

        let pk = clave_publica_desde_semilla(&seed);
        assert_eq!(
            pk.as_slice(),
            pk_esperado.as_slice(),
            "la clave pública NO coincide con el vector → codificación no conformante"
        );

        let (ss, ct) = encapsular_derand(&pk, &eseed).unwrap();
        assert_eq!(
            ct.as_slice(),
            ct_esperado.as_slice(),
            "el ciphertext NO coincide con el vector → codificación no conformante"
        );
        assert_eq!(
            ss.as_slice(),
            ss_esperado.as_slice(),
            "el secreto compartido NO coincide con el KAT de X-Wing draft-10 → NO conformante"
        );
        // Y el destinatario recupera el mismo secreto de su ct.
        let ss_dec = decapsular(&seed, &ct).unwrap();
        assert_eq!(ss_dec, ss, "round-trip: decapsular no reprodujo el secreto");
    }

    /// Caso ROJO del KAT: si la etiqueta de dominio cambia un byte, el combinador
    /// da otro secreto y el KAT DEBE romperse. Prueba que la aguja discrimina
    /// (directiva 33): sin esto, un combinador con la etiqueta mal saldría verde.
    #[test]
    fn kat_rojo_etiqueta_distinta_no_coincide() {
        let ss_m = [1u8; 32];
        let ss_x = [2u8; 32];
        let ct_x = [3u8; 32];
        let pk_x = [4u8; 32];
        let bueno = combinar(&ss_m, &ss_x, &ct_x, &pk_x);
        // Mismo cómputo pero con la etiqueta equivocada, a mano.
        let malo = Sha3_256::new()
            .chain_update(ss_m)
            .chain_update(ss_x)
            .chain_update(ct_x)
            .chain_update(pk_x)
            .chain_update([0x00u8; 6]) // etiqueta equivocada
            .finalize();
        assert_ne!(
            bueno.as_slice(),
            malo.as_slice(),
            "el combinador debe depender de la etiqueta de dominio"
        );
    }

    /// Round-trip con claves ALEATORIAS (100 pares): encapsular/decapsular deben
    /// coincidir siempre, y una ct manipulada NO debe reproducir el secreto.
    #[test]
    fn round_trip_aleatorio_y_ct_manipulada() {
        for _ in 0..100 {
            let (seed, pk) = generar_par().unwrap();
            let (ss, mut ct) = encapsular(&pk).unwrap();
            let ss_dec = decapsular(&seed, &ct).unwrap();
            assert_eq!(ss, ss_dec, "round-trip básico");

            // Manipular el ct_X (parte X25519) cambia ss_X → secreto distinto.
            ct[CIPHERTEXT_LEN - 1] ^= 0x01;
            let ss_malo = decapsular(&seed, &ct).unwrap();
            assert_ne!(ss, ss_malo, "una ct manipulada no puede dar el mismo secreto");
        }
    }

    #[test]
    fn tamanos_del_estandar() {
        assert_eq!(PUBLIC_KEY_LEN, 1216);
        assert_eq!(CIPHERTEXT_LEN, 1120);
        assert_eq!(SHARED_SECRET_LEN, 32);
        assert_eq!(SECRET_SEED_LEN, 32);
        let (seed, pk) = generar_par().unwrap();
        assert_eq!(pk.len(), PUBLIC_KEY_LEN);
        let (_ss, ct) = encapsular(&pk).unwrap();
        assert_eq!(ct.len(), CIPHERTEXT_LEN);
        assert_eq!(seed.len(), SECRET_SEED_LEN);
    }

    #[test]
    fn pk_y_ct_mal_dimensionados_fallan() {
        assert_eq!(
            encapsular(&[0u8; 10]).unwrap_err(),
            XWingError::ClavePublicaInvalida
        );
        let (seed, _pk) = generar_par().unwrap();
        assert_eq!(
            decapsular(&seed, &[0u8; 10]).unwrap_err(),
            XWingError::CiphertextInvalido
        );
    }

    /// Caso ROJO §7.2 (MUST del draft): una `ek` de ML-KEM con un coeficiente
    /// ≥ q=3329 debe rechazarse. Poner los 1152 bytes de coeficientes a `0xff`
    /// hace cada coeficiente de 12 bits = 0xfff (4095) ≥ q. Si una versión futura
    /// de `ml-kem` relajara esta comprobación, este caso se pondría rojo.
    #[test]
    fn ek_fuera_de_rango_rechazada() {
        let (_seed, mut pk) = generar_par().unwrap();
        for b in &mut pk[0..MLKEM768_EK_LEN - 32] {
            *b = 0xff; // solo la parte de coeficientes, no el rho final de 32 B
        }
        assert_eq!(
            encapsular(&pk).unwrap_err(),
            XWingError::ClavePublicaInvalida,
            "una ek con coeficiente >= q debe rechazarse (draft §7.2)"
        );
    }

    /// Caso ROJO del rechazo implícito de ML-KEM: manipular un byte de `ct_M`
    /// (no de `ct_X`) debe dar un secreto DISTINTO, no fallar. Complementa al
    /// round-trip, que solo voltea `ct_X`.
    #[test]
    fn ct_m_manipulada_da_secreto_distinto() {
        let (seed, pk) = generar_par().unwrap();
        let (ss, mut ct) = encapsular(&pk).unwrap();
        ct[0] ^= 0x01; // primer byte de ct_M
        let ss_malo = decapsular(&seed, &ct).unwrap();
        assert_ne!(
            ss, ss_malo,
            "manipular ct_M debe cambiar el secreto (rechazo implícito de ML-KEM)"
        );
    }
}
