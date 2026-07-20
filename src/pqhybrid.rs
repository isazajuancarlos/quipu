// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Cifrado híbrido post-cuántico: X25519 (clásico) + ML-KEM-1024 (FIPS-203).
//!
//! Combina DOS secretos compartidos (uno clásico, uno post-cuántico) vía HKDF
//! en una única clave de contenido de 32 bytes. Resistente a "harvest now,
//! decrypt later": un atacante tendría que romper AMBOS para recuperar la clave.
//!
//! Es un modo ASIMÉTRICO (cifrar a una clave pública del destinatario),
//! complementario al modo simétrico basado en passphrase.

use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
// `ExpandedKeyEncoding` está marcada obsoleta por `ml-kem`, y se usa a
// propósito: es la ÚNICA forma de leer las claves secretas que Quipu escribió
// hasta 0.8.0. Para eso existe una API obsoleta — para no dejar tirado a quien
// ya guardó algo. Se usa solo al LEER; al escribir siempre sale el formato
// nuevo, así que cada clave que pase por aquí queda migrada.
#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;
use ml_kem::{Kem, Key, KeyExport, KeyInit, MlKem1024};

use crate::aleatorio::{self, SinEntropia};
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};
use zeroize::{Zeroize, Zeroizing};

type MlEk = <MlKem1024 as Kem>::EncapsulationKey;
type MlDk = <MlKem1024 as Kem>::DecapsulationKey;

/// Longitud de la clave pública X25519.
pub const X25519_PUB_LEN: usize = 32;
/// Longitud de la clave de encapsulación ML-KEM-1024.
pub const MLKEM_EK_LEN: usize = 1568;
/// Longitud del ciphertext (encapsulación) ML-KEM-1024.
pub const MLKEM_CT_LEN: usize = 1568;
/// Longitud de la encapsulación híbrida (eph X25519 pub || ML-KEM ct).
pub const ENCAPSULATION_LEN: usize = X25519_PUB_LEN + MLKEM_CT_LEN;
/// Longitud de la clave pública híbrida serializada.
pub const PUBLIC_KEY_LEN: usize = X25519_PUB_LEN + MLKEM_EK_LEN;
/// Longitud de la SEMILLA de decapsulación ML-KEM-1024 (formato actual).
///
/// `ml-kem` 0.3 serializa la clave de decapsulación como la semilla de 64 bytes
/// de la que se deriva, en vez de la forma expandida de 3168. La expandida
/// quedó marcada como obsoleta en el propio crate.
pub const MLKEM_DK_LEN: usize = 64;
/// Longitud de la clave de decapsulación ML-KEM-1024 en el formato ANTERIOR,
/// el que escribía Quipu hasta 0.8.0 inclusive.
pub const MLKEM_DK_LEN_EXPANDIDA: usize = 3168;
/// Longitud de la clave secreta híbrida serializada (formato actual).
pub const SECRET_KEY_LEN: usize = X25519_PUB_LEN + MLKEM_DK_LEN;
/// Longitud de la clave secreta híbrida en el formato anterior.
///
/// Se sigue LEYENDO para no dejar inservible ninguna clave ya guardada: una
/// clave secreta es lo único que el usuario no puede regenerar sin perder todo
/// lo cifrado hacia ella. Se escribe siempre en el formato actual.
pub const SECRET_KEY_LEN_ANTERIOR: usize = X25519_PUB_LEN + MLKEM_DK_LEN_EXPANDIDA;
/// Longitud de la clave de contenido derivada.
pub const CONTENT_KEY_LEN: usize = 32;

const HKDF_INFO: &[u8] = b"quipu/v2/hybrid-kem";

/// Clave pública híbrida del destinatario.
pub struct PublicKey {
    x: XPublic,
    ml: MlEk,
}

/// Clave secreta híbrida del destinatario.
pub struct SecretKey {
    x: XSecret,
    ml: MlDk,
}

/// Genera un par de claves híbrido.
///
/// Dispara la autoprueba de arranque una vez por proceso: ninguna clave debe
/// nacer de un módulo roto. Se engancha aquí, y no en el camino caliente,
/// porque generar claves ya es caro y raro — 12 ms una sola vez no se notan.
pub fn generate_keypair() -> Result<(PublicKey, SecretKey), SinEntropia> {
    crate::selftest::ensure();
    generate_keypair_unchecked()
}

/// Igual que [`generate_keypair`] pero **sin** disparar la autoprueba.
///
/// Existe solo para que `selftest` pueda generar claves DENTRO de la propia
/// autoprueba: `Once::call_once` no es reentrante, así que llamar a la versión
/// pública desde ahí bloquearía la hebra para siempre esperando una
/// inicialización que ella misma está haciendo.
pub(crate) fn generate_keypair_unchecked() -> Result<(PublicKey, SecretKey), SinEntropia> {
    // UN solo generador para las dos mitades: la entropía se pide una vez, se
    // comprueba una vez, y de ahí salen ambas claves. Pedirla dos veces
    // duplicaría el punto de fallo sin ganar nada.
    let mut rng = aleatorio::generador()?;
    let x_secret = XSecret::random_from_rng(&mut rng);
    let x_public = XPublic::from(&x_secret);
    let (ml_dk, ml_ek) = MlKem1024::generate_keypair_from_rng(&mut rng);
    Ok((
        PublicKey {
            x: x_public,
            ml: ml_ek,
        },
        SecretKey {
            x: x_secret,
            ml: ml_dk,
        },
    ))
}

impl PublicKey {
    /// Serializa la clave pública (X25519 pub || ML-KEM ek).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(PUBLIC_KEY_LEN);
        v.extend_from_slice(self.x.as_bytes());
        v.extend_from_slice(&self.ml.to_bytes());
        v
    }

    /// Reconstruye la clave pública desde bytes.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != PUBLIC_KEY_LEN {
            return None;
        }
        let x_bytes: [u8; 32] = b[0..32].try_into().ok()?;
        let x = XPublic::from(x_bytes);
        let ml_encoded = Key::<MlEk>::try_from(&b[32..]).ok()?;
        let ml = MlEk::new(&ml_encoded).ok()?;
        Some(Self { x, ml })
    }
}

impl SecretKey {
    /// Serializa la clave secreta (X25519 secret || ML-KEM dk). Devuelve un
    /// `Zeroizing`: el buffer se borra al soltarse, igual que en `pqsign`, para
    /// no dejar la serialización del secreto en RAM (paridad de higiene entre
    /// módulos). `Zeroizing<Vec<u8>>` deref-ea a `&[u8]`, así que los usos
    /// existentes (PyBytes, `from_bytes`, `.len()`) siguen compilando.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Vec::with_capacity(SECRET_KEY_LEN);
        v.extend_from_slice(&self.x.to_bytes());
        v.extend_from_slice(&self.ml.to_bytes());
        Zeroizing::new(v)
    }

    /// Reconstruye la clave secreta desde bytes, en cualquiera de los dos
    /// formatos.
    ///
    /// # Por qué se leen los dos
    ///
    /// `ml-kem` 0.3 cambió la serialización de la clave de decapsulación: de la
    /// forma expandida (3168 bytes) a la semilla (64). Escribir solo el formato
    /// nuevo y leer solo el formato nuevo habría dejado ilegible **toda clave
    /// guardada con Quipu 0.8.0 o anterior**.
    ///
    /// Y una clave secreta no es un dato cualquiera: es lo único que el usuario
    /// no puede regenerar. Si la pierde, pierde todo lo que se cifró hacia
    /// ella. Romperla en silencio habría sido el peor fallo posible de esta
    /// migración, y encima uno que no aparece hasta que alguien intenta
    /// descifrar algo viejo.
    ///
    /// Se LEEN los dos, se ESCRIBE el actual. La longitud discrimina sin
    /// ambigüedad: 96 contra 3200 bytes.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let x_bytes: [u8; 32] = b.get(0..32)?.try_into().ok()?;
        let x = XSecret::from(x_bytes);
        let ml = match b.len() {
            SECRET_KEY_LEN => {
                let semilla = Key::<MlDk>::try_from(&b[32..]).ok()?;
                MlDk::new(&semilla)
            }
            SECRET_KEY_LEN_ANTERIOR => {
                let expandida = ml_kem::ExpandedDecapsulationKey::<MlKem1024>::try_from(&b[32..])
                    .ok()?;
                #[allow(deprecated)]
                let dk = MlDk::from_expanded_bytes(&expandida).ok()?;
                dk
            }
            _ => return None,
        };
        Some(Self { x, ml })
    }
}

/// Encapsula: produce una clave de contenido y la encapsulación que el
/// destinatario usará para recuperarla.
pub fn encapsulate(pk: &PublicKey) -> Result<([u8; CONTENT_KEY_LEN], Vec<u8>), SinEntropia> {
    let mut rng = aleatorio::generador()?;

    // Parte clásica: X25519 efímero.
    let eph = XSecret::random_from_rng(&mut rng);
    let eph_pub = XPublic::from(&eph);
    let x_ss = eph.diffie_hellman(&pk.x);

    // Parte post-cuántica: ML-KEM.
    let (ml_ct, ml_ss) = pk.ml.encapsulate_with_rng(&mut rng);

    let mut encapsulation = Vec::with_capacity(ENCAPSULATION_LEN);
    encapsulation.extend_from_slice(eph_pub.as_bytes());
    encapsulation.extend_from_slice(&ml_ct);

    // F2: liga la clave pública COMPLETA del destinatario (X25519 + ML-KEM ek)
    // al transcript (estilo X-Wing). Ligar la `ek` impide que un atacante que
    // sustituya la `ek` en tránsito produzca la misma clave de contenido.
    let transcript = build_transcript(pk.x.as_bytes(), &pk.ml.to_bytes(), &encapsulation);

    let key = combine(x_ss.as_bytes(), &ml_ss, &transcript);
    Ok((key, encapsulation))
}

/// Decapsula con la clave secreta del destinatario.
pub fn decapsulate(sk: &SecretKey, encapsulation: &[u8]) -> Option<[u8; CONTENT_KEY_LEN]> {
    if encapsulation.len() != ENCAPSULATION_LEN {
        return None;
    }
    let eph_bytes: [u8; 32] = encapsulation[0..32].try_into().ok()?;
    let eph_pub = XPublic::from(eph_bytes);
    let x_ss = sk.x.diffie_hellman(&eph_pub);

    let ml_ct = ml_kem::Ciphertext::<MlKem1024>::try_from(&encapsulation[32..]).ok()?;
    let ml_ss = sk.ml.decapsulate(&ml_ct);

    // F2: reconstruye el mismo transcript con la clave pública COMPLETA del
    // destinatario. La `ek` de ML-KEM se recomputa desde la `dk`.
    let recipient_x_pub = XPublic::from(&sk.x);
    let recipient_ek = sk.ml.encapsulation_key().to_bytes();
    let transcript = build_transcript(recipient_x_pub.as_bytes(), &recipient_ek, encapsulation);

    Some(combine(x_ss.as_bytes(), &ml_ss, &transcript))
}

/// Transcript ligado a la derivación: clave pública completa del destinatario
/// (X25519 pub || ML-KEM ek) seguida de la encapsulación (eph pub || ML-KEM ct).
fn build_transcript(recipient_x_pub: &[u8], recipient_ek: &[u8], encapsulation: &[u8]) -> Vec<u8> {
    let mut t = Vec::with_capacity(recipient_x_pub.len() + recipient_ek.len() + encapsulation.len());
    t.extend_from_slice(recipient_x_pub);
    t.extend_from_slice(recipient_ek);
    t.extend_from_slice(encapsulation);
    t
}

/// Combinador híbrido: HKDF-SHA256 sobre (ss_clásico || ss_pq), ligando el
/// transcript como contexto.
fn combine(x_ss: &[u8], ml_ss: &[u8], transcript: &[u8]) -> [u8; CONTENT_KEY_LEN] {
    let mut ikm = Vec::with_capacity(x_ss.len() + ml_ss.len());
    ikm.extend_from_slice(x_ss);
    ikm.extend_from_slice(ml_ss);

    let mut info = HKDF_INFO.to_vec();
    info.extend_from_slice(transcript);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut out = [0u8; CONTENT_KEY_LEN];
    hk.expand(&info, &mut out).expect("longitud HKDF válida");
    // O5: borra el material de clave intermedio (ss combinados).
    ikm.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameters_are_cnsa_level5() {
        // CNSA 2.0 (NSA) exige ML-KEM-1024 = categoría de seguridad NIST 5.
        // Fija los tamaños FIPS-203 del nivel 5 para detectar cualquier
        // regresión de parámetros.
        //
        // OJO con qué se comprueba: la SEMILLA mide 64 bytes en ML-KEM-512, 768
        // y 1024 por igual, así que desde `ml-kem` 0.3 la longitud de `dk`
        // serializada YA NO distingue el nivel. Antes sí, y por eso esta prueba
        // la usaba. Se comprueba donde sigue discriminando: `ek`, el ciphertext
        // y la clave expandida.
        #[allow(deprecated)]
        use ml_kem::ExpandedKeyEncoding;
        assert_eq!(MLKEM_EK_LEN, 1568, "ek ML-KEM-1024");
        assert_eq!(MLKEM_CT_LEN, 1568, "ciphertext ML-KEM-1024");
        assert_eq!(MLKEM_DK_LEN_EXPANDIDA, 3168, "dk expandida ML-KEM-1024");

        // Y contra la implementación, no solo contra las constantes: una
        // constante que se cambia a mano no detecta nada.
        let (pk, sk) = generate_keypair().unwrap();
        assert_eq!(pk.ml.to_bytes().len(), MLKEM_EK_LEN);
        #[allow(deprecated)]
        let expandida = sk.ml.to_expanded_bytes();
        assert_eq!(expandida.len(), MLKEM_DK_LEN_EXPANDIDA);
    }

    #[test]
    fn kem_round_trip_recovers_shared_secret() {
        let (pk, sk) = generate_keypair().unwrap();
        let (key1, enc) = encapsulate(&pk).unwrap();
        assert_eq!(enc.len(), ENCAPSULATION_LEN);
        let key2 = decapsulate(&sk, &enc).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn wrong_secret_key_yields_different_key() {
        let (pk, _sk) = generate_keypair().unwrap();
        let (_pk2, sk2) = generate_keypair().unwrap();
        let (key1, enc) = encapsulate(&pk).unwrap();
        // ML-KEM usa rechazo implícito: no falla, pero da una clave distinta.
        let key2 = decapsulate(&sk2, &enc).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn secret_key_serialization_round_trips() {
        let (pk, sk) = generate_keypair().unwrap();
        let (key1, enc) = encapsulate(&pk).unwrap();
        let sk_bytes = sk.to_bytes();
        assert_eq!(sk_bytes.len(), SECRET_KEY_LEN);
        let sk2 = SecretKey::from_bytes(&sk_bytes).unwrap();
        // La sk reconstruida debe decapsular igual.
        assert_eq!(decapsulate(&sk2, &enc).unwrap(), key1);
    }

    #[test]
    fn lee_una_clave_secreta_del_formato_anterior() {
        // La prueba que de verdad protege al usuario: una clave guardada con
        // Quipu 0.8.0 —forma expandida, 3200 bytes— tiene que seguir
        // descifrando. Sin esto, actualizar la librería habría destruido en
        // silencio todo lo cifrado hacia claves ya emitidas.
        #[allow(deprecated)]
        use ml_kem::ExpandedKeyEncoding;
        let (pk, sk) = generate_keypair().unwrap();
        let (clave, enc) = encapsulate(&pk).unwrap();

        // Se fabrica la serialización ANTIGUA a mano: X25519 || dk expandida.
        let mut antigua = Vec::with_capacity(SECRET_KEY_LEN_ANTERIOR);
        antigua.extend_from_slice(&sk.x.to_bytes());
        #[allow(deprecated)]
        let dk_expandida = sk.ml.to_expanded_bytes();
        antigua.extend_from_slice(&dk_expandida);
        assert_eq!(antigua.len(), SECRET_KEY_LEN_ANTERIOR);

        let recuperada = SecretKey::from_bytes(&antigua)
            .expect("una clave del formato anterior debe seguir leyéndose");
        assert_eq!(decapsulate(&recuperada, &enc).unwrap(), clave);
    }

    #[test]
    fn se_escribe_siempre_el_formato_nuevo() {
        // Leer los dos, escribir uno. Si esto dejara de cumplirse tendríamos
        // dos formatos vivos en vez de una migración.
        let (_pk, sk) = generate_keypair().unwrap();
        assert_eq!(sk.to_bytes().len(), SECRET_KEY_LEN);
        assert_ne!(SECRET_KEY_LEN, SECRET_KEY_LEN_ANTERIOR);
    }

    #[test]
    fn una_longitud_que_no_es_de_ningun_formato_se_rechaza() {
        assert!(SecretKey::from_bytes(&[0u8; 100]).is_none());
        assert!(SecretKey::from_bytes(&[]).is_none());
    }

    #[test]
    fn recomputed_ek_from_dk_matches_original() {
        // El destinatario debe poder reconstruir el transcript ligando su `ek`,
        // recomputándola desde su `dk`. Si no coincidiera, decapsulate fallaría.
        let (pk, sk) = generate_keypair().unwrap();
        assert_eq!(sk.ml.encapsulation_key().to_bytes(), pk.ml.to_bytes());
    }

    #[test]
    fn public_key_serialization_round_trips() {
        let (pk, _sk) = generate_keypair().unwrap();
        let bytes = pk.to_bytes();
        assert_eq!(bytes.len(), PUBLIC_KEY_LEN);
        let pk2 = PublicKey::from_bytes(&bytes).unwrap();
        // Verifica que la pública reconstruida encapsula hacia la misma sk.
        assert_eq!(pk2.to_bytes(), bytes);
    }
}
