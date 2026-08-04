// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Canal de destinatario con **ML-KEM-1024 puro**, que es lo que CNSA 2.0 pide.
//!
//! Cifrar para alguien que solo publicó una clave pública: se encapsula una
//! clave de contenido con ML-KEM-1024 y con ella se cifra el mensaje en
//! AES-256-GCM. Sin contraseña y sin canal previo.
//!
//! # PURO, y eso es MÁS DÉBIL que `quipu`. Léase antes de elegir.
//!
//! `quipu` usa un KEM **híbrido**, X25519 **y** ML-KEM-1024 combinados, de modo
//! que romper el secreto exige romper las dos familias. Aquí no hay socio
//! clásico: **si ML-KEM cae, el secreto cae con él.**
//!
//! Y hay una asimetría con la firma que conviene ver: una firma rota se explota
//! el día que se rompe; **un secreto cifrado hoy se guarda y se rompe mañana**
//! («cosecha ahora, descifra después»). El híbrido protege justo contra eso. Es
//! el argumento más fuerte para usar `quipu` si no hay mandato que lo impida.
//!
//! # El transcript ata la clave pública del destinatario
//!
//! La clave de contenido no sale del secreto compartido a secas: sale de
//! HKDF-**SHA-384** sobre `secreto || etiqueta || ek || ciphertext`. Atar la
//! clave de encapsulación completa impide que quien sustituya la `ek` en
//! tránsito llegue a la misma clave de contenido. Es la defensa estilo X-Wing
//! que ya usa `quipu::pqhybrid`, con el SHA-384 que exige este perfil.
//!
//! # Por qué el nonce de 96 bits no necesita estado
//!
//! Igual que en el resto del crate: la clave de contenido es **distinta en cada
//! encapsulación** —sale de un `(ct, ss)` recién sorteado—, así que repetir el
//! par `(clave, nonce)` exigiría que colisionaran los dos a la vez. La unicidad
//! la da la encapsulación, no el contador.

use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Kem, Key, KeyExport, KeyInit, MlKem1024};
use rand_core::SeedableRng as _;
use sha2::Sha384;
use zeroize::Zeroizing;

use crate::api::SinEntropia;
use crate::cipher::{self, KEY_LEN, NONCE_LEN};

type MlEk = <MlKem1024 as Kem>::EncapsulationKey;
type MlDk = <MlKem1024 as Kem>::DecapsulationKey;

/// Longitud de la clave pública (encapsulación) ML-KEM-1024.
pub const PUBLIC_KEY_LEN: usize = 1568;
/// Longitud del ciphertext de ML-KEM-1024.
pub const ENCAPSULATION_LEN: usize = 1568;
/// Longitud de la clave secreta: la SEMILLA de 64 bytes, no la forma expandida
/// de 3168. `ml-kem` 0.3 serializa así, y es lo que hay que guardar.
pub const SECRET_KEY_LEN: usize = 64;
/// Longitud de la clave de contenido.
pub const CONTENT_KEY_LEN: usize = KEY_LEN;

/// Etiqueta de dominio. Distinta de la de `quipu` a propósito.
const ETIQUETA: &[u8] = b"quipu-cnsa/destinatario/ml-kem-1024/v1";

/// Clave pública del destinatario.
#[derive(Clone)]
pub struct PublicKey {
    ml: MlEk,
}

/// Clave secreta del destinatario.
pub struct SecretKey {
    ml: MlDk,
}

/// Errores del canal de destinatario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestinatarioError {
    /// El blob es más corto de lo que exige el formato, o el AEAD no validó.
    ///
    /// **Un solo error a propósito.** Separar «encapsulación mal formada» de
    /// «tag inválido» le diría al atacante en qué punto del formato falló, que
    /// es el oráculo que el invariante I4 prohíbe.
    NoAbre,
}

impl core::fmt::Display for DestinatarioError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "no se pudo abrir para este destinatario")
    }
}

impl std::error::Error for DestinatarioError {}

/// El generador: ChaCha20 sembrado UNA vez desde el del sistema. Es el mismo
/// patrón que `quipu::aleatorio::generador`, y la razón de pedir la entropía una
/// sola vez es que duplicar la petición duplica el punto de fallo sin ganar nada.
fn generador() -> Result<rand_chacha::ChaCha20Rng, SinEntropia> {
    let mut semilla = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut semilla[..]).map_err(|_| SinEntropia)?;
    Ok(rand_chacha::ChaCha20Rng::from_seed(*semilla))
}

/// Genera un par de claves de destinatario.
pub fn generar_par() -> Result<(PublicKey, SecretKey), SinEntropia> {
    let mut rng = generador()?;
    let (dk, ek) = MlKem1024::generate_keypair_from_rng(&mut rng);
    Ok((PublicKey { ml: ek }, SecretKey { ml: dk }))
}

/// El transcript que ata la clave pública del destinatario y el ciphertext.
fn transcript(ek: &[u8], ct: &[u8]) -> Vec<u8> {
    let mut t = Vec::with_capacity(ETIQUETA.len() + ek.len() + ct.len() + 16);
    t.extend_from_slice(ETIQUETA);
    t.extend_from_slice(&(ek.len() as u64).to_be_bytes());
    t.extend_from_slice(ek);
    t.extend_from_slice(ct);
    t
}

/// Deriva la clave de contenido desde el secreto compartido y el transcript.
fn clave_de_contenido(ss: &[u8], t: &[u8]) -> [u8; CONTENT_KEY_LEN] {
    let hk = Hkdf::<Sha384>::new(Some(t), ss);
    let mut k = [0u8; CONTENT_KEY_LEN];
    hk.expand(ETIQUETA, &mut k).expect("longitud HKDF válida");
    k
}

impl PublicKey {
    /// Serializa.
    pub fn a_bytes(&self) -> Vec<u8> {
        self.ml.to_bytes().to_vec()
    }
    /// Reconstruye. `None` si no es una clave válida.
    pub fn desde_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != PUBLIC_KEY_LEN {
            return None;
        }
        let k = Key::<MlEk>::try_from(b).ok()?;
        Some(Self {
            ml: MlEk::new(&k).ok()?,
        })
    }
}

impl SecretKey {
    /// Serializa la clave secreta (la semilla de 64 bytes). Devuelve un
    /// `Zeroizing`: el buffer se borra al soltarse, para no dejar el secreto en
    /// RAM más de lo necesario.
    pub fn a_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.ml.to_bytes().to_vec())
    }
    /// Reconstruye. `None` si no es una clave válida.
    pub fn desde_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != SECRET_KEY_LEN {
            return None;
        }
        let semilla = Key::<MlDk>::try_from(b).ok()?;
        Some(Self {
            ml: MlDk::new(&semilla),
        })
    }
    /// La clave pública correspondiente.
    pub fn clave_publica(&self) -> PublicKey {
        PublicKey {
            ml: self.ml.encapsulation_key().clone(),
        }
    }
}

/// Cifra `mensaje` para el destinatario. Devuelve
/// `ciphertext_kem || nonce || aead`.
pub fn cifrar_para(pk: &PublicKey, mensaje: &[u8]) -> Result<Vec<u8>, SinEntropia> {
    let mut rng = generador()?;
    let (ct, ss) = pk.ml.encapsulate_with_rng(&mut rng);
    let ek = pk.a_bytes();
    let clave = clave_de_contenido(&ss, &transcript(&ek, &ct));

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| SinEntropia)?;

    // El ciphertext del KEM va como AAD: alterarlo tiene que romper el tag, no
    // producir un descifrado distinto.
    let sellado = cipher::encrypt(&clave, &nonce, mensaje, &ct);

    let mut out = Vec::with_capacity(ENCAPSULATION_LEN + NONCE_LEN + sellado.len());
    out.extend_from_slice(&ct);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sellado);
    Ok(out)
}

/// Descifra lo que [`cifrar_para`] produjo.
pub fn descifrar(sk: &SecretKey, blob: &[u8]) -> Result<Vec<u8>, DestinatarioError> {
    if blob.len() < ENCAPSULATION_LEN + NONCE_LEN {
        return Err(DestinatarioError::NoAbre);
    }
    let (ct_bytes, resto) = blob.split_at(ENCAPSULATION_LEN);
    let (nonce_bytes, sellado) = resto.split_at(NONCE_LEN);

    let ct = ml_kem::Ciphertext::<MlKem1024>::try_from(ct_bytes)
        .map_err(|_| DestinatarioError::NoAbre)?;
    let ss = sk.ml.decapsulate(&ct);

    // La `ek` se recomputa desde la `dk`: el transcript no puede venir del blob,
    // o quien lo entrega elegiría con qué se deriva la clave.
    let ek = sk.ml.encapsulation_key().to_bytes();
    let clave = clave_de_contenido(&ss, &transcript(&ek, ct_bytes));

    let nonce: [u8; NONCE_LEN] = nonce_bytes.try_into().expect("NONCE_LEN bytes");
    cipher::decrypt(&clave, &nonce, sellado, ct_bytes).map_err(|_| DestinatarioError::NoAbre)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn va_y_vuelve() {
        let (pk, sk) = generar_par().unwrap();
        let blob = cifrar_para(&pk, b"historia clinica").unwrap();
        assert_eq!(descifrar(&sk, &blob).unwrap(), b"historia clinica");
    }

    #[test]
    fn otro_destinatario_no_abre() {
        let (pk, _) = generar_par().unwrap();
        let (_, sk2) = generar_par().unwrap();
        let blob = cifrar_para(&pk, b"secreto").unwrap();
        assert_eq!(descifrar(&sk2, &blob), Err(DestinatarioError::NoAbre));
    }

    #[test]
    fn tocar_cualquier_tramo_impide_abrir() {
        let (pk, sk) = generar_par().unwrap();
        let base = cifrar_para(&pk, b"un mensaje de prueba").unwrap();
        // El ciphertext del KEM, el nonce y el sellado: los tres.
        for pos in [0usize, ENCAPSULATION_LEN, base.len() - 1] {
            let mut roto = base.clone();
            roto[pos] ^= 0x01;
            assert_eq!(
                descifrar(&sk, &roto),
                Err(DestinatarioError::NoAbre),
                "un bit movido en {pos} debería impedir abrir"
            );
        }
    }

    #[test]
    fn un_blob_corto_no_entra_en_panico() {
        let (_, sk) = generar_par().unwrap();
        for n in [0usize, 1, ENCAPSULATION_LEN, ENCAPSULATION_LEN + NONCE_LEN - 1] {
            assert_eq!(descifrar(&sk, &vec![0u8; n]), Err(DestinatarioError::NoAbre));
        }
    }

    #[test]
    fn las_claves_van_y_vuelven() {
        let (pk, sk) = generar_par().unwrap();
        let pk2 = PublicKey::desde_bytes(&pk.a_bytes()).unwrap();
        let sk2 = SecretKey::desde_bytes(&sk.a_bytes()).unwrap();
        let blob = cifrar_para(&pk2, b"m").unwrap();
        assert_eq!(descifrar(&sk2, &blob).unwrap(), b"m");
        assert_eq!(sk.clave_publica().a_bytes(), pk.a_bytes());
        assert!(PublicKey::desde_bytes(b"corta").is_none());
        assert!(SecretKey::desde_bytes(b"corta").is_none());
    }

    #[test]
    fn dos_cifrados_del_mismo_mensaje_no_se_parecen() {
        // Si se parecieran, la clave de contenido no vendría de una
        // encapsulación fresca y el nonce de 96 bits sí necesitaría estado.
        let (pk, _) = generar_par().unwrap();
        let a = cifrar_para(&pk, b"igual").unwrap();
        let b = cifrar_para(&pk, b"igual").unwrap();
        assert_ne!(a, b);
        assert_ne!(a[..ENCAPSULATION_LEN], b[..ENCAPSULATION_LEN]);
    }

    #[test]
    fn el_transcript_ata_la_clave_publica() {
        let (pk_a, _) = generar_par().unwrap();
        let (pk_b, _) = generar_par().unwrap();
        assert_ne!(
            transcript(&pk_a.a_bytes(), b"ct"),
            transcript(&pk_b.a_bytes(), b"ct")
        );
        // Y la longitud explícita evita mover el corte entre ek y ct.
        assert_ne!(transcript(b"AB", b"C"), transcript(b"A", b"BC"));
    }
}
