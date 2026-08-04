// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Firma **ML-DSA-87 pura**, que es lo que CNSA 2.0 pide.
//!
//! # PURO, y eso es MÁS DÉBIL que `quipu`. Léase antes de elegir.
//!
//! `quipu` firma **híbrido**: Ed25519 **y** ML-DSA-87, con combinador AND, de
//! modo que falsificar exige romper las dos familias — la de curva elíptica y la
//! de retículos. Aquí no hay socio clásico: **si ML-DSA cae, no queda nada
//! sujetando la firma.**
//!
//! No es un descuido, es el mandato: CNSA 2.0 nombra ML-DSA-87 para firma y no
//! exige híbrido. Este perfil existe para quien tiene esa obligación normativa.
//! **Si puedes elegir, firma con `quipu`.** Es la misma frase que abre el crate,
//! y aquí es donde más cuesta.
//!
//! # Qué NO es este módulo
//!
//! - **No está validado FIPS 140-3.** Implementar el algoritmo no es estar
//!   validado; eso es un laboratorio acreditado y no está en el plan.
//! - **No es LMS ni XMSS.** Esos están aprobados (SP 800-208) **solo** para
//!   firmar software y firmware, y traen un coste operativo serio: llevan
//!   ESTADO, y reutilizar el contador es catastrófico. ML-DSA-87 está aprobado
//!   para cualquier uso, incluido ese, así que para estar alineados basta.
//! - **No es SLH-DSA**, que no está en CNSA 2.0 en absoluto.
//!
//! # La preimagen ata la clave pública, y por qué
//!
//! No se firma el mensaje a secas: se firma `etiqueta || vk || mensaje`. Sin
//! atar la clave pública completa, una firma válida bajo una clave podría
//! presentarse bajo otra en un protocolo que las mezcle (sustitución de clave).
//! Es la misma defensa que usa `quipu::pqsign`, y aquí importa más porque no hay
//! una segunda firma que discrepe.
//!
//! # La firma es DETERMINISTA, y conviene que esté dicho
//!
//! `ml-dsa` expone `raw_sign_deterministic` con contexto vacío. Es conforme a
//! FIPS 204 y es lo que hace que dos firmas del mismo mensaje con la misma clave
//! sean idénticas — cosa que las pruebas dan por buena.
//!
//! **Lo que se paga:** la variante determinista es la expuesta a **inyección de
//! fallos**. Un adversario con acceso físico que provoque un fallo diferencial
//! puede obtener dos firmas del mismo mensaje que difieran y, con ellas, extraer
//! clave. Por eso FIPS 204 ofrece también la variante *hedged*, que mezcla
//! aleatoriedad fresca.
//!
//! **Por qué se acepta aquí:** la inyección de fallos exige acceso físico al
//! dispositivo que firma, que es la clase de adversario que el modelo de amenaza
//! de Quipu deja fuera (ver `docs/THREAT_MODEL.md`). Si algún día este perfil se
//! usa en una tarjeta o un HSM al alcance de quien lo ataca, **hay que pasar a
//! la variante hedged** — y esta nota es el sitio donde mirarlo.
//!
//! Estaba sin escribir hasta el 2026-08-01: el módulo razonaba con detalle por
//! qué es puro y no híbrido, y no decía una palabra de esto.

use ml_dsa::signature::{Keypair as _, Signer as _, Verifier as _};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa87, Seed, Signature as MlSignature,
    SigningKey as MlSigningKey, VerifyingKey as MlVerifyingKey,
};
use zeroize::Zeroizing;

use crate::api::SinEntropia;

/// Longitud de la clave de verificación ML-DSA-87.
pub const VERIFYING_KEY_LEN: usize = 2592;
/// Longitud de la firma ML-DSA-87.
pub const SIGNATURE_LEN: usize = 4627;
/// Longitud de la semilla de la clave de firma.
pub const SIGNING_KEY_LEN: usize = 32;

/// Etiqueta de dominio. Distinta de la de `quipu` a propósito: una firma de este
/// perfil no debe verificar jamás como una de aquel, ni al revés.
const ETIQUETA: &[u8] = b"quipu-cnsa/firma/ml-dsa-87/v1";

/// Clave de verificación (pública).
#[derive(Clone)]
pub struct VerifyingKey {
    ml: MlVerifyingKey<MlDsa87>,
}

/// Clave de firma (privada). Se guarda la SEMILLA, no la clave expandida: son
/// 32 bytes en vez de miles, y se limpia sola al soltarla.
pub struct SigningKey {
    semilla: Zeroizing<[u8; SIGNING_KEY_LEN]>,
}

/// Reconstruye la clave de firma desde su semilla.
fn clave_desde_semilla(semilla: &[u8; SIGNING_KEY_LEN]) -> MlSigningKey<MlDsa87> {
    let s = Seed::try_from(&semilla[..]).expect("semilla ML-DSA de 32 bytes");
    MlSigningKey::<MlDsa87>::from_seed(&s)
}

/// Lo que de verdad se firma. Ata la etiqueta de dominio y la clave pública
/// COMPLETA delante del mensaje.
fn preimagen(vk: &[u8], mensaje: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(ETIQUETA.len() + vk.len() + mensaje.len() + 16);
    p.extend_from_slice(ETIQUETA);
    // La longitud va explícita: sin ella, `vk || mensaje` y `vk' || mensaje'`
    // podrían coincidir moviendo el corte entre los dos campos.
    p.extend_from_slice(&(vk.len() as u64).to_be_bytes());
    p.extend_from_slice(vk);
    p.extend_from_slice(mensaje);
    p
}

/// Genera un par de claves.
pub fn generar_par() -> Result<(VerifyingKey, SigningKey), SinEntropia> {
    let mut semilla = [0u8; SIGNING_KEY_LEN];
    getrandom::fill(&mut semilla).map_err(|_| SinEntropia)?;
    let sk = SigningKey {
        semilla: Zeroizing::new(semilla),
    };
    let vk = sk.clave_de_verificacion();
    Ok((vk, sk))
}

impl SigningKey {
    /// Reconstruye una clave de firma desde su semilla de 32 bytes.
    pub fn desde_semilla(semilla: [u8; SIGNING_KEY_LEN]) -> Self {
        Self {
            semilla: Zeroizing::new(semilla),
        }
    }

    /// La clave de verificación correspondiente.
    pub fn clave_de_verificacion(&self) -> VerifyingKey {
        VerifyingKey {
            ml: clave_desde_semilla(&self.semilla).verifying_key(),
        }
    }

    /// La semilla de 32 bytes, para poder guardarla.
    ///
    /// SIN ESTO, UNA CLAVE GENERADA POR LA LIBRERÍA NO SE PODÍA PERSISTIR:
    /// existía `desde_semilla` y no su inversa, así que el único camino práctico
    /// era que el usuario sorteara sus propios 32 bytes y los importara —
    /// esquivando el manejo de entropía del crate, que es justo lo contrario de
    /// lo que se quiere. El módulo hermano ya lo resolvía bien
    /// (`destinatario::SecretKey::a_bytes`); esta es la simétrica.
    ///
    /// Devuelve `Zeroizing`: la copia que se lleva el llamante se limpia sola al
    /// soltarla.
    pub fn a_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.semilla.to_vec())
    }

    /// Firma `mensaje`.
    ///
    /// EXPANDE LA SEMILLA UNA SOLA VEZ. Antes lo hacía dos —una dentro de
    /// `clave_de_verificacion()` y otra para firmar—, y en ML-DSA la expansión
    /// (matriz + NTT) es la parte cara: se pagaba el doble por firma y se
    /// duplicaba la superficie de residuo de la clave privada en memoria.
    pub fn firmar(&self, mensaje: &[u8]) -> Vec<u8> {
        let sk = clave_desde_semilla(&self.semilla);
        let vk = VerifyingKey {
            ml: sk.verifying_key(),
        };
        let p = preimagen(&vk.a_bytes(), mensaje);
        sk.sign(&p).encode().as_slice().to_vec()
    }
}

impl VerifyingKey {
    /// Serializa la clave de verificación.
    pub fn a_bytes(&self) -> Vec<u8> {
        self.ml.encode().as_slice().to_vec()
    }

    /// Reconstruye desde bytes. `None` si no es una clave válida.
    pub fn desde_bytes(b: &[u8]) -> Option<Self> {
        let enc = EncodedVerifyingKey::<MlDsa87>::try_from(b).ok()?;
        Some(Self {
            ml: MlVerifyingKey::<MlDsa87>::decode(&enc),
        })
    }

    /// Verifica. `false` ante cualquier problema —firma corta, mal codificada o
    /// simplemente inválida—: **el motivo no se distingue**, porque distinguirlo
    /// es exactamente el oráculo que el invariante I4 prohíbe.
    pub fn verificar(&self, mensaje: &[u8], firma: &[u8]) -> bool {
        if firma.len() != SIGNATURE_LEN {
            return false;
        }
        let p = preimagen(&self.a_bytes(), mensaje);
        match EncodedSignature::<MlDsa87>::try_from(firma) {
            Ok(enc) => match MlSignature::<MlDsa87>::decode(&enc) {
                Some(sig) => self.ml.verify(&p, &sig).is_ok(),
                None => false,
            },
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firma_y_verifica() {
        let (vk, sk) = generar_par().unwrap();
        let f = sk.firmar(b"acta de custodia");
        assert_eq!(f.len(), SIGNATURE_LEN);
        assert!(vk.verificar(b"acta de custodia", &f));
    }

    #[test]
    fn un_mensaje_distinto_no_verifica() {
        let (vk, sk) = generar_par().unwrap();
        let f = sk.firmar(b"pagar 100");
        assert!(!vk.verificar(b"pagar 900", &f));
    }

    #[test]
    fn la_firma_de_otro_par_no_verifica() {
        let (vk_a, _) = generar_par().unwrap();
        let (_, sk_b) = generar_par().unwrap();
        let f = sk_b.firmar(b"mensaje");
        assert!(!vk_a.verificar(b"mensaje", &f));
    }

    #[test]
    fn un_bit_movido_invalida() {
        let (vk, sk) = generar_par().unwrap();
        let mut f = sk.firmar(b"mensaje");
        f[0] ^= 0x01;
        assert!(!vk.verificar(b"mensaje", &f));
        let mut f = sk.firmar(b"mensaje");
        let ultimo = f.len() - 1;
        f[ultimo] ^= 0x01;
        assert!(!vk.verificar(b"mensaje", &f));
    }

    #[test]
    fn una_firma_de_longitud_rara_no_pasa() {
        let (vk, sk) = generar_par().unwrap();
        let f = sk.firmar(b"m");
        assert!(!vk.verificar(b"m", &f[..f.len() - 1]));
        assert!(!vk.verificar(b"m", &[]));
        let mut larga = f.clone();
        larga.push(0);
        assert!(!vk.verificar(b"m", &larga));
    }

    #[test]
    fn la_semilla_reconstruye_la_misma_clave() {
        let (vk, sk) = generar_par().unwrap();
        let semilla = *sk.semilla;
        let sk2 = SigningKey::desde_semilla(semilla);
        assert_eq!(vk.a_bytes(), sk2.clave_de_verificacion().a_bytes());
        let f = sk2.firmar(b"x");
        assert!(vk.verificar(b"x", &f));
    }

    #[test]
    fn la_clave_publica_va_y_vuelve() {
        let (vk, sk) = generar_par().unwrap();
        let vk2 = VerifyingKey::desde_bytes(&vk.a_bytes()).unwrap();
        assert!(vk2.verificar(b"m", &sk.firmar(b"m")));
        assert!(VerifyingKey::desde_bytes(b"corta").is_none());
    }

    #[test]
    fn la_preimagen_ata_la_clave_publica() {
        // Dos claves distintas producen preimágenes distintas para el MISMO
        // mensaje: es lo que impide presentar una firma bajo otra clave.
        let (vk_a, _) = generar_par().unwrap();
        let (vk_b, _) = generar_par().unwrap();
        assert_ne!(
            preimagen(&vk_a.a_bytes(), b"m"),
            preimagen(&vk_b.a_bytes(), b"m")
        );
    }

    #[test]
    fn la_longitud_explicita_evita_mover_el_corte() {
        // Sin el prefijo de longitud, (vk="AB", msg="C") y (vk="A", msg="BC")
        // darían la misma preimagen. Con él, no.
        assert_ne!(preimagen(b"AB", b"C"), preimagen(b"A", b"BC"));
    }
}
