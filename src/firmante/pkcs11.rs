// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Custodio cuya clave privada vive en un dispositivo PKCS#11 y **no sale de él**.
//!
//! Esta es la respuesta a la primera pregunta de todo comité de seguridad. Las
//! dos mitades de la firma híbrida —Ed25519 y ML-DSA-87— se generan y se usan
//! DENTRO del dispositivo; de aquí solo salen firmas y la clave pública.
//!
//! # Cómo encaja con el resto
//!
//! Implementa [`Custodio`](super::Custodio), así que
//! [`firmar`](super::firmar) arma la firma en el ÚNICO sitio donde se decide el
//! formato. Este módulo no compone nada: pide al dispositivo que firme la
//! preimagen con cada mitad y devuelve los bytes crudos. Una firma hecha aquí y
//! una hecha en memoria son idénticas y las verifica el mismo verificador.
//!
//! # Qué se probó, y contra qué
//!
//! Contra `kryoptic` (token PKCS#11 por software, con OpenSSL 3.5): se genera el
//! par, se firma dentro del token y la firma **verifica con el mismo `pqsign`**
//! de Quipu. El dispositivo real solo cambia el módulo que se carga.
//!
//! # Dos rarezas de PKCS#11 que este código absorbe
//!
//! 1. **La clave pública Ed25519 (`CKA_EC_POINT`) llega de dos formas.** El
//!    estándar dice que es un OCTET STRING DER (`04 20 || 32 bytes`); kryoptic
//!    la devuelve cruda. Se aceptan las dos, porque un HSM distinto elige
//!    distinto y no es negociable a cuál nos atamos.
//! 2. **La firma ML-DSA admite «hedge».** Se pide `Preferred`: el dispositivo
//!    firma de forma aleatorizada si puede. No afecta a la verificación —una
//!    firma hedged y una determinista validan igual contra la misma clave.

use super::{Custodio, ErrorDeFirma};
use crate::pqsign::{VerifyingKey, ED25519_PUB_LEN, MLDSA_VK_LEN, VERIFYING_KEY_LEN};
use cryptoki::mechanism::dsa::{HedgeType, SignAdditionalContext};
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;

/// Convierte cualquier fallo de la capa PKCS#11 en el error del módulo,
/// separando lo que se recupera reintentando de lo que no.
///
/// La distinción no es cosmética: un servicio que firma decide si reintenta o
/// si alerta a un operador según esto. Un token ausente puede volver; un PIN
/// mal presentado, no.
fn traducir(contexto: &str, e: cryptoki::error::Error) -> ErrorDeFirma {
    use cryptoki::error::{Error, RvError};
    let detalle = format!("{contexto}: {e}");
    match e {
        // El dispositivo no está o la sesión se cayó: reintentar tiene sentido.
        Error::Pkcs11(
            RvError::DeviceRemoved
            | RvError::DeviceError
            | RvError::TokenNotPresent
            | RvError::SessionClosed
            | RvError::SessionHandleInvalid,
            _,
        ) => ErrorDeFirma::CustodioNoDisponible(detalle),
        // Todo lo demás (PIN, permisos de la clave, política) no se arregla
        // repitiendo la misma llamada.
        _ => ErrorDeFirma::OperacionRechazada(detalle),
    }
}

/// Un firmante respaldado por un dispositivo PKCS#11 ya abierto.
///
/// No abre la sesión ni presenta el PIN: eso es política del integrador (cuándo
/// se hace login, con qué credencial, cuánto dura). Aquí llega una sesión con
/// la que ya se puede firmar, y los manejadores de las dos claves.
pub struct CustodioPkcs11 {
    sesion: Session,
    clave_ed25519: ObjectHandle,
    clave_mldsa: ObjectHandle,
    /// Cacheada: la clave pública no cambia mientras viva el custodio, y leerla
    /// del dispositivo en cada firma es una ida y vuelta que no aporta nada.
    verificacion: VerifyingKey,
}

impl CustodioPkcs11 {
    /// Construye el custodio a partir de una sesión abierta y los manejadores de
    /// las dos claves privadas (Ed25519 y ML-DSA-87), junto con sus públicas.
    ///
    /// Se leen las dos claves públicas al construir y se arma la
    /// [`VerifyingKey`] una vez. Si el dispositivo no entrega una clave con la
    /// forma esperada, falla AQUÍ y no en mitad de una firma.
    pub fn nuevo(
        sesion: Session,
        clave_ed25519: ObjectHandle,
        publica_ed25519: ObjectHandle,
        clave_mldsa: ObjectHandle,
        publica_mldsa: ObjectHandle,
    ) -> Result<Self, ErrorDeFirma> {
        let ed = leer_ed25519_publica(&sesion, publica_ed25519)?;
        let ml = leer_mldsa_publica(&sesion, publica_mldsa)?;

        let mut bytes = Vec::with_capacity(VERIFYING_KEY_LEN);
        bytes.extend_from_slice(&ed);
        bytes.extend_from_slice(&ml);
        let verificacion = VerifyingKey::from_bytes(&bytes).ok_or_else(|| {
            ErrorDeFirma::OperacionRechazada(
                "el dispositivo entregó claves públicas que no forman una VerifyingKey de Quipu"
                    .into(),
            )
        })?;

        Ok(Self { sesion, clave_ed25519, clave_mldsa, verificacion })
    }

    /// Construye el custodio localizando las claves por su etiqueta
    /// (`CKA_LABEL`), en vez de exigir manejadores crudos.
    ///
    /// Es el camino cómodo para quien integra: nombra las dos claves al
    /// crearlas y aquí las busca por ese nombre. Cada etiqueta debe apuntar a
    /// una clave privada y su pública correspondiente, y a una sola: si hay
    /// ambigüedad, falla en vez de firmar con la que no era.
    pub fn por_etiqueta(
        sesion: Session,
        etiqueta_ed25519: &str,
        etiqueta_mldsa: &str,
    ) -> Result<Self, ErrorDeFirma> {
        let (ed_priv, ed_pub) = buscar_par(&sesion, etiqueta_ed25519)?;
        let (ml_priv, ml_pub) = buscar_par(&sesion, etiqueta_mldsa)?;
        Self::nuevo(sesion, ed_priv, ed_pub, ml_priv, ml_pub)
    }
}

/// Encuentra el par (privada, pública) con una etiqueta dada, exigiendo que
/// haya exactamente una de cada.
fn buscar_par(
    sesion: &Session,
    etiqueta: &str,
) -> Result<(ObjectHandle, ObjectHandle), ErrorDeFirma> {
    let priv_ = buscar_uno(sesion, etiqueta, ObjectClass::PRIVATE_KEY, "privada")?;
    let pub_ = buscar_uno(sesion, etiqueta, ObjectClass::PUBLIC_KEY, "pública")?;
    Ok((priv_, pub_))
}

fn buscar_uno(
    sesion: &Session,
    etiqueta: &str,
    clase: ObjectClass,
    cual: &str,
) -> Result<ObjectHandle, ErrorDeFirma> {
    let encontrados = sesion
        .find_objects(&[
            Attribute::Label(etiqueta.as_bytes().to_vec()),
            Attribute::Class(clase),
        ])
        .map_err(|e| traducir(&format!("buscar la clave {cual} «{etiqueta}»"), e))?;
    match encontrados.len() {
        1 => Ok(encontrados[0]),
        0 => Err(ErrorDeFirma::OperacionRechazada(format!(
            "no hay clave {cual} con etiqueta «{etiqueta}»"
        ))),
        n => Err(ErrorDeFirma::OperacionRechazada(format!(
            "hay {n} claves {cual} con etiqueta «{etiqueta}»: la etiqueta debe ser única"
        ))),
    }
}

impl Custodio for CustodioPkcs11 {
    fn clave_de_verificacion(&self) -> Result<VerifyingKey, ErrorDeFirma> {
        Ok(self.verificacion.clone())
    }

    fn firmar_ed25519(&self, preimagen: &[u8]) -> Result<Vec<u8>, ErrorDeFirma> {
        let mech = Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure));
        self.sesion
            .sign(&mech, self.clave_ed25519, preimagen)
            .map_err(|e| traducir("firmar Ed25519 en el dispositivo", e))
    }

    fn firmar_mldsa(&self, preimagen: &[u8]) -> Result<Vec<u8>, ErrorDeFirma> {
        // Hedge preferido: aleatorizado si el dispositivo puede, sin contexto.
        let mech = Mechanism::MlDsa(SignAdditionalContext::new(HedgeType::Preferred, None));
        self.sesion
            .sign(&mech, self.clave_mldsa, preimagen)
            .map_err(|e| traducir("firmar ML-DSA en el dispositivo", e))
    }
}

/// Lee la clave pública Ed25519 como 32 bytes crudos, aceptando las dos formas
/// en que un dispositivo la puede devolver (ver la nota del módulo).
fn leer_ed25519_publica(
    sesion: &Session,
    handle: ObjectHandle,
) -> Result<Vec<u8>, ErrorDeFirma> {
    let attrs = sesion
        .get_attributes(handle, &[AttributeType::EcPoint])
        .map_err(|e| traducir("leer EC_POINT Ed25519", e))?;
    let punto = attrs
        .into_iter()
        .find_map(|a| if let Attribute::EcPoint(v) = a { Some(v) } else { None })
        .ok_or_else(|| {
            ErrorDeFirma::OperacionRechazada("la clave Ed25519 no expone EC_POINT".into())
        })?;

    let crudo: &[u8] = if punto.len() == ED25519_PUB_LEN + 2
        && punto[0] == 0x04
        && punto[1] == ED25519_PUB_LEN as u8
    {
        // Envuelta en OCTET STRING DER: 04 20 || 32 bytes.
        &punto[2..]
    } else {
        // Cruda, como la da kryoptic.
        &punto
    };

    if crudo.len() != ED25519_PUB_LEN {
        return Err(ErrorDeFirma::OperacionRechazada(format!(
            "EC_POINT Ed25519 mide {} y se esperaban {ED25519_PUB_LEN}",
            crudo.len()
        )));
    }
    Ok(crudo.to_vec())
}

/// Lee la clave pública ML-DSA-87 como sus 2592 bytes.
fn leer_mldsa_publica(
    sesion: &Session,
    handle: ObjectHandle,
) -> Result<Vec<u8>, ErrorDeFirma> {
    let attrs = sesion
        .get_attributes(handle, &[AttributeType::Value])
        .map_err(|e| traducir("leer Value ML-DSA", e))?;
    let valor = attrs
        .into_iter()
        .find_map(|a| if let Attribute::Value(v) = a { Some(v) } else { None })
        .ok_or_else(|| {
            ErrorDeFirma::OperacionRechazada("la clave ML-DSA no expone Value".into())
        })?;
    if valor.len() != MLDSA_VK_LEN {
        return Err(ErrorDeFirma::OperacionRechazada(format!(
            "clave pública ML-DSA mide {} y se esperaban {MLDSA_VK_LEN}",
            valor.len()
        )));
    }
    Ok(valor)
}

/// Reexporta el contexto PKCS#11 para que el integrador cargue el módulo sin
/// declarar `cryptoki` en su propio `Cargo.toml`.
pub use cryptoki::context::Pkcs11 as Contexto;
