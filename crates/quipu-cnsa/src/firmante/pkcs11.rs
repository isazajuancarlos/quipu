// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

//! Custodio cuya clave privada vive en un dispositivo PKCS#11 y **no sale de él**.
//!
//! Esta es la respuesta a la primera pregunta de todo comité de seguridad, y en
//! el perfil CNSA es además la respuesta a las dos preguntas normativas que
//! ninguna librería de software puede contestar por sí sola: la validación
//! FIPS 140-3 del módulo, y el §8.1 de SP 800-208, que confina la generación de
//! claves y de firmas de LMS/XMSS a módulos hardware validados.
//!
//! La clave ML-DSA-87 se genera y se usa DENTRO del dispositivo; de aquí solo
//! salen firmas y la clave pública.
//!
//! # Cómo encaja con el resto
//!
//! Implementa [`super::Custodio`], así que [`super::firmar`] arma la firma en
//! el ÚNICO sitio donde se decide el formato. Este módulo no
//! compone nada: pide al dispositivo que firme la preimagen y devuelve los
//! bytes crudos. Una firma hecha aquí la verifica el mismo
//! [`crate::firma::VerifyingKey::verificar`] de siempre.
//!
//! # Una sola clave, y esa es la diferencia con `quipu`
//!
//! El custodio de `quipu` maneja dos claves —Ed25519 y ML-DSA-87— porque firma
//! híbrido. CNSA 2.0 nombra ML-DSA-87 y no pide socio clásico, así que aquí hay
//! una clave, un mecanismo y una firma. Menos código y **menos seguridad**: si
//! ML-DSA cae, no queda nada sujetando. Está dicho en [`crate::firma`].
//!
//! # La firma del dispositivo se pide *hedged*, y el camino en memoria no
//!
//! [`crate::firma::SigningKey::firmar`] es determinista, y su cabecera dice por
//! qué se acepta: la inyección de fallos exige acceso físico al aparato que
//! firma, que es un adversario fuera del modelo… **mientras la clave viva en
//! este proceso**. Un HSM cambia justo eso: es un aparato, y suele estar donde
//! alguien puede tocarlo. Por eso aquí se pide `HedgeType::Preferred` —el
//! dispositivo aleatoriza si puede—, que es la variante que FIPS 204 ofrece
//! para ese caso. No afecta a la verificación: una firma *hedged* y una
//! determinista validan igual contra la misma clave.
//!
//! # Qué se probó, y contra qué
//!
//! Contra `kryoptic` (token PKCS#11 por software, con OpenSSL 3.5): se genera
//! el par DENTRO del token, se firma dentro y la firma verifica con el
//! verificador puro de este crate. Un dispositivo real solo cambia el módulo
//! que se carga. Ver `tests/hsm_pkcs11.rs`.

use super::{Custodio, ErrorDeFirma, Preimagen};
use crate::firma::{VerifyingKey, VERIFYING_KEY_LEN};
use cryptoki::mechanism::dsa::{HedgeType, SignAdditionalContext};
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
/// la que ya se puede firmar, y el manejador de la clave.
pub struct CustodioPkcs11 {
    sesion: Session,
    clave: ObjectHandle,
    /// Cacheada: la clave pública no cambia mientras viva el custodio, y leerla
    /// del dispositivo en cada firma es una ida y vuelta que no aporta nada.
    verificacion: VerifyingKey,
    /// `CKA_EXTRACTABLE` leído del dispositivo al construir. Ver
    /// [`CustodioPkcs11::clave_extraible`].
    extraible: bool,
}

impl CustodioPkcs11 {
    /// Construye el custodio a partir de una sesión abierta y los manejadores
    /// de la clave privada ML-DSA-87 y su pública.
    ///
    /// La clave pública se lee al construir y se arma la [`VerifyingKey`] una
    /// vez. Si el dispositivo no entrega una clave con la forma esperada, falla
    /// AQUÍ y no en mitad de una firma.
    pub fn nuevo(
        sesion: Session,
        clave: ObjectHandle,
        publica: ObjectHandle,
    ) -> Result<Self, ErrorDeFirma> {
        let bytes = leer_mldsa_publica(&sesion, publica)?;
        let verificacion = VerifyingKey::desde_bytes(&bytes).ok_or_else(|| {
            ErrorDeFirma::OperacionRechazada(
                "el dispositivo entregó una clave pública que no es una ML-DSA-87 válida".into(),
            )
        })?;
        let extraible = comprobar_custodia(&sesion, clave)?;
        Ok(Self { sesion, clave, verificacion, extraible })
    }

    /// Si el dispositivo permite EXPORTAR la clave privada envuelta
    /// (`CKA_EXTRACTABLE`).
    ///
    /// **No se rechaza al construir, y es una decisión.** La copia de respaldo
    /// de una clave de HSM se hace exactamente así —envuelta bajo otra clave del
    /// propio dispositivo—, y es práctica legítima de operación: negarse sería
    /// el sesgo a cerrar, y dejaría fuera a un cliente real por estética
    /// (directiva 21). Lo que sí se rechaza, sin escape, es `CKA_SENSITIVE`
    /// falso: ahí el valor privado se lee **en claro**, y entonces la frase
    /// «la clave no sale del dispositivo» sería simplemente mentira.
    ///
    /// Quien tenga una política más dura que eso la afirma con esto:
    ///
    /// ```rust,ignore
    /// assert!(!custodio.clave_extraible(), "la política prohíbe claves exportables");
    /// ```
    pub fn clave_extraible(&self) -> bool {
        self.extraible
    }

    /// Construye el custodio localizando la clave por su etiqueta
    /// (`CKA_LABEL`), en vez de exigir manejadores crudos.
    ///
    /// Es el camino cómodo para quien integra: nombra la clave al crearla y
    /// aquí se busca por ese nombre. La etiqueta debe apuntar a una clave
    /// privada y su pública correspondiente, y a UNA sola: si hay ambigüedad,
    /// falla en vez de firmar con la que no era.
    pub fn por_etiqueta(sesion: Session, etiqueta: &str) -> Result<Self, ErrorDeFirma> {
        let privada = buscar_uno(&sesion, etiqueta, ObjectClass::PRIVATE_KEY, "privada")?;
        let publica = buscar_uno(&sesion, etiqueta, ObjectClass::PUBLIC_KEY, "pública")?;
        Self::nuevo(sesion, privada, publica)
    }
}

/// Comprueba, contra el DISPOSITIVO, que la clave privada merece llamarse
/// custodiada; devuelve si además es exportable envuelta.
///
/// Existe porque el README de este crate promete que la clave «se genera y se
/// usa DENTRO del dispositivo y no sale», y hasta el 2026-08-13 eso no lo
/// comprobaba nadie: era una propiedad de los atributos con que alguien creó el
/// objeto, y el custodio se construía igual sobre una clave que se pudiera leer
/// en claro. Lo señaló la revisión de seguridad. Ante el dato ausente se falla
/// ruidosamente, no se supone (directiva 20).
fn comprobar_custodia(sesion: &Session, clave: ObjectHandle) -> Result<bool, ErrorDeFirma> {
    let attrs = sesion
        .get_attributes(
            clave,
            &[AttributeType::Sensitive, AttributeType::Extractable],
        )
        .map_err(|e| traducir("leer CKA_SENSITIVE/CKA_EXTRACTABLE de la clave privada", e))?;

    let mut sensible = None;
    let mut extraible = None;
    for a in attrs {
        match a {
            Attribute::Sensitive(v) => sensible = Some(v),
            Attribute::Extractable(v) => extraible = Some(v),
            _ => {}
        }
    }

    match sensible {
        Some(true) => {}
        Some(false) => {
            return Err(ErrorDeFirma::OperacionRechazada(
                "la clave privada tiene CKA_SENSITIVE = false: su valor se puede leer EN CLARO del dispositivo, así que no está custodiada. Este crate no firma con ella"
                    .into(),
            ))
        }
        None => {
            return Err(ErrorDeFirma::OperacionRechazada(
                "el dispositivo no expone CKA_SENSITIVE de la clave privada: no se puede saber si está custodiada, y suponerlo sería justo lo que este módulo promete no hacer"
                    .into(),
            ))
        }
    }

    // `CKA_EXTRACTABLE` ausente se lee como el caso conservador: no exportable.
    // Es lo contrario que arriba a propósito — aquí el dato solo alimenta un
    // informe para el integrador, no una garantía nuestra, y negarse a operar
    // por no poder leerlo cerraría la puerta a dispositivos correctos.
    Ok(extraible.unwrap_or(false))
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

    fn firmar_mldsa(&self, preimagen: &Preimagen) -> Result<Vec<u8>, ErrorDeFirma> {
        // Hedge preferido: aleatorizado si el dispositivo puede, sin contexto.
        // El porqué está en la cabecera del módulo, y no es un detalle.
        let mech = Mechanism::MlDsa(SignAdditionalContext::new(HedgeType::Preferred, None));
        self.sesion
            .sign(&mech, self.clave, preimagen.como_bytes())
            .map_err(|e| traducir("firmar ML-DSA en el dispositivo", e))
    }
}

/// Lee la clave pública ML-DSA-87 como sus 2592 bytes.
fn leer_mldsa_publica(sesion: &Session, handle: ObjectHandle) -> Result<Vec<u8>, ErrorDeFirma> {
    let attrs = sesion
        .get_attributes(handle, &[AttributeType::Value])
        .map_err(|e| traducir("leer Value ML-DSA", e))?;
    let valor = attrs
        .into_iter()
        .find_map(|a| if let Attribute::Value(v) = a { Some(v) } else { None })
        .ok_or_else(|| {
            ErrorDeFirma::OperacionRechazada("la clave ML-DSA no expone Value".into())
        })?;
    if valor.len() != VERIFYING_KEY_LEN {
        return Err(ErrorDeFirma::OperacionRechazada(format!(
            "clave pública ML-DSA mide {} y se esperaban {VERIFYING_KEY_LEN}",
            valor.len()
        )));
    }
    Ok(valor)
}

/// Reexporta el contexto PKCS#11 para que el integrador cargue el módulo sin
/// declarar `cryptoki` en su propio `Cargo.toml`.
pub use cryptoki::context::Pkcs11 as Contexto;
