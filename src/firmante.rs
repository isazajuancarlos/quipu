// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Dónde vive la clave privada de firma.
//!
//! # El problema que resuelve
//!
//! Hasta 0.8.0 la única respuesta posible era «en memoria del proceso»:
//! [`crate::pqsign::SigningKey`] guarda las dos semillas y firma con ellas. Para
//! un comité de seguridad esa respuesta cierra la conversación en la primera
//! pregunta, porque la clave puede acabar en un volcado, en el *swap*, o en una
//! variable de entorno de la que nadie se acuerda.
//!
//! Este módulo separa **quién custodia la clave** de **cómo se arma la firma**.
//! El formato en cable no cambia: una firma hecha dentro de un HSM y una hecha
//! en memoria son el mismo byte a byte, y las verifica el mismo verificador.
//!
//! # Por qué el trait no expone la clave
//!
//! La tentación es un trait con `fn clave_privada(&self) -> SigningKey`. Eso
//! haría trivial cualquier backend y **destruiría el único punto** del asunto:
//! si la clave se puede pedir, ya salió del HSM. Lo que se pide aquí es una
//! *operación*, nunca el material.
//!
//! # Por qué el ensamblado no es tarea del backend
//!
//! Una firma de Quipu no es la concatenación de dos firmas cualesquiera: ata la
//! clave pública completa del firmante y una etiqueta de dominio, y ese detalle
//! es lo que impide sustituir una mitad por la de otro par de claves. Si cada
//! backend armara la firma, cada backend podría equivocarse en eso, y el error
//! saldría como «firma inválida» en producción y no en una prueba.
//!
//! Por eso el backend implementa solo lo que **obliga** a tener la clave —
//! firmar unos bytes con cada mitad— y [`firmar`] pone el resto. La preimagen
//! es aritmética pura sobre datos públicos: no hay razón para que cruce a un
//! dispositivo.

use crate::pqsign::{
    build_preimage, SigningKey, VerifyingKey, ED25519_SIG_LEN, MLDSA_SIG_LEN, SIGNATURE_LEN,
};

/// Por qué no se pudo firmar.
///
/// No lleva variante «clave incorrecta»: eso es un fallo de programación, no un
/// estado del que un servicio se recupere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorDeFirma {
    /// El custodio no está disponible: HSM desconectado, sesión caída, el token
    /// no está presente. Reintentar puede tener sentido.
    CustodioNoDisponible(String),
    /// El custodio está, pero rechazó la operación: PIN no presentado, la clave
    /// no permite firmar, política del dispositivo. Reintentar no sirve.
    OperacionRechazada(String),
    /// El custodio devolvió una firma con una longitud que no es la del
    /// algoritmo. Se comprueba porque una firma corta silenciosa es
    /// indistinguible de una válida hasta que alguien la verifica.
    LongitudInesperada { esperaba: usize, recibio: usize },
}

impl core::fmt::Display for ErrorDeFirma {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CustodioNoDisponible(d) => {
                write!(f, "el custodio de la clave no está disponible: {d}")
            }
            Self::OperacionRechazada(d) => write!(f, "el custodio rechazó firmar: {d}"),
            Self::LongitudInesperada { esperaba, recibio } => write!(
                f,
                "el custodio devolvió {recibio} bytes de firma y el algoritmo son {esperaba}"
            ),
        }
    }
}

impl core::error::Error for ErrorDeFirma {}

/// Lo mínimo que hay que saber hacer para custodiar una clave de firma de Quipu.
///
/// Las dos operaciones son justo las que **exigen** tener el material privado.
/// Todo lo demás lo pone [`firmar`].
pub trait Custodio {
    /// La clave pública de la identidad que este custodio representa.
    ///
    /// Es falible a propósito: un HSM puede tener que abrir sesión para leerla.
    fn clave_de_verificacion(&self) -> Result<VerifyingKey, ErrorDeFirma>;

    /// Firma `preimagen` con la mitad Ed25519.
    fn firmar_ed25519(&self, preimagen: &[u8]) -> Result<Vec<u8>, ErrorDeFirma>;

    /// Firma `preimagen` con la mitad ML-DSA-87.
    fn firmar_mldsa(&self, preimagen: &[u8]) -> Result<Vec<u8>, ErrorDeFirma>;
}

/// Arma la firma híbrida de Quipu contra cualquier custodio.
///
/// **Este es el único sitio donde se decide el formato.** Un backend nuevo no
/// puede producir una firma con otra forma aunque quiera, porque no participa
/// en el ensamblado.
pub fn firmar<C: Custodio + ?Sized>(
    custodio: &C,
    mensaje: &[u8],
) -> Result<Vec<u8>, ErrorDeFirma> {
    let vk = custodio.clave_de_verificacion()?;
    let preimagen = build_preimage(&vk.to_bytes(), mensaje);

    let ed = custodio.firmar_ed25519(&preimagen)?;
    comprobar_longitud(ed.len(), ED25519_SIG_LEN)?;
    let ml = custodio.firmar_mldsa(&preimagen)?;
    comprobar_longitud(ml.len(), MLDSA_SIG_LEN)?;

    let mut firma = Vec::with_capacity(SIGNATURE_LEN);
    firma.extend_from_slice(&ed);
    firma.extend_from_slice(&ml);
    Ok(firma)
}

fn comprobar_longitud(recibio: usize, esperaba: usize) -> Result<(), ErrorDeFirma> {
    if recibio == esperaba {
        Ok(())
    } else {
        Err(ErrorDeFirma::LongitudInesperada { esperaba, recibio })
    }
}

/// El custodio de siempre: la clave vive en la memoria de este proceso.
///
/// Sigue siendo el predeterminado y no está deprecado. Para la mayoría de los
/// despliegues es la respuesta correcta; lo que cambia es que ahora **es una
/// elección explícita** y no la única posible.
pub struct EnMemoria {
    clave: SigningKey,
}

impl EnMemoria {
    /// Toma posesión de la clave.
    pub fn nuevo(clave: SigningKey) -> Self {
        Self { clave }
    }
}

impl Custodio for EnMemoria {
    fn clave_de_verificacion(&self) -> Result<VerifyingKey, ErrorDeFirma> {
        Ok(self.clave.verifying_key())
    }

    fn firmar_ed25519(&self, preimagen: &[u8]) -> Result<Vec<u8>, ErrorDeFirma> {
        Ok(self.clave.firmar_ed25519_crudo(preimagen))
    }

    fn firmar_mldsa(&self, preimagen: &[u8]) -> Result<Vec<u8>, ErrorDeFirma> {
        Ok(self.clave.firmar_mldsa_crudo(preimagen))
    }
}

/// Firma con una clave repartida en comparticiones de Shamir, sin que la clave
/// salga de esta función.
///
/// # Por qué existe
///
/// El caso que la motiva es real: un sistema de informes guarda la clave de
/// firma repartida entre custodios y la reconstruye **solo para firmar**. Antes,
/// la única forma era `combine` → `SigningKey::from_bytes` → `sign`, y en un
/// binding esos pasos intermedios cruzan la frontera FFI: en Python la clave
/// acaba en un objeto que vive hasta que pase el recolector de basura.
///
/// Aquí la vida del secreto queda acotada a **una llamada de función en Rust**,
/// no a la disciplina de quien integra. Se reconstruye, se firma, se borra al
/// soltar, y lo único que sale es la firma.
///
/// # Lo que esto NO resuelve, y conviene no fingir que sí
///
/// La zeroización en Rust es de mejor esfuerzo: el optimizador puede haber
/// dejado copias en registros o en la pila, y el sistema pudo pasar la página
/// al *swap* antes de que nada se borrara. Acotar la vida reduce la ventana,
/// no la cierra. Lo único que la cerraría de verdad es que la clave nunca se
/// reconstruya — que es lo que ofrece un custodio PKCS#11, no este.
#[cfg(feature = "escrow")]
pub fn firmar_con_comparticiones(
    comparticiones: &[crate::shamir::Share],
    mensaje: &[u8],
) -> Result<Vec<u8>, ErrorDeFirma> {
    let bytes = crate::shamir::combine(comparticiones)
        .map_err(|e| ErrorDeFirma::OperacionRechazada(format!("reparto inválido: {e}")))?;
    let clave = SigningKey::from_bytes(&bytes).ok_or_else(|| {
        ErrorDeFirma::OperacionRechazada(
            "las comparticiones reconstruyen algo que no es una clave de firma".into(),
        )
    })?;
    // `clave` se suelta al salir de la expresión y `SigningKey` zeroiza sus
    // semillas. La firma es lo único que sobrevive.
    firmar(&EnMemoria::nuevo(clave), mensaje)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqsign::generate_keypair;

    /// La prueba que hace útil a todo el módulo: pasar por el trait tiene que
    /// dar EXACTAMENTE la misma firma que el camino directo. Si no, cambiar de
    /// custodio rompería las firmas ya emitidas.
    #[test]
    fn firmar_por_el_trait_da_lo_mismo_que_el_camino_directo() {
        let (_, sk) = generate_keypair();
        let mensaje = b"acta con validez juridica";
        let directa = sk.sign(mensaje);
        let por_trait = firmar(&EnMemoria::nuevo(sk), mensaje).unwrap();
        assert_eq!(directa, por_trait, "el trait cambia el formato en cable");
    }

    /// Y la firma que sale del trait la verifica el verificador de siempre, sin
    /// saber que hubo un custodio de por medio.
    #[test]
    fn el_verificador_de_siempre_acepta_la_firma_del_custodio() {
        let (vk, sk) = generate_keypair();
        let mensaje = b"acta con validez juridica";
        let firma = firmar(&EnMemoria::nuevo(sk), mensaje).unwrap();
        assert!(vk.verify(mensaje, &firma));
        assert!(!vk.verify(b"otra cosa", &firma), "verifica cualquier mensaje");
    }

    /// Un custodio que devuelve una firma corta no puede colarla. Sin esta
    /// comprobación el fallo aparecería como «firma inválida» mucho después, y
    /// muy lejos del backend que la produjo.
    #[test]
    fn una_firma_de_longitud_rara_se_caza_al_armarla() {
        struct Tramposo(VerifyingKey);
        impl Custodio for Tramposo {
            fn clave_de_verificacion(&self) -> Result<VerifyingKey, ErrorDeFirma> {
                Ok(self.0.clone())
            }
            fn firmar_ed25519(&self, _: &[u8]) -> Result<Vec<u8>, ErrorDeFirma> {
                Ok(vec![0u8; ED25519_SIG_LEN - 1])
            }
            fn firmar_mldsa(&self, _: &[u8]) -> Result<Vec<u8>, ErrorDeFirma> {
                Ok(vec![0u8; MLDSA_SIG_LEN])
            }
        }
        let (vk, _) = generate_keypair();
        let e = firmar(&Tramposo(vk), b"x").unwrap_err();
        assert_eq!(
            e,
            ErrorDeFirma::LongitudInesperada {
                esperaba: ED25519_SIG_LEN,
                recibio: ED25519_SIG_LEN - 1
            }
        );
    }

    /// El error del custodio llega al llamante en vez de convertirse en pánico
    /// o en una firma inventada.
    #[test]
    fn el_fallo_del_custodio_sube_como_error() {
        struct Caido;
        impl Custodio for Caido {
            fn clave_de_verificacion(&self) -> Result<VerifyingKey, ErrorDeFirma> {
                Err(ErrorDeFirma::CustodioNoDisponible("token ausente".into()))
            }
            fn firmar_ed25519(&self, _: &[u8]) -> Result<Vec<u8>, ErrorDeFirma> {
                unreachable!("no debería llegar aquí sin clave pública")
            }
            fn firmar_mldsa(&self, _: &[u8]) -> Result<Vec<u8>, ErrorDeFirma> {
                unreachable!()
            }
        }
        let e = firmar(&Caido, b"x").unwrap_err();
        assert!(matches!(e, ErrorDeFirma::CustodioNoDisponible(_)));
    }
}

#[cfg(all(test, feature = "escrow"))]
mod pruebas_con_comparticiones {
    use super::*;
    use crate::pqsign::generate_keypair;
    use crate::shamir;

    /// La firma reconstruida desde comparticiones es la misma que la directa, y
    /// la verifica el verificador de siempre.
    #[test]
    fn firmar_desde_comparticiones_da_una_firma_valida() {
        let (vk, sk) = generate_keypair();
        let mensaje = b"informe con firma repartida";
        let esperada = sk.sign(mensaje);

        let partes = shamir::split(&sk.to_bytes(), 3, 5).unwrap();
        let firma = firmar_con_comparticiones(&partes[..3], mensaje).unwrap();

        assert_eq!(firma, esperada, "el camino repartido cambia la firma");
        assert!(vk.verify(mensaje, &firma));
    }

    /// Por debajo del umbral no se firma. Quien lo caza es `combine`, que
    /// cuenta las comparticiones contra el umbral que ellas mismas declaran.
    #[test]
    fn por_debajo_del_umbral_no_se_firma() {
        let (_, sk) = generate_keypair();
        let partes = shamir::split(&sk.to_bytes(), 3, 5).unwrap();
        match firmar_con_comparticiones(&partes[..2], b"x") {
            Err(ErrorDeFirma::OperacionRechazada(_)) => {}
            Ok(_) => panic!("firmó con menos comparticiones que el umbral"),
            Err(e) => panic!("error inesperado: {e}"),
        }
    }

    /// Mezclar comparticiones de dos repartos distintos tampoco puede firmar.
    ///
    /// Comprobado quién lo caza, porque importa: NO es `SigningKey::from_bytes`
    /// —64 bytes cualesquiera son dos semillas válidas y los aceptaría— sino el
    /// verificador que `combine` lleva dentro (`VerificationFailed`). Sin él,
    /// esta mezcla habría firmado con una clave inventada y la firma habría
    /// tenido formato perfecto.
    #[test]
    fn comparticiones_de_repartos_distintos_no_firman() {
        let (_, sk_a) = generate_keypair();
        let (_, sk_b) = generate_keypair();
        let a = shamir::split(&sk_a.to_bytes(), 3, 5).unwrap();
        let b = shamir::split(&sk_b.to_bytes(), 3, 5).unwrap();
        let mezcla = vec![a[0].clone(), a[1].clone(), b[2].clone()];
        assert!(
            firmar_con_comparticiones(&mezcla, b"x").is_err(),
            "firmó mezclando dos repartos distintos"
        );
    }
}
