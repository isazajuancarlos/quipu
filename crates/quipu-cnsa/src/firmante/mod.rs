// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

//! Dónde vive la clave privada de firma.
//!
//! # El problema que resuelve, y por qué en ESTE perfil pesa más
//!
//! Hasta ahora la única respuesta posible era «en la memoria del proceso»:
//! [`crate::firma::SigningKey`] guarda la semilla y firma con ella. Para un
//! comité de seguridad esa respuesta cierra la conversación en la primera
//! pregunta, porque la clave puede acabar en un volcado, en el *swap* o en una
//! variable de entorno de la que nadie se acuerda.
//!
//! En el perfil CNSA la pregunta llega antes y por dos caminos a la vez:
//!
//! - **FIPS 140-3.** Esta librería NO está validada y no va a estarlo (ver el
//!   README). La vía real para un pliego que lo exija es poner debajo un
//!   dispositivo que sí lo esté — y para eso hace falta este módulo.
//! - **SP 800-208.** Su §8.1 obliga a que la generación de claves y de firmas
//!   de LMS/XMSS se valide *«only … within hardware cryptographic modules»*.
//!   Ese renglón no lo cubre ninguna librería de software, y la respuesta que
//!   damos por escrito —un HSM debajo— tiene que existir AQUÍ, no solo en
//!   `quipu`, que firma híbrido y es justo el asterisco que este perfil evita.
//!
//! # Por qué el trait no expone la clave
//!
//! La tentación es un trait con `fn clave_privada(&self) -> SigningKey`. Eso
//! haría trivial cualquier backend y **destruiría el único punto** del asunto:
//! si la clave se puede pedir, ya salió del dispositivo. Lo que se pide aquí es
//! una *operación*, nunca el material.
//!
//! # Por qué el ensamblado no es tarea del backend
//!
//! Una firma de este perfil no es «ML-DSA sobre el mensaje»: ata una etiqueta
//! de dominio y la clave pública COMPLETA con su longitud explícita delante
//! (ver [`crate::firma`]). Si cada backend armara la preimagen, cada backend
//! podría equivocarse en eso, y el error saldría como «firma inválida» en
//! producción y no en una prueba. El backend implementa solo lo que **obliga**
//! a tener la clave —firmar unos bytes— y [`firmar`] pone el resto.
//!
//! # El formato en cable no cambia
//!
//! Una firma hecha dentro de un HSM y una hecha en memoria son verificables por
//! el mismo [`crate::firma::VerifyingKey::verificar`]. No son byte a byte
//! idénticas y no deben serlo: la de memoria es determinista y la del
//! dispositivo se pide *hedged* (ver [`pkcs11`]), que es la variante que FIPS
//! 204 recomienda cuando el atacante puede tocar el aparato — precisamente el
//! adversario que aparece en cuanto la clave se muda a un HSM.

use crate::firma::{SigningKey, VerifyingKey, SIGNATURE_LEN};

// Custodio respaldado por un dispositivo PKCS#11 (HSM, token, tarjeta). Tras la
// feature `hsm` porque arrastra `cryptoki` y su cadena de FFI.
//
// La documentación va DENTRO del módulo, por lo mismo que en `lib.rs`: un `///`
// aquí haría que rustdoc resolviera los enlaces de `pkcs11` en el ámbito del
// padre, y `[`super::Custodio`]` se rompería.
#[cfg(feature = "hsm")]
pub mod pkcs11;

/// Los bytes que un custodio tiene derecho a firmar, y **la única forma de
/// obtenerlos**.
///
/// # Por qué existe este tipo, y no un `&[u8]`
///
/// Con `&[u8]` en el trait, la separación de dominio del perfil era una promesa
/// escrita y no una propiedad del código: `Custodio` es público, así que
/// cualquiera con un custodio en la mano —incluido quien reciba un
/// `&dyn Custodio` sin la sesión PKCS#11— podía pedirle una firma ML-DSA-87 de
/// la clave de producción sobre BYTES ARBITRARIOS, fuera de la forma
/// `etiqueta || len(vk) || vk || mensaje`. Justo el conjunto de bytes que otro
/// protocolo aceptaría como suyos: la mitad ML-DSA de una firma de `quipu`, un
/// TBSCertificate, un manifiesto de firmware.
///
/// Lo cazó la revisión de seguridad del 2026-08-13, y era peor que un descuido:
/// dos comentarios de este crate —el de `firma::firmar_preimagen_cruda` y el de
/// [`firmar`]— afirmaban literalmente que ese camino no existía. Probado con una
/// sonda desde FUERA del crate antes de arreglarlo: 4627 bytes sobre
/// `b"TBSCertificate ajeno"`.
///
/// Ahora el constructor es `pub(crate)`, así que el único origen posible de una
/// `Preimagen` es [`firmar`]. Un backend de terceros sigue pudiendo implementar
/// [`Custodio`] —lee los bytes con [`Preimagen::como_bytes`] y se los pasa a su
/// dispositivo—; lo que ya no puede es FABRICARLOS.
pub struct Preimagen(Vec<u8>);

impl Preimagen {
    /// Compone la preimagen del perfil. `pub(crate)`: es la barandilla entera.
    pub(crate) fn nueva(vk: &[u8], mensaje: &[u8]) -> Self {
        Self(crate::firma::preimagen_publica(vk, mensaje))
    }

    /// Los bytes que hay que entregarle al dispositivo, tal cual.
    pub fn como_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Por qué no se pudo firmar.
///
/// No lleva variante «clave incorrecta»: eso es un fallo de programación, no un
/// estado del que un servicio se recupere.
///
/// `#[non_exhaustive]` desde que nace (0.1.2): una variante nueva —como
/// `FirmaNoVerifica`, que llegó en el concilio antes de cortar— no debe romper el
/// `match` de nadie aguas abajo. Es la lección de `quipu::stream::StreamError`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    /// La firma tiene la longitud buena pero NO verifica bajo la clave pública
    /// que el custodio anuncia: una firma inválida disfrazada de válida. La
    /// produce un custodio cuya pública no es el par de su privada (manejadores
    /// cruzados, una etiqueta compartida entre claves rotadas), uno que cambia
    /// de clave entre leer la vk y firmar, o un fallo del dispositivo al firmar
    /// —y una firma corrompida por fallo es justo la que filtra la clave—. Es la
    /// misma variante que el `firmante` de `quipu`, que ya la tenía.
    FirmaNoVerifica,
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
            Self::FirmaNoVerifica => write!(
                f,
                "la firma no verifica bajo la clave pública del custodio (par cruzado, carrera o fallo del dispositivo)"
            ),
        }
    }
}

impl core::error::Error for ErrorDeFirma {}

/// Lo mínimo que hay que saber hacer para custodiar la clave de firma de este
/// perfil.
///
/// Es UNA sola operación, y ahí está la diferencia con el `Custodio` de
/// `quipu`: aquel arma dos mitades —Ed25519 y ML-DSA-87— porque firma híbrido.
/// CNSA 2.0 nombra ML-DSA-87 y no pide socio clásico, así que aquí solo hay una
/// firma que pedirle al dispositivo. Es más simple y es **más débil**; está
/// dicho en la cabecera de [`crate::firma`].
pub trait Custodio {
    /// La clave pública de la identidad que este custodio representa.
    ///
    /// Es falible a propósito: un dispositivo puede tener que abrir sesión para
    /// leerla.
    fn clave_de_verificacion(&self) -> Result<VerifyingKey, ErrorDeFirma>;

    /// Firma la [`Preimagen`] —los bytes exactos, sin envolver ni volver a
    /// componer— con la clave ML-DSA-87 que custodia.
    ///
    /// El parámetro es un tipo opaco y no un `&[u8]` a propósito: es lo que
    /// impide que alguien con un custodio en la mano firme lo que quiera. Ver
    /// [`Preimagen`].
    fn firmar_mldsa(&self, preimagen: &Preimagen) -> Result<Vec<u8>, ErrorDeFirma>;
}

/// Arma la firma del perfil CNSA contra cualquier custodio.
///
/// **Este es el único sitio donde se decide el formato.** Un backend nuevo no
/// puede producir una firma con otra forma aunque quiera, porque no participa
/// en el ensamblado — y desde el 2026-08-13 eso lo sostiene el compilador y no
/// un comentario (ver [`Preimagen`]).
///
/// # El camino legítimo COMPILA
///
/// ```
/// use quipu_cnsa::firma::generar_par;
/// use quipu_cnsa::firmante::{firmar, EnMemoria};
///
/// let (vk, sk) = generar_par().unwrap();
/// let firma = firmar(&EnMemoria::nuevo(sk), b"acta").unwrap();
/// assert!(vk.verificar(b"acta", &firma));
/// ```
///
/// # Y el ilegítimo NO COMPILA, que es la mitad que importa
///
/// Pedirle al custodio una firma sobre bytes que uno elige —saltándose la
/// etiqueta de dominio y la clave pública— es un error de tipos. Las dos
/// pruebas van juntas a propósito: un `compile_fail` solo, con una errata,
/// pasaría igual.
///
/// ```compile_fail
/// use quipu_cnsa::firma::generar_par;
/// use quipu_cnsa::firmante::{Custodio, EnMemoria};
///
/// let (_vk, sk) = generar_par().unwrap();
/// let custodio = EnMemoria::nuevo(sk);
/// // `firmar_mldsa` pide `&Preimagen`, no `&[u8]`: esto no existe.
/// let _ = custodio.firmar_mldsa(b"TBSCertificate ajeno");
/// ```
///
/// Y fabricarse la preimagen tampoco, porque su constructor es `pub(crate)`:
///
/// ```compile_fail
/// use quipu_cnsa::firmante::Preimagen;
/// let _ = Preimagen::nueva(b"vk", b"mensaje");
/// ```
pub fn firmar<C: Custodio + ?Sized>(custodio: &C, mensaje: &[u8]) -> Result<Vec<u8>, ErrorDeFirma> {
    let vk = custodio.clave_de_verificacion()?;
    let preimagen = Preimagen::nueva(&vk.a_bytes(), mensaje);

    let firma = custodio.firmar_mldsa(&preimagen)?;
    if firma.len() != SIGNATURE_LEN {
        return Err(ErrorDeFirma::LongitudInesperada {
            esperaba: SIGNATURE_LEN,
            recibio: firma.len(),
        });
    }
    // VERIFICAR TRAS FIRMAR, antes de que la firma salga del proceso. Falla
    // CERRADO en el origen en vez de en un verificador remoto, tarde y con el
    // documento ya emitido; y no deja salir una firma corrompida por un fallo del
    // dispositivo, que es la que filtra la clave en un ataque por fallo inducido.
    // Cuesta una verificación ML-DSA-87, menos que la firma que acaba de pedir.
    // Hasta el 2026-11-06 aquí solo se miraba la longitud, mientras que el
    // `firmante` de `quipu` ya verificaba: lo cazó el concilio (haiku, verificado
    // por sonnet contra kryoptic).
    if !vk.verificar(mensaje, &firma) {
        return Err(ErrorDeFirma::FirmaNoVerifica);
    }
    Ok(firma)
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
        Ok(self.clave.clave_de_verificacion())
    }

    fn firmar_mldsa(&self, preimagen: &Preimagen) -> Result<Vec<u8>, ErrorDeFirma> {
        Ok(self.clave.firmar_preimagen_cruda(preimagen.como_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firma::generar_par;

    /// LA MITAD QUE TIENE QUE COINCIDIR, y es la prueba de que el camino nuevo
    /// no inventó un formato: firmar por `EnMemoria` da el MISMO byte que
    /// `SigningKey::firmar`, que es el camino de siempre.
    #[test]
    fn en_memoria_produce_la_misma_firma_que_el_camino_directo() {
        let (vk, sk) = generar_par().unwrap();
        let directa = sk.firmar(b"acta de custodia");
        let por_custodio = firmar(&EnMemoria::nuevo(sk), b"acta de custodia").unwrap();
        assert_eq!(directa, por_custodio, "el custodio cambió el formato");
        assert!(vk.verificar(b"acta de custodia", &por_custodio));
    }

    /// Custodio de mentira que devuelve lo que se le diga: es el instrumento
    /// con el que se prueban los caminos de error sin un dispositivo.
    struct Falso {
        vk: VerifyingKey,
        respuesta: Result<Vec<u8>, ErrorDeFirma>,
    }

    impl Custodio for Falso {
        fn clave_de_verificacion(&self) -> Result<VerifyingKey, ErrorDeFirma> {
            Ok(self.vk.clone())
        }
        fn firmar_mldsa(&self, _preimagen: &Preimagen) -> Result<Vec<u8>, ErrorDeFirma> {
            self.respuesta.clone()
        }
    }

    /// LA MITAD QUE TIENE QUE FALLAR. Una firma corta es indistinguible de una
    /// buena hasta que alguien la verifica, y un dispositivo que la devuelva
    /// tiene que estrellarse aquí, con su longitud dicha.
    #[test]
    fn una_firma_de_longitud_ajena_se_rechaza_antes_de_salir() {
        let (vk, sk) = generar_par().unwrap();
        let corta = sk.firmar(b"m")[..SIGNATURE_LEN - 1].to_vec();
        let falso = Falso { vk: vk.clone(), respuesta: Ok(corta) };
        assert_eq!(
            firmar(&falso, b"m"),
            Err(ErrorDeFirma::LongitudInesperada {
                esperaba: SIGNATURE_LEN,
                recibio: SIGNATURE_LEN - 1
            })
        );

        let mut larga = sk.firmar(b"m");
        larga.push(0);
        let falso = Falso { vk, respuesta: Ok(larga) };
        assert!(matches!(
            firmar(&falso, b"m"),
            Err(ErrorDeFirma::LongitudInesperada { .. })
        ));
    }

    /// El error del dispositivo sube tal cual: `firmar` no lo reclasifica ni lo
    /// convierte en una firma vacía.
    #[test]
    fn el_fallo_del_dispositivo_sube_sin_disfraz() {
        let (vk, _) = generar_par().unwrap();
        let falso = Falso {
            vk,
            respuesta: Err(ErrorDeFirma::CustodioNoDisponible("token fuera".into())),
        };
        assert_eq!(
            firmar(&falso, b"m"),
            Err(ErrorDeFirma::CustodioNoDisponible("token fuera".into()))
        );
    }

    /// Un custodio que firma con OTRA clave que la que anuncia produce una firma
    /// de longitud correcta que NO verifica: `firmar` la rechaza EN EL ORIGEN.
    /// (Hasta el 2026-11-06 esta prueba fijaba lo contrario —que pasaba y «moría
    /// en el verificador»— con un comentario que decía que `firmar` no tenía con
    /// qué detectarlo; tenía la vk en la mano.)
    #[test]
    fn una_firma_de_otra_clave_se_rechaza_en_el_origen() {
        let (vk_a, _) = generar_par().unwrap();
        let (_, sk_b) = generar_par().unwrap();
        let falso = Falso {
            vk: vk_a,
            respuesta: Ok(sk_b.firmar(b"m")),
        };
        assert_eq!(firmar(&falso, b"m"), Err(ErrorDeFirma::FirmaNoVerifica));
    }

    /// FALLO INDUCIDO: la firma LEGÍTIMA de la clave buena, con un solo byte
    /// volteado, no sale. Con la verificación tras firmar revertida, `firmar`
    /// devuelve `Ok` y esta prueba se pone roja. El CONTROL (la mitad que acepta)
    /// es el mismo custodio sin voltear nada.
    #[test]
    fn una_firma_corrompida_por_fallo_no_sale_del_proceso() {
        struct Volteador {
            dentro: EnMemoria,
            voltear: std::cell::Cell<bool>,
        }
        impl Custodio for Volteador {
            fn clave_de_verificacion(&self) -> Result<VerifyingKey, ErrorDeFirma> {
                self.dentro.clave_de_verificacion()
            }
            fn firmar_mldsa(&self, preimagen: &Preimagen) -> Result<Vec<u8>, ErrorDeFirma> {
                let mut f = self.dentro.firmar_mldsa(preimagen)?;
                if self.voltear.get() {
                    f[100] ^= 0x01;
                }
                Ok(f)
            }
        }
        let (vk, sk) = generar_par().unwrap();
        let custodio = Volteador {
            dentro: EnMemoria::nuevo(sk),
            voltear: std::cell::Cell::new(false),
        };
        let f = firmar(&custodio, b"acta").expect("control: la firma sana sale");
        assert!(vk.verificar(b"acta", &f), "control: y verifica");

        custodio.voltear.set(true);
        assert_eq!(firmar(&custodio, b"acta"), Err(ErrorDeFirma::FirmaNoVerifica));
    }

    /// La preimagen que recibe el backend es EXACTAMENTE la del formato: ata la
    /// etiqueta de dominio y la clave pública. Si alguien «simplificara»
    /// `firmar` para pasar el mensaje pelado, esto se pone rojo.
    #[test]
    fn al_backend_le_llega_la_preimagen_completa_y_no_el_mensaje() {
        use std::sync::Mutex;

        struct Espia {
            vk: VerifyingKey,
            visto: Mutex<Vec<u8>>,
        }
        impl Custodio for Espia {
            fn clave_de_verificacion(&self) -> Result<VerifyingKey, ErrorDeFirma> {
                Ok(self.vk.clone())
            }
            fn firmar_mldsa(&self, preimagen: &Preimagen) -> Result<Vec<u8>, ErrorDeFirma> {
                *self.visto.lock().unwrap() = preimagen.como_bytes().to_vec();
                Err(ErrorDeFirma::OperacionRechazada("solo miraba".into()))
            }
        }

        let (vk, _) = generar_par().unwrap();
        let espia = Espia { vk: vk.clone(), visto: Mutex::new(Vec::new()) };
        let _ = firmar(&espia, b"mensaje");
        let visto = espia.visto.lock().unwrap().clone();

        assert_eq!(visto, crate::firma::preimagen_publica(&vk.a_bytes(), b"mensaje"));
        assert_ne!(visto, b"mensaje".to_vec());
    }
}
