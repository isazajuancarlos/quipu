// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

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
//! El formato en cable no cambia y las verifica el mismo verificador.
//!
//! **Lo que NO son es byte a byte iguales, y aquí ponía que sí.** La mitad
//! ML-DSA se pide al dispositivo con `HedgeType::Preferred` (ver
//! [`pkcs11`]), o sea aleatorizada si el aparato puede: dos firmas del mismo
//! mensaje con la misma clave difieren, y una del HSM difiere de la de memoria,
//! que es determinista. Intercambiables sí; idénticas no. Lo señaló la revisión
//! de seguridad del 2026-08-13 comparando este párrafo con el código de al
//! lado.
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

/// Custodio respaldado por un dispositivo PKCS#11 (HSM, token, tarjeta). Tras
/// la feature `hsm` porque arrastra `cryptoki` y su cadena de FFI.
#[cfg(feature = "hsm")]
pub mod pkcs11;

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
    /// La firma ARMADA no verifica bajo la clave pública que el propio custodio
    /// declaró. Es la misma lógica que [`Self::LongitudInesperada`] llevada de la
    /// longitud al contenido: una firma inválida no debe salir del dispositivo
    /// disfrazada de válida. La produce un custodio que reenvía una firma vieja,
    /// que degrada una mitad, o que cambia de clave entre leer la vk y firmar
    /// (carrera), y también un fallo de hardware en la firma. Ver el laboratorio
    /// `lab::custodio_ataque`.
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
                "la firma armada no verifica bajo la clave pública del custodio (reenvío, degradación, carrera o fallo del dispositivo)"
            ),
        }
    }
}

impl core::error::Error for ErrorDeFirma {}

/// Lo mínimo que hay que saber hacer para custodiar una clave de firma de Quipu.
///
/// Las dos operaciones son justo las que **exigen** tener el material privado.
/// Todo lo demás lo pone [`firmar`].
/// Los bytes que se le entregan al dispositivo para que los firme.
///
/// # Por qué existe un tipo para esto
///
/// Con `&[u8]` en el trait, la separación de dominio del formato era una promesa
/// escrita y no una propiedad del código: `Custodio` es **público**, así que
/// cualquiera con un custodio en la mano —incluido quien reciba un
/// `&dyn Custodio` sin la sesión PKCS#11— podía pedirle una firma Ed25519 o
/// ML-DSA-87 de la clave de PRODUCCIÓN sobre **bytes arbitrarios**, sin la
/// etiqueta `quipu/v3/sign` ni la clave pública delante. Justo el conjunto de
/// bytes que otro protocolo aceptaría como suyos: un TBSCertificate, un
/// manifiesto de firmware, la mitad ML-DSA de una firma ajena.
///
/// La objeción obvia —«quien tiene el custodio ya puede llamar a `firmar` y
/// firmar lo que quiera»— es correcta y no salva el caso: `firmar` produce bytes
/// con la etiqueta de dominio delante, que ningún otro protocolo acepta. Lo que
/// el `&[u8]` añadía era la capacidad de SALIRSE de ese formato, y la etiqueta
/// existe precisamente porque eso importa. Si no importara, sobraría la etiqueta.
///
/// El constructor es `pub(crate)`: **ésa es la barandilla entera**. Un backend
/// sigue pudiendo hacer lo suyo —hablar con el token, elegir mecanismo, subir el
/// error— pero ya no puede FABRICAR lo que se firma.
///
/// Lo cazó una auditoría en `quipu-cnsa` el 2026-08-13 y se cerró allí; aquí
/// llegó el 2026-08-17, cuando otra auditoría encontró que el arreglo nunca se
/// había portado — y que en `quipu` la superficie es MAYOR, porque hay dos
/// mitades y con las dos se monta una firma híbrida completa.
pub struct Preimagen(Vec<u8>);

/// La barandilla, comprobada por el COMPILADOR y no por una prueba.
///
/// Desde fuera del crate no se puede fabricar lo que el dispositivo firma:
///
/// ```compile_fail
/// use quipu::firmante::Preimagen;
/// // `nueva` es pub(crate): esto NO compila, y ésa es la garantía.
/// let p = Preimagen::nueva(b"vk", b"TBSCertificate ajeno");
/// ```
///
/// Y la mitad que lo acredita — sin ella, un `compile_fail` con una errata
/// pasaría igual y no probaría nada. Esto SÍ compila:
///
/// ```
/// use quipu::firmante::{firmar, EnMemoria};
/// let (_vk, sk) = quipu::pqsign::generate_keypair();
/// let custodio = EnMemoria::nuevo(sk);
/// let firma = firmar(&custodio, b"un acta").expect("firma");
/// assert_eq!(firma.len(), quipu::pqsign::SIGNATURE_LEN);
/// ```
impl Preimagen {
    /// Compone la preimagen del formato. `pub(crate)` a propósito.
    pub(crate) fn nueva(vk: &[u8], mensaje: &[u8]) -> Self {
        Self(build_preimage(vk, mensaje))
    }

    /// Los bytes que hay que entregarle al dispositivo, tal cual.
    pub fn como_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub trait Custodio {
    /// La clave pública de la identidad que este custodio representa.
    ///
    /// Es falible a propósito: un HSM puede tener que abrir sesión para leerla.
    fn clave_de_verificacion(&self) -> Result<VerifyingKey, ErrorDeFirma>;

    /// Firma `preimagen` con la mitad Ed25519.
    fn firmar_ed25519(&self, preimagen: &Preimagen) -> Result<Vec<u8>, ErrorDeFirma>;

    /// Firma `preimagen` con la mitad ML-DSA-87.
    fn firmar_mldsa(&self, preimagen: &Preimagen) -> Result<Vec<u8>, ErrorDeFirma>;
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
    let preimagen = Preimagen::nueva(&vk.to_bytes(), mensaje);

    let ed = custodio.firmar_ed25519(&preimagen)?;
    comprobar_longitud(ed.len(), ED25519_SIG_LEN)?;
    let ml = custodio.firmar_mldsa(&preimagen)?;
    comprobar_longitud(ml.len(), MLDSA_SIG_LEN)?;

    let mut firma = Vec::with_capacity(SIGNATURE_LEN);
    firma.extend_from_slice(&ed);
    firma.extend_from_slice(&ml);

    // Verificar-tras-firmar: la firma armada tiene que verificar bajo la MISMA vk
    // que se leyó al empezar. Es la comprobación de longitud llevada al contenido
    // —falla CERRADO en el origen en vez de dejar viajar una firma inválida— y
    // cierra de un golpe las tres formas de manipular la conversación con el
    // custodio: el reenvío (mitad de otra preimagen), la degradación (una mitad
    // basura) y la carrera (la vk atada no es la que firmó). Cubre además un
    // fallo de hardware en la firma. Cuesta una verificación, órdenes de magnitud
    // menos que las dos firmas que acaba de pedir. Lo motivó `lab::custodio_ataque`.
    if !vk.verify(mensaje, &firma) {
        return Err(ErrorDeFirma::FirmaNoVerifica);
    }
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

    fn firmar_ed25519(&self, preimagen: &Preimagen) -> Result<Vec<u8>, ErrorDeFirma> {
        Ok(self.clave.firmar_ed25519_crudo(preimagen.como_bytes()))
    }

    fn firmar_mldsa(&self, preimagen: &Preimagen) -> Result<Vec<u8>, ErrorDeFirma> {
        Ok(self.clave.firmar_mldsa_crudo(preimagen.como_bytes()))
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
    // TODO EL TRATO CON EL SECRETO OCURRE EN UN MARCO MÁS PROFUNDO, y el marco se
    // borra al volver. No es estilo: `limpiar_pila()` solo puede sobreescribir por
    // DEBAJO de su propio marco, así que llamarla desde la misma función que tiene
    // la clave en una variable local no limpia esa variable — el `#[inline(never)]`
    // es lo que garantiza que `interior` tenga marco propio y que quede por debajo.
    //
    // Hace falta porque `zeroize` no llega: en Rust MOVER un valor es un `memcpy`
    // y `Drop` solo corre en el destino final, de modo que cada movimiento de la
    // clave —al parámetro de `EnMemoria::nuevo`, al campo de la struct— deja una
    // copia que nadie borra.
    //
    // HONESTAMENTE: esto es DEFENSA EN PROFUNDIDAD, no una reparación demostrada.
    // El residuo que lo motivó —2 copias medidas en el runner del CI— resultó ser
    // en buena parte contaminación del propio banco de pruebas, que construía la
    // clave para montar el escenario y dejaba SU rastro. Con el banco corregido
    // —monta el escenario en un marco aparte y solo entrega comparticiones, que es
    // lo que hace un llamante real— la medida da cero CON Y SIN estas líneas.
    // Se conservan porque no cuestan nada y porque la propiedad que dan sí está
    // probada en aislamiento (`el_limpiador_de_pila_borra_lo_que_un_marco_dejo_atras`),
    // pero que no se lea aquí que arreglaron algo que se pudiera demostrar roto.
    #[inline(never)]
    fn interior(
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

    let firma = interior(comparticiones, mensaje);
    crate::antihacker::limpiar_pila();
    firma
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqsign::generate_keypair;

    /// **AL DISPOSITIVO LE LLEGA LA PREIMAGEN COMPLETA, NO EL MENSAJE.**
    ///
    /// Es la mitad medible de la barandilla: el `compile_fail` del doctest
    /// impide FABRICAR una preimagen desde fuera, y esto comprueba que lo que se
    /// entrega lleva de verdad la etiqueta de dominio y la clave pública
    /// delante. Si alguien «simplificara» `firmar` para pasar el mensaje pelado,
    /// el tipo seguiría compilando y la garantía se habría ido — esta prueba es
    /// lo que se pone rojo.
    #[test]
    fn al_dispositivo_le_llega_la_preimagen_y_no_el_mensaje() {
        use std::cell::RefCell;

        struct Espia {
            clave: SigningKey,
            visto: RefCell<Vec<Vec<u8>>>,
        }
        impl Custodio for Espia {
            fn clave_de_verificacion(&self) -> Result<VerifyingKey, ErrorDeFirma> {
                Ok(self.clave.verifying_key())
            }
            fn firmar_ed25519(&self, p: &Preimagen) -> Result<Vec<u8>, ErrorDeFirma> {
                self.visto.borrow_mut().push(p.como_bytes().to_vec());
                Ok(self.clave.firmar_ed25519_crudo(p.como_bytes()))
            }
            fn firmar_mldsa(&self, p: &Preimagen) -> Result<Vec<u8>, ErrorDeFirma> {
                self.visto.borrow_mut().push(p.como_bytes().to_vec());
                Ok(self.clave.firmar_mldsa_crudo(p.como_bytes()))
            }
        }

        let (vk, sk) = crate::pqsign::generate_keypair();
        let mensaje = b"acta pericial numero 7";
        let espia = Espia { clave: sk, visto: RefCell::new(Vec::new()) };
        let firma = firmar(&espia, mensaje).expect("firma");

        let visto = espia.visto.borrow();
        assert_eq!(visto.len(), 2, "tienen que ser las DOS mitades");
        let esperado = build_preimage(&vk.to_bytes(), mensaje);
        for (n, v) in visto.iter().enumerate() {
            assert_eq!(v, &esperado, "la mitad {n} no recibió la preimagen del formato");
            assert_ne!(
                v.as_slice(),
                mensaje.as_slice(),
                "la mitad {n} recibió el MENSAJE pelado: la separación de dominio se perdió"
            );
        }
        // Y el control de que todo esto sirvió para algo: la firma verifica.
        assert!(vk.verify(mensaje, &firma), "la firma armada por el trait tiene que verificar");
    }


    /// La prueba que hace útil a todo el módulo: pasar por el trait tiene que
    /// dar EXACTAMENTE la misma firma que el camino directo.
    ///
    /// LO QUE ESTA PRUEBA **NO** DEMUESTRA, y el README llegó a afirmarlo: nada
    /// sobre un custodio de HARDWARE. Solo ejercita `EnMemoria`, donde la
    /// igualdad se cumple trivialmente porque los dos caminos llaman al mismo
    /// código determinista. En PKCS#11 se pide `HedgeType::Preferred` —ML-DSA
    /// aleatorizado si el dispositivo lo admite—, así que ahí los bytes SÍ
    /// difieren, y eso es correcto: el hedging es lo que recomienda FIPS-204.
    ///
    /// Lo que de verdad importa —que la firma la verifique el verificador de
    /// siempre, venga de donde venga— lo cubre la prueba de abajo, y esa sí es
    /// la propiedad que un cambio de custodio no puede romper. Una prueba que
    /// se lee como más general de lo que es acaba sosteniendo una frase falsa en
    /// la portada, y eso fue exactamente lo que pasó.
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
            fn firmar_ed25519(&self, _: &Preimagen) -> Result<Vec<u8>, ErrorDeFirma> {
                Ok(vec![0u8; ED25519_SIG_LEN - 1])
            }
            fn firmar_mldsa(&self, _: &Preimagen) -> Result<Vec<u8>, ErrorDeFirma> {
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
            fn firmar_ed25519(&self, _: &Preimagen) -> Result<Vec<u8>, ErrorDeFirma> {
                unreachable!("no debería llegar aquí sin clave pública")
            }
            fn firmar_mldsa(&self, _: &Preimagen) -> Result<Vec<u8>, ErrorDeFirma> {
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
