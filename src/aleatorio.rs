// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! El único sitio por donde Quipu pide aleatoriedad al sistema.
//!
//! # Por qué existe este módulo
//!
//! Antes había ocho `getrandom(...).expect("RNG del sistema")` repartidos por
//! `api`, `stream`, `oprf`, `pqsign` y `pqhybrid`. Ocho decisiones idénticas
//! tomadas por omisión, en ocho sitios, sin que nadie las hubiera decidido.
//!
//! # Las tres reglas
//!
//! **1. Nunca se sustituye.** Si el sistema no da entropía, no hay alternativa
//! segura: una clave con aleatoriedad predecible produce un contenedor que
//! *parece* correcto y es trivial de romper. Es el peor fallo posible porque no
//! se nota nunca. Ver [[directiva-fallar-en-vez-de-suponer]].
//!
//! **2. Se reintenta, pero ACOTADO.** De las causas reales de fallo solo una es
//! transitoria:
//!
//! | causa | ¿reintentar ayuda? |
//! |---|---|
//! | descriptores de fichero agotados | **sí**, se liberan en milisegundos |
//! | arranque temprano, pool sin sembrar | en Linux ni siquiera falla: bloquea |
//! | `seccomp` bloquea la llamada | no — sería un bucle infinito |
//! | falta `/dev/urandom` (chroot roto) | no — sería un bucle infinito |
//! | plataforma sin fuente de entropía | no — sería un bucle infinito |
//!
//! Un número pequeño de intentos cubre la transitoria; ante las permanentes
//! cuesta microsegundos antes de informar. Reintentar sin límite convertiría
//! cuatro de cinco causas en un cuelgue silencioso, que es peor que el error.
//!
//! **3. Se informa, y se informa lo accionable.** Lo que necesita quien integra
//! no es el detalle del kernel sino una decisión: *¿reintento yo también, o
//! tengo que arreglar el despliegue?* Por eso [`SinEntropia::probablemente_transitorio`].
//!
//! # Por qué no basta con `panic`
//!
//! `Cargo.toml` evita `panic = "abort"` porque el Security Lab usa
//! `catch_unwind`. Pero eso lo controla Quipu, **no quien integra**. Un binario
//! aguas abajo compilado con `panic = "abort"` —habitual para reducir tamaño—
//! convierte cada `.expect` en terminación sin desenrollar la pila, y por tanto
//! **sin ejecutar los `Drop`: sin zeroizar**. Un fallo de entropía es justo
//! cuando más importa que la limpieza ocurra.
//!
//! Y una biblioteca no debería matar el proceso de quien la usa. El llamante
//! sabe si puede abortar un cierre de mes limpiamente; Quipu no.

use core::fmt;

/// Intentos totales antes de rendirse. Tres porque la única causa transitoria
/// —descriptores agotados— se resuelve en el primer reintento o no se resuelve.
/// Más intentos no compran nada y retrasan el diagnóstico de las permanentes.
const INTENTOS: u32 = 3;

/// Cuántos bytes idénticos seguidos bastan para declarar la fuente atascada.
///
/// Ocho. La probabilidad de que salgan por azar en una posición dada es 2⁻⁵⁶: no
/// va a ocurrir nunca en la vida del programa. Un número más pequeño empezaría a
/// producir falsas alarmas, y una alarma que resulta falsa dos veces es una
/// alarma que a la tercera nadie mira.
const REPETICION_QUE_DELATA: usize = 8;

/// Por qué no se confía en lo que la fuente entregó.
///
/// # Lo que estas pruebas SÍ detectan
///
/// Entornos donde la fuente **está rota y lo aparenta**: un filtro seccomp que
/// devuelve éxito con el buffer intacto, un `chroot` sin `/dev/urandom` mal
/// emulado, un objetivo empotrado o un *shim* de WASM que devuelve constantes.
/// Son fallos deterministas del despliegue, y aparecen siempre.
///
/// # Lo que NO detectan, y hay que decirlo
///
/// **Un generador subvertido pero estadísticamente bueno pasa TODAS estas
/// pruebas**, y pasaría también monobit, rachas y cualquier batería que se le
/// añada: esa es justo la definición de un buen PRNG con semilla conocida por
/// otro. Contra eso no hay comprobación estadística posible — la defensa es la
/// procedencia del binario (build reproducible, release firmado), no una prueba
/// de salida.
///
/// Decirlo importa: una comprobación que se anuncia como más de lo que es
/// produce la misma falsa sensación de cobertura que un antivirus mal colocado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FalloDeSalud {
    /// La fuente devolvió un buffer entero de ceros.
    TodoCeros,
    /// Salieron [`REPETICION_QUE_DELATA`] o más bytes idénticos seguidos.
    Atascada {
        /// El byte que se repetía.
        byte: u8,
        /// Cuántas veces seguidas.
        veces: usize,
    },
}

impl fmt::Display for FalloDeSalud {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TodoCeros => write!(f, "la fuente devolvió TODO CEROS"),
            Self::Atascada { byte, veces } => write!(
                f,
                "la fuente devolvió el byte {byte:#04x} {veces} veces seguidas"
            ),
        }
    }
}

/// El sistema no pudo entregar aleatoriedad **en la que se pueda confiar**.
///
/// Cubre dos casos que exigen respuestas distintas y por eso se distinguen con
/// [`SinEntropia::salud`]:
///
/// - la fuente **no contestó** (`salud: None`) — revisar el despliegue;
/// - la fuente **contestó y su salida no supera las pruebas de salud**
///   (`salud: Some(_)`) — mucho más grave: está entregando algo que no es
///   aleatorio y lo presenta como si lo fuera.
///
/// No lleva ningún dato derivado de material sensible: un fallo de entropía
/// ocurre *antes* de que exista nada que proteger, así que el mensaje se puede
/// propagar y registrar sin filtrar nada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinEntropia {
    /// Cuántos bytes se pedían.
    pub bytes: usize,
    /// Intentos realizados.
    pub intentos: u32,
    /// Código que devolvió el sistema operativo, si lo hubo.
    pub codigo_os: Option<i32>,
    /// Qué prueba de salud falló, si el fallo fue de salud y no de respuesta.
    pub salud: Option<FalloDeSalud>,
}

/// Pruebas de salud CONTINUAS sobre lo que la fuente acaba de entregar.
///
/// Van en cada extracción y no solo al arrancar, que es la diferencia que
/// importa: una fuente puede degradarse DESPUÉS del arranque —un `seccomp` que
/// se endurece, una migración de máquina virtual— y una comprobación única no lo
/// vería. Es el mismo principio que la SP 800-90B de NIST exige para las fuentes
/// de ruido, aplicado aquí a la salida del CSPRNG del sistema.
///
/// Coste: una pasada O(n) con una comparación por byte. Frente a un Argon2id o
/// un AEAD, no se nota.
fn salud_de(muestra: &[u8]) -> Option<FalloDeSalud> {
    // UNA SOLA COTA, y es la de repetición. La primera versión tenía además un
    // `MINIMO_PARA_CEROS = 16` para la prueba de «todo ceros», y era REGLA
    // MUERTA: quince ceros ya disparan la de repetición, así que las dos se
    // contradecían — una decía «plausible» y la otra «atascada» sobre el mismo
    // buffer. Lo cazó la mitad del banco que comprueba que NO se rechaza lo
    // legítimo, que es justo para lo que existe esa mitad.
    //
    // `TodoCeros` sobrevive como DIAGNÓSTICO, no como regla aparte: un buffer
    // entero de ceros es el caso del `seccomp` que devuelve éxito sin tocar
    // nada, y decirlo así ahorra media hora a quien lo lea en un registro.
    if muestra.len() >= REPETICION_QUE_DELATA && muestra.iter().all(|b| *b == 0) {
        return Some(FalloDeSalud::TodoCeros);
    }
    let mut seguidos = 1usize;
    for par in muestra.windows(2) {
        if par[0] == par[1] {
            seguidos += 1;
            if seguidos >= REPETICION_QUE_DELATA {
                return Some(FalloDeSalud::Atascada {
                    byte: par[0],
                    veces: seguidos,
                });
            }
        } else {
            seguidos = 1;
        }
    }
    None
}

impl SinEntropia {
    /// Si volver a intentarlo más tarde tiene alguna posibilidad.
    ///
    /// Es lo ÚNICO accionable para quien integra: distingue «espera y repite»
    /// de «arregla el despliegue». No se pretende clasificar la causa exacta —
    /// eso depende del sistema y no siempre se puede saber—, solo separar las
    /// dos respuestas posibles.
    ///
    /// Ante la duda devuelve `false`: decirle a alguien que reintente algo que
    /// nunca va a funcionar lo mete en un bucle; decirle que revise el
    /// despliegue cuando bastaba esperar le cuesta una mirada.
    pub fn probablemente_transitorio(&self) -> bool {
        // UN FALLO DE SALUD NUNCA ES TRANSITORIO, y decir lo contrario sería
        // peligroso: quien reintente acabará obteniendo una extracción que
        // «parece bien» de la MISMA fuente rota, y seguirá adelante con ella.
        // Ahí no se reintenta; se para.
        if self.salud.is_some() {
            return false;
        }
        // EMFILE (24) y ENFILE (23): descriptores agotados, en el proceso o en
        // el sistema. Son los únicos que se resuelven solos.
        matches!(self.codigo_os, Some(23) | Some(24))
    }
}

impl fmt::Display for SinEntropia {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(s) = self.salud {
            return write!(
                f,
                "la fuente de aleatoriedad ENTREGÓ {} bytes pero no son de fiar: {s}. \
                 NO se generó ninguna clave. Esto no se reintenta: la misma fuente \
                 rota puede devolver a la siguiente algo que PAREZCA bien",
                self.bytes
            );
        }
        write!(
            f,
            "el sistema no entregó {} bytes de aleatoriedad tras {} intento(s)",
            self.bytes, self.intentos
        )?;
        if let Some(c) = self.codigo_os {
            write!(f, " (código del sistema: {c})")?;
        }
        if self.probablemente_transitorio() {
            write!(f, ". Parece transitorio —descriptores agotados—: reintentar puede servir")
        } else {
            write!(
                f,
                ". No parece transitorio: revise el despliegue (¿seccomp bloquea \
                 getrandom?, ¿falta /dev/urandom en el chroot?). NO se generó \
                 ninguna clave: Quipu no sustituye la entropía por nada"
            )
        }
    }
}

impl std::error::Error for SinEntropia {}

/// Llena `destino` con aleatoriedad del sistema.
///
/// Reintenta hasta [`INTENTOS`] veces y, si no lo consigue, informa. **No
/// sustituye ni degrada** bajo ninguna circunstancia.
pub fn llenar(destino: &mut [u8]) -> Result<(), SinEntropia> {
    let mut ultimo: Option<i32> = None;
    for intento in 1..=INTENTOS {
        match getrandom::fill(destino) {
            Ok(()) => {
                // LA SALUD SE COMPRUEBA ANTES DE DEVOLVER. Si la fuente contestó
                // pero lo que entregó no pasa las pruebas, se BORRA el buffer —
                // el llamante no puede quedarse con bytes que ya sabemos malos—
                // y se falla sin reintentar.
                return match salud_de(destino) {
                    None => Ok(()),
                    Some(fallo) => {
                        destino.fill(0);
                        Err(SinEntropia {
                            bytes: destino.len(),
                            intentos: intento,
                            codigo_os: None,
                            salud: Some(fallo),
                        })
                    }
                };
            }
            Err(e) => {
                ultimo = e.raw_os_error();
                // Si el sistema dice claramente que esto no va a funcionar
                // nunca, no se gastan los intentos restantes: se informa ya.
                // Un diagnóstico rápido vale más que una insistencia inútil.
                let transitorio = matches!(ultimo, Some(23) | Some(24));
                if !transitorio {
                    return Err(SinEntropia {
                        bytes: destino.len(),
                        intentos: intento,
                        codigo_os: ultimo,
                        salud: None,
                    });
                }
            }
        }
    }
    Err(SinEntropia {
        bytes: destino.len(),
        intentos: INTENTOS,
        codigo_os: ultimo,
        salud: None,
    })
}

/// Un array de `N` bytes aleatorios.
pub fn bytes<const N: usize>() -> Result<[u8; N], SinEntropia> {
    let mut buf = [0u8; N];
    llenar(&mut buf)?;
    Ok(buf)
}

/// Un generador recién sembrado desde el sistema, listo para las funciones que
/// exigen `CryptoRng`.
///
/// # La frontera entre lo falible y lo infalible
///
/// Los traits de RNG de `rand_core` son INFALIBLES: `fill_bytes` devuelve
/// bytes, no `Result`. Un generador que hable con el sistema operativo en cada
/// llamada, si el sistema falla, solo puede entrar en pánico o devolver basura.
/// Por eso el ecosistema usa `UnwrapErr(SysRng)`, que es el nombre educado del
/// pánico.
///
/// La salida es mover el fallo **antes** de entrar a ese mundo:
///
/// ```text
/// 1. pedir 32 bytes al sistema   ← aquí puede fallar, y devuelve Result
/// 2. expandirlos con ChaCha20    ← ya no puede fallar: es aritmética pura
/// 3. entregárselos a ml-kem      ← que exige un CryptoRng infalible
/// ```
///
/// Esta función es el paso 1 y 2. **Es el único punto del programa donde una
/// operación falible se convierte en una infalible**, y por eso está aquí sola
/// y no repartida por los módulos que la necesitan.
///
/// # Por qué `rand_chacha` y no ChaCha20 a pelo
///
/// Escribir el paso 2 a mano son quince líneas —clave = semilla, nonce a cero,
/// producir flujo— y son quince líneas de criptografía propia. `stream.rs` ya
/// fija la regla de la casa: *no se inventan primitivas*. `rand_chacha` hace
/// exactamente esto, escrito y auditado por el equipo de `rust-random`.
///
/// # Qué NO hace
///
/// **No sustituye la entropía del sistema: la expande.** La semilla es fresca
/// en cada llamada y no hay estado global ni generador de larga vida. Si el
/// sistema no da los 32 bytes, esta función falla y no se genera ninguna clave.
pub fn generador() -> Result<rand_chacha::ChaCha20Rng, SinEntropia> {
    use rand_core::SeedableRng;
    Ok(rand_chacha::ChaCha20Rng::from_seed(bytes::<32>()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn llena_el_buffer_entero() {
        // Con 4096 bytes, que todos salgan cero es 2^-32768: si pasa, el RNG
        // está roto y la prueba tiene razón en fallar.
        let mut buf = [0u8; 4096];
        llenar(&mut buf).expect("el RNG del sistema debe funcionar en el CI");
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn dos_llamadas_no_dan_lo_mismo() {
        let a: [u8; 32] = bytes().unwrap();
        let b: [u8; 32] = bytes().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn un_buffer_vacio_no_es_un_error() {
        // Pedir cero bytes es legítimo y no debe inventarse un fallo.
        assert!(llenar(&mut []).is_ok());
    }

    #[test]
    fn el_mensaje_distingue_transitorio_de_permanente() {
        let transitorio =
            SinEntropia { bytes: 32, intentos: 3, codigo_os: Some(24), salud: None };
        assert!(transitorio.probablemente_transitorio());
        assert!(transitorio.to_string().contains("reintentar puede servir"));

        let permanente =
            SinEntropia { bytes: 32, intentos: 1, codigo_os: Some(1), salud: None };
        assert!(!permanente.probablemente_transitorio());
        assert!(permanente.to_string().contains("revise el despliegue"));
        // Y dice lo más importante: que NO se fabricó nada.
        assert!(permanente.to_string().contains("no sustituye"));
    }

    #[test]
    fn sin_codigo_del_sistema_se_asume_permanente() {
        // Ante la duda, no se manda a nadie a un bucle de reintentos.
        let desconocido =
            SinEntropia { bytes: 32, intentos: 3, codigo_os: None, salud: None };
        assert!(!desconocido.probablemente_transitorio());
    }

    // --- El reintento tiene que DISCRIMINAR -------------------------------
    //
    // Un mecanismo de reintento que no se ha probado contra las dos ramas es
    // una suposición. Se reproduce aquí la lógica de `llenar` contra una fuente
    // simulada, porque no se puede hacer fallar al RNG del sistema a voluntad.
    // Lo que se fija es la POLÍTICA, que es lo que decidimos y lo que se puede
    // romper sin darse cuenta.

    /// Igual que `llenar`, pero pidiéndole los bytes a `fuente`.
    fn politica(fuente: &mut dyn FnMut() -> Result<(), i32>) -> Result<u32, (u32, Option<i32>)> {
        let mut ultimo = None;
        for intento in 1..=INTENTOS {
            match fuente() {
                Ok(()) => return Ok(intento),
                Err(c) => {
                    ultimo = Some(c);
                    if !matches!(ultimo, Some(23) | Some(24)) {
                        return Err((intento, ultimo));
                    }
                }
            }
        }
        Err((INTENTOS, ultimo))
    }

    #[test]
    fn un_fallo_transitorio_se_recupera_en_el_reintento() {
        // Descriptores agotados que se liberan: la razón por la que el
        // reintento existe.
        let mut n = 0;
        let mut fuente = || {
            n += 1;
            if n == 1 { Err(24) } else { Ok(()) }
        };
        assert_eq!(politica(&mut fuente), Ok(2), "debía recuperarse al segundo");
    }

    #[test]
    fn un_fallo_permanente_no_gasta_los_intentos() {
        // seccomp o /dev/urandom ausente: insistir no arregla nada y solo
        // retrasa el diagnóstico. Tiene que rendirse al PRIMER intento.
        let mut llamadas = 0;
        let mut fuente = || {
            llamadas += 1;
            Err(1) // EPERM
        };
        assert_eq!(politica(&mut fuente), Err((1, Some(1))));
        assert_eq!(llamadas, 1, "insistió ante una causa permanente");
    }

    #[test]
    fn un_transitorio_que_nunca_cede_se_rinde_y_no_se_cuelga() {
        // El caso que hace que el reintento sea ACOTADO: si insistiera sin
        // límite, cuatro de las cinco causas serían un cuelgue silencioso.
        let mut llamadas = 0;
        let mut fuente = || {
            llamadas += 1;
            Err(24)
        };
        assert_eq!(politica(&mut fuente), Err((INTENTOS, Some(24))));
        assert_eq!(llamadas, INTENTOS, "el número de intentos no es el acotado");
    }

    #[test]
    fn al_primer_intento_bueno_no_hay_reintento() {
        let mut llamadas = 0;
        let mut fuente = || {
            llamadas += 1;
            Ok(())
        };
        assert_eq!(politica(&mut fuente), Ok(1));
        assert_eq!(llamadas, 1, "reintentó sin motivo");
    }
}

#[cfg(test)]
mod pruebas_salud {
    use super::*;

    /// LO QUE LA PRUEBA DETECTA. Sin estos casos, `salud_de` podría devolver
    /// `None` siempre y todo lo demás pasaría igual.
    #[test]
    fn caza_las_fuentes_rotas_que_lo_aparentan() {
        // El caso del seccomp que devuelve éxito sin tocar el buffer.
        assert_eq!(salud_de(&[0u8; 32]), Some(FalloDeSalud::TodoCeros));
        assert_eq!(salud_de(&[0u8; REPETICION_QUE_DELATA]), Some(FalloDeSalud::TodoCeros));

        // La fuente atascada en un valor.
        assert_eq!(
            salud_de(&[0xAAu8; 32]),
            Some(FalloDeSalud::Atascada { byte: 0xAA, veces: REPETICION_QUE_DELATA })
        );

        // Y atascada solo en un TRAMO, con el resto correcto: no vale mirar
        // únicamente el principio o el final.
        let mut a_medias = vec![0x11u8, 0x22, 0x33, 0x44];
        a_medias.extend_from_slice(&[0x77u8; REPETICION_QUE_DELATA]);
        a_medias.extend_from_slice(&[0x55u8, 0x66]);
        assert!(
            matches!(salud_de(&a_medias), Some(FalloDeSalud::Atascada { byte: 0x77, .. })),
            "un tramo atascado en medio tiene que verse"
        );
    }

    /// LO QUE NO PUEDE RECHAZAR, que es la mitad que decide si la regla está
    /// bien puesta: aleatoriedad legítima no puede disparar la alarma.
    #[test]
    fn no_rechaza_aleatoriedad_legitima() {
        // La fuente real, muchas veces y en muchos tamaños.
        for n in [1usize, 2, 8, 16, 32, 64, 256, 4096] {
            for _ in 0..40 {
                let mut buf = vec![0u8; n];
                llenar(&mut buf).expect("la fuente del sistema debe responder");
                assert_eq!(
                    salud_de(&buf),
                    None,
                    "falsa alarma sobre {n} bytes de aleatoriedad real: {:02x?}",
                    &buf[..buf.len().min(16)]
                );
            }
        }

        // Y los bordes que NO deben disparar. La cota es UNA: siete bytes
        // idénticos —ceros incluidos— se quedan por debajo, y siete ceros por
        // azar son 2⁻⁵⁶, que es donde tiene que estar el suelo.
        assert_eq!(salud_de(&[0u8; REPETICION_QUE_DELATA - 1]), None);
        assert_eq!(salud_de(&[0x5Au8; REPETICION_QUE_DELATA - 1]), None);
        assert_eq!(salud_de(&[]), None);
    }

    /// Un fallo de salud NO se anuncia como transitorio: reintentar con la misma
    /// fuente rota acabaría dando algo que «parece bien».
    #[test]
    fn un_fallo_de_salud_nunca_invita_a_reintentar() {
        let e = SinEntropia {
            bytes: 32,
            intentos: 1,
            codigo_os: None,
            salud: Some(FalloDeSalud::TodoCeros),
        };
        assert!(!e.probablemente_transitorio());
        assert!(e.to_string().contains("no son de fiar"));
        assert!(e.to_string().contains("no se reintenta"));

        // Y el contraste: la falta de respuesta por descriptores agotados SÍ.
        let t = SinEntropia { bytes: 32, intentos: 3, codigo_os: Some(24), salud: None };
        assert!(t.probablemente_transitorio());
    }
}
