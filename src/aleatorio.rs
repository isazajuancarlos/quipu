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

/// El sistema no pudo entregar aleatoriedad.
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
        // EMFILE (24) y ENFILE (23): descriptores agotados, en el proceso o en
        // el sistema. Son los únicos que se resuelven solos.
        matches!(self.codigo_os, Some(23) | Some(24))
    }
}

impl fmt::Display for SinEntropia {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
            Ok(()) => return Ok(()),
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
                    });
                }
            }
        }
    }
    Err(SinEntropia {
        bytes: destino.len(),
        intentos: INTENTOS,
        codigo_os: ultimo,
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
        let transitorio = SinEntropia { bytes: 32, intentos: 3, codigo_os: Some(24) };
        assert!(transitorio.probablemente_transitorio());
        assert!(transitorio.to_string().contains("reintentar puede servir"));

        let permanente = SinEntropia { bytes: 32, intentos: 1, codigo_os: Some(1) };
        assert!(!permanente.probablemente_transitorio());
        assert!(permanente.to_string().contains("revise el despliegue"));
        // Y dice lo más importante: que NO se fabricó nada.
        assert!(permanente.to_string().contains("no sustituye"));
    }

    #[test]
    fn sin_codigo_del_sistema_se_asume_permanente() {
        // Ante la duda, no se manda a nadie a un bucle de reintentos.
        let desconocido = SinEntropia { bytes: 32, intentos: 3, codigo_os: None };
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
