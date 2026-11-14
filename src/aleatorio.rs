// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

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
    /// Un byte apareció demasiadas veces en una ventana, aunque no seguidas.
    /// Es la fuente PERIÓDICA o SESGADA, que la cota de repetición no ve.
    Sesgada {
        /// El byte que se repetía.
        byte: u8,
        /// Cuántas veces apareció.
        veces: usize,
        /// De cuántos bytes de ventana.
        de: usize,
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
            Self::Sesgada { byte, veces, de } => write!(
                f,
                "la fuente devolvió el byte {byte:#04x} {veces} veces en {de} bytes"
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

// ===========================================================================
// LA SEGUNDA PRUEBA CONTINUA DE LA SP 800-90B
// ===========================================================================
//
// La norma exige DOS pruebas continuas y hasta el 2026-08-16 aquí había UNA.
// La que faltaba —*Adaptive Proportion Test*— mira la FRECUENCIA de un valor en
// una ventana, no las repeticiones seguidas, y esa diferencia no es académica:
// una fuente atrapada en un ciclo corto (`A5 5A A5 5A…`) tiene 1 bit de entropía
// por byte y **no tiene jamás dos bytes iguales seguidos**. La cota de
// repetición caza la fuente MUERTA; ésta caza la fuente PERIÓDICA.
//
// # Dos desviaciones de la letra de la norma, y las dos con motivo
//
// **1. La ventana es el búfer, no un W fijo de 512.** Quipu pide 16, 24 o 32
// bytes casi siempre —un salt, un nonce, una clave—, así que un W fijo de 512
// no se llenaría nunca y la prueba no llegaría a ejecutarse. Un vigilante que
// no corre y uno que aprueba se ven exactamente igual (directiva 30). El corte
// se recalcula para la longitud real; para búferes largos se recorren ventanas
// consecutivas de hasta 4096.
//
// **2. Se compara contra CUALQUIER valor, no contra el primero de la ventana.**
// La norma toma el primer byte como referencia; preguntar «¿algún valor cruza el
// corte?» es estrictamente más potente y solo cuesta pagar una cota de unión
// sobre los 256 valores posibles, que ya está pagada en la tabla.
//
// Matiz que evita una lectura falsa del diagnóstico: la DECISIÓN es la del
// máximo —`máx_v cuenta_v ≥ c` es lo mismo que `∃v: cuenta_v ≥ c`— pero el
// `byte` que se reporta es el PRIMERO en cruzar recorriendo 0..256, o sea el
// numéricamente menor, no necesariamente el más frecuente. Da igual para
// rechazar y no da igual para leer un registro.
//
// # El corte, y por qué es mucho más estricto que el de la norma
//
// NIST calibra con α = 2⁻²⁰ porque allí un fallo se REPORTA. Aquí un fallo
// **para la operación y no se reintenta**, así que un falso positivo le rompe el
// día a un cliente legítimo — que es el sesgo a cerrar de la directiva 21.
//
// La tabla está calibrada a **α ≤ 2⁻⁶⁴ POR VENTANA de hasta 4096 bytes**, y esa
// unidad importa: un búfer se recorre en ventanas disjuntas, así que lo exacto
// para una extracción de N bytes es `⌈N/4096⌉ · 2⁻⁶⁴`. Para los tamaños que
// Quipu pide casi siempre —16, 24, 32— es una sola ventana y las dos cifras
// coinciden; para `blindaje::repartir`, que pide el tamaño del claro, no. Un
// mensaje de 10 MiB son 2560 ventanas y la α agregada es ≈ 2⁻⁵³ — que con 2³⁰
// extracciones de ese tamaño en toda la vida del despliegue deja la falsa alarma
// en 2⁻²³. Sigue sobrando margen; lo que no vale es citar 2⁻⁶⁴ y que sea otra
// cosa.
//
// **El suelo de sensibilidad es fijo y NO mejora con más datos**, porque las
// ventanas no se agregan entre sí: un sesgo por debajo de 79/4096 ≈ **1,93 %**
// para un valor dado (4,9× su frecuencia esperada del 0,39 %) es invisible sea
// cual sea el tamaño del búfer. Escrito con el número delante para que nadie
// cuente con que pedir 1 MiB detecta más que pedir 4 KiB.
//
// Cota usada: P(algún valor aparezca ≥ c veces en n bytes uniformes)
// ≤ 256 · C(n, c) · 256⁻ᶜ. Cada entrada es el menor `c` que la deja bajo 2⁻⁶⁴
// para el TOPE de su tramo, así que dentro del tramo el corte solo puede ser más
// permisivo — nunca menos. Lo recalcula `la_tabla_de_cortes_es_la_calculada`.
//
// # Lo que NO caza, dicho de frente
//
// Con menos de 12 bytes **no existe corte**: ni ocho bytes idénticos bastan para
// bajar de 2⁻⁶⁴, así que la prueba se declara no aplicable en vez de inventarse
// un umbral. Y un ciclo de periodo 16 en 32 bytes da 2 apariciones por valor:
// invisible para esta prueba. Caza el sesgo de FRECUENCIA, no toda periodicidad.

/// La ventana más larga que se examina de una vez. Los búferes mayores se
/// recorren en ventanas consecutivas de este tamaño.
const VENTANA_MAXIMA: usize = 4096;

/// Por debajo de esto la prueba de proporción no puede decir nada al nivel de
/// falso positivo exigido, y lo declara en vez de adivinar.
const MINIMO_PARA_PROPORCION: usize = 12;

/// `(tope de la ventana, apariciones del mismo byte que delatan)`, calibrada a
/// α ≤ 2⁻⁶⁴. Monótona por construcción.
const CORTES_DE_PROPORCION: &[(usize, usize)] = &[
    (16, 11),
    (24, 12),
    (32, 13),
    (48, 14),
    (64, 15),
    (96, 17),
    (128, 18),
    (256, 23),
    (512, 29),
    (1024, 38),
    (VENTANA_MAXIMA, 79),
];

/// Cuántas apariciones del mismo byte delatan una ventana de `n` bytes.
/// `None` si `n` es demasiado corto para concluir nada.
fn corte_de_proporcion(n: usize) -> Option<usize> {
    if n < MINIMO_PARA_PROPORCION {
        return None;
    }
    CORTES_DE_PROPORCION
        .iter()
        .find(|(tope, _)| n <= *tope)
        .map(|(_, corte)| *corte)
}

/// La prueba de proporción sobre una ventana suelta.
fn proporcion_de(ventana: &[u8]) -> Option<FalloDeSalud> {
    // El `None` de abajo significa «la ventana es demasiado CORTA para concluir».
    // Si alguna vez llegara una demasiado LARGA, `corte_de_proporcion` devolvería
    // también `None` y esta función saldría sin comprobar nada — un fallo
    // ABIERTO, indistinguible de «limpio» (directiva 30). Hoy es inalcanzable
    // porque el único llamante trocea en `VENTANA_MAXIMA`; esto lo deja dicho
    // para que siga siéndolo.
    debug_assert!(
        ventana.len() <= VENTANA_MAXIMA,
        "una ventana mayor que la tabla saldría sin comprobar nada"
    );
    let corte = corte_de_proporcion(ventana.len())?;
    let mut cuenta = [0u32; 256];
    for b in ventana {
        cuenta[*b as usize] += 1;
    }
    cuenta.iter().enumerate().find_map(|(byte, veces)| {
        (*veces as usize >= corte).then_some(FalloDeSalud::Sesgada {
            byte: byte as u8,
            veces: *veces as usize,
            de: ventana.len(),
        })
    })
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
pub(crate) fn salud_de(muestra: &[u8]) -> Option<FalloDeSalud> {
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
    // La SEGUNDA prueba continua: frecuencia por ventana. Va después porque la
    // de repetición es más barata y más específica —dice «atascada», que es un
    // diagnóstico— y porque una fuente atascada dispara las dos.
    for ventana in muestra.chunks(VENTANA_MAXIMA) {
        if let Some(fallo) = proporcion_de(ventana) {
            return Some(fallo);
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
    // La fuente real: `getrandom::fill`, con su código de error del sistema.
    // Toda la LÓGICA —reintento, salud, borrado del búfer— vive en `llenar_con`,
    // que recibe la fuente como parámetro. Es lo que hace medible el módulo del
    // que cuelga todo: una prueba puede inyectar una fuente atascada, o una que
    // llene de menos, POR LA MISMA COSTURA que usa este camino (directiva 33) —
    // antes esa lógica se probaba sobre una RÉPLICA dentro de `mod tests`, que
    // es probar otra cosa.
    llenar_con(destino, |b| getrandom::fill(b).map_err(|e| e.raw_os_error()))
}

/// La lógica de [`llenar`] con la fuente de entropía como parámetro.
///
/// `fuente(buf)` devuelve `Ok(())` si llenó `buf`, o `Err(codigo)` con el código
/// de error del sistema (o `None` si no lo hay). Es exactamente lo que hace
/// `getrandom::fill`, y por eso el camino real y el de prueba comparten esta
/// función en vez de parecerse.
pub(crate) fn llenar_con(
    destino: &mut [u8],
    mut fuente: impl FnMut(&mut [u8]) -> Result<(), Option<i32>>,
) -> Result<(), SinEntropia> {
    let mut ultimo: Option<i32> = None;
    for intento in 1..=INTENTOS {
        match fuente(destino) {
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
            Err(codigo) => {
                ultimo = codigo;
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
/// # Por qué NO se escribe ChaCha20 a pelo
///
/// Escribir el paso 2 a mano son quince líneas —clave = semilla, nonce a cero,
/// producir flujo— y son quince líneas de criptografía propia. `stream.rs` ya
/// fija la regla de la casa: *no se inventan primitivas*. Esa regla no ha
/// cambiado y no se reabre.
///
/// # Por qué `chacha20` y ya no `rand_chacha` (2026-08-14)
///
/// Las dos hacen exactamente lo mismo y las dos están auditadas. Lo que las
/// separa es lo que arrastran, y eso se midió en vez de suponerse:
///
/// - **`chacha20` YA ESTABA en el árbol**: `chacha20poly1305` —el AEAD con el
///   que se cifra de verdad— cuelga de él. Su feature `rng` no añade un solo
///   crate: enciende un módulo de algo que ya viaja, y su única dependencia
///   nueva es `rand_core`, que también teníamos ya.
/// - **`rand_chacha` costaba 32 356 líneas**: él mismo (2 033) más `zerocopy`
///   (28 512) y `ppv-lite86` (3 844), ninguno de los cuales usábamos para nada
///   más. Y `zerocopy` **ejecuta código al compilar**, que es el vector por el
///   que entraron los gusanos de npm y del AUR.
///
/// **No se escribió una sola línea de criptografía para este cambio**, y ése es
/// el punto: la regla de arriba se cumple entera. Se cambió a qué
/// implementación auditada se le pide el mismo flujo.
///
/// **Y no hay superficie de compatibilidad**: la semilla es fresca del sistema
/// en cada llamada, así que ninguna salida era reproducible ni está persistida.
/// Por eso este cambio no lleva vector fijo — no hay nada que anclar.
///
/// # Qué NO hace
///
/// **No sustituye la entropía del sistema: la expande.** La semilla es fresca
/// en cada llamada y no hay estado global ni generador de larga vida. Si el
/// sistema no da los 32 bytes, esta función falla y no se genera ninguna clave.
pub fn generador() -> Result<chacha20::ChaCha20Rng, SinEntropia> {
    use rand_core::SeedableRng;
    Ok(chacha20::ChaCha20Rng::from_seed(bytes::<32>()?))
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
mod pruebas_de_la_costura {
    //! Inyecta fuentes de entropía rotas por `llenar_con` —la MISMA costura que
    //! usa `llenar`— y comprueba que la lógica de reintento, salud y borrado del
    //! búfer hace lo que dice. Antes esta lógica se probaba sobre una réplica
    //! dentro de `mod tests`, así que un mutante en `llenar` no la ponía roja
    //! (defecto A2, confianza 10 de la auditoría del 2026-08-17).

    use super::*;

    /// Una fuente que llena con un patrón fijo y siempre tiene éxito.
    fn con_bytes(patron: &'static [u8]) -> impl FnMut(&mut [u8]) -> Result<(), Option<i32>> {
        move |b: &mut [u8]| {
            for (i, x) in b.iter_mut().enumerate() {
                *x = patron[i % patron.len()];
            }
            Ok(())
        }
    }

    #[test]
    fn una_fuente_de_ceros_se_caza_y_el_bufer_queda_borrado() {
        let mut buf = [0xAAu8; 64];
        let r = llenar_con(&mut buf, con_bytes(&[0x00]));
        // La caza la salud (TodoCeros), no un `Ok`.
        assert!(matches!(r, Err(SinEntropia { salud: Some(_), .. })), "una fuente de ceros tiene que fallar");
        // **LA RAMA QUE ANTES NO EJECUTABA NADIE**: el búfer se deja a cero, para
        // que el llamante no se quede con bytes que ya sabemos malos. Aquí ya
        // eran ceros, así que el control de verdad es el de abajo.
        assert!(buf.iter().all(|&b| b == 0), "el búfer no se borró");
    }

    #[test]
    fn una_fuente_atascada_deja_el_bufer_a_cero_aunque_no_fuera_cero() {
        // Fuente atascada en una constante NO nula: la caza la prueba de
        // repetición, y el borrado tiene que dejar CEROS (no la constante).
        let mut buf = [0x11u8; 64];
        let r = llenar_con(&mut buf, con_bytes(&[0x5A]));
        assert!(matches!(r, Err(SinEntropia { salud: Some(_), .. })), "una constante tiene que fallar");
        assert!(
            buf.iter().all(|&b| b == 0),
            "el búfer tenía que quedar A CERO tras el fallo de salud, y quedó: {:?}",
            &buf[..4]
        );
    }

    #[test]
    fn un_ciclo_corto_se_caza_por_encima_de_su_punto_ciego() {
        // Periodo 2, 64 bytes: por encima del mínimo de la prueba de proporción.
        let mut buf = [0u8; 64];
        assert!(
            llenar_con(&mut buf, con_bytes(&[0xA5, 0x5A])).is_err(),
            "un ciclo de periodo 2 en 64 bytes tiene que cazarse"
        );
    }

    #[test]
    fn una_fuente_que_llena_de_menos_no_pasa_por_buena() {
        // Deja la segunda mitad SIN TOCAR (a 0x00), como haría un `read` corto
        // que el contrato de `getrandom` promete no hacer pero un shim roto sí.
        let fuente = |b: &mut [u8]| {
            let mitad = b.len() / 2;
            for x in b[..mitad].iter_mut() {
                *x = 0x37;
            }
            // la cola queda como estaba
            Ok(())
        };
        let mut buf = [0u8; 64];
        // 32 bytes de 0x37 seguidos de 32 ceros: la corrida de ceros de la cola
        // dispara la prueba de repetición. Se documenta el resultado y se fija.
        assert!(
            llenar_con(&mut buf, fuente).is_err(),
            "una fuente que deja media cola a ceros tiene que cazarse por la corrida"
        );
    }

    #[test]
    fn el_reintento_transitorio_es_de_exactamente_dos_intentos() {
        // EMFILE (24) una vez, luego éxito con entropía real: 2 llamadas, Ok.
        let mut llamadas = 0;
        let fuente = |b: &mut [u8]| {
            llamadas += 1;
            if llamadas == 1 {
                Err(Some(24)) // EMFILE, transitorio
            } else {
                for (i, x) in b.iter_mut().enumerate() {
                    *x = (i as u8).wrapping_mul(97).wrapping_add(13);
                }
                Ok(())
            }
        };
        let mut buf = [0u8; 64];
        assert!(llenar_con(&mut buf, fuente).is_ok(), "un fallo transitorio único tiene que reintentarse con éxito");
        assert_eq!(llamadas, 2, "tenían que ser EXACTAMENTE 2 llamadas");
    }

    #[test]
    fn un_error_permanente_no_gasta_los_reintentos() {
        // EPERM (1) es permanente: UNA sola llamada, y el error dice que NO es
        // transitorio, para que el llamante no insista.
        let mut llamadas = 0;
        let fuente = |b: &mut [u8]| {
            let _ = b;
            llamadas += 1;
            Err(Some(1))
        };
        let mut buf = [0u8; 64];
        let r = llenar_con(&mut buf, fuente);
        assert_eq!(llamadas, 1, "un error permanente NO puede reintentarse");
        match r {
            Err(e) => assert!(!e.probablemente_transitorio(), "EPERM no es transitorio"),
            Ok(()) => panic!("un error permanente no puede dar Ok"),
        }
    }

    #[test]
    fn un_transitorio_persistente_agota_los_intentos_y_los_cuenta() {
        let mut llamadas = 0;
        let fuente = |b: &mut [u8]| {
            let _ = b;
            llamadas += 1;
            Err(Some(24))
        };
        let mut buf = [0u8; 64];
        let r = llenar_con(&mut buf, fuente);
        assert_eq!(llamadas, INTENTOS, "un transitorio persistente agota los INTENTOS");
        assert!(matches!(r, Err(SinEntropia { intentos, .. }) if intentos == INTENTOS));
    }

    /// **EL CONTROL POSITIVO**, sin el cual todo lo de arriba pasaría con un
    /// `llenar_con` que fallara siempre: la entropía real, por la misma costura,
    /// llena y NO se rechaza.
    #[test]
    fn la_entropia_real_por_la_costura_pasa() {
        for _ in 0..200 {
            let mut buf = [0u8; 64];
            llenar_con(&mut buf, |b| getrandom::fill(b).map_err(|e| e.raw_os_error()))
                .expect("la entropía real no puede rechazarse");
            assert!(buf.iter().any(|&b| b != 0));
        }
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
        // La fuente real, muchas veces y en muchos tamaños. Los cuatro primeros
        // tamaños son los que Quipu pide de verdad (salt 16, nonce 24, clave 32,
        // id 16), y son justo donde el corte está más apretado.
        for n in [1usize, 2, 8, 12, 16, 24, 32, 48, 64, 256, 512, 4096, 8192] {
            for _ in 0..200 {
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

    /// EL CICLO CORTO, que hasta el 2026-08-16 pasaba limpio.
    ///
    /// Esta prueba nació al revés: afirmaba que `salud_de` devuelve `None` sobre
    /// una fuente de periodo 2, y decía encima de sí misma que se pondría roja
    /// el día que entrara la prueba de proporción. Ese día llegó, y aquí está
    /// dada la vuelta. Se conserva la historia porque es el positivo de control
    /// de que la prueba nueva hace algo que la vieja no hacía.
    #[test]
    fn un_ciclo_corto_lo_caza_la_prueba_de_proporcion() {
        // Periodo 2: 4 KiB, 1 bit de entropía por byte, y ni un par adyacente
        // igual — o sea invisible para la cota de repetición.
        let ciclo_2: Vec<u8> =
            (0..4096).map(|i| if i % 2 == 0 { 0xA5 } else { 0x5A }).collect();
        assert!(
            ciclo_2.windows(2).all(|p| p[0] != p[1]),
            "el control: este caso NO puede tener dos bytes iguales seguidos, o lo \
             estaría cazando la otra prueba y esto no probaría nada"
        );
        assert!(
            matches!(salud_de(&ciclo_2), Some(FalloDeSalud::Sesgada { veces: 2048, .. })),
            "el ciclo de periodo 2 tiene que verse: {:?}",
            salud_de(&ciclo_2)
        );

        // Periodo 3. Aquí está la frontera medida, y conviene tenerla escrita:
        // en 32 bytes cada valor sale 11 veces frente a un corte de 13, así que
        // NO se caza; en 48 salen 16 frente a 14 y sí. Cuanto más largo el
        // periodo, más datos hacen falta — es aritmética, no un defecto.
        let periodo_3 = |n: usize| -> Vec<u8> {
            (0..n).map(|i| [0x01u8, 0x02, 0x03][i % 3]).collect()
        };
        assert_eq!(salud_de(&periodo_3(32)), None, "con 32 bytes, el periodo 3 no da");
        assert!(
            matches!(salud_de(&periodo_3(48)), Some(FalloDeSalud::Sesgada { .. })),
            "con 48 sí tiene que darse: {:?}",
            salud_de(&periodo_3(48))
        );
    }

    /// EL LÍMITE, escrito para que nadie lo dé por cubierto.
    ///
    /// Con menos de 12 bytes no hay corte posible al nivel de falso positivo
    /// exigido, y con 16 un ciclo de periodo 2 da 8 apariciones frente a un corte
    /// de 11: **no se caza**. No es un defecto que arreglar, es lo que se puede
    /// afirmar con esa cantidad de datos; escribirlo evita que alguien cuente con
    /// una cobertura que no existe.
    #[test]
    fn con_muy_pocos_bytes_la_proporcion_no_puede_concluir() {
        assert_eq!(corte_de_proporcion(11), None, "por debajo de 12 no hay corte");
        assert_eq!(corte_de_proporcion(0), None);
        assert!(corte_de_proporcion(12).is_some(), "desde 12 sí lo hay");

        // Un ciclo de periodo 2 en 16 bytes: 8 apariciones, corte 11. Se escapa.
        let corto: Vec<u8> = (0..16).map(|i| if i % 2 == 0 { 0xA5 } else { 0x5A }).collect();
        assert_eq!(salud_de(&corto), None, "con 16 bytes no da para concluir");

        // Y el mismo ciclo con 32 bytes SÍ: 16 apariciones frente a un corte de
        // 13. Es el control de que lo de arriba es falta de datos y no ceguera.
        let suficiente: Vec<u8> = (0..32).map(|i| if i % 2 == 0 { 0xA5 } else { 0x5A }).collect();
        assert!(matches!(salud_de(&suficiente), Some(FalloDeSalud::Sesgada { .. })));
    }

    /// LA TABLA NO SE CREE, SE RECALCULA.
    ///
    /// Cada entrada tiene que ser el MENOR `c` que deja la cota de falso positivo
    /// —`256 · C(n, c) · 256⁻ᶜ`— por debajo de 2⁻⁶⁴ para el tope de su tramo. Se
    /// comprueban las dos mitades: que el valor elegido cumple, y que **uno menos
    /// NO cumple**. Sin la segunda, una tabla con todo a 200 pasaría igual y la
    /// prueba de proporción no se dispararía jamás.
    #[test]
    fn la_tabla_de_cortes_es_la_calculada() {
        /// log2 de la cota de unión, en coma flotante: 8 + log2(C(n,c)) - 8c.
        fn log2_cota(n: usize, c: usize) -> f64 {
            let log2_binomial: f64 = (1..=c)
                .map(|i| ((n - c + i) as f64 / i as f64).log2())
                .sum();
            8.0 + log2_binomial - 8.0 * c as f64
        }

        for (tope, corte) in CORTES_DE_PROPORCION {
            assert!(
                log2_cota(*tope, *corte) <= -64.0,
                "el corte {corte} para {tope} bytes no llega a 2^-64: 2^{}",
                log2_cota(*tope, *corte)
            );
            assert!(
                log2_cota(*tope, corte - 1) > -64.0,
                "el corte para {tope} bytes podría ser {} y está en {corte}: cierra de más",
                corte - 1
            );
        }

        // Monótona y sin tramos repetidos: si no, un búfer podría caer en dos.
        for par in CORTES_DE_PROPORCION.windows(2) {
            assert!(par[0].0 < par[1].0, "los topes tienen que crecer");
            assert!(par[0].1 <= par[1].1, "los cortes tienen que crecer");
        }
        assert_eq!(
            CORTES_DE_PROPORCION.last().expect("la tabla no está vacía").0,
            VENTANA_MAXIMA,
            "el último tramo tiene que llegar hasta la ventana máxima"
        );
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
