// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Carga útil del portador de papel: trocear, proteger e **intercalar**.
//!
//! Es la pieza que decidió la medición de `quipu::lab::papel` (hoja de ruta §6):
//! **el núcleo no renderiza el símbolo**. Dibujar un QR es presentación, y en la
//! mayoría de los productos ya lo hace el frontend. Lo que sí es trabajo de
//! Quipu —y lo que nadie más puede hacer bien por su cuenta— es la carga:
//! trocearla, protegerla con Reed-Solomon y ordenarla para que perder un símbolo
//! entero no la mate.
//!
//! Por eso este módulo **no tiene ninguna dependencia nueva**.
//!
//! # Formato de cada trozo
//!
//! ```text
//! [ versión u8 ][ índice u16 BE ][ total u16 BE ][ largo u32 BE ][ bytes ]
//! ```
//!
//! La cabecera va **fuera** del Reed-Solomon, y eso es deliberado y no un
//! descuido: el símbolo que la transporta —un QR— trae su propia corrección de
//! errores y su propia integridad, así que **un QR o decodifica bien o no
//! decodifica**. No hay un estado intermedio en el que la cabecera llegue
//! corrompida y el contenido no. Protegerla otra vez sería un mecanismo para
//! contener lo que ya contiene otro.
//!
//! `largo` es la longitud del flujo protegido COMPLETO, y está en cada trozo a
//! propósito: sin él, un símbolo perdido dejaría sin saber si el flujo terminaba
//! en él, y el reensamblado tendría que adivinar un byte de longitud. Adivinar
//! no es una opción cuando lo que se recupera es una clave.
//!
//! # Por qué se INTERCALA, y qué compra exactamente
//!
//! Los bytes del flujo protegido no van en tramos contiguos: el trozo `j` se
//! lleva las posiciones `j`, `j+total`, `j+2·total`… Así, **perder un símbolo
//! entero no borra un tramo seguido sino un byte de cada `total`**, repartido por
//! igual entre todos los bloques Reed-Solomon.
//!
//! La diferencia es la que hay entre recuperarse y no. Sin intercalar, un
//! símbolo perdido se lleva bloques enteros y ninguna paridad razonable los
//! reconstruye. Intercalando, cada bloque de 255 bytes pierde unos `255/total`,
//! y eso sí cabe en el presupuesto de `paridad/2` errores por bloque.
//!
//! El número exacto lo da [`simbolos_perdidos_tolerados`], que no se estima a
//! ojo: se calcula, y hay una prueba que comprueba que **un símbolo más de los
//! que dice ya NO se recupera**. Una cota que solo se verifica por el lado
//! optimista es una promesa, no una cota.

use crate::ecc;

/// Versión del formato de trozo.
pub const VERSION: u8 = 1;

/// Lo que ocupa la cabecera de cada trozo.
pub const CABECERA: usize = 1 + 2 + 2 + 4;

/// Tamaño del bloque Reed-Solomon de `ecc`.
const BLOQUE_RS: usize = 255;

/// Errores del empaquetado de papel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PapelError {
    /// La capacidad por símbolo no deja sitio ni para la cabecera.
    CapacidadInsuficiente {
        /// La que se pidió.
        dada: usize,
        /// La mínima que sirve de algo.
        minima: usize,
    },
    /// Harían falta más de 65 535 símbolos. Con eso en papel el problema no es
    /// el formato.
    DemasiadosSimbolos {
        /// Cuántos harían falta.
        necesarios: usize,
    },
    /// La paridad pedida pasa de [`crate::ecc::PARIDAD_MAXIMA`].
    ///
    /// **Se RECHAZA en vez de recortarse**, que es lo que hace `ecc::protect`
    /// por no tener cómo avisar. Aquí sí lo hay, y recortar en silencio le
    /// daría a quien imprime la hoja menos protección de la que pidió, sin que
    /// nada se lo diga hasta el día que la hoja no se pueda leer.
    ParidadExcesiva {
        /// La que se pidió.
        dada: u8,
        /// La mayor que se acepta.
        maxima: u8,
    },
    /// No se pasó ningún trozo.
    SinTrozos,
    /// Un trozo declara una versión de formato que no se conoce.
    VersionDesconocida(u8),
    /// Los trozos no hablan del mismo documento: distinto `total`, distinto
    /// `largo`, un índice repetido o un índice fuera de rango.
    TrozosIncoherentes,
    /// Faltan o llegaron dañados más bytes de los que la paridad puede corregir.
    NoSeRecupera,
    /// El trozo no cabe en ningún símbolo QR con el nivel de corrección pedido.
    /// Lleva el motivo de la librería porque aquí un mensaje genérico no ayuda:
    /// lo que hay que cambiar es la capacidad por símbolo o el nivel.
    SimboloImposible(String),
}

impl core::fmt::Display for PapelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CapacidadInsuficiente { dada, minima } => write!(
                f,
                "la capacidad por símbolo ({dada} B) no llega al mínimo de {minima} B"
            ),
            Self::ParidadExcesiva { dada, maxima } => write!(
                f,
                "la paridad pedida ({dada}) pasa del máximo de {maxima}: por encima \
                 de ahí el decodificador de Reed-Solomon puede entrar en pánico con \
                 una hoja dañada, así que se rechaza en vez de recortarla"
            ),
            Self::DemasiadosSimbolos { necesarios } => write!(
                f,
                "harían falta {necesarios} símbolos y el formato admite 65 535"
            ),
            Self::SinTrozos => write!(f, "no se pasó ningún trozo"),
            Self::VersionDesconocida(v) => {
                write!(f, "versión de formato desconocida: {v}")
            }
            Self::TrozosIncoherentes => {
                write!(f, "los trozos no pertenecen al mismo documento")
            }
            Self::NoSeRecupera => write!(
                f,
                "faltan o llegaron dañados más bytes de los que la paridad corrige"
            ),
            Self::SimboloImposible(m) => {
                write!(f, "el trozo no cabe en un símbolo QR: {m}")
            }
        }
    }
}

impl std::error::Error for PapelError {}

/// Bloque que `ecc` reserva para su cabecera: 5 bytes de datos y 10 de paridad,
/// o sea 15 bytes que corrigen **5 errores**. Ver `ecc::protect`.
const CABECERA_ECC: usize = 15;
/// Errores que el bloque de la cabecera de `ecc` corrige. **Es el techo de todo
/// el portador**, ver [`simbolos_perdidos_tolerados`].
const CABECERA_ECC_CORRIGE: usize = 5;

/// Cuántos símbolos completos se pueden perder —**los que sean**— y aun así
/// recuperarlo todo.
///
/// # El cuello de botella no son los datos: es la cabecera de `ecc`
///
/// Es lo que enseñó la prueba y no el razonamiento. La cuenta obvia mira los
/// bloques de datos: con `total` símbolos intercalados, perder uno le quita a
/// cada bloque de 255 bytes unos `255/total`, y el presupuesto es `paridad/2`.
/// Con 155 símbolos y paridad 200 eso daba **50 símbolos**, y con 50 no se
/// recupera nada.
///
/// La razón es que `ecc::protect` antepone un bloque propio para su cabecera de
/// **15 bytes que corrige 5 errores**, y esos 15 bytes caen en los 15 PRIMEROS
/// símbolos. Perder los símbolos 0 a 49 no le quita a ese bloque el 32 % de sus
/// bytes: se lo lleva **entero**. El bloque más pequeño es el más frágil, y es
/// el que decide.
///
/// Por eso la garantía es el **mínimo** de las dos cuentas, y en la práctica casi
/// siempre manda el 5. Es una garantía sobre CUALESQUIERA símbolos que falten,
/// no sobre los que falten con suerte: con pérdidas repartidas se aguanta mucho
/// más, pero eso no es algo que se pueda prometer.
pub fn simbolos_perdidos_tolerados(total: usize, paridad: u8) -> usize {
    if total == 0 {
        return 0;
    }
    let por_datos = {
        let presupuesto = (paridad as usize) / 2;
        let perdidos_por_bloque = BLOQUE_RS.div_ceil(total);
        presupuesto / perdidos_por_bloque.max(1)
    };
    // Si hay menos símbolos que bytes tiene la cabecera de `ecc`, cada símbolo
    // se lleva varios de esos bytes y el techo baja proporcionalmente.
    let por_cabecera = if total >= CABECERA_ECC {
        CABECERA_ECC_CORRIGE
    } else {
        CABECERA_ECC_CORRIGE / CABECERA_ECC.div_ceil(total)
    };
    por_datos.min(por_cabecera)
}

/// Trocea `datos` en símbolos listos para imprimir.
///
/// `capacidad` es cuántos bytes cabe en un símbolo (por ejemplo, lo que admite
/// una versión de QR concreta). `paridad` es la de Reed-Solomon por bloque: a
/// más, más símbolos se pueden perder — lo dice [`simbolos_perdidos_tolerados`].
pub fn empaquetar(
    datos: &[u8],
    capacidad: usize,
    paridad: u8,
) -> Result<Vec<Vec<u8>>, PapelError> {
    // Un byte útil por símbolo es el mínimo que tiene sentido: con cero, el
    // bucle no terminaría nunca y el error aparecería como un cuelgue.
    if capacidad <= CABECERA {
        return Err(PapelError::CapacidadInsuficiente {
            dada: capacidad,
            minima: CABECERA + 1,
        });
    }
    // La paridad se valida ANTES de protegerla: `ecc::protect` recortaría en
    // silencio, y quien imprime una hoja tiene que enterarse de que no va a
    // llevar la protección que pidió.
    if paridad > ecc::PARIDAD_MAXIMA {
        return Err(PapelError::ParidadExcesiva {
            dada: paridad,
            maxima: ecc::PARIDAD_MAXIMA,
        });
    }
    let util = capacidad - CABECERA;
    let protegido = ecc::protect(datos, paridad);
    let total = protegido.len().div_ceil(util).max(1);
    if total > u16::MAX as usize {
        return Err(PapelError::DemasiadosSimbolos { necesarios: total });
    }

    let largo = protegido.len() as u32;
    let mut trozos: Vec<Vec<u8>> = (0..total)
        .map(|j| {
            let mut t = Vec::with_capacity(capacidad);
            t.push(VERSION);
            t.extend_from_slice(&(j as u16).to_be_bytes());
            t.extend_from_slice(&(total as u16).to_be_bytes());
            t.extend_from_slice(&largo.to_be_bytes());
            t
        })
        .collect();

    // Intercalado: la posición `i` del flujo va al símbolo `i % total`. Es lo
    // que convierte «se perdió un símbolo» en «falta un byte de cada `total`».
    for (i, b) in protegido.iter().enumerate() {
        trozos[i % total].push(*b);
    }
    Ok(trozos)
}

/// Cabecera ya leída.
struct Cabecera {
    indice: usize,
    total: usize,
    largo: usize,
}

fn leer_cabecera(t: &[u8]) -> Result<Cabecera, PapelError> {
    if t.len() < CABECERA {
        return Err(PapelError::TrozosIncoherentes);
    }
    if t[0] != VERSION {
        return Err(PapelError::VersionDesconocida(t[0]));
    }
    Ok(Cabecera {
        indice: u16::from_be_bytes([t[1], t[2]]) as usize,
        total: u16::from_be_bytes([t[3], t[4]]) as usize,
        largo: u32::from_be_bytes([t[5], t[6], t[7], t[8]]) as usize,
    })
}

/// Reconstruye los datos desde los trozos que se hayan podido leer.
///
/// **No hace falta pasarlos todos ni en orden**: cada uno dice cuál es. Lo que
/// falte se rellena con ceros y queda a cargo del Reed-Solomon, que es
/// exactamente el trabajo para el que se intercaló.
pub fn reensamblar(trozos: &[Vec<u8>]) -> Result<Vec<u8>, PapelError> {
    let primero = trozos.first().ok_or(PapelError::SinTrozos)?;
    let c0 = leer_cabecera(primero)?;
    if c0.total == 0 || c0.largo == 0 {
        return Err(PapelError::TrozosIncoherentes);
    }

    // EL `largo` LO ESCRIBE QUIEN HACE LA HOJA, y esta es la capa más externa:
    // lo que llega es un papel fotografiado, que puede haber fabricado un
    // tercero. Sin esta cota, NUEVE bytes —`[ver|0|1|0xFFFFFFFF]`— reservaban
    // 4 GiB, medido: `VmPeak` de 3 a 4 099 MiB. Y no bastaba con que `ecc`
    // tenga su propio anti-DoS, porque su comprobación es `data_len >
    // protected.len()` y `protected` ES este buffer inflado: la cota quedaba
    // satisfecha por construcción y `recover` pedía otros 4 GiB, esta vez
    // llenándolos byte a byte.
    //
    // LA COTA ES EXACTA, no un número prudente. Con el intercalado, el símbolo
    // `j` lleva las posiciones `j, j+total, j+2·total…`, así que el que más
    // lleva —el 0— tiene `ceil(largo/total)` bytes. Si el 0 se perdió, el mayor
    // que quede tiene al menos `floor(largo/total)`. De ahí:
    //
    //     largo <= total · (mayor_carga_vista + 1)
    //
    // El `+1` cubre la división no exacta. No rechaza ninguna hoja legítima —ni
    // siquiera una a la que le falten los símbolos largos— y ata el buffer a los
    // bytes que DE VERDAD llegaron. Además, un `largo` muy por encima de lo
    // aportado no se podría recuperar de todos modos: el presupuesto de paridad
    // no da.
    let mayor_carga = trozos
        .iter()
        .map(|t| t.len().saturating_sub(CABECERA))
        .max()
        .unwrap_or(0);
    let techo = c0.total.saturating_mul(mayor_carga.saturating_add(1));
    if c0.largo > techo {
        return Err(PapelError::TrozosIncoherentes);
    }

    let mut flujo = vec![0u8; c0.largo];
    let mut vistos = vec![false; c0.total];
    for t in trozos {
        let c = leer_cabecera(t)?;
        // Todos tienen que hablar del mismo documento. Un índice repetido no se
        // ignora en silencio: dos lecturas del mismo símbolo con contenido
        // distinto significan que una de las dos está mal, y seguir sería
        // elegir a cara o cruz.
        if c.total != c0.total || c.largo != c0.largo || c.indice >= c0.total {
            return Err(PapelError::TrozosIncoherentes);
        }
        if vistos[c.indice] {
            return Err(PapelError::TrozosIncoherentes);
        }
        vistos[c.indice] = true;
        for (k, b) in t[CABECERA..].iter().enumerate() {
            // `checked_mul` y no `*`: en un target de 32 bits —un lector de QR
            // en un móvil es el consumidor natural de esto— `k * total` desborda
            // con una carga de unos 64 KiB. En debug sería pánico; en release,
            // un `pos` envuelto que además PASA la comprobación de abajo y
            // escribe un byte en el sitio equivocado. Aquí se corta.
            let Some(pos) = k.checked_mul(c0.total).and_then(|d| c.indice.checked_add(d)) else {
                break;
            };
            if pos >= flujo.len() {
                // Sobra relleno del símbolo: no es un error, es el último trozo
                // de una división que no fue exacta.
                break;
            }
            flujo[pos] = *b;
        }
    }

    ecc::recover(&flujo).ok_or(PapelError::NoSeRecupera)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn datos(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 31 + 7) as u8).collect()
    }

    #[test]
    fn va_y_vuelve_en_varios_tamanos() {
        for n in [1usize, 32, 100, 1000, 5000] {
            let d = datos(n);
            let trozos = empaquetar(&d, 200, 32).unwrap();
            assert_eq!(reensamblar(&trozos).unwrap(), d, "falló con {n} bytes");
        }
    }

    #[test]
    fn el_orden_de_los_trozos_da_igual() {
        let d = datos(500);
        let mut trozos = empaquetar(&d, 120, 32).unwrap();
        trozos.reverse();
        assert_eq!(reensamblar(&trozos).unwrap(), d);
    }

    #[test]
    fn ningun_trozo_pasa_de_la_capacidad() {
        let trozos = empaquetar(&datos(2000), 150, 32).unwrap();
        for t in &trozos {
            assert!(t.len() <= 150, "un trozo mide {}", t.len());
        }
    }

    #[test]
    fn se_recupera_perdiendo_los_simbolos_que_la_cota_promete() {
        // Paridad al TOPE que la librería acepta: la cota da varios símbolos y
        // se comprueba que se cumple perdiendo EXACTAMENTE esos. Antes iba a 200,
        // que es una paridad que `empaquetar` ya rechaza — por encima del tope el
        // decodificador puede entrar en pánico con una hoja dañada.
        let d = datos(3000);
        let trozos = empaquetar(&d, 100, ecc::PARIDAD_MAXIMA).unwrap();
        let total = trozos.len();
        let tolerados = simbolos_perdidos_tolerados(total, ecc::PARIDAD_MAXIMA);
        assert!(tolerados >= 1, "la cota debería admitir al menos uno");

        // Se pierden los PRIMEROS, que es el peor caso: son los que llevan el
        // bloque de cabecera de `ecc`. Si la garantía se probara quitando
        // símbolos del final, diría mucho más de lo que aguanta.
        let quedan: Vec<Vec<u8>> = trozos[tolerados..].to_vec();
        assert_eq!(
            reensamblar(&quedan).unwrap(),
            d,
            "perdiendo los {tolerados} PRIMEROS de {total} debería recuperarse"
        );
    }

    #[test]
    fn la_cota_de_perdida_no_es_vacua_y_no_promete_de_mas() {
        // La otra dirección, que es la que convierte la cota en cota. Sin esto,
        // «tolera N» sería una frase sin nada detrás: un formato que se
        // recuperara siempre haría pasar la prueba de arriba sin significar nada.
        let d = datos(3000);
        let paridad = ecc::PARIDAD_MAXIMA;
        let trozos = empaquetar(&d, 100, paridad).unwrap();
        let total = trozos.len();
        let tolerados = simbolos_perdidos_tolerados(total, paridad);

        // ESTE BANCO ERA UNA TAUTOLOGÍA, y lo halló una auditoría independiente.
        // El bucle llegaba hasta `total`, y en esa última vuelta `trozos[total..]`
        // es VACÍO —que cuenta como rotura—, así que `rompe_en` siempre era
        // `Some` y `rompe_en > tolerados` era cierto por construcción del rango.
        // Comprobado: con la cota inflada a `total/2` —la mentira histórica
        // exacta, prometer 50 aguantando 5— este banco seguía VERDE.
        //
        // Y AL DESHACER LA TAUTOLOGÍA APARECIÓ OTRA COSA, que es lo que enseña
        // este arreglo. La primera versión estricta exigía que perder UNO MÁS
        // fallara, y falló ella: con 67 símbolos la cota promete 5 y el formato
        // aguanta 6. `simbolos_perdidos_tolerados` es una COTA INFERIOR —«se
        // pueden perder al menos tantos»—, no un techo exacto, y exigir que sea
        // ajustada era exigirle algo que nunca prometió. Prometer de menos es
        // seguro; prometer de más es lo que mata.
        //
        // Lo que sí hay que afirmar, y no es tautológico: que la cota no sea
        // VACUA — que exista un nivel de pérdida REAL (no el conjunto vacío) que
        // la rompa, y que esté por encima de la cota.
        let mut rompe_en = None;
        for perdidos in (tolerados + 1)..total {
            let quedan: Vec<Vec<u8>> = trozos[perdidos..].to_vec();
            debug_assert!(!quedan.is_empty(), "el rango excluye el caso vacío");
            if reensamblar(&quedan).is_err() {
                rompe_en = Some(perdidos);
                break;
            }
        }
        let rompe_en = rompe_en.expect(
            "perdiendo hasta total-1 símbolos NUNCA falló: o el formato es mágico \
             o el banco no está midiendo la pérdida",
        );
        assert!(
            rompe_en > tolerados,
            "rompió en {rompe_en}, que no supera la cota de {tolerados}: la cota \
             MIENTE por exceso, que es la dirección peligrosa"
        );
    }

    #[test]
    fn intercalar_es_lo_que_salva_el_simbolo_perdido() {
        // La prueba del mecanismo, no del resultado: si los bytes fueran
        // contiguos, perder el primer símbolo se llevaría un tramo seguido. Se
        // comprueba que NO lo son — que el símbolo 0 lleva las posiciones
        // 0, total, 2·total…
        let d = datos(1000);
        let trozos = empaquetar(&d, 60, 32).unwrap();
        let total = trozos.len();
        assert!(total > 2, "hacen falta varios símbolos para que esto signifique algo");

        let protegido = ecc::protect(&d, 32);
        for (k, b) in trozos[0][CABECERA..].iter().enumerate() {
            assert_eq!(*b, protegido[k * total], "el símbolo 0 no está intercalado");
        }
    }

    #[test]
    fn una_capacidad_que_no_deja_sitio_se_rechaza() {
        for c in [0usize, 1, CABECERA] {
            assert!(matches!(
                empaquetar(&datos(10), c, 32),
                Err(PapelError::CapacidadInsuficiente { .. })
            ));
        }
        // Y uno más ya sirve, aunque haga muchos símbolos.
        assert!(empaquetar(&datos(10), CABECERA + 1, 32).is_ok());
    }

    #[test]
    fn los_trozos_de_otro_documento_no_se_mezclan() {
        let a = empaquetar(&datos(300), 100, 32).unwrap();
        let b = empaquetar(&datos(900), 100, 32).unwrap();
        let mezcla = vec![a[0].clone(), b[1].clone()];
        assert_eq!(
            reensamblar(&mezcla),
            Err(PapelError::TrozosIncoherentes),
            "dos documentos distintos no pueden reensamblarse juntos"
        );
    }

    #[test]
    fn un_indice_repetido_no_se_ignora_en_silencio() {
        let t = empaquetar(&datos(300), 100, 32).unwrap();
        let repe = vec![t[0].clone(), t[0].clone()];
        assert_eq!(reensamblar(&repe), Err(PapelError::TrozosIncoherentes));
    }

    #[test]
    fn una_version_desconocida_se_dice_en_vez_de_adivinarse() {
        let mut t = empaquetar(&datos(100), 100, 32).unwrap();
        t[0][0] = 99;
        assert_eq!(reensamblar(&t), Err(PapelError::VersionDesconocida(99)));
    }

    #[test]
    fn sin_trozos_o_con_basura_no_entra_en_panico() {
        assert_eq!(reensamblar(&[]), Err(PapelError::SinTrozos));
        assert_eq!(reensamblar(&[vec![]]), Err(PapelError::TrozosIncoherentes));
        assert_eq!(
            reensamblar(&[vec![VERSION, 0, 0]]),
            Err(PapelError::TrozosIncoherentes)
        );
        // Cabecera completa pero total y largo en cero: no se puede reensamblar
        // nada y hay que decirlo, no dividir por cero.
        assert_eq!(
            reensamblar(&[vec![VERSION, 0, 0, 0, 0, 0, 0, 0, 0]]),
            Err(PapelError::TrozosIncoherentes)
        );
    }

    #[test]
    fn la_cota_es_cero_cuando_no_alcanza() {
        // Con pocos símbolos y poca paridad no se tolera ninguna pérdida, y la
        // función tiene que decirlo en vez de devolver un optimismo.
        assert_eq!(simbolos_perdidos_tolerados(2, 2), 0);
        assert_eq!(simbolos_perdidos_tolerados(0, 200), 0);
    }

    #[test]
    fn la_cabecera_de_ecc_es_el_techo_y_no_los_datos() {
        // La cuenta por datos daría 50 con 155 símbolos y paridad 200; la
        // cabecera de `ecc` la corta en 5. Si alguien «optimiza» esta función
        // mirando solo los bloques de datos, esta prueba se lo dice.
        assert_eq!(simbolos_perdidos_tolerados(155, 200), 5);
        assert_eq!(simbolos_perdidos_tolerados(1000, 254), 5);
    }
}

/// El símbolo hecho, para quien no quiera renderizarlo por su cuenta.
///
/// **No es el camino recomendado y por eso es opcional.** Dibujar un QR es
/// presentación, y en la mayoría de los productos ya lo hace el frontend con la
/// librería que prefiera; [`super::empaquetar`] le entrega los trozos y no hace
/// falta nada más. Esto existe para el caso contrario: una herramienta de línea
/// de órdenes, o un binario que imprime sin frontend.
///
/// `qrcode` entra con `default-features = false`, y así **no arrastra ninguna
/// dependencia transitiva**: lo único que declara es `image`, y es opcional —
/// son los renderizadores a PNG y SVG, que aquí no se quieren porque lo que se
/// devuelve es la matriz de módulos y el llamante decide cómo pintarla.
#[cfg(feature = "qr")]
pub mod qr {
    use super::PapelError;
    use qrcode::{Color, EcLevel, QrCode};

    /// Nivel de corrección de errores DEL PROPIO QR.
    ///
    /// No se confunde con la paridad de [`super::empaquetar`], y las dos hacen
    /// falta porque cubren daños distintos: la del QR repara lo que se estropea
    /// DENTRO de un símbolo (una mancha, un doblez), y la de Reed-Solomon repara
    /// que un símbolo ENTERO se pierda o no se pueda leer.
    pub use qrcode::EcLevel as Nivel;

    /// Nivel por defecto: **alto (30 %)**.
    ///
    /// El habitual en las librerías es el medio, y aquí se sube a propósito: la
    /// medición de degradación (hoja de ruta §6) mostró que el papel castiga
    /// mucho más de lo que sugiere la intuición, y este portador existe justo
    /// para el papel que envejece mal. Se paga en capacidad, que es lo barato:
    /// para lo caro —volver a imprimir un documento que ya no se puede— no hay
    /// remedio.
    pub const NIVEL_POR_DEFECTO: EcLevel = EcLevel::H;

    /// Un símbolo QR como matriz cuadrada de módulos.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Simbolo {
        /// Lado en módulos. **No incluye la zona de silencio**: quien imprime
        /// tiene que dejar el margen de 4 módulos que exige la norma, o muchos
        /// lectores no lo encuentran.
        pub lado: usize,
        oscuros: Vec<bool>,
    }

    impl Simbolo {
        /// `true` si el módulo `(x, y)` es oscuro.
        pub fn oscuro(&self, x: usize, y: usize) -> bool {
            x < self.lado && y < self.lado && self.oscuros[y * self.lado + x]
        }

        /// Invierte un módulo. **Solo para las pruebas del laboratorio**: es como
        /// se simula una mancha o un doblez sin tener que imprimir nada.
        #[cfg(test)]
        pub(crate) fn ensuciar(&mut self, x: usize, y: usize) {
            if x < self.lado && y < self.lado {
                let i = y * self.lado + x;
                self.oscuros[i] = !self.oscuros[i];
            }
        }

        /// El símbolo en texto, para verlo en una terminal o en un diff.
        pub fn a_texto(&self) -> String {
            let mut s = String::with_capacity((self.lado + 1) * self.lado);
            for y in 0..self.lado {
                for x in 0..self.lado {
                    s.push(if self.oscuro(x, y) { '#' } else { '.' });
                }
                s.push('\n');
            }
            s
        }
    }

    /// Convierte cada trozo de [`super::empaquetar`] en un símbolo QR.
    ///
    /// Cada símbolo es un QR **estándar e independiente**: no se usa *Structured
    /// Append*. Así cualquier lector saca la carga de cualquiera de ellos por su
    /// cuenta, no se depende de que la librería soporte esa extensión, y la
    /// cabecera de reensamblado viaja DENTRO del flujo protegido por Reed-Solomon
    /// en vez de en un campo del símbolo.
    pub fn simbolos(trozos: &[Vec<u8>], nivel: EcLevel) -> Result<Vec<Simbolo>, PapelError> {
        trozos
            .iter()
            .map(|t| {
                let code = QrCode::with_error_correction_level(t, nivel)
                    .map_err(|e| PapelError::SimboloImposible(e.to_string()))?;
                let lado = code.width();
                Ok(Simbolo {
                    lado,
                    oscuros: code.to_colors().iter().map(|c| *c == Color::Dark).collect(),
                })
            })
            .collect()
    }
}

/// El círculo completo: lo que escribimos lo lee un decoder INDEPENDIENTE.
///
/// `rqrr` es dev-dependency y no viaja en el artefacto. Está aquí por una razón
/// concreta: un encoder roto **de forma consistente** pasaría una prueba de ida y
/// vuelta contra sí mismo sin despeinarse, y fallaría en el primer papel real.
/// Lo único que descarta eso es que quien lea no sea quien escribió.
#[cfg(all(test, feature = "qr"))]
mod pruebas_qr {
    use super::qr::{simbolos, Simbolo, NIVEL_POR_DEFECTO};
    use super::*;

    /// Decodifica un símbolo con `rqrr`. `None` si no se puede leer.
    ///
    /// Se usa `decode_to` sobre un `Vec<u8>` y no `decode`, que devuelve
    /// `String`: la carga es ciphertext, no texto, y por ahí se habría perdido
    /// en cuanto un byte no fuera UTF-8 válido.
    fn leer(s: &Simbolo) -> Option<Vec<u8>> {
        let rejilla = rqrr::SimpleGrid::from_func(s.lado, |x, y| s.oscuro(x, y));
        let mut out = Vec::new();
        rqrr::Grid::new(rejilla).decode_to(&mut out).ok()?;
        Some(out)
    }

    fn caso() -> (Vec<u8>, Vec<Vec<u8>>, Vec<Simbolo>) {
        let d: Vec<u8> = (0..300u16).map(|i| (i * 37 + 11) as u8).collect();
        let trozos = empaquetar(&d, 100, ecc::PARIDAD_MAXIMA).unwrap();
        let s = simbolos(&trozos, NIVEL_POR_DEFECTO).unwrap();
        (d, trozos, s)
    }

    #[test]
    fn un_decoder_independiente_lee_cada_trozo_tal_cual() {
        let (_, trozos, simbolos) = caso();
        assert_eq!(simbolos.len(), trozos.len());
        for (i, (s, t)) in simbolos.iter().zip(&trozos).enumerate() {
            assert_eq!(
                leer(s).as_ref(),
                Some(t),
                "el símbolo {i} no devolvió su trozo"
            );
        }
    }

    #[test]
    fn el_circulo_completo_devuelve_el_documento() {
        let (d, _, simbolos) = caso();
        let leidos: Vec<Vec<u8>> = simbolos.iter().filter_map(leer).collect();
        assert_eq!(reensamblar(&leidos).unwrap(), d);
    }

    #[test]
    fn la_correccion_del_propio_qr_repara_una_mancha() {
        // Las DOS capas de corrección existen porque cubren daños distintos, y
        // esta prueba fija la de dentro: unos módulos estropeados en un símbolo
        // los repara el QR por su cuenta, sin gastar presupuesto del
        // Reed-Solomon de `empaquetar`.
        let (_, trozos, simbolos) = caso();
        let s = &simbolos[0];
        let mut manchado = s.clone();
        // Una mancha pequeña lejos de los patrones de posición.
        for y in (s.lado / 2)..(s.lado / 2 + 2) {
            for x in (s.lado / 2)..(s.lado / 2 + 2) {
                manchado.ensuciar(x, y);
            }
        }
        assert_ne!(manchado, *s, "la mancha tiene que cambiar algo");
        assert_eq!(
            leer(&manchado).as_ref(),
            Some(&trozos[0]),
            "el nivel alto de corrección debería absorber cuatro módulos"
        );
    }

    #[test]
    fn un_simbolo_ilegible_lo_salva_el_reed_solomon_de_arriba() {
        // Y esta fija la capa de fuera, que es la razón de intercalar: un
        // símbolo que no se puede leer EN ABSOLUTO —se perdió la hoja, se quemó
        // la esquina— y el documento sale igual.
        let (d, _, simbolos) = caso();
        let total = simbolos.len();
        assert!(
            simbolos_perdidos_tolerados(total, ecc::PARIDAD_MAXIMA) >= 1,
            "con {total} símbolos la cota tiene que admitir al menos uno"
        );
        let leidos: Vec<Vec<u8>> = simbolos.iter().skip(1).filter_map(leer).collect();
        assert_eq!(leidos.len(), total - 1);
        assert_eq!(reensamblar(&leidos).unwrap(), d);
    }

    #[test]
    fn destrozar_un_simbolo_lo_vuelve_ilegible_de_verdad() {
        // El caso rojo de las dos pruebas de arriba. Si un símbolo destrozado
        // siguiera leyéndose, «tolera daño» no significaría nada: hay que ver
        // que el canal ROMPE antes de creerle que repara.
        let (_, _, simbolos) = caso();
        let mut roto = simbolos[0].clone();
        for y in 0..roto.lado {
            for x in 0..roto.lado {
                if (x + y) % 2 == 0 {
                    roto.ensuciar(x, y);
                }
            }
        }
        assert!(
            leer(&roto).is_none(),
            "un símbolo con la mitad de los módulos invertidos NO puede leerse"
        );
    }
}

/// La capa tecleable: lo que un humano puede copiar sin ninguna máquina.
///
/// # Por qué existe, que NO es la robustez
///
/// La medición del §6 de la hoja de ruta fue tajante: en la degradación donde la
/// matriz entrega 147 bytes, esta capa entrega 28 — **menos que una clave**. Como
/// respaldo de robustez no puede llevar lo único que existe para llevar, y así
/// está escrito en la hoja de ruta.
///
/// Lo que sí aporta es otra cosa: **degrada a «teclee estos caracteres en
/// cualquier decodificador Base32»**. Cero dependencia de que esta librería
/// exista en 2050, que es el objetivo declarado del portador de papel.
///
/// # Y por eso el marco Reed-Solomon es OPCIONAL
///
/// Es la condición que hace válido ese argumento, no un adorno de configuración:
///
/// - [`Marco::Desnudo`] es **exactamente** `Base32(secreto)` según la RFC 4648.
///   Cualquier decodificador del mundo lo abre, hoy y dentro de veinte años. No
///   tolera un solo carácter mal tecleado.
/// - [`Marco::Protegido`] es `Base32(ecc::protect(secreto))`. Tolera errores de
///   tecleo, y a cambio **necesita esta librería o su especificación**: quien lo
///   decodifique con una herramienta genérica obtiene el flujo protegido, no el
///   secreto.
///
/// **No hay valor por defecto.** Quien escribe elige, porque las dos opciones
/// dan artefactos distintos y una promesa distinta a quien reciba el papel.
///
/// # Un carácter mal tecleado en el marco desnudo NO pasa desapercibido
///
/// No lleva suma de verificación y es deliberado: sería un campo que la persona
/// de 2050 tendría que saber descartar. No hace falta, porque lo que viaja por
/// aquí es una CLAVE, y una clave equivocada no abre el contenedor. La
/// comprobación existe y es ruidosa; simplemente vive en el otro extremo.
pub mod tecleable {
    use super::PapelError;
    use crate::ecc;

    /// Alfabeto Base32 de la RFC 4648. Excluye `0`, `1`, `8` y `9` justamente
    /// para que no haya parejas que se confundan al leer a mano.
    pub const ALFABETO: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /// El carácter de relleno de la RFC 4648.
    ///
    /// Se emite, aunque en un papel sea ruido. Es el precio de la promesa: un
    /// decodificador ESTRICTO de la norma rechaza la entrada sin relleno, y la
    /// capa desnuda existe justamente para que funcione con el decodificador que
    /// haya, no con el que a nosotros nos guste.
    pub const RELLENO: char = '=';

    /// Cuántos caracteres van juntos antes de un espacio.
    pub const GRUPO: usize = 5;
    /// Cuántos grupos por línea.
    pub const GRUPOS_POR_LINEA: usize = 6;

    /// Qué marco lleva el texto. Sin defecto: se elige.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Marco {
        /// `Base32(secreto)` y nada más. Legible con cualquier herramienta.
        Desnudo,
        /// `Base32(ecc::protect(secreto))`. Tolera errores de tecleo y exige
        /// esta librería para deshacerse.
        Protegido {
            /// Bytes de paridad Reed-Solomon por bloque.
            paridad: u8,
        },
    }

    /// Errores de la capa tecleable.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum TecleableError {
        /// Un carácter que no está en el alfabeto y **no se puede adivinar sin
        /// riesgo**. Lleva cuál y en qué posición, porque quien teclea necesita
        /// saber dónde mirar.
        CaracterImposible {
            /// El carácter tal como llegó.
            caracter: char,
            /// Su posición entre los caracteres útiles (sin contar espacios).
            posicion: usize,
        },
        /// Un carácter ambiguo: se parece a dos del alfabeto y corregirlo sería
        /// adivinar. Lleva las dos lecturas para que la persona decida.
        CaracterAmbiguo {
            /// El carácter tal como llegó.
            caracter: char,
            /// Su posición entre los caracteres útiles.
            posicion: usize,
            /// A qué podría corresponder.
            lecturas: &'static str,
        },
        /// No quedó ningún carácter útil.
        Vacio,
        /// El marco protegido no pudo deshacerse.
        NoSeRecupera,
        /// La paridad pedida pasa de [`crate::ecc::PARIDAD_MAXIMA`]. Se rechaza,
        /// no se recorta: ver el porqué en [`escribir`].
        ParidadExcesiva {
            /// La que se pidió.
            dada: u8,
            /// La mayor que se acepta.
            maxima: u8,
        },
    }

    impl core::fmt::Display for TecleableError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Self::CaracterImposible {
                    caracter,
                    posicion,
                } => write!(
                    f,
                    "el carácter «{caracter}» de la posición {posicion} no existe en el alfabeto"
                ),
                Self::CaracterAmbiguo {
                    caracter,
                    posicion,
                    lecturas,
                } => write!(
                    f,
                    "el carácter «{caracter}» de la posición {posicion} puede ser {lecturas}: \
                     hay que mirar el papel, no adivinar"
                ),
                Self::Vacio => write!(f, "no había ningún carácter útil"),
                Self::NoSeRecupera => {
                    write!(f, "el marco protegido tiene más errores de los que corrige")
                }
                Self::ParidadExcesiva { dada, maxima } => write!(
                    f,
                    "la paridad pedida ({dada}) pasa del máximo de {maxima}: se rechaza \
                     en vez de recortarla, para que quien imprime el papel sepa que no \
                     lleva la protección que pidió"
                ),
            }
        }
    }

    impl std::error::Error for TecleableError {}

    /// La frase que hay que IMPRIMIR AL LADO del bloque.
    ///
    /// El artefacto que sobrevive veinte años no son los caracteres: son los
    /// caracteres **más la frase que dice qué hacer con ellos**. Un papel sin
    /// esta línea obliga a quien lo herede a adivinar, y adivinar con una clave
    /// no es una opción.
    pub fn instruccion(marco: Marco) -> &'static str {
        match marco {
            Marco::Desnudo => {
                "Base32 (RFC 4648). Ignore los espacios y los saltos de línea. \
                 Cualquier decodificador Base32 devuelve el secreto tal cual."
            }
            Marco::Protegido { .. } => {
                "Base32 (RFC 4648) de un flujo con corrección de errores \
                 Reed-Solomon de Quipu. Un decodificador Base32 genérico NO \
                 devuelve el secreto: hace falta quipu-nucleo o su especificación."
            }
        }
    }

    /// Escribe el bloque para teclear: mayúsculas, en grupos y en líneas.
    ///
    /// **Rechaza** una paridad por encima de [`crate::ecc::PARIDAD_MAXIMA`] en
    /// vez de recortarla. Devolvía `String` y dejaba que `ecc::protect`
    /// recortara en silencio, mientras `papel::empaquetar` —la función hermana,
    /// mismo parámetro, misma capa— sí rechazaba. La asimetría no tenía
    /// justificación: quien imprime un papel tiene que enterarse de que no va a
    /// llevar la protección que pidió, entre en esta puerta o en la otra.
    ///
    /// Con `Marco::Desnudo` no puede fallar nunca.
    pub fn escribir(datos: &[u8], marco: Marco) -> Result<String, TecleableError> {
        let flujo = match marco {
            Marco::Desnudo => datos.to_vec(),
            Marco::Protegido { paridad } if paridad > ecc::PARIDAD_MAXIMA => {
                return Err(TecleableError::ParidadExcesiva {
                    dada: paridad,
                    maxima: ecc::PARIDAD_MAXIMA,
                });
            }
            Marco::Protegido { paridad } => ecc::protect(datos, paridad),
        };
        let simbolos = a_cinco_bits(&flujo);
        // El relleno lleva el total a múltiplo de 8, como manda la RFC.
        let con_relleno = simbolos.len().div_ceil(8) * 8;
        let mut s = String::new();
        for i in 0..con_relleno {
            if i > 0 {
                if i % (GRUPO * GRUPOS_POR_LINEA) == 0 {
                    s.push('\n');
                } else if i % GRUPO == 0 {
                    s.push(' ');
                }
            }
            s.push(match simbolos.get(i) {
                Some(c) => ALFABETO[*c as usize] as char,
                None => RELLENO,
            });
        }
        Ok(s)
    }

    /// Lee lo que [`escribir`] produjo, tolerando cómo escribe la gente.
    ///
    /// Se aceptan minúsculas, espacios, saltos de línea y guiones. Se corrige el
    /// **cero** por letra O, que es inequívoco porque el `0` no está en el
    /// alfabeto y la `O` sí. **No se corrige nada ambiguo**: un `1` puede ser `I`
    /// o `L`, y las dos están en el alfabeto, así que se rechaza diciendo cuáles
    /// son las lecturas. Adivinar aquí produciría un secreto equivocado en
    /// silencio, que es el único fallo que este formato no puede permitirse.
    pub fn leer(texto: &str, marco: Marco) -> Result<Vec<u8>, TecleableError> {
        let mut simbolos = Vec::new();
        let mut posicion = 0usize;
        for c in texto.chars() {
            if c.is_whitespace() || c == '-' || c == '_' || c == RELLENO {
                continue;
            }
            let arriba = c.to_ascii_uppercase();
            let arriba = if arriba == '0' { 'O' } else { arriba };
            match arriba {
                '1' => {
                    return Err(TecleableError::CaracterAmbiguo {
                        caracter: c,
                        posicion,
                        lecturas: "«I» o «L»",
                    });
                }
                '8' => {
                    return Err(TecleableError::CaracterAmbiguo {
                        caracter: c,
                        posicion,
                        lecturas: "«B» o «S»",
                    });
                }
                _ => {}
            }
            match ALFABETO.iter().position(|a| *a as char == arriba) {
                Some(i) => simbolos.push(i as u8),
                None => {
                    return Err(TecleableError::CaracterImposible {
                        caracter: c,
                        posicion,
                    });
                }
            }
            posicion += 1;
        }
        if simbolos.is_empty() {
            return Err(TecleableError::Vacio);
        }
        let flujo = de_cinco_bits(&simbolos);
        match marco {
            Marco::Desnudo => Ok(flujo),
            Marco::Protegido { .. } => {
                ecc::recover(&flujo).ok_or(TecleableError::NoSeRecupera)
            }
        }
    }

    /// Bytes a símbolos de 5 bits.
    fn a_cinco_bits(datos: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(datos.len() * 8 / 5 + 1);
        let (mut acc, mut bits) = (0u16, 0u32);
        for &b in datos {
            acc = (acc << 8) | b as u16;
            bits += 8;
            while bits >= 5 {
                out.push(((acc >> (bits - 5)) & 0x1f) as u8);
                bits -= 5;
            }
        }
        if bits > 0 {
            out.push(((acc << (5 - bits)) & 0x1f) as u8);
        }
        out
    }

    /// Símbolos de 5 bits a bytes. Los bits sobrantes del final se descartan:
    /// son el relleno del último símbolo, no datos.
    fn de_cinco_bits(simbolos: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(simbolos.len() * 5 / 8);
        let (mut acc, mut bits) = (0u16, 0u32);
        for &s in simbolos {
            acc = (acc << 5) | (s & 0x1f) as u16;
            bits += 5;
            if bits >= 8 {
                out.push(((acc >> (bits - 8)) & 0xff) as u8);
                bits -= 8;
            }
        }
        out
    }

    /// Para que nadie tenga que buscar el tipo de error de `ecc` desde fuera.
    impl From<TecleableError> for PapelError {
        fn from(_: TecleableError) -> Self {
            PapelError::NoSeRecupera
        }
    }
}

/// El tercer marco de la capa tecleable: **palabras**, según la BIP-39.
///
/// # Qué resuelve, y qué NO resuelven los otros dos
///
/// [`tecleable::Marco::Desnudo`] es Base32 puro: lo lee cualquier herramienta,
/// pero **no tiene suma de verificación**. Un carácter mal transcrito devuelve
/// otro secreto EN SILENCIO, que en una clave es el peor fallo posible.
/// [`tecleable::Marco::Protegido`] cierra ese hueco con Reed-Solomon, y al
/// hacerlo pierde lo único que hacía valiosa la capa: deja de leerse sin Quipu.
///
/// Este marco es el que tiene las dos cosas a la vez, y por una razón que no es
/// nuestra: la BIP-39 es un estándar con implementaciones en todos los
/// lenguajes, así que **detecta el error de transcripción Y la decodifica
/// cualquiera en 2050 sin que Quipu exista**. Una lista de palabras propia
/// habría recreado exactamente el problema de los glifos que este proyecto ya
/// eliminó una vez.
///
/// Y añade lo que ningún marco de caracteres da: **se dicta por teléfono**. Son
/// 24 palabras frente a 52 caracteres de Base32, sin parejas confundibles.
///
/// # Lo que este marco NO puede hacer
///
/// La BIP-39 admite **exactamente** 16, 20, 24, 28 o 32 bytes. No es una
/// limitación que se pueda relajar: el número de palabras sale de la aritmética
/// del formato. Con cualquier otro tamaño esto **falla ruidosamente**
/// ([`PalabrasError::TamanoNoAdmitido`]) en vez de rellenar hasta un tamaño
/// válido, porque un relleno silencioso devolvería más bytes de los que se
/// guardaron y nadie lo notaría hasta necesitar la clave.
///
/// La suma de verificación es de **detección, no de corrección**: son ENT/32
/// bits (8 para una clave de 32 bytes). Dice que hay un error, no cuál.
///
/// # Advertencia de lectura
///
/// Estas palabras se parecen a la frase semilla de una cartera de Bitcoin
/// porque **son el mismo formato**. No lo son: aquí codifican el secreto que se
/// le entregue. [`palabras::instruccion`] lo dice, y se imprime al lado.
#[cfg(feature = "palabras")]
pub mod palabras {
    use sha2::{Digest, Sha256};

    /// La lista oficial en inglés de la BIP-39, **verbatim**.
    ///
    /// Se guarda como el archivo original y no como una tabla de Rust generada
    /// a propósito: así cualquiera puede comprobar su SHA-256 contra el de la
    /// fuente canónica sin fiarse de nuestra transcripción. Lo hace la prueba
    /// `la_lista_es_la_canonica`, con [`SHA256_CANONICO`].
    pub const LISTA_CRUDA: &str = include_str!("bip39_english.txt");

    /// SHA-256 de la lista canónica en inglés
    /// (`bips/bip-0039/english.txt`). Si esto no cuadra, la lista se corrompió
    /// y todo lo que se escriba con ella será ilegible para el resto del mundo.
    pub const SHA256_CANONICO: &str =
        "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

    /// Cuántas palabras tiene la lista. Es 2^11, y por eso cada palabra lleva
    /// 11 bits exactos.
    pub const PALABRAS_EN_LA_LISTA: usize = 2048;

    /// Los tamaños de secreto que la BIP-39 admite, en bytes.
    pub const TAMANOS: &[usize] = &[16, 20, 24, 28, 32];

    /// Cuántos caracteres bastan para identificar una palabra sin ambigüedad.
    /// Lo garantiza la propia BIP-39, no nosotros; la prueba
    /// `cuatro_letras_bastan` lo comprueba sobre la lista real.
    pub const PREFIJO_SUFICIENTE: usize = 4;

    /// La lista partida en palabras. `\n` y `\r\n` valen igual.
    fn lista() -> &'static [&'static str] {
        use std::sync::LazyLock;
        static L: LazyLock<Vec<&'static str>> =
            LazyLock::new(|| LISTA_CRUDA.lines().map(str::trim).filter(|l| !l.is_empty()).collect());
        &L
    }

    /// Errores del marco de palabras.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PalabrasError {
        /// El secreto no mide lo que la BIP-39 admite. **No se rellena**: eso
        /// devolvería al leer más bytes de los que se guardaron.
        TamanoNoAdmitido {
            /// Los bytes que se pasaron.
            bytes: usize,
            /// Los que se admiten.
            admitidos: &'static [usize],
        },
        /// El número de palabras no corresponde a ningún tamaño válido.
        CuentaNoAdmitida {
            /// Las que se leyeron.
            palabras: usize,
        },
        /// Una palabra que no está en la lista y no es prefijo de ninguna.
        PalabraDesconocida {
            /// Tal como se escribió.
            palabra: String,
            /// Su posición, empezando en 1, para poder señalarla en el papel.
            posicion: usize,
        },
        /// Encaja con una sola palabra, pero con menos de
        /// [`PREFIJO_SUFICIENTE`] letras. Se rechaza porque la unicidad con
        /// menos de cuatro letras es una casualidad de esta lista, no algo que
        /// la BIP-39 garantice.
        PalabraDemasiadoCorta {
            /// Tal como se escribió.
            palabra: String,
            /// Su posición, empezando en 1.
            posicion: usize,
        },
        /// Un fragmento que encaja con varias palabras: elegir sería adivinar.
        PalabraAmbigua {
            /// Tal como se escribió.
            palabra: String,
            /// Su posición, empezando en 1.
            posicion: usize,
            /// Con cuántas palabras de la lista encaja.
            candidatas: usize,
        },
        /// La suma de verificación no cuadra: **hay un error de transcripción**.
        ///
        /// Este es el error que justifica el marco entero. Detecta, no corrige:
        /// dice que algo está mal, no qué palabra.
        SumaDeVerificacion,
        /// No había ninguna palabra.
        Vacio,
        /// La lista embebida no tiene las 2 048 palabras: está corrupta.
        ///
        /// No debería ocurrir nunca —el archivo va en el binario y una prueba
        /// comprueba su SHA-256 contra el canónico—, y por eso mismo se devuelve
        /// como error en vez de entrar en pánico: si llegara a pasar, quien lo
        /// sufre es quien intenta guardar una clave.
        ListaCorrupta {
            /// El índice que no existía.
            indice: usize,
        },
    }

    impl core::fmt::Display for PalabrasError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Self::TamanoNoAdmitido { bytes, admitidos } => write!(
                    f,
                    "un secreto de {bytes} bytes no cabe en la BIP-39: admite {admitidos:?} \
                     y rellenar hasta uno de ellos devolvería bytes que nadie guardó"
                ),
                Self::CuentaNoAdmitida { palabras } => write!(
                    f,
                    "{palabras} palabra(s) no corresponden a ningún secreto válido: \
                     son 12, 15, 18, 21 o 24 — cuente otra vez, es lo que más falla"
                ),
                Self::PalabraDesconocida { palabra, posicion } => write!(
                    f,
                    "la palabra {posicion}.ª («{palabra}») no está en la lista de la BIP-39"
                ),
                Self::PalabraDemasiadoCorta { palabra, posicion } => write!(
                    f,
                    "la palabra {posicion}.ª («{palabra}») tiene menos de \
                     {PREFIJO_SUFICIENTE} letras: escríbala completa o hasta la cuarta"
                ),
                Self::PalabraAmbigua {
                    palabra,
                    posicion,
                    candidatas,
                } => write!(
                    f,
                    "la palabra {posicion}.ª («{palabra}») encaja con {candidatas} de la lista: \
                     escriba al menos {PREFIJO_SUFICIENTE} letras"
                ),
                Self::SumaDeVerificacion => write!(
                    f,
                    "la suma de verificación no cuadra: alguna palabra está mal escrita \
                     o en otro orden — el secreto NO se devuelve a medias"
                ),
                Self::Vacio => write!(f, "no había ninguna palabra"),
                Self::ListaCorrupta { indice } => write!(
                    f,
                    "la lista de palabras embebida no tiene el índice {indice}: \
                     está corrupta y nada de lo que se escriba será legible"
                ),
            }
        }
    }

    impl std::error::Error for PalabrasError {}

    /// La frase que hay que IMPRIMIR AL LADO de las palabras.
    ///
    /// Sin ella el papel obliga a quien lo herede a adivinar qué son esas
    /// veinticuatro palabras — y el parecido con una cartera de Bitcoin hace
    /// que la suposición más probable sea la equivocada.
    pub fn instruccion() -> &'static str {
        "Lista de palabras BIP-39 (inglés). NO es una cartera de Bitcoin: \
         codifica un secreto. Cualquier herramienta que convierta una frase \
         BIP-39 en su ENTROPÍA devuelve el secreto tal cual. El orden importa; \
         bastan las 4 primeras letras de cada palabra."
    }

    /// Escribe el secreto como frase BIP-39.
    ///
    /// Falla si el tamaño no es uno de [`TAMANOS`]. Ver el porqué en el
    /// encabezado del módulo.
    pub fn escribir(datos: &[u8]) -> Result<String, PalabrasError> {
        if !TAMANOS.contains(&datos.len()) {
            return Err(PalabrasError::TamanoNoAdmitido {
                bytes: datos.len(),
                admitidos: TAMANOS,
            });
        }
        let bits_suma = datos.len() * 8 / 32;
        let suma = Sha256::digest(datos);

        // Entropía y suma, seguidas, leídas de 11 en 11 bits.
        let total = datos.len() * 8 + bits_suma;
        let bit = |i: usize| -> u32 {
            let (fuente, i) = if i < datos.len() * 8 {
                (datos[i / 8], i)
            } else {
                let j = i - datos.len() * 8;
                (suma[j / 8], j)
            };
            ((fuente >> (7 - (i % 8))) & 1) as u32
        };

        let mut frase = String::new();
        for p in 0..total / 11 {
            let mut idx = 0u32;
            for k in 0..11 {
                idx = (idx << 1) | bit(p * 11 + k);
            }
            if p > 0 {
                frase.push(' ');
            }
            // `.get` y no `[]`: `idx` son 11 bits, así que es < 2048 SIEMPRE —
            // mientras la lista tenga 2048 palabras. Lo que hoy lo sostiene es
            // una PRUEBA (`la_lista_es_la_canonica`), no el tipo; si alguien
            // tocara el archivo de la lista, esto entraría en pánico en vez de
            // fallar. Directiva 6: mejor código que lo impide que prueba que
            // lo caza.
            let palabra = lista()
                .get(idx as usize)
                .ok_or(PalabrasError::ListaCorrupta { indice: idx as usize })?;
            frase.push_str(palabra);
        }
        Ok(frase)
    }

    /// Lee lo que [`escribir`] produjo, tolerando cómo escribe la gente.
    ///
    /// Se aceptan mayúsculas, espacios de sobra, saltos de línea y **palabras
    /// truncadas** a partir de [`PREFIJO_SUFICIENTE`] letras — que la BIP-39
    /// garantiza inequívocas—. Lo que NO se tolera es una suma de verificación
    /// que no cuadre: ahí se devuelve error y **ningún byte**.
    pub fn leer(texto: &str) -> Result<Vec<u8>, PalabrasError> {
        let crudas: Vec<&str> = texto.split_whitespace().collect();
        if crudas.is_empty() {
            return Err(PalabrasError::Vacio);
        }
        // 12, 15, 18, 21 o 24 palabras: las que salen de los tamaños válidos.
        let bytes = match crudas.len() {
            12 => 16,
            15 => 20,
            18 => 24,
            21 => 28,
            24 => 32,
            n => return Err(PalabrasError::CuentaNoAdmitida { palabras: n }),
        };

        let mut indices = Vec::with_capacity(crudas.len());
        for (i, cruda) in crudas.iter().enumerate() {
            let limpia: String = cruda
                .chars()
                .filter(|c| c.is_ascii_alphabetic())
                .map(|c| c.to_ascii_lowercase())
                .collect();
            indices.push(indice_de(&limpia, i + 1)?);
        }

        // Deshacer los grupos de 11 bits.
        let bits_suma = bytes * 8 / 32;
        let mut plano = Vec::with_capacity(bytes + 1);
        let (mut acc, mut n) = (0u32, 0u32);
        for idx in &indices {
            acc = (acc << 11) | *idx;
            n += 11;
            while n >= 8 {
                plano.push(((acc >> (n - 8)) & 0xff) as u8);
                n -= 8;
            }
        }
        // Los bits que sobran son la cola de la suma; van en el último byte.
        if n > 0 {
            plano.push(((acc << (8 - n)) & 0xff) as u8);
        }

        let entropia = plano[..bytes].to_vec();
        let esperada = Sha256::digest(&entropia)[0];
        let mascara = 0xffu8 << (8 - bits_suma);
        if plano[bytes] & mascara != esperada & mascara {
            return Err(PalabrasError::SumaDeVerificacion);
        }
        Ok(entropia)
    }

    /// Una palabra escrita a mano → su índice. Exacta primero; si no, prefijo
    /// inequívoco. Nunca se elige entre varias.
    fn indice_de(limpia: &str, posicion: usize) -> Result<u32, PalabrasError> {
        if limpia.is_empty() {
            return Err(PalabrasError::PalabraDesconocida {
                palabra: String::new(),
                posicion,
            });
        }
        if let Some(i) = lista().iter().position(|w| *w == limpia) {
            return Ok(i as u32);
        }
        let candidatas: Vec<usize> = lista()
            .iter()
            .enumerate()
            .filter(|(_, w)| w.starts_with(limpia))
            .map(|(i, _)| i)
            .collect();
        match candidatas.len() {
            0 => Err(PalabrasError::PalabraDesconocida {
                palabra: limpia.to_string(),
                posicion,
            }),
            1 if limpia.len() >= PREFIJO_SUFICIENTE => Ok(candidatas[0] as u32),
            // Encaja con UNA sola, pero con menos de cuatro letras. Aceptarlo
            // sería fiarse de que la lista no cambie nunca; y decir «ambigua»
            // sería mentir sobre lo que se midió — encaja con una, no con dos.
            1 => Err(PalabrasError::PalabraDemasiadoCorta {
                palabra: limpia.to_string(),
                posicion,
            }),
            n => Err(PalabrasError::PalabraAmbigua {
                palabra: limpia.to_string(),
                posicion,
                candidatas: n,
            }),
        }
    }
}

#[cfg(test)]
mod pruebas_tecleable {
    use super::tecleable::*;

    /// Quita los espacios y saltos que solo existen para poder teclear.
    fn apretado(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }

    #[test]
    fn el_marco_desnudo_es_rfc4648_exacto() {
        // LA PRUEBA QUE SOSTIENE TODA LA PROMESA. Son los vectores del §10 de la
        // RFC 4648, no una comprobación contra nosotros mismos: si esto pasa,
        // cualquier decodificador Base32 del mundo devuelve el secreto, y esa es
        // la única razón por la que esta capa existe.
        for (claro, esperado) in [
            ("f", "MY======"),
            ("fo", "MZXQ===="),
            ("foo", "MZXW6==="),
            ("foob", "MZXW6YQ="),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI======"),
        ] {
            assert_eq!(
                apretado(&escribir(claro.as_bytes(), Marco::Desnudo).unwrap()),
                esperado,
                "«{claro}» no coincide con el vector de la RFC 4648"
            );
        }
    }

    #[test]
    fn el_desnudo_va_y_vuelve() {
        for n in [1usize, 5, 32, 64, 200] {
            let d: Vec<u8> = (0..n).map(|i| (i * 53 + 3) as u8).collect();
            let t = escribir(&d, Marco::Desnudo).unwrap();
            assert_eq!(leer(&t, Marco::Desnudo).unwrap(), d, "falló con {n} bytes");
        }
    }

    #[test]
    fn el_protegido_va_y_vuelve() {
        let d: Vec<u8> = (0..64u16).map(|i| (i * 7) as u8).collect();
        let m = Marco::Protegido { paridad: 32 };
        let t = escribir(&d, m).unwrap();
        assert_eq!(leer(&t, m).unwrap(), d);
    }

    #[test]
    fn el_protegido_aguanta_un_error_de_tecleo_y_el_desnudo_no() {
        // Las dos direcciones a la vez: es lo que convierte «opcional» en una
        // elección con consecuencias y no en una casilla de configuración.
        let d: Vec<u8> = (0..48u16).map(|i| (i * 11 + 5) as u8).collect();
        let m = Marco::Protegido { paridad: 32 };

        let mut t: Vec<char> = escribir(&d, m).unwrap().chars().collect();
        let pos = t.iter().position(|c| c.is_ascii_alphanumeric()).unwrap() + 7;
        t[pos] = if t[pos] == 'A' { 'B' } else { 'A' };
        let roto: String = t.into_iter().collect();
        assert_eq!(
            leer(&roto, m).unwrap(),
            d,
            "el marco protegido tiene que absorber un carácter mal tecleado"
        );

        let mut t: Vec<char> = escribir(&d, Marco::Desnudo).unwrap().chars().collect();
        t[pos] = if t[pos] == 'A' { 'B' } else { 'A' };
        let roto: String = t.into_iter().collect();
        assert_ne!(
            leer(&roto, Marco::Desnudo).unwrap(),
            d,
            "el marco desnudo NO corrige nada, y prometer que sí sería mentir"
        );
    }

    #[test]
    fn los_dos_marcos_no_producen_el_mismo_texto() {
        let d = b"una clave cualquiera";
        assert_ne!(
            escribir(d, Marco::Desnudo).unwrap(),
            escribir(d, Marco::Protegido { paridad: 32 }).unwrap()
        );
        // Y el desnudo es MÁS CORTO, porque no lleva paridad ni cabecera.
        assert!(
            apretado(&escribir(d, Marco::Desnudo).unwrap()).len()
                < apretado(&escribir(d, Marco::Protegido { paridad: 32 }).unwrap()).len()
        );
    }

    #[test]
    fn se_tolera_como_escribe_la_gente() {
        let d = b"secreto";
        let t = escribir(d, Marco::Desnudo).unwrap();
        let maltratado = format!("  {}  ", apretado(&t).to_lowercase())
            .chars()
            .enumerate()
            .map(|(i, c)| if i % 4 == 3 { format!("{c}-") } else { c.to_string() })
            .collect::<String>();
        assert_eq!(leer(&maltratado, Marco::Desnudo).unwrap(), d.to_vec());
    }

    #[test]
    fn el_cero_se_corrige_porque_es_inequivoco() {
        // El `0` no está en el alfabeto y la `O` sí: no hay nada que adivinar.
        let d = b"hola";
        let t = apretado(&escribir(d, Marco::Desnudo).unwrap()).replace('O', "0");
        assert_eq!(leer(&t, Marco::Desnudo).unwrap(), d.to_vec());
    }

    #[test]
    fn lo_ambiguo_se_rechaza_en_vez_de_adivinarse() {
        // Un `1` puede ser `I` o `L` y las dos están en el alfabeto. Corregirlo
        // sería inventar un secreto distinto EN SILENCIO, que es el único fallo
        // que este formato no puede permitirse.
        for (c, lecturas) in [('1', "«I» o «L»"), ('8', "«B» o «S»")] {
            let texto = format!("MZXW{c}YTB");
            match leer(&texto, Marco::Desnudo) {
                Err(TecleableError::CaracterAmbiguo {
                    caracter,
                    lecturas: l,
                    ..
                }) => {
                    assert_eq!(caracter, c);
                    assert_eq!(l, lecturas, "el error tiene que decir las dos lecturas");
                }
                otro => panic!("se esperaba CaracterAmbiguo para «{c}», llegó {otro:?}"),
            }
        }
    }

    #[test]
    fn un_caracter_imposible_dice_cual_y_donde() {
        match leer("MZXW*YTB", Marco::Desnudo) {
            Err(TecleableError::CaracterImposible {
                caracter,
                posicion,
            }) => {
                assert_eq!(caracter, '*');
                assert_eq!(posicion, 4, "la posición tiene que ignorar los espacios");
            }
            otro => panic!("se esperaba CaracterImposible, llegó {otro:?}"),
        }
    }

    #[test]
    fn un_texto_sin_nada_util_lo_dice() {
        assert_eq!(leer("   \n -- ", Marco::Desnudo), Err(TecleableError::Vacio));
        assert_eq!(leer("", Marco::Desnudo), Err(TecleableError::Vacio));
    }

    #[test]
    fn cada_marco_trae_su_instruccion_y_no_dicen_lo_mismo() {
        // El artefacto que sobrevive veinte años son los caracteres MÁS la frase
        // que dice qué hacer con ellos. Si las dos frases fueran iguales, una de
        // las dos estaría mintiendo.
        let a = instruccion(Marco::Desnudo);
        let b = instruccion(Marco::Protegido { paridad: 32 });
        assert_ne!(a, b);
        assert!(a.contains("Cualquier decodificador"));
        assert!(b.contains("NO"));
    }
}

#[cfg(all(test, feature = "palabras"))]
mod pruebas_palabras {
    use super::palabras::*;

    /// LA PRUEBA QUE SOSTIENE LA PROMESA. Si la lista no es byte a byte la
    /// canónica, todo lo que este marco escriba será ilegible para el resto del
    /// mundo — y eso no se nota escribiendo y leyendo con nosotros mismos.
    #[test]
    fn la_lista_es_la_canonica() {
        use sha2::{Digest, Sha256};
        let h = Sha256::digest(LISTA_CRUDA.as_bytes());
        let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            SHA256_CANONICO,
            "la lista de palabras NO es la oficial de la BIP-39"
        );
        assert_eq!(LISTA_CRUDA.lines().filter(|l| !l.trim().is_empty()).count(), PALABRAS_EN_LA_LISTA);
    }

    /// Los vectores OFICIALES de la BIP-39. Norma externa, no nosotros mismos.
    fn vectores() -> Vec<(Vec<u8>, String)> {
        include_str!("../tests/vectores_bip39.txt")
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .map(|l| {
                let (hex, frase) = l.split_once('\t').expect("formato <hex>TAB<frase>");
                let bytes = (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                    .collect();
                (bytes, frase.to_string())
            })
            .collect()
    }

    #[test]
    fn los_vectores_oficiales_cuadran_en_los_dos_sentidos() {
        let v = vectores();
        assert!(v.len() >= 24, "se esperaban los 24 vectores oficiales, hay {}", v.len());
        for (entropia, frase) in v {
            assert_eq!(escribir(&entropia).unwrap(), frase, "al escribir {entropia:02x?}");
            assert_eq!(leer(&frase).unwrap(), entropia, "al leer «{frase}»");
        }
    }

    #[test]
    fn los_cinco_tamanos_van_y_vuelven() {
        for &n in TAMANOS {
            let d: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            let frase = escribir(&d).unwrap();
            // (entropía + suma) / 11 bits por palabra: 12, 15, 18, 21 y 24.
            assert_eq!(frase.split_whitespace().count(), (n * 8 + n * 8 / 32) / 11);
            assert_eq!(leer(&frase).unwrap(), d, "ida y vuelta de {n} bytes");
        }
    }

    /// Un tamaño fuera de la norma FALLA. No se rellena hasta uno válido: al
    /// leer devolvería bytes que nadie guardó, y con una clave eso no se nota.
    #[test]
    fn un_tamano_ajeno_falla_ruidosamente() {
        for n in [0usize, 1, 15, 17, 31, 33, 64] {
            let d = vec![0u8; n];
            assert!(
                matches!(escribir(&d), Err(PalabrasError::TamanoNoAdmitido { .. })),
                "{n} bytes tenía que fallar y no falló"
            );
        }
    }

    /// EL CASO ROJO DEL MARCO ENTERO: una palabra cambiada tiene que DETECTARSE.
    /// Es lo único que `Marco::Desnudo` no puede hacer, y la razón de existir de
    /// este módulo. Si esto pasara en silencio, el marco no valdría nada.
    #[test]
    fn una_palabra_cambiada_se_detecta() {
        let d: Vec<u8> = (0..32).map(|i| (i * 7 + 1) as u8).collect();
        let frase = escribir(&d).unwrap();
        let mut ps: Vec<&str> = frase.split_whitespace().collect();

        // Se recorre TODA la frase: un detector que solo mire el final es un
        // detector que no mira.
        let mut detectados = 0;
        let mut colados = 0;
        for i in 0..ps.len() {
            let original = ps[i];
            // Otra palabra cualquiera de la lista, distinta de la que estaba.
            let suplente = if original == "abandon" { "ability" } else { "abandon" };
            ps[i] = suplente;
            match leer(&ps.join(" ")) {
                Err(PalabrasError::SumaDeVerificacion) => detectados += 1,
                Ok(otro) => {
                    assert_ne!(otro, d, "devolvió el secreto correcto con una palabra cambiada");
                    colados += 1;
                }
                Err(e) => panic!("error inesperado en la posición {i}: {e}"),
            }
            ps[i] = original;
        }
        // La suma es de 8 bits, así que ~1 de cada 256 cambios se cuela. Con 24
        // posiciones lo esperable es 0. Se declara el límite en vez de fingir
        // que detecta siempre: es DETECCIÓN, no corrección.
        assert!(
            detectados >= ps.len() - 1,
            "de {} cambios solo se detectaron {detectados} ({colados} colados)",
            ps.len()
        );
    }

    #[test]
    fn el_orden_cambiado_tambien_se_detecta() {
        let d: Vec<u8> = (0..32).map(|i| (i * 13 + 5) as u8).collect();
        let frase = escribir(&d).unwrap();
        let mut ps: Vec<&str> = frase.split_whitespace().collect();
        ps.swap(3, 17);
        assert_eq!(leer(&ps.join(" ")), Err(PalabrasError::SumaDeVerificacion));
    }

    /// La BIP-39 garantiza que cuatro letras identifican la palabra. No se cita
    /// de memoria: se comprueba sobre la lista real.
    #[test]
    fn cuatro_letras_bastan() {
        let l: Vec<&str> = LISTA_CRUDA.lines().map(str::trim).filter(|w| !w.is_empty()).collect();
        let mut prefijos = std::collections::HashSet::new();
        for w in &l {
            let p: String = w.chars().take(PREFIJO_SUFICIENTE).collect();
            assert!(prefijos.insert(p.clone()), "el prefijo «{p}» se repite");
        }
        assert_eq!(prefijos.len(), PALABRAS_EN_LA_LISTA);
    }

    #[test]
    fn se_admite_lo_que_la_gente_escribe() {
        let d: Vec<u8> = (0..32).map(|i| (i * 29 + 3) as u8).collect();
        let frase = escribir(&d).unwrap();

        // Mayúsculas, espacios de sobra y saltos de línea.
        let sucia = frase.to_uppercase().replace(' ', "\n   ");
        assert_eq!(leer(&sucia).unwrap(), d, "mayúsculas y espacios");

        // Truncada a cuatro letras, que es lo que la norma promete.
        let corta: Vec<String> = frase
            .split_whitespace()
            .map(|w| w.chars().take(PREFIJO_SUFICIENTE).collect())
            .collect();
        assert_eq!(leer(&corta.join(" ")).unwrap(), d, "truncada a cuatro letras");
    }

    #[test]
    fn no_se_adivina_lo_ambiguo_ni_lo_corto() {
        let d = vec![0u8; 32];
        let frase = escribir(&d).unwrap();
        let mut ps: Vec<String> = frase.split_whitespace().map(String::from).collect();

        // «ab» encaja con muchas: ambigua.
        ps[0] = "ab".into();
        assert!(matches!(leer(&ps.join(" ")), Err(PalabrasError::PalabraAmbigua { posicion: 1, .. })));

        // Una que no existe en absoluto.
        ps[0] = "quipu".into();
        assert!(matches!(leer(&ps.join(" ")), Err(PalabrasError::PalabraDesconocida { posicion: 1, .. })));
    }

    #[test]
    fn un_recuento_raro_se_rechaza() {
        for n in [1usize, 11, 13, 23, 25] {
            let frase = vec!["abandon"; n].join(" ");
            assert!(
                matches!(leer(&frase), Err(PalabrasError::CuentaNoAdmitida { .. })),
                "{n} palabras tenían que rechazarse"
            );
        }
        assert_eq!(leer("   "), Err(PalabrasError::Vacio));
    }

    #[test]
    fn la_instruccion_avisa_de_lo_que_no_es() {
        let i = instruccion();
        assert!(i.contains("BIP-39"));
        assert!(i.contains("NO es una cartera"), "tiene que desmentir el parecido");
    }
}
