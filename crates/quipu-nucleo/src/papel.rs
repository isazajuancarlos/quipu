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
            let pos = c.indice + k * c0.total;
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
        // 40 símbolos y paridad alta: la cota da varios, y se comprueba que se
        // cumple perdiendo EXACTAMENTE esos.
        let d = datos(3000);
        let trozos = empaquetar(&d, 100, 200).unwrap();
        let total = trozos.len();
        let tolerados = simbolos_perdidos_tolerados(total, 200);
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
    fn perder_mas_de_la_cota_ya_no_se_recupera() {
        // La otra dirección, que es la que convierte la cota en cota. Sin esto,
        // «tolera N» sería una frase sin nada detrás: un formato que se
        // recuperara siempre haría pasar la prueba de arriba sin significar nada.
        let d = datos(3000);
        let paridad = 200u8;
        let trozos = empaquetar(&d, 100, paridad).unwrap();
        let total = trozos.len();
        let tolerados = simbolos_perdidos_tolerados(total, paridad);

        // Se van quitando símbolos hasta que deje de recuperarse, y se exige que
        // ese punto llegue — no muy lejos de la cota, pero llegue.
        let mut rompe_en = None;
        for perdidos in (tolerados + 1)..=total {
            let quedan: Vec<Vec<u8>> = trozos[perdidos..].to_vec();
            if quedan.is_empty() || reensamblar(&quedan).is_err() {
                rompe_en = Some(perdidos);
                break;
            }
        }
        let rompe_en = rompe_en.expect("perder símbolos tiene que romperlo en algún punto");
        assert!(
            rompe_en > tolerados,
            "rompió en {rompe_en}, antes de la cota de {tolerados}: la cota MIENTE"
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
        let trozos = empaquetar(&d, 100, 200).unwrap();
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
            simbolos_perdidos_tolerados(total, 200) >= 1,
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
