// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Corrección de errores Reed-Solomon (GF(256)) para canales ruidosos
//! (impreso/fotografiado). Añade paridad que corrige errores en posiciones
//! DESCONOCIDAS (no solo borrados), hasta `parity/2` por bloque de 255 bytes.
//!
//! Formato:
//!   [ parity(1) | data_len(4 LE) | bloques RS... ]
//!   cada bloque = chunk_de_datos (hasta 255-parity) + bytes de paridad
//!
//! La cabecera lleva SU PROPIO bloque Reed-Solomon (5 datos + 10 de paridad).
//!
//! Antes iba desnuda, y en un archivo eso era razonable: los bytes 0-4 no se
//! corrompen solos. En papel es otra cosa — una mancha en la esquina izquierda
//! de la hoja destruía el mensaje entero mientras el resto de la tira estaba
//! intacta. Un punto único de fallo en el canal que más ruido tiene.
//!
//! Se protege con su propio bloque y no replicando copias porque una mancha
//! daña bytes CONTIGUOS: tres copias seguidas mueren juntas, y repartirlas por
//! el cuerpo obligaría a saltárselas al leer los bloques. Un bloque RS propio
//! resuelve lo mismo sin tocar la disposición.

use reed_solomon::{Decoder, Encoder};

/// Cabecera: parity(1) + data_len(4).
const HEADER: usize = 5;
/// Paridad del bloque que protege la cabecera. Corrige hasta 5 bytes, que en
/// el canal de glifos es algo más de un glifo entero borrado.
const HEADER_PARITY: usize = 10;
/// Lo que ocupa la cabecera protegida.
const HEADER_BLOCK: usize = HEADER + HEADER_PARITY;

/// Cuánto ocupa la cabecera protegida, para que nadie la escriba a mano.
pub fn tamano_cabecera() -> usize {
    HEADER_BLOCK
}

/// La paridad más alta que este módulo acepta, por bloque de 255 bytes.
///
/// # Por qué existe un tope, y por qué es este número
///
/// **`reed-solomon 0.2.1` ENTRA EN PÁNICO** —no devuelve error— al decodificar
/// un bloque dañado por encima de su capacidad cuando la paridad es alta. El
/// bucle de Berlekamp-Massey de `decoder.rs` hace `push` sobre un `Polynom` de
/// array FIJO de 256 bytes sin comprobar el límite, y el desbordamiento sale
/// como `range end index 257 out of range for slice of length 256`. Es un fallo
/// del crate, no de la aritmética de aquí.
///
/// Eso lo convierte en una **caída del proceso que lee la hoja**, provocable
/// por quien fabrique el papel: la cabecera lleva la paridad y va protegida por
/// Reed-Solomon, que es un código de corrección y **no un MAC** — cualquiera
/// puede recalcularla.
///
/// # EL LÍMITE ESTÁ DERIVADO, NO MEDIDO
///
/// Primero se midió, y el número bailaba: la primera batería situó el umbral en
/// 174 y al ensancharla bajó a 171. Un tope ajustado a la última batería que uno
/// corre es un tope que la siguiente batería vuelve a bajar.
///
/// Así que se buscó la aritmética. `Decoder::correct` llama a
/// `find_error_evaluator`, que hace `synd.mul(err_loc)`, y `mul` produce
/// longitud `len₁ + len₂ − 1`:
///
/// | | |
/// |---|---|
/// | `synd.len()` | `ecc_len + 1` |
/// | `err_loc.len()` como mucho | `ecc_len / 2 + 1` |
/// | producto | `ecc_len + err_loc.len()` |
///
/// Desborda el array fijo cuando ese producto pasa de 256, o sea cuando
/// **`ecc_len > 170`**. La fórmula predice **171** como primera paridad que
/// revienta — que es exactamente lo que midió el barrido denso, y explica el
/// `257` del mensaje de pánico. El límite dejó de ser una observación y pasó a
/// ser una consecuencia.
///
/// # Por qué 128 y no 170
///
/// Porque 170 lo fija la aritmética de ESTE crate, y un tope pegado al límite se
/// rompe con cualquier cambio de la dependencia. 128 tiene **42 de margen
/// derivado**, y además se sostiene solo: con paridad 128 se corrigen 64 errores
/// por bloque de 255 —el 25 % del bloque, con el 50 % de redundancia— y por
/// encima de ahí se gastan más bytes en paridad que en datos, que para una hoja
/// es peor negocio que imprimir la hoja dos veces. La medición del portador
/// (`docs/HOJA_DE_RUTA.md` §6) usa 15 % y 30 %; nadie ha pedido más.
///
/// Lo sujetan dos bancos: `el_tope_queda_por_debajo_del_limite_de_la_aritmetica`
/// comprueba la fórmula, y `la_bateria_de_dano_no_hace_entrar_en_panico_a_
/// ninguna_paridad_aceptada` recorre las 127 paridades admitidas con 45 000
/// casos de daño.
///
/// # Por qué NO se vendoriza el crate, evaluado el 2026-08-01
///
/// `reed-solomon 0.2.1` está **abandonado desde enero de 2018** y es MIT, así que
/// vendorizar era viable. Se descartó, y conviene que el porqué esté aquí para
/// no reabrirlo:
///
/// - **No hay alternativa que sirva.** `reed-solomon-erasure`, `-simd` y
///   `-novelpoly` son códigos de BORRADO —posiciones conocidas—, y aquí hacen
///   falta posiciones DESCONOCIDAS: otro algoritmo, no otro crate.
///   `reed-solomon-32` es un fork sobre GF(32), campo inútil para bloques de
///   255, y arrastra el mismo `set_length` sin comprobar.
/// - **Lo único que compraría vendorizar es usar paridad 129–254**, que es
///   capacidad que nadie quiere: son más bytes de paridad que de datos.
/// - **Y costaría ser dueños de la aritmética de GF(256)** para cero beneficio
///   de producto.
///
/// Lo que queda en pie y hay que decir: dependemos de código sin mantenimiento
/// desde hace ocho años. No es un fallo, es un hecho de cadena de suministro, y
/// se revisa si algún día hace falta paridad por encima de 128 o si aparece otro
/// pánico DENTRO del rango aceptado.
pub const PARIDAD_MAXIMA: u8 = 128;

/// Protege `data` con Reed-Solomon usando `parity` bytes de paridad por bloque.
///
/// `parity` se ajusta al rango `2..=`[`PARIDAD_MAXIMA`]. El extremo bajo ya se
/// ajustaba desde siempre (con menos de 2 no se corrige ni un error); el alto
/// es la defensa descrita en [`PARIDAD_MAXIMA`].
///
/// AJUSTA EN SILENCIO PORQUE NO TIENE CÓMO HABLAR: devuelve `Vec<u8>`, no
/// `Result`. Quien necesite que se le avise debe entrar por
/// `papel::empaquetar`, que **rechaza** la paridad excesiva en vez de
/// recortarla — es la capa que sí puede informar, y es la que usa la gente.
pub fn protect(data: &[u8], parity: u8) -> Vec<u8> {
    let parity = parity.clamp(2, PARIDAD_MAXIMA);
    let chunk = 255 - parity as usize;
    let encoder = Encoder::new(parity as usize);

    let mut cabecera = Vec::with_capacity(HEADER);
    cabecera.push(parity);
    cabecera.extend_from_slice(&(data.len() as u32).to_le_bytes());

    let mut out = Vec::with_capacity(HEADER_BLOCK + data.len() + parity as usize);
    out.extend_from_slice(&Encoder::new(HEADER_PARITY).encode(&cabecera));
    for block in data.chunks(chunk) {
        let encoded = encoder.encode(block);
        out.extend_from_slice(&encoded); // chunk de datos + paridad
    }
    out
}

/// Recupera los datos corrigiendo errores. Devuelve `None` si hay demasiados
/// errores o la cabecera está corrupta.
pub fn recover(protected: &[u8]) -> Option<Vec<u8>> {
    if protected.len() < HEADER_BLOCK {
        return None;
    }
    // La cabecera viene con su propio bloque RS: se corrige antes de creerle
    // nada. Si ni siquiera eso se puede reparar, no hay por dónde empezar.
    let cabecera = Decoder::new(HEADER_PARITY)
        .correct(&protected[..HEADER_BLOCK], None)
        .ok()?;
    let cabecera = cabecera.data();
    let parity = cabecera[0];
    // `parity` viene de la cabecera, y la cabecera la puede fabricar CUALQUIERA:
    // su bloque Reed-Solomon corrige, no autentica. Así que este byte es entrada
    // hostil y se valida como tal.
    //
    //   - por abajo: con menos de 2 no se corrige ni un error.
    //   - por arriba: `PARIDAD_MAXIMA`, o el decodificador de `reed-solomon`
    //     puede ENTRAR EN PÁNICO con un bloque dañado y tumbar al proceso que
    //     está leyendo la hoja. Ver el porqué en `PARIDAD_MAXIMA`.
    //
    // Rechazar aquí es lo que impide que la entrada hostil llegue al decoder.
    if !(2..=PARIDAD_MAXIMA).contains(&parity) {
        return None;
    }
    let data_len = u32::from_le_bytes(cabecera[1..HEADER].try_into().ok()?) as usize;
    // Anti-DoS: un data_len mayor que los bytes disponibles es imposible y
    // evitaría una asignación gigante (with_capacity con un u32 malicioso).
    if data_len > protected.len() {
        return None;
    }
    let chunk = 255 - parity as usize;
    let decoder = Decoder::new(parity as usize);

    let mut body = &protected[HEADER_BLOCK..];
    let mut out = Vec::with_capacity(data_len);
    let mut remaining = data_len;
    while remaining > 0 {
        let data_in_block = remaining.min(chunk);
        let block_len = data_in_block + parity as usize;
        if body.len() < block_len {
            return None;
        }
        let corrected = decoder.correct(&body[..block_len], None).ok()?;
        out.extend_from_slice(&corrected.data()[..data_in_block]);
        body = &body[block_len..];
        remaining -= data_in_block;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_without_errors() {
        let data = b"datos a proteger con correccion de errores";
        let prot = protect(data, 8);
        assert_eq!(recover(&prot).unwrap(), data);
    }

    #[test]
    fn round_trips_large_data_across_blocks() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let prot = protect(&data, 8);
        assert_eq!(recover(&prot).unwrap(), data);
    }

    #[test]
    fn corrects_errors_within_capacity() {
        let data = b"mensaje que sufrira corrupcion en el canal";
        let mut prot = protect(data, 8); // corrige hasta 4 errores/bloque
        // Corrompe 4 bytes dentro del primer bloque (tras la cabecera de 5).
        for k in 0..4 {
            prot[HEADER + k] ^= 0xFF;
        }
        assert_eq!(recover(&prot).unwrap(), data);
    }

    /// Arma un buffer con una cabecera BIEN FORMADA y valores hostiles.
    ///
    /// Desde que la cabecera lleva su propio bloque Reed-Solomon, escribir
    /// `prot[0]` a mano ya no inyecta nada: la corrección lo repara. Y eso
    /// haría que estas pruebas pasaran sin comprobar nada — el peor desenlace
    /// para una prueba de seguridad.
    ///
    /// Un atacante real sí puede recalcular la cabecera, así que el límite hay
    /// que probarlo contra una cabecera válida que diga cosas imposibles. Es
    /// una prueba más fuerte que la que había.
    fn con_cabecera_hostil(parity: u8, data_len: u32, cuerpo: &[u8]) -> Vec<u8> {
        let mut cabecera = Vec::with_capacity(HEADER);
        cabecera.push(parity);
        cabecera.extend_from_slice(&data_len.to_le_bytes());
        let mut out = Encoder::new(HEADER_PARITY).encode(&cabecera).to_vec();
        out.extend_from_slice(cuerpo);
        out
    }

    #[test]
    fn fails_when_too_many_errors() {
        let data = b"corto";
        let mut prot = protect(data, 4); // corrige hasta 2 errores
        // Corrompe 5 bytes DEL CUERPO -> excede la capacidad. El desplazamiento
        // sale de la constante y no de un 5 escrito a mano: cuando la cabecera
        // pasó de 5 bytes desnudos a un bloque de 15, un offset fijo metía el
        // daño DENTRO de la cabecera, que lo reparaba, y la prueba fallaba por
        // un motivo que no era el que mide.
        for k in 0..5 {
            prot[HEADER_BLOCK + k] ^= 0xFF;
        }
        assert!(recover(&prot).is_none());
    }

    #[test]
    fn round_trips_empty() {
        let prot = protect(b"", 8);
        assert_eq!(recover(&prot).unwrap(), b"");
    }

    #[test]
    fn rejects_malicious_data_len_without_oom() {
        // data_len = u32::MAX en un buffer minúsculo -> None, sin reservar 4 GiB.
        let prot = con_cabecera_hostil(8, u32::MAX, b"unos pocos bytes");
        assert!(recover(&prot).is_none());
    }

    /// LA SALVAGUARDA DE `PARIDAD_MAXIMA`, revalidada en cada corrida.
    ///
    /// Recorre TODAS las paridades que el módulo acepta y, para cada una, un
    /// banco de daño que incluye el peor caso conocido —bloque final corto y
    /// corrupción por encima de la capacidad de corrección—. Ninguna puede
    /// entrar en pánico.
    ///
    /// No comprueba que 129 SÍ reviente, a propósito: eso sería fijar una
    /// prueba a un fallo de una dependencia, y si algún día lo arreglan la
    /// prueba se pondría roja sin que nada nuestro esté mal. Lo que se afirma
    /// es la propiedad que nos importa: **lo que aceptamos, no tumba a nadie.**
    #[test]
    fn la_bateria_de_dano_no_hace_entrar_en_panico_a_ninguna_paridad_aceptada() {
        let anterior = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));

        let mut casos = 0usize;
        let mut panicos = Vec::new();
        for parity in 2..=PARIDAD_MAXIMA {
            let chunk = 255 - parity as usize;
            // Tamaños que dejan el ÚLTIMO bloque corto, que es donde apareció.
            for largo in [1usize, 2, 5, 17, chunk / 2, chunk - 1, chunk, chunk + 1, chunk * 2 + 3] {
                if largo == 0 {
                    continue;
                }
                let d = vec![0x5Au8; largo];
                let prot = protect(&d, parity);
                for corte in [
                    HEADER_BLOCK,
                    prot.len() / 4,
                    prot.len() / 2,
                    prot.len() * 3 / 4,
                    prot.len().saturating_sub(2),
                ] {
                    if corte >= prot.len() {
                        continue;
                    }
                    // Cola a cero: el símbolo que no se pudo leer.
                    let mut a = prot.clone();
                    a[corte..].fill(0);
                    // Cola invertida: la mancha de tóner.
                    let mut b = prot.clone();
                    for x in b[corte..].iter_mut() {
                        *x ^= 0xFF;
                    }
                    // RÁFAGA EN EL MEDIO, con la cola INTACTA. Rellenar la cola
                    // produce recuentos de error masivos que el decodificador
                    // rechaza ANTES de llegar a Berlekamp-Massey; el
                    // desbordamiento vive justo POR ENCIMA de la capacidad, no
                    // muy por encima. Sin este patrón la batería medía la parte
                    // fácil.
                    let mut c = prot.clone();
                    for j in 0..(parity as usize / 2) + 1 {
                        let pos = corte + j;
                        if pos < c.len() {
                            c[pos] ^= 0xFF;
                        }
                    }
                    // El otro filo: capacidad + 3, esparcido.
                    let mut d2 = prot.clone();
                    for j in 0..(parity as usize / 2) + 3 {
                        let pos = corte + j * 2;
                        if pos < d2.len() {
                            d2[pos] ^= 0xA5;
                        }
                    }
                    // TRUNCADO en vez de sobrescrito: otro modo de fallo entero.
                    let e = prot[..corte.max(HEADER_BLOCK)].to_vec();

                    for (etiqueta, roto) in [
                        ("ceros", a),
                        ("invertida", b),
                        ("rafaga-capacidad+1", c),
                        ("rafaga-capacidad+3", d2),
                        ("truncado", e),
                    ] {
                        casos += 1;
                        if std::panic::catch_unwind(|| recover(&roto)).is_err() {
                            panicos.push(format!(
                                "paridad {parity}, largo {largo}, corte {corte} ({etiqueta})"
                            ));
                        }
                    }
                }
            }
        }
        std::panic::set_hook(anterior);

        // CUERPOS QUE NO SALEN DE `protect()`. El modelo de amenaza declarado es
        // «quien fabrique el papel», y ese elige TODOS los bytes. Una batería
        // cuyos cuerpos vengan siempre de nuestro propio codificador prueba lo
        // que nosotros producimos, no lo que va a llegar. `con_cabecera_hostil`
        // ya vivía en este módulo y la batería no lo usaba.
        let anterior = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        for parity in [2u8, 17, 64, PARIDAD_MAXIMA] {
            let chunk = 255 - parity as usize;
            for patron in [0x00u8, 0xFF, 0x5A, 0xA5] {
                for largo_cuerpo in [1usize, chunk, chunk + parity as usize, 255, 600] {
                    let cuerpo = vec![patron; largo_cuerpo];
                    for declarado in [1u32, chunk as u32, 255, 1000] {
                        let prot = con_cabecera_hostil(parity, declarado, &cuerpo);
                        casos += 1;
                        if std::panic::catch_unwind(|| recover(&prot)).is_err() {
                            panicos.push(format!(
                                "cuerpo AJENO: paridad {parity}, patron {patron:#04x}, \
                                 cuerpo {largo_cuerpo}, declarado {declarado}"
                            ));
                        }
                    }
                }
            }
        }
        std::panic::set_hook(anterior);

        assert!(casos > 5_000, "el banco solo probó {casos} casos");
        assert!(
            panicos.is_empty(),
            "{} de {casos} paridades ACEPTADAS entran en pánico — el tope de \
             PARIDAD_MAXIMA ya no protege. Primeros: {:?}",
            panicos.len(),
            &panicos[..panicos.len().min(5)]
        );
    }

    /// Una paridad por encima del tope no se recorta en silencio al leer: se
    /// RECHAZA. Es lo que impide que la entrada hostil llegue al decodificador.
    /// EL TOPE NO SE PUEDE SUBIR POR ENCIMA DE LO QUE LA ARITMÉTICA PERMITE.
    ///
    /// Codifica la derivación del encabezado de [`PARIDAD_MAXIMA`], que es lo
    /// que convirtió un umbral MEDIDO —que bailaba entre 174 y 171 según la
    /// batería— en uno DEDUCIDO. `find_error_evaluator` hace `synd.mul(err_loc)`
    /// y `mul` produce `len₁ + len₂ − 1`, sobre un array fijo de 256:
    ///
    ///     synd.len()    = ecc_len + 1
    ///     err_loc.len() ≤ ecc_len / 2 + 1
    ///     producto      = ecc_len + err_loc.len()   →   desborda si > 256
    ///
    /// NO comprueba que 171 reviente de verdad, y es a propósito: eso sería
    /// atar una prueba nuestra a un fallo AJENO, y el día que lo arreglen se
    /// pondría roja sin que nada nuestro esté mal. Lo que afirma es lo único
    /// que depende de nosotros — **que nuestro tope queda por debajo del
    /// límite**—, y eso sigue siendo cierto lo arreglen o no.
    ///
    /// Si alguien sube `PARIDAD_MAXIMA` sin mirar esto, aquí se entera.
    #[test]
    fn el_tope_queda_por_debajo_del_limite_de_la_aritmetica() {
        /// El array fijo de `Polynom` en `reed-solomon 0.2.1`.
        const MAX_POLINOMIO: usize = 256;

        let cabe = |ecc_len: usize| -> bool {
            let synd = ecc_len + 1;
            let err_loc_max = ecc_len / 2 + 1;
            synd + err_loc_max - 1 <= MAX_POLINOMIO
        };

        let limite = (2..=254usize)
            .filter(|&p| cabe(p))
            .max()
            .expect("alguna paridad tiene que caber");

        assert_eq!(
            limite, 170,
            "la derivación cambió: el límite de la aritmética ya no es 170. \
             Revisa el encabezado de PARIDAD_MAXIMA antes de tocar nada"
        );
        assert!(
            (PARIDAD_MAXIMA as usize) < limite,
            "PARIDAD_MAXIMA ({PARIDAD_MAXIMA}) llega al límite de la aritmética \
             ({limite}): sin margen, cualquier cambio de la dependencia lo rompe"
        );
        // Y que el margen no se quede en nada por un descuido.
        assert!(
            limite - (PARIDAD_MAXIMA as usize) >= 32,
            "el margen bajó a {}: era 42 y se eligió para que un cambio de la \
             dependencia no lo consuma entero",
            limite - PARIDAD_MAXIMA as usize
        );
    }

    /// Una paridad por encima del tope se RECHAZA al leer.
    ///
    /// ESTA PRUEBA NO DISCRIMINABA, y lo halló una auditoría independiente el
    /// mismo día que se escribió. El cuerpo era `b"lo que sea, da igual"`, 20
    /// bytes, y con paridad ≥ 129 el bloque mide `4 + paridad ≥ 133`: `recover`
    /// salía por `if body.len() < block_len` **antes** de mirar la paridad. Con
    /// el tope quitado a propósito, la suite entera seguía verde.
    ///
    /// Es la cascada de siempre —la primera capa se lo come todo— y la lección
    /// es que una prueba de una comprobación hay que fijarla a SU capa: darle un
    /// cuerpo VÁLIDO y lo bastante largo para que la comprobación de longitud lo
    /// deje pasar y el tope sea lo único que pueda rechazarlo. Reverificado con
    /// el veneno: sin tope, esta prueba se pone roja.
    #[test]
    fn una_paridad_por_encima_del_tope_se_rechaza_al_leer() {
        for excesiva in [PARIDAD_MAXIMA + 1, 173, 200, 254] {
            let chunk = 255 - excesiva as usize;
            let datos = vec![0x5Au8; chunk];
            // Un bloque Reed-Solomon REAL de esa paridad: pasa la comprobación
            // de longitud, así que lo único que puede rechazarlo es el tope.
            let cuerpo = Encoder::new(excesiva as usize).encode(&datos).to_vec();
            let prot = con_cabecera_hostil(excesiva, chunk as u32, &cuerpo);
            assert!(
                prot.len() >= HEADER_BLOCK + chunk + excesiva as usize,
                "el cuerpo de la prueba no llega: la comprobación de longitud lo \
                 rechazaría antes que el tope y esto no mediría nada"
            );
            assert!(
                recover(&prot).is_none(),
                "una cabecera que declara paridad {excesiva} llegó al decodificador"
            );
        }
        // Y el borde justo por debajo SÍ se acepta, o el tope estaría de más.
        let sana = protect(b"hola", PARIDAD_MAXIMA);
        assert_eq!(recover(&sana).unwrap(), b"hola");
    }

    /// `protect` recorta por arriba, y lo que escribe en la cabecera es lo
    /// recortado — o `recover` leería una paridad que no se usó.
    #[test]
    fn protect_recorta_y_la_cabecera_dice_la_verdad() {
        for pedida in [PARIDAD_MAXIMA + 1, 200, 255] {
            let prot = protect(b"contenido", pedida);
            let cab = Decoder::new(HEADER_PARITY)
                .correct(&prot[..HEADER_BLOCK], None)
                .expect("la cabecera tiene que leerse");
            assert_eq!(
                cab.data()[0],
                PARIDAD_MAXIMA,
                "pidiendo {pedida} la cabecera tiene que declarar el recorte"
            );
            assert_eq!(recover(&prot).unwrap(), b"contenido");
        }
    }

    #[test]
    fn rejects_degenerate_parity_byte() {
        // parity==255 -> chunk==0: bloques de pura paridad y bucle inútil.
        let prot = con_cabecera_hostil(255, 4, b"unos pocos bytes");
        assert!(recover(&prot).is_none());

        // parity==0 y 1 tampoco: no dejan sitio para corregir ni un error.
        for degenerado in [0u8, 1] {
            let p = con_cabecera_hostil(degenerado, 4, b"unos pocos bytes");
            assert!(recover(&p).is_none(), "parity={degenerado} debería rechazarse");
        }

        // parity==254 (chunk==1) es límite pero legible: no debe entrar en
        // pánico. Devuelve None por longitudes inconsistentes.
        let p2 = con_cabecera_hostil(254, 4, b"unos pocos bytes");
        let _ = recover(&p2);
    }

    #[test]
    fn la_cabecera_hostil_es_valida_o_la_prueba_no_prueba_nada() {
        // Que discrimine: si `con_cabecera_hostil` produjera una cabecera
        // ilegible, las tres de arriba pasarían por el motivo equivocado —
        // rechazadas por corrupta, no por sus valores.
        let sana = con_cabecera_hostil(8, 4, &protect(b"hola", 8)[HEADER_BLOCK..]);
        assert_eq!(recover(&sana).unwrap(), b"hola");
    }
}
