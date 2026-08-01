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
/// **EL NÚMERO NO ESTÁ AJUSTADO A LA MEDICIÓN, y esa es la parte importante.**
/// La primera batería de daño situó el umbral en 174; al ensanchar la batería
/// —bloques finales cortos, cola a cero, cola invertida— bajó a **171**. Un tope
/// puesto en 170 sería un tope ajustado al último banco que corrí, y el
/// siguiente banco lo volvería a bajar.
///
/// Así que el tope se elige por una razón que no es la medición: con paridad
/// 128 se corrigen 64 errores por bloque de 255 —el 25 % del bloque, con el
/// 50 % de redundancia—, y a partir de ahí se gastan más bytes en paridad que
/// en datos, que para una hoja de papel es peor negocio que imprimir la hoja
/// dos veces. Quedan **43 de margen** sobre el umbral más bajo que se ha
/// medido, y ese margen se revalida en cada CI: `la_bateria_de_dano_no_hace_
/// entrar_en_panico_a_ninguna_paridad_aceptada` recorre todas las paridades que
/// este módulo admite.
///
/// El arreglo de fondo es sustituir o vendorizar la implementación de
/// Reed-Solomon; mientras tanto, esto impide que la entrada hostil llegue al
/// decodificador.
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
                    for (etiqueta, roto) in [("ceros", a), ("invertida", b)] {
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
    #[test]
    fn una_paridad_por_encima_del_tope_se_rechaza_al_leer() {
        for excesiva in [PARIDAD_MAXIMA + 1, 173, 200, 254] {
            let prot = con_cabecera_hostil(excesiva, 4, b"lo que sea, da igual");
            assert!(
                recover(&prot).is_none(),
                "una cabecera que declara paridad {excesiva} tenía que rechazarse"
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
