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

/// Protege `data` con Reed-Solomon usando `parity` bytes de paridad por bloque.
pub fn protect(data: &[u8], parity: u8) -> Vec<u8> {
    let parity = parity.max(2); // mínimo para corregir 1 error
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
    // `parity` viene de la cabecera NO protegida. Debe dejar sitio para datos:
    // con parity==255 el chunk sería 0 (bloque de pura paridad) -> trabajo inútil
    // y parámetros Reed-Solomon degenerados. Exige 2 <= parity <= 254.
    if parity < 2 || 255 - (parity as usize) == 0 {
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
