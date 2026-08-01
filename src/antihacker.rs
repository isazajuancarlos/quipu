// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Antihacker: endurecimiento defensivo (defensa en profundidad).
//!
//! NO es seguridad por oscuridad: son defensas estándar y públicas que reducen
//! la superficie de ataque alrededor del cifrado.
//!
//!   - `wipe`: borrado seguro de claves/buffers sensibles (anti volcado de memoria).
//!   - `ct_eq`: comparación en tiempo constante (anti ataques de temporización).
//!
//! Políticas aplicadas en `api` (ver sección 12 del plan):
//!   - error de descifrado ÚNICO (sin oráculos que revelen qué comprobación falló);
//!   - sin salida parcial hasta que el tag AEAD valida;
//!   - coste Argon2id como antibot offline.

use std::collections::HashMap;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::cipher::NONCE_LEN;
use crate::container;

/// Borra de forma segura el contenido de `buf` (lo pone a cero sin que el
/// compilador pueda optimizar el borrado).
pub fn wipe(buf: &mut [u8]) {
    buf.zeroize();
}

/// Profundidad de pila que sobreescribe [`limpiar_pila`], en bytes.
///
/// **Es el parámetro delicado de este mecanismo, y conviene saber por qué.** Un
/// limpiador solo borra lo que alcanza: si la operación anterior gastó más pila
/// que esto, lo que quede por debajo sobrevive — y sobrevive EN SILENCIO, que es
/// la peor forma. No hay manera de medir en Rust seguro cuánta pila usó una
/// llamada (haría falta aritmética de punteros, y este crate es
/// `#![forbid(unsafe_code)]`), así que la cifra es un margen elegido, no una
/// medida.
///
/// 64 KiB: holgado frente a los marcos de una firma híbrida, y un 3 % de la pila
/// de un hilo (2 MiB por defecto; 8 MiB el principal). Si algún día una operación
/// gastara más, la prueba que lo detecta es la de `tests/residuo_memoria.rs`, no
/// el razonamiento de este comentario.
const PILA_A_LIMPIAR: usize = 64 * 1024;

/// Sobreescribe con ceros la región de pila que acaba de usar una operación con
/// material sensible.
///
/// # Por qué hace falta, y por qué `zeroize` NO lo cubre
///
/// En Rust **mover** un valor es un `memcpy`, y `Drop` solo corre en el destino
/// final. `Zeroizing` borra donde el valor **acabó**; las posiciones intermedias
/// por las que pasó al moverse quedan intactas. Una clave que se construye en la
/// pila y luego se mueve a una struct deja tantas copias como movimientos.
///
/// No es teoría: `tests/residuo_memoria.rs` midió **2 copias** de la semilla de
/// firma en memoria tras `firmar_con_comparticiones` —que la mueve dos veces, al
/// parámetro de `EnMemoria::nuevo` y al campo de la struct— en el runner del CI.
/// En la máquina de desarrollo daban **cero**, 50 corridas seguidas. Depende del
/// asignador y del compilador, así que no se puede razonar: hay que medirlo, y
/// por eso la prueba vive en el CI y no en la cabeza de nadie.
///
/// # La regla, no el caso
///
/// Toda función que materialice en la pila material sensible RECONSTRUIDO —y por
/// tanto no controlado por un `Zeroizing` que sobreviva— debe llamar a esto antes
/// de volver. No sustituye a `zeroize`: lo complementa, porque atacan cosas
/// distintas (el valor vivo frente a las copias que dejó al moverse).
///
/// # Lo que NO hace
///
/// No toca el montón —de eso se encargan `Zeroizing` y [`wipe`]— ni protege de un
/// adversario que lea la memoria MIENTRAS la operación corre. Eso es R5 en
/// `docs/THREAT_MODEL.md`, endpoint comprometido, y está fuera de alcance por
/// declaración. Esto cierra T6: la memoria leída DESPUÉS.
///
/// **Y NO PUEDE TOCAR EL MARCO DE QUIEN LA LLAMA.** Sobrescribe hacia ABAJO
/// desde el punto de la llamada, así que todo lo que viva en marcos más
/// superficiales —incluido el marco vivo del llamante— queda fuera de su
/// alcance por construcción. No es una carencia: un limpiador no puede borrar la
/// pila sobre la que está corriendo.
///
/// La consecuencia práctica, y costó media hora averiguarla: **si el llamante
/// tiene el secreto en su PROPIO marco, esto no lo borra**, y en `--release` un
/// `fill(0)` sobre esa variable puede no bastar porque el compilador deja copias
/// en otros huecos del mismo marco. Lo correcto es que el material sensible viva
/// en un marco anidado, de modo que quede por debajo del punto de limpieza.
/// `tests/residuo_memoria.rs` lo hace así desde el 2026-08-01, y hasta entonces
/// su propio canario producía un falso fallo en release que parecía un defecto
/// de esta función.
pub fn limpiar_pila() {
    let mut lienzo = [0u8; PILA_A_LIMPIAR];
    // Sin las dos barreras el optimizador tiene todo el derecho a eliminar un
    // buffer que nadie lee: el borrado tiene que ser observable para él.
    std::hint::black_box(&mut lienzo);
    lienzo.zeroize();
    std::hint::black_box(&lienzo);
}

/// Compara dos secuencias en tiempo constante (no termina antes ante el primer
/// byte distinto). Devuelve `true` si son iguales.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Busca reúso de nonce en un conjunto de contenedores de Quipu.
///
/// Devuelve los PARES `(primero, repetido)` de índices cuyos nonces coinciden —
/// no un booleano— porque quien lo corre necesita saber CUÁLES recifrar, y un
/// detector que solo dijera «hay un problema» sin señalar dónde se desactiva a
/// la semana.
///
/// # Por qué esto es una herramienta pública y no una prueba
///
/// Quipu **nunca** repite un nonce: cada uno sale del RNG del sistema en el
/// momento de cifrar. El riesgo no está en la librería sino en cómo la usa el
/// integrador —serializar mal, copiar un contenedor, restaurar un respaldo sobre
/// un cifrado nuevo—, y ese almacén Quipu no lo ve. Esta función le da al
/// integrador el detector para correrlo sobre su propio almacén (es la «vacuna»
/// que sí se abre, a diferencia del laboratorio ofensivo tras `feature = "lab"`).
///
/// # Por qué el reúso de nonce es grave y a la vez invisible
///
/// Con XChaCha20, dos mensajes bajo la misma clave y el mismo nonce comparten el
/// flujo de cifrado: su XOR entrega el XOR de los dos textos claros, **sin error
/// ni aviso**. No hay excepción que lo delate; por eso hace falta buscarlo a
/// propósito.
///
/// # Qué NO cuenta como colisión
///
/// Un blob que no parsea como contenedor de Quipu se **ignora**: no tiene nonce
/// que comparar. Se prefiere ignorarlo a inventar una colisión — un falso
/// positivo aquí manda a recifrar datos sanos.
///
/// Nonces distintos bajo claves distintas tampoco son colisión: el peligro es el
/// mismo nonce, y el nonce extendido de 192 bits hace la coincidencia por azar
/// despreciable, así que un par encontrado es casi con certeza un error de
/// manejo, no mala suerte.
pub fn nonces_repetidos(contenedores: &[impl AsRef<[u8]>]) -> Vec<(usize, usize)> {
    let mut visto: HashMap<[u8; NONCE_LEN], usize> = HashMap::new();
    let mut pares = Vec::new();
    for (i, c) in contenedores.iter().enumerate() {
        // Se parsea con el parser real del contenedor, no cortando bytes a mano:
        // así un blob ilegible cae en `Err` y se ignora, en vez de leerse un
        // «nonce» de una posición que no lo es.
        if let Ok((cabecera, _)) = container::parse(c.as_ref()) {
            match visto.get(&cabecera.nonce) {
                Some(&primero) => pares.push((primero, i)),
                None => {
                    visto.insert(cabecera.nonce, i);
                }
            }
        }
    }
    pares
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipe_zeroes_the_buffer() {
        let mut secret = [0xAAu8; 32];
        wipe(&mut secret);
        assert_eq!(secret, [0u8; 32]);
    }

    #[test]
    fn ct_eq_matches_equality() {
        assert!(ct_eq(b"clave-igual", b"clave-igual"));
        assert!(!ct_eq(b"clave-igual", b"clave-otra!"));
        assert!(!ct_eq(b"corta", b"mas-larga"));
    }

    fn opciones_baratas() -> crate::api::Options<'static> {
        use crate::kdf::KdfParams;
        crate::api::Options {
            pepper: b"",
            // KDF barata: la prueba mira el nonce, no el coste.
            kdf_params: KdfParams { mem_kib: 64, iterations: 1, parallelism: 1 },
            ..Default::default()
        }
    }

    fn corpus_sano(n: usize) -> Vec<Vec<u8>> {
        use crate::api::encode_to_blob;
        let opts = opciones_baratas();
        (0..n)
            .map(|i| encode_to_blob(format!("mensaje {i}").as_bytes(), "clave", [0u8; 8], &opts))
            .collect()
    }

    #[test]
    fn nonces_repetidos_no_inventa_sobre_contenedores_sanos() {
        // Cada contenedor toma su nonce del RNG: no debe haber colisiones. Un
        // falso positivo aquí manda a recifrar datos intactos.
        let corpus = corpus_sano(16);
        assert!(
            nonces_repetidos(&corpus).is_empty(),
            "falsos positivos sobre 16 contenedores sanos"
        );
    }

    #[test]
    fn nonces_repetidos_encuentra_el_duplicado_sembrado() {
        // El escenario real: se restaura una copia de un contenedor ya cifrado.
        // Comparte nonce con el original y hay que detectarlo.
        let mut almacen = corpus_sano(8);
        let copia = almacen[3].clone();
        almacen.push(copia); // índice 8 == copia del 3
        let choques = nonces_repetidos(&almacen);
        assert_eq!(
            choques,
            vec![(3, 8)],
            "no encontró el nonce duplicado sembrado, o inventó pares: {choques:?}"
        );
    }

    #[test]
    fn nonces_repetidos_ignora_lo_que_no_es_contenedor() {
        // Un blob ilegible no tiene nonce que comparar: se ignora, no cuenta como
        // colisión ni revienta.
        let basura: Vec<Vec<u8>> = vec![b"no soy un contenedor".to_vec(), vec![0u8; 10], Vec::new()];
        assert!(
            nonces_repetidos(&basura).is_empty(),
            "un blob que no parsea no debe producir colisiones"
        );
    }
}
