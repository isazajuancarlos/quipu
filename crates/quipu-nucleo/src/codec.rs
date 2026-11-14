// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

//! Codec base-N: convierte una secuencia de bytes en una secuencia de índices
//! de símbolo (0..N) y viceversa, de forma totalmente reversible.
//!
//! El "valor binario" de un símbolo es su índice (codificación posicional): el
//! codebook (capa superior) solo traduce índice -> identidad de símbolo.
//!
//! Para preservar bytes cero a la izquierda y la entrada vacía, se antepone un
//! marcador 0x01 antes de interpretar los bytes como un entero grande.

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{ToPrimitive, Zero};

/// El mayor `k` tal que `n^k` cabe en un `u64`, junto con ese `n^k`.
///
/// Es el tamaño del BLOQUE: `k` dígitos base `n` caben en una palabra de
/// máquina, así que un bloque se desmenuza con aritmética de `u64`, sin tocar
/// el entero grande. En la base 94 por defecto, `k = 9`.
fn paso_maximo(n: u64) -> (u64, u32) {
    let mut paso = n;
    let mut k = 1;
    while let Some(p) = paso.checked_mul(n) {
        paso = p;
        k += 1;
    }
    (paso, k)
}

// ===========================================================================
// POR QUÉ ESTO NO ES UN BUCLE DE DIVISIONES
// ===========================================================================
//
// Convertir de base es dividir repetidamente. La forma obvia —dividir el
// entero grande por `n^k` una y otra vez— es CUADRÁTICA: cada división de un
// número de `m` limbos cuesta O(m) y hay O(m/k) divisiones.
//
// Esa era la implementación hasta el 2026-08-16, y sacar `k = 9` dígitos por
// pasada en vez de uno **divide la constante por 9 y deja el orden intacto**.
// El comentario que lo explicaba se leía como si hubiera resuelto el problema;
// no lo había resuelto. Medido entonces: cada duplicación del tamaño
// multiplicaba el tiempo por 4,0 exacto y 512 KiB costaban **50,7 s**.
//
// La salida es clásica: **dividir y vencer**. En vez de arrancar bloques por un
// extremo, se parte el número por la mitad —dividiéndolo por `paso^(2^i)`, que
// tiene la mitad de los dígitos— y se recurre sobre las dos mitades. El árbol
// tiene log(m) niveles y en cada uno el trabajo total es una multiplicación
// grande, así que el coste pasa de O(m²) a O(M(m)·log m).
//
// **Esto solo compensa si la división de la librería es subcuadrática**, y hay
// que comprobarlo antes de escribirlo: con división escolar, `T(m) = 2·T(m/2) +
// O(m²)` sigue siendo cuadrático y con PEOR constante que el bucle. `num-bigint`
// trae Karatsuba y Toom-3 para multiplicar y **Burnikel-Ziegler** para dividir
// (umbral: 64 limbos), o sea que sí compensa. Si algún día se cambia de librería
// de enteros grandes, esta es la propiedad que hay que volver a verificar.
//
// Es la misma estructura que `to_radix_digits_le_divide_and_conquer` de
// `num-bigint`, que no se puede reutilizar porque su API pública de radix se
// limita a bases ≤ 256 y aquí la base llega a `u32`.
//
// El precio es memoria: la tabla de potencias `paso^(2^i)` suma
// aproximadamente el tamaño del propio valor, y la recursión mantiene viva una
// rama, que suma otro tanto. Por eso los mensajes pequeños siguen yendo por el
// bucle de siempre, que no reserva nada.
//
// Y un precio que no es memoria: **el árbol tiene atajos que dependen del
// VALOR** —`a_digitos_partiendo` se salta un subárbol entero si vale cero, y
// `de_limbos` igual—, donde el bucle y el esquema de Horner no tenían ninguno.
// El tiempo pasa a depender del contenido. No es una fuga: lo que atraviesa
// este códec es ciphertext AEAD —indistinguible de aleatorio, así que un
// subárbol nulo exigiría decenas de bits consecutivos en cero— o, en los modos
// FIRMADOS SIN CIFRAR, el texto plano que el propio artefacto publica. Se
// declara porque es un cambio de propiedad del módulo y `quipu-cnsa` comparte
// este códec.

/// Por debajo de este número de limbos, el bucle lineal gana: la tabla de
/// potencias y las divisiones balanceadas no amortizan su coste fijo.
/// El valor es el mismo que usa `num-bigint` internamente para la misma
/// decisión.
const LIMBOS_PARA_DIVIDIR_Y_VENCER: u64 = 32;

/// Bits por limbo de `num-bigint` en las plataformas que soportamos.
const BITS_POR_LIMBO: u64 = 64;

/// Si un valor de `bits` bits merece el árbol en vez del bucle.
///
/// Está aparte para que las pruebas puedan preguntar POR QUÉ CAMINO va a ir una
/// entrada concreta, en vez de suponerlo. Sin eso, un banco que solo usa
/// mensajes cortos sale verde con el árbol roto — y con el árbol borrado.
fn vale_la_pena_partir(bits: u64) -> bool {
    bits.div_ceil(BITS_POR_LIMBO) >= LIMBOS_PARA_DIVIDIR_Y_VENCER
}

/// Mete en `out` los `k` dígitos de un bloque, en orden little-endian.
///
/// Siempre `k` dígitos, ceros de relleno incluidos: quien llama es el que sabe
/// si este bloque es el más significativo, y esa decisión no puede tomarse
/// aquí.
fn empujar_bloque(mut resto: u64, k: u32, n: u64, out: &mut Vec<u32>) {
    for _ in 0..k {
        out.push((resto % n) as u32);
        resto /= n;
    }
}

/// Escribe EXACTAMENTE `bloques * k` dígitos little-endian, rellenando con
/// ceros por arriba. Es **la hoja del árbol, y solo eso**: los mensajes
/// pequeños llevan su propio bucle dentro de `encode_base_n` y no pasan por
/// aquí. (La primera versión de esta línea decía que sí, y despistaba justo a
/// quien fuera a razonar sobre el alcance del `assert!` de abajo.)
///
/// # Pánico
///
/// Si `value >= paso^bloques`, o sea si quien llama pidió menos sitio del que
/// el valor necesita. Es un fallo de programación, no de datos: se prefiere el
/// pánico a escribir un número truncado, que sería un dato falso silencioso.
fn a_digitos_con_relleno(
    mut value: BigUint,
    bloques: usize,
    paso: &BigUint,
    k: u32,
    n: u64,
    out: &mut Vec<u32>,
) {
    let objetivo = out.len() + bloques * k as usize;
    while !value.is_zero() {
        let (cociente, resto) = value.div_rem(paso);
        let resto = resto.to_u64().expect("el resto es menor que n^k, que cabe en u64");
        empujar_bloque(resto, k, n, out);
        value = cociente;
    }
    assert!(
        out.len() <= objetivo,
        "el valor no cabe en {bloques} bloques: la recursión pidió mal el tamaño"
    );
    out.resize(objetivo, 0);
}

/// La rama del árbol. Escribe exactamente `2^nivel * k` dígitos little-endian.
///
/// `pot[i] = paso^(2^i)`, así que partir por `pot[nivel - 1]` deja las dos
/// mitades con `2^(nivel-1)` bloques cada una.
fn a_digitos_partiendo(
    value: BigUint,
    nivel: usize,
    pot: &[BigUint],
    paso: &BigUint,
    k: u32,
    n: u64,
    out: &mut Vec<u32>,
) {
    // Una rama entera a cero no se divide: se rellena. Pasa siempre en la parte
    // alta, porque `2^nivel` bloques es una cota superior y sobra sitio.
    if nivel == 0 || value.is_zero() {
        a_digitos_con_relleno(value, 1usize << nivel, paso, k, n, out);
        return;
    }
    let (alto, bajo) = value.div_rem(&pot[nivel - 1]);
    // Little-endian: la mitad BAJA va primero.
    a_digitos_partiendo(bajo, nivel - 1, pot, paso, k, n, out);
    a_digitos_partiendo(alto, nivel - 1, pot, paso, k, n, out);
}

/// Tabla `pot[i] = paso^(2^i)`, tan alta como haga falta para que
/// `pot.last()^2 > value`.
///
/// Devuelve la tabla; el nivel de arranque de la recursión es `pot.len()`, que
/// es el exponente `t` tal que `value < paso^(2^t)`.
///
/// La condición de parada —el último elemento pasa de la mitad de los limbos
/// del valor— es la de `num-bigint`, y garantiza lo que hace falta: si
/// `|pot| > |value|/2 + 1` limbos, entonces `|pot²| >= 2|pot| - 1 > |value|`,
/// luego `pot² > value`. Cortar ahí y no un nivel más arriba es lo que mantiene
/// la tabla en ~1× el tamaño del valor en vez de ~4×.
fn tabla_de_potencias(paso: &BigUint, value: &BigUint) -> Vec<BigUint> {
    let limbos_valor = value.bits().div_ceil(BITS_POR_LIMBO);
    let mut pot = vec![paso.clone()];
    loop {
        let ultimo = pot.last().expect("la tabla nunca está vacía");
        if ultimo.bits().div_ceil(BITS_POR_LIMBO) > limbos_valor / 2 + 1 {
            break;
        }
        let cuadrado = ultimo * ultimo;
        pot.push(cuadrado);
    }
    pot
}

/// Codifica `data` a una secuencia de índices en base `n` (orden big-endian:
/// el dígito más significativo primero).
///
/// Coste O(M(m)·log m) en el tamaño de la entrada; ver el bloque de comentarios
/// de arriba. El banco que lo mide es
/// `crates/quipu-nucleo/tests/escala_del_codec.rs`.
///
/// # Pánico
///
/// Con `n < 2`. Una base de 0 o 1 no representa nada, y la versión anterior de
/// esta función se quedaba dando vueltas para siempre en vez de decirlo
/// (directiva 20: ante un dato imposible, fallar de forma ruidosa).
pub fn encode_base_n(data: &[u8], n: u32) -> Vec<u32> {
    assert!(n >= 2, "una base de {n} no codifica nada: se exige n >= 2");

    // Marcador 0x01 al frente: preserva ceros a la izquierda y la entrada vacía.
    // Además garantiza `value >= 1`, de donde sale que siempre queda al menos un
    // dígito distinto de cero tras quitar el relleno.
    let mut buf = Vec::with_capacity(data.len() + 1);
    buf.push(1u8);
    buf.extend_from_slice(data);

    let n = u64::from(n);
    let (paso, k) = paso_maximo(n);
    let paso_grande = BigUint::from(paso);

    let value = BigUint::from_bytes_be(&buf);

    let mut digits = Vec::new();
    if !vale_la_pena_partir(value.bits()) {
        // Mensajes pequeños: el bucle de siempre, sin reservar tabla. No se
        // rellena por arriba porque aquí no hay nadie esperando un ancho fijo.
        let mut value = value;
        while value >= paso_grande {
            let (cociente, resto) = value.div_rem(&paso_grande);
            let resto = resto.to_u64().expect("el resto es menor que n^k, que cabe en u64");
            empujar_bloque(resto, k, n, &mut digits);
            value = cociente;
        }
        let mut resto = value.to_u64().expect("value < n^k, que cabe en u64");
        while !resto.is_zero() {
            digits.push((resto % n) as u32);
            resto /= n;
        }
    } else {
        let pot = tabla_de_potencias(&paso_grande, &value);
        let nivel = pot.len();
        a_digitos_partiendo(value, nivel, &pot, &paso_grande, k, n, &mut digits);
        // El ancho del árbol es una cota superior: sobran ceros por arriba, que
        // en little-endian están al final.
        while digits.last() == Some(&0) {
            digits.pop();
        }
    }

    digits.reverse(); // little-endian -> big-endian
    digits
}

/// Junta los limbos base `paso` —little-endian, `2^nivel` de ellos— en un solo
/// entero, por el mismo árbol balanceado que usa la codificación.
fn de_limbos(limbos: &[u64], nivel: usize, pot: &[BigUint]) -> BigUint {
    if nivel == 0 {
        return BigUint::from(limbos[0]);
    }
    // La mitad alta suele ser relleno: reconocerlo ahorra el subárbol entero.
    if limbos.iter().all(|l| *l == 0) {
        return BigUint::zero();
    }
    let mitad = 1usize << (nivel - 1);
    let bajo = de_limbos(&limbos[..mitad], nivel - 1, pot);
    let alto = de_limbos(&limbos[mitad..], nivel - 1, pot);
    alto * &pot[nivel - 1] + bajo
}

/// Operación inversa de [`encode_base_n`].
///
/// Mismo coste O(M(m)·log m) y misma estructura: los dígitos se agrupan en
/// bloques de `k` que caben en un `u64` y se combinan por un árbol balanceado,
/// en vez de por el esquema de Horner, que es cuadrático.
pub fn decode_base_n(indices: &[u32], n: u32) -> Vec<u8> {
    // MISMA EXIGENCIA QUE AL CODIFICAR, y aquí es una REGRESIÓN que hay que
    // cerrar, no una simetría estética.
    //
    // El `decode_base_n` de antes no llamaba a `paso_maximo` y con `n < 2`
    // devolvía tan tranquilo. El de ahora sí la llama, y `paso_maximo(1)` **no
    // termina**: multiplica por 1 para siempre —en release el `k: u32` da la
    // vuelta en silencio—. O sea que la reescritura convirtió un valor
    // absurdo-pero-inocuo en un cuelgue, para cualquier tercero que llame al
    // crate directamente. No es alcanzable desde `api` —`Dictionary::new`
    // rechaza menos de dos símbolos— pero `quipu-nucleo` se publica aparte.
    // Lo cazó la revisión de seguridad del 2026-08-16.
    assert!(n >= 2, "una base de {n} no descodifica nada: se exige n >= 2");

    let base = BigUint::from(n);
    let n64 = u64::from(n);
    let (paso, k) = paso_maximo(n64);

    // Horner, el camino de siempre. Se usa para entradas pequeñas —donde gana— y
    // como salida de emergencia si algún dígito viene fuera del alfabeto: ahí un
    // bloque puede no caber en un `u64`, y truncarlo sería inventar un valor.
    // No puede pasar con dígitos legítimos (`d < n` implica bloque `< n^k`), así
    // que esta rama solo la alcanza una entrada mal formada.
    let horner = || {
        let mut value = BigUint::zero();
        for &d in indices {
            value = value * &base + BigUint::from(d);
        }
        value
    };

    // Un bloque de `k` dígitos es un limbo largo: el mismo umbral, contado en la
    // moneda de la entrada que toca.
    let bloques = indices.len().div_ceil(k as usize) as u64;
    let value = if !vale_la_pena_partir(bloques * BITS_POR_LIMBO) {
        horner()
    } else {
        match a_limbos(indices, n64, k) {
            None => horner(),
            Some(mut limbos) => {
                let ancho = limbos.len().next_power_of_two();
                limbos.resize(ancho, 0); // relleno por arriba: no cambia el valor
                let nivel = ancho.trailing_zeros() as usize;

                let paso_grande = BigUint::from(paso);
                let mut pot = Vec::with_capacity(nivel);
                if nivel > 0 {
                    pot.push(paso_grande);
                    for i in 1..nivel {
                        let cuadrado = &pot[i - 1] * &pot[i - 1];
                        pot.push(cuadrado);
                    }
                }
                de_limbos(&limbos, nivel, &pot)
            }
        }
    };

    let bytes = value.to_bytes_be();
    // Quita el marcador 0x01 inicial.
    bytes[1..].to_vec()
}

/// Agrupa los dígitos —de menos a más significativo— en limbos base `n^k`.
///
/// Devuelve `None` si algún bloque se sale de un `u64`.
///
/// **OJO A LO QUE ESTO NO DICE**, corregido tras la revisión del 2026-08-16: un
/// dígito fuera del alfabeto NO implica desbordar. En base 94, `paso = 94^9 ≈
/// 5,7·10¹⁷` contra `u64::MAX ≈ 1,8·10¹⁹`, así que un dígito 94 o 95 cabe de
/// sobra: se devuelve `Some` y el limbo resultante queda **≥ paso**, rompiendo
/// la invariante implícita «cada limbo < paso».
///
/// El resultado sigue siendo exacto —`de_limbos` calcula `Σ limbo_i · paso^i` y
/// `BigUint` propaga el acarreo solo, sin importar que un sumando se pase— y
/// está comprobado con dígitos apenas ilegales en cada posición. Se escribe
/// porque la versión anterior de este comentario decía lo contrario, y quien lo
/// leyera podría apoyarse en una invariante que no se cumple.
fn a_limbos(indices: &[u32], n: u64, k: u32) -> Option<Vec<u64>> {
    let mut limbos = Vec::with_capacity(indices.len().div_ceil(k as usize));
    let mut fin = indices.len();
    while fin > 0 {
        let inicio = fin.saturating_sub(k as usize);
        let mut acumulado = 0u64;
        for &d in &indices[inicio..fin] {
            acumulado = acumulado.checked_mul(n)?.checked_add(u64::from(d))?;
        }
        limbos.push(acumulado);
        fin = inicio;
    }
    Some(limbos)
}

// ===========================================================================
// CODIFICACIÓN POR GRUPOS, PARA QUE EL DAÑO SEA LOCAL
// ===========================================================================
//
// `encode_base_n` convierte el mensaje entero como UN número. Eso no tiene
// localidad: un glifo mal leído no cambia un byte, cambia el número y con él
// todos los bytes que siguen. Reed-Solomon corrige errores dispersos, así que
// detrás de esa transformación no puede hacer nada — medido el 2026-07-26: el
// canal protegido no aguantaba ni un glifo dañado.
//
// Aquí el mapeo es local y de tamaño fijo:
//
//     3 bytes  <->  4 glifos      94^4 = 78 074 896  >=  2^24 = 16 777 216
//
// Un glifo dañado corrompe EXACTAMENTE 3 bytes, que es lo que el corrector
// espera. Y como solo el 21,5 % del espacio de 4 glifos corresponde a un valor
// de 3 bytes, el 78,5 % de las corrupciones se detecta aquí mismo: el grupo da
// un valor imposible. Ese detector local es lo que compra el 8,4 % de densidad
// que la proporción 3:4 no aprovecha.

/// Bytes por grupo.
pub const GRUPO_BYTES: usize = 3;
/// Glifos por grupo.
pub const GRUPO_DIGITOS: usize = 4;
/// Base mínima para los grupos 3:4: `64^4 = 2^24`, justo los valores de 3 bytes.
pub const GRUPO_BASE_MINIMA: u32 = 64;

/// Codifica en grupos de 3 bytes -> 4 dígitos base `n`.
///
/// Rellena con ceros hasta un múltiplo de 3. El relleno es inofensivo: quien
/// llama conoce la longitud real por su propia cabecera y descarta la cola.
/// (Su llamador en este repo era el canal de glifos, retirado en `ca9a874`
/// (#93); hoy solo la usan sus pruebas, y sigue siendo API pública.)
///
/// # Pánico
///
/// Si `n < 64`. Cuatro dígitos base `n` solo cubren los 2^24 valores de un grupo
/// de 3 bytes cuando `n^4 >= 2^24`, o sea `n >= 64`; por debajo, el dígito más
/// alto se truncaba EN SILENCIO y `decode_grupos` devolvía otros bytes sin
/// marcar nada (lo cazó el concilio del 2026-11-06). Es un fallo de programación,
/// no de datos: pánico antes que un dato falso (directiva 20).
pub fn encode_grupos(data: &[u8], n: u32) -> Vec<u32> {
    assert!(
        n >= GRUPO_BASE_MINIMA,
        "una base de {n} no cabe en grupos 3:4: se exige n >= {GRUPO_BASE_MINIMA}"
    );
    let base = n as u64;
    let mut out = Vec::with_capacity(data.len().div_ceil(GRUPO_BYTES) * GRUPO_DIGITOS);
    for trozo in data.chunks(GRUPO_BYTES) {
        let mut v = 0u64;
        for i in 0..GRUPO_BYTES {
            v = (v << 8) | *trozo.get(i).unwrap_or(&0) as u64;
        }
        let mut digitos = [0u32; GRUPO_DIGITOS];
        for d in digitos.iter_mut().rev() {
            *d = (v % base) as u32;
            v /= base;
        }
        out.extend_from_slice(&digitos);
    }
    out
}

/// Operación inversa. Devuelve también qué grupos vinieron corruptos.
///
/// Un grupo cuyo valor no cabe en 3 bytes es imposible: no lo produjo
/// `encode_grupos`. Se devuelve como ceros y se anota su posición, para que el
/// corrector sepa dónde mirar en vez de tratarlo como dato bueno.
///
/// # Pánico
///
/// Si `n < 64`, por la misma razón que [`encode_grupos`].
pub fn decode_grupos(indices: &[Option<u32>], n: u32) -> (Vec<u8>, Vec<usize>) {
    assert!(
        n >= GRUPO_BASE_MINIMA,
        "una base de {n} no cabe en grupos 3:4: se exige n >= {GRUPO_BASE_MINIMA}"
    );
    let base = n as u64;
    let mut out = Vec::with_capacity(indices.len() / GRUPO_DIGITOS * GRUPO_BYTES);
    let mut corruptos = Vec::new();

    for (g, grupo) in indices.chunks(GRUPO_DIGITOS).enumerate() {
        if grupo.len() < GRUPO_DIGITOS {
            // Cola incompleta: no la produjo el codificador. Se descarta en vez
            // de rellenarla, que sería inventar bytes.
            corruptos.push(g);
            break;
        }
        // Una posición ilegible contamina su grupo entero: no se puede
        // reconstruir el valor sin ella. Se marca y Reed-Solomon lo repara.
        if grupo.iter().any(|d| d.is_none()) {
            corruptos.push(g);
            out.extend_from_slice(&[0u8; GRUPO_BYTES]);
            continue;
        }
        // Un índice fuera del alfabeto solo puede venir de una lectura rota, y
        // marca el grupo ENTERO como corrupto. Antes se saturaba a `n - 1` y solo
        // caía si el valor resultante desbordaba 3 bytes: en la última posición
        // casi nunca desborda, así que el índice imposible pasaba como dato bueno
        // y Reed-Solomon lo recibía como error en vez de como borrado (la mitad
        // de capacidad de corrección). Lo cazó el concilio del 2026-11-06.
        if grupo.iter().flatten().any(|&d| d >= n) {
            corruptos.push(g);
            out.extend_from_slice(&[0u8; GRUPO_BYTES]);
            continue;
        }
        let mut v = 0u64;
        for d in grupo.iter().flatten() {
            // Saturar, no multiplicar a pelo: con una base enorme `n^4` no cabe
            // en u64, y la saturación cae igual en el `v > 0x00FF_FFFF` de abajo.
            v = v.saturating_mul(base).saturating_add(*d as u64);
        }
        if v > 0x00FF_FFFF {
            corruptos.push(g);
            out.extend_from_slice(&[0u8; GRUPO_BYTES]);
            continue;
        }
        out.push((v >> 16) as u8);
        out.push((v >> 8) as u8);
        out.push(v as u8);
    }
    (out, corruptos)
}


#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn round_trips_simple_bytes() {
        let data = b"hello";
        let encoded = encode_base_n(data, 94);
        let decoded = decode_base_n(&encoded, 94);
        assert_eq!(decoded, data);
    }

    #[test]
    fn round_trips_empty_input() {
        let data = b"";
        let encoded = encode_base_n(data, 94);
        let decoded = decode_base_n(&encoded, 94);
        assert_eq!(decoded, data);
    }

    #[test]
    fn round_trips_leading_zero_bytes() {
        // El marcador 0x01 debe preservar los ceros a la izquierda.
        let data = &[0u8, 0, 0, 42];
        let encoded = encode_base_n(data, 94);
        let decoded = decode_base_n(&encoded, 94);
        assert_eq!(decoded, data);
    }

    proptest! {
        #[test]
        fn round_trips_any_bytes_any_base(
            data in proptest::collection::vec(any::<u8>(), 0..256),
            n in 2u32..=4096,
        ) {
            let encoded = encode_base_n(&data, n);
            // Todo índice debe estar en el rango [0, n).
            prop_assert!(encoded.iter().all(|&d| d < n));
            let decoded = decode_base_n(&encoded, n);
            prop_assert_eq!(decoded, data);
        }
    }

    // =======================================================================
    // QUE LA SALIDA NO CAMBIE
    // =======================================================================
    //
    // Las pruebas de ida y vuelta de arriba NO bastan para proteger el formato:
    // pasan igual si se cambia la codificación entera, mientras siga siendo
    // consistente consigo misma. Y este formato es el de un artefacto FIRMADO
    // que ya está guardado en bases de datos de clientes: cambiarlo invalida
    // firmas emitidas. Lo que sigue lo fija de dos maneras independientes.

    /// La implementación ingenua —un dígito por división— tal como estuvo hasta
    /// el 2026-07-31. Es la DEFINICIÓN del formato; la versión rápida solo puede
    /// diferir en el tiempo que tarda.
    fn encode_base_n_ingenuo(data: &[u8], n: u32) -> Vec<u32> {
        let mut buf = Vec::with_capacity(data.len() + 1);
        buf.push(1u8);
        buf.extend_from_slice(data);

        let base = BigUint::from(n);
        let mut value = BigUint::from_bytes_be(&buf);
        let mut digits = Vec::new();
        while !value.is_zero() {
            let rem = &value % &base;
            digits.push(rem.to_u32().expect("rem < n cabe en u32"));
            value /= &base;
        }
        digits.reverse();
        digits
    }

    proptest! {
        /// La versión rápida produce EXACTAMENTE los mismos dígitos que la
        /// ingenua, para cualquier entrada y cualquier base.
        #[test]
        fn la_version_rapida_da_los_mismos_digitos_que_la_ingenua(
            data in proptest::collection::vec(any::<u8>(), 0..512),
            n in 2u32..=4096,
        ) {
            prop_assert_eq!(encode_base_n(&data, n), encode_base_n_ingenuo(&data, n));
        }
    }

    /// Vectores tomados de la implementación ingenua ANTES de acelerarla. Si el
    /// oráculo de arriba se tocara alguna vez, estos siguen sujetando el formato.
    #[test]
    fn los_vectores_de_referencia_no_se_mueven() {
        assert_eq!(encode_base_n(b"quipu", 94), vec![2, 28, 20, 22, 35, 86, 69]);
        assert_eq!(encode_base_n(&[0u8, 0, 0, 42], 94), vec![55, 1, 1, 91, 84]);
        assert_eq!(encode_base_n(b"", 94), vec![1]);
        assert_eq!(encode_base_n(&[255u8; 8], 2), vec![1; 65]);
        assert_eq!(encode_base_n(&[1u8, 2, 3], 4096), vec![1, 16, 515]);

        // Un caso largo, donde el paso por bloques sí entra en juego (79 dígitos
        // = 8 bloques de 9 más un bloque parcial de 7).
        let largo: Vec<u8> = (0..64).map(|i| (i * 7 % 251) as u8).collect();
        let e = encode_base_n(&largo, 94);
        assert_eq!(e.len(), 79);
        assert_eq!(&e[..8], &[1, 63, 22, 42, 28, 2, 71, 12]);
        assert_eq!(&e[e.len() - 8..], &[18, 6, 42, 45, 73, 30, 87, 12]);
        assert_eq!(e.iter().map(|&d| u64::from(d)).sum::<u64>(), 3530);
    }

    /// El bloque más significativo NO lleva ceros de relleno, pero los bloques
    /// interiores SÍ. Es el único sitio donde el paso por bloques puede
    /// desviarse del dígito a dígito, así que se prueba a propósito: se buscan
    /// entradas cuyo dígito más significativo caiga justo en un cambio de bloque.
    #[test]
    fn los_ceros_de_relleno_van_dentro_pero_no_delante() {
        for largo in 1..40usize {
            let data = vec![0u8; largo];
            let rapido = encode_base_n(&data, 94);
            assert_eq!(rapido, encode_base_n_ingenuo(&data, 94), "con {largo} ceros");
            assert_ne!(rapido[0], 0, "el dígito más significativo nunca es cero ({largo} ceros)");
        }
    }

    // =======================================================================
    // EL ÁRBOL: QUE SE RECORRA, Y QUE DÉ LO MISMO QUE EL BUCLE
    // =======================================================================
    //
    // Todo lo de arriba pasa igual con el árbol borrado, porque las entradas son
    // cortas y se van por el bucle. Estas tres pruebas son la mitad que faltaba.

    /// POSITIVO DE CONTROL. Antes de comparar nada, hay que saber que el camino
    /// nuevo se recorre de verdad: si el umbral cambiara, o si la estimación de
    /// limbos se torciera, las comparaciones de abajo seguirían verdes midiendo
    /// dos veces el bucle de siempre.
    #[test]
    fn las_entradas_grandes_van_de_verdad_por_el_arbol() {
        // 4 KiB: 32 769 bits -> 513 limbos, muy por encima del umbral de 32.
        assert!(vale_la_pena_partir((4096u64 + 1) * 8), "4 KiB tiene que partir");
        // Y el borde, por los dos lados, contra el umbral real y no contra 32
        // escrito a mano.
        let borde = LIMBOS_PARA_DIVIDIR_Y_VENCER * BITS_POR_LIMBO;
        assert!(vale_la_pena_partir(borde), "justo en el umbral, parte");
        assert!(!vale_la_pena_partir(borde - BITS_POR_LIMBO), "un limbo menos, no parte");
        // Un mensaje corriente sigue yendo por el bucle: el árbol no se cuela
        // donde no compensa.
        assert!(!vale_la_pena_partir(64 * 8), "64 bytes no parten");
    }

    /// El árbol da EXACTAMENTE los mismos dígitos que la definición ingenua, en
    /// tamaños donde el bucle ya no se usa. Es la misma comparación de arriba,
    /// sobre el otro camino.
    #[test]
    fn el_arbol_da_los_mismos_digitos_que_la_definicion() {
        for largo in [300usize, 512, 1000, 2048, 4097] {
            let data: Vec<u8> = (0..largo).map(|i| (i * 131 % 256) as u8).collect();
            assert!(
                vale_la_pena_partir((largo as u64 + 1) * 8),
                "{largo} bytes tienen que ir por el árbol para que esto pruebe algo"
            );
            for n in [2u32, 3, 94, 256, 4096, u32::MAX] {
                assert_eq!(
                    encode_base_n(&data, n),
                    encode_base_n_ingenuo(&data, n),
                    "difieren con {largo} bytes en base {n}"
                );
            }
        }
    }

    /// Y la vuelta, que tiene su propio árbol: los dígitos de una entrada grande
    /// reconstruyen los bytes. Se comprueba además que el descodificado va por
    /// el árbol y no por Horner.
    #[test]
    fn el_arbol_de_vuelta_reconstruye_lo_mismo() {
        for largo in [300usize, 1000, 4097] {
            let data: Vec<u8> = (0..largo).map(|i| (i * 251 % 256) as u8).collect();
            for n in [2u32, 94, 4096] {
                let digitos = encode_base_n(&data, n);
                let bloques = digitos.len().div_ceil(paso_maximo(u64::from(n)).1 as usize) as u64;
                assert!(
                    vale_la_pena_partir(bloques * BITS_POR_LIMBO),
                    "{largo} bytes en base {n} tienen que descodificarse por el árbol"
                );
                assert_eq!(decode_base_n(&digitos, n), data, "{largo} bytes, base {n}");
            }
        }
    }

    /// LA BASE IMPOSIBLE, ahora también al DESCODIFICAR.
    ///
    /// El gemelo `una_base_de_uno_falla_en_vez_de_colgarse` existía solo para
    /// `encode_base_n`. Al reescribir el códec, `decode_base_n` pasó a llamar a
    /// `paso_maximo`, que con `n < 2` no termina — o sea que la reescritura
    /// convirtió un valor absurdo-pero-inocuo en un cuelgue. Esta prueba es la
    /// que faltaba.
    /// **Y se comprueba el MENSAJE, no solo que reviente**, porque «revienta» no
    /// discrimina: medido con el mutante, quitando el `assert!` la prueba seguía
    /// pasando —en debug `paso_maximo(1)` acaba desbordando `k` tras 2³² vueltas
    /// y da pánico igual, en 41 segundos—. En release no daría pánico: se
    /// colgaría para siempre. Atarla al texto del `assert!` es lo único que
    /// distingue «lo rechazamos nosotros» de «se murió sola por otra cosa».
    #[test]
    fn descodificar_con_una_base_imposible_falla_en_vez_de_colgarse() {
        for base in [0u32, 1] {
            let r = std::panic::catch_unwind(|| decode_base_n(&[0, 1, 0], base));
            let panico = r.expect_err("la base {base} tiene que dar pánico, no colgarse");
            let texto = panico
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panico.downcast_ref::<&str>().copied())
                .unwrap_or("");
            assert!(
                texto.contains("no descodifica nada"),
                "con la base {base} el pánico tiene que venir de NUESTRO assert, \
                 no de un desbordamiento diez mil millones de vueltas después. \
                 Llegó: {texto:?}"
            );
        }
        // CONTROL: la base mínima legítima sí funciona. Sin esto, un `assert!`
        // cableado a `n >= 3` pasaría igual.
        assert_eq!(decode_base_n(&encode_base_n(b"ab", 2), 2), b"ab");
    }

    /// UN DÍGITO APENAS ILEGAL, que es el caso que la pareja no cubría.
    ///
    /// `un_digito_fuera_del_alfabeto_cae_a_horner_y_no_trunca` usa `u32::MAX`,
    /// que SÍ desborda el bloque. Un 94 o un 95 en base 94 **no desbordan** —el
    /// bloque cabe de sobra en un `u64`— así que `a_limbos` devuelve `Some` con
    /// un limbo mayor que `paso`, y el camino recorrido es el del árbol, no el
    /// de Horner. Es el positivo sin su pareja: se probaba el camino fácil.
    #[test]
    fn un_digito_apenas_ilegal_no_cae_a_horner_y_aun_asi_da_lo_mismo() {
        let base = 94u32;
        let k = paso_maximo(u64::from(base)).1;
        let mut digitos: Vec<u32> = (0..400).map(|i| (i * 7 % 94) as u32).collect();

        for ilegal in [94u32, 95, 100] {
            digitos[123] = ilegal;
            // EL CONTROL, y es lo que distingue esta prueba de la otra: este
            // dígito NO desborda, así que NO se cae a Horner.
            assert!(
                a_limbos(&digitos, u64::from(base), k).is_some(),
                "el dígito {ilegal} no debería desbordar el bloque: si desborda, \
                 esta prueba está midiendo el camino de Horner otra vez"
            );
            assert_eq!(
                decode_base_n(&digitos, base),
                horner_ingenuo(&digitos, base),
                "con el dígito {ilegal}"
            );
        }
    }

    /// LOS HUECOS DE CEROS, que es lo único que distingue el relleno de la hoja
    /// de no hacer nada.
    ///
    /// Escrita porque un mutante SOBREVIVIÓ: borrando el `resize` que rellena
    /// con ceros, las catorce pruebas de arriba seguían verdes. El motivo es que
    /// una rama a cero solo cambia el resultado si está en medio — si está
    /// arriba, sus ceros se recortan igual—, y con datos pseudoaleatorios no
    /// aparece jamás un hueco de nueve dígitos seguidos a cero. Hay que
    /// fabricarlo a propósito.
    #[test]
    fn el_arbol_no_pierde_los_huecos_de_ceros_de_en_medio() {
        let casos: Vec<Vec<u8>> = vec![
            // Un hueco enorme en medio: obliga a que subárboles interiores
            // enteros valgan cero.
            {
                let mut v = vec![0xFFu8];
                v.extend(std::iter::repeat_n(0u8, 4000));
                v.push(0xFF);
                v
            },
            // Todo ceros salvo el marcador: el caso extremo.
            vec![0u8; 4096],
            // Huecos alternos, para que caigan en niveles distintos del árbol.
            (0..4096).map(|i| if i % 512 < 500 { 0 } else { 0xA5 }).collect(),
        ];
        for (caso, data) in casos.iter().enumerate() {
            assert!(
                vale_la_pena_partir((data.len() as u64 + 1) * 8),
                "el caso {caso} tiene que ir por el árbol"
            );
            for n in [2u32, 94, 4096] {
                let digitos = encode_base_n(data, n);
                assert_eq!(
                    digitos,
                    encode_base_n_ingenuo(data, n),
                    "caso {caso}, base {n}: el árbol perdió un hueco de ceros"
                );
                assert_eq!(&decode_base_n(&digitos, n), data, "caso {caso}, base {n}");
            }
        }
    }

    /// La salida de emergencia del descodificador. Un dígito fuera del alfabeto
    /// no lo produce este códec, pero puede llegar: entonces un bloque no cabe
    /// en un `u64` y hay que caer a Horner en vez de truncar. Se compara contra
    /// la definición —Horner puro— para que «no truncar» sea comprobable y no
    /// una intención.
    #[test]
    fn un_digito_fuera_del_alfabeto_cae_a_horner_y_no_trunca() {
        let base = 94u32;
        let mut digitos: Vec<u32> = (0..400).map(|i| (i * 7 % 94) as u32).collect();
        // Sin dígitos ilegales, los dos caminos coinciden.
        assert_eq!(decode_base_n(&digitos, base), horner_ingenuo(&digitos, base));
        // Con uno ilegal —y bastante grande para desbordar su bloque— también.
        digitos[123] = u32::MAX;
        assert!(
            a_limbos(&digitos, u64::from(base), paso_maximo(u64::from(base)).1).is_none(),
            "el control: este dígito TIENE que desbordar el bloque, si no la prueba no prueba nada"
        );
        assert_eq!(decode_base_n(&digitos, base), horner_ingenuo(&digitos, base));
    }

    /// Horner puro sobre los dígitos, que es la definición del descodificado.
    fn horner_ingenuo(indices: &[u32], n: u32) -> Vec<u8> {
        let base = BigUint::from(n);
        let mut value = BigUint::zero();
        for &d in indices {
            value = value * &base + BigUint::from(d);
        }
        value.to_bytes_be()[1..].to_vec()
    }

    /// Las bases EXTREMAS, que la proptest de arriba (2..=4096) no alcanza.
    ///
    /// `paso_maximo` busca el mayor `n^k` que cabe en un `u64`, y ahí hay dos
    /// bordes con nombre propio: en la base 2 el paso es `2^63` con 63 dígitos
    /// por bloque, y en `u32::MAX` el cuadrado se queda a un pelo del techo
    /// (`4294967295² = 18 446 744 065 119 617 025` contra
    /// `u64::MAX = 18 446 744 073 709 551 615`), así que `k` vale 2 y no 1. Un
    /// error de uno en cualquiera de los dos sitios rompería el codec justo
    /// donde nadie mira.
    #[test]
    fn las_bases_extremas_dan_los_mismos_digitos() {
        for n in [2u32, 3, 255, 256, 65535, 65536, u32::MAX - 1, u32::MAX] {
            for data in [
                &b""[..],
                &b"x"[..],
                &[0u8, 0, 0, 1][..],
                &[255u8; 33][..],
                &[0xAB; 100][..],
            ] {
                assert_eq!(
                    encode_base_n(data, n),
                    encode_base_n_ingenuo(data, n),
                    "base {n}, {} bytes",
                    data.len()
                );
            }
        }
    }

    /// Que `paso_maximo` devuelva de verdad el MAYOR `n^k` que cabe: un `k` de
    /// menos solo sería más lento, pero uno de más desbordaría en silencio.
    #[test]
    fn el_paso_es_el_mayor_que_cabe_en_u64() {
        for n in [2u64, 3, 94, 255, 256, 4096, 65536, u64::from(u32::MAX)] {
            let (paso, k) = paso_maximo(n);
            assert_eq!(paso, n.pow(k), "el paso debe ser n^k (base {n})");
            assert!(
                n.checked_pow(k + 1).is_none(),
                "base {n}: n^{} también cabía, el paso se quedó corto",
                k + 1
            );
        }
        assert_eq!(paso_maximo(2), (1u64 << 63, 63));
        assert_eq!(paso_maximo(94).1, 9);
    }

    #[test]
    #[should_panic(expected = "no codifica nada")]
    fn una_base_de_uno_falla_en_vez_de_colgarse() {
        // Antes esto se quedaba dando vueltas para siempre: value % 1 == 0 y
        // value / 1 == value, así que el bucle no terminaba nunca.
        encode_base_n(b"lo que sea", 1);
    }

    // =======================================================================
    // EL CÓDEC POR GRUPOS (3 bytes -> 4 dígitos), que es OTRO códec
    // =======================================================================
    //
    // Todo lo de arriba prueba `encode_base_n`/`decode_base_n`, el códec del
    // contenedor. `encode_grupos`/`decode_grupos` es el del canal de glifos (hoy
    // retirado, `ca9a874`; queda como API pública sin llamador en el repo):
    // empaqueta CADA grupo por separado para que una corrupción quede confinada
    // a su grupo en vez de contaminar el número entero. No tenía ni una prueba
    // directa, y su afirmación medible —«el 78,5 % de las corrupciones se
    // detecta aquí mismo» (ver la nota sobre GRUPO_BYTES)— no la sujetaba nada.

    /// Un PRNG determinista y sin dependencias, para medir una tasa sin
    /// `proptest` (que corre casos aislados y no acumula).
    fn splitmix64(estado: &mut u64) -> u64 {
        *estado = estado.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *estado;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Ida y vuelta limpia: datos que NO son múltiplo de 3, para ejercitar el
    /// relleno de la cola. Un grupo legítimo nunca se marca corrupto.
    #[test]
    fn los_grupos_van_y_vuelven_sin_marcar_corrupcion() {
        let base = 94u32;
        let data = b"quipu!!"; // 7 bytes -> 3 grupos (9 con relleno)
        let digitos = encode_grupos(data, base);
        assert_eq!(digitos.len(), 3 * GRUPO_DIGITOS, "3 grupos de 4 dígitos");
        assert!(digitos.iter().all(|&d| d < base), "todo dígito en [0, base)");

        let indices: Vec<Option<u32>> = digitos.iter().map(|&d| Some(d)).collect();
        let (bytes, corruptos) = decode_grupos(&indices, base);
        assert!(corruptos.is_empty(), "datos legítimos no producen corruptos");
        assert_eq!(&bytes[..data.len()], data, "el prefijo es el dato original");
        assert_eq!(&bytes[data.len()..], &[0u8, 0], "la cola es relleno de ceros");
    }

    /// LA AFIRMACIÓN MEDIBLE: la fracción de grupos aleatorios que caen fuera
    /// del espacio de 3 bytes es 1 - 2²⁴/94⁴ = 0,7851. Es el detector local, y
    /// es lo único que compra el códec por grupos frente a un número entero.
    ///
    /// DISCRIMINA: si se borrara el `if v > 0x00FF_FFFF` de `decode_grupos`,
    /// ningún grupo se marcaría y la tasa caería a 0 — esta prueba se pone roja.
    #[test]
    fn la_deteccion_local_de_corrupcion_ronda_el_785_por_ciento() {
        let base = 94u64;
        const N: u64 = 200_000;
        let espacio = base.pow(4); // 94⁴ = 78 074 896 valores de grupo posibles
        let mut estado = 0x1234_5678_9ABC_DEF0u64;
        let mut detectados = 0u64;

        for _ in 0..N {
            // Un valor UNIFORME en [0, 94⁴): un grupo de 4 dígitos base 94.
            let v = splitmix64(&mut estado) % espacio;
            let mut digitos = [0u32; GRUPO_DIGITOS];
            let mut w = v;
            for d in digitos.iter_mut().rev() {
                *d = (w % base) as u32;
                w /= base;
            }
            let indices: Vec<Option<u32>> = digitos.iter().map(|&d| Some(d)).collect();
            let (_, corruptos) = decode_grupos(&indices, base as u32);
            if !corruptos.is_empty() {
                detectados += 1;
            }
        }

        let tasa = detectados as f64 / N as f64;
        let esperada = 1.0 - (1u64 << 24) as f64 / espacio as f64; // 0,7851…
        assert!(
            (tasa - esperada).abs() < 0.01,
            "la tasa de detección medida ({tasa:.4}) se aparta de la teórica \
             ({esperada:.4}): el detector del grupo imposible cambió"
        );
        // CONTROL de que la tasa es no trivial: sin el umbral daría 0, con un
        // umbral demasiado laxo daría 1. Ninguno de los dos pasa esta banda.
        assert!(
            (0.5..0.95).contains(&tasa),
            "tasa fuera de la banda esperada: {tasa}"
        );
    }

    /// Un índice FUERA DEL ALFABETO marca su grupo como corrupto en CUALQUIER
    /// posición. La última es la que discrimina: antes se saturaba a `n - 1`,
    /// `[0, 0, 0, n]` daba el valor 93 (cabe en 3 bytes) y pasaba como dato bueno.
    /// Con el arreglo revertido, la primera aserción se pone roja.
    #[test]
    fn un_indice_fuera_del_alfabeto_marca_su_grupo_en_cualquier_posicion() {
        let base = 94u32;
        for pos in 0..GRUPO_DIGITOS {
            let mut grupo = [Some(0u32); GRUPO_DIGITOS];
            grupo[pos] = Some(base); // el primer índice imposible
            let (bytes, corruptos) = decode_grupos(&grupo, base);
            assert_eq!(corruptos, vec![0], "índice {base} en la posición {pos} no se marcó");
            assert_eq!(bytes, vec![0u8; GRUPO_BYTES], "el grupo corrupto sale como ceros");
        }
        // CONTROL (la mitad que acepta): el índice más alto LEGAL no se marca.
        let legal = [Some(0), Some(0), Some(0), Some(base - 1)];
        let (bytes, corruptos) = decode_grupos(&legal, base);
        assert!(corruptos.is_empty(), "n - 1 es un dígito legítimo");
        assert_eq!(bytes, vec![0, 0, (base - 1) as u8]);
    }

    /// Por debajo de 64 los grupos 3:4 no caben: se niega en vez de truncar.
    #[test]
    #[should_panic(expected = "se exige n >= 64")]
    fn encode_grupos_rechaza_una_base_que_trunca() {
        let _ = encode_grupos(&[0xFF, 0xFF, 0xFF], 63);
    }

    /// CONTROL de la pareja: la base mínima cubre el grupo máximo exacto.
    #[test]
    fn la_base_minima_cubre_el_grupo_maximo() {
        let d = encode_grupos(&[0xFF, 0xFF, 0xFF], GRUPO_BASE_MINIMA);
        let idx: Vec<Option<u32>> = d.iter().map(|&x| Some(x)).collect();
        let (bytes, corruptos) = decode_grupos(&idx, GRUPO_BASE_MINIMA);
        assert!(corruptos.is_empty());
        assert_eq!(bytes, vec![0xFF, 0xFF, 0xFF]);
    }

    /// Un dígito ILEGIBLE (`None`) contamina su grupo entero: se marca corrupto
    /// y sale como ceros, sin arrastrar a los grupos vecinos.
    #[test]
    fn un_digito_ilegible_marca_solo_su_grupo() {
        let base = 94u32;
        let data = b"abcdef"; // 2 grupos exactos
        let digitos = encode_grupos(data, base);

        // CONTROL: sin borrar nada, cero corruptos.
        let limpio: Vec<Option<u32>> = digitos.iter().map(|&d| Some(d)).collect();
        assert!(decode_grupos(&limpio, base).1.is_empty(), "control: nada corrupto");

        let mut indices = limpio;
        indices[5] = None; // un dígito del grupo 1
        let (bytes, corruptos) = decode_grupos(&indices, base);
        assert_eq!(corruptos, vec![1], "solo el grupo 1 queda ilegible");
        assert_eq!(&bytes[0..3], b"abc", "el grupo 0 se conserva intacto");
        assert_eq!(&bytes[3..6], &[0u8, 0, 0], "el grupo ilegible sale como ceros");
    }

    /// Una cola INCOMPLETA (longitud no múltiplo de 4) no la produjo el
    /// codificador: se descarta como corrupta en vez de rellenarse.
    #[test]
    fn una_cola_incompleta_se_descarta_en_vez_de_inventar_bytes() {
        let base = 94u32;
        // Un grupo completo + 1 dígito suelto.
        let indices: Vec<Option<u32>> = vec![Some(1), Some(2), Some(3), Some(4), Some(5)];
        let (bytes, corruptos) = decode_grupos(&indices, base);
        assert_eq!(bytes.len(), GRUPO_BYTES, "solo el grupo completo da bytes");
        assert_eq!(corruptos, vec![1], "la cola incompleta (grupo 1) es corrupta");
    }
}

