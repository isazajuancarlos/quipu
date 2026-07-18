// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Compartición de secretos de Shamir (k-de-n) sobre GF(2^8).
//!
//! Parte un secreto en `n` comparticiones de forma que **k** cualesquiera lo
//! reconstruyen y **k-1** no revelan absolutamente nada (secreto perfecto, no
//! computacional: con k-1 comparticiones todos los secretos del mismo tamaño
//! siguen siendo igual de probables).
//!
//! ## Aislado tras `escrow`, a propósito
//!
//! El módulo va tras un feature gate no-default. No es que sea peligroso: es que
//! una herramienta debe estar **contenida a su único fin**. Quien cifra datos no
//! necesita repartir claves, y código que no se compila no expone API, no se
//! puede invocar por error y no puede interferir con nada. La rueda de PyPI y el
//! CI lo activan explícitamente porque ahí sí se usa.
//!
//! ## Para qué está aquí
//!
//! `THREAT_MODEL` §N7 deja la *custodia* de claves fuera de alcance: Quipu
//! entrega **primitivas**, no gestiona claves. Este módulo es exactamente eso,
//! una primitiva. No hay almacén, ni servicio, ni rotación: `split` y `combine`.
//!
//! Cierra el riesgo residual **R2** («perder la clave del servidor OPRF hace los
//! secretos irrecuperables»), cuya mitigación documentada es *respaldo offline*:
//! repartir la clave en k-de-n comparticiones custodiadas por separado es la
//! forma disciplinada de ese respaldo. Sirve igual para la clave de firma
//! ML-DSA de un integrador y para escrow contractual, y **funciona sin red y sin
//! HSM**, que es la condición de los despliegues air-gapped.
//!
//! ## Qué NO es
//!
//! - **No es firma umbral.** No se firma con las comparticiones: el secreto se
//!   reconstruye en memoria para usarlo. Un esquema umbral de verdad (FROST, o
//!   ML-DSA umbral) es otro problema; el primero no es post-cuántico y el
//!   segundo no está estandarizado.
//! - **No es criptografía inventada.** Es el esquema de Shamir (1979) sobre el
//!   campo de AES, tal como lo usan SLIP-39 y Vault. Implementarlo es como
//!   implementar HKDF desde su RFC: hay una especificación fija que seguir.
//!
//! ## Por qué no hay advertencia sobre secretos de baja entropía
//!
//! Porque no hace falta. La etiqueta de integridad viaja **dentro** de lo
//! repartido, no en la cabecera, así que con `k-1` comparticiones no hay nada
//! contra qué probar una conjetura: rige el secreto perfecto sobre todo el
//! payload, etiqueta incluida. Quien puede verificar una conjetura es quien ya
//! tiene `k` comparticiones — y ese ya tiene el secreto.
//!
//! Un diseño anterior ponía el verificador en la cabecera y eso SÍ abría un
//! oráculo: obligaba a un piso de longitud, a encarecer la derivación y a
//! documentar la limitación. Tres parches para sostener una decisión que
//! sobraba. Al mover ocho bytes de sitio, los tres desaparecen.
//!
//! ```
//! use quipu::shamir;
//!
//! let clave = [7u8; 32];   // material de clave, no una contraseña
//! let comparticiones = shamir::split(&clave, 3, 5).unwrap();
//!
//! // Tres cualesquiera bastan.
//! let subconjunto = [comparticiones[4].clone(), comparticiones[0].clone(), comparticiones[2].clone()];
//! assert_eq!(&shamir::combine(&subconjunto).unwrap()[..], &clave[..]);
//! ```

use crate::antihacker::ct_eq;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// Marca de formato de una compartición serializada.
const MAGIC: &[u8; 4] = b"QSS2";
/// Longitud de la etiqueta de integridad, que viaja DENTRO de lo repartido.
const TAG_LEN: usize = 8;
/// Separación de dominio de la etiqueta.
const TAG_INFO: &[u8] = b"quipu/v1/shamir-tag";
/// Bytes de cabecera de una compartición: magic ‖ k ‖ x ‖ len.
///
/// No hay sal ni verificador en la cabecera, y esa ausencia es el diseño: si el
/// verificador viviera aquí, cualquiera con UNA compartición podría probar
/// conjeturas del secreto contra él, y además dos comparticiones del mismo
/// reparto exhibirían campos idénticos que las delatarían como pareja. Al
/// meterlo dentro de lo repartido desaparecen las dos cosas de raíz.
const HEADER_LEN: usize = 4 + 1 + 1 + 4;

/// Umbral mínimo con sentido: con k=1 no hay secreto que repartir.
const MIN_THRESHOLD: u8 = 2;

// No hay longitud mínima. El piso anterior existía únicamente para contener
// el oráculo de conjeturas del verificador; sin oráculo no hay nada que
// contener. Shamir es seguro en sentido informacional: con k-1 comparticiones
// no se aprende NADA del secreto, tenga la entropía que tenga.

/// Errores de la compartición de secretos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShamirError {
    /// `threshold` < 2, `shares` < `threshold`, o `shares` > 255.
    BadParameters,
    /// El secreto está vacío.
    EmptySecret,
    /// Se aportaron menos comparticiones que el umbral.
    NotEnoughShares {
        /// Comparticiones necesarias.
        needed: usize,
        /// Comparticiones aportadas.
        got: usize,
    },
    /// Las comparticiones no pertenecen al mismo reparto (sal, umbral,
    /// verificador o longitud discrepantes), o hay índices repetidos.
    Inconsistent,
    /// La reconstrucción no supera el verificador: alguna compartición está
    /// corrupta o alterada. No se indica cuál.
    VerificationFailed,
    /// Los bytes no son una compartición válida.
    Malformed,
}

impl core::fmt::Display for ShamirError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadParameters => write!(f, "parámetros de reparto inválidos"),
            Self::EmptySecret => write!(f, "el secreto está vacío"),
            Self::NotEnoughShares { needed, got } => {
                write!(f, "hacen falta {needed} comparticiones, se aportaron {got}")
            }
            Self::Inconsistent => write!(f, "las comparticiones no son del mismo reparto"),
            Self::VerificationFailed => write!(f, "la reconstrucción no supera el verificador"),
            Self::Malformed => write!(f, "compartición mal formada"),
        }
    }
}

impl std::error::Error for ShamirError {}

// --- GF(2^8), en tiempo constante ---------------------------------------------
//
// Sin tablas de consulta a propósito: una tabla indexada por un byte secreto
// filtra por caché. Todo se hace con máscaras aritméticas.

/// Multiplicación en GF(2^8) con el polinomio de AES (0x11B).
fn gf_mul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut out = 0u8;
    for _ in 0..8 {
        // Suma `a` si el bit bajo de `b` es 1, sin ramificar.
        out ^= a & (b & 1).wrapping_neg();
        // Duplica `a` y reduce módulo el polinomio si se desbordó.
        let alto = (a >> 7) & 1;
        a <<= 1;
        a ^= 0x1b & alto.wrapping_neg();
        b >>= 1;
    }
    out
}

/// Inverso multiplicativo en GF(2^8) por exponenciación: a^254 = a^-1.
/// `gf_inv(0)` devuelve 0, que nunca se usa: los índices `x` son != 0.
fn gf_inv(a: u8) -> u8 {
    // Cadena de cuadrados y productos para el exponente 254 = 0b11111110.
    let mut resultado = 1u8;
    let mut base = a;
    let mut exp = 254u32;
    while exp > 0 {
        let bit = (exp & 1) as u8;
        // Multiplica solo si el bit está puesto, sin ramificar sobre el secreto.
        let candidato = gf_mul(resultado, base);
        let mascara = bit.wrapping_neg();
        resultado = (candidato & mascara) | (resultado & !mascara);
        base = gf_mul(base, base);
        exp >>= 1;
    }
    resultado
}

// --- Compartición -------------------------------------------------------------

/// Una compartición del secreto. Debe custodiarse como material sensible.
#[derive(Clone, PartialEq, Eq)]
pub struct Share {
    /// Umbral del reparto del que procede.
    threshold: u8,
    /// Índice de evaluación, en 1..=255. Nunca 0: ahí vive el secreto.
    index: u8,
    /// Evaluación del polinomio en `index`, byte a byte, sobre el payload
    /// completo (secreto ‖ etiqueta).
    y: Vec<u8>,
}

impl Drop for Share {
    fn drop(&mut self) {
        self.y.zeroize();
    }
}

// No derivamos Debug: volcar `y` en un log sería filtrar material de clave.
impl core::fmt::Debug for Share {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Share")
            .field("threshold", &self.threshold)
            .field("index", &self.index)
            .field("len", &self.y.len())
            .finish_non_exhaustive()
    }
}

impl Share {
    /// Índice de esta compartición (1..=255).
    pub fn index(&self) -> u8 {
        self.index
    }

    /// Umbral del reparto: cuántas comparticiones hacen falta.
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Serializa la compartición para custodiarla o transportarla.
    ///
    /// El resultado **es material sensible**: `HEADER_LEN` bytes de cabecera más
    /// la longitud del secreto.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Vec::with_capacity(HEADER_LEN + self.y.len());
        v.extend_from_slice(MAGIC);
        v.push(self.threshold);
        v.push(self.index);
        v.extend_from_slice(&(self.y.len() as u32).to_be_bytes());
        v.extend_from_slice(&self.y);
        Zeroizing::new(v)
    }

    /// Reconstruye una compartición desde bytes. La entrada es NO confiable.
    pub fn from_bytes(b: &[u8]) -> Result<Self, ShamirError> {
        if b.len() < HEADER_LEN || &b[0..4] != MAGIC {
            return Err(ShamirError::Malformed);
        }
        let threshold = b[4];
        let index = b[5];
        if threshold < MIN_THRESHOLD || index == 0 {
            return Err(ShamirError::Malformed);
        }

        let len = u32::from_be_bytes([b[6], b[7], b[8], b[9]]) as usize;

        // La longitud declarada tiene que cuadrar con lo que hay: una
        // compartición truncada no se acepta en silencio. Y el payload nunca
        // puede ser menor que la etiqueta que lleva dentro.
        if len <= TAG_LEN || b.len() != HEADER_LEN + len {
            return Err(ShamirError::Malformed);
        }

        Ok(Self {
            threshold,
            index,
            y: b[HEADER_LEN..].to_vec(),
        })
    }
}

/// Etiqueta de integridad del secreto. Viaja **dentro** de lo repartido.
///
/// Ahí está toda la diferencia. En la cabecera sería un oráculo: quien tuviera
/// una compartición podría probar conjeturas contra ella, y dos comparticiones
/// del mismo reparto mostrarían campos idénticos que las delatarían como pareja.
/// Dentro del payload no es ninguna de las dos cosas — con `k-1` comparticiones
/// rige el secreto perfecto sobre todo, etiqueta incluida.
///
/// Y por eso basta un hash: no necesita ser caro de calcular, porque nadie que
/// no tenga ya el secreto puede llegar a compararlo con nada.
fn etiqueta(secret: &[u8]) -> [u8; TAG_LEN] {
    let mut h = Sha256::new();
    h.update(TAG_INFO);
    h.update(secret);
    let d = h.finalize();
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(&d[..TAG_LEN]);
    out
}

/// Parte `secret` en `shares` comparticiones, de las que `threshold` bastan.
///
/// `threshold` debe estar en 2..=`shares` y `shares` en ..=255.
pub fn split(secret: &[u8], threshold: u8, shares: u8) -> Result<Vec<Share>, ShamirError> {
    if secret.is_empty() {
        return Err(ShamirError::EmptySecret);
    }
    if threshold < MIN_THRESHOLD || shares < threshold {
        return Err(ShamirError::BadParameters);
    }

    // Lo que se reparte es el secreto CON su etiqueta pegada. Así la integridad
    // queda protegida por el mismo secreto perfecto que el secreto: con k-1
    // comparticiones no se aprende nada de ninguno de los dos.
    let mut payload = Zeroizing::new(Vec::with_capacity(secret.len() + TAG_LEN));
    payload.extend_from_slice(secret);
    payload.extend_from_slice(&etiqueta(secret));

    // Índices 1..=shares. El 0 se reserva: f(0) es el payload.
    let mut fuera: Vec<Share> = (1..=shares)
        .map(|index| Share {
            threshold,
            index,
            y: Vec::with_capacity(payload.len()),
        })
        .collect();

    // Un polinomio independiente por byte del secreto, de grado threshold-1,
    // con término independiente igual al byte y el resto aleatorio.
    let mut coeficientes = vec![0u8; threshold as usize - 1];
    for &byte in payload.iter() {
        OsRng.fill_bytes(&mut coeficientes);
        for compartición in fuera.iter_mut() {
            let x = compartición.index;
            // Horner de mayor a menor grado, terminando en el término
            // independiente (el byte del secreto).
            let mut acc = 0u8;
            for &c in coeficientes.iter().rev() {
                acc = gf_mul(acc, x) ^ c;
            }
            acc = gf_mul(acc, x) ^ byte;
            compartición.y.push(acc);
        }
    }
    coeficientes.zeroize();

    Ok(fuera)
}

/// Reconstruye el secreto a partir de al menos `threshold` comparticiones.
///
/// Falla con [`ShamirError::VerificationFailed`] si alguna está corrupta, sin
/// indicar cuál.
pub fn combine(shares: &[Share]) -> Result<Zeroizing<Vec<u8>>, ShamirError> {
    let primera = shares.first().ok_or(ShamirError::NotEnoughShares {
        needed: MIN_THRESHOLD as usize,
        got: 0,
    })?;

    let needed = primera.threshold as usize;
    if shares.len() < needed {
        return Err(ShamirError::NotEnoughShares {
            needed,
            got: shares.len(),
        });
    }

    // Todas deben ser del mismo reparto, y sin índices repetidos.
    for s in shares {
        if s.threshold != primera.threshold || s.y.len() != primera.y.len() || s.index == 0
        {
            return Err(ShamirError::Inconsistent);
        }
    }
    for (i, a) in shares.iter().enumerate() {
        if shares[i + 1..].iter().any(|b| b.index == a.index) {
            return Err(ShamirError::Inconsistent);
        }
    }

    // Con exactamente `needed` se interpola; sobrantes se ignoran (aportar más
    // no cambia el resultado si son correctas, y limita el coste).
    let usadas = &shares[..needed];

    // Coeficientes de Lagrange en x=0: prod_{j!=i} x_j / (x_i + x_j).
    // En GF(2^8) la resta es XOR, así que x_i - x_j = x_i ^ x_j.
    let mut lambdas = Vec::with_capacity(needed);
    for (i, si) in usadas.iter().enumerate() {
        let mut num = 1u8;
        let mut den = 1u8;
        for (j, sj) in usadas.iter().enumerate() {
            if i == j {
                continue;
            }
            num = gf_mul(num, sj.index);
            den = gf_mul(den, si.index ^ sj.index);
        }
        // `den` nunca es 0: los índices son distintos y no nulos.
        lambdas.push(gf_mul(num, gf_inv(den)));
    }

    let mut recuperado = Zeroizing::new(vec![0u8; primera.y.len()]);
    for (pos, byte) in recuperado.iter_mut().enumerate() {
        let mut acc = 0u8;
        for (i, s) in usadas.iter().enumerate() {
            acc ^= gf_mul(s.y[pos], lambdas[i]);
        }
        *byte = acc;
    }
    lambdas.zeroize();

    // Separa la etiqueta del secreto y comprueba. Esto convierte la "basura
    // silenciosa" en un error, y hace además de detector de mezcla: si las
    // comparticiones fueran de repartos distintos, lo reconstruido no sería el
    // payload y la etiqueta no cuadraría.
    let corte = recuperado.len() - TAG_LEN;
    let secreto = Zeroizing::new(recuperado[..corte].to_vec());
    if !ct_eq(&etiqueta(&secreto), &recuperado[corte..]) {
        return Err(ShamirError::VerificationFailed);
    }

    Ok(secreto)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- campo ---

    #[test]
    fn gf_mul_cumple_los_axiomas() {
        assert_eq!(gf_mul(0, 0xAB), 0, "el 0 absorbe");
        assert_eq!(gf_mul(1, 0xAB), 0xAB, "el 1 es neutro");
        assert_eq!(gf_mul(0xAB, 1), 0xAB);
        // Conmutatividad y asociatividad sobre todo el campo (256*256 barato).
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(gf_mul(a, b), gf_mul(b, a));
            }
        }
        for a in [1u8, 2, 0x53, 0xCA, 0xFF] {
            for b in [1u8, 3, 0x1B, 0x80, 0xFE] {
                for c in [1u8, 5, 0x7A, 0xFF] {
                    assert_eq!(gf_mul(gf_mul(a, b), c), gf_mul(a, gf_mul(b, c)));
                }
            }
        }
    }

    #[test]
    fn gf_mul_coincide_con_el_vector_conocido_de_aes() {
        // Valores clásicos del campo de AES (polinomio 0x11B).
        assert_eq!(gf_mul(0x57, 0x83), 0xC1);
        assert_eq!(gf_mul(0x57, 0x13), 0xFE);
    }

    #[test]
    fn gf_inv_invierte_todo_elemento_no_nulo() {
        for a in 1..=255u8 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "inverso de {a}");
        }
    }

    // --- reparto ---

    #[test]
    fn cualquier_subconjunto_del_umbral_reconstruye() {
        let secreto = &[0x6Bu8; 64];
        let comparticiones = split(secreto, 3, 5).unwrap();
        assert_eq!(comparticiones.len(), 5);

        // Las 10 combinaciones de 3 entre 5, todas deben reconstruir.
        for i in 0..5 {
            for j in (i + 1)..5 {
                for k in (j + 1)..5 {
                    let sub = [
                        comparticiones[i].clone(),
                        comparticiones[j].clone(),
                        comparticiones[k].clone(),
                    ];
                    assert_eq!(&combine(&sub).unwrap()[..], &secreto[..], "{i},{j},{k}");
                }
            }
        }
    }

    #[test]
    fn menos_del_umbral_no_reconstruye() {
        let comparticiones = split(&[0x11u8; 32], 3, 5).unwrap();
        let sub = [comparticiones[0].clone(), comparticiones[1].clone()];
        assert_eq!(
            combine(&sub),
            Err(ShamirError::NotEnoughShares { needed: 3, got: 2 })
        );
    }

    #[test]
    fn sobran_comparticiones_y_sigue_funcionando() {
        let secreto = &[0x5Eu8; 32];
        let comparticiones = split(secreto, 2, 5).unwrap();
        assert_eq!(&combine(&comparticiones).unwrap()[..], &secreto[..]);
    }

    #[test]
    fn una_comparticion_alterada_se_detecta() {
        let comparticiones = split(&[0x3Cu8; 32], 3, 5).unwrap();
        let mut sub = [
            comparticiones[0].clone(),
            comparticiones[1].clone(),
            comparticiones[2].clone(),
        ];
        sub[1].y[0] ^= 0x01; // un solo bit
        assert_eq!(combine(&sub), Err(ShamirError::VerificationFailed));
    }

    #[test]
    fn no_se_pueden_mezclar_repartos_distintos() {
        // Ya no se detecta comparando campos de cabecera —no queda ninguno en
        // común, que es lo que las hace inenlazables— sino porque lo que sale
        // de interpolar no es el payload y la etiqueta no cuadra.
        let a = split(&[0xAAu8; 32], 2, 3).unwrap();
        let b = split(&[0xBBu8; 32], 2, 3).unwrap();
        let sub = [a[0].clone(), b[1].clone()];
        assert_eq!(combine(&sub), Err(ShamirError::VerificationFailed));
    }

    #[test]
    fn dos_comparticiones_no_se_delatan_como_pareja() {
        // La propiedad que motivó el rediseño: nada en una compartición permite
        // saber si otra pertenece al mismo reparto. Antes la sal y el
        // verificador eran 24 bytes idénticos que las emparejaban a simple
        // vista, y en un archivo con secretos de varios clientes eso los
        // particiona en clases de equivalencia.
        let a = split(&[0xA1u8; 32], 2, 5).unwrap();
        let b = split(&[0xB2u8; 32], 2, 5).unwrap();

        // La cabecera de dos del MISMO reparto solo comparte magic, umbral y
        // longitud — exactamente lo mismo que comparte con una de otro reparto.
        let cab = |s: &Share| s.to_bytes()[..HEADER_LEN].to_vec();
        let mismo: Vec<u8> = cab(&a[0]).iter().zip(cab(&a[1])).filter(|(x, y)| *x == y).map(|(x, _)| *x).collect();
        let ajeno: Vec<u8> = cab(&a[0]).iter().zip(cab(&b[1])).filter(|(x, y)| *x == y).map(|(x, _)| *x).collect();
        assert_eq!(
            mismo.len(),
            ajeno.len(),
            "la cabecera distingue pareja de ajena: quedó un campo enlazable"
        );

        // Y el cuerpo tampoco: son evaluaciones de polinomios independientes.
        assert_ne!(a[0].y, a[1].y);
    }

    #[test]
    fn indices_repetidos_se_rechazan() {
        let comparticiones = split(&[0x11u8; 32], 2, 3).unwrap();
        let sub = [comparticiones[0].clone(), comparticiones[0].clone()];
        assert_eq!(combine(&sub), Err(ShamirError::Inconsistent));
    }

    #[test]
    fn parametros_invalidos() {
        let s = [0x11u8; 32];
        assert_eq!(split(&s, 1, 5), Err(ShamirError::BadParameters));
        assert_eq!(split(&s, 4, 3), Err(ShamirError::BadParameters));
        assert_eq!(split(b"", 2, 3), Err(ShamirError::EmptySecret));
    }

    #[test]
    fn n_maximo_de_255_comparticiones() {
        let secreto = &[0x99u8; 32];
        let comparticiones = split(secreto, 2, 255).unwrap();
        assert_eq!(comparticiones.len(), 255);
        assert_eq!(comparticiones[254].index(), 255);
        let sub = [comparticiones[0].clone(), comparticiones[254].clone()];
        assert_eq!(&combine(&sub).unwrap()[..], &secreto[..]);
    }

    #[test]
    fn el_umbral_puede_ser_igual_a_n() {
        let secreto = &[0x77u8; 48];
        let comparticiones = split(secreto, 4, 4).unwrap();
        assert_eq!(&combine(&comparticiones).unwrap()[..], &secreto[..]);
        let sub = [
            comparticiones[0].clone(),
            comparticiones[1].clone(),
            comparticiones[2].clone(),
        ];
        assert_eq!(
            combine(&sub),
            Err(ShamirError::NotEnoughShares { needed: 4, got: 3 })
        );
    }

    // --- serialización ---

    #[test]
    fn serializacion_ida_y_vuelta() {
        let secreto = [0xA5u8; 64];
        let comparticiones = split(&secreto, 3, 5).unwrap();
        let recuperadas: Vec<Share> = comparticiones
            .iter()
            .map(|s| Share::from_bytes(&s.to_bytes()).unwrap())
            .collect();
        assert_eq!(&combine(&recuperadas[1..4]).unwrap()[..], &secreto[..]);
    }

    #[test]
    fn bytes_no_confiables_se_rechazan_sin_panico() {
        assert_eq!(Share::from_bytes(&[]), Err(ShamirError::Malformed));
        assert_eq!(Share::from_bytes(b"XXXX"), Err(ShamirError::Malformed));

        let comparticiones = split(&[0x11u8; 32], 2, 3).unwrap();
        let buenos = comparticiones[0].to_bytes();

        // Magic alterado.
        let mut malo = buenos.to_vec();
        malo[0] = b'Z';
        assert_eq!(Share::from_bytes(&malo), Err(ShamirError::Malformed));

        // Truncado: la longitud declarada ya no cuadra.
        assert_eq!(
            Share::from_bytes(&buenos[..buenos.len() - 1]),
            Err(ShamirError::Malformed)
        );

        // Longitud mentida en la cabecera.
        let mut mentira = buenos.to_vec();
        mentira[6..10].copy_from_slice(&9999u32.to_be_bytes());
        assert_eq!(Share::from_bytes(&mentira), Err(ShamirError::Malformed));

        // Índice 0 (el del secreto) no es una compartición legítima.
        let mut cero = buenos.to_vec();
        cero[5] = 0;
        assert_eq!(Share::from_bytes(&cero), Err(ShamirError::Malformed));
    }

    #[test]
    fn debug_no_filtra_el_material() {
        let comparticiones = split(&[0xDEu8; 32], 2, 3).unwrap();
        let s = &comparticiones[0];
        let texto = format!("{s:?}");

        // El material (`y`) no debe aparecer en NINGUNA forma: ni como lista de
        // bytes ni en hexadecimal. Un `Debug` derivado lo volcaría entero, y un
        // log de un integrador se llevaría la compartición.
        let como_lista = format!("{:?}", s.y);
        let como_hex: String = s.y.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!texto.contains(&como_lista), "volcó `y` como lista: {texto}");
        assert!(!texto.contains(&como_hex), "volcó `y` en hex: {texto}");

        // Y sí debe traer lo que sirve para diagnosticar sin filtrar nada.
        assert!(texto.contains("threshold"), "{texto}");
        assert!(texto.contains("len"), "{texto}");
    }

    // --- propiedades de secreto ---

    #[test]
    fn comparticiones_distintas_para_el_mismo_secreto() {
        // Dos repartos del mismo secreto no deben coincidir: la sal y los
        // coeficientes son aleatorios. Si coincidieran, habría un RNG muerto.
        let a = split(&[0x42u8; 32], 2, 3).unwrap();
        let b = split(&[0x42u8; 32], 2, 3).unwrap();
        assert_ne!(a[0].y, b[0].y);
    }

    #[test]
    fn el_secreto_no_aparece_en_las_comparticiones() {
        // Con k=n=2 y un secreto muy reconocible, ninguna compartición puede
        // contenerlo en claro.
        let secreto = vec![0x42u8; 32];
        let comparticiones = split(&secreto, 2, 2).unwrap();
        for s in &comparticiones {
            assert_ne!(s.y, secreto);
        }
    }

    #[test]
    fn funciona_con_una_clave_de_firma_realista() {
        // Tamaño de una clave secreta ML-DSA-87: el caso de uso que motiva
        // el módulo (custodia de la clave de firma de un integrador).
        let clave = vec![0x9Cu8; 4896];
        let comparticiones = split(&clave, 3, 5).unwrap();
        let sub = [
            comparticiones[0].clone(),
            comparticiones[3].clone(),
            comparticiones[4].clone(),
        ];
        assert_eq!(&combine(&sub).unwrap()[..], &clave[..]);
    }
}
