// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

//! Honey Encryption: cifrado con **señuelos** para secretos de baja entropía.
//!
//! La idea (Juels & Ristenpart, 2014) es la versión *con demostración* de "una
//! muralla que engaña al culpable": bajo **cualquier** passphrase equivocada, el
//! descifrado no da un error ni basura — da **otro secreto válido y plausible**.
//! Un atacante offline que prueba millones de passphrases nunca recibe la señal
//! "¡acerté!": cada intento le entrega un secreto creíble. Se le retira el
//! *oráculo de éxito* que hace viable la fuerza bruta contra una clave débil.
//!
//! ## Construcción (uniforme, sin dependencias nuevas)
//!
//! El secreto se modela como una secuencia de `L` tokens, cada uno de un
//! alfabeto de tamaño `A` (p. ej. un PIN: `L` dígitos, `A = 10`; una frase
//! mnemónica: `L` palabras de una lista de `A` términos). El espacio de mensajes
//! **es exactamente** el conjunto de secuencias válidas `A^L`, así que todo
//! valor descifrado *es* un secreto plausible. El cifrado es un one-time-pad en
//! base `A` cuyo flujo de clave sale de Argon2id + HKDF:
//!
//! ```text
//!   k_i  = HKDF(Argon2id(passphrase, salt, pepper))  reducido a [0, A)
//!   c_i  = (t_i + k_i) mod A          (cifrar)
//!   t_i  = (c_i - k_i) mod A          (descifrar)
//! ```
//!
//! Passphrase equivocada -> `k'_i` uniforme -> `t'_i` uniforme -> secuencia
//! uniforme = **señuelo perfecto** para la distribución uniforme.
//!
//! ## Modelo de amenaza — LÉELO
//!
//! - **Qué defiende:** fuerza bruta offline contra un secreto de baja entropía
//!   protegido por una passphrase débil. Elimina el oráculo de "clave correcta".
//! - **Qué CEDE a propósito:** **NO hay autenticación**. Un tag delataría la
//!   clave correcta (volvería a ser un oráculo), así que este modo *no lleva
//!   tag*. En consecuencia **no detecta manipulación ni corrupción**: alterar el
//!   contenedor produce en silencio otro secreto válido. Es inherente a Honey
//!   Encryption y por eso este modo es un COMPAÑERO especializado, no un
//!   sustituto del núcleo AEAD autenticado ([`crate::api::encode`]).
//! - **Dónde NO sirve:** datos arbitrarios de alta entropía. Solo tiene sentido
//!   cuando *toda* decodificación es plausible, es decir, secuencias uniformes de
//!   alfabeto fijo. No cifres aquí un documento: cífralo con el AEAD.
//! - **Known-plaintext:** si el atacante conoce parte del secreto, puede filtrar
//!   los señuelos que la contradicen. Reduce (no elimina) el beneficio.

use crate::antihacker;
use crate::kdf::{self, KdfParams, SALT_LEN};

/// Etiqueta de dominio del flujo de clave honey.
const HONEY_INFO: &[u8] = b"quipu-honey-v1/pad";
/// Bytes de flujo por token (64 bits): el sesgo de `u64 % A` es <= A/2^64,
/// despreciable (< 2^-48 para A <= 2^16).
const STREAM_BYTES_PER_TOKEN: usize = 8;
/// Bytes mágicos del contenedor honey.
const MAGIC: [u8; 4] = *b"QHNY";
/// Versión de formato.
const VERSION: u8 = 1;
/// Cabecera: magic(4) ver(1) salt(16) mem(4) iter(4) par(4) A(2) L(4) = 39.
const HEADER_LEN: usize = 4 + 1 + SALT_LEN + 4 + 4 + 4 + 2 + 4;
/// Tope de tokens: mantiene el flujo HKDF dentro de su límite (255*32 bytes) y
/// acota la memoria al descifrar un contenedor no confiable.
const MAX_TOKENS: usize = 1000;

/// Errores del modo honey. Nótese que **NO** existe un error de "clave
/// incorrecta": esa es justamente la propiedad del esquema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoneyError {
    /// Un token queda fuera del alfabeto (`>= size`).
    TokenOutOfRange,
    /// El alfabeto es degenerado (`size < 2`).
    BadAlphabet,
    /// La secuencia está vacía o excede [`MAX_TOKENS`].
    BadLength,
    /// El contenedor es más corto que una cabecera o que su payload declarado.
    Truncated,
    /// Bytes mágicos incorrectos.
    BadMagic,
    /// Versión de formato no soportada.
    UnsupportedVersion(u8),
    /// Parámetros KDF fuera de rango (anti-DoS antes de derivar).
    InsaneKdf,
}

/// Alfabeto uniforme de tamaño `size` (número de símbolos distintos).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alphabet {
    size: u16,
}

impl Alphabet {
    /// Crea un alfabeto de `size` símbolos (`size >= 2`).
    pub fn new(size: u16) -> Result<Self, HoneyError> {
        if size < 2 {
            return Err(HoneyError::BadAlphabet);
        }
        Ok(Self { size })
    }

    /// Alfabeto decimal (PIN / secreto numérico): 10 símbolos.
    pub fn digits() -> Self {
        Self { size: 10 }
    }

    /// Número de símbolos.
    pub fn size(&self) -> u16 {
        self.size
    }
}

/// Opciones del cifrado honey.
#[derive(Debug, Clone)]
pub struct HoneyOptions<'a> {
    /// Pepper opcional (secreto fuera del dato), como en el modo por defecto.
    pub pepper: &'a [u8],
    /// Coste Argon2id.
    pub kdf_params: KdfParams,
}

impl Default for HoneyOptions<'_> {
    fn default() -> Self {
        Self {
            pepper: b"",
            kdf_params: KdfParams::default(),
        }
    }
}

/// La cabecera QHNY ya parseada. TODO lo que hay aquí viaja EN CLARO delante del
/// payload: ni el salt ni el coste KDF son secretos.
struct Cabecera {
    salt: [u8; SALT_LEN],
    params: KdfParams,
    size: u16,
    len: usize,
    /// Desplazamiento del primer byte del payload cifrado.
    offset: usize,
}

/// Parsea y valida la cabecera QHNY (magic, versión, alfabeto, longitud, coste
/// KDF). Es la ÚNICA lectura de esos desplazamientos: `decrypt` y el accesor
/// público de más abajo la comparten, para que un cambio de formato se arregle en
/// un solo sitio (directiva 32) y no se reconstruya a ciegas en dos.
fn leer_cabecera(blob: &[u8]) -> Result<Cabecera, HoneyError> {
    if blob.len() < HEADER_LEN {
        return Err(HoneyError::Truncated);
    }
    if blob[0..4] != MAGIC {
        return Err(HoneyError::BadMagic);
    }
    let version = blob[4];
    if version != VERSION {
        return Err(HoneyError::UnsupportedVersion(version));
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&blob[5..5 + SALT_LEN]);
    let mut p = 5 + SALT_LEN;
    let mem_kib = u32::from_be_bytes(blob[p..p + 4].try_into().expect("4 bytes"));
    p += 4;
    let iterations = u32::from_be_bytes(blob[p..p + 4].try_into().expect("4 bytes"));
    p += 4;
    let parallelism = u32::from_be_bytes(blob[p..p + 4].try_into().expect("4 bytes"));
    p += 4;
    let size = u16::from_be_bytes(blob[p..p + 2].try_into().expect("2 bytes"));
    p += 2;
    let len = u32::from_be_bytes(blob[p..p + 4].try_into().expect("4 bytes")) as usize;
    p += 4;

    if size < 2 {
        return Err(HoneyError::BadAlphabet);
    }
    if len == 0 || len > MAX_TOKENS {
        return Err(HoneyError::BadLength);
    }
    let params = KdfParams {
        mem_kib,
        iterations,
        parallelism,
    };
    if !params.is_sane() {
        return Err(HoneyError::InsaneKdf);
    }
    Ok(Cabecera {
        salt,
        params,
        size,
        len,
        offset: p,
    })
}

/// Lee de un contenedor honey los parámetros PÚBLICOS de su cabecera: el salt y
/// el coste KDF. Como en `stream`, los dos viajan en claro y exponerlos no revela
/// nada nuevo; sirve para reproducir la derivación de la clave maestra sin
/// adivinar el formato (el banco de residuo T6 lo usa para saber qué buscar).
pub fn parametros_de_cabecera(blob: &[u8]) -> Result<([u8; SALT_LEN], KdfParams), HoneyError> {
    let c = leer_cabecera(blob)?;
    Ok((c.salt, c.params))
}

/// Deriva el flujo de dígitos de clave `k_i in [0, A)` para `len` tokens.
fn keystream_digits(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
    pepper: &[u8],
    params: &KdfParams,
    size: u16,
    len: usize,
) -> Vec<u16> {
    let mut master = kdf::derive_master_key(passphrase, salt, pepper, params);
    let mut buf = vec![0u8; len * STREAM_BYTES_PER_TOKEN];
    kdf::derive_stream(&master, HONEY_INFO, &mut buf);
    antihacker::wipe(&mut master);

    let a = size as u64;
    let mut out = Vec::with_capacity(len);
    for chunk in buf.chunks_exact(STREAM_BYTES_PER_TOKEN) {
        let v = u64::from_be_bytes(chunk.try_into().expect("8 bytes"));
        out.push((v % a) as u16);
    }
    antihacker::wipe(&mut buf);
    out
}

/// Cifra una secuencia de `tokens` (cada uno `< alphabet.size`) en modo honey.
/// El contenedor resultante **no lleva tag**: cualquier passphrase lo descifra a
/// un secreto plausible (ver el modelo de amenaza del módulo).
pub fn encrypt(
    tokens: &[u16],
    alphabet: Alphabet,
    passphrase: &str,
    opts: &HoneyOptions,
) -> Result<Vec<u8>, HoneyError> {
    if tokens.is_empty() || tokens.len() > MAX_TOKENS {
        return Err(HoneyError::BadLength);
    }
    if tokens.iter().any(|&t| t >= alphabet.size) {
        return Err(HoneyError::TokenOutOfRange);
    }

    let mut salt = [0u8; SALT_LEN];
    crate::aleatorio::llenar(&mut salt).expect("RNG del sistema");

    let ks = keystream_digits(
        passphrase,
        &salt,
        opts.pepper,
        &opts.kdf_params,
        alphabet.size,
        tokens.len(),
    );
    let a = alphabet.size;

    let mut out = Vec::with_capacity(HEADER_LEN + tokens.len() * 2);
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&opts.kdf_params.mem_kib.to_be_bytes());
    out.extend_from_slice(&opts.kdf_params.iterations.to_be_bytes());
    out.extend_from_slice(&opts.kdf_params.parallelism.to_be_bytes());
    out.extend_from_slice(&a.to_be_bytes());
    out.extend_from_slice(&(tokens.len() as u32).to_be_bytes());
    for (i, &t) in tokens.iter().enumerate() {
        let c = ((t as u32 + ks[i] as u32) % a as u32) as u16;
        out.extend_from_slice(&c.to_be_bytes());
    }
    Ok(out)
}

/// Descifra un contenedor honey. Con la passphrase correcta recupera el secreto;
/// con **cualquier otra** devuelve un señuelo válido (no un error). Solo falla
/// por problemas *estructurales* del contenedor (magic/versión/truncado/params),
/// que son deterministas respecto de la entrada y no revelan nada de la clave.
pub fn decrypt(blob: &[u8], passphrase: &str, pepper: &[u8]) -> Result<Vec<u16>, HoneyError> {
    let Cabecera {
        salt,
        params,
        size,
        len,
        offset: p,
    } = leer_cabecera(blob)?;
    if blob.len() < HEADER_LEN + len * 2 {
        return Err(HoneyError::Truncated);
    }

    let ks = keystream_digits(passphrase, &salt, pepper, &params, size, len);
    let a = size as u32;
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        let c = u16::from_be_bytes(blob[p + i * 2..p + i * 2 + 2].try_into().expect("2 bytes"));
        // (c - k) mod A, sin restas negativas.
        let t = ((c as u32 + a - ks[i] as u32) % a) as u16;
        out.push(t);
    }
    Ok(out)
}

// ----------------------------- Conveniencia: PIN / numérico -----------------------------

/// Cifra un PIN (o secreto numérico) dado como cadena de dígitos `0-9`.
pub fn encrypt_pin(pin: &str, passphrase: &str, opts: &HoneyOptions) -> Result<Vec<u8>, HoneyError> {
    let tokens = pin_to_tokens(pin)?;
    encrypt(&tokens, Alphabet::digits(), passphrase, opts)
}

/// Descifra un contenedor honey numérico y lo devuelve como cadena de dígitos.
/// Con una passphrase equivocada, devuelve **otro PIN plausible**, no un error.
pub fn decrypt_pin(blob: &[u8], passphrase: &str, pepper: &[u8]) -> Result<String, HoneyError> {
    // **EL ALFABETO SE COMPRUEBA ANTES DE MAPEAR A DÍGITOS.**
    //
    // El campo `size` de la cabecera QHNY lo elige quien manda el contenedor, va
    // en claro y —por diseño de honey— **no lo autentica nada**. `leer_cabecera`
    // lo acepta hasta 65535. Sin esta comprobación, `(b'0' + t as u8)` con
    // `t ∈ [208, 255]` DESBORDA `u8`: en el perfil `dev` de cualquier consumidor,
    // que lleva `overflow-checks`, eso es un **pánico**; en release envuelve y
    // devuelve `\0`, `ÿ`, `/`… o sea una «cadena de dígitos» que no lo es.
    //
    // Las dos cosas rompen lo que este modo promete: que con la contraseña
    // equivocada salga **otro PIN plausible**, no un error y no basura. Un
    // pánico no es un secreto válido. Lo cazó la auditoría del 2026-08-17, y la
    // causa raíz es que los dos fuzzers del árbol clavan el alfabeto a 10 y
    // ninguno llama a esta función.
    if leer_cabecera(blob)?.size != 10 {
        return Err(HoneyError::TokenOutOfRange);
    }
    let tokens = decrypt(blob, passphrase, pepper)?;
    Ok(tokens
        .iter()
        .map(|&t| char::from_digit(u32::from(t), 10).ok_or(HoneyError::TokenOutOfRange))
        .collect::<Result<String, _>>()?)
}

fn pin_to_tokens(pin: &str) -> Result<Vec<u16>, HoneyError> {
    if pin.is_empty() || pin.len() > MAX_TOKENS {
        return Err(HoneyError::BadLength);
    }
    pin.chars()
        .map(|c| c.to_digit(10).map(|d| d as u16).ok_or(HoneyError::TokenOutOfRange))
        .collect()
}

#[cfg(test)]
mod pruebas_del_alfabeto_hostil {
    use super::*;

    /// **UN `size` HOSTIL EN LA CABECERA NO PUEDE ROMPER `decrypt_pin`.**
    ///
    /// El campo va en claro y no lo autentica nada —honey no autentica, ésa es
    /// su propiedad—, así que lo elige el atacante. Antes del 2026-08-17,
    /// `(b'0' + t as u8)` con tokens grandes desbordaba `u8`: pánico en debug,
    /// basura en release. Las dos rompen la promesa del modo, que es devolver
    /// **otro PIN plausible** y nunca un error ni un carácter que no sea dígito.
    #[test]
    fn un_alfabeto_hostil_no_revienta_ni_devuelve_algo_que_no_sea_un_pin() {
        let opts = HoneyOptions {
            kdf_params: crate::kdf::KdfParams { mem_kib: 64, iterations: 1, parallelism: 1 },
            pepper: b"",
        };
        let bueno = encrypt_pin("482913", "clave", &opts).expect("cifra");

        // El campo `size` son los 2 bytes que preceden a los 4 de `len`.
        let pos_size = HEADER_LEN - 6;
        for hostil in [2u16, 11, 255, 1000, 40000, u16::MAX] {
            let mut tocado = bueno.clone();
            tocado[pos_size..pos_size + 2].copy_from_slice(&hostil.to_be_bytes());
            match decrypt_pin(&tocado, "clave", b"") {
                Err(_) => {}
                Ok(s) => panic!(
                    "con size={hostil} devolvió {s:?}: o es Err, o son dígitos, \
                     y desde luego no puede entrar en pánico"
                ),
            }
        }

        // EL CONTROL, sin el cual lo de arriba pasaría con un `decrypt_pin` que
        // fallara siempre: intacto, abre y son seis dígitos.
        let claro = decrypt_pin(&bueno, "clave", b"").expect("el contenedor intacto abre");
        assert_eq!(claro, "482913");
        // Y con la contraseña equivocada sigue dando un PIN plausible, que es la
        // propiedad entera del modo.
        let senuelo = decrypt_pin(&bueno, "otra", b"").expect("honey no da error con clave mala");
        assert_eq!(senuelo.len(), 6, "el señuelo tiene que medir lo mismo");
        assert!(senuelo.chars().all(|c| c.is_ascii_digit()), "y ser dígitos: {senuelo}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cheap() -> HoneyOptions<'static> {
        HoneyOptions {
            pepper: b"",
            kdf_params: KdfParams {
                mem_kib: 64,
                iterations: 1,
                parallelism: 1,
            },
        }
    }

    #[test]
    fn pin_round_trips_with_correct_passphrase() {
        let blob = encrypt_pin("4913", "correcta", &cheap()).unwrap();
        assert_eq!(decrypt_pin(&blob, "correcta", b"").unwrap(), "4913");
    }

    #[test]
    fn wrong_passphrase_yields_a_valid_decoy_not_an_error() {
        let blob = encrypt_pin("4913", "correcta", &cheap()).unwrap();
        // La propiedad honey: NO hay error, sale otro PIN válido.
        let decoy = decrypt_pin(&blob, "incorrecta", b"").unwrap();
        assert_eq!(decoy.len(), 4, "el señuelo tiene la misma longitud");
        assert!(decoy.chars().all(|c| c.is_ascii_digit()), "señuelo válido: {decoy}");
    }

    #[test]
    fn no_success_oracle_over_a_brute_force_batch() {
        // Un atacante que prueba muchas passphrases NUNCA recibe una señal
        // distinta para la correcta: todas devuelven un PIN válido de 6 dígitos.
        let blob = encrypt_pin("271828", "la-correcta", &cheap()).unwrap();
        let mut seen = std::collections::HashSet::new();
        for i in 0..200 {
            let guess = format!("intento-{i}");
            let pin = decrypt_pin(&blob, &guess, b"").expect("nunca hay error de clave");
            assert_eq!(pin.len(), 6);
            assert!(pin.chars().all(|c| c.is_ascii_digit()));
            seen.insert(pin);
        }
        // Los señuelos varían (no es una constante): hay dispersión real.
        assert!(seen.len() > 100, "señuelos poco dispersos: {}", seen.len());
    }

    #[test]
    fn decoys_are_roughly_uniform() {
        // El primer dígito de los señuelos debe repartirse por los 10 valores.
        let blob = encrypt_pin("0000", "real", &cheap()).unwrap();
        let mut hist = [0u32; 10];
        for i in 0..1000 {
            let pin = decrypt_pin(&blob, &format!("g{i}"), b"").unwrap();
            let d = pin.as_bytes()[0] - b'0';
            hist[d as usize] += 1;
        }
        // Ningún dígito debe faltar ni acaparar (uniforme ~100 cada uno).
        assert!(hist.iter().all(|&h| h > 40 && h < 180), "histograma sesgado: {hist:?}");
    }

    #[test]
    fn pepper_changes_the_result() {
        let blob = encrypt_pin("4913", "clave", &cheap()).unwrap();
        // Con el pepper correcto (vacío) sale el real; con otro, un señuelo.
        assert_eq!(decrypt_pin(&blob, "clave", b"").unwrap(), "4913");
        let with_pepper = decrypt_pin(&blob, "clave", b"pepper-distinto").unwrap();
        assert_ne!(with_pepper, "4913");
        assert_eq!(with_pepper.len(), 4);
    }

    #[test]
    fn deterministic_given_the_same_salt() {
        // Mismo salt (mismo blob) + misma passphrase -> mismo resultado.
        let blob = encrypt_pin("1234", "clave", &cheap()).unwrap();
        assert_eq!(
            decrypt_pin(&blob, "otra", b"").unwrap(),
            decrypt_pin(&blob, "otra", b"").unwrap()
        );
    }

    #[test]
    fn generic_alphabet_round_trips() {
        // Alfabeto de 2048 (estilo lista mnemónica): tokens arbitrarios válidos.
        let ab = Alphabet::new(2048).unwrap();
        let secret = vec![1337u16, 42, 2000, 0, 2047];
        let blob = encrypt(&secret, ab, "frase-clave", &cheap()).unwrap();
        assert_eq!(decrypt(&blob, "frase-clave", b"").unwrap(), secret);
        // Passphrase equivocada -> secuencia válida (todos < 2048), no error.
        let decoy = decrypt(&blob, "otra-frase", b"").unwrap();
        assert_eq!(decoy.len(), 5);
        assert!(decoy.iter().all(|&t| t < 2048));
    }

    #[test]
    fn rejects_token_out_of_range() {
        let ab = Alphabet::new(10).unwrap();
        assert_eq!(encrypt(&[9, 10], ab, "k", &cheap()), Err(HoneyError::TokenOutOfRange));
    }

    #[test]
    fn rejects_degenerate_alphabet() {
        assert_eq!(Alphabet::new(1).err(), Some(HoneyError::BadAlphabet));
    }

    #[test]
    fn decrypt_rejects_structural_corruption() {
        let mut blob = encrypt_pin("4913", "clave", &cheap()).unwrap();
        blob[0] ^= 0xFF; // rompe el magic
        assert_eq!(decrypt_pin(&blob, "clave", b""), Err(HoneyError::BadMagic));
    }

    #[test]
    fn decrypt_rejects_insane_kdf_params_before_deriving() {
        let mut blob = encrypt_pin("4913", "clave", &cheap()).unwrap();
        // Sobrescribe mem_kib con un valor absurdo (offset 5 + SALT_LEN).
        let off = 5 + SALT_LEN;
        blob[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        assert_eq!(decrypt_pin(&blob, "clave", b""), Err(HoneyError::InsaneKdf));
    }
}
