// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

//! Fachada de la librería: une todo el pipeline.
//!
//! encode: datos -> KDF(passphrase+pepper) -> AEAD -> contenedor -> codec -> diccionario -> símbolos
//! decode: símbolos -> diccionario -> codec -> contenedor -> KDF -> AEAD -> datos
//!
//! La seguridad vive en KDF + AEAD. El codec y el diccionario son representación.

use crate::cipher::{self, NONCE_LEN};
use crate::codec;
use crate::container::{self, ContainerError, Header, VERSION};
// `HuellaDeCodebook` da el `.fingerprint()` de ESTE perfil (SHA-256 truncado).
// El codebook en sí es agnóstico y vive en `quipu-nucleo`; el hash no.
use crate::dictionary::{Dictionary, DictionaryError, HuellaDeCodebook};
use crate::kdf::{self, KdfParams, SALT_LEN};
use crate::antihacker;
use crate::oprf_net;
use crate::pqhybrid;
use crate::pqsign;
use crate::prelayers;
use crate::voprf;

pub use crate::stream::{
    decrypt_stream, decrypt_stream_bytes, encrypt_stream, encrypt_stream_bytes, StreamError,
    StreamOptions,
};

/// Etiqueta de dominio HKDF para la subclave del reparto ciego. Distinta de la
/// del cifrado normal: la misma passphrase no deriva dos veces el mismo
/// material para dos modos distintos.
#[cfg(feature = "blindaje")]
const BLINDAJE_SUBKEY_INFO: &[u8] = b"quipu/v1/blindaje";

/// Etiqueta de dominio HKDF para la subclave de cifrado.
const CIPHER_SUBKEY_INFO: &[u8] = b"quipu/v1/cipher";

/// Opciones de codificación.
pub struct Options<'a> {
    /// Secreto que vive fuera del dato (código/HSM/env). `b""` si no se usa.
    pub pepper: &'a [u8],
    /// Coste Argon2id.
    ///
    /// **Use uno de [`KdfParams::canonicos`]** —`LIGERO`, `EQUILIBRADO` (el
    /// defecto) o `FUERTE`— salvo que tenga un motivo concreto para no hacerlo.
    ///
    /// No es una recomendación de rendimiento: estos tres valores **viajan en
    /// claro en la cabecera** y son idénticos entre todos los contenedores que
    /// usted escriba. Ajustados a mano son **una huella de su configuración**
    /// que agrupa sus archivos en un corpus de procedencia mezclada; en la
    /// escalera, se ve igual que todo el mundo. Medido y declarado en N9 de
    /// `docs/THREAT_MODEL.md`.
    ///
    /// Se acepta cualquier valor sensato: quien tenga una razón real —un
    /// dispositivo con poca memoria, una política que exija otro coste— no
    /// puede quedarse sin camino. Lo que se hace es decirlo.
    pub kdf_params: KdfParams,
    /// **RESERVADO Y OBSOLETO. Déjelo en 0.**
    ///
    /// Se escribe en claro en la cabecera y **nunca se lee**: verificado en las
    /// dos implementaciones — quien decide qué alfabeto se usó es la huella
    /// (`codebook_hash_prefix`), que sí se comprueba. Este campo no entrega
    /// nada.
    ///
    /// Y no es inocuo: son **16 bits de metadato en claro, elegidos por quien
    /// cifra y estables entre todos sus contenedores**. Ponerle un valor con
    /// significado —un identificador de inquilino, de usuario, de documento—
    /// convierte cada archivo en enlazable con los demás del mismo dueño. Ver
    /// N9 en `docs/THREAT_MODEL.md`, con la medición.
    ///
    /// **Por qué NO se rechaza un valor distinto de cero**, a diferencia de
    /// `flags`: este campo es público y ajustable desde la 0.10.0. Rechazarlo al
    /// descifrar dejaría ILEGIBLE PARA SIEMPRE cualquier contenedor que alguien
    /// haya creado con él. Datos huérfanos y sin recurso, a cambio de limpieza.
    /// Se marca, se documenta, y se quita en la próxima ruptura de formato —
    /// cuando ya nadie lo escriba.
    pub codebook_id: u16,
}

impl Default for Options<'_> {
    fn default() -> Self {
        Self {
            pepper: b"",
            kdf_params: KdfParams::default(),
            codebook_id: 0,
        }
    }
}

/// Errores de decodificación.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// Un símbolo no pertenece al diccionario.
    Symbol(DictionaryError),
    /// La cabecera del contenedor es inválida.
    Container(ContainerError),
    /// El codebook no corresponde al usado al codificar.
    CodebookMismatch,
    /// Descifrado fallido: passphrase/pepper incorrectos o datos alterados.
    Decrypt,
    /// Los parámetros del KDF que trae la cabecera están **fuera de los límites
    /// seguros**, así que no se deriva nada y no se intenta descifrar.
    ///
    /// **Es corrupción de FORMATO, no una contraseña equivocada**, y por eso
    /// tiene variante propia. Hasta el 2026-08-17 salía como [`Self::Decrypt`],
    /// que se documenta como «passphrase incorrectos o datos alterados»: quien
    /// lo recibiera reintentaría su contraseña buena media hora. Es exactamente
    /// el razonamiento que ya sostenía a [`Self::ModoNoCompilado`] y a
    /// [`Self::BlindajeDeOtraVersion`], aplicado en un renglón y no en el otro
    /// del mismo archivo — y `StreamError::InsaneKdf` demuestra que el proyecto
    /// ya sabía cómo.
    ///
    /// **No abre ningún oráculo**: el veredicto es independiente de la clave —el
    /// Argon2id ni se ejecuta— así que no distingue nada que quien tenga el
    /// archivo no pueda leer ya con un editor hexadecimal.
    ///
    /// Sin carga, por lo mismo que `ModoNoCompilado`: el enum no puede crecer.
    KdfFueraDeRango,
    /// La firma híbrida no valida: mensaje alterado o firmante incorrecto.
    BadSignature,
    /// El contenedor declara un modo que este binario NO tiene compilado.
    ///
    /// Hoy solo puede ser el reparto ciego: recompile con `--features blindaje`.
    /// Existe para que la ausencia de la feature falle DICIÉNDOLO: sin este
    /// error, un binario sin la feature vería el flag, no sabría qué hacer con
    /// él y el camino más corto sería tratar el contenido como un ciphertext
    /// normal — que fallaría el AEAD y saldría como `Decrypt`, mandando a quien
    /// lo lea a buscar una passphrase equivocada durante media hora.
    ///
    /// **NO LLEVA CARGA, y eso es deliberado.** La primera versión traía un
    /// `&'static str` con el motivo. Dieciséis bytes, y bastaron para romper
    /// `tests/residuo_memoria.rs`: al crecer el enum crece
    /// `Result<Vec<u8>, DecodeError>`, se mueven los marcos y la clave de
    /// contenido acaba **fuera de los 128 KiB que alcanza
    /// `antihacker::limpiar_pila`**. El acoplamiento no lo conocía nadie; lo
    /// vigila ahora `tests::los_result_del_camino_de_descifrado_no_crecen`.
    ModoNoCompilado,
    /// El contenedor lleva un blindaje de **otra versión del formato** (hoy: un
    /// `QBL1`, anterior al 2026-08-17). No es que la contraseña esté mal.
    ///
    /// # Por qué no se colapsa en [`DecodeError::Decrypt`], que es lo que hacía
    ///
    /// Lo cazó la revisión de seguridad: `blindaje::descifrar` distingue
    /// «esto dice ser de otra versión» ([`crate::blindaje::BlindajeError::OtraVersion`])
    /// de «el marco no cuadra» (`Formato`) y de «no autentica», y aquí se
    /// colapsaban los tres en `Decrypt`.
    ///
    /// **El error solo se emite si el contenedor AUTENTICA bajo la versión que
    /// dice ser** — ver el rustdoc de `BlindajeError::OtraVersion`. La marca viaja
    /// en claro, pero afirmarla exige abrirla, así que es un hecho y no una
    /// pista. Sin el diagnóstico, quien
    /// guardara un artefacto de la v1 recibiría «no se pudo descifrar» y
    /// reintentaría una y otra vez la frase que SÍ es correcta — el dato ausente
    /// sustituido por el diagnóstico por defecto, que es la directiva 20 al
    /// revés.
    ///
    /// **Y no se oculta nada a ningún atacante distinguiéndolo**: la marca
    /// `QBL*` viaja EN CLARO dentro del contenedor, así que cualquiera con el
    /// archivo la lee sin ejecutar nada. `Formato` solo depende de bytes que el
    /// propio atacante escribió, nunca de la clave: no hay oráculo que abrir.
    /// Colapsarlo tenía coste y beneficio cero.
    ///
    /// **Sin carga**, por lo mismo que [`DecodeError::ModoNoCompilado`]: hacer
    /// crecer este enum mueve los marcos de pila y saca secretos del alcance de
    /// `antihacker::limpiar_pila`. Lo vigila `tests::los_result_del_camino_de_descifrado_no_crecen`.
    BlindajeDeOtraVersion,
}

/// Codifica `data` protegido por `passphrase`, representado con `dict`.
pub fn encode(data: &[u8], passphrase: &str, dict: &Dictionary, opts: &Options) -> String {
    // Autoprueba de arranque: una vez por proceso. Tras la primera, el coste
    // medido es de ~8,7 ns por llamada — despreciable, y órdenes de magnitud
    // menor que el Argon2id que esta misma función va a ejecutar (64 MiB, 3
    // iteraciones por defecto). No tiene sentido dejar la ruta más usada sin
    // verificar para ahorrar eso.
    crate::selftest::ensure();

    let blob = encode_to_blob(data, passphrase, dict.fingerprint(), opts);
    let indices = codec::encode_base_n(&blob, dict.base());
    dict.encode(&indices)
        .expect("los índices del codec están en [0, base)")
}

/// Como [`encode`] pero con **reparto ciego** (feature `blindaje`): el contenido
/// va en dos AEAD de dos crates distintos y ninguno de los dos recibe el texto
/// en claro. Defiende de que una de las dos librerías esté comprometida.
///
/// **Lo abre [`decode`], la misma de siempre**: el modo viaja en la cabecera, así
/// que quien descifra no tiene que saberlo de antemano. Un binario sin la
/// feature devuelve [`DecodeError::ModoNoCompilado`], y uno anterior al
/// 2026-08-16 devuelve `FlagsDesconocidos` — en los dos casos en voz alta.
///
/// **Cuesta ~2× de símbolos.** Ver `src/blindaje.rs` para por qué ese precio no
/// es optimizable.
#[cfg(feature = "blindaje")]
pub fn encode_blindado(
    data: &[u8],
    passphrase: &str,
    dict: &Dictionary,
    opts: &Options,
) -> String {
    crate::selftest::ensure();
    let blob = encode_to_blob_blindado(data, passphrase, dict.fingerprint(), opts);
    let indices = codec::encode_base_n(&blob, dict.base());
    dict.encode(&indices)
        .expect("los índices del codec están en [0, base)")
}

/// Operación inversa de [`encode`] **y de [`encode_blindado`]**: el modo lo
/// declara la cabecera del artefacto, no quien lo abre.
pub fn decode(
    symbols: &str,
    passphrase: &str,
    dict: &Dictionary,
    pepper: &[u8],
) -> Result<Vec<u8>, DecodeError> {
    // Autoprueba de arranque: una vez por proceso. Tras la primera, el coste
    // medido es de ~8,7 ns por llamada — despreciable, y órdenes de magnitud
    // menor que el Argon2id que esta misma función va a ejecutar (64 MiB, 3
    // iteraciones por defecto). No tiene sentido dejar la ruta más usada sin
    // verificar para ahorrar eso.
    crate::selftest::ensure();

    let indices = dict.decode(symbols).map_err(DecodeError::Symbol)?;
    let blob = codec::decode_base_n(&indices, dict.base());
    decode_from_blob(&blob, passphrase, dict.fingerprint(), pepper)
}

/// Construye el contenedor binario cifrado (modo passphrase), sin la capa de
/// representación. Reutilizable por canales alternativos (p. ej. imagen).
pub fn encode_to_blob(
    data: &[u8],
    passphrase: &str,
    codebook_fingerprint: [u8; 8],
    opts: &Options,
) -> Vec<u8> {
    // LA AUTOPRUEBA VA EN TODA PUERTA DE ENTRADA, no solo en las tres de arriba.
    // `selftest.rs` promete que «el núcleo la invoca solo, así que no hay que
    // acordarse», y hasta el 2026-08-17 eso era falso para media superficie
    // pública: `encode_to_blob` —documentado como la vía para canales
    // alternativos—, `decode_from_blob`, `encode_signed` y `decode_verified` no
    // la llamaban. El caso que sobrevive a cualquier objeción es el que el
    // propio módulo describe: una primitiva CONSISTENTEMENTE rota pasa el
    // round-trip local del integrador y produce contenedores incorrectos que
    // nadie descubre hasta dos años después. Coste tras la primera llamada del
    // proceso: ~8,7 ns.
    crate::selftest::ensure();
    armar_blob(data, passphrase, codebook_fingerprint, opts, 0)
}

/// Como [`encode_to_blob`] pero con **reparto ciego**: el contenido va en dos
/// AEAD de dos crates distintos y ninguno de los dos recibe el texto en claro.
///
/// El contenedor es el MISMO —misma cabecera, misma versión, mismo AAD—; lo
/// único que cambia es el bit [`container::FLAG_BLINDAJE`] y qué hay dentro. Un
/// decodificador anterior al 2026-08-16 se encuentra el bit y **se niega en voz
/// alta** (`FlagsDesconocidos`) en vez de malinterpretar el contenido.
///
/// **El blob resulta ~2× más grande**, y en el camino simbólico eso es el doble
/// de glifos. Ver `src/blindaje.rs` para el porqué de que ese precio no sea
/// optimizable.
#[cfg(feature = "blindaje")]
pub fn encode_to_blob_blindado(
    data: &[u8],
    passphrase: &str,
    codebook_fingerprint: [u8; 8],
    opts: &Options,
) -> Vec<u8> {
    // LA AUTOPRUEBA VA EN TODA PUERTA DE ENTRADA, no solo en las tres de arriba.
    // `selftest.rs` promete que «el núcleo la invoca solo, así que no hay que
    // acordarse», y hasta el 2026-08-17 eso era falso para media superficie
    // pública: `encode_to_blob` —documentado como la vía para canales
    // alternativos—, `decode_from_blob`, `encode_signed` y `decode_verified` no
    // la llamaban. El caso que sobrevive a cualquier objeción es el que el
    // propio módulo describe: una primitiva CONSISTENTEMENTE rota pasa el
    // round-trip local del integrador y produce contenedores incorrectos que
    // nadie descubre hasta dos años después. Coste tras la primera llamada del
    // proceso: ~8,7 ns.
    crate::selftest::ensure();
    armar_blob(
        data,
        passphrase,
        codebook_fingerprint,
        opts,
        container::FLAG_BLINDAJE,
    )
}

/// El cuerpo común de los dos, con el modo en `flags`.
fn armar_blob(
    data: &[u8],
    passphrase: &str,
    codebook_fingerprint: [u8; 8],
    opts: &Options,
    flags: u8,
) -> Vec<u8> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    crate::aleatorio::llenar(&mut salt).expect("RNG del sistema");
    crate::aleatorio::llenar(&mut nonce).expect("RNG del sistema");

    let mut master = kdf::derive_master_key(passphrase, &salt, opts.pepper, &opts.kdf_params);
    let mut cipher_key = kdf::derive_subkey(&master, CIPHER_SUBKEY_INFO);
    // El reparto ciego deriva SU propia subclave de la misma maestra, con otra
    // etiqueta, y se deriva AQUÍ —antes del borrado— en vez de copiarse la
    // maestra para más tarde.
    //
    // La primera versión sí la copiaba, y el banco de residuo la cazó: una copia
    // de la maestra sobrevivía a la operación entera. Es exactamente para lo que
    // existe ese banco, y la pilló porque el gate empezó a correr las features
    // opt-in el mismo día. Sin eso, la fuga habría entrado sin que nada se
    // quejara.
    #[cfg(feature = "blindaje")]
    let mut clave_blindaje = (flags & container::FLAG_BLINDAJE != 0)
        .then(|| kdf::derive_subkey(&master, BLINDAJE_SUBKEY_INFO));
    antihacker::wipe(&mut master); // ya no se necesita tras derivar las subclaves

    let header = Header {
        version: VERSION,
        flags,
        // PASO 2 DE LA RETIRADA DE `codebook_id` (2026-08-01): se escribe
        // SIEMPRE 0, ignorando lo que pida el llamante.
        //
        // El campo nunca se lee —quien decide qué alfabeto se usó es la huella,
        // que sí se comprueba— y son 16 bits de metadato en claro, elegidos por
        // quien cifra y estables entre todos sus contenedores (N9).
        //
        // POR QUÉ ESTE PASO Y NO EL BORRADO: quitar el campo del formato, o
        // rechazarlo al leer, dejaría ILEGIBLE cualquier contenedor que alguien
        // ya haya creado con un valor. Escribir cero al crear no huerfana nada:
        // los viejos se siguen abriendo, y los nuevos dejan de sumar al
        // problema. Cuando no queden contenedores nuevos con valor, el paso 3
        // es validarlo a cero como se hizo con `flags`.
        codebook_id: 0,
        codebook_hash_prefix: codebook_fingerprint,
        salt,
        nonce,
        kdf_mem_kib: opts.kdf_params.mem_kib,
        kdf_iterations: opts.kdf_params.iterations,
        kdf_parallelism: opts.kdf_params.parallelism,
    };

    // Precapa: padding Padmé sobre el plaintext (oculta la longitud real).
    let mut padded = prelayers::pad(data);

    // La cabecera completa es el Associated Data: la ata al ciphertext, y con
    // ella el propio `flags` — así que declarar otro modo del que se usó rompe
    // la autenticación en vez de pasar desapercibido.
    let aad = header.to_bytes();

    #[cfg(feature = "blindaje")]
    let ciphertext = if let Some(clave) = clave_blindaje.as_mut() {
        // EL CAMINO DE ERROR TAMBIÉN BORRA. Si la fuente de entropía falla, aquí
        // hay vivos el claro con relleno y DOS claves, y un `expect` a secas se
        // los lleva por delante sin ejecutar ningún `Drop` — literalmente el
        // escenario contra el que argumenta `aleatorio.rs` cuando explica por
        // qué no basta con `panic`: un binario aguas abajo con `panic = "abort"`
        // no desenrolla la pila. Se limpia a mano antes de rendirse.
        match crate::blindaje::cifrar(clave, &padded, &aad) {
            Ok(salida) => {
                antihacker::wipe(clave);
                salida
            }
            Err(e) => {
                antihacker::wipe(clave);
                antihacker::wipe(&mut cipher_key);
                antihacker::wipe(&mut padded);
                antihacker::limpiar_pila();
                panic!("RNG del sistema: {e}");
            }
        }
    } else {
        cipher::encrypt(&cipher_key, &nonce, &padded, &aad)
    };
    #[cfg(not(feature = "blindaje"))]
    let ciphertext = cipher::encrypt(&cipher_key, &nonce, &padded, &aad);

    antihacker::wipe(&mut cipher_key);
    antihacker::wipe(&mut padded); // el plaintext con padding ya no se necesita

    container::serialize(&header, &ciphertext)
}

/// Operación inversa de [`encode_to_blob`].
pub fn decode_from_blob(
    blob: &[u8],
    passphrase: &str,
    expected_fingerprint: [u8; 8],
    pepper: &[u8],
) -> Result<Vec<u8>, DecodeError> {
    // LA AUTOPRUEBA VA EN TODA PUERTA DE ENTRADA, no solo en las tres de arriba.
    // `selftest.rs` promete que «el núcleo la invoca solo, así que no hay que
    // acordarse», y hasta el 2026-08-17 eso era falso para media superficie
    // pública: `encode_to_blob` —documentado como la vía para canales
    // alternativos—, `decode_from_blob`, `encode_signed` y `decode_verified` no
    // la llamaban. El caso que sobrevive a cualquier objeción es el que el
    // propio módulo describe: una primitiva CONSISTENTEMENTE rota pasa el
    // round-trip local del integrador y produce contenedores incorrectos que
    // nadie descubre hasta dos años después. Coste tras la primera llamada del
    // proceso: ~8,7 ns.
    crate::selftest::ensure();
    let (header, ciphertext) = container::parse(blob).map_err(DecodeError::Container)?;

    // Verifica que se decodifica con el codebook correcto.
    if header.codebook_hash_prefix != expected_fingerprint {
        return Err(DecodeError::CodebookMismatch);
    }

    // Los parámetros KDF vienen de la cabecera. Aunque están autenticados (AAD),
    // la autenticación ocurre DESPUÉS de derivar la clave, así que primero hay
    // que rechazar valores fuera de rango para evitar un DoS por memoria/overflow.
    let params = KdfParams {
        mem_kib: header.kdf_mem_kib,
        iterations: header.kdf_iterations,
        parallelism: header.kdf_parallelism,
    };
    if !params.is_sane() {
        return Err(DecodeError::KdfFueraDeRango);
    }
    // EL MODO LO DECLARA EL ARTEFACTO, no quien lo abre. Un contenedor guardado
    // sabe cómo se escribió, así que no hay una `decode` por modo: se lee el
    // flag. Y si el modo no está compilado se dice, en vez de intentar abrirlo
    // como si fuera del otro (directiva 20).
    let blindado = header.flags & container::FLAG_BLINDAJE != 0;
    #[cfg(not(feature = "blindaje"))]
    if blindado {
        return Err(DecodeError::ModoNoCompilado);
    }

    let mut master = kdf::derive_master_key(passphrase, &header.salt, pepper, &params);
    let mut cipher_key = kdf::derive_subkey(&master, CIPHER_SUBKEY_INFO);
    // Igual que al cifrar: se deriva antes de borrar la maestra, no se copia.
    #[cfg(feature = "blindaje")]
    let mut clave_blindaje =
        blindado.then(|| kdf::derive_subkey(&master, BLINDAJE_SUBKEY_INFO));
    antihacker::wipe(&mut master);

    let aad = header.to_bytes();

    // Se declara fuera del `if` para que el motivo sobreviva al brazo sin
    // obligar a un `return` temprano (ver abajo).
    #[cfg(feature = "blindaje")]
    let mut otra_version = false;

    #[cfg(feature = "blindaje")]
    let result = if let Some(clave) = clave_blindaje.as_mut() {
        // EL MOTIVO DEL FALLO SE CONSERVA. Antes los dos `BlindajeError` caían en
        // `DecryptFailed` y de ahí en `Decrypt`, así que un artefacto de otra
        // versión del formato se anunciaba como «contraseña mala». Ver
        // `DecodeError::BlindajeDeOtraVersion`.
        let abierto = crate::blindaje::descifrar(clave, ciphertext, &aad);
        antihacker::wipe(clave);
        // NO SE SALE DE AQUÍ. El motivo se anota y el retorno espera a después
        // del `wipe(&mut cipher_key)` de abajo — cuyo comentario dice «wipe antes
        // de cualquier retorno» y hay que cumplirlo: un `return` en este brazo
        // dejaría la clave de cifrado viva en el marco.
        // SOLO `OtraVersion`. Mapear también `Formato` —que es lo que hacía la
        // primera versión de este arreglo— le decía «tu archivo es de un formato
        // antiguo» a quien tuviera un blob MANIPULADO: el campo de largo va en
        // claro y sin autenticar, así que voltear un bit ahí caía en `Formato`.
        // La revisión de seguridad lo midió con tres entradas y sus dos controles.
        otra_version = matches!(abierto, Err(crate::blindaje::BlindajeError::OtraVersion));
        abierto.map_err(|_| crate::cipher::CipherError::DecryptFailed)
    } else {
        cipher::decrypt(&cipher_key, &header.nonce, ciphertext, &aad)
    };
    #[cfg(not(feature = "blindaje"))]
    let result = cipher::decrypt(&cipher_key, &header.nonce, ciphertext, &aad);

    antihacker::wipe(&mut cipher_key); // wipe antes de cualquier retorno

    // Ya con la clave borrada, se puede distinguir el motivo.
    #[cfg(feature = "blindaje")]
    if otra_version {
        return Err(DecodeError::BlindajeDeOtraVersion);
    }

    let mut padded = result.map_err(|_| DecodeError::Decrypt)?;
    // Quita el padding Padmé. Tras validar el tag AEAD, el bloque es de confianza.
    let data = prelayers::unpad(&padded).map_err(|_| DecodeError::Decrypt);
    antihacker::wipe(&mut padded); // el plaintext intermedio ya no se necesita
    data
}

// ============================ Modo online (OPRF, antibot real) ============================

/// Errores del modo online.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnlineError {
    /// Fallo de red al hablar con el servidor.
    Network,
    /// El servidor denegó la consulta (rate-limit).
    Denied,
    /// La PRUEBA DLEQ no validó: el servidor no usó la clave pública fijada
    /// (servidor deshonesto/comprometido o clave incorrecta).
    Verification,
    /// Fallo de decodificación.
    Decode(DecodeError),
}

/// Endurece la passphrase vía el servidor VOPRF, VERIFICANDO la prueba contra la
/// clave pública fijada (`server_pub`). Cierra el hallazgo F1.
///
/// Devuelve 64 B: es la salida de RFC 9497 (`Hash` = SHA-512). Antes eran 32,
/// con la construcción propia; truncarla haría fallar los vectores oficiales.
fn harden(
    passphrase: &str,
    server_addr: &str,
    server_pub: &[u8; 32],
) -> Result<[u8; voprf::OUTPUT_LEN], OnlineError> {
    // `blind` puede fallar si la entrada mapea a la identidad (RFC §3.3.2:
    // InvalidInputError). Es astronómicamente improbable, pero no se ignora.
    let (state, blinded) = voprf::blind(passphrase.as_bytes()).ok_or(OnlineError::Verification)?;
    let resp = oprf_net::evaluate_remote_verified(server_addr, &blinded)
        .map_err(|_| OnlineError::Network)?;
    let (z, proof) = resp.ok_or(OnlineError::Denied)?;
    voprf::finalize(passphrase.as_bytes(), &state, &z, &proof, server_pub)
        .ok_or(OnlineError::Verification)
}

/// Como [`encode`] pero ENDURECE la passphrase vía un servidor VOPRF: adivinarla
/// requiere consultar al servidor (rate-limit real), y el cliente VERIFICA que
/// el servidor usó la clave correcta (`server_pub` fijada). El output se añade al
/// pepper. Tanto encode como decode deben hablar con el mismo servidor.
pub fn encode_online(
    data: &[u8],
    passphrase: &str,
    server_addr: &str,
    server_pub: &[u8; 32],
    dict: &Dictionary,
    opts: &Options,
) -> Result<String, OnlineError> {
    let hardened = harden(passphrase, server_addr, server_pub)?;
    let mut pepper = opts.pepper.to_vec();
    pepper.extend_from_slice(&hardened);
    let opts2 = Options {
        pepper: &pepper,
        kdf_params: opts.kdf_params,
        // PASO 2 DE LA RETIRADA DE `codebook_id` (2026-08-01): se escribe
        // SIEMPRE 0, ignorando lo que pida el llamante.
        //
        // El campo nunca se lee —quien decide qué alfabeto se usó es la huella,
        // que sí se comprueba— y son 16 bits de metadato en claro, elegidos por
        // quien cifra y estables entre todos sus contenedores (N9).
        //
        // POR QUÉ ESTE PASO Y NO EL BORRADO: quitar el campo del formato, o
        // rechazarlo al leer, dejaría ILEGIBLE cualquier contenedor que alguien
        // ya haya creado con un valor. Escribir cero al crear no huerfana nada:
        // los viejos se siguen abriendo, y los nuevos dejan de sumar al
        // problema. Cuando no queden contenedores nuevos con valor, el paso 3
        // es validarlo a cero como se hizo con `flags`.
        codebook_id: 0,
    };
    Ok(encode(data, passphrase, dict, &opts2))
}

/// Operación inversa de [`encode_online`] (también consulta y verifica).
pub fn decode_online(
    symbols: &str,
    passphrase: &str,
    server_addr: &str,
    server_pub: &[u8; 32],
    dict: &Dictionary,
    base_pepper: &[u8],
) -> Result<Vec<u8>, OnlineError> {
    let hardened = harden(passphrase, server_addr, server_pub)?;
    let mut pepper = base_pepper.to_vec();
    pepper.extend_from_slice(&hardened);
    decode(symbols, passphrase, dict, &pepper).map_err(OnlineError::Decode)
}

// ============================ Modo híbrido post-cuántico ============================

/// Magic del contenedor híbrido (X25519 + ML-KEM).
const HYBRID_MAGIC: [u8; 4] = *b"QPQ1";
const HYBRID_VERSION: u8 = 1;
/// Bytes de cabecera híbrida antes de la encapsulación: magic+version+flags+nonce.
const HYBRID_PREFIX: usize = 4 + 1 + 1 + NONCE_LEN;

/// Cifra `data` hacia la clave pública híbrida del destinatario (post-cuántico).
/// No usa passphrase: la clave de contenido sale del KEM híbrido.
pub fn encode_to_recipient(
    data: &[u8],
    recipient: &pqhybrid::PublicKey,
    dict: &Dictionary,
) -> Result<String, crate::aleatorio::SinEntropia> {
    let (mut content_key, encapsulation) = pqhybrid::encapsulate(recipient)?;
    let mut nonce = [0u8; NONCE_LEN];
    crate::aleatorio::llenar(&mut nonce)?;

    // Cabecera (AAD): magic | version | flags | nonce | encapsulación.
    let mut header = Vec::with_capacity(HYBRID_PREFIX + encapsulation.len());
    header.extend_from_slice(&HYBRID_MAGIC);
    header.push(HYBRID_VERSION);
    header.push(0u8); // flags
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&encapsulation);

    let mut padded = prelayers::pad(data);
    let ciphertext = cipher::encrypt(&content_key, &nonce, &padded, &header);
    antihacker::wipe(&mut content_key);
    antihacker::wipe(&mut padded);

    let mut blob = header;
    blob.extend_from_slice(&ciphertext);
    let indices = codec::encode_base_n(&blob, dict.base());
    Ok(dict
        .encode(&indices)
        .expect("los índices del codec están en [0, base)"))
}

/// Descifra con la clave secreta híbrida del destinatario.
pub fn decode_as_recipient(
    symbols: &str,
    recipient: &pqhybrid::SecretKey,
    dict: &Dictionary,
) -> Result<Vec<u8>, DecodeError> {
    let indices = dict.decode(symbols).map_err(DecodeError::Symbol)?;
    let blob = codec::decode_base_n(&indices, dict.base());

    let header_len = HYBRID_PREFIX + pqhybrid::ENCAPSULATION_LEN;
    if blob.len() < header_len {
        return Err(DecodeError::Container(ContainerError::TooShort));
    }
    if blob[0..4] != HYBRID_MAGIC {
        return Err(DecodeError::Container(ContainerError::BadMagic));
    }
    if blob[4] != HYBRID_VERSION {
        return Err(DecodeError::Container(ContainerError::UnsupportedVersion(
            blob[4],
        )));
    }
    let nonce: [u8; NONCE_LEN] = blob[6..HYBRID_PREFIX].try_into().expect("24 bytes");
    let encapsulation = &blob[HYBRID_PREFIX..header_len];
    let aad = &blob[0..header_len];
    let ciphertext = &blob[header_len..];

    let mut content_key =
        pqhybrid::decapsulate(recipient, encapsulation).ok_or(DecodeError::Decrypt)?;
    let result = cipher::decrypt(&content_key, &nonce, ciphertext, aad);
    antihacker::wipe(&mut content_key);
    // `wipe` borra la copia que tiene NOMBRE; la clave llegó aquí devuelta por
    // valor desde `decapsulate`, y ese viaje deja copias en el marco —ya muerto—
    // de quien la produjo. Solo el llamante puede pisarlo, y solo después de que
    // vuelva. Medido en release (T6): sin esta línea quedaba 1 copia de la clave
    // de contenido. La regla general: quien recibe un secreto POR VALOR limpia la
    // pila del que se lo dio.
    antihacker::limpiar_pila();

    let mut padded = result.map_err(|_| DecodeError::Decrypt)?;
    let data = prelayers::unpad(&padded).map_err(|_| DecodeError::Decrypt);
    antihacker::wipe(&mut padded);
    data
}

// ============================ Modo firmado (autenticidad, no confidencialidad) ============================

/// Magic del contenedor firmado híbrido (Ed25519 + ML-DSA).
const SIGNED_MAGIC: [u8; 4] = *b"QSG1";
const SIGNED_VERSION: u8 = 1;
/// Cabecera del contenedor firmado antes del mensaje: magic+version+flags+msg_len.
const SIGNED_PREFIX: usize = 4 + 1 + 1 + 4;

#[cfg(feature = "slh")]
const SIGNED_TRIPLE_MAGIC: [u8; 4] = *b"QSG3";
#[cfg(feature = "slh")]
const SIGNED_TRIPLE_VERSION: u8 = 1;
/// Cabecera QSG3: magic+version+flags+msg_len (idéntico layout que QSG1).
#[cfg(feature = "slh")]
const SIGNED_TRIPLE_PREFIX: usize = 4 + 1 + 1 + 4;

/// Firma `data` con la clave triple-híbrida y lo representa con `dict` (contenedor
/// QSG3). Autosuficiente, FIRMADO PERO EN CLARO: autenticidad/integridad/no-repudio,
/// no confidencialidad. Modo de alta garantía (firma ~34 KB, firma lenta).
#[cfg(feature = "slh")]
pub fn encode_signed_triple(
    data: &[u8],
    signer: &pqsign::TripleSigningKey,
    dict: &Dictionary,
) -> String {
    let signature = signer.sign(data);
    let mut blob = Vec::with_capacity(SIGNED_TRIPLE_PREFIX + data.len() + signature.len());
    blob.extend_from_slice(&SIGNED_TRIPLE_MAGIC);
    blob.push(SIGNED_TRIPLE_VERSION);
    blob.push(0u8); // flags
    blob.extend_from_slice(&(data.len() as u32).to_be_bytes());
    blob.extend_from_slice(data);
    blob.extend_from_slice(&signature);

    let indices = codec::encode_base_n(&blob, dict.base());
    dict.encode(&indices)
        .expect("los índices del codec están en [0, base)")
}

/// Verifica un artefacto QSG3 contra la clave triple FIJADA y, sólo si valida,
/// devuelve el mensaje. Un artefacto QSG1 aquí da `BadMagic` (sin downgrade).
#[cfg(feature = "slh")]
pub fn decode_verified_triple(
    symbols: &str,
    verifier: &pqsign::TripleVerifyingKey,
    dict: &Dictionary,
) -> Result<Vec<u8>, DecodeError> {
    let indices = dict.decode(symbols).map_err(DecodeError::Symbol)?;
    let blob = codec::decode_base_n(&indices, dict.base());

    if blob.len() < SIGNED_TRIPLE_PREFIX + pqsign::TRIPLE_SIGNATURE_LEN {
        return Err(DecodeError::Container(ContainerError::TooShort));
    }
    if blob[0..4] != SIGNED_TRIPLE_MAGIC {
        return Err(DecodeError::Container(ContainerError::BadMagic));
    }
    if blob[4] != SIGNED_TRIPLE_VERSION {
        return Err(DecodeError::Container(ContainerError::UnsupportedVersion(
            blob[4],
        )));
    }
    let msg_len = u32::from_be_bytes(blob[6..10].try_into().expect("4 bytes")) as usize;

    // Aritmética verificada (misma defensa F4 que decode_verified).
    let Some(msg_end) = SIGNED_TRIPLE_PREFIX.checked_add(msg_len) else {
        return Err(DecodeError::Container(ContainerError::TooShort));
    };
    let Some(expected_len) = msg_end.checked_add(pqsign::TRIPLE_SIGNATURE_LEN) else {
        return Err(DecodeError::Container(ContainerError::TooShort));
    };
    if blob.len() != expected_len {
        return Err(DecodeError::Container(ContainerError::TooShort));
    }
    let message = &blob[SIGNED_TRIPLE_PREFIX..msg_end];
    let signature = &blob[msg_end..];

    if !verifier.verify(message, signature) {
        return Err(DecodeError::BadSignature);
    }
    Ok(message.to_vec())
}

/// Firma `data` con la clave híbrida `signer` y lo representa con `dict`.
///
/// El resultado es un artefacto AUTOSUFICIENTE, FIRMADO PERO EN CLARO: cualquiera
/// con la clave de verificación puede comprobar autoría e integridad Y leer el
/// mensaje. Da autenticidad, integridad y no-repudio; NO da confidencialidad (si
/// necesitas ocultar el contenido, usa además un modo de cifrado).
pub fn encode_signed(data: &[u8], signer: &pqsign::SigningKey, dict: &Dictionary) -> String {
    // LA AUTOPRUEBA VA EN TODA PUERTA DE ENTRADA, no solo en las tres de arriba.
    // `selftest.rs` promete que «el núcleo la invoca solo, así que no hay que
    // acordarse», y hasta el 2026-08-17 eso era falso para media superficie
    // pública: `encode_to_blob` —documentado como la vía para canales
    // alternativos—, `decode_from_blob`, `encode_signed` y `decode_verified` no
    // la llamaban. El caso que sobrevive a cualquier objeción es el que el
    // propio módulo describe: una primitiva CONSISTENTEMENTE rota pasa el
    // round-trip local del integrador y produce contenedores incorrectos que
    // nadie descubre hasta dos años después. Coste tras la primera llamada del
    // proceso: ~8,7 ns.
    crate::selftest::ensure();
    armar_firmado(data, &signer.sign(data), dict)
}

/// Como [`encode_signed`], pero firma contra un [`Custodio`](crate::firmante::Custodio)
/// —memoria, comparticiones o un dispositivo PKCS#11— en vez de una clave en
/// claro.
///
/// El artefacto es IDÉNTICo al de [`encode_signed`]: [`firmar`](crate::firmante::firmar)
/// produce la misma firma, y lo verifica el mismo [`decode_verified`]. La única
/// diferencia es de dónde salió la firma, y ese es justo el punto: la clave pudo
/// no salir nunca de un HSM.
pub fn encode_signed_con_custodio<C: crate::firmante::Custodio + ?Sized>(
    data: &[u8],
    custodio: &C,
    dict: &Dictionary,
) -> Result<String, crate::firmante::ErrorDeFirma> {
    let signature = crate::firmante::firmar(custodio, data)?;
    Ok(armar_firmado(data, &signature, dict))
}

/// Arma el contenedor firmado a partir del mensaje y su firma ya calculada.
/// Único sitio donde vive el formato en cable de [`encode_signed`].
fn armar_firmado(data: &[u8], signature: &[u8], dict: &Dictionary) -> String {
    let mut blob = Vec::with_capacity(SIGNED_PREFIX + data.len() + signature.len());
    blob.extend_from_slice(&SIGNED_MAGIC);
    blob.push(SIGNED_VERSION);
    blob.push(0u8); // flags
    blob.extend_from_slice(&(data.len() as u32).to_be_bytes());
    blob.extend_from_slice(data);
    blob.extend_from_slice(signature);

    let indices = codec::encode_base_n(&blob, dict.base());
    dict.encode(&indices)
        .expect("los índices del codec están en [0, base)")
}

/// Verifica la firma de un artefacto de [`encode_signed`] contra la clave pública
/// FIJADA `verifier` y, sólo si valida, devuelve el mensaje.
pub fn decode_verified(
    symbols: &str,
    verifier: &pqsign::VerifyingKey,
    dict: &Dictionary,
) -> Result<Vec<u8>, DecodeError> {
    // LA AUTOPRUEBA VA EN TODA PUERTA DE ENTRADA, no solo en las tres de arriba.
    // `selftest.rs` promete que «el núcleo la invoca solo, así que no hay que
    // acordarse», y hasta el 2026-08-17 eso era falso para media superficie
    // pública: `encode_to_blob` —documentado como la vía para canales
    // alternativos—, `decode_from_blob`, `encode_signed` y `decode_verified` no
    // la llamaban. El caso que sobrevive a cualquier objeción es el que el
    // propio módulo describe: una primitiva CONSISTENTEMENTE rota pasa el
    // round-trip local del integrador y produce contenedores incorrectos que
    // nadie descubre hasta dos años después. Coste tras la primera llamada del
    // proceso: ~8,7 ns.
    crate::selftest::ensure();
    let indices = dict.decode(symbols).map_err(DecodeError::Symbol)?;
    let blob = codec::decode_base_n(&indices, dict.base());

    if blob.len() < SIGNED_PREFIX + pqsign::SIGNATURE_LEN {
        return Err(DecodeError::Container(ContainerError::TooShort));
    }
    if blob[0..4] != SIGNED_MAGIC {
        return Err(DecodeError::Container(ContainerError::BadMagic));
    }
    if blob[4] != SIGNED_VERSION {
        return Err(DecodeError::Container(ContainerError::UnsupportedVersion(
            blob[4],
        )));
    }
    let msg_len = u32::from_be_bytes(blob[6..10].try_into().expect("4 bytes")) as usize;

    // La longitud declarada debe encajar EXACTAMENTE con mensaje + firma fija.
    // Aritmética VERIFICADA: en targets de 32 bits, `msg_len` (hasta ~4 GiB)
    // podría desbordar `usize` al sumar y hacer pasar el chequeo con un rango de
    // slice fuera de límites (panic/DoS). `checked_add` lo rechaza limpiamente.
    let Some(msg_end) = SIGNED_PREFIX.checked_add(msg_len) else {
        return Err(DecodeError::Container(ContainerError::TooShort));
    };
    let Some(expected_len) = msg_end.checked_add(pqsign::SIGNATURE_LEN) else {
        return Err(DecodeError::Container(ContainerError::TooShort));
    };
    if blob.len() != expected_len {
        return Err(DecodeError::Container(ContainerError::TooShort));
    }
    let message = &blob[SIGNED_PREFIX..msg_end];
    let signature = &blob[msg_end..];

    if !verifier.verify(message, signature) {
        return Err(DecodeError::BadSignature);
    }
    Ok(message.to_vec())
}

#[cfg(test)]
mod tests {
    /// **EL TAMAÑO DE `DecodeError` NO PUEDE CRECER**, y el motivo no se
    /// adivina mirando el tipo.
    ///
    /// Descubierto el 2026-08-16 por accidente: añadirle una variante con un
    /// `&'static str` —dieciséis bytes— puso en rojo
    /// `tests/residuo_memoria.rs::el_camino_del_destinatario_no_deja_la_clave_de_contenido_en_memoria`,
    /// una prueba de un camino que ni siquiera se había tocado. Al crecer el
    /// enum crece `Result<Vec<u8>, DecodeError>`, se mueven los marcos de la
    /// pila, y la clave de contenido acaba **por debajo de los 128 KiB que
    /// alcanza `antihacker::limpiar_pila`** — o sea, sin borrar.
    ///
    /// Eso significa que este tipo, que parece un detalle de ergonomía, es parte
    /// del presupuesto de pila de la librería. El acoplamiento era invisible: la
    /// prueba de residuo se ponía roja sin decir por qué, y en otro archivo.
    /// Aquí se hace ruidoso.
    ///
    /// Si algún día hay que hacerlo crecer de verdad, el camino está escrito en
    /// `antihacker::PILA_A_LIMPIAR`: se sube la constante CON la medición
    /// delante, sabiendo que sube el mínimo de pila que Quipu exige a quien lo
    /// llama.
    ///
    /// **La cota vigila el `Result`, no el enum, y la primera versión lo hizo
    /// mal.** Medido por la revisión de seguridad: `Result<Vec<u8>, DecodeError>`
    /// se queda en 24 bytes mientras el enum no pase de 16, y solo salta a 32 a
    /// partir de 17. La cota original —«el enum ≤ 8»— bloqueaba un crecimiento a
    /// 16 que no movía nada, y a la vez no decía nada de los OTROS `Result` del
    /// mismo marco. Se mide lo que de verdad empuja la pila.
    #[test]
    fn los_result_del_camino_de_descifrado_no_crecen() {
        use super::DecodeError;
        use core::mem::size_of;

        // El que causó el incidente. 24 hoy; crece a 32 si `DecodeError` pasa
        // de 16 bytes.
        assert!(
            size_of::<Result<Vec<u8>, DecodeError>>() <= 24,
            "Result<Vec<u8>, DecodeError> ocupa {} bytes (DecodeError: {}). Al \
             crecer se mueven los marcos y los secretos salen del alcance de \
             antihacker::limpiar_pila. Lee el comentario de \
             DecodeError::ModoNoCompilado antes de subir esta cota.",
            size_of::<Result<Vec<u8>, DecodeError>>(),
            size_of::<DecodeError>()
        );

        // Y los dos que este camino ESTRENÓ y que no pasan por `DecodeError`:
        // el del reparto ciego y el de la fuente de entropía. El segundo es hoy
        // el mayor de todos (48), así que es el que hay que mirar primero si el
        // banco de residuo vuelve a ponerse raro.
        #[cfg(feature = "blindaje")]
        {
            assert!(
                size_of::<Result<Vec<u8>, crate::blindaje::BlindajeError>>() <= 24,
                "Result de blindaje: {} bytes",
                size_of::<Result<Vec<u8>, crate::blindaje::BlindajeError>>()
            );
            assert!(
                size_of::<Result<Vec<u8>, crate::aleatorio::SinEntropia>>() <= 48,
                "Result de SinEntropia: {} bytes",
                size_of::<Result<Vec<u8>, crate::aleatorio::SinEntropia>>()
            );
        }
    }

    /// LOS DOS MODOS NO COMPARTEN MATERIAL DERIVADO.
    ///
    /// Escrita porque un mutante sobrevivió: poner `BLINDAJE_SUBKEY_INFO =
    /// CIPHER_SUBKEY_INFO` dejaba las ocho pruebas de extremo a extremo en
    /// verde. Y es lógico —los dos caminos nunca se usan sobre el mismo
    /// contenedor, así que la corrección no se resiente—, pero significaría que
    /// la misma passphrase y el mismo salt derivan el mismo secreto para dos
    /// modos distintos. Eso no es un fallo hoy y es la clase de cosa que lo es
    /// dentro de dos versiones.
    #[test]
    #[cfg(feature = "blindaje")]
    fn los_dos_modos_derivan_material_distinto() {
        use super::*;
        assert_ne!(
            CIPHER_SUBKEY_INFO, BLINDAJE_SUBKEY_INFO,
            "los dos modos comparten etiqueta de dominio"
        );

        // Y sobre el artefacto, no sobre las constantes: de una maestra fija,
        // las dos subclaves tienen que salir distintas.
        let maestra = [0x42u8; kdf::KEY_LEN];
        let a = kdf::derive_subkey(&maestra, CIPHER_SUBKEY_INFO);
        let b = kdf::derive_subkey(&maestra, BLINDAJE_SUBKEY_INFO);
        assert_ne!(a, b, "la misma maestra deriva lo mismo para los dos modos");

        // CONTROL: con la MISMA etiqueta sí coinciden — o sea que la aserción de
        // arriba mide la etiqueta y no un derivador que devuelva azar.
        assert_eq!(a, kdf::derive_subkey(&maestra, CIPHER_SUBKEY_INFO));
    }

    /// PASO 2 DE LA RETIRADA DE `codebook_id`: aunque el llamante pida un
    /// valor, lo que se ESCRIBE es cero.
    ///
    /// De extremo a extremo, sobre el blob real, porque es donde importa: el
    /// campo son 16 bits de metadato en claro y estables (N9), y quien lo
    /// rellenara con un identificador de inquilino enlazaría todos sus
    /// contenedores. Los contenedores VIEJOS con valor se siguen abriendo —eso
    /// lo sujeta `codebook_id_distinto_de_cero_se_sigue_aceptando` en el crate
    /// del formato—, así que esto no huerfana nada.
    #[test]
    fn el_campo_obsoleto_se_escribe_en_cero_aunque_se_pida_otra_cosa() {
        let dict = crate::dictionaries::ascii94();
        #[allow(deprecated)]
        let opts = super::Options {
            pepper: b"",
            kdf_params: crate::kdf::KdfParams::LIGERO,
            codebook_id: 0xBEEF,
        };
        let blob = super::encode_to_blob(
            b"lo que sea",
            "una contrasena",
            crate::dictionary::HuellaDeCodebook::fingerprint(&dict),
            &opts,
        );
        assert_eq!(&blob[6..8], &[0, 0], "se coló el codebook_id del llamante");
        // Y el contenedor sigue abriéndose, que es lo único que no puede fallar.
        assert_eq!(
            super::decode_from_blob(&blob, "una contrasena", crate::dictionary::HuellaDeCodebook::fingerprint(&dict), b"").unwrap(),
            b"lo que sea"
        );
    }

    use super::*;
    use proptest::prelude::*;

    fn test_opts() -> Options<'static> {
        // Coste bajo para tests rápidos.
        Options {
            pepper: b"",
            kdf_params: KdfParams {
                mem_kib: 64,
                iterations: 1,
                parallelism: 1,
            },
            codebook_id: 1,
        }
    }

    fn ascii_dict() -> Dictionary {
        Dictionary::new((0x21u8..=0x7e).map(|b| b as char).collect()).unwrap()
    }

    #[test]
    fn round_trips_data() {
        let dict = ascii_dict();
        let data = b"mensaje secreto";
        let symbols = encode(data, "clave-correcta", &dict, &test_opts());
        let back = decode(&symbols, "clave-correcta", &dict, b"").unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn hides_length_within_padme_bucket() {
        // 100 y 101 bytes caen en el mismo cubo Padmé -> misma longitud de salida.
        let dict = ascii_dict();
        let a = encode(&[0u8; 100], "clave", &dict, &test_opts());
        let b = encode(&[1u8; 101], "clave", &dict, &test_opts());
        assert_eq!(a.chars().count(), b.chars().count());
    }

    #[test]
    fn round_trips_empty_data() {
        let dict = ascii_dict();
        let symbols = encode(b"", "clave", &dict, &test_opts());
        assert_eq!(decode(&symbols, "clave", &dict, b"").unwrap(), b"");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let dict = ascii_dict();
        let symbols = encode(b"datos", "correcta", &dict, &test_opts());
        assert_eq!(
            decode(&symbols, "incorrecta", &dict, b""),
            Err(DecodeError::Decrypt)
        );
    }

    #[test]
    fn wrong_pepper_fails() {
        let dict = ascii_dict();
        let opts = Options {
            pepper: b"pepper-correcto",
            ..test_opts()
        };
        let symbols = encode(b"datos", "clave", &dict, &opts);
        assert_eq!(
            decode(&symbols, "clave", &dict, b"pepper-incorrecto"),
            Err(DecodeError::Decrypt)
        );
    }

    /// **UN PARÁMETRO DE KDF FUERA DE RANGO NO SE DISFRAZA DE CONTRASEÑA MALA.**
    ///
    /// Los dos lados, porque la mitad sola no dice nada: la corrupción de
    /// formato tiene que dar `KdfFueraDeRango`, y la contraseña equivocada sobre
    /// el MISMO contenedor intacto tiene que seguir dando `Decrypt`. Si las dos
    /// dieran lo mismo, el diagnóstico manda a quien lo lea a reintentar una
    /// contraseña que ya era correcta.
    #[test]
    fn el_kdf_fuera_de_rango_no_se_confunde_con_la_contrasena() {
        let dict = ascii_dict();
        let huella = dict.fingerprint();
        let blob = encode_to_blob(b"acta", "clave", huella, &test_opts());

        // CONTROL: intacto y con la clave buena, abre.
        assert_eq!(
            decode_from_blob(&blob, "clave", huella, b"").expect("el control tiene que abrir"),
            b"acta".to_vec()
        );
        // CONTROL 2: intacto y con la clave MALA, `Decrypt`.
        assert_eq!(
            decode_from_blob(&blob, "otra", huella, b""),
            Err(DecodeError::Decrypt)
        );

        // Y el caso: `mem_kib` a un valor imposible. Es corrupción de formato,
        // independiente de la clave — con la buena y con la mala da lo mismo.
        let mut roto = blob;
        roto[56..60].copy_from_slice(&u32::MAX.to_be_bytes());
        for clave in ["clave", "otra"] {
            assert_eq!(
                decode_from_blob(&roto, clave, huella, b""),
                Err(DecodeError::KdfFueraDeRango),
                "con la contraseña {clave:?} tendría que decir que el KDF está fuera de rango"
            );
        }
    }

    #[test]
    fn decode_rejects_malicious_kdf_params_without_panic() {
        // Regresión del hallazgo del hackerbot: parámetros KDF gigantes en una
        // cabecera manipulada causaban panic por overflow en Argon2.
        use crate::container::{self, Header, VERSION};
        let dict = ascii_dict();
        let header = Header {
            version: VERSION,
            flags: 0,
            codebook_id: 1,
            codebook_hash_prefix: dict.fingerprint(),
            salt: [0u8; 16],
            nonce: [0u8; 24],
            kdf_mem_kib: u32::MAX,
            kdf_iterations: u32::MAX,
            kdf_parallelism: u32::MAX,
        };
        let blob = container::serialize(&header, b"ciphertext-falso-con-tag-relleno");
        let indices = crate::codec::encode_base_n(&blob, dict.base());
        let symbols = dict.encode(&indices).unwrap();
        // ESTA ASERCIÓN DECÍA `Decrypt`, y con ella el banco fijaba el defecto en
        // vez de la propiedad: unos parámetros de KDF imposibles son corrupción
        // de FORMATO —independiente de la clave, el Argon2id ni se ejecuta— y
        // decirle «contraseña incorrecta» a eso manda a quien lo lea a reintentar
        // media hora una clave que ya era buena. Cambiado el 2026-08-17 junto con
        // la variante nueva; lo que la prueba comprueba de verdad —que no entra
        // en pánico— no se toca.
        assert_eq!(
            decode(&symbols, "clave", &dict, b""),
            Err(DecodeError::KdfFueraDeRango)
        );
    }

    #[test]
    fn tampered_symbols_fail() {
        let dict = ascii_dict();
        let symbols = encode(b"datos importantes", "clave", &dict, &test_opts());
        // Cambia un símbolo por otro válido del alfabeto.
        let mut chars: Vec<char> = symbols.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert!(decode(&tampered, "clave", &dict, b"").is_err());
    }

    #[test]
    fn decode_verified_rejects_overflowing_msg_len_without_panic() {
        // Contenedor firmado manipulado con msg_len = u32::MAX: en 32-bit la suma
        // SIGNED_PREFIX+msg_len+SIGNATURE_LEN desbordaría; `checked_add` lo
        // rechaza limpiamente en cualquier target, sin panic de slice.
        let dict = ascii_dict();
        let mut blob = Vec::new();
        blob.extend_from_slice(b"QSG1");
        blob.push(1); // version
        blob.push(0); // flags
        blob.extend_from_slice(&u32::MAX.to_be_bytes()); // msg_len malicioso
        blob.extend_from_slice(&[0u8; 200]); // cuerpo corto (no cuadra)
        let indices = crate::codec::encode_base_n(&blob, dict.base());
        let symbols = dict.encode(&indices).unwrap();
        let (vk, _sk) = pqsign::generate_keypair();
        // No debe entrar en pánico; devuelve error de contenedor/firma.
        assert!(decode_verified(&symbols, &vk, &dict).is_err());
    }

    proptest! {
        #[test]
        fn round_trips_any_data(
            data in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            let dict = ascii_dict();
            let symbols = encode(&data, "clave", &dict, &test_opts());
            let back = decode(&symbols, "clave", &dict, b"").unwrap();
            prop_assert_eq!(back, data);
        }
    }

    fn spawn_voprf_server(
        connections: usize,
        allowed: bool,
    ) -> (String, [u8; 32], std::thread::JoinHandle<()>) {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = voprf::Server::new();
        let pubkey = server.public_key();
        let handle = std::thread::spawn(move || {
            for _ in 0..connections {
                let (mut stream, _) = listener.accept().unwrap();
                crate::oprf_net::handle_connection_verified(&mut stream, &server, allowed).unwrap();
            }
        });
        (addr, pubkey, handle)
    }

    #[test]
    fn online_mode_round_trips_via_server() {
        let (addr, pk, handle) = spawn_voprf_server(2, true); // encode + decode
        let dict = ascii_dict();
        let data = b"secreto endurecido online";
        let sym = encode_online(data, "clave", &addr, &pk, &dict, &test_opts()).unwrap();
        let back = decode_online(&sym, "clave", &addr, &pk, &dict, b"").unwrap();
        assert_eq!(back, data);
        handle.join().unwrap();
    }

    #[test]
    fn online_mode_denied_by_server_errors() {
        let (addr, pk, handle) = spawn_voprf_server(1, false); // servidor deniega
        let dict = ascii_dict();
        let r = encode_online(b"x", "clave", &addr, &pk, &dict, &test_opts());
        assert_eq!(r, Err(OnlineError::Denied));
        handle.join().unwrap();
    }

    #[test]
    fn online_mode_detects_dishonest_server() {
        // El cliente fija una clave pública que NO es la del servidor -> la
        // prueba DLEQ no valida -> se detecta (Verification), no se usa la salida.
        let (addr, _real_pk, handle) = spawn_voprf_server(1, true);
        let wrong_pk = voprf::Server::new().public_key();
        let dict = ascii_dict();
        let r = encode_online(b"x", "clave", &addr, &wrong_pk, &dict, &test_opts());
        assert_eq!(r, Err(OnlineError::Verification));
        handle.join().unwrap();
    }

    #[test]
    fn hybrid_round_trips_to_recipient() {
        let (pk, sk) = pqhybrid::generate_keypair().unwrap();
        let dict = ascii_dict();
        let data = b"secreto resistente a cuantica";
        let symbols = encode_to_recipient(data, &pk, &dict).unwrap();
        assert_eq!(decode_as_recipient(&symbols, &sk, &dict).unwrap(), data);
    }

    #[test]
    fn hybrid_wrong_recipient_fails() {
        let (pk, _sk) = pqhybrid::generate_keypair().unwrap();
        let (_pk2, sk2) = pqhybrid::generate_keypair().unwrap();
        let dict = ascii_dict();
        let symbols = encode_to_recipient(b"datos", &pk, &dict).unwrap();
        assert!(decode_as_recipient(&symbols, &sk2, &dict).is_err());
    }

    #[test]
    fn signed_round_trips_and_reveals_message() {
        let (vk, sk) = pqsign::generate_keypair();
        let dict = ascii_dict();
        let data = b"acta firmada verificable por terceros";
        let symbols = encode_signed(data, &sk, &dict);
        assert_eq!(decode_verified(&symbols, &vk, &dict).unwrap(), data);
    }

    #[test]
    fn signed_wrong_signer_fails() {
        let (_vk, sk) = pqsign::generate_keypair();
        let (vk2, _sk2) = pqsign::generate_keypair();
        let dict = ascii_dict();
        let symbols = encode_signed(b"datos", &sk, &dict);
        assert_eq!(
            decode_verified(&symbols, &vk2, &dict),
            Err(DecodeError::BadSignature)
        );
    }

    #[test]
    fn signed_tampered_message_fails() {
        let (vk, sk) = pqsign::generate_keypair();
        let dict = ascii_dict();
        let symbols = encode_signed(b"transferir 100", &sk, &dict);
        // Sustituye un símbolo por otro válido del alfabeto.
        let mut chars: Vec<char> = symbols.chars().collect();
        chars[SIGNED_PREFIX] = if chars[SIGNED_PREFIX] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert!(decode_verified(&tampered, &vk, &dict).is_err());
    }

    #[test]
    fn signed_empty_message_round_trips() {
        let (vk, sk) = pqsign::generate_keypair();
        let dict = ascii_dict();
        let symbols = encode_signed(b"", &sk, &dict);
        assert_eq!(decode_verified(&symbols, &vk, &dict).unwrap(), b"");
    }

    proptest! {
        #[test]
        fn signed_round_trips_any_data(
            data in proptest::collection::vec(any::<u8>(), 0..96),
        ) {
            let (vk, sk) = pqsign::generate_keypair();
            let dict = ascii_dict();
            let symbols = encode_signed(&data, &sk, &dict);
            let back = decode_verified(&symbols, &vk, &dict).unwrap();
            prop_assert_eq!(back, data);
        }
    }

    #[cfg(feature = "slh")]
    #[test]
    fn triple_signed_round_trips() {
        let dict = ascii_dict();
        let (vk, sk) = pqsign::generate_triple_keypair();
        let data = b"artefacto de altisimo valor";
        let symbols = encode_signed_triple(data, &sk, &dict);
        assert_eq!(decode_verified_triple(&symbols, &vk, &dict).unwrap(), data);
    }

    #[cfg(feature = "slh")]
    #[test]
    fn triple_wrong_key_rejected() {
        let dict = ascii_dict();
        let (_vk, sk) = pqsign::generate_triple_keypair();
        let (vk2, _sk2) = pqsign::generate_triple_keypair();
        let symbols = encode_signed_triple(b"datos", &sk, &dict);
        assert!(matches!(
            decode_verified_triple(&symbols, &vk2, &dict),
            Err(DecodeError::BadSignature)
        ));
    }

    #[cfg(feature = "slh")]
    #[test]
    fn triple_region_tamper_rejected() {
        let dict = ascii_dict();
        let (vk, sk) = pqsign::generate_triple_keypair();
        let symbols = encode_signed_triple(b"transferir 100", &sk, &dict);
        let mut chars: Vec<char> = symbols.chars().collect();
        chars[SIGNED_TRIPLE_PREFIX] = if chars[SIGNED_TRIPLE_PREFIX] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert!(decode_verified_triple(&tampered, &vk, &dict).is_err());
    }

    #[cfg(feature = "slh")]
    #[test]
    fn triple_empty_message_round_trips() {
        let dict = ascii_dict();
        let (vk, sk) = pqsign::generate_triple_keypair();
        let symbols = encode_signed_triple(b"", &sk, &dict);
        assert_eq!(decode_verified_triple(&symbols, &vk, &dict).unwrap(), b"");
    }

    #[cfg(feature = "slh")]
    #[test]
    fn triple_rejects_overflowing_msg_len_without_panic() {
        let dict = ascii_dict();
        let (vk, _sk) = pqsign::generate_triple_keypair();
        let mut blob = Vec::new();
        blob.extend_from_slice(b"QSG3");
        blob.push(1); // version
        blob.push(0); // flags
        blob.extend_from_slice(&u32::MAX.to_be_bytes()); // msg_len enorme
        let indices = codec::encode_base_n(&blob, dict.base());
        let symbols = dict.encode(&indices).unwrap();
        assert!(decode_verified_triple(&symbols, &vk, &dict).is_err());
    }
}

// ---------------------------------------------------------------------------
// Cifrado perforable: sellar / abrir (feature `perforable`)
// ---------------------------------------------------------------------------

/// Errores de [`sellar`] y [`abrir`].
#[cfg(feature = "perforable")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelloError {
    /// La etiqueta ya no tiene clave: su lacre se abrió (y la clave se destruyó).
    Perforada,
    /// No hubo entropía del sistema para el nonce.
    SinEntropia,
    /// El lacre está truncado o no es de este formato/versión.
    Formato(&'static str),
    /// El AEAD no validó: clave, nonce, etiqueta o contenido alterados.
    Autenticacion,
}

#[cfg(feature = "perforable")]
impl core::fmt::Display for SelloError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Perforada => write!(f, "la etiqueta está perforada (el lacre ya se abrió)"),
            Self::SinEntropia => write!(f, "sin entropía del sistema para el nonce"),
            Self::Formato(m) => write!(f, "lacre con formato inválido: {m}"),
            Self::Autenticacion => write!(f, "el lacre no autenticó"),
        }
    }
}
#[cfg(feature = "perforable")]
impl std::error::Error for SelloError {}

/// Magia del lacre perforable. Formato: `magic(4) || nonce(24) || ciphertext||tag`.
#[cfg(feature = "perforable")]
const SELLO_MAGIC: &[u8; 4] = b"QPS1";

/// Sella `datos` bajo `etiqueta` con la clave que le da `pf`.
///
/// **No perfora**: sellar no consume la clave. La etiqueta viaja como AEAD
/// `aad`, así que un lacre no se puede reetiquetar. Falla con
/// [`SelloError::Perforada`] si la etiqueta ya no tiene clave.
///
/// **Cuidado con re-sellar la misma etiqueta.** Todos los lacres de una etiqueta
/// comparten UNA clave (la hoja de esa etiqueta), así que abrir CUALQUIERA de
/// ellos con [`abrir`] perfora esa clave y deja a los demás **imposibles de
/// abrir para siempre**. Es un riesgo de disponibilidad, no de
/// confidencialidad: destruye de más, nunca de menos. Si necesitas varios
/// lacres que se abran por separado, dales etiquetas distintas.
///
/// El AEAD y su seguridad son los de [`crate::cipher`]; aquí solo se elige la
/// clave. Ver el modelo de amenaza de [`crate::perforable`].
#[cfg(feature = "perforable")]
pub fn sellar(
    pf: &crate::perforable::Perforable,
    etiqueta: &[u8],
    datos: &[u8],
) -> Result<Vec<u8>, SelloError> {
    let clave = pf.clave_de(etiqueta).ok_or(SelloError::Perforada)?;
    let mut nonce = [0u8; NONCE_LEN];
    crate::aleatorio::llenar(&mut nonce).map_err(|_| SelloError::SinEntropia)?;
    let ct = cipher::encrypt(&clave, &nonce, datos, etiqueta);
    let mut blob = Vec::with_capacity(4 + NONCE_LEN + ct.len());
    blob.extend_from_slice(SELLO_MAGIC);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    // Mismo barrido que `abrir` (T6): sellar también deriva la clave de hoja y la
    // pasa a cipher::encrypt, dejando copias en marcos reclamados bajo este.
    crate::antihacker::limpiar_pila();
    Ok(blob)
}

/// Abre el lacre de `etiqueta` y **destruye la clave** (perfora `pf`) si y solo
/// si el AEAD valida.
///
/// Un intento fallido —frase/clave equivocada, lacre corrupto— **no** perfora:
/// la clave solo se quema en una apertura exitosa, que es lo que significa
/// «destruir la clave al abrir». Tras devolver, [`crate::perforable::Perforable`]
/// ha cambiado: **persiste el nuevo estado y destruye el viejo** (regla 2 del
/// modelo de amenaza), o la protección no existe.
#[cfg(feature = "perforable")]
pub fn abrir(
    pf: &mut crate::perforable::Perforable,
    etiqueta: &[u8],
    blob: &[u8],
) -> Result<Vec<u8>, SelloError> {
    if blob.len() < 4 + NONCE_LEN {
        return Err(SelloError::Formato("truncado"));
    }
    if &blob[..4] != SELLO_MAGIC {
        return Err(SelloError::Formato("magic"));
    }
    let clave = pf.clave_de(etiqueta).ok_or(SelloError::Perforada)?;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob[4..4 + NONCE_LEN]);
    let ct = &blob[4 + NONCE_LEN..];
    let datos = cipher::decrypt(&clave, &nonce, ct, etiqueta).map_err(|_| SelloError::Autenticacion)?;
    // Solo aquí, con la apertura ya verificada: destruir la clave.
    pf.perforar(etiqueta);
    // Barre la pila: la clave de hoja se copia en marcos de `cipher::decrypt`
    // (temporal `*key`) y `perforar` que quedan reclamados bajo este marco.
    // `abrir` NO está en el hot path (a diferencia de cipher::decrypt), así que el
    // barrido va aquí. Medido con `tests/residuo_memoria.rs` (T6): la derivación
    // sola no deja residuo; este barrido cierra el que dejan decrypt/perforar.
    crate::antihacker::limpiar_pila();
    Ok(datos)
}

/// Abre el lacre de `etiqueta` (sobre de un solo uso) y **anota la apertura** en
/// el registro encadenado, en un solo paso. La anotación se hace **solo si la
/// apertura tuvo éxito**: un intento fallido no ensucia el rastro. Devuelve los
/// datos; la nueva cabeza del registro queda en `registro`. Ver
/// [`crate::lacre::RegistroDeAperturas`].
#[cfg(feature = "perforable")]
pub fn abrir_y_registrar(
    pf: &mut crate::perforable::Perforable,
    etiqueta: &[u8],
    blob: &[u8],
    registro: &mut crate::lacre::RegistroDeAperturas,
) -> Result<Vec<u8>, SelloError> {
    let datos = abrir(pf, etiqueta, blob)?;
    registro.anotar(etiqueta);
    Ok(datos)
}

#[cfg(all(test, feature = "perforable"))]
mod tests_perforable {
    use super::*;
    use crate::perforable::Perforable;

    #[test]
    fn abrir_y_registrar_anota_solo_en_exito() {
        use crate::lacre::RegistroDeAperturas;
        let mut pf = Perforable::nueva().unwrap();
        let mut reg = RegistroDeAperturas::nuevo();
        let tag = b"expediente-9";
        let lacre = sellar(&pf, tag, b"contenido").unwrap();

        // Apertura exitosa: anota.
        assert_eq!(abrir_y_registrar(&mut pf, tag, &lacre, &mut reg).unwrap(), b"contenido");
        assert_eq!(reg.len(), 1);
        assert!(reg.contiene(tag) && reg.verificar());
        let cabeza_tras_uno = reg.cabeza();

        // Segundo intento (ya perforada): falla y NO anota.
        assert_eq!(
            abrir_y_registrar(&mut pf, tag, &lacre, &mut reg),
            Err(SelloError::Perforada)
        );
        assert_eq!(reg.len(), 1, "un intento fallido no debe ensuciar el rastro");
        assert_eq!(reg.cabeza(), cabeza_tras_uno);
    }

    #[test]
    fn abrir_una_vez_y_solo_una() {
        let mut pf = Perforable::nueva().unwrap();
        let tag = b"expediente-42";
        let secreto = b"lo que solo se lee una vez";
        let lacre = sellar(&pf, tag, secreto).unwrap();

        assert_eq!(abrir(&mut pf, tag, &lacre).unwrap(), secreto);
        // Segunda apertura: la clave ya no existe.
        assert_eq!(abrir(&mut pf, tag, &lacre), Err(SelloError::Perforada));
    }

    /// CASO ROJO por la vía real (D33): tras abrir, el atacante con el ESTADO
    /// COMPLETO posterior + el lacre + la etiqueta no puede reabrirlo.
    /// Control que discrimina: un lacre NO abierto sí se abre desde ese estado.
    #[test]
    fn estado_robado_tras_abrir_no_reabre() {
        let mut pf = Perforable::nueva().unwrap();
        let abierto = sellar(&pf, b"leido", b"ya lo lei").unwrap();
        let pendiente = sellar(&pf, b"no-leido", b"aun no").unwrap();

        // Se abre el primero (se quema su clave).
        assert_eq!(abrir(&mut pf, b"leido", &abierto).unwrap(), b"ya lo lei");

        // El atacante toma el estado completo de después.
        let robado = pf.a_bytes();
        let mut visto = Perforable::de_bytes(&robado).unwrap();

        // No puede reabrir lo ya leído...
        assert_eq!(abrir(&mut visto, b"leido", &abierto), Err(SelloError::Perforada));
        // ...pero SÍ lo pendiente (control: el estado no está simplemente roto).
        assert_eq!(abrir(&mut visto, b"no-leido", &pendiente).unwrap(), b"aun no");
    }

    #[test]
    fn intento_fallido_no_quema_la_clave() {
        let mut pf = Perforable::nueva().unwrap();
        let tag = b"fragil";
        let lacre = sellar(&pf, tag, b"contenido").unwrap();
        let mut corrupto = lacre.clone();
        *corrupto.last_mut().unwrap() ^= 0xff; // altera el tag AEAD

        assert_eq!(abrir(&mut pf, tag, &corrupto), Err(SelloError::Autenticacion));
        assert!(!pf.esta_perforada(tag), "un fallo NO debe perforar");
        // y el lacre bueno todavía abre
        assert_eq!(abrir(&mut pf, tag, &lacre).unwrap(), b"contenido");
    }

    #[test]
    fn etiqueta_atada_al_lacre() {
        let pf = Perforable::nueva().unwrap();
        let lacre = sellar(&pf, b"tag-a", b"x").unwrap();
        let mut pf2 = pf;
        // Abrir con otra etiqueta usa otra clave -> no autentica (no Perforada).
        assert_eq!(abrir(&mut pf2, b"tag-b", &lacre), Err(SelloError::Autenticacion));
    }

    #[test]
    fn rechaza_lacre_truncado() {
        let mut pf = Perforable::nueva().unwrap();
        assert!(matches!(abrir(&mut pf, b"t", b"QPS1short"), Err(SelloError::Formato(_))));
        assert!(matches!(abrir(&mut pf, b"t", &[]), Err(SelloError::Formato(_))));
    }

    #[test]
    fn rechaza_magic_erroneo_con_longitud_valida() {
        // Un blob de longitud suficiente pero con magic incorrecto: la única vía
        // a `Formato("magic")` (los truncados caen antes por longitud).
        let pf = Perforable::nueva().unwrap();
        let mut lacre = sellar(&pf, b"t", b"x").unwrap();
        lacre[0] ^= 0xff; // rompe el magic, conserva la longitud
        let mut pf2 = pf;
        assert!(matches!(abrir(&mut pf2, b"t", &lacre), Err(SelloError::Formato(_))));
    }

    #[test]
    fn sellar_sobre_etiqueta_perforada_falla() {
        let mut pf = Perforable::nueva().unwrap();
        let lacre = sellar(&pf, b"t", b"x").unwrap();
        abrir(&mut pf, b"t", &lacre).unwrap(); // perfora la clave de "t"
        assert_eq!(sellar(&pf, b"t", b"otro"), Err(SelloError::Perforada));
    }
}

// ---------------------------------------------------------------------------
// Custodia por umbral del DOCUMENTO (feature `escrow`)
// ---------------------------------------------------------------------------
//
// Shamir aplicado al DOCUMENTO, no solo a la semilla del servidor: se cifra el
// documento bajo una clave de contenido ALEATORIA y se reparte ESA clave en
// k-de-n comparticiones. Descifrar exige juntar al menos k. La clave no se
// deriva de ninguna frase y no vive en ningún sitio salvo repartida — «la
// seguridad vive en la clave y el AEAD»: aquí la clave la custodian n personas.

/// Errores de [`encode_con_custodia`] / [`decode_con_custodia`].
#[cfg(feature = "escrow")]
#[derive(Debug)]
pub enum CustodiaError {
    /// No hubo entropía del sistema para la clave de contenido o el nonce.
    SinEntropia,
    /// El reparto o la reconstrucción de Shamir falló: umbral no alcanzado,
    /// comparticiones de repartos distintos, o alguna corrupta.
    Reparto(crate::shamir::ShamirError),
    /// El lacre está truncado o no es de este formato.
    Formato(&'static str),
    /// Las comparticiones reconstruyen algo que no mide una clave de contenido.
    ClaveInvalida,
    /// El AEAD no validó: comparticiones equivocadas (pero de la longitud justa)
    /// o lacre alterado.
    Descifrado,
}

#[cfg(feature = "escrow")]
impl From<crate::shamir::ShamirError> for CustodiaError {
    fn from(e: crate::shamir::ShamirError) -> Self {
        Self::Reparto(e)
    }
}

#[cfg(feature = "escrow")]
impl core::fmt::Display for CustodiaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SinEntropia => write!(f, "sin entropía del sistema para la clave o el nonce"),
            Self::Reparto(e) => write!(f, "reparto/reconstrucción de Shamir: {e}"),
            Self::Formato(m) => write!(f, "lacre con formato inválido: {m}"),
            Self::ClaveInvalida => write!(f, "las comparticiones no reconstruyen una clave de contenido"),
            Self::Descifrado => write!(f, "el lacre no descifró (comparticiones equivocadas o alterado)"),
        }
    }
}
#[cfg(feature = "escrow")]
impl std::error::Error for CustodiaError {}

/// Magia del lacre de custodia. Formato: `magic(4) ‖ nonce(24) ‖ ciphertext‖tag`.
#[cfg(feature = "escrow")]
const CUSTODIA_MAGIC: &[u8; 4] = b"QCU1";

/// Cifra `datos` bajo una clave de contenido aleatoria y reparte esa clave en
/// `total` comparticiones de Shamir con umbral `umbral`. Devuelve el lacre y las
/// comparticiones para repartir entre custodios. Descifrar exigirá `umbral` de
/// ellas ([`decode_con_custodia`]).
///
/// Los límites de `umbral`/`total` los impone y los verifica
/// [`crate::shamir::split`] (falla ruidosamente si no tienen sentido); aquí no se
/// rellenan defectos. La clave de contenido se borra tras repartirla: solo debe
/// vivir en las comparticiones.
#[cfg(feature = "escrow")]
pub fn encode_con_custodia(
    datos: &[u8],
    umbral: u8,
    total: u8,
) -> Result<(Vec<u8>, Vec<crate::shamir::Share>), CustodiaError> {
    let mut clave =
        crate::aleatorio::bytes::<{ cipher::KEY_LEN }>().map_err(|_| CustodiaError::SinEntropia)?;
    let mut nonce = [0u8; NONCE_LEN];
    crate::aleatorio::llenar(&mut nonce).map_err(|_| CustodiaError::SinEntropia)?;

    // Repartir ANTES de cifrar: si el reparto no es válido (umbral absurdo), no
    // se llega a producir un lacre huérfano que nadie podría abrir. Se borra la
    // clave también en ESE camino de error (simetría de zeroización del módulo).
    let comparticiones = match crate::shamir::split(&clave, umbral, total) {
        Ok(c) => c,
        Err(e) => {
            antihacker::wipe(&mut clave);
            return Err(e.into());
        }
    };

    let ct = cipher::encrypt(&clave, &nonce, datos, CUSTODIA_MAGIC);
    antihacker::wipe(&mut clave); // la clave solo debe sobrevivir REPARTIDA

    let mut blob = Vec::with_capacity(4 + NONCE_LEN + ct.len());
    blob.extend_from_slice(CUSTODIA_MAGIC);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    Ok((blob, comparticiones))
}

/// Abre un lacre de [`encode_con_custodia`] reconstruyendo la clave de contenido
/// a partir de al menos `umbral` comparticiones. Falla si no se alcanza el
/// umbral, si las comparticiones son de otro reparto, o si el lacre fue alterado.
#[cfg(feature = "escrow")]
pub fn decode_con_custodia(
    blob: &[u8],
    comparticiones: &[crate::shamir::Share],
) -> Result<Vec<u8>, CustodiaError> {
    if blob.len() < 4 + NONCE_LEN {
        return Err(CustodiaError::Formato("truncado"));
    }
    if &blob[..4] != CUSTODIA_MAGIC {
        return Err(CustodiaError::Formato("magic"));
    }
    // combine verifica el umbral y la integridad del secreto reconstruido.
    let clave_reconstruida = crate::shamir::combine(comparticiones)?;
    if clave_reconstruida.len() != cipher::KEY_LEN {
        return Err(CustodiaError::ClaveInvalida);
    }
    let mut clave = [0u8; cipher::KEY_LEN];
    clave.copy_from_slice(&clave_reconstruida);

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob[4..4 + NONCE_LEN]);
    let ct = &blob[4 + NONCE_LEN..];

    let resultado = cipher::decrypt(&clave, &nonce, ct, CUSTODIA_MAGIC)
        .map_err(|_| CustodiaError::Descifrado);
    antihacker::wipe(&mut clave);
    resultado
}

#[cfg(all(test, feature = "escrow"))]
mod tests_custodia {
    use super::*;

    #[test]
    fn ida_y_vuelta_con_el_umbral() {
        let datos = b"acta reservada bajo custodia de tres";
        let (blob, partes) = encode_con_custodia(datos, 3, 5).unwrap();
        // Cualquier subconjunto de 3 abre.
        assert_eq!(decode_con_custodia(&blob, &partes[0..3]).unwrap(), datos);
        assert_eq!(decode_con_custodia(&blob, &partes[2..5]).unwrap(), datos);
    }

    /// CASO ROJO (D33): con MENOS del umbral no se abre. Un mutante que ignorara
    /// el umbral en `combine` pondría esto rojo por la vía real.
    #[test]
    fn menos_del_umbral_no_abre() {
        let datos = b"secreto";
        let (blob, partes) = encode_con_custodia(datos, 3, 5).unwrap();
        match decode_con_custodia(&blob, &partes[0..2]) {
            Err(CustodiaError::Reparto(_)) => {}
            otro => panic!("con 2 de 3 no debía abrir, salió {otro:?}"),
        }
    }

    #[test]
    fn comparticiones_de_otro_reparto_no_abren() {
        let (blob, _partes) = encode_con_custodia(b"documento A", 2, 3).unwrap();
        let (_blob_b, partes_b) = encode_con_custodia(b"documento B", 2, 3).unwrap();
        // Umbral alcanzado en número, pero de OTRO reparto: la integridad de
        // Shamir o el AEAD lo rechazan; nunca devuelve datos.
        assert!(decode_con_custodia(&blob, &partes_b[0..2]).is_err());
    }

    #[test]
    fn lacre_alterado_no_abre() {
        let (mut blob, partes) = encode_con_custodia(b"integridad", 2, 3).unwrap();
        *blob.last_mut().unwrap() ^= 0xff; // altera el tag AEAD
        assert!(matches!(
            decode_con_custodia(&blob, &partes[0..2]),
            Err(CustodiaError::Descifrado)
        ));
    }

    #[test]
    fn rechaza_lacre_truncado_o_magic() {
        let (_blob, partes) = encode_con_custodia(b"x", 2, 3).unwrap();
        assert!(matches!(decode_con_custodia(b"QCU1corto", &partes[0..2]), Err(CustodiaError::Formato(_))));
        assert!(matches!(decode_con_custodia(&[], &partes[0..2]), Err(CustodiaError::Formato(_))));
    }

    /// Borde (sugerido por la revisión): un blob que pasa el chequeo de longitud
    /// mínima (>= 4+24) y el magic, pero con el ciphertext más corto que el tag
    /// AEAD — no debe entrar en pánico, sale `Descifrado`.
    #[test]
    fn lacre_con_magic_pero_sin_tag_no_entra_en_panico() {
        let (blob, partes) = encode_con_custodia(b"contenido real", 2, 3).unwrap();
        let recortado = &blob[..4 + NONCE_LEN + 3]; // magic + nonce + 3 bytes (< 16 del tag)
        assert!(matches!(
            decode_con_custodia(recortado, &partes[0..2]),
            Err(CustodiaError::Descifrado)
        ));
    }

    /// D8: muchos documentos, tamaños y subconjuntos del umbral.
    #[test]
    fn simulacion_muchos_documentos() {
        for i in 0..120usize {
            let datos = format!("documento numero {i} con longitud variable {}", "x".repeat(i));
            let (blob, partes) = encode_con_custodia(datos.as_bytes(), 2, 4).unwrap();
            // rota el subconjunto de 2 comparticiones que se usa
            let a = i % 4;
            let b = (i + 1) % 4;
            let sub = [partes[a].clone(), partes[b].clone()];
            assert_eq!(decode_con_custodia(&blob, &sub).unwrap(), datos.as_bytes());
        }
    }
}

// ---------------------------------------------------------------------------
// Modo DISCRETO — contenedor sin cabecera en claro (PURB, feature `discreto`)
// ---------------------------------------------------------------------------
//
// Un PURB (Padded Uniform Random Blob, Nikitin et al. 2019): el contenedor NO
// lleva cabecera en claro —ni magic, ni versión, ni `codebook_id`, ni los
// parámetros del KDF—, y su longitud está acolchada con Padmé. Sin la clave, el
// blob es indistinguible de bytes uniformes: no se puede fingerprintear como
// Quipu ni leer su configuración (cierra el N9 del modelo de amenaza a cambio de
// renunciar a la flexibilidad).
//
// Layout: salt(16) ‖ nonce(24) ‖ ciphertext‖tag. Los parámetros del KDF son
// FIJOS (canónicos, `EQUILIBRADO`): no viajan y no dejan huella. El AAD es un
// dominio fijo que NO viaja en el blob (ata el modo sin filtrar nada).
//
// Coste honesto, y hay que decirlo:
//  - Sin magic, el decodificador NO distingue «frase/pepper equivocados» de «no
//    es un contenedor Quipu»: los dos fallan idénticos. Un error distinto sería
//    justo la huella que este modo evita.
//  - Parámetros FIJOS: este modo no tiene escalera de coste (LIGERO/FUERTE). Si
//    necesitas otro coste, no es este el modo — elegirlo lo dejaría escrito.

/// Errores del modo discreto.
#[cfg(feature = "discreto")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscretoError {
    /// No hubo entropía del sistema para el salt o el nonce.
    SinEntropia,
    /// El blob ni siquiera cabe: salt(16) + nonce(24) + tag(16).
    Truncado,
    /// No autenticó. **Indistinguible por diseño** entre «frase/pepper
    /// equivocados» y «esto no es un contenedor discreto de Quipu».
    NoAutentica,
}

#[cfg(feature = "discreto")]
impl core::fmt::Display for DiscretoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SinEntropia => write!(f, "sin entropía del sistema para salt/nonce"),
            Self::Truncado => write!(f, "el blob discreto está truncado"),
            Self::NoAutentica => write!(f, "el blob discreto no autenticó (frase/pepper, o no es uno)"),
        }
    }
}
#[cfg(feature = "discreto")]
impl std::error::Error for DiscretoError {}

/// Dominio del AEAD del modo discreto. NO viaja en el blob: ata el modo sin
/// dejar huella visible.
#[cfg(feature = "discreto")]
const DISCRETO_AAD: &[u8] = b"quipu/v1/discreto";

/// Longitud del tag Poly1305.
#[cfg(feature = "discreto")]
const TAG_LEN: usize = 16;

/// Cifra `data` en un contenedor **discreto** (PURB): sin cabecera en claro,
/// parámetros KDF fijos y longitud acolchada con Padmé. El blob resultante es
/// indistinguible de bytes uniformes sin la clave. `pepper` puede ir vacío.
#[cfg(feature = "discreto")]
pub fn encode_discreto(data: &[u8], passphrase: &str, pepper: &[u8]) -> Result<Vec<u8>, DiscretoError> {
    crate::selftest::ensure();

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    crate::aleatorio::llenar(&mut salt).map_err(|_| DiscretoError::SinEntropia)?;
    crate::aleatorio::llenar(&mut nonce).map_err(|_| DiscretoError::SinEntropia)?;

    // Parámetros FIJOS: sin huella de configuración (N9).
    let params = KdfParams::default();
    let mut master = kdf::derive_master_key(passphrase, &salt, pepper, &params);
    let mut cipher_key = kdf::derive_subkey(&master, CIPHER_SUBKEY_INFO);
    antihacker::wipe(&mut master);

    let mut padded = prelayers::pad(data); // Padmé: la longitud no delata el tamaño exacto
    let ct = cipher::encrypt(&cipher_key, &nonce, &padded, DISCRETO_AAD);
    antihacker::wipe(&mut cipher_key);
    antihacker::wipe(&mut padded); // el plaintext acolchado no debe sobrevivir

    let mut blob = Vec::with_capacity(SALT_LEN + NONCE_LEN + ct.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// Operación inversa de [`encode_discreto`]. Falla con [`DiscretoError::NoAutentica`]
/// si la frase/pepper no corresponden **o** si el blob no es un contenedor
/// discreto: los dos casos son indistinguibles a propósito.
#[cfg(feature = "discreto")]
pub fn decode_discreto(blob: &[u8], passphrase: &str, pepper: &[u8]) -> Result<Vec<u8>, DiscretoError> {
    crate::selftest::ensure();

    if blob.len() < SALT_LEN + NONCE_LEN + TAG_LEN {
        return Err(DiscretoError::Truncado);
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&blob[..SALT_LEN]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob[SALT_LEN..SALT_LEN + NONCE_LEN]);
    let ct = &blob[SALT_LEN + NONCE_LEN..];

    let params = KdfParams::default();
    let mut master = kdf::derive_master_key(passphrase, &salt, pepper, &params);
    let mut cipher_key = kdf::derive_subkey(&master, CIPHER_SUBKEY_INFO);
    antihacker::wipe(&mut master);

    let descifrado = cipher::decrypt(&cipher_key, &nonce, ct, DISCRETO_AAD);
    antihacker::wipe(&mut cipher_key);

    let mut padded = descifrado.map_err(|_| DiscretoError::NoAutentica)?;
    // NO usar `?` en unpad: un retorno temprano dejaría el PLAINTEXT descifrado
    // sin borrar, y este es el modo de resistencia forense (mismo idiom que el
    // `decode` normal). Se liga el resultado, se borra el acolchado, y se retorna.
    let resultado = prelayers::unpad(&padded)
        .map(|d| d.to_vec())
        .map_err(|_| DiscretoError::NoAutentica);
    antihacker::wipe(&mut padded);
    resultado
}

#[cfg(all(test, feature = "discreto"))]
mod tests_discreto {
    use super::*;

    #[test]
    fn ida_y_vuelta_con_pepper() {
        let data = b"acta discreta, indistinguible de ruido";
        let blob = encode_discreto(data, "frase larga y aleatoria", b"pepper").unwrap();
        assert_eq!(decode_discreto(&blob, "frase larga y aleatoria", b"pepper").unwrap(), data);
    }

    /// NO hay cabecera en claro: el blob mide EXACTAMENTE salt+nonce+pad+tag, sin
    /// un solo byte de magic/versión/parámetros.
    #[test]
    fn sin_cabecera_la_longitud_es_exacta() {
        let data = b"contenido";
        let blob = encode_discreto(data, "frase", b"").unwrap();
        let esperado = SALT_LEN + NONCE_LEN + prelayers::pad(data).len() + TAG_LEN;
        assert_eq!(blob.len(), esperado, "hay bytes de cabecera que no deberían estar");
    }

    /// Dos cifrados del mismo dato son DISTINTOS (salt/nonce aleatorios) — no hay
    /// prefijo constante que fingerprintee el modo.
    #[test]
    fn dos_cifrados_no_comparten_prefijo_fijo() {
        let data = b"igual dato";
        let a = encode_discreto(data, "f", b"").unwrap();
        let b = encode_discreto(data, "f", b"").unwrap();
        assert_ne!(a, b);
        assert_ne!(&a[..SALT_LEN], &b[..SALT_LEN], "el salt debe ser aleatorio");
    }

    #[test]
    fn frase_equivocada_no_autentica() {
        let blob = encode_discreto(b"x", "correcta", b"").unwrap();
        assert_eq!(decode_discreto(&blob, "incorrecta", b""), Err(DiscretoError::NoAutentica));
        // pepper equivocado, mismo resultado indistinguible
        assert_eq!(decode_discreto(&blob, "correcta", b"pepper"), Err(DiscretoError::NoAutentica));
    }

    /// CASO ROJO (D33): bytes ALEATORIOS (no un contenedor) no se aceptan jamás.
    /// El control que discrimina: un contenedor real SÍ abre.
    #[test]
    fn ruido_no_se_acepta_pero_lo_real_si() {
        let ruido = crate::aleatorio::bytes::<200>().unwrap().to_vec();
        assert_eq!(decode_discreto(&ruido, "cualquiera", b""), Err(DiscretoError::NoAutentica));
        let real = encode_discreto(b"real", "clave", b"").unwrap();
        assert_eq!(decode_discreto(&real, "clave", b"").unwrap(), b"real");
    }

    #[test]
    fn alterado_no_autentica() {
        let mut blob = encode_discreto(b"integridad", "c", b"").unwrap();
        *blob.last_mut().unwrap() ^= 0xff;
        assert_eq!(decode_discreto(&blob, "c", b""), Err(DiscretoError::NoAutentica));
    }

    #[test]
    fn truncado() {
        assert_eq!(decode_discreto(&[0u8; 10], "c", b""), Err(DiscretoError::Truncado));
    }

    /// La longitud oculta el tamaño exacto dentro del bucket de Padmé: dos datos
    /// de tamaños distintos pero del mismo bucket dan blobs de igual longitud.
    #[test]
    fn la_longitud_cae_en_buckets_de_padme() {
        // pad() acolcha a la misma longitud en un rango; tomamos dos tamaños que
        // Padmé lleva al mismo bucket.
        let corto = prelayers::pad(&[0u8; 100]).len();
        let mut n = 100;
        while prelayers::pad(&vec![0u8; n]).len() == corto {
            n += 1;
        }
        // n-1 y 100 comparten bucket → blobs de igual longitud.
        let a = encode_discreto(&[7u8; 100], "k", b"").unwrap();
        let b = encode_discreto(&vec![7u8; n - 1], "k", b"").unwrap();
        assert_eq!(a.len(), b.len(), "mismo bucket de Padmé → misma longitud de blob");
    }

    /// D8: muchos round-trips de tamaños variados.
    #[test]
    fn simulacion_muchos() {
        for i in 0..150usize {
            let data = vec![(i % 251) as u8; i];
            let blob = encode_discreto(&data, "frase de prueba", b"p").unwrap();
            assert_eq!(decode_discreto(&blob, "frase de prueba", b"p").unwrap(), data);
        }
    }
}
