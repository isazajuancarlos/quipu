// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

//! Reparto ciego: dos AEAD independientes, y **ninguno de los dos llega a ver
//! el texto en claro**.
//!
//! # Qué amenaza cubre, que NO es la de siempre
//!
//! El núcleo de Quipu protege contra quien intercepta el contenedor. Este módulo
//! protege contra otra cosa: **que una de las librerías de las que dependemos
//! esté comprometida**. No es una amenaza imaginaria — los ataques a los
//! registros de paquetes de 2026 fueron seguidos y sistemáticos — y contra ella
//! el cifrado normal no hace nada, porque el crate comprometido corre en el
//! mismo proceso, con la misma memoria, y ve el claro y la clave antes que
//! nadie.
//!
//! # Por qué NO es una cascada, que era lo primero que se pensó
//!
//! Lo evidente es encadenar: `AES(XChaCha(P))`. Eso sirve contra un **fallo
//! criptoanalítico** de una de las dos —hay que romper las dos para leer— y no
//! sirve para nada contra una librería comprometida: **la capa de dentro recibe
//! el claro**. Un `chacha20poly1305` con puerta trasera lo tiene entero antes de
//! que la capa de fuera exista.
//!
//! Aquí se reparte en vez de encadenar:
//!
//! ```text
//!     S1 = aleatorio(|P|)                 S2 = P xor S1
//!     C1 = AES-256-GCM(K1, S1)            C2 = XChaCha20-Poly1305(K2, S2)
//! ```
//!
//! `S1` es uniforme por construcción y `S2` lo es porque es `P` enmascarado con
//! `S1`. **Cada implementación de algoritmo recibe ruido**: por separado,
//! ninguna de las dos contiene un solo bit de información sobre `P`. Y sigue
//! haciendo falta romper las dos para leer, igual que la cascada — así que el
//! reparto no cambia una propiedad por otra, las tiene las dos.
//!
//! «Implementación de algoritmo» y no «crate», y la diferencia no es
//! pedantería: los dos caminos comparten paquetes, `aead` entre ellos, y ése sí
//! veía las dos mitades. Está medido y explicado abajo, en «Hasta dónde llega
//! el AND» — léelo antes de citar este módulo en ninguna parte.
//!
//! # Esto NO es criptografía inventada
//!
//! El reparto `P = S1 xor S2` con `S1` uniforme es el cuaderno de un solo uso
//! (Shannon, 1949) y a la vez el caso `k = n = 2` del esquema de Shamir, que ya
//! vive en [`crate::shamir`]. Su secreto es **perfecto**, no computacional: no
//! hay supuesto que romper.
//!
//! **Dos matices que la revisión del 2026-08-17 obligó a escribir, porque «no
//! hay supuesto que romper» es una frase que alguien va a citar.**
//!
//! 1. Lo perfecto es el secreto de **cada mitad por separado**. La propiedad que
//!    añade `QBL2` —que juntar las dos llamadas no dé el claro— es
//!    COMPUTACIONAL: descansa en que HKDF-SHA256 sea un PRF. Son dos
//!    afirmaciones distintas y conviene no mezclarlas.
//! 2. **`S1` no es exactamente uniforme.** `aleatorio::llenar` RECHAZA los
//!    búferes que no pasan `salud_de`, así que `S1` es uniforme *condicionada a
//!    pasar la prueba*, y quien vea `S2` puede descartar los `P` cuyo `S1`
//!    habría sido rechazado. La distancia a la uniforme es la probabilidad de
//!    rechazo, dominada por la racha: ~2⁻⁴⁴ con 4 KiB, ~2⁻³⁶ con 1 MiB, ~2⁻²⁶
//!    con 1 GiB. Es irrelevante en la práctica y **deja de serlo el día que
//!    alguien endurezca la prueba de salud**, que es exactamente por qué está
//!    escrito aquí y no en la cabeza de nadie.
//!
//!    Efecto colateral del mismo diseño: `llenar` no re-muestrea —borra el búfer
//!    y falla, que es lo correcto: re-muestrear enmascararía un generador
//!    degradado—, así que `api::encode_to_blob_blindado` entra en pánico con esa
//!    misma probabilidad por operación. El pánico borra los secretos antes de
//!    rendirse; está en `armar_blob` con su motivo.
//!
//! Lo que este módulo aporta es la COMPOSICIÓN —qué
//! recibe cada capa, cómo se derivan las claves, qué las ata— y eso no es un
//! primitivo. La regla de la casa sigue intacta: no se inventa criptografía.
//!
//! # El precio, dicho antes de que nadie lo descubra
//!
//! **La salida ocupa el doble** (`2|P|` más dos tags), y eso no es un detalle de
//! implementación que se pueda optimizar luego: es **necesario**. Cualquier
//! construcción que conserve el tamaño tiene por fuerza un componente que toca
//! el claro el primero, y ese componente ve el claro. Mantener a todos ciegos
//! cuesta el doble de salida. Por eso el modo es OPT-IN (`--features blindaje`)
//! y no el camino por defecto: en el camino simbólico, el doble de bytes es el
//! doble de glifos.
//!
//! # HASTA DÓNDE LLEGA EL «AND», que es más corto de lo que parece
//!
//! Esto lo encontró la revisión de seguridad del 2026-08-16 y **corrige lo que
//! decía la primera versión de este comentario**. Es el límite más importante
//! del módulo y va antes que ninguna otra advertencia.
//!
//! **Ni `aes-gcm` ni `chacha20poly1305` implementan el `fn encrypt` que recibe
//! el mensaje.** Los dos heredan el `impl<T: AeadInOut> Aead for T` genérico del
//! crate `aead`, cuyo cuerpo hace `buffer.extend_from_slice(payload.msg)`. O
//! sea que **`aead` recibe `S1` en una llamada y `S2` en la siguiente**, en el
//! mismo proceso y el mismo turno, y `S1 xor S2 = P`. Debajo pasa lo mismo con
//! `cipher`, `inout` y `crypto-common`, que son los que aplican el flujo de
//! clave sobre el búfer.
//!
//! Medido sobre `Cargo.lock`: de los cierres de dependencias de las dos capas,
//! **22 paquetes son COMPARTIDOS y solo 8 son exclusivos** —seis de AES (`aes`,
//! `ctr`, `ghash`, `polyval`, `cpubits`, `subtle`) y dos de ChaCha (`chacha20`,
//! `poly1305`)—. Y las dos vienen del mismo publicador (RustCrypto), así que los
//! dos sucesos del AND están correlacionados.
//!
//! **ESE RECUENTO ES DE UNA MEDICIÓN CON UN DEFECTO, y se conserva porque el
//! ARGUMENTO sigue valiendo, no el número.** Se calculó con un grafo indexado
//! solo por el NOMBRE del paquete, y el `Cargo.lock` de quipu tiene dos
//! `digest`, dos `crypto-common`, dos `block-buffer` y dos `sha2`: eso fusiona
//! ramas de generaciones distintas —daba `subtle` como compartido, y no lo es—.
//! Los números buenos, por `(nombre, versión)`, están abajo y en
//! `docs/AUDITORIA_PEGAMENTO.md`: **18 compartidos y 14 exclusivos**.
//!
//! **Lo que el reparto da de verdad, dicho con precisión:** las dos
//! IMPLEMENTACIONES DE ALGORITMO reciben cada una solo ruido, así que un fallo
//! criptoanalítico o una puerta trasera en `aes` o en `chacha20` no entrega
//! nada. Lo que NO da es inmunidad a que esté comprometido uno de los 22
//! paquetes compartidos, empezando por `aead` — 698 líneas de pegamento sin
//! glamour que nadie audita.
//!
//! **CERRADO EN `QBL2` (2026-08-17), y no como se esperaba.** El párrafo que
//! había aquí decía que costaría traer una capa de fuera de RustCrypto —`ring`,
//! `openssl`, `boring`— y que eso se proponía, no se hacía. Se cerró sin
//! importar ningún ecosistema, con dos XOR:
//!
//! **La capa AES no recibe `S1`, recibe `S1 xor M`**, donde `M` es una máscara
//! derivada por HKDF-SHA256 del maestro y del id del mensaje
//! ([`aplicar_mascara`]). Un crate del camino AEAD que vea las dos llamadas
//! obtiene `S1 xor M xor S2 = P xor M`, y sin `M` eso no es nada. El resto del
//! reparto no se toca: `S2` ya era uniforme y sigue viajando tal cual.
//!
//! **Lo que lo hace funcionar es un hecho de la cadena de suministro**, medido y
//! no supuesto: los **14 paquetes exclusivos** del camino AEAD —`aead`,
//! `cipher`, `inout`, `aes`, `ctr`, `ghash`, `polyval`, `chacha20`, `poly1305`,
//! `subtle`, `universal-hash`, `cpubits` y los dos AEAD— **no están en el cierre
//! de dependencias de `hkdf`/`sha2`**. Ninguno puede ver `M`. Lo vigila
//! `tests/pegamento_disjunto.rs`, que además enumera los compartidos que quedan
//! con su motivo y se pone rojo si aparece uno nuevo — porque esto cambia con un
//! `cargo update`, sin que nadie toque nuestro código.
//!
//! **Lo que sigue abierto, y ahora con el criterio delante en vez de un número.**
//! Este párrafo ha dicho «queda UNO» y luego «son DOS», y las dos veces estuvo
//! mal por la misma razón: un recuento no es un criterio. Lo que hay que decir es
//! **qué recibe cada paquete compartido y qué le faltaría** para leer el
//! documento. De los 18 de la intersección, cuatro tocan datos:
//!
//! | paquete | qué RECIBE por el camino legítimo | qué le faltaría |
//! |---|---|---|
//! | `zeroize` | **`S1` y `S2` en claro**: [`Mitad`] es `Zeroizing<Vec<u8>>` y `Drop` corre sobre las dos | **nada** |
//! | `getrandom` | **`S1` entero**, y además lo CONTROLA (`aleatorio::llenar`) | `S2`, que no ve |
//! | `block-buffer` | `S2 xor M` (envoltorio de `chacha20`) y bloques del HKDF | `S1`, que no ve |
//! | `hybrid-array` | es el TIPO de los bloques del mensaje en las dos rutas | según lo que instrumente |
//!
//! **Y sobre esa tabla manda el CIERRE DE DEPENDENCIAS, que es más pesimista.**
//! Los cuatro están compilados y enlazados dentro de `cipher` y de `digest`: un
//! crate comprometido no está obligado a esperar a que se le llame por donde
//! creemos, le vale un `Drop` o un inicializador. Así que la columna «qué le
//! faltaría» describe el ataque BARATO, no el techo. Para el techo: cualquiera de
//! los cuatro es un riesgo de un solo componente.
//!
//! En `QBL1` esto alcanzaba a los 22 compartidos entre las dos capas, `aead` el
//! primero; hoy no alcanza a ninguno de los 14 exclusivos del camino AEAD. Ése
//! es el avance, y es real; el «queda uno» no lo era.
//!
//! Traer una capa de fuera de RustCrypto sigue siendo la única forma de cerrar
//! también eso, y ESO sí sigue siendo una propuesta y no un hecho.
//!
//! *(Este párrafo decía «es UN paquete de 2 KiB» y sobrevivió a la corrección de
//! los otros cuatro sitios: la revisión del commit de arreglos lo encontró aquí,
//! catorce líneas por encima de su propia versión corregida y en el sitio más
//! visible de todos, el rustdoc público. Se deja escrito porque el modo de fallo
//! —corregir una afirmación y dejar viva su copia— es el que más veces ha pasado
//! en este archivo.)*
//!
//! **Por qué no bastaba cambiar de API**: `AeadInOut::encrypt_inout_detached`
//! quita el cuerpo de `aead` del camino pero deja `cipher` e `inout`, y habría
//! quedado una promesa más fuerte que el hecho. La máscara no depende de por
//! dónde entren los bytes.
//!
//! # De qué NO protege, que es tan importante como de qué sí
//!
//! - **De que esté comprometido `block-buffer` o `zeroize`.** Son los DOS que
//!   quedan, no uno — lo corrigió la revisión de seguridad del 2026-08-17, que
//!   encontró el contraejemplo al enunciado anterior. `block-buffer` está en las
//!   dos rutas y bufferiza bloques del hash. **`zeroize` es peor y por otra vía
//!   que la máscara no toca**: [`Mitad`] es `Zeroizing<Vec<u8>>`, así que
//!   `repartir` le entrega `S1` y `S2` EN CLARO por la puerta principal, en cada
//!   operación, y su XOR es el documento. No necesita ver `M` para nada.
//!   En `QBL1` eran 22 paquetes, `aead` incluido; ahora son dos, y ninguno de
//!   los dos es del camino AEAD.
//!
//!   **`zeroize` no se puede quitar de ahí, y tampoco serviría**: `kdf.rs`
//!   envuelve la clave maestra con el mismo crate, así que uno comprometido se
//!   la lleva por otra puerta y el modo entero cae igual. Es residuo declarado,
//!   no un defecto que esté esperando arreglo.
//! - **De que estén comprometidos LOS DOS crates de algoritmo.** Es un AND, no
//!   una garantía absoluta.
//! - **De un generador de aleatoriedad comprometido.** Si `S1` es predecible, el
//!   reparto se desmonta y `S2` es el claro enmascarado con algo conocido. Toda
//!   la seguridad del reparto descansa en [`crate::aleatorio`] — que, eso sí, es
//!   una superficie mucho más pequeña y ya tiene pruebas de salud continuas.
//! - **De un HKDF o un Argon2id comprometidos**, que ven la clave maestra.
//! - **De que el atacante ya esté leyendo tu memoria.** Esto reduce lo que ve un
//!   crate, no lo que ve un depurador.

use crate::aleatorio::{self, SinEntropia};
use crate::cipher;
use crate::kdf;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use zeroize::Zeroizing;

/// Marca de formato. `QBL2` = Quipu, BLindaje, versión 2.
///
/// La **v2** añade la máscara de [`INFO_M1`], que es lo que hace verdadera la
/// promesa del AND (ver «Hasta dónde llega el AND» en la cabecera del módulo).
/// El salto de marca no es cosmético: un `QBL1` abierto como `QBL2` devolvería
/// basura autenticada, así que el formato tiene que decir cuál es.
pub const MAGIA: &[u8; 4] = b"QBL2";
/// Identificador aleatorio por mensaje. Ata las dos capas entre sí y hace que
/// cada mensaje derive claves y nonces propios.
pub const ID_LEN: usize = 16;
/// Nonce de AES-256-GCM.
/// Largo del nonce de la capa AES-GCM. `pub` por lo mismo que [`INFO_K1`]: el
/// banco de residuo tiene que reconstruir el nonce real para poder abrir la capa
/// y así VALIDAR CONTRA EL ARTEFACTO la clave que busca, en vez de fiarse de que
/// la derivó bien.
pub const NONCE_AES: usize = 12;
/// Tag de Poly1305 y de GCM: 16 bytes cada uno.
const TAG: usize = 16;
/// Cabecera en claro: magia + id + largo de la primera capa.
const CABECERA: usize = 4 + ID_LEN + 4;

/// Etiquetas de dominio. Distintas por capa y por uso: la misma clave maestra
/// nunca produce dos veces el mismo material para cosas distintas.
///
/// # Por qué son `pub`, que no era el estado original
///
/// No son secretas —la seguridad descansa entera en `master`, y estas etiquetas
/// solo separan dominios—, y hacerlas visibles cierra un agujero del banco de
/// pruebas que la directiva 33 nombra: `tests/residuo_memoria.rs` tiene que
/// buscar en la memoria del proceso las claves de capa que
/// [`crate::antihacker::limpiar_pila`] dice borrar, y para eso tiene que
/// DERIVARLAS. Con las etiquetas privadas, el banco no tenía más remedio que
/// copiar el literal — o sea, **fabricar la aguja**, que es exactamente el
/// fallo por el que este repositorio ya midió cuatro ceros falsos: el control
/// plantaba la misma aguja inventada que la medición buscaba y los dos se daban
/// la razón sin tocar el código medido.
///
/// Públicas, el banco lee la etiqueta de donde la escribió el código medido.
pub const INFO_K1: &[u8] = b"quipu blindaje v1 :: clave capa AES-256-GCM";
/// Ver [`INFO_K1`].
pub const INFO_K2: &[u8] = b"quipu blindaje v1 :: clave capa XChaCha20-Poly1305";
/// Ver [`INFO_K1`].
pub const INFO_N1: &[u8] = b"quipu blindaje v1 :: nonce capa AES-256-GCM";
/// Ver [`INFO_K1`].
pub const INFO_N2: &[u8] = b"quipu blindaje v1 :: nonce capa XChaCha20-Poly1305";
/// Etiqueta de la MÁSCARA del reparto, que es la pieza nueva de `QBL2`.
///
/// Lleva `v2` en el texto a propósito: es material que no existía en `QBL1`, y
/// que una etiqueta nueva se distinga de las cuatro viejas **por el prefijo** es
/// lo que mantiene inyectiva la concatenación (ver [`material`] y
/// [`pruebas::ninguna_etiqueta_de_dominio_es_prefijo_de_otra`]).
pub const INFO_M1: &[u8] = b"quipu blindaje v2 :: mascara de la mitad dependiente del claro";

/// Lo máximo que HKDF-Expand puede entregar de una vez: `255 * 32` bytes.
///
/// `pub` por lo mismo que [`INFO_K1`]: fija el TROCEADO de la máscara, o sea que
/// es parte del formato, y el banco de residuo tiene que poder rehacerla para
/// validar sus agujas contra el artefacto en vez de fabricarlas.
///
/// No es un parámetro que se pueda subir: lo fija el RFC 5869, y `derive_stream`
/// entra en pánico si se le pide más. Por eso la máscara se deriva por TRAMOS
/// con un contador en la etiqueta, en vez de en una sola llamada — un mensaje
/// blindado no tiene techo de tamaño y éste lo tendría a 8 KiB.
pub const TRAMO_HKDF: usize = 255 * 32;

/// Lo que puede salir mal al abrir un blindaje.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlindajeError {
    /// El blob no llega ni a la cabecera, o el largo declarado de la primera capa
    /// no cuadra con lo que hay, o la marca no es de esta familia. Son fallos de
    /// FORMATO: no dicen nada de la clave y se pueden distinguir sin peligro.
    ///
    /// **Ojo a lo que NO significa**: un marco que no cuadra es casi siempre un
    /// blob MANIPULADO —el campo de largo va en claro y sin autenticar, así que
    /// voltear un bit ahí cae aquí—. Para «esto es de otra versión del formato»
    /// está [`BlindajeError::OtraVersion`], y confundirlos le dice a la víctima
    /// que busque una versión vieja del programa cuando lo que pasó es que
    /// alguien le tocó el archivo. Lo cazó la revisión de seguridad del
    /// 2026-08-17, que midió las tres formas de llegar aquí.
    Formato,
    /// La marca empieza por `QBL` y **no es `QBL2`**: parece un contenedor de otra
    /// versión de este mismo formato, típicamente un `QBL1` anterior al
    /// 2026-08-17.
    ///
    /// # ES UN HECHO AUTENTICADO, y hasta el 2026-08-17 no lo era
    ///
    /// La marca `QBL*` viaja **en claro** dentro del cuerpo y no la cubre ningún
    /// AEAD, así que mirarla es mirar algo que el atacante escribe. Durante un
    /// día este error se concedía con esos tres bytes, y la revisión adversaria
    /// lo rompió con **uno**: escribir `QBL1` encima de un `QBL2` forzaba el
    /// diagnóstico, con la contraseña correcta y con la equivocada.
    ///
    /// Se dio por imposible de cerrar —«la versión dice cómo autenticar, así que
    /// hay que leerla antes de autenticar»—, y la conclusión no se seguía: **no
    /// hace falta autenticarla antes, basta no afirmarla hasta después**. Hoy el
    /// blob tiene que ABRIR bajo la versión que dice ser
    /// ([`autentica_como_otra_version`]) para llevarse este error. Un atacante no
    /// puede conseguirlo sin la clave.
    ///
    /// Lo que se puede decir de este error, entonces: **quien lo recibe tiene un
    /// contenedor que de verdad es de otra versión de esta familia, y su clave lo
    /// abre.** Sin la clave correcta el diagnóstico cae a
    /// [`BlindajeError::NoAutentica`] —no se puede afirmar de qué versión es algo
    /// que no se puede abrir—, y eso es correcto, no una pérdida.
    OtraVersion,
    /// Alguna de las dos capas no autenticó. **No se dice cuál a propósito**: la
    /// distinción no le sirve a nadie legítimo y a un atacante le diría qué capa
    /// atacar. Las dos se verifican siempre, sin cortocircuito — y eso lo sujeta
    /// [`pruebas::las_dos_capas_se_intentan_aunque_la_primera_falle`], no este
    /// comentario.
    ///
    /// # PERO EL RELOJ SÍ LO DICE, y la promesa era más fuerte que el hecho
    ///
    /// Medido por la revisión adversaria del 2026-08-17: **`aes-gcm` y
    /// `chacha20poly1305` cortocircuitan POR DENTRO** —solo aplican el flujo de
    /// clave si el tag valida—, así que la capa que falla se ahorra una pasada de
    /// `|P|` bytes. Sobre 4 MiB, cuatro repeticiones, la diferencia fue del 8 % al
    /// 70 %, con el signo consistente.
    ///
    /// **No es explotable**: para llegar al estado que la produce hay que
    /// conseguir que una capa autentique y la otra no, o sea falsificar un tag
    /// bajo una clave que no se tiene. Y no está en nuestra mano cerrarlo: el
    /// cortocircuito es de los dos crates AEAD, no de este módulo.
    ///
    /// Se escribe porque el `Err` que no distingue es una decisión de diseño
    /// REAL y alguien la va a citar como si cerrara el canal entero. Cierra el
    /// canal del VALOR devuelto; el del tiempo no.
    NoAutentica,
}

impl core::fmt::Display for BlindajeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Formato => write!(f, "el blob no tiene la forma de un blindaje QBL2 (marco inválido o manipulado)"),
            Self::OtraVersion => write!(
                f,
                "el blob es un blindaje de otra versión del formato (no QBL2), y \
                 AUTENTICA como tal: no es la contraseña, es el formato"
            ),
            Self::NoAutentica => write!(f, "el blindaje no autentica: clave, aad o contenido alterados"),
        }
    }
}

impl std::error::Error for BlindajeError {}

/// Una mitad del reparto. Es material equivalente al claro —`S1 xor S2 = P`—
/// así que se borra al salir de ámbito, igual que una clave.
type Mitad = Zeroizing<Vec<u8>>;

/// Reparte `claro` en dos mitades de las que ninguna, por separado, dice nada.
///
/// Está aparte —y es visible para las pruebas— porque es LA propiedad del
/// módulo: si esto no reparte de verdad, todo lo demás es teatro. La prueba que
/// lo vigila busca un testigo del claro dentro de cada mitad.
fn repartir(claro: &[u8]) -> Result<(Mitad, Mitad), SinEntropia> {
    let mut s1 = Zeroizing::new(vec![0u8; claro.len()]);
    aleatorio::llenar(&mut s1)?;
    let s2 = Zeroizing::new(claro.iter().zip(s1.iter()).map(|(p, r)| p ^ r).collect::<Vec<u8>>());
    Ok((s1, s2))
}

// POR HILO, y no es un detalle de estilo.
//
// La primera versión era un `static AtomicUsize` global, y eso hizo INTERMITENTE
// al banco: `cargo test` corre las pruebas del mismo binario en paralelo, así que
// cualquier otra que cifrara o descifrara entre el `store(0)` y el `load()` de la
// prueba corrompía la cuenta. Falló 1 de cada 6 corridas.
//
// Y el precio no era una prueba molesta: **un banco inestable deja
// `sin-caso-rojo` sin poder medir nada** —se niega, y con razón, porque si el
// banco ya está rojo cada hunk saldría «cubierto» por un fallo que ya estaba—.
// Se descubrió justo así, midiendo la cobertura de este mismo cambio.
//
// `thread_local!` lo cierra por construcción: cada prueba corre en su hilo y
// `aplicar_mascara` se ejecuta en el hilo de quien la llama.
#[cfg(test)]
thread_local! {
    /// Veces que se ha intentado abrir cada capa, en este hilo. Sujeta la
    /// promesa «LAS DOS SIEMPRE, sin cortocircuito», que hasta el 2026-08-17 no
    /// la probaba nadie: el banco de mutación metió un cortocircuito explícito
    /// —no abrir la capa 2 si la 1 falló— y las 235 pruebas siguieron verdes,
    /// porque el RESULTADO es idéntico y lo único que cambia es el tiempo. Que es
    /// justo lo que el módulo promete que no se puede medir.
    pub(crate) static VECES_CAPA: std::cell::Cell<(usize, usize)> =
        const { std::cell::Cell::new((0, 0)) };
}

#[cfg(test)]
thread_local! {
    /// Cuántas veces se ha llamado a [`aplicar_mascara`] en este hilo. Solo en
    /// pruebas, y existe para sujetar DÓNDE se llama, no cuántas veces: ver
    /// [`pruebas::un_blob_que_no_autentica_no_deriva_ni_un_byte_de_mascara`].
    pub(crate) static VECES_ENMASCARADO: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}


/// Aplica —o quita— la máscara de la capa 1. Es su propia inversa: XOR dos veces
/// deja el buffer como estaba.
///
/// # Qué compra, y es LA razón de existir de `QBL2`
///
/// Sin ella, el reparto `P = S1 xor S2` es ciego para cada IMPLEMENTACIÓN DE
/// ALGORITMO y no para el PEGAMENTO: `aead`, `cipher` e `inout` reciben `S1` en
/// una llamada y `S2` en la siguiente, en el mismo proceso y el mismo turno, y
/// un XOR da el claro. Es la limitación que la cabecera del módulo documenta.
///
/// Con ella, la capa AES recibe `S1 xor M`. Un crate del camino AEAD que vea las
/// dos llamadas obtiene `P xor M`, que sin `M` no es nada.
///
/// # SOBRE QUÉ MITAD VA, y esto lo tuve mal
///
/// Va sobre **`S2`**, la mitad que depende del claro. La primera versión la
/// ponía sobre `S1` —la aleatoria— y escribía, con todas sus letras, que la capa
/// «daba igual» y que esto se dejaba anotado «para que nadie lo arregle
/// moviéndolo». Era falso, y lo encontró la revisión adversaria del 2026-08-17.
///
/// El álgebra, que es corta. Lo que ve un crate del camino AEAD:
///
/// ```text
///   máscara sobre S1:   X1 = S1 xor M      X2 = S2 = P xor S1
///   máscara sobre S2:   Y1 = S1            Y2 = S2 xor M = P xor S1 xor M
/// ```
///
/// Contra el pegamento SOLO, las dos son idénticas: `X1 xor X2 = Y1 xor Y2 =
/// P xor M`, y sin `M` eso no es nada. Ahí mi conclusión era correcta.
///
/// **Deja de serlo en cuanto `S1` es predecible**, que es un modo de fallo que
/// este mismo módulo declara abierto tres párrafos más abajo:
///
/// ```text
///   máscara sobre S1:   X2 xor S1 = P          <-- el claro ENTERO
///   máscara sobre S2:   Y2 xor S1 = P xor M    <-- sigue haciendo falta M
/// ```
///
/// Con la máscara sobre `S1`, la mitad SIN enmascarar es `P xor S1`: quien
/// prediga `S1` lee el documento sin tocar la criptografía. Con la máscara sobre
/// `S2` necesita además `M`, que vive en el camino del HKDF. **Enmascarar `S2`
/// domina estrictamente y cuesta exactamente lo mismo**; para que ganara la otra
/// posición haría falta un atacante que predijera `S2` sin predecir `S1`, y
/// predecir `S2` es conocer `P`.
///
/// # Por qué UNA máscara y no dos
///
/// Con la máscara en el sitio correcto, la segunda solo cubriría el caso de
/// predecir `S2`, que es el caso degenerado de arriba. Duplica el coste de
/// derivación —que no es despreciable: ver los números del CHANGELOG— y no
/// añade un escenario. *(El argumento anterior era «`S2` ya era uniforme por
/// construcción», y ése sí era circular: `S2` es uniforme PORQUE `S1` lo es.)*
///
/// # Hasta dónde llega, con los números
///
/// Cierra el agujero contra los **14 paquetes exclusivos** del camino AEAD
/// —`aead`, `cipher`, `inout`, `aes`, `ctr`, `ghash`, `polyval`, `chacha20`,
/// `poly1305`, `subtle`, `universal-hash`, `cpubits` y los dos AEAD—, que son
/// todos los que la cabecera de este módulo señalaba, `aead` el primero.
/// Ninguno está en el camino del HKDF, así que ninguno puede ver `M`.
///
/// NO lo cierra contra los **18 compartidos** con la derivación. De ésos, DOS
/// tocan datos y hay que nombrarlos: `block-buffer`, que bufferiza bloques del
/// hash, y **`zeroize`**, al que este mismo módulo le entrega `S1` y `S2` en
/// claro en cada operación porque [`Mitad`] es `Zeroizing<Vec<u8>>` — o sea que
/// a `zeroize` la máscara no le quita nada, y rompe el AND él solo. El resto
/// son tipos, plataforma o macros de compilación, y sobre esas últimas ver la
/// nota de `tests/pegamento_disjunto.rs`: en un modelo de cadena de suministro
/// un proc-macro comprometido es la MEJOR posición, no la más inocua.
/// Lo vigila `tests/pegamento_disjunto.rs`, que enumera esos 18 con su motivo y
/// se pone rojo si entra uno más.
///
/// # Lo que NO compra
///
/// Nada contra DOS crates coludiendo, ni contra un HKDF o un Argon2id
/// comprometidos —que ven la maestra y derivan la máscara ellos mismos—. Es un
/// AND, como todo el módulo.
///
/// **Y NADA CONTRA UNA COLISIÓN DE `id`: ahí la máscara es exactamente neutra.**
/// Se cancela en la diferencia, y el álgebra es de una línea:
///
/// ```text
///   C2 xor C2' = (S2 xor M xor KS2) xor (S2' xor M xor KS2) = S2 xor S2'
/// ```
///
/// `M` es el mismo valor sumado a los dos operandos de una resta, así que
/// desaparece. Con `id` repetido se recupera `P xor P'` desde el cable, igual que
/// sin máscara — comprobado byte a byte por la revisión del 2026-08-17, que
/// además forjó un blob válido empalmando `C1` de un mensaje con `C2` de otro.
///
/// Que sea neutra es EVITABLE: una sal propia para la máscara dejaría
/// `M != M'` y acotaría el desastre a una capa. No se hizo —la colisión es de
/// cumpleaños a 2⁶⁴ y romper el formato hoy no lo justifica— pero queda escrito
/// aquí porque el argumento de «una máscara basta» se apoya en que el RNG esté
/// sano, y el RNG es un modo de fallo que este módulo declara abierto.
fn aplicar_mascara(master: &[u8; kdf::KEY_LEN], id: &[u8; ID_LEN], buf: &mut [u8]) {
    #[cfg(test)]
    VECES_ENMASCARADO.with(|v| v.set(v.get() + 1));
    if buf.is_empty() {
        return;
    }
    // LA ETIQUETA DE DOMINIO ENTRA UNA VEZ, no 255 por tramo.
    //
    // La primera versión metía `INFO_M1 ‖ id` —71 bytes— dentro de cada
    // iteración de HKDF-Expand, o sea 255 veces por tramo, y eso hace que cada
    // iteración procese dos bloques de SHA-256 en vez de uno. Derivando una CLAVE
    // de máscara con esa etiqueta y expandiendo desde ella con el contador como
    // contexto, es el mismo HKDF-SHA256 con los mismos supuestos y **×1,51 más
    // rápido** (medido el 2026-08-17 sobre 256 KiB).
    //
    // La separación de dominios no se pierde, se mueve: `km` ya es material
    // propio de esta etiqueta y de este mensaje, así que el contador solo tiene
    // que separar tramos entre sí.
    let mut km = Zeroizing::new([0u8; kdf::KEY_LEN]);
    {
        let mut etiqueta = Vec::with_capacity(INFO_M1.len() + ID_LEN);
        etiqueta.extend_from_slice(INFO_M1);
        etiqueta.extend_from_slice(id);
        kdf::derive_stream(master, &etiqueta, km.as_mut());
    }

    let mut tramo = Zeroizing::new(vec![0u8; TRAMO_HKDF.min(buf.len())]);
    for (i, bloque) in buf.chunks_mut(TRAMO_HKDF).enumerate() {
        // El contador, de largo fijo. Sigue haciendo falta: sin él todos los
        // tramos saldrían iguales y la máscara sería periódica cada 8 160 B.
        let ctr = u32::try_from(i)
            .expect("un mensaje no llega a 2^32 tramos")
            .to_be_bytes();
        let m = &mut tramo[..bloque.len()];
        kdf::expand_desde(&km, &ctr, m);
        for (b, k) in bloque.iter_mut().zip(m.iter()) {
            *b ^= *k;
        }
    }
}

/// Los datos asociados de una capa: los del llamante, más lo que ata esta capa
/// a ESTE mensaje y a ESTA posición.
///
/// **SEGUNDA CERRADURA, no la primera, y esta frase costó tres mutantes.** La
/// primera versión de este comentario decía que el `id` de aquí es lo que impide
/// empalmar la capa A de un mensaje con la capa B de otro. Es falso: quitarlo no
/// pone en rojo ninguna prueba, porque **el id también entra en la derivación de
/// claves** y la capa B de otro mensaje ya está cifrada bajo otra clave. Lo
/// mismo con la etiqueta de capa: intercambiar las dos mitades falla porque una
/// la cifró AES y la otra XChaCha, no por esta etiqueta.
///
/// Las dos se quedan a propósito, y ahora con el motivo correcto escrito: son
/// redundantes HOY, y dejan de serlo el día que alguien simplifique la
/// derivación de claves. Lo que las prueba es
/// [`pruebas::los_datos_asociados_llevan_el_id_y_la_capa`], que mira lo que la
/// función produce; lo que prueba la cerradura de verdad es
/// [`pruebas::cada_capa_deriva_material_propio_y_por_mensaje`].
fn aad_de_capa(aad: &[u8], id: &[u8; ID_LEN], capa: u8) -> Vec<u8> {
    aad_de_capa_con(aad, MAGIA, id, capa)
}

/// Igual, con la marca como parámetro. La necesita
/// [`autentica_como_otra_version`], que tiene que rehacer los datos asociados
/// con la marca QUE TRAE EL BLOB y no con la nuestra.
fn aad_de_capa_con(aad: &[u8], magia: &[u8; 4], id: &[u8; ID_LEN], capa: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(aad.len() + 4 + ID_LEN + 1);
    v.extend_from_slice(aad);
    v.extend_from_slice(magia);
    v.extend_from_slice(id);
    v.push(capa);
    v
}

/// ¿Este blob es DE VERDAD un contenedor de otra versión de esta familia, o solo
/// lo dice?
///
/// # El problema que resuelve, y por qué la respuesta obvia no servía
///
/// La marca `QBL*` viaja en claro dentro del cuerpo y no la cubre ningún AEAD,
/// así que la comprobación de versión corre antes de que la clave importe.
/// Durante un día este módulo devolvió [`BlindajeError::OtraVersion`] mirando
/// solo esos tres bytes, y la revisión adversaria del 2026-08-17 lo rompió con
/// **un byte**: escribir `QBL1` encima de un `QBL2` forzaba el diagnóstico, con
/// la contraseña correcta y con la equivocada. O sea que el mensaje que ve la
/// víctima —«no es la contraseña, es el formato»— lo elegía quien tocó el
/// archivo.
///
/// Se dio por imposible con este argumento: *la versión dice cómo autenticar,
/// así que hay que leerla antes de autenticar*. El argumento es correcto y **la
/// conclusión no se sigue**: no hace falta autenticar la versión ANTES, basta
/// **no afirmarla hasta después**.
///
/// Aquí se intenta abrir el blob bajo la versión que dice ser, y solo si las dos
/// capas AUTENTICAN se le concede el diagnóstico. Un atacante no puede hacer que
/// autentiquen —no tiene la clave—, así que `OtraVersion` deja de ser una pista
/// y pasa a ser un hecho.
///
/// # Qué NO hace
///
/// **No descifra.** Comprueba y tira. Devolver el claro de un formato viejo
/// sería reintroducir por la puerta de atrás el modo que se retiró, y eso es una
/// decisión de migración, no un diagnóstico.
///
/// # Qué cubre
///
/// El marco de la familia `QBL*` no ha cambiado —cabecera, dos capas, mismas
/// claves y nonces derivados de `(master, id)`—; lo que cambió en `QBL2` es la
/// máscara, que se aplica ANTES de cifrar y por tanto no afecta a los tags. Así
/// que esta comprobación vale para cualquier versión de la familia cuyo marco
/// sea éste. Una que cambiara el marco no autenticaría, y saldría por `Formato`
/// — que es el lado conservador y el correcto.
fn autentica_como_otra_version(master: &[u8; kdf::KEY_LEN], blob: &[u8], aad: &[u8]) -> bool {
    let mut magia = [0u8; 4];
    magia.copy_from_slice(&blob[..4]);
    let mut id = [0u8; ID_LEN];
    id.copy_from_slice(&blob[4..4 + ID_LEN]);

    let Ok(cuatro) = <[u8; 4]>::try_from(&blob[4 + ID_LEN..CABECERA]) else {
        return false;
    };
    let largo_c1 = u32::from_be_bytes(cuatro) as usize;
    let cuerpo = &blob[CABECERA..];
    let cabe = cuerpo
        .len()
        .checked_sub(TAG)
        .is_some_and(|maximo| largo_c1 <= maximo);
    if largo_c1 < TAG || !cabe {
        return false;
    }
    let (c1, c2) = cuerpo.split_at(largo_c1);
    if c1.len() != c2.len() {
        return false;
    }

    // LAS DOS, sin cortocircuito, igual que en el camino normal.
    let a = capa_aes_descifrar(master, &id, c1, &aad_de_capa_con(aad, &magia, &id, 1));
    let b = capa_chacha_descifrar(master, &id, c2, &aad_de_capa_con(aad, &magia, &id, 2));
    a.is_some() && b.is_some()
}

/// Cifra `claro` en dos capas ciegas. Devuelve el blob `QBL2` completo.
///
/// # AVISO PARA QUIEN LLAME A ESTO DIRECTAMENTE
///
/// **El `aad` NO entra en la derivación de claves ni de nonces**, solo en los
/// datos asociados de cada capa. Todo el material sale de `(master, id)`, así que
/// dos mensajes con el mismo `id` comparten `K1`, `N1`, `K2`, `N2` y la máscara
/// **aunque sus `aad` sean completamente distintos**. Lo midió la revisión
/// adversaria del 2026-08-17, y es la trampa natural: se supone que «contextos
/// distintos, riesgos distintos», y aquí no.
///
/// No es un problema con el uso normal —`id` sale del CSPRNG en cada llamada, sin
/// estado cacheado ni ventana de `fork`, y la colisión es de cumpleaños a 2⁶⁴—;
/// lo es si alguien reutiliza un `master` de larga vida y se apoya en el `aad`
/// para separar contextos. **Para eso, derive una subclave por contexto** con
/// [`crate::kdf::derive_subkey`], que es lo que hace `api`.
///
/// Tamaño de salida: **`2·|claro| + 56`** — cabecera 24 (magia 4 + id 16 + largo
/// 4), dos mitades de `|claro|` y dos tags de 16. Lo fija una prueba.
pub fn cifrar(
    master: &[u8; kdf::KEY_LEN],
    claro: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, SinEntropia> {
    let id: [u8; ID_LEN] = aleatorio::bytes()?;
    let (s1, s2) = repartir(claro)?;
    Ok(armar(master, &id, &s1, &s2, aad))
}

/// El cuerpo determinista de [`cifrar`], con el azar ya sorteado y pasado como
/// argumento.
///
/// Existe para poder CONGELAR vectores: mientras el azar se sortee dentro, dos
/// corridas no dan lo mismo y no hay nada que fijar. Separarlo es lo que
/// convierte «el formato no debe moverse» en una prueba en vez de una intención.
fn armar(
    master: &[u8; kdf::KEY_LEN],
    id: &[u8; ID_LEN],
    s1: &[u8],
    s2: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    // LA MÁSCARA, que es lo que separa `QBL2` de `QBL1`. Va sobre **`S2`** —la
    // mitad que DEPENDE DEL CLARO— y antes de que el buffer cruce la frontera
    // hacia `chacha20poly1305`.
    let mut s2m = Zeroizing::new(s2.to_vec());
    aplicar_mascara(master, id, &mut s2m);

    let c1 = capa_aes_cifrar(master, id, s1, &aad_de_capa(aad, id, 1));
    let c2 = capa_chacha_cifrar(master, id, &s2m, &aad_de_capa(aad, id, 2));

    // LA PILA, que es la mitad que se olvida. `claves_aes` y `claves_chacha`
    // devuelven la clave POR VALOR, y mover un `Zeroizing<[u8;32]>` COPIA los 32
    // bytes al destino sin ejecutar `Drop` en el origen: el marco ya muerto de
    // quien la produjo conserva la clave. Es exactamente lo que `kdf.rs`
    // documenta y cierra con esta misma llamada. Aquí pasa dos veces por
    // operación, así que se limpia una vez al final, que las cubre las dos.
    //
    // AHORA CON NÚMERO, y el número NO dice lo que este comentario decía
    // (medido el 2026-08-17, `tests/residuo_memoria.rs`, escenarios
    // `blindaje-cifra*` y `blindaje-descifra*`):
    //
    // | | |
    // |---|---|
    // | claves de capa y claro tras cifrar y tras descifrar | **0 copias** |
    // | lo mismo con estas DOS llamadas RETIRADAS (mutante) | **0 copias** |
    // | testigo: la misma clave en un marco de la misma profundidad, sin limpiar | **>0** |
    //
    // O sea: la fuga que este comentario describe **no se observa**, y no es que
    // el banco sea ciego ahí —el testigo de profundidad, que es su pareja, la ve
    // perfectamente y desaparece al limpiar—. En release el compilador incrusta
    // `claves_*` y construye la clave en un solo hueco, que `Zeroizing` borra al
    // caer; en debug tampoco sobrevive. La llamada es SEGURO, no remedio.
    //
    // EL PRECIO, y este cuadro ha estado mal DOS veces, así que va con el
    // denominador delante. `limpiar_pila()` cuesta ~56 µs, fijos.
    //
    // | denominador | las dos llamadas son |
    // |---|---|
    // | `blindaje::cifrar`+`descifrar`, 1 KiB (228 µs) | 53 % |
    // | ídem, 64 KiB (5 152 µs) | 2 % |
    // | ídem, 256 KiB (21 751 µs) | 1 % |
    // | **`api::decode`, el camino del producto (132 ms)** | **0,04 %** |
    //
    // La última fila es la que faltaba, y **retira una decisión que le escalé a
    // Juan**. Las tres primeras miden funciones que reciben el maestro YA
    // DERIVADO: no incluyen Argon2id, que con los parámetros de fábrica —64 MiB,
    // 3 iteraciones— son ~132 ms y domina todo lo demás por tres órdenes de
    // magnitud. Un coste fijo de 56 µs solo parece grande si lo divides por algo
    // que excluye el KDF.
    //
    // La primera versión decía «139 µs de los 178 µs: el 78 %» sin decir de qué
    // tamaño y sobre el ciclo de `QBL1`; la segunda arregló el tamaño y dejó el
    // denominador equivocado. El error no era el número: era medir el porcentaje
    // de una operación que nadie hace suelta.
    //
    // Consecuencia: en `kdf.rs`, `api.rs`, `pqhybrid.rs` y `firmante/` —los que
    // NO son opt-in— esto es ruido y no hay nada que decidir. Donde sí pesa es
    // llamando a `blindaje::cifrar` directamente en un bucle con un maestro de
    // larga vida, que es un uso legítimo de la API pública y conviene saberlo.
    // SE QUEDAN, y el motivo se escribe para que no haya que redescubrirlo: lo
    // medido es «no se observa en ESTE compilador, ESTE perfil y a ESA
    // profundidad», que no es «no puede pasar» — el colapso de las copias lo
    // decide el inliner, y eso cambia sin avisar entre versiones de `rustc`. Lo
    // que sigue abierto es lo otro: el mismo seguro se paga en `kdf.rs`,
    // `api.rs`, `pqhybrid.rs` y `firmante/`, que NO son opt-in, y ahí nadie ha
    // medido si quita algo NI con qué tamaños de mensaje se usa.
    crate::antihacker::limpiar_pila();

    let mut salida = Vec::with_capacity(CABECERA + c1.len() + c2.len());
    salida.extend_from_slice(MAGIA);
    salida.extend_from_slice(id);
    // RUIDOSO, no silencioso. Con `as u32` un claro de 4 GiB o más truncaba el
    // campo y producía un contenedor que ni este mismo módulo puede reabrir
    // —cae en `Formato` por mitades desiguales—, sin un solo error: destrucción
    // silenciosa de datos propios, que es la directiva 20 al revés. Lo señaló la
    // revisión adversaria del 2026-08-17 sobre la aritmética; la operación no es
    // alcanzable hoy (harían falta ~16 GiB de RAM) y por eso costaba tan poco
    // dejarla mal.
    salida.extend_from_slice(
        &u32::try_from(c1.len())
            .expect("una capa de blindaje no llega a 4 GiB")
            .to_be_bytes(),
    );
    salida.extend_from_slice(&c1);
    salida.extend_from_slice(&c2);
    salida
}

/// Operación inversa de [`cifrar`].
pub fn descifrar(
    master: &[u8; kdf::KEY_LEN],
    blob: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, BlindajeError> {
    if blob.len() < CABECERA {
        return Err(BlindajeError::Formato);
    }
    if &blob[..4] != MAGIA {
        // SOLO la marca autoriza a decir «otra versión», y solo si es de esta
        // familia. Un marco que no cuadra —el largo, las mitades desiguales— es
        // casi siempre manipulación, y decirle a la víctima que su archivo es de
        // un formato antiguo la manda a buscar una versión vieja del programa en
        // vez de a sospechar. Los tres bytes `QBL` no le sirven de nada a un
        // atacante y separan los dos diagnósticos limpiamente.
        // SOLO SI AUTENTICA. Mirar los tres bytes de la marca era una pista que
        // el atacante elegía; exigir que el blob abra bajo la versión que dice
        // ser lo convierte en un hecho. Ver `autentica_como_otra_version`.
        return Err(if &blob[..3] == b"QBL" && autentica_como_otra_version(master, blob, aad) {
            BlindajeError::OtraVersion
        } else {
            BlindajeError::Formato
        });
    }
    let mut id = [0u8; ID_LEN];
    id.copy_from_slice(&blob[4..4 + ID_LEN]);
    let largo_c1 = u32::from_be_bytes(
        blob[4 + ID_LEN..CABECERA]
            .try_into()
            .expect("cuatro bytes exactos"),
    ) as usize;

    let cuerpo = &blob[CABECERA..];
    // Cada capa tiene que llevar al menos su tag, y las dos tienen que caber.
    //
    // La resta y no la suma: `largo_c1` lo elige quien manda el blob y llega
    // hasta `u32::MAX`. En 64 bits `largo_c1 + TAG` no puede desbordar, pero en
    // un objetivo de 32 bits envuelve, el chequeo pasa y el `split_at` de abajo
    // entra en pánico. Restar del lado que SÍ está acotado no depende del ancho
    // de `usize`.
    let cabe = cuerpo
        .len()
        .checked_sub(TAG)
        .is_some_and(|maximo| largo_c1 <= maximo);
    // `largo_c1 < TAG` es INALCANZABLE, y se deja escrito en vez de fingir que
    // trabaja. El banco de mutación del 2026-08-17 lo midió —quitarlo no cambia
    // ni una de 7 249 salidas— y el álgebra lo explica: la igualdad de mitades de
    // abajo obliga a `cuerpo.len() == 2·largo_c1`, y `cabe` exige
    // `largo_c1 ≤ 2·largo_c1 − TAG`, o sea `largo_c1 ≥ TAG`. Todo lo que esta
    // rama rechazaría lo rechaza la de abajo.
    //
    // Se queda porque cierra de más —el lado seguro— y porque documenta la
    // invariante a quien lea; lo que NO se queda es el comentario anterior, que
    // le atribuía impedir un pánico del `split_at`. Ese trabajo lo hace `cabe`.
    if largo_c1 < TAG || !cabe {
        return Err(BlindajeError::Formato);
    }
    let (c1, c2) = cuerpo.split_at(largo_c1);
    // Las dos mitades cifran el MISMO número de bytes: si no, no son un reparto.
    if c1.len() != c2.len() {
        return Err(BlindajeError::Formato);
    }

    // LAS DOS SIEMPRE, sin cortocircuito: que falle la primera no debe poder
    // medirse en el tiempo de respuesta.
    let s1 = capa_aes_descifrar(master, &id, c1, &aad_de_capa(aad, &id, 1));
    let s2 = capa_chacha_descifrar(master, &id, c2, &aad_de_capa(aad, &id, 2));

    // Igual que al cifrar, con el mismo matiz medido: las claves viajan por valor
    // y PODRÍAN dejar copias en marcos ya muertos, pero el banco de residuo mide
    // 0 con esta llamada y 0 sin ella (ver el cuadro en `armar`). Es seguro, no
    // remedio. Va ANTES del `match` para que cubra los dos caminos, el de éxito
    // y el de fallo.
    crate::antihacker::limpiar_pila();

    match (s1, s2) {
        // `s1.len() == s2.len()` TAMBIÉN ES INALCANZABLE aquí, igual que el
        // `largo_c1 < TAG` de arriba: los dos AEAD devuelven `ct − TAG` y la
        // igualdad de `c1`/`c2` ya está impuesta antes del troceado. Medido por
        // la revisión del 2026-08-17 sobre 7 249 entradas: quitarlo no cambia una
        // sola salida. Se queda por lo mismo —cierra de más, que es el lado
        // seguro— y se anota para que nadie le atribuya un trabajo que no hace.
        (Some(s1), Some(mut s2)) if s1.len() == s2.len() => {
            // Se quita la máscara DESPUÉS de que las dos capas hayan
            // autenticado. Ponerlo aquí y no antes del `match` no abre un canal
            // de tiempo: lo que hay que ocultar es CUÁL de las dos capas falló,
            // y eso ya lo garantiza que las dos se ejecuten siempre; que un
            // fallo devuelva antes de desenmascarar solo revela que hubo fallo,
            // y eso lo dice el propio `Err`.
            aplicar_mascara(master, &id, s2.as_mut());
            Ok(s1.iter().zip(s2.iter()).map(|(a, b)| a ^ b).collect())
        }
        _ => Err(BlindajeError::NoAutentica),
    }
}

// --- Las dos capas -----------------------------------------------------------
//
// Cada una deriva SU clave y SU nonce del maestro y del id del mensaje. Como el
// id es distinto en cada mensaje, la clave también lo es, y la reutilización de
// nonce —que en GCM es catastrófica— deja de depender de un contador o de un
// sorteo de 96 bits.

/// Deriva material desde la maestra y el id del mensaje.
///
/// **La concatenación `info || id` es inyectiva y hay que decir por qué**, que
/// no es evidente: no es por las longitudes de las etiquetas, es porque el `id`
/// mide SIEMPRE 16 bytes. Si `info₁‖id₁ = info₂‖id₂` como cadenas, las
/// longitudes totales coinciden, luego `|info₁| = |info₂|`, luego son la misma
/// etiqueta y el mismo id. **Un sufijo de longitud fija basta; un prefijo de
/// longitud variable no.** El día que el `id` deje de ser fijo, o que se meta el
/// `aad` del llamante aquí, la ambigüedad aparece sin que nada se ponga rojo.
/// (`kdf.rs` lleva el aviso del caso contrario, `NFKC(pw) ‖ pepper`; sin esta
/// nota, quien compare los dos sitios no puede saber por qué uno está mal y el
/// otro bien.)
fn material(master: &[u8; kdf::KEY_LEN], id: &[u8; ID_LEN], info: &[u8], out: &mut [u8]) {
    let mut etiqueta = Vec::with_capacity(info.len() + ID_LEN);
    etiqueta.extend_from_slice(info);
    etiqueta.extend_from_slice(id);
    kdf::derive_stream(master, &etiqueta, out);
}

fn claves_aes(master: &[u8; kdf::KEY_LEN], id: &[u8; ID_LEN]) -> (Zeroizing<[u8; 32]>, [u8; NONCE_AES]) {
    let mut k = Zeroizing::new([0u8; 32]);
    let mut n = [0u8; NONCE_AES];
    material(master, id, INFO_K1, k.as_mut());
    material(master, id, INFO_N1, &mut n);
    (k, n)
}

fn claves_chacha(
    master: &[u8; kdf::KEY_LEN],
    id: &[u8; ID_LEN],
) -> (Zeroizing<[u8; cipher::KEY_LEN]>, [u8; cipher::NONCE_LEN]) {
    let mut k = Zeroizing::new([0u8; cipher::KEY_LEN]);
    let mut n = [0u8; cipher::NONCE_LEN];
    material(master, id, INFO_K2, k.as_mut());
    material(master, id, INFO_N2, &mut n);
    (k, n)
}

fn capa_aes_cifrar(master: &[u8; kdf::KEY_LEN], id: &[u8; ID_LEN], msg: &[u8], aad: &[u8]) -> Vec<u8> {
    let (k, n) = claves_aes(master, id);
    Aes256Gcm::new(&(*k).into())
        .encrypt(&n.into(), Payload { msg, aad })
        .expect("AES-256-GCM encrypt no debe fallar con entradas válidas")
}

fn capa_aes_descifrar(
    master: &[u8; kdf::KEY_LEN],
    id: &[u8; ID_LEN],
    msg: &[u8],
    aad: &[u8],
) -> Option<Mitad> {
    #[cfg(test)]
    VECES_CAPA.with(|v| {
        let (a, b) = v.get();
        v.set((a + 1, b));
    });
    let (k, n) = claves_aes(master, id);
    Aes256Gcm::new(&(*k).into())
        .decrypt(&n.into(), Payload { msg, aad })
        .ok()
        .map(Zeroizing::new)
}

fn capa_chacha_cifrar(
    master: &[u8; kdf::KEY_LEN],
    id: &[u8; ID_LEN],
    msg: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let (k, n) = claves_chacha(master, id);
    cipher::encrypt(&k, &n, msg, aad)
}

fn capa_chacha_descifrar(
    master: &[u8; kdf::KEY_LEN],
    id: &[u8; ID_LEN],
    msg: &[u8],
    aad: &[u8],
) -> Option<Mitad> {
    #[cfg(test)]
    VECES_CAPA.with(|v| {
        let (a, b) = v.get();
        v.set((a, b + 1));
    });
    let (k, n) = claves_chacha(master, id);
    cipher::decrypt(&k, &n, msg, aad).ok().map(Zeroizing::new)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn maestra() -> [u8; kdf::KEY_LEN] {
        [0x5Au8; kdf::KEY_LEN]
    }

    /// Recupera lo que CADA CAPA recibió de verdad, descifrando cada una por su
    /// lado con el material que el módulo derivó.
    ///
    /// No reconstruye el reparto: lo lee del artefacto. Es la diferencia entre
    /// comprobar lo que el código pretende y lo que el código hizo.
    fn mitades_reales(
        master: &[u8; kdf::KEY_LEN],
        blob: &[u8],
        aad: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let mut id = [0u8; ID_LEN];
        id.copy_from_slice(&blob[4..4 + ID_LEN]);
        let largo_c1 =
            u32::from_be_bytes(blob[4 + ID_LEN..CABECERA].try_into().unwrap()) as usize;
        let (c1, c2) = blob[CABECERA..].split_at(largo_c1);
        let s1 = capa_aes_descifrar(master, &id, c1, &aad_de_capa(aad, &id, 1))
            .expect("la capa AES tiene que abrir");
        let s2 = capa_chacha_descifrar(master, &id, c2, &aad_de_capa(aad, &id, 2))
            .expect("la capa XChaCha tiene que abrir");
        (s1.to_vec(), s2.to_vec())
    }

    #[test]
    fn ida_y_vuelta() {
        let m = maestra();
        for largo in [0usize, 1, 15, 16, 17, 1024, 4096] {
            let claro: Vec<u8> = (0..largo).map(|i| (i * 37 % 256) as u8).collect();
            let blob = cifrar(&m, &claro, b"cabecera").expect("hay entropía");
            assert_eq!(descifrar(&m, &blob, b"cabecera"), Ok(claro), "con {largo} bytes");
        }
    }

    /// El id de un blob, para poder rehacer la máscara desde una prueba.
    fn id_de(blob: &[u8]) -> [u8; ID_LEN] {
        let mut id = [0u8; ID_LEN];
        id.copy_from_slice(&blob[4..4 + ID_LEN]);
        id
    }

    /// **LA PROPIEDAD DEL MÓDULO**, y en `QBL2` son DOS, no una. Se comprueba
    /// sobre lo que las capas recibieron REALMENTE, sacado del blob, no sobre lo
    /// que `repartir` devuelve por su cuenta.
    ///
    /// El testigo son 32 bytes reconocibles: la probabilidad de que aparezcan
    /// por azar dentro de una mitad uniforme es 2⁻²⁵⁶ por posición.
    ///
    /// # La segunda propiedad es la que `QBL1` NO tenía
    ///
    /// Que ninguna capa contenga el claro nunca fue suficiente, y esta prueba lo
    /// decía sin darse cuenta: su última línea comprobaba que el XOR de las dos
    /// mitades **es** el claro. Eso era cierto, era necesario para que el
    /// reparto fuese un reparto de verdad… y era exactamente la operación que un
    /// crate comprometido del pegamento podía hacer, porque `aead`, `cipher` e
    /// `inout` reciben las dos mitades en el mismo proceso y el mismo turno.
    ///
    /// En `QBL2` ese XOR ya no da el claro. Y para que eso no se pueda cumplir
    /// por estar roto el reparto, la prueba QUITA la máscara y exige que
    /// entonces sí lo dé.
    #[test]
    fn ninguna_capa_ve_el_claro() {
        let m = maestra();
        let testigo = b"CLARO-QUE-NINGUNA-CAPA-DEBE-VER!";
        assert_eq!(testigo.len(), 32);

        let mut claro = vec![0u8; 256];
        claro[100..132].copy_from_slice(testigo);

        // CONTROL POSITIVO: el testigo SÍ está en el claro. Sin esto, un
        // buscador roto daría «no está» sobre las dos mitades y sobre todo lo
        // demás.
        assert!(contiene(&claro, testigo), "el control: el testigo está en el claro");

        let blob = cifrar(&m, &claro, b"").expect("hay entropía");
        let (s1, s2) = mitades_reales(&m, &blob, b"");

        assert!(!contiene(&s1, testigo), "la capa AES recibió el claro");
        assert!(!contiene(&s2, testigo), "la capa XChaCha recibió el claro");

        // LO NUEVO: juntar las dos llamadas no basta.
        let xor: Vec<u8> = s1.iter().zip(s2.iter()).map(|(a, b)| a ^ b).collect();
        assert_ne!(
            xor, claro,
            "el XOR de lo que recibieron las dos capas ES el claro: la máscara no \
             está puesta, y el pegamento compartido puede leer el documento"
        );
        assert!(
            !contiene(&xor, testigo),
            "el testigo aparece al juntar las dos capas"
        );

        // Y LA OTRA MITAD, sin la cual lo de arriba se cumpliría también con un
        // `cifrar` roto que metiera basura en la capa AES: quitando la máscara,
        // las mitades TIENEN que recomponer el claro.
        let mut s1_sin_mascara = s1;
        aplicar_mascara(&m, &id_de(&blob), &mut s1_sin_mascara);
        let recompuesto: Vec<u8> = s1_sin_mascara
            .iter()
            .zip(s2.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        assert_eq!(
            recompuesto, claro,
            "quitada la máscara, las mitades tienen que recomponer el claro"
        );
    }

    /// **LAS DOS CAPAS SE INTENTAN SIEMPRE**, aunque la primera falle.
    ///
    /// El módulo lo promete —«No se dice cuál a propósito … Las dos se verifican
    /// siempre, sin cortocircuito»— y hasta el 2026-08-17 no lo probaba nadie: el
    /// banco de mutación metió el cortocircuito explícito y las 235 pruebas
    /// siguieron verdes. Y no es raro que siguieran: el RESULTADO es idéntico
    /// —`NoAutentica` en los dos casos— y lo único que cambia es el TIEMPO, que
    /// es exactamente el canal que la promesa dice cerrar.
    ///
    /// Un `assert` sobre el `Err` no puede verlo. Un contador, sí.
    #[test]
    fn las_dos_capas_se_intentan_aunque_la_primera_falle() {
        let m = maestra();
        let claro = vec![0x5Au8; 256];
        let blob = cifrar(&m, &claro, b"aad").expect("hay entropía");

        // CONTROL: en el camino bueno se intentan las dos, una vez cada una.
        VECES_CAPA.with(|v| v.set((0, 0)));
        assert_eq!(descifrar(&m, &blob, b"aad"), Ok(claro), "el camino bueno abre");
        assert_eq!(
            VECES_CAPA.with(std::cell::Cell::get),
            (1, 1),
            "el control: descifrar con éxito intenta cada capa exactamente una vez"
        );

        // EL CASO QUE IMPORTA: se rompe la capa AES —el primer byte de `c1`, que
        // está dentro de su ciphertext— y la capa 2 TIENE que intentarse igual.
        let mut roto = blob.clone();
        roto[CABECERA] ^= 0x01;
        VECES_CAPA.with(|v| v.set((0, 0)));
        assert_eq!(
            descifrar(&m, &roto, b"aad"),
            Err(BlindajeError::NoAutentica),
            "con la capa AES rota tiene que rechazarse"
        );
        assert_eq!(
            VECES_CAPA.with(std::cell::Cell::get),
            (1, 1),
            "la capa 2 NO se intentó al fallar la 1: hay cortocircuito, y el tiempo \
             de respuesta dice cuál de las dos capas rechazó el blob"
        );

        // Y al revés: rota la capa 2, la 1 se intenta igual.
        let mut roto2 = blob;
        let ultimo = roto2.len() - 1;
        roto2[ultimo] ^= 0x01;
        VECES_CAPA.with(|v| v.set((0, 0)));
        assert_eq!(descifrar(&m, &roto2, b"aad"), Err(BlindajeError::NoAutentica));
        assert_eq!(VECES_CAPA.with(std::cell::Cell::get), (1, 1));
    }

    /// **EL `id` SE SORTEA ENTERO**, y no lo medía nadie.
    ///
    /// Lo encontró el banco de mutación del 2026-08-17: duplicar la primera
    /// mitad del `id` sobre la segunda —o sea bajar de 128 a 64 bits efectivos—
    /// dejaba las 235 pruebas en verde. Los vectores congelados llaman a `armar`
    /// con un `id` FIJO, así que no tocan `cifrar`;
    /// `dos_cifrados_del_mismo_claro_no_se_parecen` solo exige que dos `id` sean
    /// distintos, y con la mitad duplicada lo siguen siendo.
    ///
    /// Importa porque el `id` es la ÚNICA fuente de frescura del modo: de él
    /// salen las dos claves **y los dos nonces**. Con 64 bits efectivos, el
    /// margen de colisión por cumpleaños baja de ~2⁶⁴ mensajes a ~2³², y una
    /// colisión de `id` en GCM no es una fuga parcial — es recuperación de la
    /// clave de autenticación y forja.
    #[test]
    fn el_id_se_sortea_entero_y_no_a_medias() {
        const N: usize = 64;
        let m = maestra();
        let ids: Vec<[u8; ID_LEN]> = (0..N)
            .map(|_| {
                let blob = cifrar(&m, b"x", b"").expect("hay entropía");
                let mut id = [0u8; ID_LEN];
                id.copy_from_slice(&blob[4..4 + ID_LEN]);
                id
            })
            .collect();

        // (a) Ninguna posición es constante a lo largo de la muestra. Caza un
        // `id` truncado, rellenado con ceros o con una constante.
        for pos in 0..ID_LEN {
            let primero = ids[0][pos];
            assert!(
                ids.iter().any(|id| id[pos] != primero),
                "el byte {pos} del id es constante en {N} sorteos"
            );
        }

        // (b) NINGUNA PAREJA DE POSICIONES es idéntica en toda la muestra. Ésta
        // es la que caza la duplicación: con `id[8..16] = id[0..8]`, cada byte
        // sigue variando —(a) pasa— pero las columnas van de dos en dos.
        for a in 0..ID_LEN {
            for b in (a + 1)..ID_LEN {
                assert!(
                    ids.iter().any(|id| id[a] != id[b]),
                    "los bytes {a} y {b} del id coinciden en los {N} sorteos: el id \
                     no se está sorteando entero, y de él salen las claves Y los nonces"
                );
            }
        }

        // CONTROL DEL INSTRUMENTO: la misma comprobación sobre una muestra
        // FABRICADA con el patrón duplicado tiene que fallar. Sin esto, (b) se
        // cumpliría igual con un detector que nunca encuentra nada.
        let falsos: Vec<[u8; ID_LEN]> = ids
            .iter()
            .map(|id| {
                let mut f = *id;
                let (mitad, resto) = f.split_at_mut(ID_LEN / 2);
                resto.copy_from_slice(mitad);
                f
            })
            .collect();
        let caza = (0..ID_LEN).any(|a| {
            ((a + 1)..ID_LEN).any(|b| falsos.iter().all(|id| id[a] == id[b]))
        });
        assert!(
            caza,
            "el control: sobre una muestra con la mitad duplicada, la comprobación \
             de arriba TIENE que encontrar la pareja"
        );
    }

    /// **CONOCER `S1` NO BASTA PARA LEER EL DOCUMENTO**, y ésta es la prueba que
    /// sujeta sobre qué mitad va la máscara.
    ///
    /// Nació de un ataque que funcionó (revisión adversaria del 2026-08-17). Con
    /// la máscara sobre `S1` —como estaba— la mitad SIN enmascarar es
    /// `S2 = P xor S1`, así que quien prediga `S1` lee el claro entero **sin
    /// tocar la criptografía y sin el maestro**. Moviéndola a `S2`, lo que
    /// obtiene es `P xor M`, y `M` vive en el camino del HKDF.
    ///
    /// Sin esta prueba el cambio no lo sujeta nada: la ida y vuelta funciona
    /// igual con la máscara en cualquiera de las dos mitades, y los vectores
    /// congelados solo dicen que el formato no se movió, no cuál es el correcto.
    #[test]
    fn conocer_la_mitad_aleatoria_no_entrega_el_claro() {
        let m = maestra();
        let claro: Vec<u8> = (0..512).map(|i| (i % 251) as u8).collect();
        // El azar FIJADO: es lo que simula un `S1` predicho por quien haya
        // comprometido el generador.
        let s1 = vec_s1(claro.len());
        let s2 = vec_s2(&claro);
        let blob = armar(&maestra(), &VEC_ID, &s1, &s2, b"aad");

        let (capa1, capa2) = mitades_reales(&m, &blob, b"aad");

        // CONTROL POSITIVO: `s1` es de verdad la mitad de ESTE mensaje —si no,
        // los dos «no entrega el claro» de abajo se cumplirían por casualidad.
        let reconstruido: Vec<u8> = s1.iter().zip(s2.iter()).map(|(a, b)| a ^ b).collect();
        assert_eq!(reconstruido, claro, "el control: s1 xor s2 es el claro");

        // LO QUE SE EXIGE: ninguna de las dos mitades que viajan, combinada con
        // `S1`, da el documento.
        for (nombre, capa) in [("AES", &capa1), ("XChaCha", &capa2)] {
            let intento: Vec<u8> = capa.iter().zip(s1.iter()).map(|(a, b)| a ^ b).collect();
            assert_ne!(
                intento, claro,
                "conociendo S1, la mitad de la capa {nombre} entrega el CLARO ENTERO: \
                 la máscara está sobre la mitad equivocada. Va sobre S2, la que \
                 depende del claro; sobre S1 no protege de un generador comprometido."
            );
        }

        // Y la otra mitad del argumento: la máscara no rompió el reparto — con
        // ella quitada, las dos capas siguen recomponiendo el claro.
        let mut sin_mascara = capa2;
        aplicar_mascara(&m, &VEC_ID, &mut sin_mascara);
        let p: Vec<u8> = capa1.iter().zip(sin_mascara.iter()).map(|(a, b)| a ^ b).collect();
        assert_eq!(p, claro, "quitada la máscara de la capa 2, el reparto tiene que cerrar");
    }

    /// La máscara es su propia inversa, y por TRAMOS: un mensaje más largo que
    /// los 8160 B de un HKDF-Expand tiene que dar la vuelta igual.
    ///
    /// Es el caso que el techo del RFC 5869 haría fallar si la máscara se
    /// derivara de una sola llamada — y fallaría con un pánico dentro de
    /// `derive_stream`, no con un resultado equivocado, así que se ve. Lo que NO
    /// se vería sin esta prueba es un contador mal puesto: todos los tramos con
    /// la misma etiqueta darían una máscara periódica, la ida y vuelta seguiría
    /// funcionando, y la máscara valdría mucho menos de lo que promete.
    #[test]
    fn la_mascara_es_su_propia_inversa_y_no_se_repite_por_tramos() {
        let m = maestra();
        let id = [0x7Eu8; ID_LEN];

        for largo in [0usize, 1, TRAMO_HKDF - 1, TRAMO_HKDF, TRAMO_HKDF + 1, 3 * TRAMO_HKDF + 7] {
            let original: Vec<u8> = (0..largo).map(|i| (i % 251) as u8).collect();
            let mut v = original.clone();
            aplicar_mascara(&m, &id, &mut v);
            if largo > 0 {
                assert_ne!(v, original, "la máscara no cambió nada con {largo} bytes");
            }
            aplicar_mascara(&m, &id, &mut v);
            assert_eq!(v, original, "la máscara no es su propia inversa con {largo} bytes");
        }

        // EL CONTADOR EXISTE: dos tramos consecutivos tienen que ser distintos.
        // Sin él, la máscara se repetiría cada 8160 B y un claro estructurado
        // dejaría el patrón a la vista.
        let mut m1 = vec![0u8; 2 * TRAMO_HKDF];
        aplicar_mascara(&m, &id, &mut m1);
        assert_ne!(
            &m1[..TRAMO_HKDF],
            &m1[TRAMO_HKDF..],
            "los dos tramos de la máscara son iguales: falta el contador en la etiqueta"
        );

        // Y depende del MENSAJE: otro id, otra máscara.
        let mut otra = vec![0u8; 64];
        let mut esta = vec![0u8; 64];
        aplicar_mascara(&m, &[0x01u8; ID_LEN], &mut otra);
        aplicar_mascara(&m, &[0x02u8; ID_LEN], &mut esta);
        assert_ne!(otra, esta, "la máscara no depende del id del mensaje");
    }

    /// Y el caso que de verdad distingue repartir de no repartir: un claro
    /// ESTRUCTURADO —todo ceros— donde cualquier fallo del enmascarado se ve a
    /// simple vista. Sin el reparto, una mitad sería 4 KiB de ceros.
    #[test]
    fn un_claro_de_puros_ceros_no_deja_ceros_en_ninguna_mitad() {
        let m = maestra();
        let claro = vec![0u8; 4096];
        let blob = cifrar(&m, &claro, b"").expect("hay entropía");
        let (s1, s2) = mitades_reales(&m, &blob, b"");

        for (nombre, mitad) in [("AES", &s1), ("XChaCha", &s2)] {
            assert_eq!(mitad.len(), 4096);
            assert!(
                crate::aleatorio::salud_de(mitad).is_none(),
                "la mitad de {nombre} no parece aleatoria"
            );
            let ceros = mitad.iter().filter(|b| **b == 0).count();
            // 4096/256 = 16 esperados. Un margen amplio: esto caza «son todo
            // ceros», no un sesgo fino.
            assert!(ceros < 100, "la mitad de {nombre} tiene {ceros} ceros de 4096");
        }
    }

    /// Dos cifrados del mismo claro no comparten ni el id ni las mitades.
    #[test]
    fn dos_cifrados_del_mismo_claro_no_se_parecen() {
        let m = maestra();
        let claro = b"lo mismo dos veces";
        let a = cifrar(&m, claro, b"").expect("hay entropía");
        let b = cifrar(&m, claro, b"").expect("hay entropía");
        assert_ne!(a, b, "el id por mensaje tiene que hacerlos distintos");
        assert_ne!(a[4..4 + ID_LEN], b[4..4 + ID_LEN], "dos ids iguales");
    }

    /// El tamaño, fijado: `2·|claro| + 56`. Es el precio del módulo y no debe
    /// moverse sin que alguien lo decida.
    #[test]
    fn el_tamano_es_el_doble_mas_la_cabecera_y_los_dos_tags() {
        let m = maestra();
        for largo in [0usize, 1, 1000] {
            let blob = cifrar(&m, &vec![9u8; largo], b"").expect("hay entropía");
            assert_eq!(blob.len(), 2 * largo + 56, "con {largo} bytes de claro");
        }
    }

    // =======================================================================
    // LO QUE TIENE QUE RECHAZAR
    // =======================================================================

    /// EMPALME entre mensajes: la capa A de uno con la capa B de otro. Si esto
    /// autenticara, saldría un claro basura CON SELLO DE BUENO, que es el peor
    /// resultado posible.
    ///
    /// Lo impide que el material criptográfico se derive del id del mensaje: la
    /// capa B del otro está cifrada con otra clave. Ver
    /// [`cada_capa_deriva_material_propio_y_por_mensaje`], que es donde eso se
    /// prueba — esta de aquí comprueba el efecto, no la causa.
    #[test]
    fn no_se_pueden_empalmar_dos_mensajes() {
        let m = maestra();
        let uno = cifrar(&m, &[0xAAu8; 64], b"").expect("hay entropía");
        let dos = cifrar(&m, &[0xBBu8; 64], b"").expect("hay entropía");
        assert_eq!(uno.len(), dos.len());

        // La cabecera y la capa A de `uno`, la capa B de `dos`.
        let corte = CABECERA + (uno.len() - CABECERA) / 2;
        let mut frankenstein = uno[..corte].to_vec();
        frankenstein.extend_from_slice(&dos[corte..]);

        assert_eq!(
            descifrar(&m, &frankenstein, b""),
            Err(BlindajeError::NoAutentica),
            "un empalme de dos mensajes NO puede autenticar"
        );
    }

    /// INTERCAMBIO de capas dentro del mismo mensaje. Importa porque el XOR es
    /// conmutativo: si las dos mitades se aceptaran cambiadas de sitio, el
    /// módulo estaría abriendo un blob que no produjo.
    ///
    /// Lo impide, antes que ninguna etiqueta, que **son algoritmos distintos**:
    /// un ciphertext de XChaCha no autentica bajo AES-GCM. Medido con un
    /// mutante que borra la etiqueta de capa: esta prueba sigue verde.
    #[test]
    fn no_se_pueden_intercambiar_las_dos_capas() {
        let m = maestra();
        let blob = cifrar(&m, &[0x11u8; 64], b"").expect("hay entropía");
        let cuerpo = &blob[CABECERA..];
        let (c1, c2) = cuerpo.split_at(cuerpo.len() / 2);

        let mut cambiado = blob[..CABECERA].to_vec();
        cambiado.extend_from_slice(c2);
        cambiado.extend_from_slice(c1);

        assert_eq!(descifrar(&m, &cambiado, b""), Err(BlindajeError::NoAutentica));
    }

    /// Un bit tocado en CUALQUIERA de las dos capas. Se prueban las dos por
    /// separado: con una sola, la otra podría no estar verificándose.
    #[test]
    fn un_bit_tocado_en_cualquier_capa_lo_tumba() {
        let m = maestra();
        let claro = [0x33u8; 128];
        let blob = cifrar(&m, &claro, b"aad").expect("hay entropía");
        let mitad_del_cuerpo = CABECERA + (blob.len() - CABECERA) / 2;

        for (nombre, pos) in [("capa AES", CABECERA + 5), ("capa XChaCha", mitad_del_cuerpo + 5)] {
            let mut roto = blob.clone();
            roto[pos] ^= 1;
            assert_eq!(
                descifrar(&m, &roto, b"aad"),
                Err(BlindajeError::NoAutentica),
                "un bit en la {nombre} tiene que tumbarlo"
            );
        }
    }

    #[test]
    fn el_aad_y_la_clave_atan() {
        let m = maestra();
        let blob = cifrar(&m, b"secreto", b"cabecera").expect("hay entropía");
        assert_eq!(descifrar(&m, &blob, b"otra"), Err(BlindajeError::NoAutentica));
        assert_eq!(
            descifrar(&[0x5Bu8; kdf::KEY_LEN], &blob, b"cabecera"),
            Err(BlindajeError::NoAutentica)
        );
        // Control: con los buenos, abre.
        assert!(descifrar(&m, &blob, b"cabecera").is_ok());
    }

    #[test]
    fn los_blobs_mal_formados_se_rechazan_por_formato() {
        let m = maestra();
        let blob = cifrar(&m, &[7u8; 32], b"").expect("hay entropía");

        assert_eq!(descifrar(&m, b"", b""), Err(BlindajeError::Formato));
        assert_eq!(descifrar(&m, &blob[..CABECERA - 1], b""), Err(BlindajeError::Formato));

        let mut magia_mala = blob.clone();
        magia_mala[0] = b'X';
        assert_eq!(descifrar(&m, &magia_mala, b""), Err(BlindajeError::Formato));

        // Un largo declarado que no cabe: no puede desbordar ni entrar en pánico.
        let mut largo_mentiroso = blob.clone();
        largo_mentiroso[4 + ID_LEN..CABECERA].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(descifrar(&m, &largo_mentiroso, b""), Err(BlindajeError::Formato));

        // Y uno que cabe pero deja las mitades desiguales.
        let mut desigual = blob.clone();
        desigual[4 + ID_LEN..CABECERA].copy_from_slice(&20u32.to_be_bytes());
        assert_eq!(descifrar(&m, &desigual, b""), Err(BlindajeError::Formato));

        // Control: el blob intacto abre.
        assert!(descifrar(&m, &blob, b"").is_ok());
    }

    // =======================================================================
    // VECTORES CONGELADOS DEL FORMATO QBL2
    // =======================================================================
    //
    // El formato se congela AHORA, antes de que `api::` lo use, y no después:
    // en cuanto un modo se enchufa a la API produce artefactos que se guardan en
    // casa de un cliente, y a partir de ahí moverlo es romperle los suyos. Es la
    // misma razón por la que el códec base-N tiene vectores desde su primer día.
    //
    // El azar va FIJO —el id y la mitad `S1`— porque si no, no hay nada que
    // congelar. Los valores no significan nada: sólo tienen que no cambiar.

    const VEC_MASTER: [u8; kdf::KEY_LEN] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF, 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2,
        0xE1, 0xF0,
    ];
    const VEC_ID: [u8; ID_LEN] = [
        0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA,
        0x98,
    ];

    /// La mitad aleatoria, fijada de forma reproducible.
    fn vec_s1(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i as u8).wrapping_mul(97).wrapping_add(13)).collect()
    }

    /// La otra mitad se deriva, igual que en el camino real.
    fn vec_s2(claro: &[u8]) -> Vec<u8> {
        claro.iter().zip(vec_s1(claro.len())).map(|(p, r)| p ^ r).collect()
    }

    fn casos_congelados() -> Vec<(&'static str, &'static [u8], &'static [u8])> {
        vec![
            ("vacio", b"", b""),
            ("corto", b"quipu", b""),
            ("con-aad", b"quipu", b"cabecera"),
        ]
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn de_hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex válido en un vector"))
            .collect()
    }

    /// **EL FORMATO NO SE MUEVE.** Tres vectores con el azar fijo.
    ///
    /// Una prueba de ida y vuelta no protege esto: pasa igual si se cambia el
    /// formato entero, mientras siga siendo consistente consigo mismo. Estos
    /// bytes son la definición.
    #[test]
    fn los_vectores_de_qbl2_no_se_mueven() {
        let esperados = [
            "51424c32deadbeef0123456789abcdeffedcba980000001063e946f12ef0532115e9d149cf5142715bef4dab2e05e97b27dda70e1f2bdf2f",
            "51424c32deadbeef0123456789abcdeffedcba9800000015160e4809aa1ae1cce3efa918f4e30f354722436c37ba1b8ff91199c7b1daba1e96715ae9aba09888c5f2",
            "51424c32deadbeef0123456789abcdeffedcba9800000015160e4809aa436bf8d839fc2fc88c92b5fb8b69c8beba1b8ff911520bab53998d045270792281bc362af7",
        ];
        for ((nombre, claro, aad), esperado) in casos_congelados().iter().zip(esperados) {
            let esperado: String = esperado.chars().filter(|c| !c.is_whitespace()).collect();
            let blob = armar(&VEC_MASTER, &VEC_ID, &vec_s1(claro.len()), &vec_s2(claro), aad);
            assert_eq!(hex(&blob), esperado, "el vector «{nombre}» se movió");
        }
    }

    /// **UN BLOB QUE NO AUTENTICA NO DERIVA NI UN BYTE DE MÁSCARA**, y eso es
    /// una propiedad de DÓNDE está la llamada, no de qué hace.
    ///
    /// La señaló la revisión de seguridad del 2026-08-17 como cubierta por la
    /// forma y no por la propiedad: `aplicar_mascara` corre dentro del brazo
    /// `(Some, Some)` del `match`, o sea después de que las dos capas
    /// autentiquen. Moverla antes del `match` —refactor perfectamente plausible,
    /// «para no repetirla en dos brazos»— dejaba **todas** las pruebas en verde
    /// y abría una asimetría de coste elegible por quien manda el blob: `2·n`
    /// bytes de HKDF derivados para basura que no autentica.
    ///
    /// Un comentario no sujeta eso. Este contador sí.
    #[test]
    fn un_blob_que_no_autentica_no_deriva_ni_un_byte_de_mascara() {
        let m = maestra();
        let claro = vec![0xABu8; 512];
        let mut blob = cifrar(&m, &claro, b"aad").expect("hay entropía");

        // CONTROL: el camino bueno SÍ enmascara. Sin esto, un cero abajo se
        // cumpliría igual con una `aplicar_mascara` que no se llamara nunca —el
        // instrumento diciendo que no a todo.
        VECES_ENMASCARADO.with(|v| v.set(0));
        assert_eq!(descifrar(&m, &blob, b"aad"), Ok(claro), "el camino bueno tiene que abrir");
        assert_eq!(
            VECES_ENMASCARADO.with(std::cell::Cell::get),
            1,
            "descifrar con éxito tiene que enmascarar exactamente una vez"
        );

        // Y EL CASO ROJO: un tag tocado. El último byte del blob es del tag de
        // la capa 2, así que esto rompe la autenticación y nada más.
        let ultimo = blob.len() - 1;
        blob[ultimo] ^= 0x01;
        VECES_ENMASCARADO.with(|v| v.set(0));
        crate::kdf::BYTES_EXPANDIDOS.with(|v| v.set(0));
        assert_eq!(
            descifrar(&m, &blob, b"aad"),
            Err(BlindajeError::NoAutentica),
            "el blob tocado tiene que rechazarse"
        );
        assert_eq!(
            VECES_ENMASCARADO.with(std::cell::Cell::get),
            0,
            "se derivó máscara para un blob que NO autentica: la llamada se movió \
             fuera del brazo de éxito, y eso es trabajo que elige el atacante"
        );

        // Y EL TRABAJO, no solo la función. El banco de mutación encontró que
        // derivar los mismos `2·n` bytes llamando a `kdf::derive_stream` a pelo
        // —saltándose `aplicar_mascara`— pasaba el contador de arriba sin
        // despeinarse. Lo que hay que acotar es cuánto se expande, y en el camino
        // de fallo son EXACTAMENTE las cuatro derivaciones de claves y nonces.
        let expandido = crate::kdf::BYTES_EXPANDIDOS.with(std::cell::Cell::get);
        let solo_material = 32 + NONCE_AES + cipher::KEY_LEN + cipher::NONCE_LEN;
        assert_eq!(
            expandido, solo_material,
            "un blob que no autentica expandió {expandido} B de HKDF y solo debería \
             expandir {solo_material} (las claves y los nonces de las dos capas): \
             el resto es trabajo de tamaño elegible por quien manda el blob"
        );
    }

    /// **EL VECTOR QUE CRUZA UN TRAMO.** Existe porque un mutante sobrevivió al
    /// banco entero, y lo encontró la revisión de seguridad, no yo.
    ///
    /// Los tres casos congelados de arriba miden 0 y 5 bytes, y el mensaje más
    /// largo de todo el banco de blindaje son 4 KiB: **ninguno llega a los 8 160
    /// B de [`TRAMO_HKDF`]**, así que ninguno usa el contador de tramos para
    /// otra cosa que el tramo 0 — y en el tramo 0 el contador son cuatro ceros,
    /// que se escriben igual en big-endian que en little-endian.
    ///
    /// Medido el 2026-08-17: cambiar `to_be_bytes()` por `to_le_bytes()` en
    /// [`aplicar_mascara`] **no ponía roja ni una de las 156 pruebas**. Eso es
    /// un cambio silencioso del formato en disco para todo mensaje mayor de
    /// 8 KiB, o sea para un documento de verdad. Las dos propiedades que sí se
    /// probaban —involución y desigualdad entre tramos— se cumplen con las dos
    /// codificaciones, así que ninguna podía cazarlo: es la directiva 33 otra
    /// vez, un banco que mide la forma y no el artefacto.
    ///
    /// Se congela el SHA-256 y no el hexadecimal porque el blob son ~16 KiB.
    #[test]
    fn el_vector_que_cruza_un_tramo_no_se_mueve() {
        use sha2::{Digest, Sha256};
        let largo = TRAMO_HKDF + 1;
        let claro: Vec<u8> = (0..largo).map(|i| (i % 251) as u8).collect();
        let blob = armar(&VEC_MASTER, &VEC_ID, &vec_s1(largo), &vec_s2(&claro), b"tramo");
        assert_eq!(
            blob.len(),
            2 * largo + CABECERA + 2 * TAG,
            "el tamaño del blob cambió"
        );
        assert_eq!(
            hex(&Sha256::digest(&blob)),
            "d2f64519e5ad8e5cf1fd78966f789a26a52ac806243b3f438487e5736ac79b88",
            "el vector de más de un tramo se movió: si fue a propósito, regenéralo; \
             si no, alguien cambió el troceado o el contador de la máscara"
        );
    }

    /// **UN ARTEFACTO GUARDADO SIGUE ABRIENDO.** El mismo blob, escrito a mano,
    /// descifra a lo que descifraba.
    ///
    /// Es la otra mitad, y la que de verdad importa para un cliente: la de
    /// arriba fija lo que se PRODUCE, ésta fija lo que se puede LEER, y no
    /// depende del camino de cifrado en absoluto — si mañana se reescribiera
    /// `armar`, esta prueba seguiría sujetando la compatibilidad.
    #[test]
    fn un_blob_guardado_sigue_abriendo() {
        let blob = de_hex(
            "51424c32deadbeef0123456789abcdeffedcba9800000015160e4809aa436bf8d839fc2fc88c92b5fb8b69c8beba1b8ff911520bab53998d045270792281bc362af7",
        );
        assert_eq!(
            descifrar(&VEC_MASTER, &blob, b"cabecera"),
            Ok(b"quipu".to_vec()),
            "un blindaje guardado dejó de abrirse"
        );
        // Control: con otro aad NO abre, o sea que la prueba de arriba no está
        // pasando porque `descifrar` devuelva algo pase lo que pase.
        assert_eq!(descifrar(&VEC_MASTER, &blob, b"otra"), Err(BlindajeError::NoAutentica));
    }

    /// **UN `QBL1` SE RECHAZA EN VOZ ALTA**, y este es el vector real del
    /// formato viejo, copiado de la versión anterior de esta misma prueba.
    ///
    /// Es la mitad que no se ve venir. `QBL2` cambia dos cosas a la vez: la
    /// máscara y la marca. Si solo hubiera cambiado la máscara, un contenedor
    /// viejo habría abierto sus dos capas —las claves y los nonces no
    /// cambiaron—, se le habría quitado una máscara que nadie le puso, y
    /// `descifrar` habría devuelto **basura autenticada**: 5 bytes que no son
    /// «quipu» y ningún error. Es el fallo silencioso de la directiva 20, en el
    /// peor sitio posible.
    ///
    /// Lo impide la marca, porque entra en `aad_de_capa` **y** se comprueba a la
    /// entrada. Esta prueba fija que ese rechazo existe y que es de FORMATO
    /// —o sea, «esto es otro formato»— y no de autenticación.
    #[test]
    fn un_blob_qbl1_no_se_abre_en_silencio() {
        let viejo = de_hex(
            "51424c31deadbeef0123456789abcdeffedcba9800000015160e4809aa60e9efc9a10613860ea4256f9d548abc4906156922d73969ec12a03515903487c9dfecb9f0",
        );
        assert_eq!(
            descifrar(&VEC_MASTER, &viejo, b"cabecera"),
            Err(BlindajeError::OtraVersion),
            "un contenedor QBL1 tiene que rechazarse diciendo que es de OTRA VERSIÓN, \
             no abrirse, no fallar por tag y no confundirse con un marco manipulado"
        );

        // LA PAREJA QUE DISCRIMINA, y es la que faltaba: «otra versión» tiene que
        // ser SOLO la marca. Un blob con el campo de largo tocado —que va en claro
        // y sin autenticar— es MANIPULACIÓN, y decirle a la víctima que su archivo
        // es de un formato antiguo la manda a buscar una versión vieja del
        // programa en vez de a sospechar. Lo midió la revisión de seguridad del
        // 2026-08-17 sobre la primera versión de este arreglo, que fallaba justo
        // aquí.
        let mut largo_tocado = de_hex(
            "51424c32deadbeef0123456789abcdeffedcba9800000015160e4809aa436bf8d839fc2fc88c92b5fb8b69c8beba1b8ff911520bab53998d045270792281bc362af7",
        );
        largo_tocado[4 + ID_LEN] ^= 0x01;
        assert_eq!(
            descifrar(&VEC_MASTER, &largo_tocado, b"cabecera"),
            Err(BlindajeError::Formato),
            "un largo manipulado NO puede anunciarse como «otra versión»: es un marco \
             inválido, y casi siempre manipulación"
        );

        // Y una marca que ni siquiera es de la familia tampoco lo es.
        let mut ajeno = largo_tocado.clone();
        ajeno[..4].copy_from_slice(b"XXXX");
        assert_eq!(
            descifrar(&VEC_MASTER, &ajeno, b"cabecera"),
            Err(BlindajeError::Formato),
            "una marca ajena no es «otra versión» de este formato"
        );

        // CONTROL: el mismo blob con la marca parcheada a QBL2 tampoco abre —y
        // ahora falla por AUTENTICACIÓN, que es lo correcto—. Sin este control,
        // lo de arriba pasaría igual con un `descifrar` que rechazara cualquier
        // cosa, y no probaría que la marca es lo que discrimina.
        let mut parcheado = viejo;
        parcheado[..4].copy_from_slice(MAGIA);
        assert_eq!(
            descifrar(&VEC_MASTER, &parcheado, b"cabecera"),
            Err(BlindajeError::NoAutentica),
            "con la marca parcheada el rechazo tiene que venir del tag"
        );
    }

    /// Arma A MANO un contenedor con la marca de OTRA versión de la familia,
    /// cifrando cada capa con el `aad` que esa marca impone.
    ///
    /// Es lo que un `QBL1` legítimo produce —mismo marco, misma derivación de
    /// `(master, id)`, otra marca—, y hace falta porque los mutantes que
    /// sobrevivieron viven todos DENTRO de `autentica_como_otra_version`, a la
    /// que solo se llega con un blob de la familia que además autentique. El
    /// único vector guardado (`un_blob_qbl1_no_se_abre_en_silencio`) tiene un
    /// contenido fijo de 5 bytes y no alcanza ni el borde de `largo_c1 == TAG`
    /// ni el caso de una sola capa.
    fn blob_de_otra_version(
        master: &[u8; kdf::KEY_LEN],
        magia: &[u8; 4],
        id: &[u8; ID_LEN],
        s1: &[u8],
        s2: &[u8],
        aad: &[u8],
    ) -> Vec<u8> {
        let c1 = capa_aes_cifrar(master, id, s1, &aad_de_capa_con(aad, magia, id, 1));
        let c2 = capa_chacha_cifrar(master, id, s2, &aad_de_capa_con(aad, magia, id, 2));
        let mut blob = Vec::with_capacity(CABECERA + c1.len() + c2.len());
        blob.extend_from_slice(magia);
        blob.extend_from_slice(id);
        blob.extend_from_slice(&u32::try_from(c1.len()).expect("cabe en u32").to_be_bytes());
        blob.extend_from_slice(&c1);
        blob.extend_from_slice(&c2);
        blob
    }

    /// **EL ARNÉS SE VALIDA CONTRA EL CAMINO REAL** antes de usarlo para nada
    /// (directiva 33): un blob armado por `blob_de_otra_version` tiene que
    /// llevarse el mismo `OtraVersion` que se lleva el vector guardado. Sin
    /// esto, las tres pruebas de abajo podrían estar pasando porque el arnés
    /// produce algo que `descifrar` rechaza por FORMATO sin mirar las capas.
    #[test]
    fn el_arnes_de_otra_version_produce_lo_que_el_camino_real_reconoce() {
        let blob = blob_de_otra_version(
            &VEC_MASTER,
            b"QBL1",
            &VEC_ID,
            &[0x11u8; 32],
            &[0x22u8; 32],
            b"cabecera",
        );
        assert_eq!(
            descifrar(&VEC_MASTER, &blob, b"cabecera"),
            Err(BlindajeError::OtraVersion),
            "el arnés no llega a `autentica_como_otra_version`: lo que mida abajo no vale"
        );
        // Y la pareja: con OTRA maestra el mismo blob no autentica, así que el
        // veredicto de arriba viene de las capas y no de la marca.
        assert_eq!(
            descifrar(&[0u8; kdf::KEY_LEN], &blob, b"cabecera"),
            Err(BlindajeError::Formato),
            "sin la clave, «otra versión» no puede afirmarse: es un hecho, no una pista"
        );
    }

    /// **EL BORDE `largo_c1 == TAG`: un contenedor de otra versión con contenido
    /// VACÍO sigue siendo de otra versión.**
    ///
    /// Es el caso que separa `largo_c1 < TAG` de `<=` y de `==`, y ningún vector
    /// lo tocaba: con el contenido vacío cada capa es exactamente su tag, o sea
    /// `largo_c1 == TAG` clavado. Los tres mutantes de esa línea que
    /// `cargo-mutants` dejó vivos el 2026-08-17 se ven solo aquí — con `<=` o
    /// con `==` el blob sale por `Formato`, y al usuario se le dice que su
    /// archivo está manipulado cuando lo que tiene es un formato viejo.
    #[test]
    fn otra_version_con_contenido_vacio_sigue_siendo_otra_version() {
        let blob = blob_de_otra_version(&VEC_MASTER, b"QBL1", &VEC_ID, b"", b"", b"cabecera");
        assert_eq!(
            blob.len(),
            CABECERA + 2 * TAG,
            "el borde es `largo_c1 == TAG`: si el blob no mide esto, la prueba mide otra cosa"
        );
        assert_eq!(
            descifrar(&VEC_MASTER, &blob, b"cabecera"),
            Err(BlindajeError::OtraVersion),
            "un contenedor VACÍO de otra versión tiene que declararse como tal"
        );
    }

    /// **UN `largo_c1` DISPARATADO NO PUEDE ENTRAR EN PÁNICO.**
    ///
    /// El campo va en claro y sin autenticar, así que lo elige quien manda el
    /// blob. `cabe` es lo que impide que `split_at` reviente, y hasta hoy nada
    /// lo probaba POR ESTE CAMINO: el vector de largo manipulado que ya existe
    /// entra por el camino normal de `descifrar`, no por
    /// `autentica_como_otra_version`, que tiene su propia copia de la
    /// comprobación. Quitarla ahí es un pánico con entrada de red.
    #[test]
    fn otra_version_con_largo_disparatado_no_entra_en_panico() {
        let mut blob = blob_de_otra_version(
            &VEC_MASTER,
            b"QBL1",
            &VEC_ID,
            &[0x33u8; 48],
            &[0x44u8; 48],
            b"cabecera",
        );
        // CONTROL POSITIVO: sin tocar el largo, este blob SÍ recorre la función
        // entera. Sin él, un `Formato` de abajo sería indistinguible de un blob
        // que ni siquiera llegó.
        assert_eq!(
            descifrar(&VEC_MASTER, &blob, b"cabecera"),
            Err(BlindajeError::OtraVersion),
            "el control: este blob llega hasta el final de la función"
        );

        for largo in [u32::MAX, 0xFFFF_FF00, 1 << 31] {
            blob[4 + ID_LEN..CABECERA].copy_from_slice(&largo.to_be_bytes());
            assert_eq!(
                descifrar(&VEC_MASTER, &blob, b"cabecera"),
                Err(BlindajeError::Formato),
                "un largo de {largo} tiene que rechazarse, no partir el cuerpo por ahí"
            );
        }
    }

    /// **UNA SOLA CAPA QUE AUTENTICA NO BASTA** para declarar «otra versión».
    ///
    /// Es la propiedad que sostiene el arreglo entero: `OtraVersion` es un HECHO
    /// —el blob abre bajo la versión que dice ser— y no una pista que el
    /// atacante elige. Con media autenticación vuelve a ser elegible: quien
    /// tenga un `c1` legítimo de otro mensaje puede pegarle cualquier `c2` del
    /// mismo largo. Se prueba por los dos lados, porque un mutante que cambie el
    /// `&&` por `||` los abre los dos a la vez.
    #[test]
    fn una_sola_capa_que_autentica_no_basta() {
        let base = blob_de_otra_version(
            &VEC_MASTER,
            b"QBL1",
            &VEC_ID,
            &[0x55u8; 24],
            &[0x66u8; 24],
            b"cabecera",
        );
        let largo_c1 = 24 + TAG;
        assert_eq!(
            descifrar(&VEC_MASTER, &base, b"cabecera"),
            Err(BlindajeError::OtraVersion),
            "el control: intactas las dos capas, esto es «otra versión»"
        );

        // Solo la primera capa autentica.
        let mut sin_c2 = base.clone();
        sin_c2[CABECERA + largo_c1] ^= 0x01;
        assert_eq!(
            descifrar(&VEC_MASTER, &sin_c2, b"cabecera"),
            Err(BlindajeError::Formato),
            "con la segunda capa rota NO se puede afirmar que sea de otra versión"
        );

        // Solo la segunda.
        let mut sin_c1 = base;
        sin_c1[CABECERA] ^= 0x01;
        assert_eq!(
            descifrar(&VEC_MASTER, &sin_c1, b"cabecera"),
            Err(BlindajeError::Formato),
            "con la primera capa rota NO se puede afirmar que sea de otra versión"
        );
    }

    /// **CADA ERROR DICE DE CUÁL SE TRATA.** El `Display` es lo que ve el
    /// usuario, y los tres diagnósticos existen precisamente para no
    /// confundirse entre ellos: si los tres imprimieran lo mismo —o nada— el
    /// trabajo de separarlos se pierde en la última pulgada.
    ///
    /// Sale del mutante 345 que sobrevivió al banco del 2026-08-17: sustituir el
    /// cuerpo entero por `Ok(())` no rompía una sola prueba, porque ninguna
    /// miraba el texto.
    #[test]
    fn el_texto_de_cada_error_lo_distingue() {
        let formato = BlindajeError::Formato.to_string();
        let otra = BlindajeError::OtraVersion.to_string();
        let no_autentica = BlindajeError::NoAutentica.to_string();

        for (que, texto) in [
            ("Formato", &formato),
            ("OtraVersion", &otra),
            ("NoAutentica", &no_autentica),
        ] {
            assert!(!texto.is_empty(), "el error {que} se imprime vacío");
        }
        assert_ne!(formato, otra, "«marco inválido» y «otra versión» no pueden leerse igual");
        assert_ne!(otra, no_autentica, "«otra versión» y «no autentica» no pueden leerse igual");
        assert_ne!(formato, no_autentica, "«marco inválido» y «no autentica» no pueden leerse igual");

        // Y que cada texto sea el SUYO, no otro cualquiera no vacío: un mutante
        // que intercambie dos brazos del `match` pasaría lo de arriba.
        assert!(otra.contains("otra versión"), "el texto de OtraVersion no la nombra: {otra}");
        assert!(
            no_autentica.contains("no autentica"),
            "el texto de NoAutentica no lo dice: {no_autentica}"
        );
        assert!(
            formato.contains("QBL2") || formato.contains("forma"),
            "el texto de Formato no habla del marco: {formato}"
        );
    }

    /// El material derivado, congelado también. Un cambio en las cuatro
    /// etiquetas de dominio mueve todos los vectores de arriba a la vez y sería
    /// difícil de leer; aquí se ve de una.
    #[test]
    fn el_material_derivado_no_se_mueve() {
        let (k1, n1) = claves_aes(&VEC_MASTER, &VEC_ID);
        let (k2, n2) = claves_chacha(&VEC_MASTER, &VEC_ID);
        assert_eq!(hex(k1.as_ref()), "529cb6320962e0d862714771ccf296abf6220de5250e637abcf6483012fda931");
        assert_eq!(hex(&n1), "3746330aa4feceed24f2d5cd");
        assert_eq!(hex(k2.as_ref()), "af31295a5c156585629f08a6872224d43caae2e443fac71ff3fdbb54f1418dd7");
        assert_eq!(hex(&n2), "d6b3f9c4fbc4e3a5464408382aa9e0bcc2143c0701dee2cb");
    }

    /// Impresora de vectores, para cuando haya que regenerarlos a conciencia:
    /// `cargo test --features blindaje imprimir_vectores -- --ignored --nocapture`
    #[test]
    #[ignore = "sólo para regenerar los vectores congelados"]
    fn imprimir_vectores() {
        for (nombre, claro, aad) in casos_congelados() {
            let blob = armar(&VEC_MASTER, &VEC_ID, &vec_s1(claro.len()), &vec_s2(claro), aad);
            println!("{nombre}: {}", hex(&blob));
        }
    }

    // =======================================================================
    // LAS CERRADURAS, CADA UNA PROBADA POR SEPARADO
    // =======================================================================
    //
    // Escritas porque tres mutantes sobrevivieron al primer banco: quitar el id
    // de los datos asociados, quitar la etiqueta de capa, y hacer que las dos
    // capas compartan clave. Los tres dejaban las once pruebas en verde. Los dos
    // primeros porque había OTRA cerradura tapándolos —y entonces la
    // documentación estaba mal, no el código—; el tercero porque nadie miraba.

    /// **LA CERRADURA DE VERDAD.** Cada capa deriva su clave y su nonce, y los
    /// cuatro cambian con el id del mensaje.
    ///
    /// Es lo que impide de golpe tres cosas: reutilizar nonce en GCM (que es
    /// catastrófico), empalmar dos mensajes, y que un fallo de recuperación de
    /// clave en una capa entregue la otra.
    #[test]
    fn cada_capa_deriva_material_propio_y_por_mensaje() {
        let m = maestra();
        let id_a = [1u8; ID_LEN];
        let id_b = [2u8; ID_LEN];

        let (k1, n1) = claves_aes(&m, &id_a);
        let (k2, n2) = claves_chacha(&m, &id_a);

        // Entre capas: nada compartido.
        assert_ne!(k1.as_ref() as &[u8], k2.as_ref() as &[u8], "las dos capas comparten clave");
        assert_ne!(&n1[..], &n2[..12], "las dos capas comparten nonce");

        // Entre mensajes: nada repetido.
        let (k1b, n1b) = claves_aes(&m, &id_b);
        let (k2b, n2b) = claves_chacha(&m, &id_b);
        assert_ne!(k1.as_ref() as &[u8], k1b.as_ref() as &[u8], "la clave AES no depende del id");
        assert_ne!(k2.as_ref() as &[u8], k2b.as_ref() as &[u8], "la clave XChaCha no depende del id");
        assert_ne!(n1, n1b, "el nonce AES no depende del id");
        assert_ne!(n2, n2b, "el nonce XChaCha no depende del id");

        // CONTROL: con el mismo id, es determinista. Sin esto, un derivador que
        // devolviera aleatorio puro pasaría todo lo de arriba y no descifraría
        // nunca.
        let (otra_vez, y_su_nonce) = claves_aes(&m, &id_a);
        assert_eq!(k1.as_ref() as &[u8], otra_vez.as_ref() as &[u8]);
        assert_eq!(n1, y_su_nonce);
    }

    /// Las CINCO etiquetas de dominio son distintas **y ninguna es prefijo de
    /// otra**. Es la causa de lo de arriba, y se comprueba aparte porque una
    /// colisión aquí sería un copia-y-pega invisible.
    ///
    /// # Por qué el prefijo, y no solo la desigualdad
    ///
    /// `material` concatena `info ‖ id`, y la máscara concatena
    /// `INFO_M1 ‖ id ‖ contador`. Que dos etiquetas sean distintas NO basta para
    /// que las concatenaciones lo sean: si una fuera prefijo de otra, la cola
    /// —16 bytes de id, o 16 + 4— podría absorber la diferencia y dos usos
    /// distintos derivarían el mismo material. Con las etiquetas libres de
    /// prefijo, la concatenación es inyectiva y el argumento de `material` se
    /// mantiene al añadir el contador.
    ///
    /// Hoy se cumple de sobra —las cinco difieren dentro de los primeros 20
    /// bytes—, y por eso mismo hace falta la prueba: es una propiedad que se
    /// rompería sin que nada más se pusiera rojo.
    #[test]
    fn ninguna_etiqueta_de_dominio_es_prefijo_de_otra() {
        let etiquetas = [INFO_K1, INFO_K2, INFO_N1, INFO_N2, INFO_M1];
        for (i, a) in etiquetas.iter().enumerate() {
            for (j, b) in etiquetas.iter().enumerate() {
                if i == j {
                    continue;
                }
                assert_ne!(a, b, "dos etiquetas de dominio iguales");
                assert!(
                    !b.starts_with(a),
                    "la etiqueta {:?} es prefijo de {:?}: la concatenación con el id \
                     deja de ser inyectiva",
                    core::str::from_utf8(a).unwrap_or("<no utf8>"),
                    core::str::from_utf8(b).unwrap_or("<no utf8>"),
                );
            }
        }
    }

    /// La segunda cerradura existe de verdad: el id y la etiqueta de capa están
    /// dentro de los datos asociados, y los del llamante se conservan.
    ///
    /// Prueba la PRESENCIA, no el efecto — el efecto hoy lo tapa la derivación
    /// de claves. Está para que quitarla se note.
    #[test]
    fn los_datos_asociados_llevan_el_id_y_la_capa() {
        let id = [0xC3u8; ID_LEN];
        let a = aad_de_capa(b"del-llamante", &id, 1);
        let b = aad_de_capa(b"del-llamante", &id, 2);

        assert!(a.starts_with(b"del-llamante"), "se perdió el aad del llamante");
        assert!(contiene(&a, &id), "el id no está en los datos asociados");
        assert_ne!(a, b, "las dos capas tienen los mismos datos asociados");

        // Y cambia con el mensaje.
        let otro = aad_de_capa(b"del-llamante", &[0xC4u8; ID_LEN], 1);
        assert_ne!(a, otro, "los datos asociados no dependen del id");
    }

    fn contiene(pajar: &[u8], aguja: &[u8]) -> bool {
        pajar.windows(aguja.len()).any(|v| v == aguja)
    }

    /// El control del propio buscador: si `contiene` dijera que no a todo, las
    /// pruebas de arriba pasarían con el reparto borrado.
    #[test]
    fn el_buscador_de_testigos_encuentra_lo_que_esta() {
        assert!(contiene(b"abcdefg", b"cde"));
        assert!(contiene(b"abc", b"abc"));
        assert!(!contiene(b"abcdefg", b"xyz"));
    }

    // =======================================================================
    // DOS LÍMITES DOCUMENTADOS, CONGELADOS — no son defectos que se arreglen
    // =======================================================================
    //
    // Estas dos pruebas no cierran nada: FIJAN en un artefacto los dos límites
    // que hoy `blindaje.rs` describe SOLO en prosa y que su propio texto llama
    // «no se pondrán rojos jamás». El objetivo es exactamente ese «jamás»: que
    // el día que alguien meta un caché/reuso de `id`, o meta el `aad` en la
    // derivación, la prueba correspondiente se ponga ROJA y obligue a decidir.
    //
    // Referencias al código medido:
    //   - colisión de id  → doc de `aplicar_mascara`, sección «Y NADA CONTRA UNA
    //     COLISIÓN DE id: ahí la máscara es exactamente neutra» (el álgebra
    //     `C2 xor C2' = S2 xor S2'`), y el aviso de `cifrar`.
    //   - aad fuera de la derivación → aviso de `cifrar` («El aad NO entra en la
    //     derivación de claves ni de nonces … dos mensajes con el mismo id
    //     comparten K1,N1,K2,N2 y la máscara aunque sus aad sean distintos») y
    //     las firmas de `material`/`claves_aes`/`claves_chacha`/`aplicar_mascara`,
    //     que NO reciben `aad`.

    /// Corta el blob en sus dos capas cifradas `(c1, c2)`, cada una `cuerpo‖tag`.
    fn capas(blob: &[u8]) -> (&[u8], &[u8]) {
        let largo_c1 =
            u32::from_be_bytes(blob[4 + ID_LEN..CABECERA].try_into().unwrap()) as usize;
        blob[CABECERA..].split_at(largo_c1)
    }
    /// El CUERPO de la capa AES (sin el tag). AES-GCM es CTR: cuerpo = KS ⊕ msg.
    fn cuerpo_c1(blob: &[u8]) -> Vec<u8> {
        let (c1, _) = capas(blob);
        c1[..c1.len() - TAG].to_vec()
    }
    /// El CUERPO de la capa XChaCha (sin el tag). Es un cifrado de flujo:
    /// cuerpo = KS ⊕ (S2 ⊕ M).
    fn cuerpo_c2(blob: &[u8]) -> Vec<u8> {
        let (_, c2) = capas(blob);
        c2[..c2.len() - TAG].to_vec()
    }
    /// El TAG de la capa XChaCha. Aquí SÍ entra el `aad` (vía Poly1305).
    fn tag_c2(blob: &[u8]) -> Vec<u8> {
        let (_, c2) = capas(blob);
        c2[c2.len() - TAG..].to_vec()
    }

    fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
        a.iter().zip(b).map(|(x, y)| x ^ y).collect()
    }

    /// **LÍMITE CONGELADO — UNA COLISIÓN DE `id` CANCELA LA MÁSCARA.**
    ///
    /// No es un defecto que esta prueba arregle: es el límite que `aplicar_mascara`
    /// documenta con todas sus letras («la máscara es exactamente neutra … se
    /// cancela en la diferencia», con el álgebra `C2 xor C2' = S2 xor S2'`). Nada
    /// en `armar` impide repetir un `id`; en el uso normal sale del CSPRNG en
    /// `cifrar`, pero un caché de `id` o un `fork` lo repetiría — y AHÍ esta
    /// prueba tiene que ponerse roja para que se vea. La vía de laboratorio es
    /// `armar`, que toma `id`, `s1` y `s2` explícitos.
    ///
    /// Se usan `s1` DISTINTAS en los dos mensajes a propósito: es lo que haría un
    /// `fork` real (dos sorteos de `S1`), y demuestra que la cancelación de la
    /// máscara NO depende de que `S1` coincida.
    #[test]
    fn colision_de_id_cancela_la_mascara() {
        const LARGO: usize = 64;
        let m = maestra();
        let id = [0x42u8; ID_LEN];

        // Dos claros distintos y dos S1 distintas (como haría un fork real).
        let claro_a: Vec<u8> = (0..LARGO).map(|i| i as u8).collect();
        let claro_b: Vec<u8> = (0..LARGO).map(|i| (i as u8) ^ 0xFF).collect();
        let s1_a: Vec<u8> =
            (0..LARGO).map(|i| (i as u8).wrapping_mul(97).wrapping_add(13)).collect();
        let s1_b: Vec<u8> =
            (0..LARGO).map(|i| (i as u8).wrapping_mul(31).wrapping_add(7)).collect();
        let s2_a = xor(&claro_a, &s1_a);
        let s2_b = xor(&claro_b, &s1_b);

        // MISMO id, `aad` distinto a propósito (que tampoco lo impide, ver la otra
        // prueba). En un fork, además, las S1 difieren: aquí también.
        let blob_a = armar(&m, &id, &s1_a, &s2_a, b"contexto-A");
        let blob_b = armar(&m, &id, &s1_b, &s2_b, b"contexto-B");

        // CONTROL DE QUE LA MÁSCARA ESTÁ DE VERDAD (distingue de «no hay máscara»):
        // lo que la capa 2 recibió es `S2 ⊕ M`, y tiene que DIFERIR de `S2` crudo.
        // Sin esto, «la máscara se cancela» pasaría igual con `M = 0` — la máscara
        // es neutra bajo colisión de id, así que ninguna otra parte de esta prueba
        // puede detectar su presencia; esta línea sí.
        let (_, s2m_a) = mitades_reales(&m, &blob_a, b"contexto-A");
        assert_ne!(s2m_a, s2_a, "la capa 2 recibió S2 sin enmascarar: no hay máscara");
        let mut quitada = s2m_a;
        aplicar_mascara(&m, &id, &mut quitada);
        assert_eq!(quitada, s2_a, "quitar la máscara no devuelve S2: no es aplicar_mascara");

        // LA PROPIEDAD MEDIDA: el XOR de las dos capas 2 CIFRADAS es el XOR de las
        // S2. El keystream de ChaCha se cancela (mismo K2/N2 por el id repetido) y
        // —lo que importa— la MÁSCARA se cancela (mismo M por el id repetido). Si
        // `M` NO se cancelara (una sal por mensaje), aquí quedaría `M ⊕ M'` y la
        // igualdad fallaría.
        assert_eq!(
            xor(&cuerpo_c2(&blob_a), &cuerpo_c2(&blob_b)),
            xor(&s2_a, &s2_b),
            "el XOR de las capas 2 no es el de las S2: la máscara NO se canceló \
             (o el keystream cambió con el id)"
        );

        // LA CONSECUENCIA, para que se lea el desastre y no solo el álgebra:
        // combinando las DOS capas se recupera P ⊕ P' desde el cable, exactamente
        // como sin máscara. (c1 aporta S1⊕S1', c2 aporta S2⊕S2'; su XOR es P⊕P'.)
        let recuperado = xor(
            &xor(&cuerpo_c1(&blob_a), &cuerpo_c1(&blob_b)),
            &xor(&cuerpo_c2(&blob_a), &cuerpo_c2(&blob_b)),
        );
        assert_eq!(
            recuperado,
            xor(&claro_a, &claro_b),
            "con id repetido no se recupera P⊕P' del cable: el álgebra del \
             comentario de aplicar_mascara ya no vale"
        );

        // CONTROL: con dos ids DISTINTOS la máscara (y el keystream) NO se
        // cancelan, así que ni la propiedad ni la recuperación se sostienen. Sin
        // este control, la prueba mediría la CLAIM equivocada: que la catástrofe
        // ocurre siempre, cuando ocurre SOLO al repetir id (la frescura salva).
        let id2 = [0x99u8; ID_LEN];
        let blob_c = armar(&m, &id2, &s1_b, &s2_b, b"contexto-B");
        assert_ne!(
            xor(&cuerpo_c2(&blob_a), &cuerpo_c2(&blob_c)),
            xor(&s2_a, &s2_b),
            "el control no discrimina: con ids DISTINTOS el XOR coincidió con el de S2"
        );
        let recuperado_control = xor(
            &xor(&cuerpo_c1(&blob_a), &cuerpo_c1(&blob_c)),
            &xor(&cuerpo_c2(&blob_a), &cuerpo_c2(&blob_c)),
        );
        assert_ne!(
            recuperado_control,
            xor(&claro_a, &claro_b),
            "el control no discrimina: con ids DISTINTOS se recuperó P⊕P' del cable"
        );
    }

    /// **LÍMITE CONGELADO — EL `aad` NO ENTRA EN LA DERIVACIÓN DE CLAVES, NONCES
    /// NI MÁSCARA.**
    ///
    /// No es un defecto que esta prueba arregle: es el límite que `cifrar`
    /// documenta en su aviso («El aad NO entra en la derivación … dos mensajes con
    /// el mismo id comparten K1,N1,K2,N2 y la máscara aunque sus aad sean
    /// distintos»). Las firmas lo confirman: `material`, `claves_aes`,
    /// `claves_chacha` y `aplicar_mascara` NO reciben `aad`; solo sale de
    /// `(master, id)`. Esta prueba lo fija a nivel de artefacto y se pondrá ROJA
    /// el día que alguien meta el `aad` en la derivación —que es lo que un lector
    /// espera de «contextos distintos, riesgos distintos», y aquí no es así.
    ///
    /// La consecuencia de seguridad: no apoyarse en el `aad` para separar
    /// contextos bajo un `master` de larga vida (para eso está
    /// `kdf::derive_subkey`, que es lo que hace `api`).
    #[test]
    fn el_aad_no_entra_en_la_derivacion_de_claves_ni_nonces() {
        let m = maestra();
        let id = [0x24u8; ID_LEN];

        // (1) DIRECTO: el material derivado depende SOLO de (master, id). Las
        //     funciones ni siquiera reciben `aad`; esto fija la firma como
        //     propiedad y su determinismo.
        let (k1, n1) = claves_aes(&m, &id);
        let (k2, n2) = claves_chacha(&m, &id);
        let (k1b, n1b) = claves_aes(&m, &id);
        let (k2b, n2b) = claves_chacha(&m, &id);
        assert_eq!(k1.as_ref() as &[u8], k1b.as_ref() as &[u8], "K1 no es función de (master,id)");
        assert_eq!(n1, n1b, "N1 no es función de (master,id)");
        assert_eq!(k2.as_ref() as &[u8], k2b.as_ref() as &[u8], "K2 no es función de (master,id)");
        assert_eq!(n2, n2b, "N2 no es función de (master,id)");
        // La máscara, igual: solo (master, id).
        let mut ma = vec![0u8; 96];
        let mut mb = vec![0u8; 96];
        aplicar_mascara(&m, &id, &mut ma);
        aplicar_mascara(&m, &id, &mut mb);
        assert_eq!(ma, mb, "la máscara no es función de (master,id)");

        // (2) LA CONSECUENCIA, medida sobre el ARTEFACTO. Mismo id, mismo (s1,s2),
        //     `aad` DISTINTO ⇒ los CUERPOS cifrados de las dos capas son idénticos
        //     byte a byte (mismo keystream, misma máscara). Si el `aad` entrara en
        //     la derivación, el keystream cambiaría y los cuerpos diferirían.
        let s1 = vec_s1(48);
        let claro: Vec<u8> = (0..48).map(|i| i as u8).collect();
        let s2 = vec_s2(&claro);
        let blob_x = armar(&m, &id, &s1, &s2, b"contexto-X");
        let blob_y = armar(&m, &id, &s1, &s2, b"contexto-Y-mas-largo");
        assert_eq!(
            cuerpo_c1(&blob_x),
            cuerpo_c1(&blob_y),
            "el cuerpo de la capa AES cambió con el aad: el aad entró en la derivación"
        );
        assert_eq!(
            cuerpo_c2(&blob_x),
            cuerpo_c2(&blob_y),
            "el cuerpo de la capa XChaCha cambió con el aad: el aad entró en la derivación"
        );

        // CONTROL A — el aad SÍ se usa en ALGÚN sitio (los tags lo comen): sin
        // esto, «los cuerpos son iguales» pasaría igual con un cifrado que ignore
        // el aad por completo, y no habríamos medido nada sobre el aad.
        assert_ne!(
            tag_c2(&blob_x),
            tag_c2(&blob_y),
            "los tags coinciden pese al aad distinto: el aad no llega ni al AEAD, \
             el control no discrimina"
        );

        // CONTROL B — el id SÍ entra en la derivación: con un id DISTINTO los
        // cuerpos YA NO coinciden. Sin esto, «los cuerpos son iguales» pasaría con
        // un cifrado que ignore también el id (keystream constante).
        let blob_z = armar(&m, &[0x77u8; ID_LEN], &s1, &s2, b"contexto-X");
        assert_ne!(
            cuerpo_c2(&blob_x),
            cuerpo_c2(&blob_z),
            "con id distinto los cuerpos coinciden: el keystream no depende del id, \
             el control no discrimina"
        );
    }
}
