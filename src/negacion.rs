// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Contenedor con negación: un archivo, dos contraseñas, ninguna prueba.
//!
//! Implementa `docs/DISENO_NEGACION.md`. El contenedor guarda un **señuelo**
//! (que se entrega bajo coacción) y, opcionalmente, un **volumen oculto**. Nada
//! dentro del archivo dice si el segundo existe.
//!
//! # El límite, y va aquí porque quien lo use puede depender de entenderlo
//!
//! **La negación protege contra la PRUEBA, no contra la SOSPECHA de quien ya
//! decidió sospechar.** Ante coacción física esa distinción puede no valer nada.
//! Esto NO es «cifrado indetectable».
//!
//! Y el límite del modelo de amenaza, que es operativo: el adversario ve el
//! contenedor **una vez**. Quien guarde versiones sucesivas del mismo contenedor
//! en un respaldo —o lo sincronice a la nube— **pierde la negación**, porque
//! comparar dos instantáneas delata qué región cambió.
//!
//! # Formato
//!
//! ```text
//! [ 0 .. 16 )        salt, del CSPRNG
//! [ 16 .. 16+D )     región del SEÑUELO — AEAD sobre toda la región
//! [ 16+D .. S )      región del OCULTO  — AEAD sobre toda la región, o azar puro
//! ```
//!
//! `S` lo declara el usuario y no se deriva del contenido (requisito 1 de #118:
//! si el tamaño se ajustara al señuelo, cualquier hueco delataría). `D` es la
//! mitad del cuerpo, fija por el formato: **no hay ningún campo que la diga**.
//!
//! ## Tres decisiones que se apartan del boceto del diseño, y por qué
//!
//! 1. **No hay «cabecera cifrada» aparte.** El §4 la dibujaba para llevar la
//!    longitud del señuelo. No hace falta: si el AEAD cubre la región ENTERA, la
//!    longitud viaja dentro del texto en claro (prefijo de Padmé) y el
//!    ciphertext mide siempre lo mismo. Menos piezas, y ninguna fuera del cifrado
//!    — que es exactamente lo que pide el frente de la sospecha.
//!
//! 2. **Las regiones son fijas, no derivadas de la contraseña.** El §4 hablaba de
//!    un «desplazamiento distinto» para el oculto. No aporta: el propio diseño
//!    argumenta que localizar una región NO es fuga, porque el relleno posterior
//!    es azar exista o no el oculto. Derivar el desplazamiento sí añade un modo
//!    de fallo real —solapar con la región que autentica el AEAD del señuelo, que
//!    el §4 prohíbe— a cambio de nada. Simple y profundo antes que complejo y
//!    superficial.
//!
//! 3. **El señuelo es obligatorio** (propuesta del §9.2, tomada). Un contenedor
//!    que abierto con la contraseña entregada muestra *nada* es peor que uno con
//!    un señuelo creíble: «no tengo nada ahí» no es una respuesta que salve a
//!    nadie.
//!
//! ## LA NEGACIÓN DEPENDE DE QUE EL AEAD **NO** COMPROMETA LA CLAVE
//!
//! Contraintuitivo, y por eso está escrito: es la clase de propiedad que un
//! refactor bienintencionado destruye. XChaCha20-Poly1305 **no es
//! key-committing**: existe un ciphertext que valida bajo dos claves distintas.
//! En casi cualquier otro contexto eso es un defecto que hay que tapar (CTX,
//! Bellare-Hoang) — **aquí es requisito**. Un compromiso de clave sería
//! exactamente el campo que dice «esta región abrió con ESTA clave», o sea el
//! campo que todo el formato existe para no tener.
//!
//! Si algún día alguien propone «endurecer» este módulo con un AEAD que
//! comprometa la clave, la respuesta es NO, y esta es la razón.
//!
//! ## EL INVARIANTE OPERATIVO: `abrir` NO SE EXPONE COMO SERVICIO
//!
//! El no-commitment es seguro aquí **solo porque no existe un oráculo de
//! partición** (Len–Grubbs–Ristenpart, 2021): nadie descifra, de forma repetida
//! y adaptativa, contenedores que le suministra un atacante, revelando si
//! abrieron. Esto es un volumen personal, no un servicio.
//!
//! **El día que `abrir` se ofrezca como endpoint —recibe un blob y una
//! contraseña, responde si abrió— ese oráculo nace**, y con él el ataque: un
//! contenedor fabricado cuya región valide bajo un conjunto elegido de
//! contraseñas biseca el espacio de búsqueda en cada consulta. La defensa no es
//! parchear la primitiva: es no crear el oráculo.
//!
//! ## Por qué el relleno sale del CSPRNG y no de un keystream
//!
//! Si el relleno saliera de cifrar ceros con una clave derivada, existiría una
//! clave que lo «explica» — y esa es precisamente la prueba que no puede existir.
//! Sale de [`crate::aleatorio`], que falla ruidosamente si no hay entropía.

use crate::aleatorio;
use crate::antihacker;
use crate::cipher;
use crate::kdf::{self, KdfParams};
use quipu_nucleo::prelayers;

/// Longitud del tag de Poly1305. La prueba `el_tag_mide_lo_que_creemos` lo ata:
/// si el AEAD cambiara, el cálculo de tamaños se equivocaría en silencio.
const TAG: usize = 16;

/// Etiqueta de dominio de la región del señuelo (HKDF).
const INFO_SENUELO: &[u8] = b"quipu/negacion/v1/senuelo";
/// Etiqueta de dominio de la región oculta (HKDF).
const INFO_OCULTO: &[u8] = b"quipu/negacion/v1/oculto";
/// Sufijo para derivar el nonce de cada región.
const INFO_NONCE: &[u8] = b"/nonce";

/// Tamaño total mínimo de un contenedor.
///
/// No es un límite técnico —bastarían ~64 bytes— sino de honestidad: un
/// contenedor diminuto no tiene sitio donde esconder nada y daría una sensación
/// de negación que no existe.
pub const TAMANO_MINIMO: usize = 1024;

/// El tamaño canónico igual o mayor que `minimo`: la siguiente potencia de dos,
/// nunca por debajo de [`TAMANO_MINIMO`].
///
/// # Por qué existe, y por qué es la última fuga del formato
///
/// El contenedor mide y parece lo mismo con volumen oculto y sin él — **para un
/// tamaño fijo**. Lo que queda fuera del formato es la ELECCIÓN de ese tamaño, y
/// esa la hace el llamante: un contenedor de 50 MB «para la lista de la compra»
/// delata operativamente sin que ningún byte tenga la culpa. Ningún relleno
/// arregla eso; lo único que lo acota es que todo el mundo elija entre los
/// MISMOS pocos valores.
///
/// # Por qué potencias de dos y NO Padmé, que estaba a mano
///
/// `prelayers::pad` implementa Padmé y era la respuesta obvia — hasta medirla.
/// En el rango de 1 KiB a 1 GiB:
///
/// | | sobrecoste peor | tamaños distintos |
/// |---|---|---|
/// | Padmé | 5,73 % | **496** |
/// | potencias de dos | 100 % | **21** |
///
/// Padmé está diseñado para ocultar una longitud **pagando poco relleno**, y
/// optimiza justo la variable que aquí no cuesta nada: en este formato el
/// espacio sobrante **no es desperdicio, es el diseño** —se llena de azar del
/// CSPRNG haya o no volumen oculto—. Lo único que importa es cuánta información
/// lleva la elección del tamaño, y 496 valores distintos la llevan casi entera:
/// con Padmé el tamaño del archivo revela el del contenido con un 6 % de error.
///
/// Con potencias de dos, el conjunto observable son 21 valores en seis órdenes
/// de magnitud, y saber el tamaño solo sitúa el contenido dentro de un factor 2.
///
/// # No se impone, y es deliberado
///
/// [`crear`] acepta cualquier tamaño ≥ [`TAMANO_MINIMO`]. Forzar la escalera
/// rompería a quien necesite un tamaño exacto por una razón legítima —un campo
/// de formulario, un soporte de capacidad fija—, y la prueba de si una
/// restricción está bien puesta es justo esa. Lo que sí se hace es decirlo aquí
/// y en [`crear`]: **fuera de la escalera vive la fuga que queda**.
pub const fn tamano_canonico(minimo: usize) -> usize {
    let m = if minimo < TAMANO_MINIMO {
        TAMANO_MINIMO
    } else {
        minimo
    };
    if m.is_power_of_two() {
        m
    } else {
        m.next_power_of_two()
    }
}

/// `true` si `tamano` está en la escalera de [`tamano_canonico`].
///
/// Sirve para que una herramienta sobre esta librería pueda avisar —no
/// rechazar— cuando alguien sale de la escalera.
pub const fn es_canonico(tamano: usize) -> bool {
    tamano >= TAMANO_MINIMO && tamano.is_power_of_two()
}

/// Errores del contenedor con negación.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegacionError {
    /// El tamaño declarado no llega al mínimo.
    TamanoInsuficiente {
        /// Lo que se pidió.
        dado: usize,
        /// Lo que hace falta.
        minimo: usize,
    },
    /// Los datos no caben en su región con el tamaño total declarado.
    NoCabe {
        /// Qué volumen no cabe.
        volumen: Volumen,
        /// Bytes disponibles en la región.
        disponible: usize,
        /// Bytes que harían falta.
        necesario: usize,
    },
    /// El señuelo está vacío. Es deliberado: ver el §9.2 del diseño.
    SenueloVacio,
    /// El señuelo y el oculto llevan la MISMA contraseña.
    ///
    /// Se rechaza porque destruye la única promesa del módulo: bajo coacción, el
    /// usuario entregaría la clave que abre el volumen verdadero. Ningún uso
    /// legítimo la necesita.
    MismaContrasena,
    /// El contenedor es más corto que el mínimo: no puede serlo.
    ContenedorCorto,
    /// Ninguna región abrió con esa contraseña. **No dice cuál falló**, y no es
    /// por comodidad: distinguir «el señuelo no abrió» de «el oculto no abrió»
    /// sería el campo que todo el formato existe para no tener.
    NoAbre,
    /// El CSPRNG no pudo entregar entropía. No se sustituye por nada.
    SinEntropia(String),
}

impl core::fmt::Display for NegacionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TamanoInsuficiente { dado, minimo } => write!(
                f,
                "el tamaño declarado ({dado} B) no llega al mínimo de {minimo} B"
            ),
            Self::NoCabe {
                volumen,
                disponible,
                necesario,
            } => write!(
                f,
                "el {volumen} necesita {necesario} B y su región solo tiene {disponible} B: \
                 declara un contenedor más grande"
            ),
            Self::MismaContrasena => write!(
                f,
                "el señuelo y el volumen oculto llevan la misma contraseña —comparadas \
                 como las compara el KDF, o sea tras normalizar NFKC, así que pueden \
                 diferir byte a byte y seguir siendo la misma—: entregarla bajo coacción \
                 entregaría el volumen verdadero, que es justo lo que este formato existe \
                 para evitar"
            ),
            Self::SenueloVacio => write!(
                f,
                "el señuelo no puede ir vacío: un contenedor que abierto con la contraseña \
                 entregada no muestra nada es peor que uno con un señuelo creíble"
            ),
            Self::ContenedorCorto => write!(f, "el contenedor es más corto que el mínimo"),
            Self::NoAbre => write!(f, "ninguna región abrió con esa contraseña"),
            Self::SinEntropia(e) => write!(f, "sin entropía para el relleno: {e}"),
        }
    }
}

impl std::error::Error for NegacionError {}

/// Cuál de los dos volúmenes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Volumen {
    /// El que se entrega bajo coacción.
    Senuelo,
    /// El verdadero.
    Oculto,
}

impl core::fmt::Display for Volumen {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Senuelo => write!(f, "señuelo"),
            Self::Oculto => write!(f, "volumen oculto"),
        }
    }
}

/// Perfil de coste: los parámetros del KDF, que **NO viajan en el contenedor**.
///
/// Es la salida (a) del §5, decidida por Juan el 2026-07-31. Gana dos cosas: la
/// cabecera deja de tener 12 bytes de enteros pequeños que la delatan, y —esto no
/// estaba en la cuenta— **desaparece una entrada controlada por el adversario**,
/// porque hoy `api.rs` toma el coste de Argon2id de la cabecera que aporta quien
/// entrega el archivo, y el KDF corre antes de que el AEAD valide nada.
///
/// El precio, que el §5.2 midió y conviene tener presente antes de añadir el
/// segundo: como la versión de formato tampoco puede ir en claro, **cada perfil
/// que se publique añade para siempre una pasada de Argon2id a toda apertura que
/// no diga cuál usar**. Por eso los parámetros se eligen una vez y conservadores,
/// y por eso [`abrir`] acepta el perfil como pista fuera de banda (§5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Perfil {
    /// Nombre estable, para la interfaz de usuario y los mensajes.
    pub nombre: &'static str,
    params: KdfParams,
}

impl Perfil {
    /// Perfil v1: 256 MiB, 4 iteraciones, 1 hilo.
    ///
    /// Deliberadamente por encima del coste interactivo por defecto de Quipu
    /// (64 MiB / 3): subirlo después es caro —lo paga el usuario legítimo en
    /// cada apertura, para siempre— así que se elige alto una vez. 256 MiB es el
    /// techo que ya acota [`KdfParams::MAX_MEM_KIB`], y aquí no hay riesgo de
    /// amplificación porque el coste no lo fija el archivo.
    pub const V1: Perfil = Perfil {
        nombre: "v1",
        params: KdfParams {
            mem_kib: 262_144,
            iterations: 4,
            parallelism: 1,
        },
    };

    /// Los perfiles conocidos, **del más nuevo al más viejo**: es el orden en que
    /// [`abrir`] los prueba cuando no se le da ninguno, para que el caso común
    /// —un contenedor reciente— cueste una sola pasada.
    pub const fn conocidos() -> &'static [Perfil] {
        &[Perfil::V1]
    }

    /// Los parámetros de Argon2id de este perfil.
    pub fn params(&self) -> KdfParams {
        self.params
    }

    /// Un perfil arbitrario, **solo para el laboratorio**.
    ///
    /// El banco del §8 necesita generar cientos de contenedores, y con el coste
    /// real de [`Perfil::V1`] (256 MiB) eso son horas. No es público a secas a
    /// propósito: cada perfil que se publique añade para siempre una pasada de
    /// Argon2id a toda apertura sin pista (§5.2), así que crear perfiles no debe
    /// ser cómodo. La feature `lab` nunca viaja en un build publicado.
    #[cfg(feature = "lab")]
    pub fn de_laboratorio(nombre: &'static str, params: KdfParams) -> Perfil {
        // `is_sane()` existe justamente para esto y no se estaba llamando: unos
        // parámetros con `parallelism: 0` llegaban al `expect("parámetros
        // Argon2id válidos")` de `kdf.rs` y entraban en pánico. Los pone el
        // llamante y no un atacante, pero un perfil de laboratorio que tumba el
        // banco en vez de rechazarse es ruido en el sitio donde se mide.
        assert!(
            params.is_sane(),
            "perfil de laboratorio «{nombre}» con parámetros fuera de rango: \
             mem_kib={}, iterations={}, parallelism={}",
            params.mem_kib,
            params.iterations,
            params.parallelism
        );
        Perfil { nombre, params }
    }
}

/// El resultado de abrir: qué volumen respondió y qué había dentro.
///
/// Que esto diga cuál abrió no filtra nada: vive en la memoria de quien ya tiene
/// la contraseña, no en el archivo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Apertura {
    /// Cuál de los dos volúmenes abrió.
    pub volumen: Volumen,
    /// Su contenido.
    pub datos: Vec<u8>,
}

/// Los dos tramos del cuerpo, calculados solo con el tamaño total.
///
/// Ningún campo del contenedor participa: por eso no hay nada que manipular.
fn tramos(total: usize) -> (core::ops::Range<usize>, core::ops::Range<usize>) {
    let cuerpo = total - kdf::SALT_LEN;
    let d = cuerpo / 2;
    let ini = kdf::SALT_LEN;
    (ini..ini + d, ini + d..total)
}

/// Deriva (clave, nonce) de una región. Una sola pasada de Argon2id por
/// contraseña; lo de después es HKDF y es gratis.
fn claves_de_region(
    maestra: &[u8; kdf::KEY_LEN],
    info: &[u8],
) -> ([u8; cipher::KEY_LEN], [u8; cipher::NONCE_LEN]) {
    let clave = kdf::derive_subkey(maestra, info);
    let mut nonce = [0u8; cipher::NONCE_LEN];
    let mut etiqueta = info.to_vec();
    etiqueta.extend_from_slice(INFO_NONCE);
    kdf::derive_stream(maestra, &etiqueta, &mut nonce);
    (clave, nonce)
}

/// El dato autenticado de las dos regiones: `salt ‖ tamaño_total`.
///
/// **El tamaño va DENTRO del AAD y no es adorno.** El corte entre las dos
/// regiones lo deriva [`tramos`] de la longitud del archivo, así que con solo el
/// salt autenticado un byte añadido al final movía la región del oculto sin
/// tocar la del señuelo: el señuelo seguía abriendo con toda normalidad —el
/// usuario recibe la señal «el archivo está bien»— mientras el volumen oculto
/// quedaba irrecuperable PARA SIEMPRE. Y `abrir` no podía avisar, porque
/// «oculto corrupto» y «no hay oculto» son el mismo `NoAbre` por diseño.
///
/// Con el tamaño autenticado, cualquier cambio de longitud rompe LAS DOS
/// regiones, y entonces sí hay señal: el señuelo tampoco abre.
fn dato_autenticado(salt: &[u8; kdf::SALT_LEN], tamano_total: usize) -> Vec<u8> {
    let mut aad = Vec::with_capacity(kdf::SALT_LEN + 8);
    aad.extend_from_slice(salt);
    aad.extend_from_slice(&(tamano_total as u64).to_be_bytes());
    aad
}

/// Prepara el texto en claro de una región: `Padmé(datos)` y relleno del CSPRNG
/// hasta ocupar la región entera menos el tag.
///
/// El relleno interior es azar y no ceros por la misma razón de siempre: si un
/// día el AEAD se cambiara por uno sin autenticación, unos ceros al final serían
/// un oráculo de «esta clave es la buena». Cuesta lo mismo y cierra la puerta.
fn claro_de_region(datos: &[u8], largo_claro: usize, volumen: Volumen) -> Result<Vec<u8>, NegacionError> {
    let mut claro = prelayers::pad(datos);
    if claro.len() > largo_claro {
        return Err(NegacionError::NoCabe {
            volumen,
            disponible: largo_claro,
            necesario: claro.len(),
        });
    }
    let desde = claro.len();
    claro.resize(largo_claro, 0);
    aleatorio::llenar(&mut claro[desde..]).map_err(|e| NegacionError::SinEntropia(e.to_string()))?;
    Ok(claro)
}

/// Crea el contenedor.
///
/// `tamano_total` es el tamaño exacto del archivo resultante, **elegido por
/// quien lo crea** y no derivado del contenido. `oculto` es opcional, y el
/// contenedor mide y parece lo mismo con él y sin él.
///
/// **ESA ELECCIÓN ES LA ÚLTIMA FUGA DEL FORMATO**, y no la cubre ningún byte:
/// un contenedor de 50 MB «para la lista de la compra» delata operativamente.
/// Use [`tamano_canonico`] salvo que tenga un motivo concreto para no hacerlo;
/// ahí está el porqué, con los números.
///
/// **El señuelo y el oculto NO pueden compartir contraseña**, y se rechaza con
/// [`NegacionError::MismaContrasena`]. «Compartir» significa lo que significa
/// para el KDF —igualdad tras NFKC—, no igualdad byte a byte: dos cadenas
/// distintas en bytes pero equivalentes en NFKC derivan la misma maestra y por
/// tanto abren las dos regiones, que es el fallo que la regla evita.
///
/// Hasta el 2026-08-01 esto se aceptaba en silencio, con la nota de que «no
/// tiene sentido hacerlo». Aceptar en silencio lo que no tiene sentido es la
/// directiva 20 aplicada a un parámetro: la contraseña compartida **destruye la
/// única promesa del módulo**, porque bajo coacción el usuario entrega la clave
/// que abre el volumen verdadero. Y no hay ningún uso legítimo que la necesite,
/// que es la prueba que decide si una restricción está bien puesta.
pub fn crear(
    tamano_total: usize,
    senuelo: &[u8],
    clave_senuelo: &str,
    oculto: Option<(&[u8], &str)>,
    perfil: Perfil,
) -> Result<Vec<u8>, NegacionError> {
    if senuelo.is_empty() {
        return Err(NegacionError::SenueloVacio);
    }
    if tamano_total < TAMANO_MINIMO {
        return Err(NegacionError::TamanoInsuficiente {
            dado: tamano_total,
            minimo: TAMANO_MINIMO,
        });
    }

    // La contraseña compartida se rechaza ANTES de gastar un Argon2id. La
    // comparación va en tiempo constante por costumbre, no porque aquí haya un
    // secreto que proteger: las dos las trae el mismo llamante.
    //
    // SE COMPARA LO QUE COMPARA EL KDF, no los bytes crudos. `derive_master_key`
    // normaliza NFKC antes de derivar, así que dos cadenas distintas byte a byte
    // pero equivalentes en NFKC —una «á» precompuesta contra «a» más el acento
    // combinante, una ligadura, un dígito de compatibilidad— derivan LA MISMA
    // maestra. Comparando bytes, la guarda las dejaba pasar y el contenedor
    // nacía con las dos regiones bajo la misma clave; y como `intentar` da
    // prioridad al oculto cuando las dos abren, entregar el «señuelo» bajo
    // coacción devolvía el volumen verdadero. O sea, justo lo que esta guarda
    // existe para impedir, por el hueco entre lo que comprueba y lo que deriva.
    if let Some((_, clave_oculta)) = oculto {
        let mut a = kdf::normalizar(clave_senuelo).into_bytes();
        let mut b = kdf::normalizar(clave_oculta).into_bytes();
        let iguales = antihacker::ct_eq(&a, &b);
        antihacker::wipe(&mut a);
        antihacker::wipe(&mut b);
        if iguales {
            return Err(NegacionError::MismaContrasena);
        }
    }

    let (r_senuelo, r_oculto) = tramos(tamano_total);
    let mut fuera = vec![0u8; tamano_total];

    // Todo el contenedor nace siendo azar. Lo que no se cifre encima se queda
    // así, que es el requisito 2 de #118: el resto se rellena SIEMPRE con azar,
    // haya o no volumen oculto.
    aleatorio::llenar(&mut fuera).map_err(|e| NegacionError::SinEntropia(e.to_string()))?;
    let salt: [u8; kdf::SALT_LEN] = fuera[..kdf::SALT_LEN]
        .try_into()
        .expect("el salt mide SALT_LEN");

    let aad = dato_autenticado(&salt, tamano_total);

    // Señuelo.
    //
    // TODO LO SENSIBLE SE BORRA ANTES DE SOLTARLO, y aquí no es una formalidad:
    // el claro del volumen oculto y la maestra que lo abre, si quedan en el
    // swap o en un volcado, SON LA PRUEBA de que el segundo volumen existe —
    // que es exactamente lo que este módulo entero existe para que no exista.
    // El módulo hermano `api.rs` lleva la misma secuencia de borrados desde
    // siempre; esta ruta nació sin ellos.
    let mut maestra = kdf::derive_master_key(clave_senuelo, &salt, b"", &perfil.params);
    let (mut clave, nonce) = claves_de_region(&maestra, INFO_SENUELO);
    antihacker::wipe(&mut maestra);
    let mut claro = match claro_de_region(senuelo, r_senuelo.len() - TAG, Volumen::Senuelo) {
        Ok(c) => c,
        Err(e) => {
            antihacker::wipe(&mut clave);
            return Err(e);
        }
    };
    let cifrado = cipher::encrypt(&clave, &nonce, &claro, &aad);
    antihacker::wipe(&mut clave);
    antihacker::wipe(&mut claro);
    debug_assert_eq!(cifrado.len(), r_senuelo.len());
    fuera[r_senuelo].copy_from_slice(&cifrado);

    // Oculto, si lo hay. Si no lo hay, su región se queda con el azar de arriba:
    // esa es toda la diferencia, y es indistinguible por construcción.
    // SE DERIVA SIEMPRE LA SEGUNDA CLAVE, HAYA O NO VOLUMEN OCULTO.
    //
    // Sin esto, `crear` tardaba EXACTAMENTE EL DOBLE cuando había oculto —medido
    // con el perfil V1: 839 ms sin él, 1 659 ms con él, ratio 1,98— y gastaba dos
    // veces los 256 MiB de Argon2id. O sea que el reloj y el perfil de memoria
    // del proceso entregaban justo el único bit que este módulo entero existe
    // para ocultar.
    //
    // Lo halló una revisión independiente, y lo que lo convierte en defecto y no
    // en curiosidad es la ASIMETRÍA: el camino de LECTURA se cerró con enorme
    // cuidado y por escrito —`intentar` prueba siempre las dos regiones, `abrir`
    // recorre siempre todos los perfiles, con su banco de caso rojo—, y el de
    // ESCRITURA se quedó con un delator de 2× que no mencionaba ni un comentario.
    // Cerrar una puerta y dejar la otra no es media defensa: es ninguna.
    //
    // Cuando no hay oculto se deriva contra una contraseña ALEATORIA y se tira
    // el resultado. El coste es real —crear un contenedor solo con señuelo pasa
    // a costar lo mismo que uno con los dos— y es exactamente el precio que el
    // camino de lectura ya paga.
    //
    // EL ADVERSARIO al que esto le importa no es el que controla la máquina
    // (ese es N2/S7, fuera de alcance y ya vería el claro): es la telemetría de
    // tiempos y RSS que un agente de monitorización, una máquina corporativa o
    // una línea de tiempo forense recogen de rutina SIN ver jamás el contenido.
    let (datos_reales, clave_real, hay_oculto) = match oculto {
        Some((d, c)) => (d, c.to_string(), true),
        None => {
            // Contraseña de descarte: 32 bytes del CSPRNG en hexadecimal. No se
            // usa para nada y su claro nunca se escribe.
            let mut relleno = [0u8; 32];
            aleatorio::llenar(&mut relleno)
                .map_err(|e| NegacionError::SinEntropia(e.to_string()))?;
            let frase: String = relleno.iter().map(|b| format!("{b:02x}")).collect();
            (b"".as_slice(), frase, false)
        }
    };
    {
        let datos = datos_reales;
        let clave_oculta: &str = &clave_real;
        let mut maestra = kdf::derive_master_key(clave_oculta, &salt, b"", &perfil.params);
        let (mut clave, nonce) = claves_de_region(&maestra, INFO_OCULTO);
        antihacker::wipe(&mut maestra);
        let mut claro = match claro_de_region(datos, r_oculto.len() - TAG, Volumen::Oculto) {
            Ok(c) => c,
            Err(e) => {
                antihacker::wipe(&mut clave);
                return Err(e);
            }
        };
        let cifrado = cipher::encrypt(&clave, &nonce, &claro, &aad);
        antihacker::wipe(&mut clave);
        antihacker::wipe(&mut claro);
        debug_assert_eq!(cifrado.len(), r_oculto.len());
        // Y AQUÍ ESTÁ LA ÚNICA DIFERENCIA que queda entre los dos casos: sin
        // oculto, la región se deja con el azar del CSPRNG que ya tenía. Es una
        // copia de memoria de la que no se entera ningún reloj, frente a los
        // 256 MiB y el segundo de Argon2id que sí se enteraban.
        if hay_oculto {
            fuera[r_oculto].copy_from_slice(&cifrado);
        }
    }

    Ok(fuera)
}

/// Intenta las dos regiones con un perfil. **Siempre prueba las dos**, aunque la
/// primera abra, y por eso devuelve las dos respuestas antes de elegir.
///
/// Salir antes al acertar el señuelo haría que abrir el señuelo costara un AEAD
/// menos que abrir el oculto, y el §8.3 exige que el reloj no sea el campo que
/// dijimos que no existía.
fn intentar(contenedor: &[u8], contrasena: &str, perfil: Perfil) -> Option<Apertura> {
    let salt: [u8; kdf::SALT_LEN] = contenedor[..kdf::SALT_LEN]
        .try_into()
        .expect("ya se comprobó la longitud");
    let (r_senuelo, r_oculto) = tramos(contenedor.len());
    let aad = dato_autenticado(&salt, contenedor.len());
    let mut maestra = kdf::derive_master_key(contrasena, &salt, b"", &perfil.params);

    let (mut k_s, n_s) = claves_de_region(&maestra, INFO_SENUELO);
    let (mut k_o, n_o) = claves_de_region(&maestra, INFO_OCULTO);
    antihacker::wipe(&mut maestra);
    let mut abre_senuelo = cipher::decrypt(&k_s, &n_s, &contenedor[r_senuelo], &aad).ok();
    let mut abre_oculto = cipher::decrypt(&k_o, &n_o, &contenedor[r_oculto], &aad).ok();
    antihacker::wipe(&mut k_s);
    antihacker::wipe(&mut k_o);

    // El oculto manda si los dos abrieran: solo puede pasar si se usó la misma
    // contraseña para ambos, y en ese caso lo que el usuario quiere es lo suyo.
    let mut salida = None;
    for (volumen, claro) in [
        (Volumen::Oculto, &mut abre_oculto),
        (Volumen::Senuelo, &mut abre_senuelo),
    ] {
        if salida.is_none()
            && let Some(c) = claro.as_ref()
            && let Ok(datos) = prelayers::unpad(c)
        {
            salida = Some(Apertura { volumen, datos });
        }
    }
    // El claro con relleno se borra SIEMPRE, abra o no y por el camino que sea:
    // un `return` temprano dentro del bucle lo habría dejado en memoria justo
    // en el caso que importa, que es cuando el oculto abre.
    for c in [abre_senuelo.as_mut(), abre_oculto.as_mut()].into_iter().flatten() {
        antihacker::wipe(c);
    }
    salida
}

/// Abre el contenedor con una contraseña. Cuál de los dos volúmenes responde lo
/// decide la contraseña, no un argumento: pedirlo sería obligar a quien está
/// siendo coaccionado a teclear cuál quiere abrir.
///
/// `perfil` es la **pista fuera de banda** del §5.3: si se da, se prueba solo
/// ese y cuesta una pasada de Argon2id. Si no, se prueban los conocidos del más
/// nuevo al más viejo. La pista viaja en la cabeza del usuario o junto al
/// archivo, **nunca dentro**.
///
/// Sobre el tiempo: con un perfil dado, abrir el señuelo, abrir el oculto y
/// fallar cuestan lo mismo. Sin perfil y con varios publicados, una contraseña
/// equivocada los recorre todos y tarda más — pero eso distingue «acertó» de «no
/// acertó», que el adversario ya ve, y **no** distingue cuál de los dos volúmenes
/// abrió, que es lo que el formato promete.
pub fn abrir(
    contenedor: &[u8],
    contrasena: &str,
    perfil: Option<Perfil>,
) -> Result<Apertura, NegacionError> {
    if contenedor.len() < TAMANO_MINIMO {
        return Err(NegacionError::ContenedorCorto);
    }
    match perfil {
        Some(p) => intentar(contenedor, contrasena, p).ok_or(NegacionError::NoAbre),
        // SE PRUEBAN TODOS LOS PERFILES, SIEMPRE, aunque el primero abra.
        //
        // Antes esto era un `find_map`, que corta al acertar. Con un solo perfil
        // da igual; con dos, un contenedor del perfil nuevo costaría UNA pasada
        // de Argon2id y uno antiguo costaría N — **el reloj diría qué perfil
        // lleva el archivo**, y de ahí sale cuándo se creó. Eso es metadato, que
        // es exactamente lo que este formato existe para no tener.
        //
        // Es el mismo criterio que ya gobierna `intentar`, que prueba siempre
        // las dos regiones para que abrir el señuelo no cueste un AEAD menos que
        // abrir el oculto. Aplicarlo aquí y no allí habría sido cerrar una
        // puerta y dejar la otra.
        //
        // SE IMPLEMENTA AHORA Y NO CUANDO HAYA DOS: hacerlo después significa
        // que la primera versión con dos perfiles sale con la fuga puesta.
        None => abrir_con_perfiles(contenedor, contrasena, Perfil::conocidos())
            .ok_or(NegacionError::NoAbre),
    }
}

/// Prueba `perfiles` en orden y devuelve la primera apertura — **habiéndolos
/// probado TODOS**.
///
/// Existe aparte de [`abrir`] para que la propiedad sea comprobable: con un solo
/// perfil publicado, un banco sobre `abrir` no puede distinguir «recorre todos»
/// de «corta al primero». Aquí se le pueden pasar dos.
fn abrir_con_perfiles(contenedor: &[u8], contrasena: &str, perfiles: &[Perfil]) -> Option<Apertura> {
    let mut abierto = None;
    for p in perfiles {
        let r = intentar(contenedor, contrasena, *p);
        if abierto.is_none() {
            abierto = r;
        }
    }
    abierto
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Perfil barato: las pruebas no miden el coste de Argon2id, y con el V1
    /// real (256 MiB) la suite tardaría minutos. El formato es idéntico.
    fn barato() -> Perfil {
        Perfil {
            nombre: "prueba",
            params: KdfParams {
                mem_kib: 64,
                iterations: 1,
                parallelism: 1,
            },
        }
    }

    const S: usize = 4096;

    #[test]
    fn el_tag_mide_lo_que_creemos() {
        // Si el AEAD cambiara de tag, todos los cálculos de tamaño de este
        // módulo se equivocarían en silencio. Aquí se rompe ruidosamente.
        let c = cipher::encrypt(&[0u8; 32], &[0u8; 24], b"abc", b"");
        assert_eq!(c.len(), 3 + TAG);
    }

    #[test]
    fn el_senuelo_abre_con_su_contrasena() {
        let c = crear(S, b"declaracion de renta 2025", "entregable", None, barato()).unwrap();
        assert_eq!(c.len(), S);
        let a = abrir(&c, "entregable", Some(barato())).unwrap();
        assert_eq!(a.volumen, Volumen::Senuelo);
        assert_eq!(a.datos, b"declaracion de renta 2025");
    }

    #[test]
    fn el_oculto_abre_con_la_suya_y_el_senuelo_sigue_abriendo() {
        let c = crear(
            S,
            b"lista de la compra",
            "la que entrego",
            Some((b"las coordenadas de verdad".as_slice(), "la que no")),
            barato(),
        )
        .unwrap();

        let s = abrir(&c, "la que entrego", Some(barato())).unwrap();
        assert_eq!(s.volumen, Volumen::Senuelo);
        assert_eq!(s.datos, b"lista de la compra");

        let o = abrir(&c, "la que no", Some(barato())).unwrap();
        assert_eq!(o.volumen, Volumen::Oculto);
        assert_eq!(o.datos, b"las coordenadas de verdad");
    }

    #[test]
    fn una_contrasena_equivocada_no_dice_por_que() {
        let c = crear(S, b"senuelo", "buena", None, barato()).unwrap();
        assert_eq!(
            abrir(&c, "mala", Some(barato())).unwrap_err(),
            NegacionError::NoAbre
        );
    }

    #[test]
    fn con_y_sin_oculto_miden_exactamente_igual() {
        let sin = crear(S, b"senuelo", "a", None, barato()).unwrap();
        let con = crear(
            S,
            b"senuelo",
            "a",
            Some((b"secreto".as_slice(), "b")),
            barato(),
        )
        .unwrap();
        assert_eq!(sin.len(), con.len());
        // Y la región del señuelo NO cambia de tamaño por que haya oculto.
        let (rs, _) = tramos(S);
        assert_eq!(rs.len(), tramos(S).0.len());
        assert_eq!(sin.len(), S);
        assert_eq!(con.len(), S);
    }

    #[test]
    fn la_contrasena_del_senuelo_no_abre_el_oculto() {
        let c = crear(
            S,
            b"senuelo",
            "a",
            Some((b"secreto".as_slice(), "b")),
            barato(),
        )
        .unwrap();
        let a = abrir(&c, "a", Some(barato())).unwrap();
        assert_eq!(a.volumen, Volumen::Senuelo);
        assert_ne!(a.datos, b"secreto");
    }

    #[test]
    fn el_senuelo_vacio_se_rechaza_y_dice_por_que() {
        assert_eq!(
            crear(S, b"", "a", None, barato()).unwrap_err(),
            NegacionError::SenueloVacio
        );
    }

    #[test]
    fn un_tamano_por_debajo_del_minimo_se_rechaza() {
        let e = crear(64, b"x", "a", None, barato()).unwrap_err();
        assert!(matches!(e, NegacionError::TamanoInsuficiente { .. }));
    }

    #[test]
    fn lo_que_no_cabe_lo_dice_en_vez_de_recortar() {
        let grande = vec![7u8; S];
        let e = crear(S, &grande, "a", None, barato()).unwrap_err();
        match e {
            NegacionError::NoCabe {
                volumen,
                disponible,
                necesario,
            } => {
                assert_eq!(volumen, Volumen::Senuelo);
                assert!(necesario > disponible);
            }
            otro => panic!("se esperaba NoCabe, llegó {otro:?}"),
        }
    }

    #[test]
    fn el_oculto_que_no_cabe_no_deja_un_contenedor_a_medias() {
        let grande = vec![7u8; S];
        let e = crear(S, b"senuelo", "a", Some((grande.as_slice(), "b")), barato()).unwrap_err();
        assert!(matches!(
            e,
            NegacionError::NoCabe {
                volumen: Volumen::Oculto,
                ..
            }
        ));
    }

    #[test]
    fn sin_perfil_se_prueban_los_conocidos() {
        // Con el V1 real sería lentísimo, así que se comprueba la mecánica: un
        // contenedor hecho con un perfil que NO está en la lista no abre sin
        // pista, y sí abre con ella. Es la prueba de que la pista es necesaria
        // y suficiente, que es lo que dice el §5.3.
        let c = crear(S, b"senuelo", "a", None, barato()).unwrap();
        assert_eq!(
            abrir(&c, "a", None).unwrap_err(),
            NegacionError::NoAbre,
            "el perfil de prueba no está entre los conocidos: sin pista no debe abrir"
        );
        assert!(abrir(&c, "a", Some(barato())).is_ok());
    }

    #[test]
    fn dos_contenedores_del_mismo_tamano_no_comparten_ni_un_byte_de_salt() {
        let a = crear(S, b"x", "a", None, barato()).unwrap();
        let b = crear(S, b"x", "a", None, barato()).unwrap();
        assert_ne!(a[..kdf::SALT_LEN], b[..kdf::SALT_LEN]);
        assert_ne!(a, b, "mismo contenido y misma clave no pueden dar el mismo blob");
    }

    #[test]
    fn alterar_un_byte_cualquiera_impide_abrir() {
        let base = crear(S, b"senuelo", "a", None, barato()).unwrap();
        // Un byte de la región del señuelo: el AEAD tiene que verlo.
        let (rs, _) = tramos(S);
        let mut roto = base.clone();
        roto[rs.start + 3] ^= 0x01;
        assert_eq!(
            abrir(&roto, "a", Some(barato())).unwrap_err(),
            NegacionError::NoAbre
        );
        // Y un byte del salt: cambia la clave derivada.
        let mut roto = base;
        roto[0] ^= 0x01;
        assert_eq!(
            abrir(&roto, "a", Some(barato())).unwrap_err(),
            NegacionError::NoAbre
        );
    }

    /// LA CONTRASEÑA COMPARTIDA SE RECHAZA, no se acepta con una nota.
    ///
    /// Esta prueba decía antes que compartirla «es inútil pero no es
    /// catastrófico», y comprobaba que las dos regiones no salieran iguales.
    /// Eso era cierto y era lo de menos: con la misma contraseña, entregarla
    /// bajo coacción entrega el volumen verdadero — la única promesa del módulo,
    /// rota, y aceptada en silencio. Lo que se comprueba ahora es el rechazo.
    /// EL RELOJ TAMPOCO PUEDE DECIR SI SE ESTÁ CREANDO UN VOLUMEN OCULTO.
    ///
    /// Lo halló una revisión independiente y es la puerta hermana de la de
    /// abajo: `crear` tardaba EXACTAMENTE EL DOBLE con oculto que sin él
    /// —medido con el perfil V1: 839 ms contra 1 659 ms, ratio 1,98— porque el
    /// segundo Argon2id vivía dentro del `if let`. El camino de LECTURA se había
    /// cerrado con cuidado y el de ESCRITURA se quedó abierto.
    ///
    /// TRAE SU CONTROL DENTRO, y aquí hace falta más que en la otra: un umbral
    /// de tiempo suelto es una prueba intermitente. El control mide UNA y DOS
    /// derivaciones directas con los mismos parámetros y exige que la diferencia
    /// se vea. Si no se viera, el verde de abajo solo diría que el banco no
    /// distingue 2× a esta escala.
    #[cfg(feature = "lab")]
    #[test]
    fn el_reloj_no_delata_que_se_esta_creando_un_oculto() {
        use std::time::Instant;

        let p = Perfil::de_laboratorio(
            "lab-crear",
            KdfParams { mem_kib: 32 * 1024, iterations: 3, parallelism: 1 },
        );
        let medir = |f: &dyn Fn()| -> u128 {
            let mut m = u128::MAX;
            for _ in 0..3 {
                let t = Instant::now();
                f();
                m = m.min(t.elapsed().as_micros());
            }
            m
        };

        // CONTROL: ¿este banco distingue una derivación de dos, a esta escala?
        let sal = [7u8; kdf::SALT_LEN];
        let una = medir(&|| {
            let mut k = kdf::derive_master_key("a", &sal, b"", &p.params);
            antihacker::wipe(&mut k);
        });
        let dos = medir(&|| {
            let mut k1 = kdf::derive_master_key("a", &sal, b"", &p.params);
            let mut k2 = kdf::derive_master_key("b", &sal, b"", &p.params);
            antihacker::wipe(&mut k1);
            antihacker::wipe(&mut k2);
        });
        assert!(
            dos > una * 3 / 2,
            "el control no discrimina: una derivación dio {una} µs y dos {dos} µs. \
             A esta escala el banco no puede ver un 2×, así que el verde de abajo \
             no probaría nada"
        );

        // Y ahora lo que importa: crear con y sin oculto tiene que costar igual.
        let sin = medir(&|| {
            crear(S, b"la lista de la compra", "clave-senuelo", None, p).unwrap();
        });
        let con = medir(&|| {
            crear(
                S,
                b"la lista de la compra",
                "clave-senuelo",
                Some((b"el secreto de verdad".as_slice(), "otra-clave")),
                p,
            )
            .unwrap();
        });
        let (lento, rapido) = if sin > con { (sin, con) } else { (con, sin) };
        assert!(
            lento < rapido * 3 / 2,
            "crear sin oculto costó {sin} µs y con oculto {con} µs: el reloj \
             entrega el único bit que este módulo existe para ocultar"
        );
    }

    /// EL RELOJ NO PUEDE DECIR QUÉ PERFIL LLEVA EL CONTENEDOR.
    ///
    /// Con un solo perfil publicado esto es inerte, y por eso el banco fabrica
    /// dos de laboratorio: es la única forma de ver la propiedad ANTES de que
    /// exista el segundo perfil de verdad. Implementarla después significaría
    /// que la primera versión con dos perfiles sale con la fuga puesta.
    ///
    /// EL BANCO TRAE SU CASO ROJO DENTRO. Un umbral de tiempo suelto es una
    /// prueba intermitente esperando a fallar; en vez de eso se mide la MISMA
    /// carga por los dos caminos —el que recorre todos y un `find_map` que corta
    /// al primero— y se exige que el segundo SÍ muestre la diferencia. Si el
    /// caso rojo no se disparara, el verde de arriba no significaría nada.
    #[cfg(feature = "lab")]
    #[test]
    fn el_reloj_no_delata_que_perfil_usa_el_contenedor() {
        use std::time::Instant;

        // Dos perfiles distinguibles en coste, pero baratos: lo que se mide es
        // el NÚMERO de derivaciones, no lo caras que son.
        let a = Perfil::de_laboratorio(
            "lab-a",
            KdfParams { mem_kib: 8 * 1024, iterations: 3, parallelism: 1 },
        );
        let b = Perfil::de_laboratorio(
            "lab-b",
            KdfParams { mem_kib: 8 * 1024, iterations: 4, parallelism: 1 },
        );
        let todos = [a, b];

        let con_a = crear(S, b"senuelo", "clave-a", None, a).unwrap();
        let con_b = crear(S, b"senuelo", "clave-b", None, b).unwrap();

        // Se comprueba primero que cada uno abre con SU perfil, o el banco
        // estaría midiendo dos fallos.
        assert!(abrir_con_perfiles(&con_a, "clave-a", &todos).is_some());
        assert!(abrir_con_perfiles(&con_b, "clave-b", &todos).is_some());

        let medir = |f: &dyn Fn() -> bool| -> u128 {
            let mut mejor = u128::MAX;
            for _ in 0..3 {
                let t0 = Instant::now();
                assert!(f());
                mejor = mejor.min(t0.elapsed().as_micros());
            }
            mejor
        };

        // CAMINO BUENO: recorre todos.
        let t_a = medir(&|| abrir_con_perfiles(&con_a, "clave-a", &todos).is_some());
        let t_b = medir(&|| abrir_con_perfiles(&con_b, "clave-b", &todos).is_some());

        // CASO ROJO: el `find_map` que había antes, que corta al primero.
        let corta = |c: &[u8], p: &str| -> bool {
            todos.iter().any(|perfil| intentar(c, p, *perfil).is_some())
        };
        let r_a = medir(&|| corta(&con_a, "clave-a"));
        let r_b = medir(&|| corta(&con_b, "clave-b"));

        // El caso rojo TIENE que mostrar la diferencia, o el verde no vale.
        assert!(
            r_b > r_a * 3 / 2,
            "el caso rojo no discrimina: cortar al primer perfil dio {r_a} µs y \
             {r_b} µs, casi lo mismo. Sin esa diferencia, el verde de abajo no \
             prueba nada — puede que el banco no mida el número de derivaciones"
        );

        // Y el camino bueno tiene que ser PLANO.
        let (lento, rapido) = if t_a > t_b { (t_a, t_b) } else { (t_b, t_a) };
        assert!(
            lento < rapido * 3 / 2,
            "recorriendo TODOS los perfiles, abrir uno costó {t_a} µs y el otro \
             {t_b} µs: el reloj sigue diciendo qué perfil lleva el archivo"
        );
    }

    /// La escalera de tamaños canónicos: potencias de dos desde el mínimo.
    #[test]
    fn la_escalera_es_potencias_de_dos_y_no_baja_del_minimo() {
        assert_eq!(tamano_canonico(0), TAMANO_MINIMO);
        assert_eq!(tamano_canonico(1), TAMANO_MINIMO);
        assert_eq!(tamano_canonico(TAMANO_MINIMO), TAMANO_MINIMO);
        assert_eq!(tamano_canonico(TAMANO_MINIMO + 1), TAMANO_MINIMO * 2);
        assert_eq!(tamano_canonico(5000), 8192);
        assert_eq!(tamano_canonico(100_000), 131_072);

        // Idempotente: subir dos veces no mueve nada.
        for n in [1usize, 999, 1025, 5000, 100_000, 3_000_000] {
            let c = tamano_canonico(n);
            assert_eq!(tamano_canonico(c), c, "no es idempotente en {n}");
            assert!(c >= n.max(TAMANO_MINIMO), "se quedó corto en {n}");
            assert!(es_canonico(c), "{c} no se reconoce como canónico");
        }

        // Y discrimina: lo que NO está en la escalera se dice.
        for n in [0usize, 1, 999, 1023, 1025, 5000, 100_000] {
            assert!(!es_canonico(n), "{n} no debería contar como canónico");
        }
    }

    /// EL NÚMERO QUE DECIDIÓ LA ESCALERA, y por eso está en una prueba y no solo
    /// en un comentario: Padmé —que estaba a mano en el árbol— deja CIENTOS de
    /// tamaños distintos, y aquí lo único que cuenta es que sean pocos.
    #[test]
    fn la_escalera_deja_pocos_tamanos_observables() {
        let mut distintos = std::collections::HashSet::new();
        let mut n = TAMANO_MINIMO;
        while n < 1 << 30 {
            distintos.insert(tamano_canonico(n));
            n += 997; // paso primo, para no caer siempre en el mismo sitio
        }
        assert!(
            distintos.len() <= 32,
            "la escalera produce {} tamaños distintos entre 1 KiB y 1 GiB; si \
             pasan de unas pocas decenas, la elección del tamaño vuelve a llevar \
             casi toda la información y la escalera no sirve de nada",
            distintos.len()
        );
        // Y que no sea absurdamente gruesa tampoco.
        assert!(distintos.len() >= 15, "solo {} escalones", distintos.len());
    }

    #[test]
    fn la_misma_contrasena_para_los_dos_se_rechaza() {
        assert_eq!(
            crear(S, b"senuelo", "misma", Some((b"oculto".as_slice(), "misma")), barato())
                .unwrap_err(),
            NegacionError::MismaContrasena
        );

        // Y el gemelo, o la regla estaría rechazando lo legítimo: contraseñas
        // distintas sí pasan, y cada una abre LO SUYO.
        let c = crear(S, b"senuelo", "una", Some((b"oculto".as_slice(), "otra")), barato())
            .unwrap();
        assert_eq!(abrir(&c, "una", Some(barato())).unwrap().volumen, Volumen::Senuelo);
        assert_eq!(abrir(&c, "otra", Some(barato())).unwrap().volumen, Volumen::Oculto);

        // Ni siquiera prefijos: son cadenas distintas y las dos valen.
        assert!(crear(S, b"s", "clave", Some((b"o".as_slice(), "clave2")), barato()).is_ok());
    }

    /// «La misma contraseña» es la que el KDF trata como la misma, no la que
    /// tiene los mismos bytes.
    ///
    /// Esta prueba EXISTE PARA PONERSE ROJA si alguien devuelve la guarda a
    /// comparar `as_bytes()`: las tres parejas de abajo difieren byte a byte y
    /// las tres derivan la misma maestra, así que con la comparación cruda el
    /// contenedor nacía con las dos regiones bajo la misma clave y `abrir`
    /// devolvía el OCULTO al entregar el «señuelo» bajo coacción.
    #[test]
    fn equivalentes_en_nfkc_son_la_misma_contrasena() {
        // (precompuesta, descompuesta) — la pareja clásica de acentos.
        let parejas: [(&str, &str); 3] = [
            ("caf\u{e9}", "cafe\u{301}"),      // café: é  vs  e + ◌́
            ("\u{fb01}n", "fin"),              // ligadura ﬁ  vs  f + i
            ("clave\u{2075}", "clave5"),       // superíndice ⁵  vs  5
        ];

        for (a, b) in parejas {
            // La premisa, medida y no supuesta: son cadenas DISTINTAS…
            assert_ne!(a.as_bytes(), b.as_bytes(), "la pareja {a:?}/{b:?} ya era igual en bytes");

            // …y aun así el KDF deriva de las dos LA MISMA maestra. Si esto
            // dejara de ser cierto, la guarda de abajo sobraría y esta prueba
            // estaría midiendo otra cosa.
            let salt = [7u8; kdf::SALT_LEN];
            assert_eq!(
                kdf::derive_master_key(a, &salt, b"", &barato().params),
                kdf::derive_master_key(b, &salt, b"", &barato().params),
                "la pareja {a:?}/{b:?} no es NFKC-equivalente para el KDF"
            );

            // Luego `crear` tiene que rechazarlas, en los dos órdenes.
            //
            // Con `matches!` y no `unwrap_err()`: cuando esto se rompe, el valor
            // que hay es un contenedor de 4 KiB, y `unwrap_err` lo vuelca entero
            // en el panic. El mensaje corto se lee; cuatro mil bytes, no.
            for (x, y) in [(a, b), (b, a)] {
                let r = crear(S, b"senuelo", x, Some((b"oculto".as_slice(), y)), barato());
                assert!(
                    matches!(r, Err(NegacionError::MismaContrasena)),
                    "no rechazó {x:?} contra {y:?}: {}",
                    match r {
                        Ok(c) => format!("creó un contenedor de {} B", c.len()),
                        Err(e) => format!("falló con otro error: {e}"),
                    }
                );
            }
        }

        // EL GEMELO, que es lo que decide si la regla discrimina o solo aprieta
        // (directiva 21): dos frases que SÍ difieren tras NFKC se aceptan, y
        // cada una abre lo suyo. «café» y «cafe» se parecen a la vista y son
        // contraseñas distintas para el KDF; rechazarlas sería el falso
        // positivo que esta regla no puede permitirse.
        let c = crear(
            S,
            b"senuelo",
            "caf\u{e9}",
            Some((b"oculto".as_slice(), "cafe")),
            barato(),
        )
        .unwrap();
        assert_eq!(abrir(&c, "caf\u{e9}", Some(barato())).unwrap().volumen, Volumen::Senuelo);
        assert_eq!(abrir(&c, "cafe", Some(barato())).unwrap().volumen, Volumen::Oculto);
    }

    /// UN BYTE AÑADIDO NO PUEDE DESTRUIR EL OCULTO EN SILENCIO.
    ///
    /// El corte entre regiones lo deriva `tramos` de la longitud del archivo.
    /// Con solo el salt autenticado, añadir un byte movía la región del oculto
    /// SIN tocar la del señuelo: el señuelo seguía abriendo —«el archivo está
    /// bien»— mientras el oculto quedaba irrecuperable para siempre, y `abrir`
    /// no podía avisar porque «oculto corrupto» y «no hay oculto» son el mismo
    /// error por diseño. Con el tamaño dentro del AAD, se rompen LAS DOS y el
    /// usuario ve la señal.
    #[test]
    fn cambiar_el_tamano_rompe_tambien_el_senuelo_para_que_haya_senal() {
        let c = crear(S, b"senuelo", "una", Some((b"oculto".as_slice(), "otra")), barato())
            .unwrap();
        assert_eq!(abrir(&c, "una", Some(barato())).unwrap().volumen, Volumen::Senuelo);

        let mut mas_largo = c.clone();
        mas_largo.push(0x00);
        assert_eq!(
            abrir(&mas_largo, "una", Some(barato())).unwrap_err(),
            NegacionError::NoAbre,
            "el señuelo tiene que dejar de abrir: es la ÚNICA señal de que el \
             archivo se tocó, y sin ella el oculto se pierde en silencio"
        );
        assert_eq!(
            abrir(&mas_largo, "otra", Some(barato())).unwrap_err(),
            NegacionError::NoAbre
        );

        let mas_corto = &c[..c.len() - 1];
        assert_eq!(
            abrir(mas_corto, "una", Some(barato())).unwrap_err(),
            NegacionError::NoAbre
        );
    }

    #[test]
    fn el_maximo_que_cabe_cabe_de_verdad() {
        // El borde: justo lo que la región admite. Si el cálculo de tamaños
        // estuviera desplazado en un byte, aquí se ve.
        let (rs, _) = tramos(S);
        let largo_claro = rs.len() - TAG;
        // Padmé mete 8 bytes de prefijo y luego cuantiza; se busca el mayor
        // dato cuyo bloque acolchado quepa.
        let mut mayor = largo_claro - 8;
        while prelayers::pad(&vec![0u8; mayor]).len() > largo_claro {
            mayor -= 1;
        }
        let datos = vec![0xABu8; mayor];
        let c = crear(S, &datos, "a", None, barato()).unwrap();
        assert_eq!(abrir(&c, "a", Some(barato())).unwrap().datos, datos);
        // Y uno más ya no cabe.
        let mut demasiado = datos;
        demasiado.push(0);
        while prelayers::pad(&demasiado).len() <= largo_claro {
            demasiado.push(0);
        }
        assert!(matches!(
            crear(S, &demasiado, "a", None, barato()),
            Err(NegacionError::NoCabe { .. })
        ));
    }
}
