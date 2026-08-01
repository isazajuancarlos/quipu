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
//! ## Por qué el relleno sale del CSPRNG y no de un keystream
//!
//! Si el relleno saliera de cifrar ceros con una clave derivada, existiría una
//! clave que lo «explica» — y esa es precisamente la prueba que no puede existir.
//! Sale de [`crate::aleatorio`], que falla ruidosamente si no hay entropía.

use crate::aleatorio;
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
    pub const fn de_laboratorio(nombre: &'static str, params: KdfParams) -> Perfil {
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
/// El señuelo y el oculto pueden compartir contraseña sin peligro —cada región
/// deriva su clave con una etiqueta de dominio distinta—, pero no tiene sentido
/// hacerlo: entregar esa contraseña entrega los dos.
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

    let (r_senuelo, r_oculto) = tramos(tamano_total);
    let mut fuera = vec![0u8; tamano_total];

    // Todo el contenedor nace siendo azar. Lo que no se cifre encima se queda
    // así, que es el requisito 2 de #118: el resto se rellena SIEMPRE con azar,
    // haya o no volumen oculto.
    aleatorio::llenar(&mut fuera).map_err(|e| NegacionError::SinEntropia(e.to_string()))?;
    let salt: [u8; kdf::SALT_LEN] = fuera[..kdf::SALT_LEN]
        .try_into()
        .expect("el salt mide SALT_LEN");

    // Señuelo.
    let maestra = kdf::derive_master_key(clave_senuelo, &salt, b"", &perfil.params);
    let (clave, nonce) = claves_de_region(&maestra, INFO_SENUELO);
    let claro = claro_de_region(senuelo, r_senuelo.len() - TAG, Volumen::Senuelo)?;
    let cifrado = cipher::encrypt(&clave, &nonce, &claro, &salt);
    debug_assert_eq!(cifrado.len(), r_senuelo.len());
    fuera[r_senuelo].copy_from_slice(&cifrado);

    // Oculto, si lo hay. Si no lo hay, su región se queda con el azar de arriba:
    // esa es toda la diferencia, y es indistinguible por construcción.
    if let Some((datos, clave_oculta)) = oculto {
        let maestra = kdf::derive_master_key(clave_oculta, &salt, b"", &perfil.params);
        let (clave, nonce) = claves_de_region(&maestra, INFO_OCULTO);
        let claro = claro_de_region(datos, r_oculto.len() - TAG, Volumen::Oculto)?;
        let cifrado = cipher::encrypt(&clave, &nonce, &claro, &salt);
        debug_assert_eq!(cifrado.len(), r_oculto.len());
        fuera[r_oculto].copy_from_slice(&cifrado);
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
    let maestra = kdf::derive_master_key(contrasena, &salt, b"", &perfil.params);

    let (k_s, n_s) = claves_de_region(&maestra, INFO_SENUELO);
    let (k_o, n_o) = claves_de_region(&maestra, INFO_OCULTO);
    let abre_senuelo = cipher::decrypt(&k_s, &n_s, &contenedor[r_senuelo], &salt).ok();
    let abre_oculto = cipher::decrypt(&k_o, &n_o, &contenedor[r_oculto], &salt).ok();

    // El oculto manda si los dos abrieran: solo puede pasar si se usó la misma
    // contraseña para ambos, y en ese caso lo que el usuario quiere es lo suyo.
    for (volumen, claro) in [
        (Volumen::Oculto, abre_oculto),
        (Volumen::Senuelo, abre_senuelo),
    ] {
        if let Some(claro) = claro
            && let Ok(datos) = prelayers::unpad(&claro)
        {
            return Some(Apertura { volumen, datos });
        }
    }
    None
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
        None => Perfil::conocidos()
            .iter()
            .find_map(|p| intentar(contenedor, contrasena, *p))
            .ok_or(NegacionError::NoAbre),
    }
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

    #[test]
    fn misma_contrasena_para_los_dos_no_reutiliza_keystream() {
        // Cada región deriva con su propia etiqueta de dominio, así que compartir
        // contraseña es inútil pero no es catastrófico. Si algún día las
        // etiquetas se unificaran por error, esta prueba lo caza.
        let c = crear(
            S,
            b"senuelo",
            "misma",
            Some((b"oculto".as_slice(), "misma")),
            barato(),
        )
        .unwrap();
        let (rs, ro) = tramos(S);
        let n = rs.len().min(ro.len());
        assert_ne!(
            c[rs.start..rs.start + n],
            c[ro.start..ro.start + n],
            "las dos regiones no pueden salir iguales"
        );
        // Y con esa contraseña abre el oculto, que es lo que el usuario querría.
        assert_eq!(
            abrir(&c, "misma", Some(barato())).unwrap().volumen,
            Volumen::Oculto
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
