// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Contenedor: serializa/parsea la cabecera + el payload cifrado.
//!
//! Disposición (todo big-endian):
//!   magic(4) | version(1) | flags(1) | codebook_id(2) | codebook_hash_prefix(8)
//!   | salt(SALT) | nonce(NONCE) | kdf_mem_kib(4) | kdf_iterations(4) | kdf_parallelism(4)
//!   seguido de: padded_ciphertext+tag (variable)
//!
//! La cabecera completa se usa como Associated Data del AEAD: cualquier
//! alteración de versión/codebook_id/salt/nonce/params invalida el descifrado.
//!
//! # Por qué `SALT` y `NONCE` son parámetros
//!
//! Son las DOS únicas medidas del formato que dependen de la criptografía
//! elegida, y son justo las que divergen entre los perfiles de la familia:
//!
//! | perfil       | AEAD                | nonce            | salt |
//! |--------------|---------------------|------------------|------|
//! | `quipu`      | XChaCha20-Poly1305  | 24 B (192 bits)  | 16 B |
//! | `quipu-cnsa` | AES-256-GCM         | 12 B (96 bits)   | 16 B |
//!
//! El nonce de 96 bits de CNSA 2.0 obliga además a llevar CONTADOR, porque 96
//! bits no bastan para elegir nonces al azar sin riesgo de colisión — pero eso
//! es asunto del perfil, no del contenedor: aquí solo cambia cuántos bytes se
//! serializan.
//!
//! Se resuelve con genéricos constantes, no con un campo de longitud: el tamaño
//! queda fijado en tiempo de compilación, sin coste en ejecución y sin que un
//! blob pueda declarar una longitud que no le corresponde. Un perfil concreto se
//! fija con un alias y desaparece de la vista:
//!
//! ```
//! use quipu_nucleo::container::Header;
//! type CabeceraQuipu = Header<16, 24>;
//! assert_eq!(CabeceraQuipu::SIZE, 68);
//! ```

/// Bytes de cabecera que NO dependen del perfil criptográfico:
/// magic(4) + version(1) + flags(1) + codebook_id(2) + codebook_hash_prefix(8)
/// + kdf_mem_kib(4) + kdf_iterations(4) + kdf_parallelism(4).
const BYTES_FIJOS: usize = 28;

/// Desplazamiento donde empieza el salt (tras magic/version/flags/id/huella).
const INICIO_SALT: usize = 16;

/// Identificador de formato.
pub const MAGIC: [u8; 4] = *b"QUIP";
/// Versión de formato soportada.
pub const VERSION: u8 = 1;

/// Errores de parseo del contenedor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerError {
    /// El blob es más corto que una cabecera.
    TooShort,
    /// Los bytes mágicos no coinciden.
    BadMagic,
    /// Versión de formato no soportada.
    UnsupportedVersion(u8),
    /// El campo `flags` trae bits que esta versión no conoce.
    ///
    /// **Rechazar lo desconocido en vez de ignorarlo cierra una DEGRADACIÓN
    /// SILENCIOSA**, y es la razón entera de que este error exista. `flags` se
    /// escribe siempre a cero y nunca se leía. Si una versión futura empezara a
    /// usar un bit —«este contenedor usa el algoritmo X»—, un decodificador
    /// viejo que lo IGNORA descifraría el contenido con las reglas antiguas y
    /// devolvería algo mal interpretado **con el AEAD en verde**: la cabecera va
    /// como AAD, así que autentica igual sea cual sea el valor del campo.
    ///
    /// Es el mismo motivo por el que TLS trata las extensiones desconocidas de
    /// forma estricta. Un decodificador viejo tiene que NEGARSE, no adivinar.
    FlagsDesconocidos(u8),
}

/// Cabecera del contenedor (en claro, pero autenticada como AAD).
///
/// `SALT` y `NONCE` son las longitudes en bytes que fija el perfil
/// criptográfico. Ver el doc del módulo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header<const SALT: usize, const NONCE: usize> {
    pub version: u8,
    pub flags: u8,
    pub codebook_id: u16,
    pub codebook_hash_prefix: [u8; 8],
    pub salt: [u8; SALT],
    pub nonce: [u8; NONCE],
    pub kdf_mem_kib: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u32,
}

impl<const SALT: usize, const NONCE: usize> Header<SALT, NONCE> {
    /// Tamaño serializado de la cabecera, en bytes.
    pub const SIZE: usize = BYTES_FIJOS + SALT + NONCE;

    /// Serializa la cabecera. Estos bytes son además el AAD del AEAD.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(Self::SIZE);
        b.extend_from_slice(&MAGIC);
        b.push(self.version);
        b.push(self.flags);
        b.extend_from_slice(&self.codebook_id.to_be_bytes());
        b.extend_from_slice(&self.codebook_hash_prefix);
        b.extend_from_slice(&self.salt);
        b.extend_from_slice(&self.nonce);
        b.extend_from_slice(&self.kdf_mem_kib.to_be_bytes());
        b.extend_from_slice(&self.kdf_iterations.to_be_bytes());
        b.extend_from_slice(&self.kdf_parallelism.to_be_bytes());
        debug_assert_eq!(b.len(), Self::SIZE);
        b
    }
}

/// Serializa cabecera + ciphertext en un único blob.
pub fn serialize<const SALT: usize, const NONCE: usize>(
    header: &Header<SALT, NONCE>,
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut out = header.to_bytes();
    out.extend_from_slice(ciphertext);
    out
}

/// Parsea un blob en (cabecera, ciphertext). Valida magic y versión.
pub fn parse<const SALT: usize, const NONCE: usize>(
    blob: &[u8],
) -> Result<(Header<SALT, NONCE>, &[u8]), ContainerError> {
    let tamano = Header::<SALT, NONCE>::SIZE;
    if blob.len() < tamano {
        return Err(ContainerError::TooShort);
    }
    let (head, rest) = blob.split_at(tamano);

    if head[0..4] != MAGIC {
        return Err(ContainerError::BadMagic);
    }
    let version = head[4];
    if version != VERSION {
        return Err(ContainerError::UnsupportedVersion(version));
    }
    // `flags` es un campo RESERVADO: hoy vale cero y ninguna ruta lo escribe de
    // otra forma. Se valida en vez de ignorarse — ver `FlagsDesconocidos` para
    // el porqué, que es cerrar la degradación silenciosa y no la limpieza.
    if head[5] != 0 {
        return Err(ContainerError::FlagsDesconocidos(head[5]));
    }

    let fin_salt = INICIO_SALT + SALT;
    let fin_nonce = fin_salt + NONCE;
    let header = Header {
        version,
        flags: head[5],
        codebook_id: u16::from_be_bytes([head[6], head[7]]),
        codebook_hash_prefix: head[8..INICIO_SALT].try_into().expect("8 bytes"),
        salt: head[INICIO_SALT..fin_salt]
            .try_into()
            .expect("SALT bytes exactos"),
        nonce: head[fin_salt..fin_nonce]
            .try_into()
            .expect("NONCE bytes exactos"),
        kdf_mem_kib: u32::from_be_bytes(head[fin_nonce..fin_nonce + 4].try_into().expect("4 bytes")),
        kdf_iterations: u32::from_be_bytes(
            head[fin_nonce + 4..fin_nonce + 8]
                .try_into()
                .expect("4 bytes"),
        ),
        kdf_parallelism: u32::from_be_bytes(
            head[fin_nonce + 8..fin_nonce + 12]
                .try_into()
                .expect("4 bytes"),
        ),
    };
    Ok((header, rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// El perfil de `quipu`: salt de 16, nonce extendido de 24 (XChaCha20).
    type Quipu = Header<16, 24>;
    /// El perfil que usará `quipu-cnsa`: nonce de 96 bits (AES-256-GCM).
    type Cnsa = Header<16, 12>;

    fn sample_header() -> Quipu {
        Header {
            version: VERSION,
            flags: 0,
            codebook_id: 0x0102,
            codebook_hash_prefix: [1, 2, 3, 4, 5, 6, 7, 8],
            salt: [9u8; 16],
            nonce: [7u8; 24],
            kdf_mem_kib: 65536,
            kdf_iterations: 3,
            kdf_parallelism: 1,
        }
    }

    #[test]
    fn round_trips_header_and_ciphertext() {
        let h = sample_header();
        let ct = vec![10u8, 20, 30, 40, 50];
        let blob = serialize(&h, &ct);
        let (parsed, parsed_ct) = parse::<16, 24>(&blob).unwrap();
        assert_eq!(parsed, h);
        assert_eq!(parsed_ct, &ct[..]);
    }

    #[test]
    fn header_serializes_to_fixed_size() {
        assert_eq!(sample_header().to_bytes().len(), Quipu::SIZE);
    }

    #[test]
    fn rejects_too_short_blob() {
        let short = [0u8; Quipu::SIZE - 1];
        assert_eq!(parse::<16, 24>(&short), Err(ContainerError::TooShort));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut blob = serialize(&sample_header(), b"ct");
        blob[0] = b'X';
        assert_eq!(parse::<16, 24>(&blob), Err(ContainerError::BadMagic));
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut blob = serialize(&sample_header(), b"ct");
        blob[4] = 99;
        assert_eq!(
            parse::<16, 24>(&blob),
            Err(ContainerError::UnsupportedVersion(99))
        );
    }

    /// El formato de `quipu` NO se ha movido: 68 bytes, como en v1. Si este
    /// número cambia, todo blob ya escrito deja de leerse.
    #[test]
    fn el_perfil_de_quipu_sigue_midiendo_68() {
        assert_eq!(Quipu::SIZE, 68);
    }

    /// La parametrización sirve de algo: el perfil CNSA mide distinto porque su
    /// nonce es de 96 bits. Sin esta prueba, los genéricos podrían estar ahí sin
    /// que nadie note que en realidad no discriminan.
    #[test]
    fn el_perfil_cnsa_mide_56_por_su_nonce_de_96_bits() {
        assert_eq!(Cnsa::SIZE, 56);
        assert_eq!(Quipu::SIZE - Cnsa::SIZE, 12);
    }

    /// Un blob escrito por un perfil no se lee con el otro. Es lo que hay que
    /// exigirle a la separación: que los perfiles no se confundan en silencio.
    #[test]
    fn un_perfil_no_lee_el_blob_del_otro() {
        let blob = serialize(&sample_header(), b"ciphertext de prueba");
        // El perfil CNSA lee 56 bytes de cabecera donde había 68: magic y
        // versión están en su sitio, pero el resto se desplaza y el ciphertext
        // que devuelve NO es el que se escribió.
        let (_, ct_mal) = parse::<16, 12>(&blob).expect("magic y versión coinciden");
        assert_ne!(ct_mal, b"ciphertext de prueba");
    }
}

#[cfg(test)]
mod pruebas_campos_reservados {
    use super::*;

    fn cabecera_valida() -> Vec<u8> {
        let h = Header::<16, 24> {
            version: VERSION,
            flags: 0,
            codebook_id: 0,
            codebook_hash_prefix: [1u8; 8],
            salt: [2u8; 16],
            nonce: [3u8; 24],
            kdf_mem_kib: 65536,
            kdf_iterations: 3,
            kdf_parallelism: 1,
        };
        let mut b = h.to_bytes();
        b.extend_from_slice(b"ciphertext de mentira");
        b
    }

    /// LA MITAD QUE ACEPTA: una cabecera con `flags = 0` pasa. Sin esto, un
    /// `parse` que rechazara siempre pasaría la mitad de abajo con nota.
    #[test]
    fn una_cabecera_con_flags_cero_se_acepta() {
        let b = cabecera_valida();
        let (h, resto) = parse::<16, 24>(&b).expect("flags 0 tiene que pasar");
        assert_eq!(h.flags, 0);
        assert_eq!(resto, b"ciphertext de mentira");
    }

    /// LA MITAD QUE RECHAZA, y no es limpieza: cierra una DEGRADACIÓN
    /// SILENCIOSA.
    ///
    /// La cabecera va como AAD, así que un contenedor futuro con `flags = 1`
    /// **autentica perfectamente** contra un decodificador viejo. Si ese
    /// decodificador ignorase el campo, interpretaría el contenido con las
    /// reglas antiguas y devolvería algo mal leído CON EL AEAD EN VERDE — que es
    /// el peor desenlace posible: un fallo que no se nota.
    ///
    /// Se recorren los OCHO bits por separado: un `!= 0` mal escrito —una
    /// máscara, un `& 1`— pasaría una prueba que solo probara el valor 1.
    #[test]
    fn cualquier_bit_de_flags_desconocido_se_rechaza() {
        for bit in 0..8u8 {
            let v = 1u8 << bit;
            let mut b = cabecera_valida();
            b[5] = v;
            assert_eq!(
                parse::<16, 24>(&b).unwrap_err(),
                ContainerError::FlagsDesconocidos(v),
                "el bit {bit} de flags pasó desapercibido: un decodificador que \
                 IGNORA lo que no conoce devuelve datos mal interpretados con el \
                 AEAD en verde"
            );
        }
        // Y combinaciones, por si alguien mirara solo bits sueltos.
        for v in [0xFFu8, 0x81, 0x42] {
            let mut b = cabecera_valida();
            b[5] = v;
            assert!(matches!(
                parse::<16, 24>(&b),
                Err(ContainerError::FlagsDesconocidos(_))
            ));
        }
    }

    /// PASO 2 de la retirada: lo que `encode` ESCRIBE es siempre cero.
    ///
    /// Se comprueba aquí, en el crate del formato, y no solo en `api`: es la
    /// propiedad que hace que el paso 3 —validar a cero al leer— llegue algún
    /// día a ser seguro. Si alguien reintrodujera el valor del llamante, el
    /// paso 3 empezaría a huerfanar datos sin que nadie lo hubiera decidido.
    #[test]
    fn lo_que_se_escribe_lleva_codebook_id_en_cero() {
        let h = Header::<16, 24> {
            version: VERSION,
            flags: 0,
            codebook_id: 0,
            codebook_hash_prefix: [1u8; 8],
            salt: [2u8; 16],
            nonce: [3u8; 24],
            kdf_mem_kib: 65536,
            kdf_iterations: 3,
            kdf_parallelism: 1,
        };
        let b = h.to_bytes();
        assert_eq!(&b[6..8], &[0, 0], "el campo tiene que salir en cero");
    }

    /// `codebook_id` NO se rechaza, y es deliberado.
    ///
    /// A diferencia de `flags`, este campo es PÚBLICO y ajustable desde
    /// `Options` desde la 0.10.0. Rechazar un valor distinto de cero dejaría
    /// ILEGIBLE para siempre cualquier contenedor que alguien haya creado
    /// poniéndolo — datos huérfanos, sin recurso, para ganar limpieza. La
    /// directiva es mirar el objetivo antes de borrar, y aquí el objetivo puede
    /// tener datos de alguien.
    ///
    /// Lo que sí se hace es marcar el campo como obsoleto en `Options` con el
    /// motivo (ver N9 del modelo de amenaza: son 16 bits de metadato en claro,
    /// elegidos por el llamante y estables entre todos sus contenedores), y
    /// quitarlo en la próxima ruptura de formato, cuando ya nadie lo escriba.
    #[test]
    fn codebook_id_distinto_de_cero_se_sigue_aceptando() {
        let mut b = cabecera_valida();
        b[6] = 0x00;
        b[7] = 0x07;
        let (h, _) = parse::<16, 24>(&b).expect("no se puede huerfanar datos ajenos");
        assert_eq!(h.codebook_id, 7);
    }
}
