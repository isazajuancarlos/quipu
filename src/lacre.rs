// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

//! Registro **encadenado** de aperturas del lacre (feature `perforable`).
//!
//! # Qué resuelve
//!
//! El modo perforable ([`crate::perforable`]) da el **sobre de un solo uso**:
//! abrir un lacre destruye su clave, así que no se reabre. Lo que no da por sí
//! solo es un **rastro auditable de qué se abrió y en qué orden**, a prueba de
//! manipulación. Eso es [`RegistroDeAperturas`]: cada apertura se anota en una
//! cadena de hashes donde cada eslabón está **keyado por el anterior**, de modo
//! que quitar, reordenar o alterar una anotación cambia la **cabeza** de la
//! cadena. Si esa cabeza se ancla en algún sitio (se publica, se firma, se
//! guarda aparte), toda la historia de aperturas queda fijada.
//!
//! # Qué NO es
//!
//! No es confidencialidad: el registro guarda un **compromiso** de cada etiqueta
//! (`HKDF(dominio, etiqueta)`), no la etiqueta ni el contenido. Y como el mapeo
//! etiqueta→compromiso no tiene secreto, quien tenga el registro Y una lista de
//! etiquetas candidatas puede ver cuáles se anotaron — la misma propiedad que ya
//! declara [`crate::perforable`]. El registro prueba la INTEGRIDAD y el ORDEN de
//! las aperturas, no las oculta.

use crate::kdf;
use zeroize::Zeroize;

/// Cabeza de una cadena vacía: constante de dominio (no secreta). Exactamente 32 bytes.
const GENESIS: [u8; 32] = *b"quipu/v1/lacre/registro/genesis!";
/// Dominio del compromiso de la etiqueta.
const DOMINIO_COMPROMISO: [u8; 32] = *b"quipu/v1/lacre/compromiso-etiq!!";

/// Errores del registro.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistroError {
    /// El estado serializado está corrupto o no es de esta versión.
    EstadoInvalido(&'static str),
}

impl core::fmt::Display for RegistroError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EstadoInvalido(m) => write!(f, "registro de aperturas inválido: {m}"),
        }
    }
}
impl std::error::Error for RegistroError {}

/// Una anotación de apertura: el compromiso de la etiqueta abierta y su posición.
#[derive(Clone, PartialEq, Eq)]
struct Anotacion {
    contador: u64,
    compromiso: [u8; 32],
}

/// Registro encadenado y a prueba de manipulación de las aperturas de lacres.
///
/// La cabeza ([`cabeza`](Self::cabeza)) es un compromiso con TODA la historia:
/// cambia con cada anotación y con cualquier alteración de las anteriores.
#[derive(Clone)]
pub struct RegistroDeAperturas {
    anotaciones: Vec<Anotacion>,
    cabeza: [u8; 32],
}

impl Default for RegistroDeAperturas {
    fn default() -> Self {
        Self::nuevo()
    }
}

/// Compromiso de una etiqueta: `HKDF(DOMINIO_COMPROMISO, etiqueta)`. Público
/// (sin secreto): no oculta la etiqueta a quien pueda adivinarla, solo la fija.
fn compromiso(etiqueta: &[u8]) -> [u8; 32] {
    kdf::derive_subkey(&DOMINIO_COMPROMISO, etiqueta)
}

/// Un eslabón de la cadena: `HKDF(cabeza_previa, contador ‖ compromiso)`. Keyar
/// con la cabeza previa es lo que ata cada eslabón a toda la historia anterior.
fn eslabon(cabeza_previa: &[u8; 32], a: &Anotacion) -> [u8; 32] {
    let mut info = [0u8; 8 + 32];
    info[..8].copy_from_slice(&a.contador.to_le_bytes());
    info[8..].copy_from_slice(&a.compromiso);
    kdf::derive_subkey(cabeza_previa, &info)
}

impl RegistroDeAperturas {
    /// Un registro vacío, con la cabeza en el génesis.
    pub fn nuevo() -> Self {
        Self {
            anotaciones: Vec::new(),
            cabeza: GENESIS,
        }
    }

    /// Anota la apertura de `etiqueta` y devuelve la nueva cabeza de la cadena.
    pub fn anotar(&mut self, etiqueta: &[u8]) -> [u8; 32] {
        let a = Anotacion {
            contador: self.anotaciones.len() as u64,
            compromiso: compromiso(etiqueta),
        };
        self.cabeza = eslabon(&self.cabeza, &a);
        self.anotaciones.push(a);
        self.cabeza
    }

    /// La cabeza actual: compromiso con toda la historia de aperturas.
    pub fn cabeza(&self) -> [u8; 32] {
        self.cabeza
    }

    /// Cuántas aperturas se han anotado.
    pub fn len(&self) -> usize {
        self.anotaciones.len()
    }

    /// ¿No hay ninguna anotación?
    pub fn is_empty(&self) -> bool {
        self.anotaciones.is_empty()
    }

    /// ¿Fue anotada la apertura de `etiqueta`? (Recorre los compromisos; útil para
    /// auditar contra una lista de etiquetas conocidas.)
    ///
    /// Responde sobre el cuerpo TAL CUAL está: si viene de [`de_bytes`], ancla la
    /// cabeza fuera y llama a [`verificar`](Self::verificar) ANTES de confiar en
    /// esta respuesta — sobre un cuerpo alterado diría lo que el atacante quiera.
    pub fn contiene(&self, etiqueta: &[u8]) -> bool {
        let c = compromiso(etiqueta);
        self.anotaciones.iter().any(|a| a.compromiso == c)
    }

    /// Recalcula la cadena desde el génesis y comprueba que reproduce la cabeza.
    /// Si alguien alteró, quitó o reordenó una anotación, esto devuelve `false`.
    pub fn verificar(&self) -> bool {
        let mut cabeza = GENESIS;
        for (i, a) in self.anotaciones.iter().enumerate() {
            // El contador también se ata: reordenar cambia los contadores.
            if a.contador != i as u64 {
                return false;
            }
            cabeza = eslabon(&cabeza, a);
        }
        crate::antihacker::ct_eq(&cabeza, &self.cabeza)
    }

    // -- Serialización -------------------------------------------------------
    //
    // magic "QLR1" | version(1) | n(4 LE) | cabeza(32) | n×(contador(8 LE) | compromiso(32))

    const MAGIC: &'static [u8; 4] = b"QLR1";
    const VERSION: u8 = 1;

    /// Serializa el registro. No es secreto (guarda compromisos, no etiquetas),
    /// pero su INTEGRIDAD importa: protégelo de escritura si el rastro debe valer.
    pub fn a_bytes(&self) -> Vec<u8> {
        const ENTRADA: usize = 8 + 32;
        let mut out = Vec::with_capacity(4 + 1 + 4 + 32 + self.anotaciones.len() * ENTRADA);
        out.extend_from_slice(Self::MAGIC);
        out.push(Self::VERSION);
        out.extend_from_slice(&(self.anotaciones.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.cabeza);
        for a in &self.anotaciones {
            out.extend_from_slice(&a.contador.to_le_bytes());
            out.extend_from_slice(&a.compromiso);
        }
        out
    }

    /// Reconstruye desde [`a_bytes`](Self::a_bytes). NO valida la cadena: usa
    /// [`verificar`](Self::verificar) después para comprobar que nadie la tocó.
    pub fn de_bytes(bytes: &[u8]) -> Result<Self, RegistroError> {
        const CAB: usize = 4 + 1 + 4 + 32;
        const ENTRADA: usize = 8 + 32;
        if bytes.len() < CAB {
            return Err(RegistroError::EstadoInvalido("truncado"));
        }
        if &bytes[..4] != Self::MAGIC {
            return Err(RegistroError::EstadoInvalido("magic"));
        }
        if bytes[4] != Self::VERSION {
            return Err(RegistroError::EstadoInvalido("versión"));
        }
        let n = u32::from_le_bytes(bytes[5..9].try_into().unwrap()) as usize;
        let mut cabeza = [0u8; 32];
        cabeza.copy_from_slice(&bytes[9..41]);
        let cuerpo = &bytes[CAB..];
        let esperado = n
            .checked_mul(ENTRADA)
            .ok_or(RegistroError::EstadoInvalido("desbordamiento de longitud"))?;
        if cuerpo.len() != esperado {
            return Err(RegistroError::EstadoInvalido("longitud del cuerpo"));
        }
        let mut anotaciones = Vec::with_capacity(n);
        for e in cuerpo.as_chunks::<ENTRADA>().0 {
            let contador = u64::from_le_bytes(e[..8].try_into().unwrap());
            let mut compromiso = [0u8; 32];
            compromiso.copy_from_slice(&e[8..]);
            anotaciones.push(Anotacion { contador, compromiso });
        }
        Ok(Self { anotaciones, cabeza })
    }
}

impl Drop for RegistroDeAperturas {
    fn drop(&mut self) {
        // Los compromisos no son secretos, pero no cuesta no dejarlos por ahí.
        self.cabeza.zeroize();
        for a in &mut self.anotaciones {
            a.compromiso.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cadena_vacia_verifica_y_es_genesis() {
        let r = RegistroDeAperturas::nuevo();
        assert!(r.verificar());
        assert_eq!(r.cabeza(), GENESIS);
        assert!(r.is_empty());
    }

    #[test]
    fn cada_apertura_mueve_la_cabeza() {
        let mut r = RegistroDeAperturas::nuevo();
        let c0 = r.cabeza();
        let c1 = r.anotar(b"lacre-1");
        let c2 = r.anotar(b"lacre-2");
        assert_ne!(c0, c1);
        assert_ne!(c1, c2);
        assert_eq!(r.len(), 2);
        assert!(r.verificar());
        assert!(r.contiene(b"lacre-1") && r.contiene(b"lacre-2"));
        assert!(!r.contiene(b"lacre-3"));
    }

    /// CASO ROJO (D33): alterar, quitar o reordenar una anotación rompe
    /// `verificar`. Se muta el ARTEFACTO (los bytes internos), por la vía real.
    #[test]
    fn manipular_el_registro_lo_delata() {
        let mut r = RegistroDeAperturas::nuevo();
        for i in 0..8 {
            r.anotar(format!("acta-{i}").as_bytes());
        }
        assert!(r.verificar(), "el registro intacto verifica");

        // Alterar un compromiso.
        let mut alterado = r.clone();
        alterado.anotaciones[3].compromiso[0] ^= 1;
        assert!(!alterado.verificar(), "alterar una anotación debe delatarse");

        // Quitar una del medio (los contadores dejan de casar y la cadena no cierra).
        let mut recortado = r.clone();
        recortado.anotaciones.remove(4);
        assert!(!recortado.verificar(), "quitar una anotación debe delatarse");

        // Reordenar dos.
        let mut reordenado = r.clone();
        reordenado.anotaciones.swap(1, 5);
        assert!(!reordenado.verificar(), "reordenar debe delatarse");

        // Falsear la cabeza para que "cuadre" con un cuerpo alterado: no cuela,
        // porque verificar RECALCULA desde el génesis.
        let mut cabeza_falsa = r.clone();
        cabeza_falsa.anotaciones[0].compromiso[0] ^= 1;
        cabeza_falsa.cabeza = {
            let mut h = GENESIS;
            for a in &cabeza_falsa.anotaciones {
                h = eslabon(&h, a);
            }
            h
        };
        // Aquí el atacante recomputó bien la cadena sobre su cuerpo alterado, así
        // que `verificar` (que solo comprueba consistencia interna) pasa —por eso
        // la seguridad está en ANCLAR la cabeza original fuera, no en verificar
        // contra uno mismo. Lo dejamos explícito:
        assert!(cabeza_falsa.verificar(), "recomputar internamente es consistente");
        assert_ne!(cabeza_falsa.cabeza(), r.cabeza(),
            "PERO la cabeza difiere de la original anclada: ahí se detecta");
    }

    #[test]
    fn serializacion_ida_y_vuelta() {
        let mut r = RegistroDeAperturas::nuevo();
        for i in 0..20 {
            r.anotar(format!("x-{i}").as_bytes());
        }
        let bytes = r.a_bytes();
        let r2 = RegistroDeAperturas::de_bytes(&bytes).unwrap();
        assert_eq!(r2.len(), 20);
        assert_eq!(r2.cabeza(), r.cabeza());
        assert!(r2.verificar());
    }

    #[test]
    fn de_bytes_rechaza_corrupcion() {
        let r = RegistroDeAperturas::nuevo();
        let mut b = r.a_bytes();
        assert!(RegistroDeAperturas::de_bytes(&b).is_ok());
        b[0] ^= 1;
        assert!(matches!(RegistroDeAperturas::de_bytes(&b), Err(RegistroError::EstadoInvalido(_))));
        assert!(matches!(RegistroDeAperturas::de_bytes(&[]), Err(RegistroError::EstadoInvalido(_))));
    }

    /// D8: 200 aperturas; la cabeza es estable al serializar/recargar y la cadena
    /// verifica en cada paso.
    #[test]
    fn simulacion_200_aperturas() {
        let mut r = RegistroDeAperturas::nuevo();
        let mut cabezas = Vec::new();
        for i in 0..200 {
            cabezas.push(r.anotar(format!("op-{i:04}").as_bytes()));
        }
        assert!(r.verificar());
        // La cabeza tras recargar coincide.
        let r2 = RegistroDeAperturas::de_bytes(&r.a_bytes()).unwrap();
        assert_eq!(r2.cabeza(), *cabezas.last().unwrap());
        assert!(r2.verificar());
    }
}
