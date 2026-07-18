// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Corpus de hallazgos encadenado por hash (candado de INTEGRIDAD).
//!
//! Append-only: cada entrada liga el hash de la anterior. Envenenar el historial
//! (inyectar "todo verde" para ocultar una brecha real) rompe la cadena y
//! `verify()` lo detecta. El laboratorio no confía ciegamente en su memoria.

use sha2::{Digest, Sha256};

/// Hash raíz de la cadena (cabeza de un corpus vacío).
pub const ROOT: [u8; 32] = [0u8; 32];

/// Una entrada del corpus: tipo + datos + hash encadenado.
#[derive(Clone)]
struct Entry {
    kind: String,
    data: Vec<u8>,
    hash: [u8; 32],
}

/// Corpus append-only encadenado por hash.
pub struct Corpus {
    entries: Vec<Entry>,
}

impl Corpus {
    /// Corpus vacío (cabeza = `ROOT`).
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Hash encadenado de una entrada: `sha256(prev || kind || 0x00 || data)`.
    fn link(prev: &[u8; 32], kind: &str, data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(prev);
        h.update(kind.as_bytes());
        h.update([0u8]); // separador dominio kind/data
        h.update(data);
        h.finalize().into()
    }

    /// Añade una entrada, ligándola a la cabeza actual.
    pub fn append(&mut self, kind: &str, data: &[u8]) {
        let prev = self.head();
        let hash = Self::link(&prev, kind, data);
        self.entries.push(Entry {
            kind: kind.to_string(),
            data: data.to_vec(),
            hash,
        });
    }

    /// Cabeza actual de la cadena (hash de la última entrada, o `ROOT` si vacío).
    pub fn head(&self) -> [u8; 32] {
        self.entries.last().map(|e| e.hash).unwrap_or(ROOT)
    }

    /// Número de entradas.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` si no hay entradas.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Recalcula la cadena desde `ROOT`; `false` si alguna entrada fue alterada.
    pub fn verify(&self) -> bool {
        let mut prev = ROOT;
        for e in &self.entries {
            let expected = Self::link(&prev, &e.kind, &e.data);
            if expected != e.hash {
                return false;
            }
            prev = e.hash;
        }
        true
    }

    /// SOLO test: simula envenenamiento alterando los datos de la última entrada
    /// sin recalcular su hash.
    #[cfg(test)]
    fn corrupt_last(&mut self) {
        if let Some(e) = self.entries.last_mut() {
            e.data.push(0xFF);
        }
    }
}

impl Default for Corpus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_corpus_verifies() {
        let c = Corpus::new();
        assert!(c.is_empty());
        assert_eq!(c.head(), ROOT);
        assert!(c.verify());
    }

    #[test]
    fn appended_chain_verifies_and_advances_head() {
        let mut c = Corpus::new();
        c.append("seed", b"hola");
        let h1 = c.head();
        c.append("breach", b"forgery-x");
        assert_eq!(c.len(), 2);
        assert_ne!(c.head(), ROOT);
        assert_ne!(c.head(), h1, "cada entrada mueve la cabeza");
        assert!(c.verify());
    }

    #[test]
    fn poisoning_breaks_the_chain() {
        let mut c = Corpus::new();
        c.append("seed", b"hola");
        c.append("breach", b"forgery-x");
        c.corrupt_last();
        assert!(!c.verify(), "una entrada alterada debe romper la verificación");
    }
}
