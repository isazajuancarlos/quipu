// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

//! Cifrado **perforable**: destruir la clave al abrir el lacre (feature `perforable`).
//!
//! # Qué resuelve, en una frase
//!
//! Un corpus de lacres en reposo donde **abrir uno destruye la capacidad de
//! volver a abrirlo**, aunque el atacante robe después el estado completo, el
//! ciphertext y la frase que protege el estado. Es *forward secrecy* aplicada a
//! DATOS EN REPOSO, no a un canal.
//!
//! # Cómo, en una frase
//!
//! [`Perforable`] es la clave maestra de un [PPRF] sobre un árbol GGM: de una
//! raíz aleatoria, un PRG (HKDF-SHA256, [`kdf::expand_desde`]) deriva un árbol
//! binario de profundidad [`DEPTH`]; cada hoja es la clave de un lacre. La clave
//! de una etiqueta es la hoja al final de su camino. **Perforar** una etiqueta
//! reemplaza el nodo que la cubría por los *hermanos* del camino a su hoja: desde
//! esos hermanos se deriva cualquier otra hoja, pero **la hoja perforada ya no**
//! —el material que la generaba se sobrescribe—.
//!
//! [PPRF]: https://eprint.iacr.org/2014/838  (Boneh-Waters; Sahai-Waters, GGM)
//!
//! # El modelo de amenaza, sin adornos (léelo antes de usarlo)
//!
//! Perforar solo protege hacia adelante **si la destrucción es real**. De ahí
//! salen tres reglas que no son opcionales:
//!
//! 1. **La raíz es aleatoria y NO se deriva de una frase.** Si se pudiera
//!    regenerar de una contraseña, no habría nada que destruir: el atacante con
//!    la frase reconstruiría la raíz y abriría todo. La raíz nace de
//!    [`aleatorio`] y el estado perforado es la ÚNICA copia. Esto es lo contrario
//!    del resto de `quipu`, donde la clave se re-deriva de la frase a voluntad.
//!
//! 2. **El estado se muta en sitio; una instantánea vieja lo deshace.** Si
//!    guardas [`Perforable::a_bytes`] ANTES de abrir un lacre y esa copia
//!    sobrevive, quien la tenga vuelve a abrir el lacre. Por eso [`Perforable`]
//!    **no es `Clone`** a propósito: copiarla es justo el error.
//!
//!    **Y destruir la copia vieja es más difícil de lo que parece.** Un
//!    `unlink` no borra nada, pero **sobrescribir el archivo tampoco** en el
//!    almacenamiento de consumo real: en sistemas copy-on-write (APFS de macOS,
//!    ZFS, Btrfs), en cualquier SSD con FTL, y ante snapshots, journaling o
//!    respaldos, «sobrescribir» escribe bloques NUEVOS y deja los viejos
//!    físicamente legibles. La garantía de este modo es, con precisión: *contra
//!    una copia del estado tomada DESPUÉS de abrir, **suponiendo borrado seguro
//!    del estado anterior***, que esos sistemas no ofrecen por defecto. La
//!    mitigación real es que el borrado ocurra donde SÍ es efectivo: cifrar el
//!    estado bajo una clave de envoltura en un TPM/secure element o `fscrypt`
//!    (y destruir esa clave), o tener el estado en `tmpfs`/RAM. Es un límite
//!    inherente a todo cifrado perforable en reposo, no un defecto de esta
//!    implementación — pero hay que decirlo, no dar una receta que no cumple.
//!
//! 3. **Lo NO abierto sigue abierto para quien robe el estado.** Perforar mata
//!    lo leído, no lo pendiente: un estado robado abre todos los lacres que aún
//!    no se han abierto. Es inherente —tienes que poder abrirlos—. Lo que se
//!    gana es que lo ya leído se vuelve irrecuperable.
//!
//! El estado es sensible: protégelo en reposo con el cifrado normal de `quipu`
//! (ese es «el lacre sobre el que va lo perforable»). La confidencialidad y la
//! integridad de cada lacre vienen del AEAD de [`crate::cipher`], como siempre:
//! este módulo solo administra QUÉ clave existe y cuándo deja de existir.
//!
//! # Lo que el estado NO oculta: el HISTORIAL de lectura
//!
//! El mapeo `etiqueta -> camino` no tiene secreto (es un HKDF con clave pública),
//! así que quien obtenga el estado Y tenga una lista de etiquetas candidatas
//! puede computar cada camino y ver **cuáles se abrieron** (los perforados). Los
//! DATOS de cada lacre siguen protegidos por su AEAD; lo que se filtra es el
//! patrón de acceso, no el contenido. Si ese patrón es sensible, el estado
//! necesita protección de reposo por sí mismo (que es lo que ya se recomienda).

use crate::kdf;
use zeroize::Zeroize;

/// Profundidad del árbol = bits del camino de cada etiqueta. Con 128 bits y un
/// mapeo HKDF, dos etiquetas distintas colisionan con probabilidad despreciable
/// (cumpleaños sobre 2^128).
pub const DEPTH: usize = 128;
/// Bytes que ocupa un camino de [`DEPTH`] bits.
const RUTA_BYTES: usize = DEPTH / 8;

/// Etiqueta de dominio para mapear `etiqueta -> camino`. Exactamente 32 bytes
/// (clave de un HKDF que actúa de función de dispersión con dominio propio).
const DOMINIO_ETIQUETA: [u8; 32] = *b"quipu/v1/perforable/tag->ruta!!!";
/// Etiquetas de dominio del PRG del árbol (hijo izquierdo / derecho).
const GGM_IZQ: &[u8] = b"quipu/v1/perforable/ggm/izq";
const GGM_DER: &[u8] = b"quipu/v1/perforable/ggm/der";

/// Un nodo del árbol (raíz, interno u hoja): 32 bytes de material pseudoaleatorio.
type Nodo = [u8; kdf::KEY_LEN];

/// Errores del cifrado perforable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PerforableError {
    /// No hubo entropía del sistema para crear la raíz.
    SinEntropia,
    /// El estado serializado está corrupto o no es de esta versión/perfil.
    EstadoInvalido(&'static str),
}

impl core::fmt::Display for PerforableError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SinEntropia => write!(f, "sin entropía del sistema para la raíz"),
            Self::EstadoInvalido(m) => write!(f, "estado perforable inválido: {m}"),
        }
    }
}
impl std::error::Error for PerforableError {}

/// Un subárbol cubierto: su raíz [`clave`] deriva todas las hojas cuyo camino
/// empieza por [`prefijo`] en sus primeros [`profundidad`] bits.
///
/// Las coberturas de una [`Perforable`] **particionan** el espacio de hojas NO
/// perforadas: cada etiqueta viva cae bajo exactamente una.
struct Cobertura {
    /// Bits significativos de [`Cobertura::prefijo`] (0 = raíz, [`DEPTH`] = hoja).
    profundidad: u8,
    /// Prefijo del camino; solo importan los primeros [`Cobertura::profundidad`] bits.
    prefijo: [u8; RUTA_BYTES],
    /// Raíz del subárbol.
    clave: Nodo,
}

impl Drop for Cobertura {
    fn drop(&mut self) {
        self.clave.zeroize();
    }
}

/// Clave maestra de un cifrado perforable. **No es `Clone`**: ver la regla 2 del
/// modelo de amenaza del módulo.
pub struct Perforable {
    coberturas: Vec<Cobertura>,
    perforadas: u64,
}

impl Drop for Perforable {
    fn drop(&mut self) {
        // Las `Cobertura` se zeroizan solas al soltarse; esto lo hace explícito.
        self.coberturas.clear();
    }
}

/// Lee el bit `i` (de mayor a menor peso dentro de cada byte) de un camino.
#[inline]
fn bit(buf: &[u8], i: usize) -> bool {
    (buf[i / 8] >> (7 - (i % 8))) & 1 == 1
}

/// Fija el bit `i` de un camino.
#[inline]
fn set_bit(buf: &mut [u8], i: usize, v: bool) {
    let mask = 1u8 << (7 - (i % 8));
    if v {
        buf[i / 8] |= mask;
    } else {
        buf[i / 8] &= !mask;
    }
}

/// PRG del árbol: deriva el hijo izquierdo (`bit=false`) o derecho (`bit=true`).
///
/// Devuelve el nodo en un [`Zeroizing`](zeroize::Zeroizing) para que NINGUNA
/// copia del material de un nodo del camino sobreviva en la pila: `[u8; 32]` es
/// `Copy`, y un valor devuelto por copia deja residuo que un volcado de memoria
/// (T6) podría leer — y de un nodo del camino se deriva la hoja perforada. El
/// llamante encadena `Zeroizing`, así que cada intermedio se borra al soltarse.
fn hijo(k: &Nodo, bit: bool) -> zeroize::Zeroizing<Nodo> {
    let info = if bit { GGM_DER } else { GGM_IZQ };
    let mut out = zeroize::Zeroizing::new([0u8; kdf::KEY_LEN]);
    kdf::expand_desde(k, info, &mut *out);
    out
}

/// Mapea una etiqueta arbitraria a su camino de [`DEPTH`] bits.
fn ruta(etiqueta: &[u8]) -> [u8; RUTA_BYTES] {
    let full = kdf::derive_subkey(&DOMINIO_ETIQUETA, etiqueta);
    let mut r = [0u8; RUTA_BYTES];
    r.copy_from_slice(&full[..RUTA_BYTES]);
    r
}

/// ¿La cobertura `c` cubre el camino `p`? (Sus primeros `c.profundidad` bits coinciden.)
fn cubre(c: &Cobertura, p: &[u8]) -> bool {
    (0..c.profundidad as usize).all(|i| bit(&c.prefijo, i) == bit(p, i))
}

/// Deriva la hoja del camino `p` bajando desde la cobertura `c` que lo cubre.
///
/// Todos los nodos intermedios viven en [`Zeroizing`](zeroize::Zeroizing) —cada
/// reasignación borra el anterior— y al final se barre la pila, como en
/// [`kdf::derive_master_key`]: los nodos del camino no deben sobrevivir a la
/// derivación (T6).
fn hoja_desde(c: &Cobertura, p: &[u8]) -> zeroize::Zeroizing<Nodo> {
    let mut k = zeroize::Zeroizing::new(c.clave);
    for i in (c.profundidad as usize)..DEPTH {
        k = hijo(&k, bit(p, i));
    }
    crate::antihacker::limpiar_pila();
    k
}

impl Perforable {
    /// Crea una clave maestra nueva con raíz aleatoria del sistema.
    ///
    /// La raíz **no** se deriva de ninguna frase: es la única copia y solo vive
    /// en este estado (ver el modelo de amenaza del módulo).
    pub fn nueva() -> Result<Self, PerforableError> {
        let mut raiz = crate::aleatorio::bytes::<{ kdf::KEY_LEN }>()
            .map_err(|_| PerforableError::SinEntropia)?;
        let s = Self::desde_raiz(raiz);
        raiz.zeroize(); // no dejar la raíz —lo más sensible— copiada en la pila
        crate::antihacker::limpiar_pila(); // barre la copia que `aleatorio::bytes` devolvió por valor
        Ok(s)
    }

    /// Construye desde una raíz dada. Interno: solo para pruebas con vectores
    /// deterministas. Un consumidor usa [`Perforable::nueva`].
    pub(crate) fn desde_raiz(mut raiz: Nodo) -> Self {
        let s = Self {
            coberturas: vec![Cobertura {
                profundidad: 0,
                prefijo: [0u8; RUTA_BYTES],
                clave: raiz,
            }],
            perforadas: 0,
        };
        raiz.zeroize();
        s
    }

    /// Deriva la clave de 32 bytes de una etiqueta, o `None` si está perforada.
    ///
    /// La salida se envuelve en [`Zeroizing`](zeroize::Zeroizing): se borra al
    /// soltarse. Para etiquetas NO perforadas es estable —siempre el mismo
    /// valor— hasta que se perfore.
    pub fn clave_de(&self, etiqueta: &[u8]) -> Option<zeroize::Zeroizing<[u8; kdf::KEY_LEN]>> {
        let p = ruta(etiqueta);
        self.coberturas
            .iter()
            .find(|c| cubre(c, &p))
            .map(|c| hoja_desde(c, &p))
    }

    /// ¿La etiqueta ya no tiene clave? En un árbol de 2^DEPTH hojas TODA etiqueta
    /// tiene clave hasta que se perfora, así que en la práctica esto es «fue
    /// perforada» (una etiqueta que nunca se usó sigue teniendo su clave).
    pub fn esta_perforada(&self, etiqueta: &[u8]) -> bool {
        let p = ruta(etiqueta);
        !self.coberturas.iter().any(|c| cubre(c, &p))
    }

    /// Perfora la etiqueta: destruye su clave para siempre. Devuelve `true` si
    /// había clave que destruir, `false` si ya estaba perforada (idempotente).
    ///
    /// Tras esto, [`clave_de`](Self::clave_de) de esa etiqueta devuelve `None` y
    /// la clave no se puede reconstruir ni con el estado completo posterior.
    pub fn perforar(&mut self, etiqueta: &[u8]) -> bool {
        let p = ruta(etiqueta);
        let idx = match self.coberturas.iter().position(|c| cubre(c, &p)) {
            Some(i) => i,
            None => return false,
        };
        let inicio = self.coberturas[idx].profundidad as usize;
        // Todos los nodos del camino viven en `Zeroizing`: cada reasignación de
        // `k` borra el anterior, y `hijo` no deja copias `Copy` sueltas.
        let mut k = zeroize::Zeroizing::new(self.coberturas[idx].clave);

        // El estado nuevo se construye en un `Vec` de capacidad EXACTA —para que
        // NO haya realloc a mitad— y luego se zeroiza EN SITIO el `Vec` viejo
        // antes de soltarlo. Es la corrección de T6 que faltaba: `Vec` NO ejecuta
        // Drop sobre el búfer que ABANDONA en una realloc/`free` (mueve los
        // elementos bit a bit y libera el búfer viejo crudo), así que
        // `swap_remove` + `extend` dejaban la raíz y los hermanos legibles en el
        // heap liberado —justo lo que `limpiar_pila` (que solo barre la PILA) no
        // alcanza—. Lo cazó el concilio (revisor Fable), midiéndolo.
        let total = self.coberturas.len() - 1 + (DEPTH - inicio);
        let mut nuevas: Vec<Cobertura> = Vec::with_capacity(total);
        for (j, c) in self.coberturas.iter().enumerate() {
            if j != idx {
                nuevas.push(Cobertura {
                    profundidad: c.profundidad,
                    prefijo: c.prefijo,
                    clave: c.clave,
                });
            }
        }
        for i in inicio..DEPTH {
            let b = bit(&p, i);
            // El HERMANO se guarda (deriva todo menos `p`); el nodo del CAMINO se
            // consume y no debe sobrevivir.
            let hermano = hijo(&k, !b);
            let camino = hijo(&k, b);
            let mut prefijo = [0u8; RUTA_BYTES];
            for j in 0..i {
                set_bit(&mut prefijo, j, bit(&p, j));
            }
            set_bit(&mut prefijo, i, !b);
            nuevas.push(Cobertura {
                profundidad: (i + 1) as u8,
                prefijo,
                clave: *hermano,
            });
            k = camino; // suelta (zeroiza) el nodo del camino anterior
        }
        drop(k); // `k` era la hoja: destruida al soltarse

        // Zeroiza el búfer VIEJO en sitio antes de reemplazarlo: su `free` no lo
        // haría (el realloc/drop del `Vec` abandona los bytes sin Drop).
        for c in self.coberturas.iter_mut() {
            c.clave.zeroize();
        }
        self.coberturas = nuevas;
        self.perforadas += 1;
        // Barre las copias `Copy` transitorias de nodos que quedaron en la pila,
        // igual que `kdf::derive_master_key` (T6).
        crate::antihacker::limpiar_pila();
        true
    }

    /// Cuántas etiquetas se han perforado.
    pub fn perforadas(&self) -> u64 {
        self.perforadas
    }

    /// Cuántas coberturas guarda el estado (crece ~[`DEPTH`] por perforación;
    /// es la medida real del tamaño del estado serializado).
    pub fn coberturas(&self) -> usize {
        self.coberturas.len()
    }

    // -- Serialización -------------------------------------------------------
    //
    // magic "QPF1" | version(1) | depth(1) | perforadas(8 LE) | n(4 LE)
    //   luego n veces: profundidad(1) | prefijo(RUTA_BYTES) | clave(32)

    const MAGIC: &'static [u8; 4] = b"QPF1";
    const VERSION: u8 = 1;

    /// Serializa el estado. Es material sensible (lleva las claves de los
    /// subárboles vivos): se devuelve en [`Zeroizing`](zeroize::Zeroizing) para
    /// que se borre al soltarse. Protégelo en reposo con el cifrado normal de
    /// `quipu` y destruye las versiones viejas.
    ///
    /// La capacidad es EXACTA a propósito: sin realloc a mitad, el búfer no se
    /// abandona a medio serializar en el heap liberado (misma clase que T6).
    pub fn a_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        const CAB: usize = 4 + 1 + 1 + 8 + 4;
        let mut out =
            zeroize::Zeroizing::new(Vec::with_capacity(CAB + self.coberturas.len() * (1 + RUTA_BYTES + 32)));
        out.extend_from_slice(Self::MAGIC);
        out.push(Self::VERSION);
        out.push(DEPTH as u8);
        out.extend_from_slice(&self.perforadas.to_le_bytes());
        out.extend_from_slice(&(self.coberturas.len() as u32).to_le_bytes());
        for c in &self.coberturas {
            out.push(c.profundidad);
            out.extend_from_slice(&c.prefijo);
            out.extend_from_slice(&c.clave);
        }
        out
    }

    /// Reconstruye el estado desde [`a_bytes`](Self::a_bytes).
    pub fn de_bytes(bytes: &[u8]) -> Result<Self, PerforableError> {
        const CAB: usize = 4 + 1 + 1 + 8 + 4;
        const ENTRADA: usize = 1 + RUTA_BYTES + 32;
        if bytes.len() < CAB {
            return Err(PerforableError::EstadoInvalido("truncado"));
        }
        if &bytes[..4] != Self::MAGIC {
            return Err(PerforableError::EstadoInvalido("magic"));
        }
        if bytes[4] != Self::VERSION {
            return Err(PerforableError::EstadoInvalido("versión"));
        }
        if bytes[5] as usize != DEPTH {
            return Err(PerforableError::EstadoInvalido("profundidad de otro perfil"));
        }
        let perforadas = u64::from_le_bytes(bytes[6..14].try_into().unwrap());
        let n = u32::from_le_bytes(bytes[14..18].try_into().unwrap()) as usize;
        let cuerpo = &bytes[CAB..];
        // `checked_mul`: en 32-bit `n * ENTRADA` podría desbordar antes de la
        // comprobación de longitud. El atacante controla `n` (T2).
        let esperado = n
            .checked_mul(ENTRADA)
            .ok_or(PerforableError::EstadoInvalido("desbordamiento de longitud"))?;
        if cuerpo.len() != esperado {
            return Err(PerforableError::EstadoInvalido("longitud del cuerpo"));
        }
        let mut coberturas = Vec::with_capacity(n);
        // `cuerpo.len() == n * ENTRADA` ya está validado, así que el resto es vacío.
        for e in cuerpo.as_chunks::<ENTRADA>().0 {
            let profundidad = e[0];
            if profundidad as usize > DEPTH {
                return Err(PerforableError::EstadoInvalido("profundidad > DEPTH"));
            }
            let mut prefijo = [0u8; RUTA_BYTES];
            prefijo.copy_from_slice(&e[1..1 + RUTA_BYTES]);
            let mut clave = [0u8; 32];
            clave.copy_from_slice(&e[1 + RUTA_BYTES..]);
            coberturas.push(Cobertura {
                profundidad,
                prefijo,
                clave,
            });
        }
        Ok(Self {
            coberturas,
            perforadas,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arbol() -> Perforable {
        // Raíz fija: vectores deterministas, sin depender de la entropía del SO.
        Perforable::desde_raiz([0x5au8; 32])
    }

    #[test]
    fn dominio_etiqueta_mide_32() {
        assert_eq!(DOMINIO_ETIQUETA.len(), 32);
    }

    #[test]
    fn clave_estable_hasta_perforar() {
        let pf = arbol();
        let a = pf.clave_de(b"factura-001").unwrap();
        let b = pf.clave_de(b"factura-001").unwrap();
        assert_eq!(*a, *b, "la misma etiqueta deriva la misma clave");
        let c = pf.clave_de(b"factura-002").unwrap();
        assert_ne!(*a, *c, "etiquetas distintas, claves distintas");
    }

    /// El invariante del GGM: perforar una etiqueta NO cambia la clave de
    /// ninguna otra. (La cobertura hermana deriva la misma hoja que la raíz.)
    #[test]
    fn perforar_no_toca_a_las_demas() {
        let etiquetas: Vec<Vec<u8>> = (0..64).map(|i| format!("doc-{i}").into_bytes()).collect();
        let mut pf = arbol();
        let antes: Vec<[u8; 32]> = etiquetas
            .iter()
            .map(|e| *pf.clave_de(e).unwrap())
            .collect();

        assert!(pf.perforar(&etiquetas[10]));
        for (i, e) in etiquetas.iter().enumerate() {
            match pf.clave_de(e) {
                None => assert_eq!(i, 10, "solo la 10 debe quedar sin clave"),
                Some(k) => assert_eq!(*k, antes[i], "la {i} cambió y no debía"),
            }
        }
    }

    /// CASO ROJO (D33) por la vía real: la clave perforada NO se puede
    /// reconstruir ni con el estado COMPLETO posterior a la perforación.
    /// El control que discrimina: una etiqueta VIVA sí se deriva del mismo
    /// estado —si todo devolviera `None`, el test pasaría por estar ciego—.
    #[test]
    fn perforada_irrecuperable_del_estado_completo() {
        let mut pf = arbol();
        let victima = b"secreto-a-quemar";
        let testigo = b"secreto-que-vive";
        let k_victima = *pf.clave_de(victima).unwrap();
        let k_testigo = *pf.clave_de(testigo).unwrap();

        assert!(pf.perforar(victima));

        // Estado completo tras perforar (lo que vería un atacante).
        let estado = pf.a_bytes();
        let visto = Perforable::de_bytes(&estado).unwrap();

        assert!(visto.clave_de(victima).is_none(), "la víctima debe ser irrecuperable");
        // Control: el testigo SÍ se deriva y es el de siempre.
        let k = visto.clave_de(testigo).expect("el testigo sigue vivo");
        assert_eq!(*k, k_testigo, "el estado sigue funcionando para lo no perforado");

        // Y por si acaso: ninguna cobertura del estado deriva la clave víctima.
        assert!(!estado.windows(32).any(|w| w == k_victima.as_slice()),
            "el material de la clave víctima no debe aparecer crudo en el estado");
    }

    #[test]
    fn perforar_es_idempotente() {
        let mut pf = arbol();
        assert!(pf.perforar(b"x"));
        assert!(!pf.perforar(b"x"), "perforar de nuevo no hace nada");
        assert_eq!(pf.perforadas(), 1);
    }

    #[test]
    fn serializacion_ida_y_vuelta_tras_perforaciones() {
        let mut pf = arbol();
        for i in 0..20 {
            pf.perforar(format!("q-{i}").as_bytes());
        }
        let vivas: Vec<[u8; 32]> = (0..20)
            .map(|i| *pf.clave_de(format!("v-{i}").as_bytes()).unwrap())
            .collect();

        let bytes = pf.a_bytes();
        let pf2 = Perforable::de_bytes(&bytes).unwrap();
        assert_eq!(pf2.perforadas(), 20);
        assert_eq!(pf2.coberturas(), pf.coberturas());
        for (i, viva) in vivas.iter().enumerate() {
            assert!(pf2.esta_perforada(format!("q-{i}").as_bytes()));
            assert_eq!(*pf2.clave_de(format!("v-{i}").as_bytes()).unwrap(), *viva);
        }
    }

    #[test]
    fn de_bytes_rechaza_corrupcion() {
        let pf = arbol();
        let mut b = pf.a_bytes();
        assert!(Perforable::de_bytes(&b).is_ok());
        b[0] ^= 1; // magic roto
        assert!(matches!(Perforable::de_bytes(&b), Err(PerforableError::EstadoInvalido(_))));
        assert!(matches!(Perforable::de_bytes(&[]), Err(PerforableError::EstadoInvalido(_))));
    }

    /// D8: 200 perforaciones. Cada una destruye SOLO la suya; todas las demás
    /// vivas siguen derivando su clave original. El estado se serializa y
    /// recarga a mitad para probar que la perforación sobrevive al viaje.
    #[test]
    fn simulacion_200_perforaciones() {
        let n = 200usize;
        let etiquetas: Vec<Vec<u8>> = (0..n).map(|i| format!("op-{i:04}").into_bytes()).collect();
        let mut pf = arbol();
        let claves: Vec<[u8; 32]> = etiquetas.iter().map(|e| *pf.clave_de(e).unwrap()).collect();

        for (i, e) in etiquetas.iter().enumerate() {
            assert!(pf.perforar(e));
            // recarga desde bytes a mitad del recorrido
            if i == n / 2 {
                pf = Perforable::de_bytes(&pf.a_bytes()).unwrap();
            }
            // la recién perforada, muerta; una posterior cualquiera, viva y estable
            assert!(pf.esta_perforada(e));
            if i + 1 < n {
                assert_eq!(*pf.clave_de(&etiquetas[i + 1]).unwrap(), claves[i + 1]);
            }
        }
        assert_eq!(pf.perforadas(), n as u64);
        for e in &etiquetas {
            assert!(pf.esta_perforada(e), "al final, todas perforadas");
        }
    }
}
