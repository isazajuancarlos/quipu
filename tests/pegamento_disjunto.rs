// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

//! ¿Qué paquete puede ver A LA VEZ la máscara del blindaje y el contenido que
//! esa máscara oculta?
//!
//! # Qué sostiene, y por qué tiene que ser una prueba y no un comentario
//!
//! `blindaje` promete un AND: hacen falta DOS componentes comprometidos para
//! leer el documento. Desde `QBL2` esa promesa descansa en un hecho de la
//! CADENA DE SUMINISTRO, no del código: que los paquetes que ven el mensaje en
//! el camino AEAD y los que producen la máscara (HKDF-SHA256) sean conjuntos
//! casi disjuntos. Un paquete que esté en los dos rompe el AND él solo — ve la
//! máscara, la quita, y junta las dos mitades.
//!
//! Eso no lo puede vigilar un comentario, porque **cambia sin que nadie toque
//! nuestro código**: basta que `cipher` gane una dependencia, o que `digest`
//! reorganice la suya, para que aparezca un paquete nuevo en la intersección.
//! Un `cargo update` lo haría en silencio.
//!
//! # Por qué el CIERRE DE DEPENDENCIAS y no el camino de ejecución
//!
//! Es la corrección que costó una justificación entera en `blindaje.rs`. Leyendo
//! el código se ve que `aes-gcm` aplica el keystream con `ctr::CtrCore` y nunca
//! toca `block-buffer`; de ahí se concluyó —mal— que `block-buffer` no ve la
//! capa AES. Pero el crate está compilado y enlazado dentro de `cipher`: un
//! `block-buffer` comprometido no está obligado a esperar a que le llamemos por
//! donde creemos, le vale cualquier punto de `cipher` que sí se ejecute.
//!
//! El cierre de dependencias sobreestima el peligro, y ese es el lado correcto
//! del error (directiva 20): sobra un paquete que quizá no ve nada, y no falta
//! ninguno que sí.
//!
//! # La forma: se enumera lo PERMITIDO, y el resto se pone rojo
//!
//! Enumerar lo prohibido deja fuera lo que no se te ocurrió. Aquí cada paquete
//! de la intersección está escrito con su motivo, y cualquiera que aparezca sin
//! estarlo suspende la prueba con su nombre.

use std::collections::{BTreeMap, BTreeSet};

/// Un paquete es su NOMBRE **y** su VERSIÓN, y esto no es pedantería: costó el
/// primer rojo de esta prueba.
///
/// `Cargo.lock` de quipu tiene DOS `digest` (0.10.7 y 0.11.3), dos
/// `crypto-common`, dos `block-buffer` y dos `sha2`. Indexando el grafo solo por
/// el nombre pasa una de dos cosas, y las dos son falsas: se FUSIONAN las
/// dependencias de las dos versiones —y entonces `subtle`, que cuelga de
/// `digest 0.10.7` vía `fips205`, aparece como si estuviera en el camino de
/// nuestra máscara— o se queda la última leída y las otras desaparecen sin
/// avisar. La primera versión de este archivo hacía lo primero y la medición a
/// mano que la precedió hacía lo segundo; acertó por casualidad.
///
/// Un valor con dos significados son dos campos (directiva 32).
type Id = (String, String);

/// El grafo del lock, con las aristas ya resueltas a `(nombre, versión)`.
struct Lock {
    aristas: BTreeMap<Id, Vec<Id>>,
    versiones: BTreeMap<String, Vec<String>>,
}

impl Lock {
    fn leer() -> Self {
        let texto = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock"))
            .expect("Cargo.lock tiene que estar: sin él esta prueba no mide nada");

        // Primera pasada: los paquetes y sus dependencias EN CRUDO, tal como el
        // lock las escribe («nombre» a secas si es única, «nombre versión» si no).
        let mut crudo: Vec<(Id, Vec<String>)> = Vec::new();
        let mut versiones: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let (mut nombre, mut version) = (String::new(), String::new());
        let mut deps: Vec<String> = Vec::new();
        let mut en_deps = false;
        let mut abierto = false;
        let mut anuncian_deps: std::collections::BTreeSet<Id> = std::collections::BTreeSet::new();

        let cerrar = |nombre: &str, version: &str, deps: &mut Vec<String>, crudo: &mut Vec<(Id, Vec<String>)>| {
            if !nombre.is_empty() && !version.is_empty() {
                crudo.push(((nombre.to_string(), version.to_string()), std::mem::take(deps)));
            }
        };

        for linea in texto.lines() {
            let l = linea.trim();
            // CUALQUIER cabecera de sección cierra el paquete abierto, no solo
            // `[[package]]`. Éste era el defecto de verdad, y mi «positivo de
            // control» de contar `[[package]]` NO lo veía: un `[[patch.unused]]`
            // —que la escribe cargo sola en cuanto un `[patch.crates-io]` queda sin
            // usar— traía sus propios `name =` y `version =`, que pisaban los del
            // paquete abierto; el `cerrar` final empujaba UN nodo fantasma en vez
            // del real, y `crudo.len() == declarados` seguía cumpliéndose.
            //
            // O sea que el recuento era invariante bajo la corrupción que decía
            // cazar, y además daba FALSO ROJO cuando el nombre parcheado sí existía
            // en el lock. Las dos mitades del mismo defecto (directiva 23). Lo midió
            // la revisión del 2026-08-17 con seis variantes del lock.
            if l.starts_with('[') {
                if abierto {
                    cerrar(&nombre, &version, &mut deps, &mut crudo);
                }
                abierto = l == "[[package]]";
                nombre.clear();
                version.clear();
                en_deps = false;
            } else if !abierto {
                // Estamos dentro de una sección que no es `[[package]]`
                // (`[[patch.unused]]`, `[metadata]`, …): sus claves no son de nadie.
            } else if let Some(v) = l.strip_prefix("name = ") {
                nombre = v.trim_matches('"').to_string();
                en_deps = false;
            } else if let Some(v) = l.strip_prefix("version = ") {
                version = v.trim_matches('"').to_string();
                versiones.entry(nombre.clone()).or_default().push(version.clone());
                en_deps = false;
            } else if l.starts_with("dependencies = [") {
                anuncian_deps.insert((nombre.clone(), version.clone()));
                en_deps = l == "dependencies = [";
            } else if en_deps {
                if l == "]" {
                    en_deps = false;
                } else {
                    let d = l.trim_end_matches(',').trim_matches('"').to_string();
                    if !d.is_empty() {
                        deps.push(d);
                    }
                }
            }
        }
        if abierto {
            cerrar(&nombre, &version, &mut deps, &mut crudo);
        }

        // POSITIVO DE CONTROL DEL PROPIO LECTOR: tantos paquetes leídos como
        // `[[package]]` declara el archivo.
        //
        // **Y ESTE CONTROL, SOLO, NO VALE** — conviene decirlo porque su primera
        // versión se presentó como si valiera. Es INVARIANTE bajo la corrupción
        // que motivaba escribirlo (`[[patch.unused]]` sustituye un nodo por otro
        // sin cambiar la cuenta), así que quien lo mira y lo ve verde no ha
        // comprobado nada de eso. Lo que cierra esa familia es el cambio de
        // arriba: cerrar el paquete ante cualquier cabecera de sección.
        //
        // Se queda porque sigue cazando lo que sí cuenta: que el lector pierda
        // paquetes de verdad, por un formato que no entiende o por un corte del
        // archivo. Es un control estrecho declarado como estrecho, no un control
        // muerto vendido como ancho.
        //
        // (El otro escenario de la revisión —el array de dependencias en una sola
        // línea— NO sobrevive a `cargo test`: cargo reescribe el lock a forma
        // canónica antes de correr. Comprobado.)
        let declarados = texto.lines().filter(|l| l.trim() == "[[package]]").count();
        assert_eq!(
            crudo.len(),
            declarados,
            "el lock declara {declarados} paquetes y el lector leyó {}: se perdió \
             alguno, y un paquete perdido encoge el cierre en silencio",
            crudo.len()
        );

        // Y la otra forma de quedarse corto sin avisar: un bloque que ANUNCIA
        // dependencias y no aporta ninguna. Hoy no puede pasar —cargo escribe el
        // array multilínea— y por eso es barato exigirlo: si algún día cambia de
        // formato, esto lo dice en vez de devolver un grafo mocho.
        for (id, ds) in &crudo {
            assert!(
                !(ds.is_empty() && anuncian_deps.contains(id)),
                "«{} {}» anuncia dependencias y el lector no leyó ninguna: el \
                 formato del lock cambió y el grafo sale mocho",
                id.0,
                id.1
            );
        }

        let mut yo = Lock { aristas: BTreeMap::new(), versiones };
        let crudo2 = crudo;
        for (id, ds) in crudo2 {
            let resueltas = ds.iter().map(|d| yo.resolver(d)).collect();
            yo.aristas.insert(id, resueltas);
        }
        yo
    }

    /// «nombre» o «nombre versión» → `(nombre, versión)`.
    ///
    /// Si viene sin versión y hay más de una, ABORTA en vez de elegir: elegir
    /// sería exactamente el relleno que la directiva 20 prohíbe, y aquí el dato
    /// inventado decidiría si un paquete rompe el AND o no.
    fn resolver(&self, crudo: &str) -> Id {
        let mut t = crudo.split_whitespace();
        let n = t.next().unwrap_or("").to_string();
        if let Some(v) = t.next() {
            return (n, v.to_string());
        }
        let vs = self.versiones.get(&n).cloned().unwrap_or_default();
        assert_eq!(
            vs.len(),
            1,
            "«{n}» aparece sin versión en el lock pero tiene {} ({vs:?}): el lock \
             debería haberla escrito, y adivinarla aquí decidiría a ciegas si ese \
             paquete rompe el AND",
            vs.len()
        );
        (n, vs.into_iter().next().unwrap_or_default())
    }

    /// Las dependencias de `quipu` tal como el lock las fijó. Las raíces se
    /// LEEN de aquí y no se escriben a mano: una versión escrita a mano envejece
    /// en el primer `cargo update` y la prueba pasaría midiendo otro árbol.
    fn raiz(&self, nombre: &str) -> Id {
        let quipu = self
            .aristas
            .iter()
            .find(|((n, _), _)| n == "quipu")
            .map(|(_, ds)| ds.clone())
            .expect("«quipu» tiene que estar en su propio Cargo.lock");
        quipu
            .into_iter()
            .find(|(n, _)| n == nombre)
            .unwrap_or_else(|| panic!("«{nombre}» no es dependencia directa de quipu"))
    }

    fn cierre(&self, raices: &[&str]) -> BTreeSet<Id> {
        let mut vistos = BTreeSet::new();
        let mut pila: Vec<Id> = raices.iter().map(|n| self.raiz(n)).collect();
        while let Some(k) = pila.pop() {
            if !vistos.insert(k.clone()) {
                continue;
            }
            // NO HAY `if let` AQUÍ, Y ES EL PUNTO. Con un `if let` sin `else`, todo
            // nodo que el lector no consiguiera meter en `aristas` se recorría como
            // HOJA: sin hijos, sin error, sin nada. Y como esta prueba busca una
            // INTERSECCIÓN, cada rama perdida la encoge — o sea que el modo de
            // fallo por defecto del vigilante era el verde.
            //
            // Medido por la revisión de seguridad del 2026-08-17, y es peor de lo
            // que suena: truncando el subárbol de `chacha20poly1305` la
            // intersección salía **idéntica** a la buena y las cinco aserciones del
            // archivo pasaban. El control no lo veía porque solo miraba el cierre
            // de `aes-gcm`.
            let Some(ds) = self.aristas.get(&k) else {
                panic!(
                    "«{}» aparece como dependencia y no tiene entrada propia en el \
                     lock: el lector se rompió. Un nodo sin aristas se recorrería \
                     como hoja, encogería el cierre, y encoger el cierre es el \
                     camino al verde de esta prueba.",
                    k.0
                );
            };
            pila.extend(ds.iter().cloned());
        }
        vistos
    }
}

/// EL ALCANCE, EN UN SOLO SITIO. Antes cada prueba escribía sus raíces como
/// literal, y el banco de mutación del 2026-08-17 midió el precio: estrechar
/// `nadie_nuevo_…` a `["aes-gcm"]` dejaba las tres pruebas VERDES, porque el
/// control construye su propio cierre y comprueba ése. El archivo llevaba
/// escrito el aviso —«Las DOS capas, no solo la enmascarada»— y aun así cayó: no
/// basta con avisar si el dato está duplicado.
///
/// Compartiéndolo, estrechar el invariante es imposible sin tocar lo que el
/// control mira.
const RAICES_AEAD: &[&str] = &["aes-gcm", "chacha20poly1305"];
const RAICES_MASCARA: &[&str] = &["hkdf", "sha2"];

/// Los paquetes que solo están en el camino AEAD. Se comprueba que sean
/// EXACTAMENTE éstos, no que estén incluidos: enumerar de menos era otro mutante
/// que sobrevivía (recortar el bucle a `["aes"]`).
const EXCLUSIVOS_AEAD: &[&str] = &[
    "aead", "aes", "aes-gcm", "chacha20", "chacha20poly1305", "cipher", "cpubits", "ctr",
    "ghash", "inout", "poly1305", "polyval", "subtle", "universal-hash",
];

fn nombres(c: &BTreeSet<Id>) -> BTreeSet<&str> {
    c.iter().map(|(n, _)| n.as_str()).collect()
}

/// Los paquetes que HOY están en las dos rutas, cada uno con por qué se tolera.
///
/// # LA PREGUNTA QUE HAY QUE CONTESTAR AQUÍ, y que la primera versión no contestó
///
/// Es **«¿ve este paquete el mensaje?»**, no «¿nos conviene compartirlo?». La
/// revisión de seguridad del 2026-08-17 encontró el fallo: `zeroize` estaba
/// tolerado con el motivo «borrado de memoria; compartirlo es deseable», que
/// responde a la segunda pregunta. A la primera la respuesta es **sí, y las dos
/// mitades en claro** — o sea que rompía él solo el AND que este archivo dice
/// vigilar, y encima la documentación lo negaba diciendo que el residuo era uno.
///
/// Un motivo que contesta a otra cosa es una excepción que nadie volvió a mirar.
const TOLERADOS: &[(&str, &str)] = &[
    // ── LOS DOS RESIDUOS REALES: ven datos. Van declarados como tales en la
    //    sección «De qué NO protege» de `src/blindaje.rs`, y el recuento
    //    honesto es DOS, no uno.
    //
    // Bufferiza bloques de entrada en `digest` (ve material de la máscara) y
    // viaja dentro de `cipher` (está en el proceso de las dos capas).
    ("block-buffer", "RESIDUO REAL: ve bloques de entrada del hash y viaja en cipher"),
    // PEOR QUE EL ANTERIOR, y por una vía que la máscara no toca: `blindaje`
    // define `type Mitad = Zeroizing<Vec<u8>>`, así que `repartir` le entrega S1
    // y S2 EN CLARO por la puerta principal en cada operación, y su XOR es el
    // documento. No necesita ver la máscara. No se puede quitar —`kdf.rs`
    // envuelve la maestra con el mismo crate, así que uno comprometido se la
    // lleva igual— y por eso es residuo declarado, no un arreglo pendiente.
    ("zeroize", "RESIDUO REAL: recibe S1 y S2 en claro vía Zeroizing<Vec<u8>>"),
    // ── LAS MACROS DE COMPILACIÓN. El motivo NO es que sean inocuas.
    //
    // La primera versión decía «solo en tiempo de compilación, nunca con datos
    // del usuario», y eso está mal encuadrado: en un modelo de amenaza de
    // CADENA DE SUMINISTRO —que es el modelo entero de este módulo— un
    // proc-macro comprometido es la MEJOR posición, no la más inocua. Corre en
    // la máquina de compilación e inyecta código arbitrario en el binario que
    // sí ve los datos. Se toleran porque no hay forma de compilar sin ellos, que
    // es un riesgo ACEPTADO y no un riesgo ausente.
    ("zeroize_derive", "RIESGO DE BUILD ACEPTADO: proc-macro, inyecta código en el binario"),
    ("proc-macro2", "RIESGO DE BUILD ACEPTADO: proc-macro, inyecta código en el binario"),
    ("quote", "RIESGO DE BUILD ACEPTADO: proc-macro, inyecta código en el binario"),
    ("syn", "RIESGO DE BUILD ACEPTADO: proc-macro, inyecta código en el binario"),
    ("unicode-ident", "RIESGO DE BUILD ACEPTADO: dependencia de los proc-macro"),
    // ── TIPOS Y TAMAÑOS. Éstos sí contestan «no ve el mensaje».
    ("crypto-common", "solo traits de tamaños y KeyInit; nunca recibe el mensaje"),
    // RESIDUO REAL desde el 2026-08-17, por el mismo motivo mal encuadrado: «sin
    // lógica de datos» contesta «¿tiene lógica?», no «¿ve el mensaje?». Y lo ve:
    // `crypto-common` define `Block<B> = Array<u8, BlockSize>`, o sea que los
    // bloques del mensaje del camino AEAD SON `hybrid_array::Array`, y
    // `block-buffer` guarda su búfer como `MaybeUninit<Array<u8, BS>>` en la ruta
    // del hash. Es el tipo CONTENEDOR de los bytes en las dos rutas. Que hoy sea
    // un newtype casi transparente no vale como motivo: el modelo de amenaza es
    // una versión maliciosa, y ésa puede instrumentar `Deref`, `Index` o un `Drop`.
    ("hybrid-array", "RESIDUO REAL: es el tipo de los bloques del mensaje en las dos rutas"),
    ("typenum", "aritmética de enteros en el sistema de tipos"),
    // Estos dos MUEVEN BYTES, no son solo tipos — los miró la misma revisión.
    // Se toleran porque lo que mueven son comparaciones y selecciones de tiempo
    // constante sobre material ya derivado, no el búfer del mensaje; si alguna
    // vez entran en el camino del claro, salen de esta lista.
    ("ctutils", "primitivas de tiempo constante; no recibe el búfer del mensaje"),
    ("cmov", "movimiento condicional sin ramas; no recibe el búfer del mensaje"),
    // Plataforma y detección de CPU: no ven el búfer del mensaje.
    ("cfg-if", "macro de compilación condicional"),
    ("cpufeatures", "detección de instrucciones del procesador"),
    ("libc", "enlace al sistema"),
    ("r-efi", "objetivo UEFI; inerte en Linux"),
    // RESIDUO REAL, y estaba mal clasificado hasta el 2026-08-17: su motivo decía
    // «entropía del sistema», que es una etiqueta de categoría y no una respuesta
    // a «¿ve este paquete el mensaje?». La respuesta es que **recibe `S1` entero
    // y en claro**: `repartir` → `aleatorio::llenar` → `getrandom::fill(&mut s1)`.
    // Además lo CONTROLA, que es peor que verlo.
    ("getrandom", "RESIDUO REAL: recibe S1 entero por getrandom::fill, y lo controla"),
    ("rand_core", "traits del generador"),
];

/// CONTROL DEL INSTRUMENTO, y va primero: si el lector de `Cargo.lock` no
/// entendiera el archivo, los dos cierres saldrían vacíos, la intersección
/// también, y la prueba de abajo pasaría **sin haber mirado nada** — el negativo
/// que no distingue «limpio» de «no se ejecutó» (directiva 30).
#[test]
fn el_lector_del_lock_encuentra_las_dos_rutas() {
    let lock = Lock::leer();
    assert!(
        lock.aristas.len() > 50,
        "solo se leyeron {} paquetes de Cargo.lock: el lector está roto",
        lock.aristas.len()
    );
    // POSITIVO DE CONTROL DE LA CAUSA DEL PRIMER ROJO: el lock de quipu tiene de
    // verdad paquetes con dos versiones. Si algún día dejara de tenerlos, esta
    // prueba se cae y avisa de que el caso que motivó indexar por versión ya no
    // está representado — «no hay duplicados» y «el lector los ignora» tienen que
    // verse distinto.
    let hay_duplicados = lock.versiones.iter().any(|(_, v)| v.len() > 1);
    assert!(
        hay_duplicados,
        "ningún paquete tiene dos versiones: el caso que obliga a indexar por \
         (nombre, versión) ya no está en el árbol, y esta prueba dejó de ejercitarlo"
    );

    let cierre_aead = lock.cierre(RAICES_AEAD);
    let aead = nombres(&cierre_aead);
    // LAS DOS RAÍCES, no una. El control miraba solo `aes-gcm`, y por esa costura
    // pasaba entero el caso que la revisión midió: con el subárbol de
    // `chacha20poly1305` truncado, todo seguía verde.
    let cierre_chacha = lock.cierre(&[RAICES_AEAD[1]]);
    let chacha = nombres(&cierre_chacha);
    for c in ["chacha20", "poly1305", "aead", "cipher", "inout"] {
        assert!(
            chacha.contains(c),
            "«{c}» no está en el cierre de chacha20poly1305: la segunda capa no se \
             leyó entera, y un cierre truncado hace que TODO lo demás pase"
        );
    }
    let mascara = lock.cierre(RAICES_MASCARA);
    assert!(
        aead.contains("aead") && aead.contains("cipher") && aead.contains("inout"),
        "el cierre del AEAD no contiene su propio pegamento: el lector no siguió las aristas"
    );
    let m = nombres(&mascara);
    assert!(
        m.contains("hmac") && m.contains("digest"),
        "el cierre de la máscara no contiene hmac/digest"
    );
}

/// **EL INVARIANTE.** Ningún paquete nuevo puede entrar a la vez en el camino
/// del AEAD y en el de la máscara.
#[test]
fn nadie_nuevo_ve_la_mascara_y_el_mensaje_a_la_vez() {
    let lock = Lock::leer();
    // Las DOS capas, no solo la enmascarada: quien vea la máscara y CUALQUIERA
    // de las dos mitades está a un paso de la otra.
    let aead = lock.cierre(RAICES_AEAD);
    let mascara = lock.cierre(RAICES_MASCARA);

    let comunes: BTreeSet<Id> = aead.intersection(&mascara).cloned().collect();
    let interseccion: BTreeSet<&str> = nombres(&comunes);
    let tolerados: BTreeSet<&str> = TOLERADOS.iter().map(|(n, _)| *n).collect();

    let intrusos: Vec<&str> = interseccion.difference(&tolerados).copied().collect();
    assert!(
        intrusos.is_empty(),
        "paquetes NUEVOS que ven la máscara y el mensaje a la vez: {intrusos:?}\n\
         Cada uno rompe por sí solo el AND que promete `blindaje`. Audita qué hace \
         con los datos y, si de verdad no puede ver el mensaje, añádelo a TOLERADOS \
         CON SU MOTIVO — nunca a secas."
    );

    // Y LA OTRA DIRECCIÓN, que es la que impide que esta lista envejezca: un
    // tolerado que ya no está en la intersección es una excusa que sobrevivió a
    // su motivo, y una lista de excepciones que solo crece deja de discriminar.
    let fantasmas: Vec<&str> = tolerados.difference(&interseccion).copied().collect();
    assert!(
        fantasmas.is_empty(),
        "estos TOLERADOS ya no están en la intersección: {fantasmas:?} — quítalos, \
         o la lista acabará permitiendo cosas que nadie volvió a mirar"
    );
}

/// Los 14 exclusivos del camino AEAD —`aead`, `cipher` e `inout` entre ellos—
/// tienen que seguir estando FUERA del camino de la máscara.
///
/// Es la afirmación positiva que sostiene `QBL2`, y va aparte de la de arriba a
/// propósito: aquella dice «no entró nadie nuevo», que se cumpliría también si
/// el camino AEAD se vaciara. Ésta dice qué hay que seguir teniendo.
#[test]
fn el_pegamento_del_aead_sigue_sin_tocar_la_mascara() {
    let lock = Lock::leer();
    let cierre_mascara = lock.cierre(RAICES_MASCARA);
    let mascara = nombres(&cierre_mascara);
    let cierre_aead = lock.cierre(RAICES_AEAD);
    // EXACTAMENTE los que el cierre dice que son exclusivos, calculados aquí en
    // vez de escritos: un literal se puede recortar a `["aes"]` y la prueba
    // seguía verde. Y de paso caza que entre uno nuevo sin que nadie lo mire.
    let calculados: BTreeSet<&str> = nombres(&cierre_aead)
        .difference(&mascara)
        .copied()
        .collect();
    let declarados: BTreeSet<&str> = EXCLUSIVOS_AEAD.iter().copied().collect();
    assert_eq!(
        calculados, declarados,
        "la lista de exclusivos del camino AEAD ya no es la que dice `EXCLUSIVOS_AEAD`"
    );
    for c in EXCLUSIVOS_AEAD {
        assert!(
            !mascara.contains(c),
            "«{c}» entró en el camino del HKDF: ahora ve la máscara Y el mensaje, y el \
             reparto de `blindaje` deja de ser un AND"
        );
    }
}
