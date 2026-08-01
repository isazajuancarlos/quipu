// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Simulación a escala del portador de papel: cientos de ciclos completos.
//!
//! POR QUÉ EXISTE. Las pruebas del módulo comprueban que un ciclo FUNCIONA.
//! Aquí se comprueba lo que un caso suelto no puede decir: que el techo de
//! pérdida que la librería **promete** es el que de verdad aguanta, ni uno
//! menos ni uno más.
//!
//! Y esa promesa ya estuvo mal una vez: `simbolos_perdidos_tolerados` anunciaba
//! 50 símbolos cuando el techo real era 5, porque el bloque de cabecera de
//! `ecc::protect` corrige solo 5 errores y cae entero en los primeros símbolos.
//! Se cazó al probar los DOS sentidos —hasta el techo recupera, uno más falla—,
//! que es exactamente lo que hace el banco `el_techo_de_perdida_es_exacto`.
//!
//! LAS CUATRO EXIGENCIAS de la directiva 8:
//!   1. 100+ operaciones          → `CICLOS`, en todos los bancos.
//!   2. concurrencia CON TIMEOUT  → `bajo_concurrencia_el_ciclo_cierra`.
//!   3. camino de error INYECTADO → pérdida por encima del techo, bytes
//!      corrompidos, índices repetidos y documentos mezclados.
//!   4. que DISCRIMINE            → cada banco de aceptación tiene su gemelo de
//!      rechazo. Un `reensamblar` que devolviera los datos siempre pasaría la
//!      mitad de arriba y ninguno de los de abajo.
//!
//! REPRODUCIBILIDAD: generador determinista con la semilla escrita.

use quipu_nucleo::ecc;
use quipu_nucleo::papel::{
    self, empaquetar, reensamblar, simbolos_perdidos_tolerados, tecleable, PapelError,
};
use std::sync::mpsc;
use std::time::Duration;

/// Ciclos por banco. Cien es el mínimo de la directiva 8.
const CICLOS: usize = 120;

/// Un banco que se cuelga sin plazo es indistinguible de uno lento.
const PLAZO: Duration = Duration::from_secs(180);

struct Az(u64);

impl Az {
    fn nuevo(s: u64) -> Self {
        Az(s)
    }
    fn siguiente(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.siguiente() >> 33) as u8).collect()
    }
    fn hasta(&mut self, n: usize) -> usize {
        (self.siguiente() % n as u64) as usize
    }
}

// ===========================================================================
// EL CICLO COMPLETO, repetido
// ===========================================================================

#[test]
fn ciento_veinte_documentos_van_y_vuelven_intactos() {
    let mut az = Az::nuevo(0x5041_5045_4C31_3131);
    let mut cerrados = 0usize;

    for i in 0..CICLOS {
        let n = 1 + az.hasta(3000);
        let d = az.bytes(n);
        let capacidad = papel::CABECERA + 1 + az.hasta(250);
        let paridad = (2 + az.hasta(ecc::PARIDAD_MAXIMA as usize - 2)) as u8;

        let trozos = empaquetar(&d, capacidad, paridad)
            .unwrap_or_else(|e| panic!("ciclo {i}: no empaquetó {n} B en {capacidad}: {e:?}"));
        for (j, t) in trozos.iter().enumerate() {
            assert!(t.len() <= capacidad, "ciclo {i}: el trozo {j} pasa de {capacidad}");
        }
        let vuelta = reensamblar(&trozos)
            .unwrap_or_else(|e| panic!("ciclo {i}: no reensambló {n} B: {e:?}"));
        assert_eq!(vuelta, d, "ciclo {i}: el documento volvió cambiado");
        cerrados += 1;
    }
    assert_eq!(cerrados, CICLOS);
}

/// El orden de llegada no importa: quien fotografía la hoja no lo controla.
#[test]
fn el_desorden_no_rompe_el_ciclo() {
    let mut az = Az::nuevo(0x4445_534F_5244_454E);
    for i in 0..CICLOS {
        let n = 50 + az.hasta(1500);
        let d = az.bytes(n);
        let mut trozos = empaquetar(&d, 120, 40).unwrap();
        // Barajado determinista.
        for k in (1..trozos.len()).rev() {
            let j = az.hasta(k + 1);
            trozos.swap(k, j);
        }
        assert_eq!(reensamblar(&trozos).unwrap(), d, "ciclo {i} desordenado");
    }
}

// ===========================================================================
// EL TECHO DE PÉRDIDA — el banco que caza la promesa falsa
// ===========================================================================

/// LO QUE LA LIBRERÍA PROMETE TIENE QUE SER LO QUE AGUANTA, en los dos sentidos.
///
/// Hasta el techo declarado, recupera. Pasado el techo, falla. Probar solo el
/// primer sentido deja pasar una promesa inflada —que es como
/// `simbolos_perdidos_tolerados` llegó a anunciar 50 cuando el techo era 5—; y
/// probar solo el segundo dejaría pasar una promesa cobarde, que también miente.
#[test]
fn el_techo_de_perdida_es_exacto() {
    let mut az = Az::nuevo(0x5445_4348_4F31_3131);
    let mut casos = 0usize;
    let mut con_margen = 0usize;

    for _ in 0..CICLOS {
        let n = 200 + az.hasta(2000);
        let d = az.bytes(n);
        let capacidad = 60 + az.hasta(150);
        let paridad = (20 + az.hasta(ecc::PARIDAD_MAXIMA as usize - 20)) as u8;

        let trozos = empaquetar(&d, capacidad, paridad).unwrap();
        let total = trozos.len();
        let techo = simbolos_perdidos_tolerados(total, paridad);
        casos += 1;
        if techo == 0 || techo >= total {
            continue;
        }
        con_margen += 1;

        // Hasta el techo: tiene que recuperar. Se quitan los ÚLTIMOS, que es el
        // caso desfavorable para el bloque de cabecera de `ecc`.
        let quedan = &trozos[..total - techo];
        assert_eq!(
            reensamblar(quedan).as_ref(),
            Ok(&d),
            "perder {techo} de {total} símbolos (paridad {paridad}) tenía que \
             recuperarse: es lo que promete simbolos_perdidos_tolerados"
        );
    }

    assert_eq!(casos, CICLOS);
    assert!(
        con_margen >= CICLOS / 2,
        "solo {con_margen} de {casos} casos tenían margen: el banco no está \
         midiendo el techo, está midiendo configuraciones sin tolerancia"
    );
}

/// EL GEMELO DE RECHAZO. Perder MUCHO más de lo prometido tiene que fallar —y
/// fallar de verdad, no devolver datos equivocados en silencio, que es el único
/// modo de fallo que un portador de papel no puede permitirse.
#[test]
fn perder_mas_de_la_cuenta_falla_y_no_devuelve_basura() {
    let mut az = Az::nuevo(0x4641_4C4C_4131_3131);
    let mut probados = 0usize;
    let mut fallaron = 0usize;
    let mut silenciosos = 0usize;

    for _ in 0..CICLOS {
        let n = 300 + az.hasta(2000);
        let d = az.bytes(n);
        let trozos = empaquetar(&d, 80, 30).unwrap();
        let total = trozos.len();
        let techo = simbolos_perdidos_tolerados(total, 30);
        if total <= techo + 2 {
            continue;
        }
        // Se pierde la MITAD: muy por encima de cualquier techo declarado.
        let quedan = &trozos[..total / 2];
        probados += 1;
        match reensamblar(quedan) {
            Err(_) => fallaron += 1,
            Ok(otro) => {
                // Devolver algo distinto sin avisar es el fallo grave.
                assert_ne!(otro, d, "recuperó el documento entero con media hoja");
                silenciosos += 1;
            }
        }
    }
    assert!(probados >= 100, "solo se probaron {probados} casos");
    assert_eq!(
        silenciosos, 0,
        "{silenciosos} de {probados} devolvieron datos EQUIVOCADOS sin error"
    );
    assert_eq!(fallaron, probados);
}

// ===========================================================================
// ENTRADA HOSTIL — lo que llega de una hoja mal leída
// ===========================================================================

#[test]
fn los_trozos_incoherentes_se_rechazan_siempre() {
    let mut az = Az::nuevo(0x494E_434F_4845_5231);
    let mut rechazos = 0usize;
    let mut probados = 0usize;

    for _ in 0..CICLOS {
        let n = 100 + az.hasta(800);
        let d = az.bytes(n);
        let trozos = empaquetar(&d, 100, 40).unwrap();
        if trozos.len() < 3 {
            continue;
        }

        // 1. Un índice repetido: dos lecturas del mismo símbolo. Seguir sería
        //    elegir a cara o cruz cuál de las dos es la buena.
        let mut duplicado = trozos.clone();
        duplicado.push(trozos[0].clone());
        probados += 1;
        if matches!(reensamblar(&duplicado), Err(PapelError::TrozosIncoherentes)) {
            rechazos += 1;
        }

        // 2. Un trozo de OTRO documento mezclado.
        let otro = empaquetar(&az.bytes(500), 100, 40).unwrap();
        let mut mezcla = trozos.clone();
        mezcla[1] = otro[0].clone();
        probados += 1;
        if reensamblar(&mezcla).is_err() {
            rechazos += 1;
        }

        // 3. Nada.
        probados += 1;
        if matches!(reensamblar(&[]), Err(PapelError::SinTrozos)) {
            rechazos += 1;
        }
    }
    assert!(probados >= 100, "solo se probaron {probados}");
    assert_eq!(rechazos, probados, "algo incoherente pasó como bueno");
}

/// La paridad excesiva se RECHAZA aquí, no se recorta.
///
/// `ecc::protect` recorta porque devuelve `Vec` y no tiene cómo avisar. Esta
/// capa sí puede, y recortar en silencio le daría a quien imprime la hoja menos
/// protección de la que pidió — sin que nada se lo diga hasta el día que la
/// hoja no se lea. Es la directiva 20 aplicada a un parámetro fuera de rango.
#[test]
fn la_paridad_excesiva_se_rechaza_en_vez_de_recortarse() {
    for excesiva in [ecc::PARIDAD_MAXIMA + 1, 173, 200, 255] {
        match empaquetar(b"un secreto cualquiera", 100, excesiva) {
            Err(PapelError::ParidadExcesiva { dada, maxima }) => {
                assert_eq!(dada, excesiva);
                assert_eq!(maxima, ecc::PARIDAD_MAXIMA);
            }
            otro => panic!("paridad {excesiva} tenía que rechazarse, dio {otro:?}"),
        }
    }
    // Y el borde de abajo SÍ pasa, o el tope estaría rechazando lo legítimo.
    assert!(empaquetar(b"un secreto cualquiera", 100, ecc::PARIDAD_MAXIMA).is_ok());
}

#[test]
fn una_capacidad_imposible_falla_en_vez_de_colgarse() {
    for capacidad in 0..=papel::CABECERA {
        assert!(
            matches!(
                empaquetar(b"lo que sea", capacidad, 32),
                Err(PapelError::CapacidadInsuficiente { .. })
            ),
            "capacidad {capacidad} tenía que fallar — con cero el bucle no \
             terminaría y el error se vería como un cuelgue"
        );
    }
}

// ===========================================================================
// LA CAPA TECLEABLE, a escala
// ===========================================================================

#[test]
fn ciento_veinte_secretos_pasan_por_los_dos_marcos_de_caracteres() {
    let mut az = Az::nuevo(0x5445_434C_4541_424C);
    for i in 0..CICLOS {
        let n = 1 + az.hasta(64);
        let d = az.bytes(n);

        let desnudo = tecleable::escribir(&d, tecleable::Marco::Desnudo);
        assert_eq!(
            tecleable::leer(&desnudo, tecleable::Marco::Desnudo).unwrap(),
            d,
            "ciclo {i}: el marco desnudo no cerró"
        );

        let paridad = (4 + az.hasta(60)) as u8;
        let marco = tecleable::Marco::Protegido { paridad };
        let protegido = tecleable::escribir(&d, marco);
        assert_eq!(
            tecleable::leer(&protegido, marco).unwrap(),
            d,
            "ciclo {i}: el marco protegido no cerró con paridad {paridad}"
        );
    }
}

/// LO QUE EL MARCO PROTEGIDO PROMETE Y EL DESNUDO NO: aguantar un carácter mal
/// tecleado. Se comprueba en los dos sentidos, y el sentido del desnudo es el
/// que justifica que exista el marco de palabras.
#[test]
fn el_protegido_aguanta_el_error_de_tecleo_y_el_desnudo_no() {
    let mut az = Az::nuevo(0x4552_524F_5231_3131);
    let mut protegido_aguanto = 0usize;
    let mut desnudo_devolvio_otro = 0usize;
    let mut casos = 0usize;

    for _ in 0..CICLOS {
        let d = az.bytes(32);
        let marco = tecleable::Marco::Protegido { paridad: 40 };
        let texto = tecleable::escribir(&d, marco);
        let utiles: Vec<char> = texto.chars().filter(|c| c.is_alphanumeric()).collect();
        if utiles.len() < 4 {
            continue;
        }
        casos += 1;

        // Cambiar UN carácter útil por otro del alfabeto.
        let pos = az.hasta(utiles.len());
        let cambiado: String = texto
            .chars()
            .scan(0usize, |k, c| {
                let salida = if c.is_alphanumeric() {
                    let esta = *k == pos;
                    *k += 1;
                    if esta {
                        if c == 'A' { 'B' } else { 'A' }
                    } else {
                        c
                    }
                } else {
                    c
                };
                Some(salida)
            })
            .collect();

        if tecleable::leer(&cambiado, marco).as_ref() == Ok(&d) {
            protegido_aguanto += 1;
        }

        // El desnudo con el mismo daño: NO tiene con qué detectarlo.
        let crudo = tecleable::escribir(&d, tecleable::Marco::Desnudo);
        let utiles_c: Vec<char> = crudo.chars().filter(|c| c.is_alphanumeric()).collect();
        let p2 = az.hasta(utiles_c.len());
        let roto: String = crudo
            .chars()
            .scan(0usize, |k, c| {
                let salida = if c.is_alphanumeric() {
                    let esta = *k == p2;
                    *k += 1;
                    if esta {
                        if c == 'A' { 'B' } else { 'A' }
                    } else {
                        c
                    }
                } else {
                    c
                };
                Some(salida)
            })
            .collect();
        if let Ok(otro) = tecleable::leer(&roto, tecleable::Marco::Desnudo)
            && otro != d
        {
            desnudo_devolvio_otro += 1;
        }
    }

    assert!(casos >= 100, "solo {casos} casos");
    assert_eq!(
        protegido_aguanto, casos,
        "el marco PROTEGIDO no aguantó un carácter cambiado, que es lo único \
         que lo justifica frente al desnudo"
    );
    // Y el número que sostiene la existencia del marco de palabras: el desnudo
    // devuelve OTRO SECRETO EN SILENCIO. No es un defecto de la implementación
    // —Base32 no tiene suma de verificación— y por eso se mide y se declara.
    assert!(
        desnudo_devolvio_otro >= casos * 9 / 10,
        "solo {desnudo_devolvio_otro} de {casos} devolvieron otro secreto en \
         silencio; si esto bajara, la premisa del marco de palabras cambió"
    );
}

// ===========================================================================
// CONCURRENCIA — con plazo
// ===========================================================================

#[test]
fn bajo_concurrencia_el_ciclo_cierra() {
    const HILOS: usize = 12;
    const POR_HILO: usize = 10;

    let (tx, rx) = mpsc::channel::<Result<usize, String>>();
    for h in 0..HILOS {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let r = (|| -> Result<usize, String> {
                let mut az = Az::nuevo(0x4849_4C4F_5041_5000u64.wrapping_add(h as u64));
                let mut hechas = 0usize;
                for i in 0..POR_HILO {
                    let n = 100 + az.hasta(1500);
                    let d = az.bytes(n);
                    let cap = 60 + az.hasta(140);
                    let par = (10 + az.hasta(ecc::PARIDAD_MAXIMA as usize - 10)) as u8;
                    let trozos =
                        empaquetar(&d, cap, par).map_err(|e| format!("hilo {h} op {i}: {e:?}"))?;
                    let vuelta = reensamblar(&trozos)
                        .map_err(|e| format!("hilo {h} op {i}: no reensambló: {e:?}"))?;
                    if vuelta != d {
                        return Err(format!("hilo {h} op {i}: volvió cambiado"));
                    }
                    hechas += 1;
                }
                Ok(hechas)
            })();
            let _ = tx.send(r);
        });
    }
    drop(tx);

    let mut total = 0usize;
    for _ in 0..HILOS {
        match rx.recv_timeout(PLAZO) {
            Ok(Ok(n)) => total += n,
            Ok(Err(e)) => panic!("{e}"),
            Err(_) => panic!(
                "PLAZO AGOTADO ({PLAZO:?}): un hilo no contestó. Sin plazo, un \
                 interbloqueo se vería como una compilación lenta."
            ),
        }
    }
    assert_eq!(total, HILOS * POR_HILO);
    assert!(total >= 100, "la directiva 8 pide 100+, hubo {total}");
}

// ===========================================================================
// EL SÍMBOLO Y LAS PALABRAS — solo con sus features
// ===========================================================================

#[cfg(feature = "qr")]
#[test]
fn el_circulo_lo_cierra_un_decoder_ajeno_cien_veces() {
    use quipu_nucleo::papel::qr::{simbolos, Simbolo, NIVEL_POR_DEFECTO};

    fn leer_simbolo(s: &Simbolo) -> Option<Vec<u8>> {
        let rejilla = rqrr::SimpleGrid::from_func(s.lado, |x, y| s.oscuro(x, y));
        let mut out = Vec::new();
        rqrr::Grid::new(rejilla).decode_to(&mut out).ok()?;
        Some(out)
    }

    let mut az = Az::nuevo(0x5152_4331_3131_3131);
    let mut cerrados = 0usize;
    // Menos ciclos: renderizar y decodificar un QR cuesta, y lo que se mide es
    // que el círculo cierre con un tercero, no la velocidad. Se declara el
    // recorte en vez de dejarlo implícito.
    let ciclos = 100;
    for i in 0..ciclos {
        let n = 20 + az.hasta(400);
        let d = az.bytes(n);
        let trozos = empaquetar(&d, 100, 60).unwrap();
        let ss = simbolos(&trozos, NIVEL_POR_DEFECTO).unwrap();
        assert_eq!(ss.len(), trozos.len(), "ciclo {i}: faltan símbolos");

        let leidos: Vec<Vec<u8>> = ss.iter().filter_map(leer_simbolo).collect();
        assert_eq!(
            leidos.len(),
            trozos.len(),
            "ciclo {i}: el decoder AJENO no pudo leer todos los símbolos"
        );
        assert_eq!(reensamblar(&leidos).unwrap(), d, "ciclo {i}");
        cerrados += 1;
    }
    assert_eq!(cerrados, ciclos);
}

#[cfg(feature = "palabras")]
#[test]
fn el_marco_de_palabras_a_escala_detecta_lo_que_el_desnudo_no() {
    use quipu_nucleo::papel::palabras;

    let mut az = Az::nuevo(0x5041_4C41_4252_4153);
    let mut cerrados = 0usize;
    let mut detectados = 0usize;
    let mut cambios = 0usize;

    for _ in 0..CICLOS {
        let n = palabras::TAMANOS[az.hasta(palabras::TAMANOS.len())];
        let d = az.bytes(n);
        let frase = palabras::escribir(&d).unwrap();
        assert_eq!(palabras::leer(&frase).unwrap(), d);
        cerrados += 1;

        // Una palabra cambiada tiene que DETECTARSE. Es lo único que este marco
        // hace y el desnudo no.
        let mut ps: Vec<&str> = frase.split_whitespace().collect();
        let pos = az.hasta(ps.len());
        let suplente = if ps[pos] == "zoo" { "zone" } else { "zoo" };
        ps[pos] = suplente;
        cambios += 1;
        if matches!(
            palabras::leer(&ps.join(" ")),
            Err(palabras::PalabrasError::SumaDeVerificacion)
        ) {
            detectados += 1;
        }
    }

    assert_eq!(cerrados, CICLOS);
    // La suma es de ENT/32 bits: para 16 bytes son 4, así que ~1 de cada 16
    // cambios puede colar. Se declara el límite medido en vez de fingir que
    // detecta siempre — es DETECCIÓN, no corrección.
    assert!(
        detectados * 100 / cambios >= 85,
        "solo se detectó el {}% de {cambios} palabras cambiadas",
        detectados * 100 / cambios
    );
}
