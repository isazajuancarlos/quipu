// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

//! Laboratorio contra la **conversación con el custodio**: reenvío, degradación
//! y carrera.
//!
//! El arma no viaja con el producto: todo esto vive tras `#[cfg(feature = "lab")]`.
//!
//! # Qué se ataca
//!
//! [`crate::firmante::firmar`] conversa con un [`Custodio`] en tres pasos: lee la
//! clave de verificación, arma la preimagen `(vk ‖ etiqueta ‖ mensaje)`, y pide
//! las dos mitades de la firma (Ed25519 y ML-DSA-87). El custodio puede ser un
//! HSM al otro lado de una FFI, o un servicio en otra máquina: **la conversación
//! es superficie de ataque**, y un dispositivo comprometido, con fallo de
//! hardware, o un intermediario en el canal PKCS#11 pueden manipular las
//! respuestas. Tres formas concretas:
//!
//! - **Reenvío**: devolver una mitad VÁLIDA pero de OTRA preimagen (una firma
//!   capturada antes). La longitud cuadra; el mensaje no.
//! - **Degradación**: devolver una mitad fuerte y la otra basura (o débil), para
//!   colar un «híbrido» que en realidad se apoya en un solo algoritmo — justo lo
//!   que el combinador AND existe para impedir.
//! - **Carrera**: cambiar la clave activa ENTRE que `firmar` lee la vk y pide las
//!   mitades (TOCTOU), de modo que la preimagen ata una identidad y la firma la
//!   produce otra.
//!
//! # La propiedad dura, y la de defensa en profundidad
//!
//! 1. **Ninguna firma manipulada puede VERIFICAR** bajo la vk honesta. Esto ya lo
//!    garantizan la etiqueta de dominio y el combinador AND, pase lo que pase con
//!    el custodio. Es el mínimo no negociable ([`InformeCustodio::sin_forja`]).
//! 2. **`firmar` debería fallar CERRADO en el origen** en vez de devolver una
//!    firma inválida como `Ok`: una firma que solo se descubre inválida cuando un
//!    tercero la verifica, lejos del dispositivo que la produjo, es el mismo modo
//!    de fallo que la comprobación de longitud ya evita para las cortas
//!    ([`InformeCustodio::falla_cerrado`]).

use crate::firmante::{firmar, Custodio, ErrorDeFirma, Preimagen};
use crate::pqsign::{SigningKey, VerifyingKey, ED25519_SIG_LEN, MLDSA_SIG_LEN};
use std::sync::Mutex;

/// Resultado de atacar la conversación con el custodio, contando qué pasó.
#[derive(Debug)]
pub struct InformeCustodio {
    /// Nombre del ataque.
    pub ataque: &'static str,
    /// Intentos realizados.
    pub intentos: usize,
    /// **Propiedad dura**: firmas manipuladas que aun así VERIFICARON bajo la vk
    /// honesta. Tiene que ser 0 SIEMPRE — un solo caso es una forja real.
    pub verificaron: usize,
    /// `firmar` falló cerrado con la guarda concreta [`ErrorDeFirma::FirmaNoVerifica`].
    pub cazadas_por_no_verifica: usize,
    /// `firmar` falló con OTRO error (longitud, custodio caído): también es
    /// cerrado, pero por otra vía; se cuenta aparte para no confundir cuál guarda
    /// disparó (D33).
    pub cazadas_otro_error: usize,
    /// `firmar` devolvió `Ok` una firma que NO verifica **bajo la vk que el
    /// custodio DECLARÓ**: el fallo viaja aguas abajo. Ojo (D32): esto es
    /// «inválida bajo la vk declarada» (culpa de `firmar`); es distinto de
    /// «inválida bajo la vk ESPERADA por el llamante» (que sería culpa de no
    /// fijar identidad, y `firmar` no la conoce — eso lo cierra `decode_verified`
    /// con una vk fijada, no este parche).
    pub paso_invalida_como_ok: usize,
}

impl InformeCustodio {
    fn nuevo(ataque: &'static str) -> Self {
        Self {
            ataque,
            intentos: 0,
            verificaron: 0,
            cazadas_por_no_verifica: 0,
            cazadas_otro_error: 0,
            paso_invalida_como_ok: 0,
        }
    }

    /// El mínimo no negociable: nada se forjó.
    pub fn sin_forja(&self) -> bool {
        self.verificaron == 0
    }

    /// Defensa en profundidad: cada intento se detuvo al firmar, ninguno pasó
    /// como `Ok` con firma inválida.
    pub fn falla_cerrado(&self) -> bool {
        self.paso_invalida_como_ok == 0
    }

    fn evaluar(&mut self, r: Result<Vec<u8>, ErrorDeFirma>, vk: &VerifyingKey, mensaje: &[u8]) {
        self.intentos += 1;
        match r {
            // La guarda del parche, nombrada (D33): ata el rojo a ESTA guarda y no
            // a «algo falló».
            Err(ErrorDeFirma::FirmaNoVerifica) => self.cazadas_por_no_verifica += 1,
            Err(_) => self.cazadas_otro_error += 1,
            Ok(f) => {
                if vk.verify(mensaje, &f) {
                    self.verificaron += 1;
                } else {
                    self.paso_invalida_como_ok += 1;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Custodio 1 — REENVÍO: cachea las mitades de la primera preimagen y las
// reenvía para cualquier otra. Longitud correcta, mensaje equivocado.
// ---------------------------------------------------------------------------

struct Reenviador {
    sk: SigningKey,
    cache: Mutex<Option<(Vec<u8>, Vec<u8>)>>,
}

impl Custodio for Reenviador {
    fn clave_de_verificacion(&self) -> Result<VerifyingKey, ErrorDeFirma> {
        Ok(self.sk.verifying_key())
    }
    fn firmar_ed25519(&self, p: &Preimagen) -> Result<Vec<u8>, ErrorDeFirma> {
        let mut c = self.cache.lock().unwrap();
        if let Some((ed, _)) = c.as_ref() {
            return Ok(ed.clone()); // REENVÍO de la mitad capturada
        }
        let ed = self.sk.firmar_ed25519_crudo(p.como_bytes());
        let ml = self.sk.firmar_mldsa_crudo(p.como_bytes());
        *c = Some((ed.clone(), ml));
        Ok(ed)
    }
    fn firmar_mldsa(&self, p: &Preimagen) -> Result<Vec<u8>, ErrorDeFirma> {
        let c = self.cache.lock().unwrap();
        if let Some((_, ml)) = c.as_ref() {
            return Ok(ml.clone()); // reenvío (o la mitad legítima de la 1.ª ronda)
        }
        drop(c);
        Ok(self.sk.firmar_mldsa_crudo(p.como_bytes()))
    }
}

// ---------------------------------------------------------------------------
// Custodio 2 — DEGRADACIÓN: una mitad honesta, la otra basura (ceros de la
// longitud correcta). Intenta que el "híbrido" se apoye en un solo algoritmo.
// ---------------------------------------------------------------------------

/// Qué mitad se debilita.
#[derive(Clone, Copy)]
enum Mitad {
    Ed,
    Ml,
}

struct Degradador {
    sk: SigningKey,
    debil: Mitad,
}

impl Custodio for Degradador {
    fn clave_de_verificacion(&self) -> Result<VerifyingKey, ErrorDeFirma> {
        Ok(self.sk.verifying_key())
    }
    fn firmar_ed25519(&self, p: &Preimagen) -> Result<Vec<u8>, ErrorDeFirma> {
        match self.debil {
            Mitad::Ed => Ok(vec![0u8; ED25519_SIG_LEN]), // basura de longitud válida
            Mitad::Ml => Ok(self.sk.firmar_ed25519_crudo(p.como_bytes())),
        }
    }
    fn firmar_mldsa(&self, p: &Preimagen) -> Result<Vec<u8>, ErrorDeFirma> {
        match self.debil {
            Mitad::Ml => Ok(vec![0u8; MLDSA_SIG_LEN]),
            Mitad::Ed => Ok(self.sk.firmar_mldsa_crudo(p.como_bytes())),
        }
    }
}

// ---------------------------------------------------------------------------
// Custodio 3 — CARRERA: la clave activa cambia ENTRE leer la vk y firmar. La
// preimagen ata la identidad A; las mitades las produce la identidad B.
// ---------------------------------------------------------------------------

struct Corredor {
    a: SigningKey,
    b: SigningKey,
    cambiada: Mutex<bool>,
}

impl Custodio for Corredor {
    fn clave_de_verificacion(&self) -> Result<VerifyingKey, ErrorDeFirma> {
        // Se lee A; el atacante cambia la clave activa justo después (TOCTOU).
        *self.cambiada.lock().unwrap() = true;
        Ok(self.a.verifying_key())
    }
    fn firmar_ed25519(&self, p: &Preimagen) -> Result<Vec<u8>, ErrorDeFirma> {
        let con_b = *self.cambiada.lock().unwrap();
        let k = if con_b { &self.b } else { &self.a };
        Ok(k.firmar_ed25519_crudo(p.como_bytes()))
    }
    fn firmar_mldsa(&self, p: &Preimagen) -> Result<Vec<u8>, ErrorDeFirma> {
        let con_b = *self.cambiada.lock().unwrap();
        let k = if con_b { &self.b } else { &self.a };
        Ok(k.firmar_mldsa_crudo(p.como_bytes()))
    }
}

// ---------------------------------------------------------------------------
// Custodio 4 — FRANKENSIG: la mitad más afilada del reenvío. La mitad Ed25519 es
// VÁLIDA pero de OTRA preimagen; la mitad ML-DSA es fresca y correcta de ESTE
// mensaje. Las dos tienen la longitud del algoritmo, así que la comprobación de
// longitud no las caza: solo el verificar-tras-firmar, porque el combinador ata
// cada mitad a la preimagen de ESTE mensaje. (Sugerido por el concilio, D33.)
// ---------------------------------------------------------------------------

struct Frankensig {
    sk: SigningKey,
}

impl Custodio for Frankensig {
    fn clave_de_verificacion(&self) -> Result<VerifyingKey, ErrorDeFirma> {
        Ok(self.sk.verifying_key())
    }
    fn firmar_ed25519(&self, _p: &Preimagen) -> Result<Vec<u8>, ErrorDeFirma> {
        // Ed25519 válida, pero sobre OTROS bytes (no la preimagen de este mensaje).
        Ok(self.sk.firmar_ed25519_crudo(b"quipu/lab/frankensig/otra-preimagen"))
    }
    fn firmar_mldsa(&self, p: &Preimagen) -> Result<Vec<u8>, ErrorDeFirma> {
        Ok(self.sk.firmar_mldsa_crudo(p.como_bytes()))
    }
}

/// Corre los ataques `rondas` veces cada uno y devuelve un informe por ataque.
///
/// La vk honesta con la que se comprueba «¿verificó?» es SIEMPRE la que el
/// custodio dice representar (identidad A en la carrera): forjar es hacer que una
/// firma manipulada verifique bajo ESA.
pub fn atacar_conversacion_custodio(rondas: usize) -> Vec<InformeCustodio> {
    let mut informes = Vec::new();

    // --- Reenvío ---
    let mut inf = InformeCustodio::nuevo("reenvio");
    for i in 0..rondas {
        let (_vk, sk) = crate::pqsign::generate_keypair();
        let vk = sk.verifying_key();
        let reenv = Reenviador { sk, cache: Mutex::new(None) };
        // 1.ª firma: siembra la caché (honesta). No se cuenta como ataque.
        let _ = firmar(&reenv, b"mensaje-semilla");
        // 2.ª firma de OTRO mensaje: el custodio reenvía las mitades de la 1.ª.
        let objetivo = format!("acta-{i}");
        inf.evaluar(firmar(&reenv, objetivo.as_bytes()), &vk, objetivo.as_bytes());
    }
    informes.push(inf);

    // --- Frankensig: mitad ed de otra preimagen + mitad ml de esta ---
    let mut inf = InformeCustodio::nuevo("frankensig");
    for i in 0..rondas {
        let (_vk, sk) = crate::pqsign::generate_keypair();
        let vk = sk.verifying_key();
        let frank = Frankensig { sk };
        let objetivo = format!("frank-{i}");
        inf.evaluar(firmar(&frank, objetivo.as_bytes()), &vk, objetivo.as_bytes());
    }
    informes.push(inf);

    // --- Degradación, en las dos direcciones ---
    for (nombre, debil) in [("degradacion-ml", Mitad::Ml), ("degradacion-ed", Mitad::Ed)] {
        let mut inf = InformeCustodio::nuevo(nombre);
        for i in 0..rondas {
            let (_vk, sk) = crate::pqsign::generate_keypair();
            let vk = sk.verifying_key();
            let deg = Degradador { sk, debil };
            let objetivo = format!("orden-{i}");
            inf.evaluar(firmar(&deg, objetivo.as_bytes()), &vk, objetivo.as_bytes());
        }
        informes.push(inf);
    }

    // --- Carrera (TOCTOU determinista) ---
    let mut inf = InformeCustodio::nuevo("carrera");
    for i in 0..rondas {
        let (_va, a) = crate::pqsign::generate_keypair();
        let (_vb, b) = crate::pqsign::generate_keypair();
        let vk_a = a.verifying_key();
        let corr = Corredor { a, b, cambiada: Mutex::new(false) };
        let objetivo = format!("giro-{i}");
        // Se comprueba contra la vk que el custodio DECLARÓ (A): forjar es que la
        // firma —producida por B— verifique bajo A.
        inf.evaluar(firmar(&corr, objetivo.as_bytes()), &vk_a, objetivo.as_bytes());
    }
    informes.push(inf);

    informes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firmante::EnMemoria;
    use std::sync::Arc;

    /// PROPIEDAD DURA: ninguna conversación adversaria produce una firma que
    /// verifique bajo la vk honesta. Se cumple SIEMPRE (etiqueta de dominio + AND),
    /// haya o no defensa en profundidad en `firmar`.
    #[test]
    fn ninguna_conversacion_adversaria_forja() {
        for inf in atacar_conversacion_custodio(64) {
            assert!(inf.intentos > 0, "{}: el ataque no intentó nada", inf.ataque);
            assert!(
                inf.sin_forja(),
                "{}: {} firma(s) manipulada(s) VERIFICARON — forja real",
                inf.ataque,
                inf.verificaron
            );
        }
    }

    /// CONTROL que discrimina (D33): un custodio HONESTO pasa el mismo arnés con
    /// `Ok` y su firma VERIFICA. Sin esto, un `firmar` que siempre fallara pasaría
    /// las pruebas de «no forja» y de «falla cerrado» estando ciego.
    #[test]
    fn custodio_honesto_verifica() {
        let (vk, sk) = crate::pqsign::generate_keypair();
        let honesto = EnMemoria::nuevo(sk);
        let mensaje = b"acta legitima";
        let firma = firmar(&honesto, mensaje).expect("el honesto firma");
        assert!(vk.verify(mensaje, &firma), "la firma honesta tiene que verificar");
    }

    /// DEFENSA EN PROFUNDIDAD: `firmar` falla CERRADO ante los tres ataques, en
    /// vez de devolver una firma inválida como `Ok`. Antes del endurecimiento
    /// esta prueba se pone ROJA (las firmas inválidas pasan como Ok); es la que
    /// motiva el arreglo.
    #[test]
    fn firmar_falla_cerrado_ante_custodio_adversario() {
        for inf in atacar_conversacion_custodio(64) {
            assert!(
                inf.falla_cerrado(),
                "{}: {} firma(s) inválida(s) pasaron como Ok — el fallo viaja aguas abajo",
                inf.ataque,
                inf.paso_invalida_como_ok
            );
            // D33: atar el rojo a LA guarda del parche, no a «algo falló».
            assert_eq!(
                inf.cazadas_por_no_verifica, inf.intentos,
                "{}: se esperaba que los {} intentos se cazaran con FirmaNoVerifica; \
                 cazadas_por_no_verifica={}, otro_error={}",
                inf.ataque, inf.intentos, inf.cazadas_por_no_verifica, inf.cazadas_otro_error
            );
        }
    }

    /// D8: la carrera bajo CONCURRENCIA real. Muchos hilos comparten un custodio
    /// cuya clave gira; ninguna firma devuelta debe verificar bajo una identidad
    /// que no la produjo, y con el endurecimiento `firmar` falla cerrado. Con
    /// tope de tiempo: un hilo colgado no debe disfrazarse de trabajo lento.
    #[test]
    fn carrera_concurrente_no_forja_ni_pasa_invalida() {
        use std::sync::mpsc;
        use std::time::Duration;

        let (_va, a) = crate::pqsign::generate_keypair();
        let (_vb, b) = crate::pqsign::generate_keypair();
        let vk_a = a.verifying_key();
        // La vk se lee siempre como A y el atacante deja la clave activa en B.
        let corr = Arc::new(Corredor { a, b, cambiada: Mutex::new(false) });

        let hilos = 8;
        let por_hilo = 32; // 256 operaciones concurrentes
        let (tx, rx) = mpsc::channel();
        for h in 0..hilos {
            let corr = Arc::clone(&corr);
            let vk_a = vk_a.clone();
            let tx = tx.clone();
            std::thread::spawn(move || {
                let mut verificaron = 0usize;
                let mut paso_ok = 0usize;
                let mut cazadas = 0usize;
                for i in 0..por_hilo {
                    let msg = format!("h{h}-i{i}");
                    match firmar(&*corr, msg.as_bytes()) {
                        Err(crate::firmante::ErrorDeFirma::FirmaNoVerifica) => cazadas += 1,
                        Err(_) => {} // otro error: no cuenta como cazada por la guarda
                        Ok(f) => {
                            if vk_a.verify(msg.as_bytes(), &f) {
                                verificaron += 1;
                            } else {
                                paso_ok += 1;
                            }
                        }
                    }
                }
                let _ = tx.send((verificaron, paso_ok, cazadas));
            });
        }
        drop(tx);

        let mut verificaron = 0usize;
        let mut paso_ok = 0usize;
        let mut cazadas = 0usize;
        for _ in 0..hilos {
            let (v, p, c) = rx
                .recv_timeout(Duration::from_secs(30))
                .expect("un hilo de la carrera se colgó (o pánico): sin resultado a tiempo");
            verificaron += v;
            paso_ok += p;
            cazadas += c;
        }

        assert_eq!(verificaron, 0, "carrera concurrente: {verificaron} firma(s) forjada(s)");
        // Defensa en profundidad (post-endurecimiento): todo cazado, nada inválido como Ok.
        assert_eq!(paso_ok, 0, "carrera concurrente: {paso_ok} firma(s) inválida(s) como Ok");
        assert_eq!(cazadas, hilos * por_hilo, "no todas las firmas de la carrera se cazaron");
    }
}
