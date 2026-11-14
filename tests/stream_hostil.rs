// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza

//! **Flujo `QST1` hostil**: qué pasa cuando alguien toca el contenedor entre que
//! se escribe y se lee.
//!
//! # Por qué existe, y qué medía el banco antes
//!
//! `src/stream.rs` promete cuatro resistencias —truncación, reordenamiento,
//! empalme entre archivos y manipulación— y tenía once pruebas de manipulación
//! dentro de su propio módulo. La auditoría del 2026-08-17 encontró que **las
//! once sobreviven a borrar la cabecera del AAD**, y que la que decía medir
//! justamente eso (`header_tamper_fails`) fallaba por otra vía: su mutación
//! ponía `mem_kib` fuera de rango, así que salía por la validación de
//! parámetros **antes de derivar clave y antes de tocar el AEAD**.
//!
//! Además `stream` no tenía **ninguna** prueba de corrección fuera de su módulo:
//! sin proptest, sin simulación, sin concurrencia. `tests/simulacion.rs` cubre
//! 1 200 ciclos del camino `QUIP`, ninguno del `QST1`.
//!
//! # Qué afirma este banco, exactamente
//!
//! 1. **Ninguna mutación descifra.** Cero `Ok` sobre las ~2 000 que aplica.
//! 2. **Todo byte entregado al `Write` estaba AUTENTICADO.** Ésta es la
//!    propiedad que hay que fijar y que no estaba escrita en ninguna parte: la
//!    construcción STREAM emite cada trozo en cuanto lo verifica, porque tener
//!    memoria acotada es el punto entero del modo. O sea que un truncado deja un
//!    PREFIJO de claro en el destino y devuelve `Err`. Lo que sí se puede
//!    garantizar —y se comprueba— es que ese prefijo es **exacto**: nunca sale
//!    un byte que no haya pasado por su tag.
//! 3. **El control positivo**: los contenedores intactos abren y devuelven lo
//!    que se cifró. Sin él, un `decrypt_stream` que fallara siempre pasaría los
//!    dos puntos de arriba con nota.
//!
//! # El mutante que lo valida
//!
//! Quitar la cabecera del AAD —`header_bytes` a `b""` en las seis llamadas de
//! `src/stream.rs`— pone ROJO este banco. Comprobado el 2026-08-17.
//!
//! **Y hay que decir lo que ese mutante NO demuestra.** La auditoría afirmó que
//! las once pruebas de `stream.rs` seguían verdes con el AAD quitado; con este
//! mutante no se puede confirmar, porque al tocar también el lado de CIFRADO
//! cambia el criptograma y se caen los vectores congelados por otra razón. O sea
//! que 11 rojos ahí NO refutan la afirmación del auditor ni la confirman: mide
//! otra cosa. Lo que sí queda medido, y es lo que este archivo necesita, es que
//! **este** banco distingue los dos mundos.

use std::io::Write;

use quipu::stream::{decrypt_stream, decrypt_stream_bytes, encrypt_stream_bytes, StreamOptions};
use quipu::kdf::KdfParams;

/// PRNG determinista: el fallo tiene que ser reproducible, y la semilla se
/// imprime en cada aserción para poder volver al caso exacto.
struct Rng(u64);
impl Rng {
    fn nuevo(s: u64) -> Self {
        Self(s ^ 0x9E37_79B9_7F4A_7C15)
    }
    fn siguiente(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn hasta(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.siguiente() % n as u64) as usize }
    }
}

/// Perfil barato: esto mide FORMATO, no el coste del KDF. Con el perfil real,
/// 2 000 mutaciones serían horas y el banco no correría nunca — que es la forma
/// más común de que un banco deje de medir.
fn opciones(chunk: usize) -> StreamOptions<'static> {
    StreamOptions {
        pepper: b"",
        kdf_params: KdfParams { mem_kib: 64, iterations: 1, parallelism: 1 },
        chunk_size: chunk,
    }
}

const CABECERA: usize = 57;
const TAG: usize = 16;

/// Un `Write` que cuenta lo que recibe y se lo queda.
#[derive(Default)]
struct Contador {
    datos: Vec<u8>,
}
impl Write for Contador {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.datos.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn claro_de(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 131 % 251) as u8).collect()
}

#[test]
fn ninguna_mutacion_del_flujo_descifra_y_lo_entregado_siempre_estuvo_autenticado() {
    const FRASE: &str = "la contraseña del banco";
    let chunk = 4096usize;
    let bloque = chunk + TAG;

    // Tamaños elegidos por los BORDES del bucle de `decrypt_stream`, no al azar:
    // vacío, un byte, justo antes del corte, justo el corte, justo después, dos
    // trozos exactos, y varios trozos con cola.
    let tamanos = [0usize, 1, chunk - 1, chunk, chunk + 1, 2 * chunk, 2 * chunk + 7, 5 * chunk];

    let mut rng = Rng::nuevo(20_260_817);
    let mut oks = 0usize;
    let mut aplicadas = 0usize;
    let mut con_prefijo = 0usize;

    // Un segundo contenedor con la MISMA contraseña, para el empalme.
    let ajeno = encrypt_stream_bytes(&claro_de(5 * chunk), FRASE, &opciones(chunk));

    for &n in &tamanos {
        let claro = claro_de(n);
        let bueno = encrypt_stream_bytes(&claro, FRASE, &opciones(chunk));

        // CONTROL POSITIVO, y va primero: si esto falla, nada de lo de abajo
        // significa nada.
        assert_eq!(
            decrypt_stream_bytes(&bueno, FRASE, b"").expect("el contenedor intacto abre"),
            claro,
            "el control con {n} bytes no devolvió lo que se cifró"
        );

        let cuerpo = bueno.len() - CABECERA;
        let bloques = cuerpo.div_ceil(bloque).max(1);

        for familia in 0..8u8 {
            for _ in 0..64 {
                let mut m = bueno.clone();
                match familia {
                    // 1 · permutar dos bloques
                    0 => {
                        if bloques < 2 { continue; }
                        let (i, j) = (rng.hasta(bloques), rng.hasta(bloques));
                        if i == j { continue; }
                        let (a, b) = (CABECERA + i * bloque, CABECERA + j * bloque);
                        let largo = bloque.min(m.len() - a).min(m.len() - b);
                        for k in 0..largo { m.swap(a + k, b + k); }
                    }
                    // 2 · duplicar un bloque
                    1 => {
                        if bloques < 2 { continue; }
                        let i = rng.hasta(bloques);
                        let a = CABECERA + i * bloque;
                        let largo = bloque.min(m.len() - a);
                        let copia = m[a..a + largo].to_vec();
                        m.extend_from_slice(&copia);
                    }
                    // 3 · borrar un bloque del medio
                    2 => {
                        if bloques < 3 { continue; }
                        let i = 1 + rng.hasta(bloques - 2);
                        let a = CABECERA + i * bloque;
                        let largo = bloque.min(m.len() - a);
                        m.drain(a..a + largo);
                    }
                    // 4 · quitar el último bloque entero
                    3 => {
                        if bloques < 2 { continue; }
                        let quitar = bloque.min(m.len() - CABECERA);
                        m.truncate(m.len() - quitar);
                    }
                    // 5 · recortar 1..15 bytes del final
                    4 => {
                        let q = 1 + rng.hasta(15);
                        if m.len() <= CABECERA + q { continue; }
                        m.truncate(m.len() - q);
                    }
                    // 6 · injertar un bloque de OTRO contenedor, misma contraseña
                    5 => {
                        let a = CABECERA + rng.hasta(bloques) * bloque;
                        if a + bloque > m.len() || CABECERA + bloque > ajeno.len() { continue; }
                        let trozo = ajeno[CABECERA..CABECERA + bloque].to_vec();
                        m[a..a + bloque].copy_from_slice(&trozo);
                    }
                    // 7 · voltear un bit de la CABECERA (es la que va como AAD)
                    6 => {
                        let pos = rng.hasta(CABECERA);
                        let bit = rng.hasta(8);
                        m[pos] ^= 1 << bit;
                    }
                    // 8 · reescribir `chunk_size` a otro valor SANO del rango
                    _ => {
                        let otro: u32 = [4096u32, 8192, 65536, 262_144][rng.hasta(4)];
                        if otro as usize == chunk { continue; }
                        m[53..57].copy_from_slice(&otro.to_be_bytes());
                    }
                }
                if m == bueno { continue; }
                aplicadas += 1;

                let mut destino = Contador::default();
                match decrypt_stream(&m[..], &mut destino, FRASE, b"") {
                    Ok(()) => {
                        // Si abre, TIENE que dar exactamente el mismo claro: una
                        // mutación que produzca otro claro válido sería lo grave.
                        assert_eq!(
                            destino.datos, claro,
                            "familia {familia}, {n} bytes: una mutación descifró a OTRA COSA"
                        );
                        oks += 1;
                    }
                    Err(_) => {
                        // **LA PROPIEDAD QUE ESTE BANCO FIJA Y QUE NO ESTABA
                        // ESCRITA**: lo que ya se entregó al destino es un
                        // PREFIJO EXACTO del claro. La construcción STREAM emite
                        // cada trozo en cuanto lo verifica —memoria acotada es el
                        // punto del modo—, así que no se puede exigir cero; lo
                        // que sí se exige es que ni un byte salga sin haber
                        // pasado por su tag.
                        let escrito = destino.datos.len();
                        if escrito > 0 {
                            con_prefijo += 1;
                            assert!(
                                escrito <= claro.len() && destino.datos[..] == claro[..escrito],
                                "familia {familia}, {n} bytes: se entregaron {escrito} bytes que \
                                 NO son un prefijo del claro — salió texto sin autenticar"
                            );
                        }
                    }
                }
            }
        }
    }

    // El tope se fija POR MEDICIÓN, no por deseo: muchas familias no aplican a
    // los contenedores de uno o dos bloques, así que el número real es menor que
    // 8 familias × 64 × 8 tamaños. Se mide una vez y se ancla por debajo, para
    // que un `continue` nuevo que vacíe una familia se vea.
    assert!(
        aplicadas > 2_000,
        "solo se aplicaron {aplicadas} mutaciones: alguna familia dejó de producir casos"
    );
    assert_eq!(oks, 0, "{oks} mutaciones descifraron: el flujo no resiste lo que promete");
    // Positivo de control del propio banco: si NUNCA se entrega un prefijo, la
    // aserción de arriba no se ha ejercitado ni una vez y no prueba nada.
    assert!(
        con_prefijo > 0,
        "ninguna mutación llegó a entregar un prefijo: la aserción de \
         «todo lo entregado estaba autenticado» no se ejercitó"
    );
}

/// **EL EMPALME ENTRE ARCHIVOS NO PUEDE FUNCIONAR NI CON LA MISMA CONTRASEÑA**,
/// y conviene fijarlo aparte porque es la resistencia que la documentación
/// atribuye a «clave por archivo» y nadie había comprobado con la contraseña
/// COMPARTIDA, que es el caso real.
#[test]
fn dos_contenedores_de_la_misma_contrasena_no_se_pueden_empalmar() {
    const FRASE: &str = "una sola contraseña para los dos";
    let a = encrypt_stream_bytes(&claro_de(9000), FRASE, &opciones(4096));
    let b = encrypt_stream_bytes(&claro_de(9000), FRASE, &opciones(4096));

    // Control: los dos abren por su cuenta.
    assert!(decrypt_stream_bytes(&a, FRASE, b"").is_ok());
    assert!(decrypt_stream_bytes(&b, FRASE, b"").is_ok());
    // Y son distintos pese a cifrar el MISMO claro con la MISMA contraseña: el
    // salt y el prefijo de nonce se sortean por archivo. Si esto fallara, el
    // empalme de abajo sería trivialmente posible.
    assert_ne!(a, b, "dos contenedores del mismo claro y clave no pueden ser iguales");

    // Cabecera de A con el cuerpo de B, y al revés.
    let mut cruzado = a[..57].to_vec();
    cruzado.extend_from_slice(&b[57..]);
    assert!(
        decrypt_stream_bytes(&cruzado, FRASE, b"").is_err(),
        "la cabecera de un archivo con el cuerpo de otro NO puede abrir"
    );

    // Y un solo bloque injertado.
    let mut injertado = a;
    injertado[57..57 + 4096 + 16].copy_from_slice(&b[57..57 + 4096 + 16]);
    assert!(
        decrypt_stream_bytes(&injertado, FRASE, b"").is_err(),
        "un bloque de otro archivo NO puede colarse"
    );
}
