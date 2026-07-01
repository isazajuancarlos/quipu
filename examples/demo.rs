//! Demo end-to-end de Quipu: protege un mensaje y lo representa como símbolos.
//!
//!   cargo run --example demo

use quipu::api::{decode, encode, Options};
use quipu::dictionaries;
use quipu::kdf::KdfParams;

fn main() {
    // Diccionario fallback: 94 símbolos ASCII imprimibles.
    let dict = dictionaries::ascii94();

    let mensaje = b"Hola, esto es un secreto protegido con Quipu.";
    let clave = "mi-passphrase-larga-y-secreta";

    // Coste bajo para que el demo sea instantáneo (en producción usar el default).
    let opts = Options {
        pepper: b"pepper-de-la-app",
        kdf_params: KdfParams {
            mem_kib: 1024,
            iterations: 2,
            parallelism: 1,
        },
        codebook_id: 1,
    };

    let simbolos = encode(mensaje, clave, &dict, &opts);
    println!("Original : {}", String::from_utf8_lossy(mensaje));
    println!("Protegido ({} símbolos):\n{}\n", simbolos.chars().count(), simbolos);

    // Descifrado con clave + pepper correctos.
    let recuperado = decode(&simbolos, clave, &dict, opts.pepper).unwrap();
    println!("Recuperado: {}", String::from_utf8_lossy(&recuperado));
    assert_eq!(recuperado, mensaje);

    // Con clave incorrecta: falla de autenticación.
    match decode(&simbolos, "clave-incorrecta", &dict, opts.pepper) {
        Ok(_) => println!("\n[ERROR] no debería descifrar con clave incorrecta"),
        Err(e) => println!("\nClave incorrecta -> rechazado correctamente: {e:?}"),
    }

    // La "oruga": el mismo dato con el diccionario insignia de glifos (4096
    // símbolos = 12 bits/símbolo, ~2x más denso que ASCII).
    let glifos_dict = dictionaries::flagship();
    let glifos = encode(mensaje, clave, &glifos_dict, &opts);
    println!(
        "\nMismo secreto con el diccionario insignia ({} glifos vs {} ASCII):\n{}",
        glifos.chars().count(),
        simbolos.chars().count(),
        glifos
    );
    let recuperado2 = decode(&glifos, clave, &glifos_dict, opts.pepper).unwrap();
    assert_eq!(recuperado2, mensaje);
}
