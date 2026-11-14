#![no_main]
//! Fuzz del parser del contenedor: bytes arbitrarios nunca deben provocar panic.

use libfuzzer_sys::fuzz_target;
use quipu::container;

fuzz_target!(|data: &[u8]| {
    // El parser debe devolver Ok o Err, jamás entrar en pánico ni desbordar.
    let _ = container::parse(data);
});
