#![no_main]
//! Fuzz del despadding: bytes arbitrarios (longitud declarada maliciosa, etc.)
//! nunca deben provocar panic ni overflow.

use libfuzzer_sys::fuzz_target;
use quipu::prelayers;

fuzz_target!(|data: &[u8]| {
    let _ = prelayers::unpad(data);
});
