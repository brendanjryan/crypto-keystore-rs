#![no_main]
#[path = "../../tests/support/fuzz_cases.rs"]
#[allow(dead_code)]
mod cases;
libfuzzer_sys::fuzz_target!(|data: &[u8]| cases::authenticated(data));
