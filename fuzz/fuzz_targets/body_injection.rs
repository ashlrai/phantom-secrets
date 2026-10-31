#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    phantom_secrets_fuzz::body_injection(data);
});
