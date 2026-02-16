#![no_main]

use libfuzzer_sys::fuzz_target;
use tollway_core::{open, KeyPair};

use std::sync::LazyLock;

static RECIPIENT: LazyLock<KeyPair> = LazyLock::new(KeyPair::generate);

fuzz_target!(|data: &[u8]| {
    // Throw arbitrary bytes at the ciphertext parser
    // This should NEVER panic - it should return Err cleanly
    let recipient = &*RECIPIENT;

    // The open function internally calls parse_ciphertext
    // Any input should result in either:
    // 1. Err(InvalidCiphertext) - for malformed data
    // 2. Err(SignatureVerificationFailed) - for well-formed but invalid signatures
    // 3. Err(DecryptionFailed) - for signature-valid but wrong key/corrupted
    // Never a panic
    let _ = open(data, recipient);
});
