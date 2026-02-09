#![no_main]

use libfuzzer_sys::fuzz_target;
use tollway_core::{open, KeyPair};

// Static recipient keypair for consistent testing
// Using lazy_static equivalent via once_cell pattern
static mut RECIPIENT: Option<KeyPair> = None;

fn get_recipient() -> &'static KeyPair {
    unsafe {
        if RECIPIENT.is_none() {
            RECIPIENT = Some(KeyPair::generate());
        }
        RECIPIENT.as_ref().unwrap()
    }
}

fuzz_target!(|data: &[u8]| {
    // Throw arbitrary bytes at the ciphertext parser
    // This should NEVER panic - it should return Err cleanly
    let recipient = get_recipient();

    // The open function internally calls parse_ciphertext
    // Any input should result in either:
    // 1. Err(InvalidCiphertext) - for malformed data
    // 2. Err(SignatureVerificationFailed) - for well-formed but invalid signatures
    // 3. Err(DecryptionFailed) - for signature-valid but wrong key/corrupted
    // Never a panic
    let _ = open(data, recipient);
});
