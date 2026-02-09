#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tollway_core::{open, seal, KeyPair, TollwayError};

#[derive(Arbitrary, Debug)]
struct CorruptionInput {
    plaintext: Vec<u8>,
    // Which byte position to corrupt
    corrupt_position: usize,
    // What to XOR with the byte (0 means no change)
    corrupt_xor: u8,
    // How many bytes to corrupt
    corrupt_count: u8,
}

// Pre-generate keypairs for better fuzzing throughput
static mut SENDER: Option<KeyPair> = None;
static mut RECIPIENT: Option<KeyPair> = None;

fn get_keypairs() -> (&'static KeyPair, &'static KeyPair) {
    unsafe {
        if SENDER.is_none() {
            SENDER = Some(KeyPair::generate());
            RECIPIENT = Some(KeyPair::generate());
        }
        (SENDER.as_ref().unwrap(), RECIPIENT.as_ref().unwrap())
    }
}

fuzz_target!(|input: CorruptionInput| {
    let (sender, recipient) = get_keypairs();
    
    // Limit plaintext size
    let plaintext = if input.plaintext.is_empty() {
        b"test".to_vec()
    } else if input.plaintext.len() > 64 * 1024 {
        input.plaintext[..64 * 1024].to_vec()
    } else {
        input.plaintext.clone()
    };
    
    // Create valid ciphertext
    let ciphertext = seal(&plaintext, sender, &recipient.public_key())
        .expect("seal should succeed");
    
    // If no corruption requested, verify roundtrip works
    if input.corrupt_xor == 0 || input.corrupt_count == 0 {
        let (decrypted, _) = open(&ciphertext, recipient)
            .expect("open should succeed with valid ciphertext");
        assert_eq!(plaintext, decrypted);
        return;
    }
    
    // Corrupt the ciphertext
    let mut corrupted = ciphertext.clone();
    let count = (input.corrupt_count as usize).min(10); // Limit corruption spread
    
    for i in 0..count {
        let pos = (input.corrupt_position.wrapping_add(i)) % corrupted.len();
        corrupted[pos] ^= input.corrupt_xor;
    }
    
    // If corruption was applied, verify it's actually different
    if corrupted != ciphertext {
        // Opening corrupted ciphertext should ALWAYS fail cleanly
        let result = open(&corrupted, recipient);
        
        match result {
            Ok(_) => {
                // This could theoretically happen if corruption doesn't
                // affect authenticated data, but is extremely unlikely
                // with proper AEAD. If this triggers, investigate!
                panic!(
                    "Corrupted ciphertext was accepted! \
                     Position: {}, XOR: {}, Count: {}",
                    input.corrupt_position, input.corrupt_xor, count
                );
            }
            Err(e) => {
                // Verify we get clean error types, not panics
                match e {
                    TollwayError::InvalidCiphertext
                    | TollwayError::SignatureVerificationFailed
                    | TollwayError::DecryptionFailed
                    | TollwayError::KEMDecapsulationFailed => {
                        // These are all acceptable error paths
                    }
                    TollwayError::Internal(msg) => {
                        // Internal errors in decryption path are suspicious
                        panic!("Unexpected internal error on corrupted input: {}", msg);
                    }
                    _ => {
                        // Any other error type is unexpected
                        panic!("Unexpected error type on corrupted input: {:?}", e);
                    }
                }
            }
        }
    }
});
