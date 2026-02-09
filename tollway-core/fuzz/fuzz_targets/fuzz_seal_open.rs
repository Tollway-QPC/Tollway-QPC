#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tollway_core::{open, seal, KeyPair};

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    plaintext: Vec<u8>,
    // Use seeds to generate deterministic keypairs for reproducibility
    sender_seed: [u8; 32],
    recipient_seed: [u8; 32],
}

// Note: We generate real keypairs each time because:
// 1. KeyPair::generate() uses the system RNG, not our seeds
// 2. PQC key generation is expensive, but fuzzing throughput
//    is not the goal here - crash discovery is
fuzz_target!(|input: FuzzInput| {
    // Generate fresh keypairs for each iteration
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();
    
    // Limit plaintext size to prevent OOM
    let plaintext = if input.plaintext.len() > 1024 * 1024 {
        &input.plaintext[..1024 * 1024]
    } else {
        &input.plaintext
    };
    
    // Seal should always succeed with valid keys
    let ciphertext = match seal(plaintext, &sender, &recipient.public_key()) {
        Ok(ct) => ct,
        Err(e) => {
            // This should never happen with valid keys
            panic!("seal() failed unexpectedly: {:?}", e);
        }
    };
    
    // Open should always succeed with matching keys
    let (decrypted, sender_pk) = match open(&ciphertext, &recipient) {
        Ok(result) => result,
        Err(e) => {
            // This should never happen with matching keys
            panic!("open() failed unexpectedly: {:?}", e);
        }
    };
    
    // Verify roundtrip correctness
    assert_eq!(
        plaintext, 
        decrypted.as_slice(),
        "Plaintext mismatch after roundtrip"
    );
    
    // Verify sender identity
    assert_eq!(
        sender.public_key().signing_bytes(),
        sender_pk.signing_bytes(),
        "Sender identity mismatch"
    );
    
    // Opening with wrong keys should fail cleanly (not panic)
    let wrong_recipient = KeyPair::generate();
    let result = open(&ciphertext, &wrong_recipient);
    assert!(
        result.is_err(),
        "open() should fail with wrong recipient key"
    );
});
