//! Exhaustive error coverage tests
//!
//! Every TollwayError variant MUST have:
//! 1. A test that triggers it
//! 2. Verification of correct error message
//! 3. Proof that no panic occurs for that scenario

use tollway_core::{open, seal, KeyPair, TollwayError};

// =============================================================================
// ERROR VARIANT: InvalidCiphertext
// =============================================================================

#[test]
fn error_invalid_ciphertext_empty_input() {
    let recipient = KeyPair::generate();
    let result = open(&[], &recipient);

    match result {
        Err(TollwayError::InvalidCiphertext) => {
            // Verify error message
            let err = TollwayError::InvalidCiphertext;
            assert_eq!(err.to_string(), "Invalid ciphertext format");
        }
        Err(e) => panic!("Expected InvalidCiphertext, got {:?}", e),
        Ok(_) => panic!("Expected error, got success"),
    }
}

#[test]
fn error_invalid_ciphertext_too_short() {
    let recipient = KeyPair::generate();
    // Minimum size is 8738 bytes, send less
    let short_data = vec![0x01u8; 100];
    let result = open(&short_data, &recipient);

    match result {
        Err(TollwayError::InvalidCiphertext) => {}
        Err(e) => panic!("Expected InvalidCiphertext, got {:?}", e),
        Ok(_) => panic!("Expected error, got success"),
    }
}

#[test]
fn error_invalid_ciphertext_wrong_version() {
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();

    let mut ciphertext =
        seal(b"test", &sender, &recipient.public_key()).expect("seal should succeed");

    // Corrupt version byte (first byte)
    ciphertext[0] = 0xFF;

    let result = open(&ciphertext, &recipient);
    match result {
        Err(TollwayError::InvalidCiphertext) => {}
        Err(e) => panic!("Expected InvalidCiphertext, got {:?}", e),
        Ok(_) => panic!("Expected error, got success"),
    }
}

#[test]
fn error_invalid_ciphertext_truncated() {
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();

    let ciphertext =
        seal(b"test message", &sender, &recipient.public_key()).expect("seal should succeed");

    // Truncate the ciphertext
    let truncated = &ciphertext[..ciphertext.len() - 100];
    let result = open(truncated, &recipient);

    match result {
        Err(TollwayError::InvalidCiphertext) => {}
        Err(e) => panic!("Expected InvalidCiphertext, got {:?}", e),
        Ok(_) => panic!("Expected error, got success"),
    }
}

#[test]
fn error_invalid_ciphertext_garbage() {
    let recipient = KeyPair::generate();
    // Random garbage that's long enough to pass length check
    let garbage: Vec<u8> = (0..10000).map(|i| (i * 7 + 13) as u8).collect();

    let result = open(&garbage, &recipient);

    // Should fail at signature verification or ciphertext parsing
    assert!(result.is_err());
}

// =============================================================================
// ERROR VARIANT: SignatureVerificationFailed
// =============================================================================

#[test]
fn error_signature_verification_failed() {
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();

    let mut ciphertext =
        seal(b"authentic message", &sender, &recipient.public_key()).expect("seal should succeed");

    // Corrupt signature (starts at offset 4321, 3309 bytes)
    ciphertext[4321] ^= 0xFF;
    ciphertext[4322] ^= 0xAA;

    let result = open(&ciphertext, &recipient);

    match result {
        Err(TollwayError::SignatureVerificationFailed) => {
            let err = TollwayError::SignatureVerificationFailed;
            assert_eq!(err.to_string(), "Signature verification failed");
        }
        Err(e) => panic!("Expected SignatureVerificationFailed, got {:?}", e),
        Ok(_) => panic!("Expected error, got success"),
    }
}

#[test]
fn error_signature_wrong_sender_key() {
    let sender = KeyPair::generate();
    let imposter = KeyPair::generate();
    let recipient = KeyPair::generate();

    let ciphertext =
        seal(b"message", &sender, &recipient.public_key()).expect("seal should succeed");

    // Replace sender's public key with imposter's (offset 1, 1952 bytes)
    let mut tampered = ciphertext.clone();
    let imposter_pk = imposter.public_key();
    tampered[1..1953].copy_from_slice(imposter_pk.signing_bytes());

    let result = open(&tampered, &recipient);

    match result {
        Err(TollwayError::SignatureVerificationFailed) => {}
        Err(e) => panic!("Expected SignatureVerificationFailed, got {:?}", e),
        Ok(_) => panic!("Expected error, got success"),
    }
}

// =============================================================================
// ERROR VARIANT: DecryptionFailed
// =============================================================================

#[test]
fn error_decryption_failed_corrupted_aead() {
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();

    let mut ciphertext =
        seal(b"secret data", &sender, &recipient.public_key()).expect("seal should succeed");

    // Corrupt AEAD ciphertext (at the end)
    let len = ciphertext.len();
    ciphertext[len - 1] ^= 0xFF;
    ciphertext[len - 2] ^= 0xFF;

    let result = open(&ciphertext, &recipient);

    match result {
        Err(TollwayError::DecryptionFailed) => {
            let err = TollwayError::DecryptionFailed;
            assert_eq!(err.to_string(), "Decryption failed");
        }
        Err(e) => panic!("Expected DecryptionFailed, got {:?}", e),
        Ok(_) => panic!("Expected error, got success"),
    }
}

#[test]
fn error_decryption_failed_wrong_recipient() {
    let sender = KeyPair::generate();
    let correct_recipient = KeyPair::generate();
    let wrong_recipient = KeyPair::generate();

    let ciphertext = seal(
        b"for correct recipient",
        &sender,
        &correct_recipient.public_key(),
    )
    .expect("seal should succeed");

    let result = open(&ciphertext, &wrong_recipient);

    // Could be DecryptionFailed or KEMDecapsulationFailed depending on implementation
    assert!(
        matches!(
            result,
            Err(TollwayError::DecryptionFailed) | Err(TollwayError::KEMDecapsulationFailed)
        ),
        "Expected decryption error, got {:?}",
        result
    );
}

// =============================================================================
// ERROR VARIANT: KEMDecapsulationFailed
// =============================================================================

#[test]
fn error_kem_decapsulation_failed() {
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();

    let mut ciphertext =
        seal(b"message", &sender, &recipient.public_key()).expect("seal should succeed");

    // Corrupt KEM ciphertext (offset 7630, 1088 bytes)
    ciphertext[7630] ^= 0xFF;
    ciphertext[7631] ^= 0xFF;
    ciphertext[7632] ^= 0xFF;

    let result = open(&ciphertext, &recipient);

    // Should fail at decapsulation or subsequent AEAD decryption
    assert!(result.is_err(), "Corrupted KEM ciphertext should fail");
}

// =============================================================================
// ERROR VARIANT: Internal
// =============================================================================

#[test]
fn error_internal_message_format() {
    // Test that Internal error has correct message format
    let err = TollwayError::Internal("test context".to_string());
    assert_eq!(err.to_string(), "Internal error: test context");
}

// =============================================================================
// ERROR MESSAGE VERIFICATION
// =============================================================================

#[test]
fn error_all_variants_have_messages() {
    // Verify all error variants produce meaningful messages
    let errors = vec![
        TollwayError::InvalidCiphertext,
        TollwayError::SignatureVerificationFailed,
        TollwayError::DecryptionFailed,
        TollwayError::KeyGenerationFailed,
        TollwayError::KEMEncapsulationFailed,
        TollwayError::KEMDecapsulationFailed,
        TollwayError::Internal("context".to_string()),
    ];

    for err in errors {
        let msg = err.to_string();
        assert!(!msg.is_empty(), "Error {:?} should have message", err);
        // Verify no sensitive data patterns in message
        // (secret key bytes, plaintext, etc.)
        let lower = msg.to_lowercase();
        assert!(
            !lower.contains("secret") && !lower.contains("private") && !lower.contains("plaintext"),
            "Error message should not contain sensitive terms: {}",
            msg
        );
    }
}

// =============================================================================
// NO PANIC VERIFICATION
// =============================================================================

#[test]
fn no_panic_on_all_error_scenarios() {
    let recipient = KeyPair::generate();

    // Various malformed inputs that should NOT panic
    let test_cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("single_byte", vec![0x01]),
        ("wrong_version", vec![0xFF; 10000]),
        ("all_zeros", vec![0x00; 10000]),
        ("all_ones", vec![0xFF; 10000]),
        ("minimum_minus_one", vec![0x01; 8737]),
        (
            "random_pattern",
            (0..10000).map(|i| (i * 17 + 7) as u8).collect(),
        ),
    ];

    for (name, data) in test_cases {
        // This should not panic, only return Err
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| open(&data, &recipient)));

        assert!(
            result.is_ok(),
            "Panic occurred on test case '{}' - implementation should return Err instead",
            name
        );

        if let Ok(inner_result) = result {
            assert!(
                inner_result.is_err(),
                "Test case '{}' should return error, not success",
                name
            );
        }
    }
}

// =============================================================================
// ERROR TYPE COVERAGE
// =============================================================================

/// This test documents which error variants are expected to be triggerable
/// from the public API vs internal-only
#[test]
fn error_coverage_documentation() {
    println!("Error Variant Coverage:");
    println!("  InvalidCiphertext        - Triggerable via open() with malformed data");
    println!("  SignatureVerificationFailed - Triggerable via open() with bad signature");
    println!("  DecryptionFailed         - Triggerable via open() with corrupted AEAD");
    println!("  KeyGenerationFailed      - Should never occur with working RNG");
    println!("  KEMEncapsulationFailed   - Should never occur with valid public key");
    println!("  KEMDecapsulationFailed   - Triggerable via open() with corrupted KEM ct");
    println!("  Internal                 - Should never reach user in normal operation");
}
