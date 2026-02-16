//! Property-based tests for tollway-core
//!
//! These tests use proptest to verify invariants that should hold
//! across ALL possible inputs, not just hand-picked test cases.

use proptest::prelude::*;
use tollway_core::{open, seal, KeyPair, TollwayError};

// =============================================================================
// PROPTEST CONFIGURATION
// =============================================================================

// Reduce iterations because PQC operations are slow
proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    // =========================================================================
    // PROPERTY 1: seal → open always succeeds with correct keys
    // =========================================================================

    #[test]
    fn prop_seal_open_roundtrip(plaintext in prop::collection::vec(any::<u8>(), 0..10000)) {
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let ciphertext = seal(&plaintext, &sender, &recipient.public_key())
            .expect("seal should always succeed with valid keys");

        let (decrypted, sender_pk) = open(&ciphertext, &recipient)
            .expect("open should always succeed with correct recipient key");

        prop_assert_eq!(
            &plaintext,
            &decrypted,
            "Decrypted plaintext must match original"
        );

        let sender_pk_bytes = sender.public_key();
        prop_assert_eq!(
            sender_pk_bytes.signing_bytes(),
            sender_pk.signing_bytes(),
            "Sender identity must be preserved"
        );
    }

    // =========================================================================
    // PROPERTY 2: seal → corrupt → open always fails
    // =========================================================================

    #[test]
    fn prop_corrupted_ciphertext_fails(
        plaintext in prop::collection::vec(any::<u8>(), 1..1000),
        corrupt_pos in any::<usize>(),
        corrupt_val in 1u8..=255u8, // Non-zero to ensure actual corruption
    ) {
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let ciphertext = seal(&plaintext, &sender, &recipient.public_key())
            .expect("seal should succeed");

        // Corrupt a byte -- V2 AAD now covers all fields including sender KEM key,
        // so corruption at any position should cause open() to fail.
        let mut corrupted = ciphertext.clone();
        let pos = corrupt_pos % corrupted.len();

        corrupted[pos] ^= corrupt_val;

        // Opening corrupted ciphertext should fail
        let result = open(&corrupted, &recipient);

        prop_assert!(
            result.is_err(),
            "Opening corrupted ciphertext should always fail"
        );

        // Verify it's a clean error, not a panic
        match result.unwrap_err() {
            TollwayError::InvalidCiphertext
            | TollwayError::SignatureVerificationFailed
            | TollwayError::DecryptionFailed
            | TollwayError::KEMDecapsulationFailed => {}
            e => prop_assert!(false, "Unexpected error type: {:?}", e),
        }
    }

    // =========================================================================
    // PROPERTY 3: Different plaintexts → different ciphertexts (probabilistic)
    // =========================================================================

    #[test]
    fn prop_different_plaintexts_different_ciphertexts(
        plaintext1 in prop::collection::vec(any::<u8>(), 1..100),
        plaintext2 in prop::collection::vec(any::<u8>(), 1..100),
    ) {
        // Skip if plaintexts are equal (nothing to test)
        prop_assume!(plaintext1 != plaintext2);

        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let ct1 = seal(&plaintext1, &sender, &recipient.public_key())
            .expect("seal should succeed");
        let ct2 = seal(&plaintext2, &sender, &recipient.public_key())
            .expect("seal should succeed");

        // Ciphertexts should be different (with overwhelming probability)
        prop_assert_ne!(
            ct1, ct2,
            "Different plaintexts should produce different ciphertexts"
        );
    }

    // =========================================================================
    // PROPERTY 4: Same sender + different ephemeral = forward secrecy
    // =========================================================================

    #[test]
    fn prop_forward_secrecy_different_ephemeral(
        plaintext in prop::collection::vec(any::<u8>(), 1..100),
    ) {
        // Same sender and recipient across multiple seal operations
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        // Seal the same plaintext multiple times
        let ct1 = seal(&plaintext, &sender, &recipient.public_key())
            .expect("seal should succeed");
        let ct2 = seal(&plaintext, &sender, &recipient.public_key())
            .expect("seal should succeed");

        // Ciphertexts should be different due to fresh ephemeral keys each time
        // This demonstrates forward secrecy: each message uses unique key material
        prop_assert_ne!(
            &ct1, &ct2,
            "Same plaintext should produce different ciphertexts (fresh ephemeral)"
        );

        // Both should still decrypt correctly
        let (dec1, _) = open(&ct1, &recipient).expect("open should succeed");
        let (dec2, _) = open(&ct2, &recipient).expect("open should succeed");

        prop_assert_eq!(&plaintext, &dec1);
        prop_assert_eq!(&plaintext, &dec2);
    }

    // =========================================================================
    // PROPERTY 5: Wrong recipient key always fails
    // =========================================================================

    #[test]
    fn prop_wrong_recipient_always_fails(
        plaintext in prop::collection::vec(any::<u8>(), 0..1000),
    ) {
        let sender = KeyPair::generate();
        let correct_recipient = KeyPair::generate();
        let wrong_recipient = KeyPair::generate();

        let ciphertext = seal(&plaintext, &sender, &correct_recipient.public_key())
            .expect("seal should succeed");

        // Opening with wrong key should fail
        let result = open(&ciphertext, &wrong_recipient);

        prop_assert!(
            result.is_err(),
            "Opening with wrong recipient key should always fail"
        );
    }

    // =========================================================================
    // PROPERTY 6: Sender identity is correctly embedded
    // =========================================================================

    #[test]
    fn prop_sender_identity_preserved(
        plaintext in prop::collection::vec(any::<u8>(), 1..100),
    ) {
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let ciphertext = seal(&plaintext, &sender, &recipient.public_key())
            .expect("seal should succeed");

        let (_, recovered_sender) = open(&ciphertext, &recipient)
            .expect("open should succeed");

        // The sender's signing key should be correctly embedded and recovered
        let sender_pk = sender.public_key();
        prop_assert_eq!(
            sender_pk.signing_bytes(),
            recovered_sender.signing_bytes(),
            "Sender signing key must match"
        );

        // The sender's KEM key should also be preserved
        prop_assert_eq!(
            sender_pk.kem_bytes(),
            recovered_sender.kem_bytes(),
            "Sender KEM key must match"
        );
    }

    // =========================================================================
    // PROPERTY 7: Ciphertext size is deterministic
    // =========================================================================

    #[test]
    fn prop_ciphertext_overhead_is_constant(
        plaintext in prop::collection::vec(any::<u8>(), 0..10000),
    ) {
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let ciphertext = seal(&plaintext, &sender, &recipient.public_key())
            .expect("seal should succeed");

        // Fixed overhead: version(1) + sender_sign_pk(1952) + sender_kem_pk(1184) +
        //                 ephemeral_kem_pk(1184) + signature(3309) + kem_ct(1088) +
        //                 aead_len(4) + poly1305_tag(16)
        // = 8738 bytes fixed overhead
        let expected_overhead = 8738;
        let expected_len = plaintext.len() + expected_overhead;

        prop_assert_eq!(
            ciphertext.len(),
            expected_len,
            "Ciphertext size = plaintext + {} byte overhead",
            expected_overhead
        );
    }

    // =========================================================================
    // PROPERTY 8: Empty plaintext is valid
    // =========================================================================

    #[test]
    fn prop_empty_plaintext_works(_dummy in Just(())) {
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        let plaintext = vec![];

        let ciphertext = seal(&plaintext, &sender, &recipient.public_key())
            .expect("seal should succeed with empty plaintext");

        let (decrypted, _) = open(&ciphertext, &recipient)
            .expect("open should succeed with empty plaintext");

        prop_assert!(decrypted.is_empty());
    }
}

// =============================================================================
// NON-PROPTEST HELPERS (run once)
// =============================================================================

#[test]
fn test_keypair_uniqueness() {
    // Generate multiple keypairs and verify they're all unique
    let keypairs: Vec<_> = (0..10).map(|_| KeyPair::generate()).collect();

    for (i, kp1) in keypairs.iter().enumerate() {
        for (j, kp2) in keypairs.iter().enumerate() {
            if i != j {
                assert_ne!(
                    kp1.public_key().signing_bytes(),
                    kp2.public_key().signing_bytes(),
                    "Keypairs {} and {} should have different signing keys",
                    i,
                    j
                );
                assert_ne!(
                    kp1.public_key().kem_bytes(),
                    kp2.public_key().kem_bytes(),
                    "Keypairs {} and {} should have different KEM keys",
                    i,
                    j
                );
            }
        }
    }
}
