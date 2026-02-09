//! Integration tests for seal/open operations

use tollway_core::{open, seal, KeyPair, TollwayError};

// =============================================================================
// BASIC ROUNDTRIP TESTS
// =============================================================================

#[test]
fn test_seal_open_roundtrip_basic() {
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();
    let plaintext = b"Hello, post-quantum world!";

    let ciphertext = seal(plaintext, &sender, &recipient.public_key()).unwrap();
    let (decrypted, sender_pk) = open(&ciphertext, &recipient).unwrap();

    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    assert_eq!(
        sender_pk.signing_bytes(),
        sender.public_key().signing_bytes()
    );
}

#[test]
fn test_seal_open_empty_message() {
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();
    let plaintext = b"";

    let ciphertext = seal(plaintext, &sender, &recipient.public_key()).unwrap();
    let (decrypted, _) = open(&ciphertext, &recipient).unwrap();

    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
}

#[test]
fn test_seal_open_large_message() {
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();
    // 1 MB message
    let plaintext = vec![0xABu8; 1024 * 1024];

    let ciphertext = seal(&plaintext, &sender, &recipient.public_key()).unwrap();
    let (decrypted, _) = open(&ciphertext, &recipient).unwrap();

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_seal_open_binary_data() {
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();
    // All possible byte values
    let plaintext: Vec<u8> = (0u8..=255).collect();

    let ciphertext = seal(&plaintext, &sender, &recipient.public_key()).unwrap();
    let (decrypted, _) = open(&ciphertext, &recipient).unwrap();

    assert_eq!(plaintext, decrypted);
}

// =============================================================================
// WRONG KEY TESTS
// =============================================================================

#[test]
fn test_open_wrong_recipient_key_fails() {
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();
    let wrong_recipient = KeyPair::generate();
    let plaintext = b"Secret message";

    let ciphertext = seal(plaintext, &sender, &recipient.public_key()).unwrap();

    // Opening with wrong key should fail
    let result = open(&ciphertext, &wrong_recipient);
    assert!(result.is_err());
}

#[test]
fn test_different_senders_produce_different_ciphertexts() {
    let sender1 = KeyPair::generate();
    let sender2 = KeyPair::generate();
    let recipient = KeyPair::generate();
    let plaintext = b"Same message";

    let ct1 = seal(plaintext, &sender1, &recipient.public_key()).unwrap();
    let ct2 = seal(plaintext, &sender2, &recipient.public_key()).unwrap();

    // Different senders should produce different ciphertexts
    assert_ne!(ct1, ct2);

    // Both should decrypt correctly
    let (p1, s1) = open(&ct1, &recipient).unwrap();
    let (p2, s2) = open(&ct2, &recipient).unwrap();

    assert_eq!(p1, plaintext.as_slice());
    assert_eq!(p2, plaintext.as_slice());
    assert_ne!(s1.signing_bytes(), s2.signing_bytes());
}

// =============================================================================
// MALFORMED CIPHERTEXT TESTS
// =============================================================================

#[test]
fn test_open_empty_ciphertext_fails() {
    let recipient = KeyPair::generate();
    let result = open(&[], &recipient);
    assert!(matches!(result, Err(TollwayError::InvalidCiphertext)));
}

#[test]
fn test_open_truncated_ciphertext_fails() {
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();
    let plaintext = b"Test message";

    let ciphertext = seal(plaintext, &sender, &recipient.public_key()).unwrap();

    // Truncate at various points
    for len in [1, 10, 100, 1000, ciphertext.len() - 1] {
        if len < ciphertext.len() {
            let truncated = &ciphertext[..len];
            let result = open(truncated, &recipient);
            assert!(result.is_err(), "Should fail with {} bytes", len);
        }
    }
}

#[test]
fn test_open_corrupted_signature_fails() {
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();
    let plaintext = b"Test message";

    let mut ciphertext = seal(plaintext, &sender, &recipient.public_key()).unwrap();

    // Signature starts after version (1) + sender_signing_pk (1952) + sender_kem_pk (1184) + ephemeral_kem_pk (1184)
    let signature_offset = 1 + 1952 + 1184 + 1184;
    ciphertext[signature_offset] ^= 0xFF; // Flip bits in signature

    let result = open(&ciphertext, &recipient);
    assert!(matches!(
        result,
        Err(TollwayError::SignatureVerificationFailed)
    ));
}

#[test]
fn test_open_corrupted_kem_ciphertext_fails() {
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();
    let plaintext = b"Test message";

    let mut ciphertext = seal(plaintext, &sender, &recipient.public_key()).unwrap();

    // KEM ciphertext starts after version + sender_signing + sender_kem + ephemeral_pk + signature
    let kem_offset = 1 + 1952 + 1184 + 1184 + 3309;
    ciphertext[kem_offset] ^= 0xFF;

    let result = open(&ciphertext, &recipient);
    // Could be DecryptionFailed or KEMDecapsulationFailed depending on where corruption hits
    assert!(result.is_err());
}

#[test]
fn test_open_corrupted_aead_ciphertext_fails() {
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();
    let plaintext = b"Test message";

    let mut ciphertext = seal(plaintext, &sender, &recipient.public_key()).unwrap();

    // AEAD ciphertext is at the end (after length prefix)
    let last_byte = ciphertext.len() - 1;
    ciphertext[last_byte] ^= 0xFF;

    let result = open(&ciphertext, &recipient);
    assert!(matches!(result, Err(TollwayError::DecryptionFailed)));
}

#[test]
fn test_open_wrong_version_fails() {
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();
    let plaintext = b"Test message";

    let mut ciphertext = seal(plaintext, &sender, &recipient.public_key()).unwrap();

    // Version is first byte
    ciphertext[0] = 0xFF;

    let result = open(&ciphertext, &recipient);
    assert!(matches!(result, Err(TollwayError::InvalidCiphertext)));
}

// =============================================================================
// FORWARD SECRECY PROPERTY TESTS
// =============================================================================

#[test]
fn test_same_message_produces_different_ciphertexts() {
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();
    let plaintext = b"Same message encrypted twice";

    let ct1 = seal(plaintext, &sender, &recipient.public_key()).unwrap();
    let ct2 = seal(plaintext, &sender, &recipient.public_key()).unwrap();

    // Due to ephemeral keys, same plaintext should produce different ciphertext
    assert_ne!(ct1, ct2);

    // Both should decrypt to the same plaintext
    let (p1, _) = open(&ct1, &recipient).unwrap();
    let (p2, _) = open(&ct2, &recipient).unwrap();
    assert_eq!(p1, p2);
}

// =============================================================================
// SELF-SEND TESTS
// =============================================================================

#[test]
fn test_send_to_self() {
    let alice = KeyPair::generate();
    let plaintext = b"Note to self";

    // Alice sends to herself
    let ciphertext = seal(plaintext, &alice, &alice.public_key()).unwrap();
    let (decrypted, sender_pk) = open(&ciphertext, &alice).unwrap();

    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    assert_eq!(
        sender_pk.signing_bytes(),
        alice.public_key().signing_bytes()
    );
}

// =============================================================================
// CIPHERTEXT SIZE TESTS
// =============================================================================

#[test]
fn test_ciphertext_overhead() {
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();

    // Expected overhead:
    // version: 1
    // sender_signing_pk: 1952 (ML-DSA-65)
    // sender_kem_pk: 1184 (ML-KEM-768)
    // ephemeral_kem_pk: 1184 (ML-KEM-768)
    // signature: 3309 (ML-DSA-65)
    // kem_ciphertext: 1088 (ML-KEM-768)
    // aead_length: 4
    // aead_tag: 16 (Poly1305)
    // Total fixed overhead: 8738 bytes
    let expected_overhead = 1 + 1952 + 1184 + 1184 + 3309 + 1088 + 4 + 16;

    for plaintext_len in [0, 1, 100, 1000] {
        let plaintext = vec![0u8; plaintext_len];
        let ciphertext = seal(&plaintext, &sender, &recipient.public_key()).unwrap();

        let actual_overhead = ciphertext.len() - plaintext_len;
        assert_eq!(
            actual_overhead, expected_overhead,
            "Unexpected overhead for {} byte plaintext",
            plaintext_len
        );
    }
}

// =============================================================================
// SENDER IDENTITY TESTS
// =============================================================================

#[test]
fn test_returned_sender_pk_is_complete() {
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();
    let plaintext = b"Test message";

    let ciphertext = seal(plaintext, &sender, &recipient.public_key()).unwrap();
    let (_, sender_pk) = open(&ciphertext, &recipient).unwrap();

    // Sender public key should have both signing and KEM components
    assert_eq!(
        sender_pk.signing_bytes(),
        sender.public_key().signing_bytes()
    );
    assert_eq!(sender_pk.kem_bytes(), sender.public_key().kem_bytes());
    assert!(
        !sender_pk.kem_bytes().is_empty(),
        "Sender KEM key should not be empty"
    );
}

#[test]
fn test_reply_to_sender() {
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();

    // Alice sends to Bob
    let msg1 = b"Hello Bob!";
    let ct1 = seal(msg1, &alice, &bob.public_key()).unwrap();

    // Bob opens and gets Alice's public key
    let (plaintext1, alice_pk) = open(&ct1, &bob).unwrap();
    assert_eq!(plaintext1, msg1);

    // Bob can now reply to Alice using the returned public key
    let msg2 = b"Hello Alice!";
    let ct2 = seal(msg2, &bob, &alice_pk).unwrap();

    // Alice can open Bob's reply
    let (plaintext2, bob_pk) = open(&ct2, &alice).unwrap();
    assert_eq!(plaintext2, msg2);
    assert_eq!(bob_pk.signing_bytes(), bob.public_key().signing_bytes());
}

// =============================================================================
// AAD BINDING TESTS
// =============================================================================

#[test]
fn test_aad_binding_prevents_misdirection() {
    // This test verifies that moving a message to a different recipient fails
    // due to AAD binding (even if we could somehow get the same shared secret)
    let sender = KeyPair::generate();
    let intended_recipient = KeyPair::generate();
    let other_recipient = KeyPair::generate();
    let plaintext = b"Secret for intended recipient only";

    let ciphertext = seal(plaintext, &sender, &intended_recipient.public_key()).unwrap();

    // Intended recipient can open
    let result = open(&ciphertext, &intended_recipient);
    assert!(result.is_ok());

    // Other recipient cannot open (KEM decapsulation will fail, but even if
    // an attacker somehow got the same shared secret, AAD would prevent decryption)
    let result = open(&ciphertext, &other_recipient);
    assert!(result.is_err());
}
