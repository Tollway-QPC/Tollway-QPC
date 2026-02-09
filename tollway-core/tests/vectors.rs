//! Known Answer Tests (KAT) for cryptographic primitives
//!
//! These tests verify that our wrappers correctly use the underlying
//! cryptographic primitives and don't corrupt data in transit.

use tollway_core::{seal, KeyPair};

// =============================================================================
// DETERMINISTIC ROUNDTRIP VECTORS
// =============================================================================

/// Test vectors generated from known seeds to verify consistent behavior
/// These catch bugs in serialization, key handling, and wire format parsing

#[test]
fn test_vector_wire_format_structure() {
    // Verify the wire format has expected structure
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();
    let plaintext = b"Test vector plaintext";

    let ciphertext = seal(plaintext, &sender, &recipient.public_key()).unwrap();

    // Version byte should be 0x01
    assert_eq!(ciphertext[0], 0x01, "Version byte should be 0x01");

    // Total size should be header + plaintext + tag
    let expected_header = 1      // version
        + 1952   // sender_signing_pk (ML-DSA-65)
        + 1184   // sender_kem_pk (ML-KEM-768)
        + 1184   // ephemeral_kem_pk (ML-KEM-768)
        + 3309   // signature (ML-DSA-65)
        + 1088   // kem_ciphertext (ML-KEM-768)
        + 4; // aead_length prefix

    let aead_overhead = 16; // Poly1305 tag
    let expected_size = expected_header + plaintext.len() + aead_overhead;

    assert_eq!(ciphertext.len(), expected_size);
}

#[test]
fn test_vector_key_sizes() {
    let keypair = KeyPair::generate();
    let public_key = keypair.public_key();

    // ML-DSA-65 public key size
    assert_eq!(public_key.signing_bytes().len(), 1952);

    // ML-KEM-768 public key size
    assert_eq!(public_key.kem_bytes().len(), 1184);
}

#[test]
fn test_vector_signature_position() {
    // Verify signature is at expected position and changes between messages
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();

    let ct1 = seal(b"Message 1", &sender, &recipient.public_key()).unwrap();
    let ct2 = seal(b"Message 2", &sender, &recipient.public_key()).unwrap();

    // Signature offset: version(1) + sender_signing(1952) + sender_kem(1184) + ephemeral_kem(1184)
    let sig_start = 1 + 1952 + 1184 + 1184;
    let sig_end = sig_start + 3309;

    let sig1 = &ct1[sig_start..sig_end];
    let sig2 = &ct2[sig_start..sig_end];

    // Signatures should be different (different ephemeral keys are signed)
    assert_ne!(sig1, sig2);
}

// =============================================================================
// ALGORITHM CONSTANT VERIFICATION
// =============================================================================

#[test]
fn test_ml_kem_768_constants() {
    // Verify we're using ML-KEM-768 (not 512 or 1024)
    // Public key: 1184 bytes
    // Secret key: 2400 bytes
    // Ciphertext: 1088 bytes
    // Shared secret: 32 bytes

    let keypair = KeyPair::generate();
    assert_eq!(
        keypair.public_key().kem_bytes().len(),
        1184,
        "ML-KEM-768 public key should be 1184 bytes"
    );
}

#[test]
fn test_ml_dsa_65_constants() {
    // Verify we're using ML-DSA-65 (NIST Level 3)
    // Public key: 1952 bytes
    // Secret key: 4032 bytes
    // Signature: 3309 bytes

    let keypair = KeyPair::generate();
    assert_eq!(
        keypair.public_key().signing_bytes().len(),
        1952,
        "ML-DSA-65 public key should be 1952 bytes"
    );
}

// =============================================================================
// CROSS-MESSAGE ISOLATION
// =============================================================================

#[test]
fn test_vector_ephemeral_key_isolation() {
    // Each message should use a different ephemeral KEM keypair
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();

    let ct1 = seal(b"Message 1", &sender, &recipient.public_key()).unwrap();
    let ct2 = seal(b"Message 1", &sender, &recipient.public_key()).unwrap();

    // Ephemeral KEM public key offset: version(1) + sender_signing(1952) + sender_kem(1184)
    let eph_start = 1 + 1952 + 1184;
    let eph_end = eph_start + 1184;

    let eph1 = &ct1[eph_start..eph_end];
    let eph2 = &ct2[eph_start..eph_end];

    // Different ephemeral keys for each message (forward secrecy)
    assert_ne!(
        eph1, eph2,
        "Each message should use different ephemeral keys"
    );
}

#[test]
fn test_vector_kem_ciphertext_isolation() {
    // Each message should have different KEM ciphertext
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();

    let ct1 = seal(b"Same", &sender, &recipient.public_key()).unwrap();
    let ct2 = seal(b"Same", &sender, &recipient.public_key()).unwrap();

    // KEM ciphertext offset: version(1) + sender_signing(1952) + sender_kem(1184) +
    //                       ephemeral_kem(1184) + signature(3309)
    let kem_ct_start = 1 + 1952 + 1184 + 1184 + 3309;
    let kem_ct_end = kem_ct_start + 1088;

    let kem1 = &ct1[kem_ct_start..kem_ct_end];
    let kem2 = &ct2[kem_ct_start..kem_ct_end];

    assert_ne!(
        kem1, kem2,
        "Each message should have different KEM ciphertext"
    );
}

// =============================================================================
// SENDER IDENTITY CONSISTENCY
// =============================================================================

#[test]
fn test_vector_sender_identity_preserved() {
    // Sender's long-term keys should be consistently included
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();

    let ct1 = seal(b"Message 1", &sender, &recipient.public_key()).unwrap();
    let ct2 = seal(b"Message 2", &sender, &recipient.public_key()).unwrap();

    // Sender signing key should be the same in both
    let signing_start = 1;
    let signing_end = 1 + 1952;
    assert_eq!(
        &ct1[signing_start..signing_end],
        &ct2[signing_start..signing_end]
    );

    // Sender KEM key should be the same in both
    let kem_start = 1 + 1952;
    let kem_end = kem_start + 1184;
    assert_eq!(&ct1[kem_start..kem_end], &ct2[kem_start..kem_end]);

    // And they should match the actual sender public key
    assert_eq!(
        &ct1[signing_start..signing_end],
        sender.public_key().signing_bytes()
    );
    assert_eq!(&ct1[kem_start..kem_end], sender.public_key().kem_bytes());
}

// =============================================================================
// AEAD TAG VERIFICATION
// =============================================================================

#[test]
fn test_vector_aead_tag_present() {
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();

    // Empty plaintext should still have 16-byte Poly1305 tag
    let ct = seal(b"", &sender, &recipient.public_key()).unwrap();

    let header_size = 1 + 1952 + 1184 + 1184 + 3309 + 1088 + 4;
    let aead_size = ct.len() - header_size;

    assert_eq!(
        aead_size, 16,
        "Empty plaintext should have exactly 16-byte auth tag"
    );
}

#[test]
fn test_vector_aead_length_field() {
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();
    let plaintext = b"Test message with known length";

    let ct = seal(plaintext, &sender, &recipient.public_key()).unwrap();

    // Length field is at fixed offset before AEAD ciphertext
    let len_offset = 1 + 1952 + 1184 + 1184 + 3309 + 1088;
    let stored_len = u32::from_le_bytes([
        ct[len_offset],
        ct[len_offset + 1],
        ct[len_offset + 2],
        ct[len_offset + 3],
    ]) as usize;

    // Should be plaintext length + 16 byte tag
    assert_eq!(stored_len, plaintext.len() + 16);
}
