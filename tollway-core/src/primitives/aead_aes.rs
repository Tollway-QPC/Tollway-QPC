//! AES-256-GCM AEAD primitives (FIPS-approved)
//!
//! Mirrors the API surface of the ChaCha20-Poly1305 module (`aead.rs`)
//! so that `seal`/`open` can dispatch to either backend.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};

use crate::constants::{AES_256_GCM_KEY_BYTES, AES_256_GCM_NONCE_BYTES};
use crate::error::TollwayError;
use crate::secure::memory::SecretBytes;

/// Encrypt plaintext using AES-256-GCM with associated data
///
/// The associated data is authenticated but not encrypted, binding the
/// ciphertext to its context (sender, recipient, ephemeral keys).
pub fn encrypt(
    key: &SecretBytes<AES_256_GCM_KEY_BYTES>,
    nonce: &[u8; AES_256_GCM_NONCE_BYTES],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, TollwayError> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|_| TollwayError::Internal("Invalid AES-256-GCM key".to_string()))?;

    let nonce = Nonce::from_slice(nonce);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    cipher
        .encrypt(nonce, payload)
        .map_err(|_| TollwayError::Internal("AES-256-GCM encryption failed".to_string()))
}

/// Decrypt ciphertext using AES-256-GCM with associated data
///
/// The associated data must match exactly what was used during encryption,
/// or decryption will fail with an authentication error.
pub fn decrypt(
    key: &SecretBytes<AES_256_GCM_KEY_BYTES>,
    nonce: &[u8; AES_256_GCM_NONCE_BYTES],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, TollwayError> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|_| TollwayError::Internal("Invalid AES-256-GCM key".to_string()))?;

    let nonce = Nonce::from_slice(nonce);

    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| TollwayError::DecryptionFailed)
}

/// Build the associated data for AEAD from cryptographic context
///
/// Binds the ciphertext to:
/// - Sender's signing public key (who sent this)
/// - Sender's KEM public key (authenticates reply address)
/// - Recipient's KEM public key (who can decrypt)
/// - Ephemeral KEM public key (this specific message)
///
/// This is identical to `aead::build_aad` -- duplicated here so the FIPS
/// module can call `aead_aes::build_aad` without pulling in the non-approved
/// ChaCha20 module.
pub fn build_aad(
    sender_signing_pk: &[u8],
    sender_kem_pk: &[u8],
    recipient_kem_pk: &[u8],
    ephemeral_kem_pk: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        sender_signing_pk.len()
            + sender_kem_pk.len()
            + recipient_kem_pk.len()
            + ephemeral_kem_pk.len(),
    );
    aad.extend_from_slice(sender_signing_pk);
    aad.extend_from_slice(sender_kem_pk);
    aad.extend_from_slice(recipient_kem_pk);
    aad.extend_from_slice(ephemeral_kem_pk);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{AES_256_GCM_KEY_BYTES, AES_256_GCM_NONCE_BYTES};
    use crate::secure::memory::SecretBytes;

    fn test_key() -> SecretBytes<AES_256_GCM_KEY_BYTES> {
        SecretBytes::new([0x42u8; AES_256_GCM_KEY_BYTES])
    }

    fn test_nonce() -> [u8; AES_256_GCM_NONCE_BYTES] {
        [0x01u8; AES_256_GCM_NONCE_BYTES]
    }

    #[test]
    fn round_trip() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"hello, FIPS world";
        let aad = b"context";

        let ciphertext = encrypt(&key, &nonce, plaintext, aad).expect("encrypt");
        let recovered = decrypt(&key, &nonce, &ciphertext, aad).expect("decrypt");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"secret";
        let aad = b"ctx";

        let ciphertext = encrypt(&key, &nonce, plaintext, aad).expect("encrypt");

        let wrong_key = SecretBytes::new([0xFFu8; AES_256_GCM_KEY_BYTES]);
        let result = decrypt(&wrong_key, &nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"secret";
        let aad = b"ctx";

        let ciphertext = encrypt(&key, &nonce, plaintext, aad).expect("encrypt");

        let result = decrypt(&key, &nonce, &ciphertext, b"wrong-ctx");
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"secret";
        let aad = b"ctx";

        let mut ciphertext = encrypt(&key, &nonce, plaintext, aad).expect("encrypt");
        ciphertext[0] ^= 0xFF;

        let result = decrypt(&key, &nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn build_aad_concatenates() {
        let aad = build_aad(b"sign", b"snd_kem", b"rcv_kem", b"eph");
        assert_eq!(aad, b"signsnd_kemrcv_kemeph");
    }

    #[test]
    fn empty_plaintext_round_trip() {
        let key = test_key();
        let nonce = test_nonce();
        let aad = b"ctx";

        let ciphertext = encrypt(&key, &nonce, b"", aad).expect("encrypt");
        let recovered = decrypt(&key, &nonce, &ciphertext, aad).expect("decrypt");
        assert!(recovered.is_empty());
    }
}
