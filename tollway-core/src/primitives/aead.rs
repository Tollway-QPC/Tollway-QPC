// primitives/aead.rs - ChaCha20-Poly1305 operations

// encrypt(key, nonce, plaintext, associated_data) → ciphertext
// decrypt(key, nonce, ciphertext, associated_data) → plaintext
// wraps: chacha20poly1305 crate
// ensures: unique nonces (random generation), auth tag verification

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};

use crate::constants::{CHACHA20_POLY1305_KEY_BYTES, CHACHA20_POLY1305_NONCE_BYTES};
use crate::error::TollwayError;
use crate::secure::memory::SecretBytes;

/// Encrypt plaintext using ChaCha20-Poly1305 with associated data
///
/// The associated data is authenticated but not encrypted, binding the
/// ciphertext to its context (sender, recipient, ephemeral keys).
pub fn encrypt(
    key: &SecretBytes<CHACHA20_POLY1305_KEY_BYTES>,
    nonce: &[u8; CHACHA20_POLY1305_NONCE_BYTES],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, TollwayError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| TollwayError::Internal("Invalid AEAD key".to_string()))?;

    let nonce = Nonce::from_slice(nonce);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    cipher
        .encrypt(nonce, payload)
        .map_err(|_| TollwayError::Internal("AEAD encryption failed".to_string()))
}

/// Decrypt ciphertext using ChaCha20-Poly1305 with associated data
///
/// The associated data must match exactly what was used during encryption,
/// or decryption will fail with an authentication error.
pub fn decrypt(
    key: &SecretBytes<CHACHA20_POLY1305_KEY_BYTES>,
    nonce: &[u8; CHACHA20_POLY1305_NONCE_BYTES],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, TollwayError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| TollwayError::Internal("Invalid AEAD key".to_string()))?;

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
/// - Recipient's KEM public key (who can decrypt)
/// - Ephemeral KEM public key (this specific message)
///
/// This prevents cut-and-paste attacks and misbinding.
pub fn build_aad(
    sender_signing_pk: &[u8],
    recipient_kem_pk: &[u8],
    ephemeral_kem_pk: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        sender_signing_pk.len() + recipient_kem_pk.len() + ephemeral_kem_pk.len()
    );
    aad.extend_from_slice(sender_signing_pk);
    aad.extend_from_slice(recipient_kem_pk);
    aad.extend_from_slice(ephemeral_kem_pk);
    aad
}
