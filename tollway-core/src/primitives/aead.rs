// primitives/aead.rs - ChaCha20-Poly1305 operations

// encrypt(key, nonce, plaintext, associated_data) → ciphertext
// decrypt(key, nonce, ciphertext, associated_data) → plaintext
// wraps: chacha20poly1305 crate
// ensures: unique nonces (random generation), auth tag verification

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

use crate::constants::{CHACHA20_POLY1305_KEY_BYTES, CHACHA20_POLY1305_NONCE_BYTES};
use crate::error::TollwayError;
use crate::secure::memory::SecretBytes;

/// Encrypt plaintext using ChaCha20-Poly1305
pub fn encrypt(
    key: &SecretBytes<CHACHA20_POLY1305_KEY_BYTES>,
    nonce: &[u8; CHACHA20_POLY1305_NONCE_BYTES],
    plaintext: &[u8],
) -> Result<Vec<u8>, TollwayError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| TollwayError::Internal("Invalid AEAD key".to_string()))?;

    let nonce = Nonce::from_slice(nonce);

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| TollwayError::Internal("AEAD encryption failed".to_string()))
}

/// Decrypt ciphertext using ChaCha20-Poly1305
pub fn decrypt(
    key: &SecretBytes<CHACHA20_POLY1305_KEY_BYTES>,
    nonce: &[u8; CHACHA20_POLY1305_NONCE_BYTES],
    ciphertext: &[u8],
) -> Result<Vec<u8>, TollwayError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| TollwayError::Internal("Invalid AEAD key".to_string()))?;

    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| TollwayError::DecryptionFailed)
}
