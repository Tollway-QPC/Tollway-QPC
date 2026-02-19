//! ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD).
//!
//! This module provides the default symmetric encryption backend for
//! Tollway-Core. ChaCha20-Poly1305 was chosen for its constant-time
//! software implementation and resistance to cache-timing attacks,
//! making it suitable for environments without hardware AES support.
//!
//! When the `fips` feature is enabled, the FIPS module uses an
//! AES-256-GCM backend (`aead_aes`) instead.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};

use crate::constants::{CHACHA20_POLY1305_KEY_BYTES, CHACHA20_POLY1305_NONCE_BYTES};
use crate::error::TollwayError;
use crate::secure::memory::SecretBytes;

/// Encrypts `plaintext` with ChaCha20-Poly1305 and authenticates it along
/// with the provided associated data (`aad`).
///
/// The returned ciphertext includes a 16-byte Poly1305 authentication tag
/// appended to the encrypted payload.
///
/// # Arguments
///
/// * `key` — A 256-bit symmetric key wrapped in [`SecretBytes`].
/// * `nonce` — A 96-bit nonce. **Must never be reused** with the same key.
/// * `plaintext` — The data to encrypt. May be empty.
/// * `aad` — Associated data that is authenticated but **not** encrypted.
///   Binds the ciphertext to its cryptographic context (sender, recipient,
///   and ephemeral keys).
///
/// # Errors
///
/// Returns [`TollwayError::Internal`] if the key is invalid or the
/// underlying cipher fails unexpectedly.
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

/// Decrypts `ciphertext` with ChaCha20-Poly1305 and verifies the
/// authentication tag and associated data.
///
/// # Arguments
///
/// * `key` — The same 256-bit key used during [`encrypt`].
/// * `nonce` — The same 96-bit nonce used during [`encrypt`].
/// * `ciphertext` — The output of a previous [`encrypt`] call (payload + tag).
/// * `aad` — The same associated data used during [`encrypt`]. If it differs,
///   authentication will fail.
///
/// # Errors
///
/// Returns [`TollwayError::Internal`] if the key is invalid.
/// Returns [`TollwayError::DecryptionFailed`] if the authentication tag
/// does not verify (wrong key, wrong nonce, tampered ciphertext, or
/// mismatched AAD).
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

/// Constructs the Associated Authenticated Data (AAD) from cryptographic
/// context.
///
/// The AAD binds the AEAD ciphertext to all protocol participants and the
/// ephemeral key, preventing cut-and-paste and substitution attacks:
///
/// ```text
/// AAD = sender_signing_pk || sender_kem_pk || recipient_kem_pk || ephemeral_kem_pk
/// ```
///
/// # Arguments
///
/// * `sender_signing_pk` — Sender's ML-DSA-65 public key bytes.
/// * `sender_kem_pk` — Sender's ML-KEM-768 public key bytes. In protocol
///   v2 this is included in the AAD; in v1 it may be empty for backward
///   compatibility.
/// * `recipient_kem_pk` — Recipient's ML-KEM-768 public key bytes.
/// * `ephemeral_kem_pk` — Ephemeral ML-KEM-768 public key bytes for this
///   specific message.
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
