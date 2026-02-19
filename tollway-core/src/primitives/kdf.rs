//! Key Derivation using HKDF-SHA3-256.
//!
//! This module derives AEAD keys and nonces from the ML-KEM shared secret
//! using HKDF (RFC 5869) instantiated with SHA3-256. Domain-separation
//! strings (see [`constants::HKDF_CONTEXT_AEAD`](crate::constants::HKDF_CONTEXT_AEAD)
//! and [`constants::HKDF_CONTEXT_NONCE`](crate::constants::HKDF_CONTEXT_NONCE))
//! ensure that the key and nonce derivations are cryptographically
//! independent even when fed the same input key material.

use hkdf::Hkdf;
use sha3::Sha3_256;
use zeroize::Zeroizing;

use crate::constants::{
    CHACHA20_POLY1305_KEY_BYTES, CHACHA20_POLY1305_NONCE_BYTES, HKDF_CONTEXT_AEAD,
    HKDF_CONTEXT_NONCE,
};
use crate::error::TollwayError;
use crate::secure::memory::{SecretBytes, SecretVec};

/// Derives a 256-bit AEAD key from a KEM shared secret.
///
/// Uses the domain-separation context
/// [`HKDF_CONTEXT_AEAD`] to ensure
/// the derived key is independent of the nonce derived by
/// [`derive_aead_nonce`].
///
/// # Errors
///
/// Returns [`TollwayError::Internal`] if HKDF expansion fails (should not
/// occur with valid inputs and a 32-byte output length).
pub fn derive_aead_key(
    shared_secret: &SecretVec,
) -> Result<SecretBytes<CHACHA20_POLY1305_KEY_BYTES>, TollwayError> {
    let mut key = Zeroizing::new([0u8; CHACHA20_POLY1305_KEY_BYTES]);
    derive_key(shared_secret.as_bytes(), HKDF_CONTEXT_AEAD, key.as_mut())?;
    Ok(SecretBytes::new(*key))
}

/// Derives a 96-bit AEAD nonce from a KEM shared secret.
///
/// Uses the domain-separation context
/// [`HKDF_CONTEXT_NONCE`] to ensure
/// the derived nonce is independent of the key derived by
/// [`derive_aead_key`].
///
/// # Errors
///
/// Returns [`TollwayError::Internal`] if HKDF expansion fails.
pub fn derive_aead_nonce(
    shared_secret: &SecretVec,
) -> Result<[u8; CHACHA20_POLY1305_NONCE_BYTES], TollwayError> {
    let mut nonce = [0u8; CHACHA20_POLY1305_NONCE_BYTES];
    derive_key(shared_secret.as_bytes(), HKDF_CONTEXT_NONCE, &mut nonce)?;
    Ok(nonce)
}

/// Low-level HKDF-SHA3-256 key derivation.
///
/// Runs the HKDF extract-then-expand flow with an empty salt (HKDF uses
/// a default zero-filled salt internally) and the provided `info` string
/// for domain separation.
///
/// # Arguments
///
/// * `input_key_material` — The raw shared secret from KEM decapsulation.
/// * `info` — A context/domain-separation string (e.g.,
///   [`HKDF_CONTEXT_AEAD`]).
/// * `output` — The buffer to fill with derived key material. Its length
///   determines how many bytes are produced.
///
/// # Errors
///
/// Returns [`TollwayError::Internal`] if HKDF expansion fails (e.g.,
/// requested output length exceeds `255 * HashLen`).
pub fn derive_key(
    input_key_material: &[u8],
    info: &[u8],
    output: &mut [u8],
) -> Result<(), TollwayError> {
    // Use empty salt (HKDF will use a default zero-filled salt)
    let hkdf = Hkdf::<Sha3_256>::new(None, input_key_material);

    hkdf.expand(info, output)
        .map_err(|_| TollwayError::Internal("HKDF expansion failed".to_string()))?;

    Ok(())
}
