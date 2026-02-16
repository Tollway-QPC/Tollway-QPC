use hkdf::Hkdf;
use sha3::Sha3_256;

use crate::constants::{
    CHACHA20_POLY1305_KEY_BYTES, CHACHA20_POLY1305_NONCE_BYTES, HKDF_CONTEXT_AEAD,
    HKDF_CONTEXT_NONCE,
};
use crate::error::TollwayError;
use crate::secure::memory::{SecretBytes, SecretVec};

/// Derive an AEAD key from a shared secret
pub fn derive_aead_key(
    shared_secret: &SecretVec,
) -> Result<SecretBytes<CHACHA20_POLY1305_KEY_BYTES>, TollwayError> {
    let mut key = [0u8; CHACHA20_POLY1305_KEY_BYTES];
    derive_key(shared_secret.as_bytes(), HKDF_CONTEXT_AEAD, &mut key)?;
    Ok(SecretBytes::new(key))
}

/// Derive an AEAD nonce from a shared secret
pub fn derive_aead_nonce(
    shared_secret: &SecretVec,
) -> Result<[u8; CHACHA20_POLY1305_NONCE_BYTES], TollwayError> {
    let mut nonce = [0u8; CHACHA20_POLY1305_NONCE_BYTES];
    derive_key(shared_secret.as_bytes(), HKDF_CONTEXT_NONCE, &mut nonce)?;
    Ok(nonce)
}

/// Generic key derivation using HKDF-SHA3-256
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
