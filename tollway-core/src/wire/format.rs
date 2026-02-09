// wire/format.rs - Ciphertext wire format

// Ciphertext serialization: version || sender_pk || signature || kem_ct || aead_ct
// versioning: allows algorithm upgrades without breaking compatibility
// includes: length prefixes, type tags for forward compatibility

use crate::constants::{
    ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES, ML_KEM_768_CIPHERTEXT_BYTES,
    ML_KEM_768_PUBLIC_KEY_BYTES, TOLLWAY_VERSION_1,
};
use crate::error::TollwayError;
use crate::types::{KEMPublicKey, SigningPublicKey};

/// Parsed ciphertext structure
pub(crate) struct ParsedCiphertext {
    pub(crate) _version: u8,
    pub(crate) sender_signing_public: SigningPublicKey,
    pub(crate) sender_kem_public: KEMPublicKey,
    pub(crate) ephemeral_kem_public: KEMPublicKey,
    pub(crate) signature: Vec<u8>,
    pub(crate) kem_ciphertext: Vec<u8>,
    pub(crate) aead_ciphertext: Vec<u8>,
}

/// Build the wire format ciphertext
///
/// Format (V1):
/// - version: 1 byte
/// - sender_signing_pk: ML_DSA_65_PUBLIC_KEY_BYTES
/// - sender_kem_pk: ML_KEM_768_PUBLIC_KEY_BYTES
/// - ephemeral_kem_pk: ML_KEM_768_PUBLIC_KEY_BYTES
/// - signature: ML_DSA_65_SIGNATURE_BYTES
/// - kem_ciphertext: ML_KEM_768_CIPHERTEXT_BYTES
/// - aead_ciphertext_len: 4 bytes (u32 little-endian)
/// - aead_ciphertext: variable length
pub(crate) fn build_ciphertext(
    sender_signing_pk: &SigningPublicKey,
    sender_kem_pk: &KEMPublicKey,
    ephemeral_kem_pk: &KEMPublicKey,
    signature: &[u8],
    kem_ciphertext: &[u8],
    aead_ciphertext: &[u8],
) -> Result<Vec<u8>, TollwayError> {
    // Validate sizes
    if sender_signing_pk.0.len() != ML_DSA_65_PUBLIC_KEY_BYTES {
        return Err(TollwayError::Internal(
            "Invalid sender signing public key size".to_string(),
        ));
    }
    if sender_kem_pk.0.len() != ML_KEM_768_PUBLIC_KEY_BYTES {
        return Err(TollwayError::Internal(
            "Invalid sender KEM public key size".to_string(),
        ));
    }
    if ephemeral_kem_pk.0.len() != ML_KEM_768_PUBLIC_KEY_BYTES {
        return Err(TollwayError::Internal(
            "Invalid ephemeral KEM public key size".to_string(),
        ));
    }
    if signature.len() != ML_DSA_65_SIGNATURE_BYTES {
        return Err(TollwayError::Internal("Invalid signature size".to_string()));
    }
    if kem_ciphertext.len() != ML_KEM_768_CIPHERTEXT_BYTES {
        return Err(TollwayError::Internal(
            "Invalid KEM ciphertext size".to_string(),
        ));
    }

    let total_len = 1  // version
        + ML_DSA_65_PUBLIC_KEY_BYTES
        + ML_KEM_768_PUBLIC_KEY_BYTES  // sender_kem_pk
        + ML_KEM_768_PUBLIC_KEY_BYTES  // ephemeral_kem_pk
        + ML_DSA_65_SIGNATURE_BYTES
        + ML_KEM_768_CIPHERTEXT_BYTES
        + 4  // aead_ciphertext length
        + aead_ciphertext.len();

    let mut output = Vec::with_capacity(total_len);

    // Version
    output.push(TOLLWAY_VERSION_1);

    // Sender signing public key
    output.extend_from_slice(&sender_signing_pk.0);

    // Sender KEM public key (allows recipient to reply)
    output.extend_from_slice(&sender_kem_pk.0);

    // Ephemeral KEM public key
    output.extend_from_slice(&ephemeral_kem_pk.0);

    // Signature
    output.extend_from_slice(signature);

    // KEM ciphertext
    output.extend_from_slice(kem_ciphertext);

    // AEAD ciphertext length (u32 little-endian)
    let aead_len = aead_ciphertext.len() as u32;
    output.extend_from_slice(&aead_len.to_le_bytes());

    // AEAD ciphertext
    output.extend_from_slice(aead_ciphertext);

    Ok(output)
}

/// Parse a wire format ciphertext
pub(crate) fn parse_ciphertext(data: &[u8]) -> Result<ParsedCiphertext, TollwayError> {
    // Minimum size check
    let min_size = 1  // version
        + ML_DSA_65_PUBLIC_KEY_BYTES
        + ML_KEM_768_PUBLIC_KEY_BYTES  // sender_kem_pk
        + ML_KEM_768_PUBLIC_KEY_BYTES  // ephemeral_kem_pk
        + ML_DSA_65_SIGNATURE_BYTES
        + ML_KEM_768_CIPHERTEXT_BYTES
        + 4; // aead_ciphertext length

    if data.len() < min_size {
        return Err(TollwayError::InvalidCiphertext);
    }

    let mut offset = 0;

    // Version
    let version = data[offset];
    offset += 1;

    if version != TOLLWAY_VERSION_1 {
        return Err(TollwayError::InvalidCiphertext);
    }

    // Sender signing public key
    let sender_signing_public =
        SigningPublicKey(data[offset..offset + ML_DSA_65_PUBLIC_KEY_BYTES].to_vec());
    offset += ML_DSA_65_PUBLIC_KEY_BYTES;

    // Sender KEM public key
    let sender_kem_public =
        KEMPublicKey(data[offset..offset + ML_KEM_768_PUBLIC_KEY_BYTES].to_vec());
    offset += ML_KEM_768_PUBLIC_KEY_BYTES;

    // Ephemeral KEM public key
    let ephemeral_kem_public =
        KEMPublicKey(data[offset..offset + ML_KEM_768_PUBLIC_KEY_BYTES].to_vec());
    offset += ML_KEM_768_PUBLIC_KEY_BYTES;

    // Signature
    let signature = data[offset..offset + ML_DSA_65_SIGNATURE_BYTES].to_vec();
    offset += ML_DSA_65_SIGNATURE_BYTES;

    // KEM ciphertext
    let kem_ciphertext = data[offset..offset + ML_KEM_768_CIPHERTEXT_BYTES].to_vec();
    offset += ML_KEM_768_CIPHERTEXT_BYTES;

    // AEAD ciphertext length
    if data.len() < offset + 4 {
        return Err(TollwayError::InvalidCiphertext);
    }
    let aead_len = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    // AEAD ciphertext
    if data.len() < offset + aead_len {
        return Err(TollwayError::InvalidCiphertext);
    }
    let aead_ciphertext = data[offset..offset + aead_len].to_vec();

    Ok(ParsedCiphertext {
        _version: version,
        sender_signing_public,
        sender_kem_public,
        ephemeral_kem_public,
        signature,
        kem_ciphertext,
        aead_ciphertext,
    })
}
