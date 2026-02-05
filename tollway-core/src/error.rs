// error.rs - Error types with context

// TollwayError::InvalidCiphertext, DecryptionFailed, SignatureVerificationFailed, etc.
// includes: algorithm identifier, operation that failed, optional context

//! Error types

use thiserror::Error;

/// Errors that can occur during cryptographic operations
#[derive(Debug, Error)]
pub enum TollwayError {
    /// Ciphertext format is invalid or corrupted
    #[error("Invalid ciphertext format")]
    InvalidCiphertext,

    /// Signature verification failed (sender authentication failed)
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// AEAD decryption or authentication failed
    #[error("Decryption failed")]
    DecryptionFailed,

    /// Key generation failed (RNG issue)
    #[error("Key generation failed")]
    KeyGenerationFailed,

    /// KEM encapsulation failed
    #[error("KEM encapsulation failed")]
    KEMEncapsulationFailed,

    /// KEM decapsulation failed
    #[error("KEM decapsulation failed")]
    KEMDecapsulationFailed,

    /// Internal error (should never happen)
    #[error("Internal error: {0}")]
    Internal(String),
}
