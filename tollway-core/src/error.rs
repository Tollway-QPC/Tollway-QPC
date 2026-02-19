//! Error types for Tollway cryptographic operations.
//!
//! All fallible functions in this crate return [`TollwayError`]. The error
//! variants are deliberately coarse-grained during decryption — the
//! [`open`](crate::open) function maps most crypto failures to
//! [`DecryptionFailed`](TollwayError::DecryptionFailed) to avoid leaking
//! which step failed (timing oracle prevention).
//!
//! When the `fips` feature is enabled, additional variants cover FIPS 140-3
//! lifecycle and compliance errors (self-test failures, uninitialized module,
//! and approved-mode violations).

use thiserror::Error;

/// Errors that can occur during Tollway cryptographic operations.
///
/// Most variants carry enough context to diagnose the failure category
/// without exposing secret-dependent information.
#[derive(Debug, Error)]
pub enum TollwayError {
    /// The ciphertext wire format is invalid, truncated, or corrupted.
    ///
    /// Returned by [`crate::open`] when the input cannot be parsed
    /// according to the Tollway wire format (version byte, field
    /// lengths, etc.).
    #[error("Invalid ciphertext format")]
    InvalidCiphertext,

    /// Signature verification failed — the sender could not be authenticated.
    ///
    /// This variant is used internally during signature verification but
    /// is **not** returned directly from [`crate::open`]; instead, it is
    /// folded into [`DecryptionFailed`](Self::DecryptionFailed) to prevent
    /// timing oracles.
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// Decryption or authentication failed.
    ///
    /// This is the unified error returned by [`crate::open`] when **any**
    /// cryptographic check fails (signature, KEM decapsulation, or AEAD
    /// decryption). The unified error prevents an attacker from
    /// distinguishing which step failed via response timing.
    #[error("Decryption failed")]
    DecryptionFailed,

    /// Key generation failed, typically due to an RNG issue.
    #[error("Key generation failed")]
    KeyGenerationFailed,

    /// ML-KEM-768 encapsulation failed.
    ///
    /// Usually caused by a malformed recipient public key.
    #[error("KEM encapsulation failed")]
    KEMEncapsulationFailed,

    /// ML-KEM-768 decapsulation failed.
    ///
    /// Indicates a corrupted KEM ciphertext or mismatched secret key.
    /// During decryption, this is mapped to [`DecryptionFailed`](Self::DecryptionFailed).
    #[error("KEM decapsulation failed")]
    KEMDecapsulationFailed,

    /// Key data is invalid or corrupted during deserialization.
    ///
    /// Returned by [`KeyPair::dangerous_import`](crate::KeyPair::dangerous_import)
    /// and [`PublicKey::from_bytes`](crate::PublicKey::from_bytes) when magic
    /// bytes, version, or data length do not match the expected format.
    #[error("Invalid key data: {0}")]
    InvalidKeyData(String),

    /// An internal error that should not occur under normal operation.
    ///
    /// If this error is encountered, it may indicate a bug or an
    /// incompatibility with the underlying cryptographic library.
    #[error("Internal error: {0}")]
    Internal(String),

    /// FIPS self-test failed during module initialization.
    ///
    /// The module transitions to the terminal `Error` state when this occurs.
    #[cfg(feature = "fips")]
    #[error("FIPS self-test failed: {0}")]
    SelfTestFailed(String),

    /// FIPS module has not been initialized.
    ///
    /// Call [`fips::initialize()`](crate::fips::initialize) before performing
    /// any FIPS-approved operations.
    #[cfg(feature = "fips")]
    #[error("FIPS module not initialized")]
    ModuleNotInitialized,

    /// Operation rejected: algorithm or operation is not FIPS-approved.
    #[cfg(feature = "fips")]
    #[error("FIPS approved mode violation: {0}")]
    ApprovedModeViolation(String),
}
