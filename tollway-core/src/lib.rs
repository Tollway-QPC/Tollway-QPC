//! Tollway-Core: Post-quantum cryptographic primitives
//!
//! Provides quantum-resistant encryption with forward secrecy and authentication.
//! Built on NIST-standardized algorithms: ML-KEM-768, ML-DSA-65, ChaCha20-Poly1305.

#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    missing_copy_implementations,
    non_camel_case_types,
    unused,
    rust_2024_compatibility
)]

pub mod constants;
pub mod error;
#[cfg(feature = "fips")]
pub mod fips;
pub mod primitives;
pub mod secure;
pub mod types;
pub mod wire;

mod open;
mod seal;

pub use error::TollwayError;
pub use types::{KeyPair, PublicKey};

/// Encrypts plaintext using post-quantum cryptography with authentication.
/// Seals the plaintext for the recipient using the sender's keypair for authentication
/// and the recipient's public key for encryption.
pub fn seal(
    plaintext: &[u8],
    sender_keypair: &KeyPair,
    recipient_public_key: &PublicKey,
) -> Result<Vec<u8>, TollwayError> {
    seal::seal(plaintext, sender_keypair, recipient_public_key)
}

/// Decrypts ciphertext using post-quantum cryptography with authentication.
/// Opens the ciphertext using the recipient's keypair and returns the plaintext
/// along with the sender's public key for identity verification.
pub fn open(
    ciphertext: &[u8],
    recipient_keypair: &KeyPair,
) -> Result<(Vec<u8>, PublicKey), TollwayError> {
    open::open(ciphertext, recipient_keypair)
}
