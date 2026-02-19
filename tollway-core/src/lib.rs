//! # Tollway-Core
//!
//! Post-quantum authenticated encryption with forward secrecy.
//!
//! Tollway-Core provides a high-level API for encrypting and decrypting messages
//! using NIST-standardized post-quantum cryptographic algorithms. It is designed
//! to protect against both classical and quantum adversaries, including
//! harvest-now-decrypt-later (HNDL) attacks.
//!
//! ## Quick Start
//!
//! ```rust
//! use tollway_core::{KeyPair, seal, open};
//!
//! // Generate keypairs for sender and recipient
//! let sender = KeyPair::generate();
//! let recipient = KeyPair::generate();
//!
//! // Encrypt a message
//! let plaintext = b"Hello, post-quantum world!";
//! let ciphertext = seal(plaintext, &sender, &recipient.public_key())
//!     .expect("encryption failed");
//!
//! // Decrypt the message
//! let (recovered, sender_pk) = open(&ciphertext, &recipient)
//!     .expect("decryption failed");
//!
//! assert_eq!(recovered, plaintext);
//! assert_eq!(sender_pk, sender.public_key());
//! ```
//!
//! ## Algorithms
//!
//! | Purpose              | Algorithm           | NIST Level |
//! |----------------------|---------------------|------------|
//! | Key Encapsulation    | ML-KEM-768          | 3          |
//! | Digital Signatures   | ML-DSA-65           | 3          |
//! | Symmetric Encryption | ChaCha20-Poly1305   | —          |
//! | Key Derivation       | HKDF-SHA3-256       | —          |
//!
//! ## Security Properties
//!
//! - **IND-CCA2 confidentiality** — ciphertexts are indistinguishable under
//!   adaptive chosen-ciphertext attack.
//! - **EUF-CMA authentication** — the sender's identity is bound to every
//!   message via ML-DSA-65 signatures.
//! - **Forward secrecy** — each message uses a fresh ephemeral KEM keypair;
//!   compromising long-term keys does not reveal past messages.
//! - **Constant-time error handling** — decryption does not leak which
//!   cryptographic step failed, preventing timing oracles.
//!
//! ## Feature Flags
//!
//! | Feature  | Description                                              |
//! |----------|----------------------------------------------------------|
//! | `serde`  | Enables `serde::Serialize` / `serde::Deserialize` impls  |
//! | `fips`   | FIPS 140-3 mode: AES-256-GCM backend, memory locking,    |
//! |          | module lifecycle FSM                                      |
//!
//! ## Modules
//!
//! - [`constants`] — Protocol version bytes, algorithm sizes, and HKDF context
//!   strings.
//! - [`error`] — The [`TollwayError`] enum covering all failure modes.
//! - [`primitives`] — Low-level cryptographic building blocks (AEAD, KDF, KEM,
//!   signatures).
//! - [`secure`] — Constant-time operations and secure memory wrappers.
//! - [`types`] — Core types: [`KeyPair`] and [`PublicKey`].
//! - [`wire`] — Wire format encoding/decoding for ciphertexts and keys.

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

/// Encrypts and authenticates a message for a specific recipient.
///
/// `seal` performs the following steps:
///
/// 1. Generates an ephemeral ML-KEM-768 keypair (provides forward secrecy).
/// 2. Signs the ephemeral public key with the sender's ML-DSA-65 signing key
///    (binds the sender's identity to this message).
/// 3. Encapsulates a shared secret to the recipient's KEM public key.
/// 4. Derives an AEAD key and nonce from the shared secret via HKDF-SHA3-256.
/// 5. Encrypts the plaintext with ChaCha20-Poly1305, using associated data
///    (AAD) that binds the ciphertext to all participants and the ephemeral key.
/// 6. Assembles the result into the Tollway v2 wire format.
///
/// # Arguments
///
/// * `plaintext` — The message to encrypt. May be empty.
/// * `sender_keypair` — The sender's long-term [`KeyPair`], used for signing.
/// * `recipient_public_key` — The recipient's [`PublicKey`], used for encryption.
///
/// # Errors
///
/// Returns [`TollwayError::KEMEncapsulationFailed`] if the recipient's public
/// key is malformed, or [`TollwayError::Internal`] if an unexpected failure
/// occurs in key derivation or AEAD encryption.
///
/// # Examples
///
/// ```rust
/// use tollway_core::{KeyPair, seal};
///
/// let sender = KeyPair::generate();
/// let recipient = KeyPair::generate();
///
/// let ciphertext = seal(b"secret data", &sender, &recipient.public_key())
///     .expect("seal failed");
///
/// // The ciphertext is ~8.7 KB larger than the plaintext (fixed overhead).
/// assert!(ciphertext.len() > 11);
/// ```
pub fn seal(
    plaintext: &[u8],
    sender_keypair: &KeyPair,
    recipient_public_key: &PublicKey,
) -> Result<Vec<u8>, TollwayError> {
    seal::seal(plaintext, sender_keypair, recipient_public_key)
}

/// Decrypts and verifies an authenticated message.
///
/// `open` performs the following steps:
///
/// 1. Parses the Tollway wire format to extract all fields.
/// 2. Verifies the ML-DSA-65 signature on the ephemeral KEM public key
///    (authenticates the sender). The result is captured without
///    early-exit to prevent timing oracles.
/// 3. Decapsulates the KEM ciphertext to recover the shared secret.
/// 4. Derives the AEAD key and nonce via HKDF-SHA3-256.
/// 5. Decrypts and verifies the ChaCha20-Poly1305 ciphertext with AAD.
/// 6. Returns the plaintext and the sender's [`PublicKey`] only if **all**
///    cryptographic checks pass.
///
/// # Arguments
///
/// * `ciphertext` — The sealed message produced by [`seal`].
/// * `recipient_keypair` — The recipient's long-term [`KeyPair`], used for
///   decapsulation.
///
/// # Returns
///
/// On success, returns `(plaintext, sender_public_key)`. The caller should
/// compare `sender_public_key` against a known identity to confirm who sent
/// the message.
///
/// # Errors
///
/// Returns [`TollwayError::InvalidCiphertext`] if the wire format is
/// malformed or too short. Returns [`TollwayError::DecryptionFailed`] if
/// any cryptographic verification step fails (signature, KEM, or AEAD).
/// The unified error deliberately hides which step failed to prevent
/// timing-based oracle attacks.
///
/// # Examples
///
/// ```rust
/// use tollway_core::{KeyPair, seal, open};
///
/// let sender = KeyPair::generate();
/// let recipient = KeyPair::generate();
///
/// let ciphertext = seal(b"hello", &sender, &recipient.public_key()).unwrap();
/// let (plaintext, sender_pk) = open(&ciphertext, &recipient).unwrap();
///
/// assert_eq!(plaintext, b"hello");
/// assert_eq!(sender_pk, sender.public_key());
/// ```
pub fn open(
    ciphertext: &[u8],
    recipient_keypair: &KeyPair,
) -> Result<(Vec<u8>, PublicKey), TollwayError> {
    open::open(ciphertext, recipient_keypair)
}
