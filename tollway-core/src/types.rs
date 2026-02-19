//! Core cryptographic types for Tollway-Core.
//!
//! This module provides the fundamental cryptographic types used throughout Tollway-Core:
//!
//! - [`KeyPair`] - Complete keypair containing both signing and KEM keys
//! - [`PublicKey`] - Public portion of a keypair for encryption and verification
//!
//! # Key Components
//!
//! Each keypair contains two sub-components:
//! - **Signing keys** (ML-DSA-65): Used for digital signatures and authentication
//! - **KEM keys** (ML-KEM-768): Used for key encapsulation and encryption
//!
//! # Security
//!
//! Secret keys implement [`Zeroize`] and [`ZeroizeOnDrop`] to ensure sensitive
//! material is cleared from memory when no longer needed.

use pqcrypto::kem::mlkem768;
use pqcrypto::sign::mldsa65;
use pqcrypto::traits::kem::{PublicKey as KemPk, SecretKey as KemSk};
use pqcrypto::traits::sign::{PublicKey as SignPk, SecretKey as SignSk};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::TollwayError;
use crate::wire::serialize;

/// A complete keypair containing both signing and KEM keys
///
/// `KeyPair` intentionally does **not** implement [`Clone`].  Cloning would
/// create an untracked copy of secret key material, violating CSP isolation
/// requirements and widening the window for memory extraction attacks.
///
/// Use [`KeyPair::public_key()`] to obtain a cloneable [`PublicKey`].
pub struct KeyPair {
    pub(crate) signing: SigningKeyPair,
    pub(crate) kem: KEMKeyPair,
}

impl KeyPair {
    /// Generate a new random keypair.
    ///
    /// Creates a fresh ML-DSA-65 signing keypair and ML-KEM-768 KEM keypair
    /// using cryptographically secure randomness from the operating system.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tollway_core::KeyPair;
    ///
    /// let keypair = KeyPair::generate();
    /// let public_key = keypair.public_key();
    /// ```
    pub fn generate() -> Self {
        // Generate ML-DSA-65 signing keypair
        let (sign_pk, sign_sk) = mldsa65::keypair();

        // Generate ML-KEM-768 KEM keypair
        let (kem_pk, kem_sk) = mlkem768::keypair();

        Self {
            signing: SigningKeyPair {
                public: SigningPublicKey(sign_pk.as_bytes().to_vec()),
                secret: SigningSecretKey(sign_sk.as_bytes().to_vec()),
            },
            kem: KEMKeyPair {
                public: KEMPublicKey(kem_pk.as_bytes().to_vec()),
                secret: KEMSecretKey(kem_sk.as_bytes().to_vec()),
            },
        }
    }

    /// Returns the public key component of this keypair.
    ///
    /// The returned [`PublicKey`] can be freely shared with communication
    /// partners. It is used as the `recipient_public_key` argument to
    /// [`seal`](crate::seal).
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            signing: self.signing.public.clone(),
            kem: self.kem.public.clone(),
        }
    }

    /// Export the full keypair (including secret keys) to bytes.
    ///
    /// # Warning
    ///
    /// The returned bytes contain **unencrypted secret key material**.
    /// You **must** encrypt the output before writing it to disk or
    /// transmitting it over a network. Failure to do so exposes the
    /// signing and KEM secret keys to any observer.
    pub fn dangerous_export(&self) -> Vec<u8> {
        serialize::serialize_keypair(self)
    }

    /// Import a keypair from bytes previously produced by
    /// [`dangerous_export`](KeyPair::dangerous_export).
    ///
    /// # Warning
    ///
    /// The input must contain **unencrypted** secret key material in the
    /// Tollway keypair wire format. Callers should decrypt the data
    /// from a trusted source before calling this method.
    ///
    /// # Errors
    ///
    /// Returns [`TollwayError::InvalidKeyData`] if the magic bytes, version,
    /// or data length are incorrect.
    pub fn dangerous_import(data: &[u8]) -> Result<Self, TollwayError> {
        serialize::deserialize_keypair(data)
    }
}

/// The public portion of a [`KeyPair`], safe to share with others.
///
/// Contains the ML-DSA-65 signing public key and the ML-KEM-768 KEM public
/// key. A `PublicKey` is used as the `recipient_public_key` argument to
/// [`seal`](crate::seal) and is returned alongside the plaintext from
/// [`open`](crate::open) so the caller can identify the sender.
///
/// `PublicKey` implements [`Clone`] and [`PartialEq`], making it suitable
/// for storage in directories or trust stores.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub(crate) signing: SigningPublicKey,
    pub(crate) kem: KEMPublicKey,
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Only show first 8 bytes of each key to avoid huge debug output
        let signing_preview: Vec<_> = self.signing.0.iter().take(8).collect();
        let kem_preview: Vec<_> = self.kem.0.iter().take(8).collect();
        f.debug_struct("PublicKey")
            .field("signing", &format!("{:02x?}...", signing_preview))
            .field("kem", &format!("{:02x?}...", kem_preview))
            .finish()
    }
}

impl PublicKey {
    /// Get the raw bytes of the signing public key
    ///
    /// Useful for comparing sender identities or storing in a directory.
    pub fn signing_bytes(&self) -> &[u8] {
        &self.signing.0
    }

    /// Get the raw bytes of the KEM public key
    ///
    /// Useful for serialization or directory storage.
    pub fn kem_bytes(&self) -> &[u8] {
        &self.kem.0
    }

    /// Serialize this public key to its wire format.
    ///
    /// The output is a self-describing byte sequence (magic header + version +
    /// key material) that can be safely stored or shared out-of-band.
    ///
    /// Use [`PublicKey::from_bytes`] to reconstruct the key.
    pub fn to_bytes(&self) -> Vec<u8> {
        serialize::serialize_public_key(self)
    }

    /// Deserialize a public key from bytes previously produced by
    /// [`to_bytes`](PublicKey::to_bytes).
    ///
    /// # Errors
    ///
    /// Returns [`TollwayError::InvalidKeyData`] if the magic bytes, version,
    /// or data length are incorrect.
    pub fn from_bytes(data: &[u8]) -> Result<Self, TollwayError> {
        serialize::deserialize_public_key(data)
    }
}

/// Signing keypair (ML-DSA-65)
pub(crate) struct SigningKeyPair {
    pub(crate) public: SigningPublicKey,
    pub(crate) secret: SigningSecretKey,
}

/// Signing public key
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SigningPublicKey(pub(crate) Vec<u8>);

/// Signing secret key (zeroized on drop)
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct SigningSecretKey(pub(crate) Vec<u8>);

/// KEM keypair (ML-KEM-768)
pub(crate) struct KEMKeyPair {
    pub(crate) public: KEMPublicKey,
    pub(crate) secret: KEMSecretKey,
}

/// KEM public key
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct KEMPublicKey(pub(crate) Vec<u8>);

/// KEM secret key (zeroized on drop)
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct KEMSecretKey(pub(crate) Vec<u8>);
