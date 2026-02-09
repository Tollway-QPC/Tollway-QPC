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

// types.rs - Core cryptographic types

// KeyPair { signing: SigningKeyPair, kem: KEMKeyPair }
// PublicKey { signing: SigningPublicKey, kem: KEMPublicKey }
// SecretKey (internal, never exposed directly)
// Ciphertext { version, sender_signing_pk, signed_ephemeral_pk, kem_ciphertext, aead_ciphertext }
// implements: Clone (public keys only), Zeroize (secret keys), Serialize/Deserializ

use pqcrypto::kem::mlkem768;
use pqcrypto::sign::mldsa65;
use pqcrypto::traits::kem::{PublicKey as KemPk, SecretKey as KemSk};
use pqcrypto::traits::sign::{PublicKey as SignPk, SecretKey as SignSk};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A complete keypair containing both signing and KEM keys
#[derive(Clone)]
pub struct KeyPair {
    pub(crate) signing: SigningKeyPair,
    pub(crate) kem: KEMKeyPair,
}

impl KeyPair {
    /// Generate a new random keypair
    ///
    /// Uses cryptographically secure randomness for both signing and KEM keys.
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

    /// Get the public key component
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            signing: self.signing.public.clone(),
            kem: self.kem.public.clone(),
        }
    }
}

/// Public key (safe to share)
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
}

/// Signing keypair (ML-DSA-65)
#[derive(Clone)]
pub(crate) struct SigningKeyPair {
    pub(crate) public: SigningPublicKey,
    pub(crate) secret: SigningSecretKey,
}

/// Signing public key
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SigningPublicKey(pub(crate) Vec<u8>);

/// Signing secret key (zeroized on drop)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct SigningSecretKey(pub(crate) Vec<u8>);

/// KEM keypair (ML-KEM-768)
#[derive(Clone)]
pub(crate) struct KEMKeyPair {
    pub(crate) public: KEMPublicKey,
    pub(crate) secret: KEMSecretKey,
}

/// KEM public key
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct KEMPublicKey(pub(crate) Vec<u8>);

/// KEM secret key (zeroized on drop)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct KEMSecretKey(pub(crate) Vec<u8>);
