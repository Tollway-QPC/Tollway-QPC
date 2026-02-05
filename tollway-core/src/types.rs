// types.rs - Core cryptographic types

// KeyPair { signing: SigningKeyPair, kem: KEMKeyPair }
// PublicKey { signing: SigningPublicKey, kem: KEMPublicKey }
// SecretKey (internal, never exposed directly)
// Ciphertext { version, sender_signing_pk, signed_ephemeral_pk, kem_ciphertext, aead_ciphertext }
// implements: Clone (public keys only), Zeroize (secret keys), Serialize/Deserialize

use crate::error::TollwayError;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A complete keypair containing both signing and KEM keys
#[derive(Clone)]
pub struct KeyPair {
    pub(crate) signing: SigningKeyPair,
    pub(crate) kem: KEMKeyPair,
}

impl KeyPair {
    /// Generate a new random keypair

    /// Uses cryptographically secure randomness for both signing and KEM keys.
    pub fn generate() -> Self {
        todo!("Implementation: Generate ML-DSA-65 and ML-KEM-768 keypairs")
    }

    /// Get the public key component
    pub fn public_key(&self) -> PublicKey {
        todo!("Implementation: Extract public keys")
    }
}

/// Public key (safe to share)
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub(crate) signing: SigningPublicKey,
    pub(crate) kem: KEMPublicKey,
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
