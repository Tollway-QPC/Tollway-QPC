//! Secure memory wrappers with automatic zeroization.
//!
//! This module provides `SecretBytes` and `SecretVec`, which wrap
//! fixed-size arrays and dynamically-sized vectors respectively. Both
//! implement [`Zeroize`](zeroize::Zeroize) and
//! [`ZeroizeOnDrop`](zeroize::ZeroizeOnDrop), ensuring that secret key
//! material is overwritten with zeros when the value is dropped.
//!
//! These types are used internally to hold AEAD keys, KEM shared secrets,
//! and other sensitive values that must not persist in memory after use.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A fixed-size array wrapper that automatically zeros memory on drop.
/// Used for storing secret key material securely.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize>(pub(crate) [u8; N]);

impl<const N: usize> SecretBytes<N> {
    /// Create a new SecretBytes from a byte array
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Create SecretBytes filled with zeros
    pub fn zeroed() -> Self {
        Self([0u8; N])
    }

    /// Get a reference to the inner bytes
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    /// Get a mutable reference to the inner bytes
    pub fn as_bytes_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> AsRef<[u8]> for SecretBytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> From<[u8; N]> for SecretBytes<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
}

/// A dynamically-sized secret bytes container with automatic zeroing on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretVec(pub(crate) Vec<u8>);

impl SecretVec {
    /// Create a new SecretVec from a Vec
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get a reference to the inner bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get the length of the secret
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the secret is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for SecretVec {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for SecretVec {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}
