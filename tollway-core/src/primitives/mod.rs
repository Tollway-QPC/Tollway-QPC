//! Low-level cryptographic primitives.
//!
//! This module groups the building blocks used by [`seal`](crate::seal) and
//! [`open`](crate::open):
//!
//! - [`aead`] — ChaCha20-Poly1305 authenticated encryption (default backend).
//! - [`kdf`] — HKDF-SHA3-256 key and nonce derivation.
//! - [`kem`] — ML-KEM-768 key encapsulation and decapsulation.
//! - [`signature`] — ML-DSA-65 digital signatures.
//!
//! When the `fips` feature is enabled, an `aead_aes` module provides an
//! AES-256-GCM backend that mirrors the `aead` API surface.

/// ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD).
pub mod aead;
/// HKDF-SHA3-256 key derivation.
pub mod kdf;
/// ML-KEM-768 Key Encapsulation Mechanism.
pub mod kem;
/// ML-DSA-65 digital signatures.
pub mod signature;

/// AES-256-GCM AEAD primitives (FIPS-approved).
#[cfg(feature = "fips")]
pub mod aead_aes;
