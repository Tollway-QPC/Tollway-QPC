//! Algorithm constants, protocol versions, and wire format sizes.
//!
//! This module centralizes every magic number used by Tollway-Core so that
//! protocol changes only require updates in one place. Constants are grouped
//! by subsystem:
//!
//! - **Protocol versions** — [`TOLLWAY_VERSION_1`], [`TOLLWAY_VERSION_2`]
//! - **ML-KEM-768** — Public key, secret key, ciphertext, and shared secret sizes
//! - **ML-DSA-65** — Public key, secret key, and signature sizes
//! - **ChaCha20-Poly1305** — Key, nonce, and tag sizes
//! - **AES-256-GCM** — Key, nonce, and tag sizes (FIPS mode)
//! - **Key serialization** — Magic bytes, version, and total serialized sizes
//! - **FIPS state machine** — State codes for the module lifecycle FSM
//! - **HKDF domain separation** — Context strings for key and nonce derivation

/// Tollway protocol version 1
pub const TOLLWAY_VERSION_1: u8 = 0x01;

/// Tollway protocol version 2 (adds sender KEM public key to AAD)
pub const TOLLWAY_VERSION_2: u8 = 0x02;

/// ML-KEM-768 algorithm identifier
pub const ML_KEM_768_ID: &str = "ML-KEM-768";

/// ML-DSA-65 algorithm identifier
pub const ML_DSA_65_ID: &str = "ML-DSA-65";

/// ChaCha20-Poly1305 algorithm identifier
pub const CHACHA20_POLY1305_ID: &str = "ChaCha20-Poly1305";

/// HKDF-SHA3-256 algorithm identifier
pub const HKDF_SHA3_256_ID: &str = "HKDF-SHA3-256";

// ML-KEM-768 sizes
/// Size of an ML-KEM-768 public key in bytes.
pub const ML_KEM_768_PUBLIC_KEY_BYTES: usize = 1184;
/// Size of an ML-KEM-768 secret key in bytes.
pub const ML_KEM_768_SECRET_KEY_BYTES: usize = 2400;
/// Size of an ML-KEM-768 ciphertext (encapsulation output) in bytes.
pub const ML_KEM_768_CIPHERTEXT_BYTES: usize = 1088;
/// Size of an ML-KEM-768 shared secret in bytes.
pub const ML_KEM_768_SHARED_SECRET_BYTES: usize = 32;

// ML-DSA-65 sizes
/// Size of an ML-DSA-65 public key in bytes.
pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1952;
/// Size of an ML-DSA-65 secret key in bytes.
pub const ML_DSA_65_SECRET_KEY_BYTES: usize = 4032;
/// Size of an ML-DSA-65 detached signature in bytes.
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3309;

// ChaCha20-Poly1305 sizes
/// ChaCha20-Poly1305 key size
pub const CHACHA20_POLY1305_KEY_BYTES: usize = 32;
/// ChaCha20-Poly1305 nonce size
pub const CHACHA20_POLY1305_NONCE_BYTES: usize = 12;
/// ChaCha20-Poly1305 tag size
pub const CHACHA20_POLY1305_TAG_BYTES: usize = 16;

// Key serialization constants
/// Magic bytes for serialized public keys: "TLPK"
pub const PUBLIC_KEY_MAGIC: [u8; 4] = *b"TLPK";
/// Magic bytes for serialized keypairs: "TLKP"
pub const KEYPAIR_MAGIC: [u8; 4] = *b"TLKP";
/// Key serialization format version
pub const KEY_SERIALIZATION_VERSION: u8 = 0x01;
/// Total serialized public key size (magic + version + signing_pk + kem_pk)
pub const SERIALIZED_PUBLIC_KEY_BYTES: usize =
    4 + 1 + ML_DSA_65_PUBLIC_KEY_BYTES + ML_KEM_768_PUBLIC_KEY_BYTES;
/// Total serialized keypair size (magic + version + signing_pk + signing_sk + kem_pk + kem_sk)
pub const SERIALIZED_KEYPAIR_BYTES: usize = 4
    + 1
    + ML_DSA_65_PUBLIC_KEY_BYTES
    + ML_DSA_65_SECRET_KEY_BYTES
    + ML_KEM_768_PUBLIC_KEY_BYTES
    + ML_KEM_768_SECRET_KEY_BYTES;

// AES-256-GCM sizes
/// AES-256-GCM algorithm identifier
pub const AES_256_GCM_ID: &str = "AES-256-GCM";
/// AES-256-GCM key size (256-bit key)
pub const AES_256_GCM_KEY_BYTES: usize = 32;
/// AES-256-GCM nonce size (96-bit IV per NIST SP 800-38D)
pub const AES_256_GCM_NONCE_BYTES: usize = 12;
/// AES-256-GCM authentication tag size
pub const AES_256_GCM_TAG_BYTES: usize = 16;

// FIPS module states (used by AtomicU8 FSM in fips::state)
/// FIPS module has not been initialized
pub const FIPS_STATE_UNINITIALIZED: u8 = 0;
/// FIPS module is running self-tests
pub const FIPS_STATE_SELF_TEST: u8 = 1;
/// FIPS module is operational and ready for use
pub const FIPS_STATE_OPERATIONAL: u8 = 2;
/// FIPS module encountered a critical error
pub const FIPS_STATE_ERROR: u8 = 3;

// HKDF context strings (domain separation)
/// HKDF context string for AEAD key derivation
pub const HKDF_CONTEXT_AEAD: &[u8] = b"TOLLWAY-V1-AEAD-KEY";
/// HKDF context string for AEAD nonce derivation
pub const HKDF_CONTEXT_NONCE: &[u8] = b"TOLLWAY-V1-AEAD-NONCE";
