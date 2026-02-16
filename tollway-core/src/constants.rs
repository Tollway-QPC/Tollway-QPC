//! Algorithm constants and identifiers

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
/// ML-KEM-768 sizes (from pqcrypto)
pub const ML_KEM_768_PUBLIC_KEY_BYTES: usize = 1184;
/// ML-KEM-768 sizes (from pqcrypto)
pub const ML_KEM_768_SECRET_KEY_BYTES: usize = 2400;
/// ML-KEM-768 sizes (from pqcrypto)
pub const ML_KEM_768_CIPHERTEXT_BYTES: usize = 1088;
/// ML-KEM-768 sizes (from pqcrypto)
pub const ML_KEM_768_SHARED_SECRET_BYTES: usize = 32;

// ML-DSA-65 sizes (from pqcrypto)
/// ML-DSA-65 sizes (from pqcrypto)
pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1952;
/// ML-DSA-65 sizes (from pqcrypto)
pub const ML_DSA_65_SECRET_KEY_BYTES: usize = 4032;
/// ML-DSA-65 sizes (from pqcrypto)
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

// HKDF context strings (domain separation)
/// HKDF context string for AEAD key derivation
pub const HKDF_CONTEXT_AEAD: &[u8] = b"TOLLWAY-V1-AEAD-KEY";
/// HKDF context string for AEAD nonce derivation
pub const HKDF_CONTEXT_NONCE: &[u8] = b"TOLLWAY-V1-AEAD-NONCE";
