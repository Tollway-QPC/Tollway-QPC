//! Key serialization and deserialization.
//!
//! Provides wire-format encoding for [`PublicKey`] and [`KeyPair`] types,
//! enabling key persistence, sharing, and backup.
//!
//! # Wire Formats
//!
//! ## PublicKey (3141 bytes)
//!
//! ```text
//! MAGIC ("TLPK")  4 bytes
//! VERSION          1 byte   (0x01)
//! signing_pk       1952 bytes (ML-DSA-65)
//! kem_pk           1184 bytes (ML-KEM-768)
//! ```
//!
//! ## KeyPair (9573 bytes)
//!
//! ```text
//! MAGIC ("TLKP")  4 bytes
//! VERSION          1 byte   (0x01)
//! signing_pk       1952 bytes (ML-DSA-65)
//! signing_sk       4032 bytes (ML-DSA-65)
//! kem_pk           1184 bytes (ML-KEM-768)
//! kem_sk           2400 bytes (ML-KEM-768)
//! ```
//!
//! # Security
//!
//! - [`KeyPair`] serialization exports secret key material in the clear.
//!   Callers are responsible for encrypting the output before storage.
//! - Methods that handle secret material are prefixed with `dangerous_` to
//!   signal that the caller must protect the returned bytes.

use crate::constants::{
    KEYPAIR_MAGIC, KEY_SERIALIZATION_VERSION, ML_DSA_65_PUBLIC_KEY_BYTES,
    ML_DSA_65_SECRET_KEY_BYTES, ML_KEM_768_PUBLIC_KEY_BYTES, ML_KEM_768_SECRET_KEY_BYTES,
    PUBLIC_KEY_MAGIC, SERIALIZED_KEYPAIR_BYTES, SERIALIZED_PUBLIC_KEY_BYTES,
};
use crate::error::TollwayError;
use crate::types::{
    KEMKeyPair, KEMPublicKey, KEMSecretKey, KeyPair, PublicKey, SigningKeyPair, SigningPublicKey,
    SigningSecretKey,
};

/// Serialize a [`PublicKey`] to its wire format.
///
/// The output is a self-describing byte sequence with a magic header and
/// version byte, making it safe to store or transmit without additional framing.
pub(crate) fn serialize_public_key(pk: &PublicKey) -> Vec<u8> {
    let mut buf = Vec::with_capacity(SERIALIZED_PUBLIC_KEY_BYTES);

    buf.extend_from_slice(&PUBLIC_KEY_MAGIC);
    buf.push(KEY_SERIALIZATION_VERSION);
    buf.extend_from_slice(&pk.signing.0);
    buf.extend_from_slice(&pk.kem.0);

    debug_assert_eq!(buf.len(), SERIALIZED_PUBLIC_KEY_BYTES);
    buf
}

/// Deserialize a [`PublicKey`] from its wire format.
///
/// Validates the magic header, version byte, and exact data length before
/// constructing the key.
pub(crate) fn deserialize_public_key(data: &[u8]) -> Result<PublicKey, TollwayError> {
    if data.len() != SERIALIZED_PUBLIC_KEY_BYTES {
        return Err(TollwayError::InvalidKeyData(format!(
            "expected {} bytes, got {}",
            SERIALIZED_PUBLIC_KEY_BYTES,
            data.len()
        )));
    }

    let mut offset = 0;

    // Magic
    let magic = &data[offset..offset + 4];
    if magic != PUBLIC_KEY_MAGIC {
        return Err(TollwayError::InvalidKeyData(
            "invalid public key magic bytes".to_string(),
        ));
    }
    offset += 4;

    // Version
    let version = data[offset];
    if version != KEY_SERIALIZATION_VERSION {
        return Err(TollwayError::InvalidKeyData(format!(
            "unsupported public key version: 0x{:02x}",
            version
        )));
    }
    offset += 1;

    // Signing public key
    let signing_pk = SigningPublicKey(data[offset..offset + ML_DSA_65_PUBLIC_KEY_BYTES].to_vec());
    offset += ML_DSA_65_PUBLIC_KEY_BYTES;

    // KEM public key
    let kem_pk = KEMPublicKey(data[offset..offset + ML_KEM_768_PUBLIC_KEY_BYTES].to_vec());

    Ok(PublicKey {
        signing: signing_pk,
        kem: kem_pk,
    })
}

/// Serialize a [`KeyPair`] to its wire format.
///
/// # Warning
///
/// The output contains unencrypted secret key material. Callers **must**
/// encrypt the returned bytes before persisting to disk or transmitting
/// over a network.
pub(crate) fn serialize_keypair(kp: &KeyPair) -> Vec<u8> {
    let mut buf = Vec::with_capacity(SERIALIZED_KEYPAIR_BYTES);

    buf.extend_from_slice(&KEYPAIR_MAGIC);
    buf.push(KEY_SERIALIZATION_VERSION);
    buf.extend_from_slice(&kp.signing.public.0);
    buf.extend_from_slice(&kp.signing.secret.0);
    buf.extend_from_slice(&kp.kem.public.0);
    buf.extend_from_slice(&kp.kem.secret.0);

    debug_assert_eq!(buf.len(), SERIALIZED_KEYPAIR_BYTES);
    buf
}

/// Deserialize a [`KeyPair`] from its wire format.
///
/// Validates the magic header, version byte, and exact data length before
/// constructing the keypair.
///
/// # Warning
///
/// The input is expected to contain unencrypted secret key material.
/// Callers should only pass data that was decrypted from a trusted source.
pub(crate) fn deserialize_keypair(data: &[u8]) -> Result<KeyPair, TollwayError> {
    if data.len() != SERIALIZED_KEYPAIR_BYTES {
        return Err(TollwayError::InvalidKeyData(format!(
            "expected {} bytes, got {}",
            SERIALIZED_KEYPAIR_BYTES,
            data.len()
        )));
    }

    let mut offset = 0;

    // Magic
    let magic = &data[offset..offset + 4];
    if magic != KEYPAIR_MAGIC {
        return Err(TollwayError::InvalidKeyData(
            "invalid keypair magic bytes".to_string(),
        ));
    }
    offset += 4;

    // Version
    let version = data[offset];
    if version != KEY_SERIALIZATION_VERSION {
        return Err(TollwayError::InvalidKeyData(format!(
            "unsupported keypair version: 0x{:02x}",
            version
        )));
    }
    offset += 1;

    // Signing public key
    let signing_pk = SigningPublicKey(data[offset..offset + ML_DSA_65_PUBLIC_KEY_BYTES].to_vec());
    offset += ML_DSA_65_PUBLIC_KEY_BYTES;

    // Signing secret key
    let signing_sk = SigningSecretKey(data[offset..offset + ML_DSA_65_SECRET_KEY_BYTES].to_vec());
    offset += ML_DSA_65_SECRET_KEY_BYTES;

    // KEM public key
    let kem_pk = KEMPublicKey(data[offset..offset + ML_KEM_768_PUBLIC_KEY_BYTES].to_vec());
    offset += ML_KEM_768_PUBLIC_KEY_BYTES;

    // KEM secret key
    let kem_sk = KEMSecretKey(data[offset..offset + ML_KEM_768_SECRET_KEY_BYTES].to_vec());

    Ok(KeyPair {
        signing: SigningKeyPair {
            public: signing_pk,
            secret: signing_sk,
        },
        kem: KEMKeyPair {
            public: kem_pk,
            secret: kem_sk,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{SERIALIZED_KEYPAIR_BYTES, SERIALIZED_PUBLIC_KEY_BYTES};

    #[test]
    fn test_public_key_roundtrip() {
        let kp = KeyPair::generate();
        let pk = kp.public_key();

        let bytes = serialize_public_key(&pk);
        assert_eq!(bytes.len(), SERIALIZED_PUBLIC_KEY_BYTES);

        let recovered = deserialize_public_key(&bytes).unwrap();
        assert_eq!(recovered.signing_bytes(), pk.signing_bytes());
        assert_eq!(recovered.kem_bytes(), pk.kem_bytes());
    }

    #[test]
    fn test_keypair_roundtrip() {
        let kp = KeyPair::generate();

        let bytes = serialize_keypair(&kp);
        assert_eq!(bytes.len(), SERIALIZED_KEYPAIR_BYTES);

        let recovered = deserialize_keypair(&bytes).unwrap();
        assert_eq!(
            recovered.public_key().signing_bytes(),
            kp.public_key().signing_bytes()
        );
        assert_eq!(
            recovered.public_key().kem_bytes(),
            kp.public_key().kem_bytes()
        );
    }

    #[test]
    fn test_public_key_magic_validation() {
        let kp = KeyPair::generate();
        let mut bytes = serialize_public_key(&kp.public_key());
        bytes[0] = 0xFF; // corrupt magic

        let result = deserialize_public_key(&bytes);
        assert!(matches!(result, Err(TollwayError::InvalidKeyData(_))));
    }

    #[test]
    fn test_keypair_magic_validation() {
        let kp = KeyPair::generate();
        let mut bytes = serialize_keypair(&kp);
        bytes[0] = 0xFF; // corrupt magic

        let result = deserialize_keypair(&bytes);
        assert!(matches!(result, Err(TollwayError::InvalidKeyData(_))));
    }

    #[test]
    fn test_public_key_version_validation() {
        let kp = KeyPair::generate();
        let mut bytes = serialize_public_key(&kp.public_key());
        bytes[4] = 0xFF; // corrupt version

        let result = deserialize_public_key(&bytes);
        assert!(matches!(result, Err(TollwayError::InvalidKeyData(_))));
    }

    #[test]
    fn test_keypair_version_validation() {
        let kp = KeyPair::generate();
        let mut bytes = serialize_keypair(&kp);
        bytes[4] = 0xFF; // corrupt version

        let result = deserialize_keypair(&bytes);
        assert!(matches!(result, Err(TollwayError::InvalidKeyData(_))));
    }

    #[test]
    fn test_public_key_wrong_length_rejected() {
        let result = deserialize_public_key(&[0u8; 10]);
        assert!(matches!(result, Err(TollwayError::InvalidKeyData(_))));

        let result = deserialize_public_key(&[]);
        assert!(matches!(result, Err(TollwayError::InvalidKeyData(_))));

        // One byte too long
        let kp = KeyPair::generate();
        let mut bytes = serialize_public_key(&kp.public_key());
        bytes.push(0x00);
        let result = deserialize_public_key(&bytes);
        assert!(matches!(result, Err(TollwayError::InvalidKeyData(_))));
    }

    #[test]
    fn test_keypair_wrong_length_rejected() {
        let result = deserialize_keypair(&[0u8; 10]);
        assert!(matches!(result, Err(TollwayError::InvalidKeyData(_))));

        let result = deserialize_keypair(&[]);
        assert!(matches!(result, Err(TollwayError::InvalidKeyData(_))));
    }

    #[test]
    fn test_public_key_not_confused_with_keypair() {
        let kp = KeyPair::generate();

        let pk_bytes = serialize_public_key(&kp.public_key());
        let kp_bytes = serialize_keypair(&kp);

        // Public key bytes should not parse as keypair (wrong magic + wrong length)
        let result = deserialize_keypair(&pk_bytes);
        assert!(matches!(result, Err(TollwayError::InvalidKeyData(_))));

        // Keypair bytes should not parse as public key (wrong magic + wrong length)
        let result = deserialize_public_key(&kp_bytes);
        assert!(matches!(result, Err(TollwayError::InvalidKeyData(_))));
    }

    #[test]
    fn test_serialized_keypair_can_seal_open() {
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        let plaintext = b"roundtrip through serialization";

        // Serialize and deserialize the recipient keypair
        let bytes = serialize_keypair(&recipient);
        let recovered_recipient = deserialize_keypair(&bytes).unwrap();

        // Seal to original public key, open with deserialized keypair
        let ct = crate::seal(plaintext, &sender, &recipient.public_key()).unwrap();
        let (pt, _) = crate::open(&ct, &recovered_recipient).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_serialized_public_key_can_receive() {
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        let plaintext = b"roundtrip through serialized pubkey";

        // Serialize and deserialize the recipient's public key
        let pk_bytes = serialize_public_key(&recipient.public_key());
        let recovered_pk = deserialize_public_key(&pk_bytes).unwrap();

        // Seal to the deserialized public key, open with original keypair
        let ct = crate::seal(plaintext, &sender, &recovered_pk).unwrap();
        let (pt, _) = crate::open(&ct, &recipient).unwrap();
        assert_eq!(pt, plaintext);
    }
}
