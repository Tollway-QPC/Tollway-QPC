// types.rs - Core cryptographic types

// KeyPair { signing: SigningKeyPair, kem: KEMKeyPair }
// PublicKey { signing: SigningPublicKey, kem: KEMPublicKey }
// SecretKey (internal, never exposed directly)
// Ciphertext { version, sender_signing_pk, signed_ephemeral_pk, kem_ciphertext, aead_ciphertext }
// implements: Clone (public keys only), Zeroize (secret keys), Serialize/Deserialize
