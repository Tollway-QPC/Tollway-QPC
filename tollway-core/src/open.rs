// open.rs - Orchestrates decryption

// open(ciphertext, recipient_keypair) → (plaintext, verified_sender_pk)
// flow: parse_ciphertext → verify_signature → decapsulate → derive_aead_key → decrypt_and_verify → return_with_sender_identity

use crate::{
    constants::TOLLWAY_VERSION_2,
    error::TollwayError,
    primitives::{aead, kdf, kem, signature},
    types::{KeyPair, PublicKey},
    wire::format,
};

pub fn open(
    ciphertext: &[u8],
    recipient_keypair: &KeyPair,
) -> Result<(Vec<u8>, PublicKey), TollwayError> {
    // Parse wire format
    let parsed = format::parse_ciphertext(ciphertext)?;

    // Verify signature on ephemeral public key
    signature::verify(
        &parsed.ephemeral_kem_public.0,
        &parsed.signature,
        &parsed.sender_signing_public,
    )?;

    // Decapsulate KEM ciphertext
    let shared_secret = kem::decapsulate(&parsed.kem_ciphertext, &recipient_keypair.kem.secret)?;

    // Derive AEAD key and nonce
    let aead_key = kdf::derive_aead_key(&shared_secret)?;
    let aead_nonce = kdf::derive_aead_nonce(&shared_secret)?;

    // Rebuild AAD: must match exactly what was used during seal()
    // V2: sender KEM key is included in AAD (prevents substitution attacks)
    // V1: sender KEM key is omitted from AAD (legacy backward compatibility)
    let sender_kem_in_aad: &[u8] = if parsed.version == TOLLWAY_VERSION_2 {
        &parsed.sender_kem_public.0
    } else {
        &[]
    };
    let aad = aead::build_aad(
        &parsed.sender_signing_public.0,
        sender_kem_in_aad,
        &recipient_keypair.kem.public.0,
        &parsed.ephemeral_kem_public.0,
    );

    // Decrypt and verify AEAD (with associated data)
    let plaintext = aead::decrypt(&aead_key, &aead_nonce, &parsed.aead_ciphertext, &aad)?;

    // Return plaintext and verified sender public key
    let sender_pk = PublicKey {
        signing: parsed.sender_signing_public,
        kem: parsed.sender_kem_public,
    };

    Ok((plaintext, sender_pk))
}
