// seal.rs - Orchestrates encryption 🦭

// seal(plaintext, sender_keypair, recipient_public_key) → Ciphertext
// flow: generate_ephemeral_kem_keypair → sign_ephemeral_pk → encapsulate → derive_aead_key → encrypt → zero_ephemeral_secret → build_ciphertext

use crate::{
    error::TollwayError,
    primitives::{aead, kdf, kem, signature},
    types::{KeyPair, PublicKey},
    wire::format,
};

pub fn seal(
    plaintext: &[u8],
    sender_keypair: &KeyPair,
    recipient_public_key: &PublicKey,
) -> Result<Vec<u8>, TollwayError> {
    // Generate ephemeral KEM keypair
    let ephemeral_kem = kem::generate_ephemeral_keypair()?;

    // Sign ephemeral public key with sender's long-term signing key
    let signature = signature::sign(&ephemeral_kem.public.0, &sender_keypair.signing.secret)?;

    // Encapsulate to recipient's public KEM key
    let (shared_secret, kem_ciphertext) = kem::encapsulate(&recipient_public_key.kem)?;

    // Derive AEAD key and nonce from shared secret
    let aead_key = kdf::derive_aead_key(&shared_secret)?;
    let aead_nonce = kdf::derive_aead_nonce(&shared_secret)?;

    // Encrypt plaintext with AEAD
    let aead_ciphertext = aead::encrypt(&aead_key, &aead_nonce, plaintext)?;

    // Zero ephemeral secret key (forward secrecy)
    drop(ephemeral_kem.secret); // ZeroizeOnDrop takes care of this

    // Build wire format
    let ciphertext = format::build_ciphertext(
        &sender_keypair.signing.public,
        &ephemeral_kem.public,
        &signature,
        &kem_ciphertext,
        &aead_ciphertext,
    )?;

    Ok(ciphertext)
}
