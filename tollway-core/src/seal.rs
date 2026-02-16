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
    let sig = signature::sign(&ephemeral_kem.public.0, &sender_keypair.signing.secret)?;

    // Encapsulate to recipient's public KEM key
    let (shared_secret, kem_ciphertext) = kem::encapsulate(&recipient_public_key.kem)?;

    // Derive AEAD key and nonce from shared secret
    let aead_key = kdf::derive_aead_key(&shared_secret)?;
    let aead_nonce = kdf::derive_aead_nonce(&shared_secret)?;

    // Build AAD: binds ciphertext to sender, recipient, and this specific message
    // V2: includes sender KEM key to prevent substitution attacks on reply address
    let aad = aead::build_aad(
        &sender_keypair.signing.public.0,
        &sender_keypair.kem.public.0,
        &recipient_public_key.kem.0,
        &ephemeral_kem.public.0,
    );

    // Encrypt plaintext with AEAD (now with associated data)
    let aead_ciphertext = aead::encrypt(&aead_key, &aead_nonce, plaintext, &aad)?;

    // Zero ephemeral secret key (forward secrecy)
    drop(ephemeral_kem.secret); // ZeroizeOnDrop takes care of this

    // Build wire format
    let ciphertext = format::build_ciphertext(
        &sender_keypair.signing.public,
        &sender_keypair.kem.public,
        &ephemeral_kem.public,
        &sig,
        &kem_ciphertext,
        &aead_ciphertext,
    )?;

    Ok(ciphertext)
}
