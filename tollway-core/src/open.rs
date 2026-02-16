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
    // Parse wire format (structural check — no secret information, early-exit is safe)
    let parsed = format::parse_ciphertext(ciphertext)?;

    // Verify signature on ephemeral public key
    // Capture result as bool — do NOT early-exit, to prevent timing oracle
    let sig_ok = signature::verify(
        &parsed.ephemeral_kem_public.0,
        &parsed.signature,
        &parsed.sender_signing_public,
    )
    .is_ok();

    // Decapsulate KEM ciphertext (unified error hides which step failed)
    let shared_secret = kem::decapsulate(&parsed.kem_ciphertext, &recipient_keypair.kem.secret)
        .map_err(|_| TollwayError::DecryptionFailed)?;

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

    // Decrypt and verify AEAD (capture result — do NOT early-exit)
    let aead_result = aead::decrypt(&aead_key, &aead_nonce, &parsed.aead_ciphertext, &aad);

    // Unified result: ALL crypto steps must succeed, otherwise return DecryptionFailed.
    // This eliminates the timing oracle — an attacker cannot distinguish signature
    // failure from AEAD failure by measuring response time.
    let sender_pk = PublicKey {
        signing: parsed.sender_signing_public,
        kem: parsed.sender_kem_public,
    };

    match (sig_ok, aead_result) {
        (true, Ok(plaintext)) => Ok((plaintext, sender_pk)),
        _ => Err(TollwayError::DecryptionFailed),
    }
}
