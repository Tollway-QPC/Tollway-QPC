// primitives/signature.rs - ML-DSA-65 operations

// generate_signing_keypair() → (pk, sk)
// sign(message, sk) → signature
// verify(message, signature, pk) → bool
// wraps: pqcrypto-sign or dilithium crate
// ensures: deterministic signatures, malleability resistance

use pqcrypto::sign::mldsa65;
use pqcrypto::traits::sign::{DetachedSignature, PublicKey, SecretKey};

use crate::error::TollwayError;
use crate::types::{SigningKeyPair, SigningPublicKey, SigningSecretKey};

/// Generate a long-term signing keypair
pub(crate) fn generate_keypair() -> Result<SigningKeyPair, TollwayError> {
    let (pk, sk) = mldsa65::keypair();

    Ok(SigningKeyPair {
        public: SigningPublicKey(pk.as_bytes().to_vec()),
        secret: SigningSecretKey(sk.as_bytes().to_vec()),
    })
}

/// Sign a message with a signing secret key
pub(crate) fn sign(message: &[u8], secret_key: &SigningSecretKey) -> Result<Vec<u8>, TollwayError> {
    let sk = mldsa65::SecretKey::from_bytes(&secret_key.0)
        .map_err(|_| TollwayError::Internal("Invalid signing secret key".to_string()))?;

    let sig = mldsa65::detached_sign(message, &sk);

    Ok(sig.as_bytes().to_vec())
}

/// Verify a signature on a message
pub(crate) fn verify(
    message: &[u8],
    signature: &[u8],
    public_key: &SigningPublicKey,
) -> Result<(), TollwayError> {
    let pk = mldsa65::PublicKey::from_bytes(&public_key.0)
        .map_err(|_| TollwayError::SignatureVerificationFailed)?;

    let sig = mldsa65::DetachedSignature::from_bytes(signature)
        .map_err(|_| TollwayError::SignatureVerificationFailed)?;

    mldsa65::verify_detached_signature(&sig, message, &pk)
        .map_err(|_| TollwayError::SignatureVerificationFailed)?;

    Ok(())
}
