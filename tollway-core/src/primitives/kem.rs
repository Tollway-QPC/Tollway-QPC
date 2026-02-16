use pqcrypto::kem::mlkem768;
use pqcrypto::traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};

use crate::error::TollwayError;
use crate::secure::memory::SecretVec;
use crate::types::{KEMKeyPair, KEMPublicKey, KEMSecretKey};

/// An ephemeral KEM keypair for forward secrecy
pub(crate) struct EphemeralKEMKeyPair {
    pub(crate) public: KEMPublicKey,
    pub(crate) secret: KEMSecretKey,
}

/// Generate an ephemeral KEM keypair for use in a single message
pub(crate) fn generate_ephemeral_keypair() -> Result<EphemeralKEMKeyPair, TollwayError> {
    let (pk, sk) = mlkem768::keypair();

    Ok(EphemeralKEMKeyPair {
        public: KEMPublicKey(pk.as_bytes().to_vec()),
        secret: KEMSecretKey(sk.as_bytes().to_vec()),
    })
}

/// Generate a long-term KEM keypair
#[allow(dead_code)]
pub(crate) fn generate_keypair() -> Result<KEMKeyPair, TollwayError> {
    let (pk, sk) = mlkem768::keypair();

    Ok(KEMKeyPair {
        public: KEMPublicKey(pk.as_bytes().to_vec()),
        secret: KEMSecretKey(sk.as_bytes().to_vec()),
    })
}

/// Encapsulate to a recipient's public key, producing a shared secret and ciphertext
pub(crate) fn encapsulate(
    recipient_pk: &KEMPublicKey,
) -> Result<(SecretVec, Vec<u8>), TollwayError> {
    let pk = mlkem768::PublicKey::from_bytes(&recipient_pk.0)
        .map_err(|_| TollwayError::KEMEncapsulationFailed)?;

    let (ss, ct) = mlkem768::encapsulate(&pk);

    Ok((
        SecretVec::new(ss.as_bytes().to_vec()),
        ct.as_bytes().to_vec(),
    ))
}

/// Decapsulate a KEM ciphertext using the secret key to recover the shared secret
pub(crate) fn decapsulate(
    ciphertext: &[u8],
    secret_key: &KEMSecretKey,
) -> Result<SecretVec, TollwayError> {
    let sk = mlkem768::SecretKey::from_bytes(&secret_key.0)
        .map_err(|_| TollwayError::KEMDecapsulationFailed)?;

    let ct = mlkem768::Ciphertext::from_bytes(ciphertext)
        .map_err(|_| TollwayError::InvalidCiphertext)?;

    let ss = mlkem768::decapsulate(&ct, &sk);

    Ok(SecretVec::new(ss.as_bytes().to_vec()))
}
