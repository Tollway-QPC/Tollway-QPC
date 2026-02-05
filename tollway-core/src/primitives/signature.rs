// primitives/signature.rs - ML-DSA-65 operations

// generate_signing_keypair() → (pk, sk)
// sign(message, sk) → signature
// verify(message, signature, pk) → bool
// wraps: pqcrypto-sign or dilithium crate
// ensures: deterministic signatures, malleability resistance
