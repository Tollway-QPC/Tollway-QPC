// primitives/kem.rs - ML-KEM-768 operations

// generate_kem_keypair() → (pk, sk)
// encapsulate(pk) → (shared_secret, ciphertext)
// decapsulate(ciphertext, sk) → shared_secret
// wraps: pqcrypto-kem or dilithium crate
// ensures: constant-time operations, secure key generation
