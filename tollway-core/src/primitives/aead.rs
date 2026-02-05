// primitives/aead.rs - ChaCha20-Poly1305 operations

// encrypt(key, nonce, plaintext, associated_data) → ciphertext
// decrypt(key, nonce, ciphertext, associated_data) → plaintext
// wraps: chacha20poly1305 crate
// ensures: unique nonces (random generation), auth tag verification
