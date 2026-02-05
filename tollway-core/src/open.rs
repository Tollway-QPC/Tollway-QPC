// open.rs - Orchestrates decryption

// open(ciphertext, recipient_keypair) → (plaintext, verified_sender_pk)
// flow: parse_ciphertext → verify_signature → decapsulate → derive_aead_key → decrypt_and_verify → return_with_sender_identity
