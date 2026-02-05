// seal.rs - Orchestrates encryption

// seal(plaintext, sender_keypair, recipient_public_key) → Ciphertext
// flow: generate_ephemeral_kem_keypair → sign_ephemeral_pk → encapsulate → derive_aead_key → encrypt → zero_ephemeral_secret → build_ciphertext
