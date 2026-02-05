// identity.rs - Named entity with keypair and metadata

// Identity { id, name, keypair, metadata, policy }
// seal_to(recipient_name, plaintext) → Ciphertext
// open_from(ciphertext) → (plaintext, sender_name)
// rotate_keys() → new Identity (preserves id, updates keypair)
// is_expired() → bool
// abstracts: key lookup by name instead of raw public keys
