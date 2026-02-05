// wire/format.rs - Ciphertext wire format

// Ciphertext serialization: version || sender_pk || signature || kem_ct || aead_ct
// versioning: allows algorithm upgrades without breaking compatibility
// includes: length prefixes, type tags for forward compatibility
