// storage/encryption.rs - Storage encryption using tollway-core

// encrypt_key_data(keypair, master_key) → encrypted_blob
// decrypt_key_data(encrypted_blob, master_key) → keypair
// uses: tollway-core seal operation with derived storage keys
