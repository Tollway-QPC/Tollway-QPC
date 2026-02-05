// storage/file.rs - Encrypted file-based storage

// stores keys in: ~/.tollway/identities/
// each identity: <id>.key (encrypted with master key)
// master key: derived from system keyring or user passphrase
// ensures: file permissions (0600), atomic writes
