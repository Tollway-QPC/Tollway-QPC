// primitives/kdf.rs - Key derivation

// derive_key(shared_secret, context, output_length) → derived_key
// uses: HKDF-SHA3-256
// context strings prevent cross-protocol attacks
// ensures: domain separation between different key usages
