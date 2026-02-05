// wire/serialize.rs - Key serialization

// KeyPair::to_bytes() / from_bytes()
// PublicKey::to_bytes() / from_bytes()
// format: type_tag || signing_key || kem_key
// ensures: constant-time deserialization (no timing attacks on key parsing)
