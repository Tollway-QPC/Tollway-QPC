// rotation.rs - Key rotation logic

// check_rotation_needed(identity) → bool
// rotate_identity(identity) → new_identity
// triggers: expiration time, usage count threshold, manual request
// ensures: old keys remain available for decryption (grace period)
