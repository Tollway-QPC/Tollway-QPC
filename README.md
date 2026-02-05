# Tollway-PQC

**The post-quantum cryptography library for all.**

Tollway-PQC provides quantum-resistant encryption with forward secrecy and authenticated communication. Built for enterprises, governments, and developers who need cryptography that works correctly by default and survives the quantum transition.

## Features

- **Quantum-Resistant**: ML-KEM-768, ML-DSA-65, ChaCha20-Poly1305 (NIST-standardized algorithms)
- **Forward Secrecy**: Ephemeral keys automatically destroyed after each encryption
- **Authenticated**: Cryptographic proof of sender identity on every message
- **Misuse-Resistant**: Secure by default, unsafe operations require explicit opt-in
- **Production-Ready**: Constant-time operations, side-channel resistance, memory safety
- **Key Management**: Complete key lifecycle with rotation, expiration, backup, and recovery

## Quick Start

### Basic Encryption (tollway-core)

```rust
use tollway_core::{KeyPair, seal, open};

// Generate keypairs
let alice = KeyPair::generate();
let bob = KeyPair::generate();

// Alice encrypts to Bob
let ciphertext = seal(b"Hello Bob", &alice, &bob.public_key())?;

// Bob decrypts and verifies sender
let (plaintext, sender) = open(&ciphertext, &bob)?;
assert_eq!(plaintext, b"Hello Bob");
assert_eq!(sender, alice.public_key());
```

### Identity-Based Encryption (tollway-keys)

```rust
use tollway_keys::{KeyManager, storage::FileStorage};

// Initialize key manager
let storage = FileStorage::new("~/.tollway")?;
let manager = KeyManager::new(storage);

// Create identities
let alice = manager.create_identity("alice")?;
let bob = manager.create_identity("bob")?;

// Alice encrypts to Bob by name
let ciphertext = alice.seal_to("bob", b"Hello Bob")?;

// Bob decrypts and sees sender name
let (plaintext, sender_name) = bob.open_from(&ciphertext)?;
assert_eq!(sender_name, "alice");
```

## Design Philosophy

**Secure by default, auditable by design, quantum-ready without breaking production.**

- No algorithm configuration (one correct choice, hardcoded)
- No optional authentication (always authenticated)
- No manual key lifecycle (automatic rotation and expiration)
- No silent failures (comprehensive error context)
- No timing leaks (constant-time operations throughout)

## Architecture

- **tollway-core**: Cryptographic primitives (seal, open, key generation)
- **tollway-keys**: Key lifecycle management (identities, rotation, backup)
- **tollway-hybrid**: Classical + PQC hybrid modes (coming soon)
- **tollway-migrate**: Migration tooling from RSA/ECDSA (coming soon)

## Security

- **Algorithms**: ML-KEM-768, ML-DSA-65, ChaCha20-Poly1305, HKDF-SHA3-256
- **Implementation**: Rust (memory safety), constant-time operations, secure memory zeroing
- **Auditing**: Structured event logs for all cryptographic operations
- **Testing**: NIST test vectors, side-channel resistance tests, fuzzing

## Performance

Designed for production workloads:

- Hybrid encryption (fast bulk encryption with AEAD)
- Zero-copy operations where possible
- Minimal allocations in hot paths
- Hardware acceleration support (future)

## License

Apache 2.0 / MIT dual-licensed. See [LICENSE-APACHE](./LICENSE-APACHE) and [LICENSE-MIT](./LICENSE-MIT).

## Documentation

- [Core API Documentation](./tollway-core/README.md)
- [Key Management Documentation](./tollway-keys/README.md)
- [Design Decisions](./notes/design-decisions.md)
- [Security Policy](./SECURITY.md)

## Contributing

We welcome contributions. Please read [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.
