# Tollway-PQC

[![Crates.io](https://img.shields.io/crates/v/tollway-core.svg)](https://crates.io/crates/tollway-core)
[![Documentation](https://docs.rs/tollway-core/badge.svg)](https://docs.rs/tollway-core)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

A post-quantum cryptography library for authenticated encryption in Rust.

## Security

> [!WARNING]
> This library has **not undergone any third-party security audit**. Usage is at **own risk**.
See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Features

- **ML-KEM-768** (FIPS 203): Post-quantum key encapsulation (Security Level 3)
- **ML-DSA-65** (FIPS 204): Post-quantum digital signatures (Security Level 3)
- **ChaCha20-Poly1305**: Authenticated symmetric encryption
- **HKDF-SHA3-256**: Key derivation with domain separation
- Forward secrecy via per-message ephemeral keys
- Sender authentication with cryptographic binding
- Automatic zeroization of secret keys
- No unsafe code (`#![forbid(unsafe_code)]`)

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
tollway-core = "1.1"
```

## Usage

### Authenticated Encryption

```rust
use tollway_core::{KeyPair, seal, open};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate post-quantum keypairs
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();

    // Alice encrypts a message to Bob (authenticated)
    let ciphertext = seal(b"Hello Bob!", &alice, &bob.public_key())?;

    // Bob decrypts and verifies it came from Alice
    let (plaintext, sender) = open(&ciphertext, &bob)?;
    
    assert_eq!(plaintext, b"Hello Bob!");
    assert_eq!(sender, alice.public_key());  // Verified sender identity
    
    Ok(())
}
```

### Self-Encryption (Archives/Storage)

```rust
use tollway_core::{KeyPair, seal, open};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = KeyPair::generate();
    
    // Encrypt data to yourself
    let ciphertext = seal(b"Secret data", &key, &key.public_key())?;
    
    // Later: decrypt
    let (plaintext, _) = open(&ciphertext, &key)?;
    assert_eq!(plaintext, b"Secret data");
    
    Ok(())
}
```

## Crate Structure

| Crate                             | Description                                       |
| --------------------------------- | ------------------------------------------------- |
| [`tollway-core`](tollway-core/)   | Core primitives: `seal()`, `open()`, `KeyPair`    |
| [`tollway-keys`](tollway-keys/)   | Key management, rotation, backup (in development) |

## Sizes

| Component            | Bytes                  |
| -------------------- | ---------------------- |
| Public Key (signing) | 1,952                  |
| Public Key (KEM)     | 1,184                  |
| Signature            | 3,309                  |
| KEM Ciphertext       | 1,088                  |
| Total Overhead       | ~8,722 + 16 (AEAD tag) |

## Documentation

- API docs: [docs.rs/tollway-core](https://docs.rs/tollway-core)
- Protocol specification: [PROTOCOL.md](PROTOCOL.md)

## Tests and Fuzzing

```bash
cargo test
```

## Benchmarks

```bash
cargo bench --bench comprehensive
```

All benchmarks are in [`tollway-core/benches/`](tollway-core/benches/).

## Minimum Supported Rust Version

Rust 1.70 or later. MSRV may change in minor releases.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.MD) for guidelines.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).

## References

- [FIPS 203: ML-KEM Standard](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: ML-DSA Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [pqcrypto](https://crates.io/crates/pqcrypto) - Underlying PQC implementations
