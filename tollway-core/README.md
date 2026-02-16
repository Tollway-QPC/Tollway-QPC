# tollway-core

[![Crates.io](https://img.shields.io/crates/v/tollway-core.svg)](https://crates.io/crates/tollway-core)
[![Documentation](https://docs.rs/tollway-core/badge.svg)](https://docs.rs/tollway-core)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](../LICENSE-MIT)
[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

Core cryptographic primitives for post-quantum authenticated encryption.

## Security

> [!WARNING]
> This library has **not undergone any third-party security audit**. Usage is at **own risk**. Audit scheduled for Q2 2026.

See [SECURITY.md](../SECURITY.md) for vulnerability reporting.

## Features

- **ML-KEM-768** (FIPS 203): Post-quantum key encapsulation
- **ML-DSA-65** (FIPS 204): Post-quantum digital signatures
- **ChaCha20-Poly1305**: Authenticated symmetric encryption
- **HKDF-SHA3-256**: Key derivation with domain separation
- Forward secrecy via per-message ephemeral keys
- Sender authentication with cryptographic binding
- Automatic zeroization of secret keys (`ZeroizeOnDrop`)
- No unsafe code (`#![forbid(unsafe_code)]`)

## Installation

```toml
[dependencies]
tollway-core = "1.1"
```

## Usage

### Basic Encryption

```rust
use tollway_core::{KeyPair, seal, open};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();

    // Encrypt with sender authentication
    let ciphertext = seal(b"Hello Bob!", &alice, &bob.public_key())?;

    // Decrypt and verify sender
    let (plaintext, sender) = open(&ciphertext, &bob)?;
    
    assert_eq!(plaintext, b"Hello Bob!");
    assert_eq!(sender, alice.public_key());
    
    Ok(())
}
```

### Error Handling

```rust
use tollway_core::{open, TollwayError};

match open(&ciphertext, &recipient) {
    Ok((plaintext, sender)) => { /* success */ }
    Err(TollwayError::SignatureVerificationFailed) => { /* bad sender */ }
    Err(TollwayError::DecryptionFailed) => { /* tampered or wrong key */ }
    Err(TollwayError::InvalidCiphertext) => { /* malformed */ }
    Err(e) => { /* other error */ }
}
```

## API

### `KeyPair::generate() -> KeyPair`

Generates a new ML-KEM-768 + ML-DSA-65 keypair.

### `seal(plaintext, sender, recipient_pk) -> Result<Vec<u8>, TollwayError>`

Encrypts `plaintext` from `sender` to `recipient_pk` with authentication and forward secrecy.

### `open(ciphertext, recipient) -> Result<(Vec<u8>, PublicKey), TollwayError>`

Decrypts `ciphertext` and returns plaintext + verified sender public key.

## Errors

```rust
pub enum TollwayError {
    InvalidCiphertext,           // Malformed wire format
    SignatureVerificationFailed, // Sender auth failed
    DecryptionFailed,            // AEAD auth failed
    KeyGenerationFailed,         // RNG failure
    KEMEncapsulationFailed,      // KEM error
    KEMDecapsulationFailed,      // KEM error
    Internal(String),            // Bug (should never happen)
}
```

## Wire Format

```text
Version (1B) || Sender Signing PK (1952B) || Sender KEM PK (1184B) 
|| Ephemeral KEM PK (1184B) || Signature (3309B) || KEM CT (1088B) 
|| AEAD Length (4B) || AEAD Ciphertext (variable + 16B tag)
```

Fixed overhead: ~8,722 bytes before plaintext.

## Sizes

| Component          | Bytes |
| ------------------ | ----- |
| Signing Public Key | 1,952 |
| KEM Public Key     | 1,184 |
| Signature          | 3,309 |
| KEM Ciphertext     | 1,088 |
| AEAD Tag           | 16    |

## Tests

```bash
cargo test
```

Tests include:

- Roundtrip seal/open (`tests/seal_open.rs`)
- Property-based testing (`tests/properties.rs`)
- Error path coverage (`tests/error_coverage.rs`)
- Timing analysis (`tests/timing_rigorous.rs`)
- NIST vectors (`tests/nist_vectors.rs`)

Fuzz targets in [`fuzz/`](fuzz/).

## Benchmarks

```bash
cargo bench --bench comprehensive
```

## Documentation

- [docs.rs/tollway-core](https://docs.rs/tollway-core)
- [PROTOCOL.md](../PROTOCOL.md) - Security specification

## License

Dual-licensed under [MIT](../LICENSE-MIT) or [Apache-2.0](../LICENSE-APACHE).
