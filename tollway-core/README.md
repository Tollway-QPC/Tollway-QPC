# tollway-core

**Quantum-resistant cryptographic primitives with forward secrecy and authentication.**

`tollway-core` provides the foundational cryptographic operations for post-quantum encryption. It's designed to be impossible to misuse while delivering strong security guarantees.

## Features

- **ML-KEM-768** for key encapsulation (quantum-resistant key exchange)
- **ML-DSA-65** for digital signatures (quantum-resistant authentication)
- **ChaCha20-Poly1305** for authenticated encryption (fast, constant-time AEAD)
- **HKDF-SHA3-256** for key derivation (domain separation, forward secrecy)

## Security Properties

- **Quantum resistance**: All algorithms resistant to known quantum attacks
- **Forward secrecy**: Ephemeral keys destroyed after each operation
- **Authentication**: Cryptographic proof of sender identity
- **Constant-time**: No timing side-channels in secret-dependent operations
- **Memory safety**: Automatic secure zeroing of sensitive data

## Quick Start

```rust
use tollway_core::{KeyPair, seal, open};

// Generate keypairs for Alice and Bob
let alice = KeyPair::generate();
let bob = KeyPair::generate();

// Alice encrypts a message to Bob
let plaintext = b"Hello, Bob!";
let ciphertext = seal(plaintext, &alice, &bob.public_key())?;

// Bob decrypts and verifies it came from Alice
let (decrypted, sender_pk) = open(&ciphertext, &bob)?;
assert_eq!(decrypted, plaintext);
assert_eq!(sender_pk, alice.public_key());
```

## API

### Key Generation

```rust
let keypair = KeyPair::generate();
let public_key = keypair.public_key();
```

### Encryption (Seal)

```rust
let ciphertext = seal(
    plaintext: &[u8],
    sender_keypair: &KeyPair,
    recipient_public_key: &PublicKey,
)?;
```

Returns a `Vec<u8>` containing the ciphertext.

### Decryption (Open)

```rust
let (plaintext, verified_sender) = open(
    ciphertext: &[u8],
    recipient_keypair: &KeyPair,
)?;
```

Returns the plaintext and the sender's verified public key.

## Wire Format

Ciphertexts are self-contained and include all necessary information:

``` text
[ Version | Sender PK | Signature | Ephemeral PK | KEM CT | AEAD CT ]
```

- **Version**: Algorithm version tag (allows future upgrades)
- **Sender PK**: Sender's signing public key
- **Signature**: Signature over ephemeral KEM public key
- **Ephemeral PK**: One-time KEM public key (forward secrecy)
- **KEM CT**: Key encapsulation ciphertext
- **AEAD CT**: Encrypted plaintext with auth tag

Total overhead: ~9,189 bytes + plaintext length

## Error Handling

All operations return `Result<T, TollwayError>`:

```rust
pub enum TollwayError {
    InvalidCiphertext,
    SignatureVerificationFailed,
    DecryptionFailed,
    KeyGenerationFailed,
}
```

## No Configuration

There are no knobs to turn & no modes to configure. This is intentional. every configuration option is an opportunity for misuse.

If you need different algorithms, use a different version of the library.

## License

Dual-licensed under Apache 2.0 and MIT.
