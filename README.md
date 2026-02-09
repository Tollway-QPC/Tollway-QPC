# Tollway-PQC

**Best post-quantum cryptographic primitives for Rust. Working toward production.**

![Status: Experimental](https://img.shields.io/badge/status-experimental-orange)
![Audit: Q2 2026](https://img.shields.io/badge/audit-Q2%202026-blue)
![NIST: Level 3](https://img.shields.io/badge/NIST-Level%203-green)
![License: MIT/Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)

## The Problem

**Harvest-Now-Decrypt-Later (HNDL)** is happening today.

Nation-state adversaries are capturing encrypted traffic now, storing it indefinitely, waiting for quantum computers to break today's encryption. If your data needs to stay secret for 10+ years, it's already at risk.

- Your TLS traffic from 2024 → readable in 2035
- Healthcare records, legal documents, IP → exposed
- RSA-2048, ECDH, ECDSA → all broken by Shor's algorithm

**The quantum clock is ticking. Migration takes years. Start now.**

## The Solution

Tollway-PQC provides quantum-resistant encryption using NIST-standardized algorithms:

| Component | Algorithm | Security |
|-----------|-----------|----------|
| Key Encapsulation | **ML-KEM-768** | Post-quantum Level 3 |
| Digital Signatures | **ML-DSA-65** | Post-quantum Level 3 |
| Symmetric Encryption | **ChaCha20-Poly1305** | 256-bit classical |
| Key Derivation | **HKDF-SHA3-256** | 256-bit |

Every message is encrypted, authenticated, and protected with forward secrecy—automatically.

## Quick Start

30 seconds to working code:

```rust
use tollway_core::{KeyPair, seal, open};

// Generate post-quantum keypairs
let alice = KeyPair::generate();
let bob = KeyPair::generate();

// Alice encrypts to Bob with authentication
let ciphertext = seal(b"Hello Bob", &alice, &bob.public_key())?;

// Bob decrypts and verifies Alice's identity
let (plaintext, sender) = open(&ciphertext, &bob)?;

assert_eq!(plaintext, b"Hello Bob");
assert_eq!(sender, alice.public_key());  // Cryptographic proof it's from Alice
```

Add to your `Cargo.toml`:

```toml
[dependencies]
tollway-core = "1.0"
```

## Status

**V1.0: Experimental**

| Milestone | Status | Date |
|-----------|--------|------|
| Core API stable | ✅ Complete | Jan 2026 |
| Full test coverage | ✅ Complete | Feb 2026 |
| Fuzzing infrastructure | ✅ Complete | Feb 2026 |
| Side-channel testing | ✅ Complete | Feb 2026 |
| NIST vector validation | ✅ Complete | Feb 2026 |
| Third-party audit | 🔄 Scheduled | Q2 2026 |
| Production release | ⏳ Pending | Q3 2026 |

**Do not use in production until audit completes.** The API is stable, but professional security review is required before handling real secrets.

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                         seal()                               │
├─────────────────────────────────────────────────────────────┤
│  1. Generate ephemeral KEM keypair (fresh per message)      │
│  2. Sign ephemeral key with sender's long-term key          │
│  3. Encapsulate shared secret to recipient's public key     │
│  4. Derive AEAD key via HKDF-SHA3-256                       │
│  5. Encrypt plaintext with ChaCha20-Poly1305               │
│  6. Zeroize ephemeral secret (forward secrecy)              │
│  7. Output: ciphertext with embedded sender identity        │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                         open()                               │
├─────────────────────────────────────────────────────────────┤
│  1. Parse wire format, extract components                   │
│  2. Verify sender's signature on ephemeral key              │
│  3. Decapsulate shared secret with recipient's secret key   │
│  4. Derive AEAD key via HKDF-SHA3-256                       │
│  5. Decrypt and authenticate ciphertext                     │
│  6. Return plaintext + verified sender public key           │
└─────────────────────────────────────────────────────────────┘
```

**Security properties:**
- ✅ Confidentiality (IND-CCA2)
- ✅ Authenticity (EUF-CMA)
- ✅ Integrity (INT-CTXT)
- ✅ Forward secrecy (per-message)
- ✅ Sender binding

**Not provided:**
- ❌ Deniability (signatures prove authorship)
- ❌ Anonymity (sender ID in ciphertext)
- ❌ Replay protection (application layer)

See [PROTOCOL.md](./PROTOCOL.md) for full security specification.

## Performance

Benchmarks on AMD Ryzen 7 5800X @ 3.8GHz:

| Operation | Tollway-PQC | RSA-2048 | Comparison |
|-----------|-------------|----------|------------|
| Key Generation | ~15ms | ~150ms | **10x faster** |
| Encrypt 1KB | ~1.5ms | ~0.5ms | 3x slower |
| Decrypt 1KB | ~1.0ms | ~5ms | **5x faster** |
| Encrypt 1MB | ~3ms | ~15ms | **5x faster** |
| Decrypt 1MB | ~2.5ms | ~20ms | **8x faster** |

**Size overhead:**

| Component | Tollway-PQC | RSA-2048 |
|-----------|-------------|----------|
| Public Key | 3,136 bytes | 256 bytes |
| Ciphertext Overhead | 8,738 bytes | 256 bytes |
| Signature | 3,309 bytes | 256 bytes |

The "PQC tax" is primarily in key and ciphertext sizes, not computation. Bulk encryption uses ChaCha20-Poly1305 (same as any hybrid scheme), so throughput scales identically.

Run benchmarks yourself:

```bash
cargo bench --bench comprehensive
```

## Roadmap

### V1 (Current) — Foundation
- ✅ ML-KEM-768 + ML-DSA-65 + ChaCha20-Poly1305
- ✅ Forward secrecy with ephemeral keys
- ✅ Sender authentication
- ✅ Comprehensive test suite

### V2 — Key Management
- 🔄 `tollway-keys`: Identity-based key management
- 🔄 Automatic key rotation policies
- 🔄 Encrypted backup and recovery
- 🔄 Audit logging for compliance

### V3 — Enterprise
- ⏳ `tollway-hybrid`: Classical + PQC hybrid mode
- ⏳ `tollway-migrate`: RSA/ECDSA migration tooling
- ⏳ Hardware security module (HSM) integration
- ⏳ FIPS 140-3 certification path

## Examples

### Basic Encryption
```rust
use tollway_core::{KeyPair, seal, open};

let alice = KeyPair::generate();
let bob = KeyPair::generate();

let ciphertext = seal(b"Secret message", &alice, &bob.public_key())?;
let (plaintext, sender) = open(&ciphertext, &bob)?;
```

### File Encryption
```rust
use tollway_core::{KeyPair, seal, open};
use std::fs;

let key = KeyPair::generate();
let data = fs::read("secret.pdf")?;

// Encrypt to self
let encrypted = seal(&data, &key, &key.public_key())?;
fs::write("secret.pdf.enc", &encrypted)?;

// Later: decrypt
let encrypted = fs::read("secret.pdf.enc")?;
let (decrypted, _) = open(&encrypted, &key)?;
fs::write("secret.pdf", &decrypted)?;
```

### Encrypted Vault CLI
```bash
# Initialize vault with new keypair
cargo run --example encrypted_vault -- init

# Store encrypted values
cargo run --example encrypted_vault -- put api_key "sk-secret-12345"

# Retrieve and decrypt
cargo run --example encrypted_vault -- get api_key

# Rotate keys (re-encrypt everything)
cargo run --example encrypted_vault -- rotate
```

## Architecture

```
tollway-pqc/
├── tollway-core/     # Cryptographic primitives
│   ├── seal()        # Encrypt with authentication
│   ├── open()        # Decrypt and verify
│   └── KeyPair       # Post-quantum keypairs
│
├── tollway-keys/     # Key lifecycle management
│   ├── Identity      # Named key bundles
│   ├── KeyManager    # Storage and rotation
│   └── Backup        # Encrypted key export
│
├── tollway-hybrid/   # (Coming) Classical + PQC
└── tollway-migrate/  # (Coming) Migration tooling
```

## Security

### What We Test

- **Unit tests**: Every function, every edge case
- **Property tests**: Invariants verified with proptest (10,000+ cases)
- **Fuzz testing**: Wire format parser, seal/open roundtrip, corruption handling
- **Timing tests**: Statistical analysis for side-channel leaks
- **Error coverage**: Every error variant triggered and verified
- **NIST vectors**: Algorithm parameter validation

### What We Claim

See [PROTOCOL.md](./PROTOCOL.md) for:
- Threat model (quantum adversary, HNDL)
- Security properties with proofs
- Attack scenarios and mitigations
- Algorithm migration strategy

### Reporting Vulnerabilities

See [SECURITY.md](./SECURITY.md) for responsible disclosure.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](./CONTRIBUTING.MD) for:
- Development setup
- Code style guidelines
- Testing requirements
- Pull request process

## License

Dual-licensed under [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE) at your option.

## Acknowledgments

Built on the excellent [pqcrypto](https://crates.io/crates/pqcrypto) library, which provides Rust bindings to the reference implementations of NIST post-quantum algorithms.

---

**Questions?** Open an issue or discussion.

**Ready to start?** `cargo add tollway-core` and protect your data against quantum computers today.
