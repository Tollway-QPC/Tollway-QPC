# Design Decisions

## Core Architecture

### Why Ephemeral KEM Keys?

**Decision**: Every seal operation generates a fresh KEM keypair, uses it once, then destroys the secret key.

**Rationale**:

- Forward secrecy without protocol complexity
- Compromise of long-term keys doesn't compromise past ciphertexts
- Simpler than session-based ratcheting for one-shot encryption
- Prevents key reuse vulnerabilities

**Tradeoff**: Slight performance cost (KEM key generation per message) for strong security property that can't be violated through misuse.

---

### Why Signed Ephemeral Keys?

**Decision**: The sender signs the ephemeral KEM public key with their long-term ML-DSA signing key.

**Rationale**:

- Prevents key substitution attacks
- Binds sender identity to ciphertext cryptographically
- Recipient knows who encrypted this (not just "someone with the public key")
- Enables non-repudiation if needed

**Alternative considered**: Anonymous sealed boxes (no signatures). Rejected because real-world systems need authentication, and adding it later would break API compatibility.

---

### Why Two Keypairs Per Identity?

**Decision**: Each identity has both a signing keypair (ML-DSA-65) and a KEM keypair (ML-KEM-768).

**Rationale**:

- Post-quantum algorithms are purpose-built (can't use same keypair for both)
- Separation of concerns (signing ≠ key exchange)
- Allows independent rotation of signing vs. encryption keys
- Follows cryptographic best practices (no key reuse across primitives)

**Tradeoff**: Larger key material storage, but unavoidable in PQC world.

---

### Why ML-KEM-768 (not 512 or 1024)?

**Decision**: Use ML-KEM-768 as the default KEM algorithm.

**Rationale**:

- Security level 3 (comparable to AES-192)
- Reasonable key/ciphertext sizes (not as large as 1024)
- Sufficient for long-term security against quantum attacks
- NIST-recommended for most applications

**ML-KEM-512**: Lower security (level 1), only appropriate for short-term secrets  
**ML-KEM-1024**: Higher security (level 5), but much larger keys (50%+ overhead)

We optimize for "secure for decades" not "secure against hypothetical future adversaries with unlimited resources."

---

### Why ChaCha20-Poly1305 (not AES-GCM)?

**Decision**: Use ChaCha20-Poly1305 for authenticated encryption.

**Rationale**:

- Constant-time in software (no AES timing vulnerabilities)
- Excellent performance on platforms without AES-NI
- Well-studied, widely deployed (TLS 1.3, WireGuard)
- Simpler implementation (fewer failure modes than AES-GCM)

**AES-GCM**: Faster with hardware support, but:

- Timing vulnerabilities in software implementations
- Catastrophic failure if nonce is reused
- Complex multi-mode primitive

We value constant-time guarantee over raw throughput.

---

### Why HKDF-SHA3-256 (not HKDF-SHA2)?

**Decision**: Use HKDF with SHA3-256 for key derivation.

**Rationale**:

- SHA3 is structurally different from SHA2 (sponge construction vs. Merkle-Damgård)
- Reduces risk of cryptanalytic breakthrough affecting entire stack
- Post-quantum security considerations (no known quantum weaknesses)
- Still fast enough for our use case

**SHA2**: Slightly faster, more common. But we're building for 30 years, not optimizing for today.

---

### Why Hybrid Encryption?

**Decision**: Use KEM to derive a symmetric key, then AEAD to encrypt the actual data.

**Rationale**:

- KEM output is fixed-size (can't encrypt arbitrary-length plaintext)
- Symmetric crypto is orders of magnitude faster for bulk encryption
- Standard construction in all modern protocols (TLS, Signal, etc.)
- Allows streaming encryption (derive one AEAD key, encrypt chunks)

**Direct KEM encryption**: Would require chunking plaintext and running KEM per chunk. Wasteful and error-prone.

---

## Key Management Design

### Why Identity Abstraction?

**Decision**: Wrap keypairs in an "Identity" type with name, metadata, and policy.

**Rationale**:

- Humans think in names ("seal to Bob"), not public keys
- Enables key rotation without breaking references
- Attaches lifecycle metadata (creation time, usage count, expiration)
- Allows policy enforcement (automatic rotation, expiration)

**Alternative**: Raw keypair management. Rejected because enterprises need auditability and lifecycle management, not just crypto primitives.

---

### Why Automatic Key Rotation?

**Decision**: Keys can auto-rotate based on policy (time-based or usage-based).

**Rationale**:

- Reduces blast radius of key compromise
- Industry best practice for long-term secrets
- Manual rotation is error-prone and often forgotten
- Enables compliance with regulations requiring periodic rotation

**Implementation**: Old keys are archived (not deleted) to allow decryption of old ciphertexts during grace period.

---

### Why Encrypted Key Storage?

**Decision**: All keys are encrypted at rest using a master key.

**Rationale**:

- Defense in depth (file system breach doesn't immediately leak keys)
- Enables passphrase-based key access
- Industry standard (KeyChain, KMS, HSM all encrypt at rest)

**Tradeoff**: Requires secure master key management. We support multiple backends (system keyring, HSM, passphrase derivation).

---

### Why Audit Logging?

**Decision**: All cryptographic operations emit structured audit events.

**Rationale**:

- Compliance requirements (SOC2, FISMA, HIPAA)
- Debugging (why did this decryption fail?)
- Security monitoring (detect brute-force attempts, key theft)
- Post-incident forensics

**Format**: JSON-structured logs, easy to ingest into SIEM systems.

---

## Wire Format Design

### Why Version Tags?

**Decision**: Every ciphertext starts with a version byte.

**Rationale**:

- Allows algorithm upgrades without breaking compatibility
- V2 can use ML-KEM-1024 while V1 still works
- Gradual migration path as cryptanalysis improves
- Standard practice in all long-lived protocols

**Format**: Single byte at the start: `0x01` = V1, `0x02` = V2, etc.

---

### Why Include Sender Public Key?

**Decision**: Ciphertext includes the sender's signing public key.

**Rationale**:

- Recipient needs it to verify the signature
- Allows "encrypt to stranger" without pre-shared keys
- Enables key rotation (ciphertext carries current key, not historical reference)

**Tradeoff**: 2592 extra bytes per ciphertext. Worth it for usability and flexibility.

---

### Why Not Compress Ciphertexts?

**Decision**: No compression in wire format.

**Rationale**:

- Compression + encryption can leak information (CRIME, BREACH attacks)
- Post-quantum ciphertexts are high-entropy (won't compress well)
- Added complexity for negligible benefit
- If users want compression, they can compress before sealing

---

## API Design

### Why Minimal Configuration?

**Decision**: No algorithm selection, no modes, no knobs to turn.

**Rationale**:

- Every configuration option is a way to screw up
- OpenSSL's flexibility led to weak deployments
- Developers want "just work securely" not "configure your own crypto"
- Opinionated APIs prevent misuse

**If you need different algorithms, you use a different version of the library.** We don't make it easy to choose weak options.

---

### Why Return `Result` Everywhere?

**Decision**: No panics in public API, all errors are `Result<T, TollwayError>`.

**Rationale**:

- Panics crash programs, errors can be handled gracefully
- Cryptographic failures should be recoverable
- Forces callers to handle error cases
- Rust best practice for libraries

---

### Why Separate Core and Keys?

**Decision**: `tollway-core` has primitives, `tollway-keys` has management.

**Rationale**:

- Separation of concerns (crypto vs. lifecycle)
- Allows using core without heavy key management deps
- Embedded systems might want primitives only
- Clear architectural boundary

**You can use `tollway-core` alone if you manage keys yourself.** Most users should use `tollway-keys`.

---

## Future Considerations

### Hybrid Classical+PQC Mode

**Planned**: Combine RSA/ECDSA with PQC during transition period.

**Rationale**:

- Enterprises need migration path
- Hedges against PQC algorithm breaks
- Industry expectation during transition

**Implementation**: Dual signatures, dual KEMs, concatenated shared secrets.

---

### Hardware Acceleration

**Planned**: AVX2/AVX-512 implementations of lattice operations.

**Rationale**:

- Significant performance improvements possible
- ML-KEM benefits from vectorization
- Competitive with classical crypto performance

**Challenge**: Maintaining constant-time guarantees across platforms.

---

### Formal Verification

**Planned**: Machine-checked proofs of core properties.

**Rationale**:

- Cryptographic correctness is critical
- Bugs in crypto are catastrophic
- Formal methods are tractable for small, well-defined modules

**Scope**: Start with KDF, wire format, state machine (not full primitives).

---

## Non-Goals

### Not Building

**Custom PQC algorithms**: We wrap NIST-standardized implementations, not inventing new crypto.

**Consensus protocols**: We're building encryption, not blockchain or distributed systems.

**Network transport**: We provide the crypto, you provide the transport (HTTP, QUIC, etc.).

**Application-specific features**: We're infrastructure, not an application framework.

---

## When We'd Change Our Mind

These decisions are strong, but not absolute. We'd reconsider if:

1. **NIST deprecates an algorithm**: We'd immediately plan migration to recommended replacement
2. **Catastrophic vulnerability discovered**: Emergency version bump with algorithm swap
3. **Performance becomes adoption blocker**: Explore hardware acceleration or algorithm alternatives
4. **Enterprise feedback**: If companies need features we deemed non-goals, we listen
5. **Quantum computing advances faster than expected**: Upgrade to higher security levels
