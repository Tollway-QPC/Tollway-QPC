# Tollway-PQC Roadmap

## V1.0 - Foundation (Current)

**Status**: In development

**Scope**:

- Core seal/open primitives (ML-KEM-768, ML-DSA-65, ChaCha20-Poly1305)
- Key management (identities, rotation, storage)
- Audit logging
- Backup/recovery
- Comprehensive test coverage
- Initial benchmarks
- Documentation

**Release Criteria**:

- All NIST test vectors pass
- Side-channel tests pass (dudect)
- Memory safety verified (MIRI, valgrind)
- API stable (no breaking changes planned)
- External security review complete

---

## V1.1 - Performance & Observability (Q2 2024)

**Performance**:

- SIMD-optimized lattice operations (AVX2)
- Batch seal/open operations
- Lazy key generation
- Memory pool for frequent allocations

**Observability**:

- Prometheus metrics export
- OpenTelemetry integration
- Performance dashboards
- Key lifecycle visualizations

**DX Improvements**:

- CLI tool for key management (`tollway keygen`, `tollway rotate`, etc.)
- Interactive setup wizard
- Better error messages with recovery suggestions

---

## V1.2 - Hybrid Mode (Q3 2024)

**Classical + PQC Hybrid**:

- RSA-2048 + ML-KEM-768 dual KEM
- ECDSA-P256 + ML-DSA-65 dual signatures
- Gradual migration tooling
- Compatibility with existing systems

**Why**: Enterprises need migration paths. Hybrid mode provides:

- Hedging against PQC algorithm breaks
- Drop-in replacement for classical crypto
- Security during transition period

**API**:

```rust
let hybrid_keypair = HybridKeyPair::generate()?;
let ciphertext = seal_hybrid(plaintext, &hybrid_keypair, &their_pk)?;
```

---

## V2.0 - Migration & Compatibility (Q4 2024)

**tollway-migrate crate**:

- Scan codebases for classical crypto usage
- Generate migration reports
- Suggest drop-in replacements
- Automated refactoring (limited scope)

**tollway-compat crate**:

- Drop-in replacement for OpenSSL APIs
- Drop-in replacement for libsodium APIs
- Shim layer for existing code
- Zero application code changes

**Goal**: Make PQC migration as easy as changing a dependency.

---

## V2.1 - Advanced Key Management (Q1 2025)

**Features**:

- Threshold cryptography (M-of-N key splitting)
- Hardware security module (HSM) integration
- TPM-backed key storage
- Remote key management service (KMS)

**Use Cases**:

- High-security environments (government, finance)
- Multi-party computation scenarios
- Distributed systems with no single point of trust

---

## V3.0 - Sessions & Protocols (Q2 2025)

**tollway-session crate**:

- Double Ratchet implementation
- Post-compromise security for ongoing communication
- Out-of-order message handling
- Session resumption

**tollway-tls crate**:

- PQC TLS 1.3 handshake
- Certificate management
- Integration with existing TLS stacks

**Goal**: Move beyond one-shot encryption to full protocol support.

---

## V3.1 - Formal Verification (Q3 2025)

**Verified Components**:

- Key derivation function (HKDF)
- Wire format parsing (no panics, no OOB)
- State machine invariants (key lifecycle)

**Tooling**:

- Coq/Isabelle proofs for critical paths
- Rust→verification language translation
- Continuous verification in CI

**Goal**: Machine-checked proofs that core properties hold.

---

## Long-Term Vision (2026+)

**Ecosystem**:

- Language bindings (Python, Go, JavaScript, Java)
- Framework integrations (Rocket, Actix, gRPC)
- Cloud provider plugins (AWS KMS, GCP KMS, Azure Key Vault)

**Algorithm Evolution**:

- Support for future NIST rounds
- Graceful algorithm deprecation
- Seamless version migration

**Governance**:

- Cryptographic Data Governance (Tollway commercial)
- Asset graphs of cryptographic usage
- Policy orchestration at scale
- Migration planning tools

---

## Non-Roadmap (Things We Won't Build)

- General-purpose application framework
- Blockchain or distributed ledger tech
- Custom PQC algorithms (we use NIST standards)
- GUI applications (CLI and libraries only)

---

## How This Changes

This roadmap is a living document. Priorities shift based on:

1. **User feedback**: If enterprises need features sooner, we adjust
2. **Security landscape**: Algorithm breaks or quantum advances force reprioritization
3. **Regulatory changes**: New compliance requirements move features forward
4. **Dependency updates**: Upstream PQC library improvements unlock new capabilities

**Last updated**: 02/05/2026
