# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues!!**

Send reports to: **security@tollway.net**

Include:
- Description of the vulnerability
- Affected versions
- Steps to reproduce
- Potential impact assessment
- Suggested remediation (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix and disclosure**: Coordinated with reporter

## Security Measures

### Cryptographic Implementation

- Constant-time operations for all secret-dependent control flow
- Secure memory zeroing on key material deallocation
- Side-channel resistance testing in CI
- NIST test vector validation

### Dependencies

- Minimal dependency tree (reduce attack surface)
- Regular `cargo audit` runs in CI
- Pinned versions for cryptographic dependencies
- Review of all transitive dependencies

### Development Practices

- All code reviewed before merge
- Fuzzing of parsing and cryptographic operations
- Property-based testing for state machines
- Memory safety via Rust's type system

## Known Limitations

### Scope

- Side-channel resistance focuses on software timing attacks
- Hardware side-channels (power analysis, EM) not in scope for V1
- Formal verification of primitives deferred to upstream libraries

### Out of Scope

- Physical security (hardware tampering, cold boot attacks)
- Social engineering and phishing
- Denial of service attacks
- Compromised development environments

## Cryptographic Agility

### Algorithm Versioning

All ciphertexts include version tags allowing future algorithm upgrades without breaking compatibility.

Current (V1):

- ML-KEM-768
- ML-DSA-65  
- ChaCha20-Poly1305
- HKDF-SHA3-256

Future versions may upgrade algorithms as cryptanalysis progresses.

## Audit Status

- **V1.0**: Internal security review (Q1 2026)
- **External audit**: Planned (Q2 2026)
- **Formal verification**: Planned for core primitives (2026-2027)

## Security Contact

**Email**: security@tollway.net 
**PGP Key**: E75F 6D7D 1DFF 2292 D7F5 4A06 292E 43D9 C84E 61DF