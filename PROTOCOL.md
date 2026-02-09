# Tollway-PQC Protocol Specification

**Version**: 1.0  
**Status**: Experimental  
**Last Updated**: February 2026

## Table of Contents

1. [Threat Model](#1-threat-model)
2. [Security Properties](#2-security-properties)
3. [Attack Scenarios](#3-attack-scenarios)
4. [Algorithm Specification](#4-algorithm-specification)
5. [Wire Format](#5-wire-format)
6. [Migration Strategy](#6-migration-strategy)

---

## 1. Threat Model

### 1.1 Adversary Capabilities

Tollway-PQC is designed to resist the following adversary types:

#### Quantum Adversary (Primary Threat)

- **Capability**: Access to a cryptographically relevant quantum computer (CRQC)
- **Attacks**: Shor's algorithm against RSA, ECDH, ECDSA
- **Timeline**: NIST estimates 15-20 years, but harvest-now-decrypt-later is immediate

#### Harvest-Now-Decrypt-Later (HNDL)

- **Capability**: Passive network interception and long-term storage
- **Strategy**: Capture encrypted traffic today, decrypt when quantum computers exist
- **Risk Level**: CRITICAL for data with multi-decade confidentiality requirements
- **Affected Sectors**: Government, healthcare, financial, legal, intellectual property

#### Classical Adversary

- **Capability**: State-level compute resources, side-channel attacks, implementation bugs
- **Attacks**: Timing attacks, cache attacks, fault injection, chosen-ciphertext attacks
- **Mitigation**: Constant-time implementations, AEAD authentication, memory safety

### 1.2 Trust Boundaries

#### What Tollway-PQC Trusts

- The underlying operating system's random number generator
- The pqcrypto library's implementation of ML-KEM-768 and ML-DSA-65
- The chacha20poly1305 crate's AEAD implementation
- The user's secure storage of long-term private keys
- Correct compilation by the Rust compiler

#### What Tollway-PQC Does NOT Trust

- Network transport (assumes all traffic is observed)
- Peer identity (requires out-of-band verification of public keys)
- Forward message ordering or delivery guarantees
- Clock synchronization between parties

### 1.3 Scope Exclusions

Tollway-PQC explicitly does NOT protect against:

- Compromised endpoints (malware with access to memory)
- Side-channel attacks in uncontrolled environments
- Denial of service attacks
- Social engineering or key compromise through non-cryptographic means
- Implementation bugs in the Rust compiler or standard library

---

## 2. Security Properties

### 2.1 Guaranteed Properties

#### Confidentiality (IND-CCA2)

- **Claim**: Ciphertexts reveal no information about plaintexts
- **Mechanism**: ML-KEM-768 encapsulation + ChaCha20-Poly1305 AEAD
- **Assumption**: ML-KEM-768 is IND-CCA2 secure (NIST Level 3)

#### Authenticity (EUF-CMA)

- **Claim**: Messages are verifiably from the stated sender
- **Mechanism**: ML-DSA-65 signature on ephemeral public keys
- **Assumption**: ML-DSA-65 is EUF-CMA secure (NIST Level 3)

#### Integrity (INT-CTXT)

- **Claim**: Any modification to ciphertext is detected
- **Mechanism**: ChaCha20-Poly1305 authentication tag
- **Assumption**: Poly1305 MAC is unforgeable

#### Forward Secrecy (Per-Message)

- **Claim**: Compromise of long-term keys does not expose past messages
- **Mechanism**: Fresh ephemeral KEM keypair per `seal()` operation
- **Caveat**: Ephemeral secret key must be zeroed immediately after use

#### Sender Binding

- **Claim**: Recipient knows which public key sent the message
- **Mechanism**: Sender's signing public key embedded in ciphertext
- **Caveat**: Does not prove sender "identity" — only key ownership

### 2.2 Properties NOT Guaranteed

#### Deniability

- **Status**: NOT PROVIDED
- **Reality**: Sender's signature cryptographically proves authorship
- **Implication**: Recipient can prove to third parties who sent the message

#### Anonymity

- **Status**: NOT PROVIDED
- **Reality**: Sender's public key is transmitted in ciphertext header
- **Implication**: Passive observer can identify sender (not message content)

#### Replay Protection

- **Status**: NOT PROVIDED
- **Reality**: Same ciphertext can be delivered multiple times
- **Implication**: Application layer must implement sequence numbers or nonces

#### Key Compromise Impersonation (KCI) Resistance

- **Status**: PARTIAL
- **Reality**: If recipient's signing key is compromised, attacker cannot impersonate sender
- **Reality**: If recipient's KEM key is compromised, attacker can decrypt future messages

#### Post-Compromise Security

- **Status**: NOT PROVIDED
- **Reality**: After key compromise, attacker retains access until key rotation
- **Mitigation**: Use tollway-keys with automatic key rotation policies

---

## 3. Attack Scenarios

### 3.1 What Breaks Security

#### Scenario: Quantum Computer Attacks KEM

- **Attack**: CRQC solves MLWE problem underlying ML-KEM-768
- **Impact**: All confidentiality lost for captured ciphertexts
- **Likelihood**: LOW before 2035, possible after 2040
- **Response**: Protocol allows algorithm version upgrade (see Section 6)

#### Scenario: Quantum Computer Attacks Signatures

- **Attack**: CRQC breaks ML-DSA-65
- **Impact**: Attacker can forge messages from any sender
- **Likelihood**: Same timeline as KEM attacks
- **Response**: Version migration to stronger parameters or new algorithms

#### Scenario: RNG Compromise

- **Attack**: Predictable randomness in key generation or ephemeral keys
- **Impact**: CATASTROPHIC — all security properties lost
- **Mitigation**: Use only OS-provided CSPRNG, verify entropy sources

#### Scenario: Long-Term Key Compromise

- **Attack**: Attacker obtains recipient's long-term KEM secret key
- **Impact**: All future messages to that key are decryptable
- **Impact**: Past messages remain protected (forward secrecy)
- **Response**: Immediate key rotation, re-establish trust

#### Scenario: Ephemeral Key Reuse

- **Attack**: Implementation bug causes ephemeral key reuse
- **Impact**: Loss of forward secrecy for affected messages
- **Mitigation**: Ephemeral key generated fresh per seal(), zeroized immediately

### 3.2 What Does NOT Break Security

#### Scenario: Network Eavesdropping

- **Attack**: Passive capture of all encrypted traffic
- **Impact**: NONE — traffic is encrypted with quantum-resistant algorithms

#### Scenario: Ciphertext Modification

- **Attack**: Active attacker modifies ciphertext in transit
- **Impact**: NONE — AEAD tag verification fails, ciphertext rejected

#### Scenario: Wrong Recipient Attempt

- **Attack**: Attacker tries to decrypt with different keypair
- **Impact**: NONE — KEM decapsulation fails, garbage output

#### Scenario: Signature Forgery

- **Attack**: Attacker tries to create valid signature without sender's key
- **Impact**: NONE — ML-DSA-65 signature verification fails

---

## 4. Algorithm Specification

### 4.1 Algorithm Suite

| Component | Algorithm | Security Level | Reference |
| --------- | --------- | -------------- | --------- |
| Key Encapsulation | ML-KEM-768 | NIST Level 3 | FIPS 203 |
| Digital Signature | ML-DSA-65 | NIST Level 3 | FIPS 204 |
| AEAD | ChaCha20-Poly1305 | 256-bit classical | RFC 8439 |
| KDF | HKDF-SHA3-256 | 256-bit | RFC 5869 |

### 4.2 Key Sizes

| Key Type | Size (bytes) |
| ---------- | -------------- |
| ML-KEM-768 Public Key | 1,184 |
| ML-KEM-768 Secret Key | 2,400 |
| ML-KEM-768 Ciphertext | 1,088 |
| ML-KEM-768 Shared Secret | 32 |
| ML-DSA-65 Public Key | 1,952 |
| ML-DSA-65 Secret Key | 4,032 |
| ML-DSA-65 Signature | 3,309 |

### 4.3 Seal Operation Flow

``` text
seal(plaintext, sender_keypair, recipient_public_key):
    1. Generate ephemeral KEM keypair (pk_e, sk_e) ← ML-KEM-768.KeyGen()
    2. Sign ephemeral public key: sig ← ML-DSA-65.Sign(sk_sender, pk_e)
    3. Encapsulate shared secret: (K, ct_kem) ← ML-KEM-768.Encaps(pk_recipient)
    4. Derive AEAD key: key ← HKDF-SHA3-256(K, "tollway-aead-key")
    5. Derive AEAD nonce: nonce ← HKDF-SHA3-256(K, "tollway-aead-nonce")[:12]
    6. Build AAD: aad ← pk_sender_sign || pk_recipient_kem || pk_e
    7. Encrypt: ct_aead ← ChaCha20-Poly1305.Encrypt(key, nonce, plaintext, aad)
    8. Zeroize sk_e (forward secrecy)
    9. Return wire_format(version, pk_sender, pk_e, sig, ct_kem, ct_aead)
```

### 4.4 Open Operation Flow

``` text
open(ciphertext, recipient_keypair):
    1. Parse wire_format → (version, pk_sender, pk_e, sig, ct_kem, ct_aead)
    2. Verify: ML-DSA-65.Verify(pk_sender, pk_e, sig) or FAIL
    3. Decapsulate: K ← ML-KEM-768.Decaps(sk_recipient, ct_kem)
    4. Derive AEAD key: key ← HKDF-SHA3-256(K, "tollway-aead-key")
    5. Derive AEAD nonce: nonce ← HKDF-SHA3-256(K, "tollway-aead-nonce")[:12]
    6. Rebuild AAD: aad ← pk_sender_sign || pk_recipient_kem || pk_e
    7. Decrypt: plaintext ← ChaCha20-Poly1305.Decrypt(key, nonce, ct_aead, aad) or FAIL
    8. Return (plaintext, pk_sender)
```

---

## 5. Wire Format

### 5.1 Ciphertext Structure (Version 1)

``` text
+--------+------------------+------------------+------------------+
| Offset | Field            | Size (bytes)     | Description      |
+--------+------------------+------------------+------------------+
| 0      | version          | 1                | Protocol version |
| 1      | sender_sign_pk   | 1,952            | Sender signing PK|
| 1,953  | sender_kem_pk    | 1,184            | Sender KEM PK    |
| 3,137  | ephemeral_kem_pk | 1,184            | Ephemeral KEM PK |
| 4,321  | signature        | 3,309            | Signature on pk_e|
| 7,630  | kem_ciphertext   | 1,088            | ML-KEM-768 ct    |
| 8,718  | aead_ct_len      | 4                | AEAD ct length   |
| 8,722  | aead_ciphertext  | variable         | Encrypted data   |
+--------+------------------+------------------+------------------+

Minimum ciphertext size: 8,722 + 16 (AEAD tag) = 8,738 bytes
```

### 5.2 Version Byte

| Value     | Meaning                                    |
|-----------|--------------------------------------------|
| 0x01      | ML-KEM-768 + ML-DSA-65 + ChaCha20-Poly1305 |
| 0x02-0xFF | Reserved for future algorithm suites       |

---

## 6. Migration Strategy

### 6.1 Algorithm Version Upgrades

#### When to Upgrade

- New NIST guidance on parameter security
- Discovery of weakness in current algorithms
- Performance improvements in new algorithm variants

#### Upgrade Process

1. New version byte defined (e.g., 0x02)
2. Library updated to support both old and new versions
3. Users generate new keypairs with new algorithms
4. Transition period: accept both versions, send new version
5. Deprecation: stop accepting old version after sunset date

### 6.2 Backward Compatibility

- The `open()` function MUST accept all supported version bytes
- The `seal()` function SHOULD use the latest version by default
- Version 1 will remain supported for minimum 5 years after deprecation announcement

### 6.3 Key Rotation Recommendations

| Key Type | Recommended Rotation | Maximum Lifetime |
| ---------- | --------------------- | ------------------ |
| Long-term Signing | 2 years | 5 years |
| Long-term KEM | 1 year | 3 years |
| Ephemeral | Per message | Single use |

### 6.4 Migration from Classical Cryptography

For systems migrating from RSA/ECDSA/ECDH:

1. **Parallel Operation**: Run PQC alongside classical for transition period
2. **Hybrid Mode**: Use both classical and PQC (tollway-hybrid, coming soon)
3. **Full Migration**: Switch entirely to PQC when confidence is established

---

## Appendix A: Security Proofs

### A.1 Forward Secrecy Argument

**Theorem**: Compromise of long-term keys does not reveal past message contents.

**Proof Sketch**:

1. Each `seal()` generates fresh ephemeral KEM keypair
2. Shared secret K derived from ephemeral secret key and recipient public key
3. Ephemeral secret key zeroized immediately after encapsulation
4. To decrypt past message, attacker needs ephemeral secret key
5. Ephemeral secret key exists only in RAM during seal() execution
6. Therefore, long-term key compromise after seal() provides no advantage

**Assumptions**: Memory zeroization effective, no side-channel leakage of ephemeral key.

### A.2 Authentication Argument

**Theorem**: Valid ciphertext can only be produced by holder of sender's signing key.

**Proof Sketch**:

1. Ciphertext contains signature on ephemeral public key
2. Signature verification uses sender's public signing key
3. ML-DSA-65 is EUF-CMA secure
4. Attacker cannot forge signature without sender's secret signing key
5. Therefore, valid open() implies message originated from sender

---

## Appendix B: Implementation Requirements

### B.1 Random Number Generation

- MUST use operating system CSPRNG (e.g., `getrandom`, `BCryptGenRandom`)
- MUST NOT use userspace PRNGs for key generation
- SHOULD verify entropy pool health before critical operations

### B.2 Key Storage

- Secret keys MUST be zeroized when no longer needed (Zeroize trait)
- Secret keys SHOULD be stored in secure memory if available
- Secret keys MUST NOT be logged, serialized to disk, or transmitted

### B.3 Constant-Time Operations

- Key comparison MUST be constant-time
- Signature verification SHOULD not leak validity through timing
- AEAD decryption MUST not leak plaintext through timing

### B.4 Error Handling

- Decryption failures MUST NOT reveal which check failed
- All error paths SHOULD take similar time (prevent timing oracles)
- Error messages MUST NOT include secret key material

---

## Document History

| Version | Date     | Changes               |
|---------|----------|-----------------------|
| 1.0     | Feb 2026 | Initial specification |

---

*This document is part of the Tollway-PQC project. For implementation, see the source code. For vulnerabilities, see SECURITY.md.*
