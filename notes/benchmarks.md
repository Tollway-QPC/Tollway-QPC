# Benchmarking Notes

## Goals

- Measure absolute performance (ops/sec, latency)
- Detect regressions in hot paths
- Compare to classical crypto baselines (RSA, ECDSA, AES-GCM)
- Identify optimization opportunities

## Baseline Targets (Commodity Hardware)

**Intel Core i7 (2020s era), single-threaded:**

| Operation | Target | Notes |
| --------- | ------ | ----- |
| KeyPair generation | < 1ms | Rare operation, acceptable latency |
| Seal (1KB payload) | < 5ms | Dominated by KEM ops |
| Seal (1MB payload) | < 50ms | Dominated by AEAD |
| Open (1KB payload) | < 5ms | Symmetric to seal |
| Open (1MB payload) | < 50ms | AEAD decryption |

**Compared to classical crypto:**

- RSA-2048 seal: ~0.5ms (10x faster, but quantum-vulnerable)
- ECDSA sign/verify: ~0.2ms each (20x faster, quantum-vulnerable)
- AES-GCM throughput: 2-5 GB/s (similar to ChaCha20-Poly1305)

**The tradeoff**: PQC is slower, but that's the cost of quantum resistance. We optimize within PQC constraints, not against classical crypto.

## Benchmark Suites

### Core Operations (criterion)

- `seal_1kb`, `seal_1mb`, `seal_100mb`: Varying payload sizes
- `open_1kb`, `open_1mb`, `open_100mb`: Decryption paths
- `generate_keypair`: Key generation
- `ephemeral_kem`: Ephemeral key generation overhead

### Key Management (criterion)

- `create_identity`: Identity creation with storage
- `rotate_identity`: Key rotation
- `seal_to_name`: Name-based encryption (includes lookup)
- `export_import`: Backup/recovery round-trip

### Memory Profiling (valgrind, heaptrack)

- Check for leaks in secure memory paths
- Ensure ephemeral keys are zeroed
- Measure allocation patterns in hot paths

### Side-Channel Resistance (dudect, ctgrind)

- Constant-time verification of secret-dependent operations
- Focus on: KEM decapsulation, signature verification, key derivation

## Optimization Priorities

1. **Don't optimize prematurely**: Profile first, optimize hot paths
2. **Algorithmic wins over micro-opts**: Better data structures > hand-tuned assembly
3. **Maintain constant-time**: Never trade security for speed
4. **Benchmark on real hardware**: VM performance is not representative

## Future Work

- SIMD implementations of lattice operations (AVX2, NEON)
- Parallelization for batch operations
- Hardware offload to crypto accelerators
- Lazy key generation (defer until first use)

## Red Flags

- Variance > 10% on repeated runs (indicates non-determinism)
- Memory usage growing with iterations (indicates leak)
- Timing differences correlated with secret values (side-channel)

**If benchmarks show any red flag, stop and investigate before proceeding.**
