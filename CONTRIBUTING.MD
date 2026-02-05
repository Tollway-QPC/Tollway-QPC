# Contributing to Tollway-PQC

We're building cryptographic infrastructure that needs to be correct, performant, and maintainable for decades. Contributions are welcome, but the bar is high.

## Before You Start

1. Read the [design decisions](./notes/design-decisions.md) to understand architectural choices
2. Check existing issues and PRs to avoid duplicate work
3. For major changes, open an issue first to discuss the approach

## Code Quality Standards

### Correctness

- All cryptographic operations must be constant-time
- No panics in production code paths (use `Result` types)
- Comprehensive test coverage (unit, integration, property-based)
- NIST test vectors must pass

### Performance

- Benchmark all changes to cryptographic hot paths
- No regressions without justification
- Profile before optimizing

### Security

- Run `cargo audit` before submitting
- Use `#[must_use]` for security-critical return values
- Document all `unsafe` blocks with safety invariants
- Zero all sensitive data on drop (use `zeroize` crate)

### Code Style

- Run `cargo fmt` before committing
- Run `cargo clippy -- -D warnings` and fix all issues
- Follow Rust API guidelines
- Document public APIs with examples

## Testing

```bash
# Run all tests
cargo test --workspace

# Run with sanitizers (requires nightly)
RUSTFLAGS="-Z sanitizer=address" cargo +nightly test

# Run benchmarks
cargo bench

# Check for timing leaks (requires additional tooling)
cargo test --features timing-tests -- --ignored
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes with clear, atomic commits
4. Add tests for all new functionality
5. Update documentation as needed
6. Run full test suite and linters
7. Submit PR with clear description of changes and motivation

## Security Issues

**Do not open public issues for security vulnerabilities.**

Email security@tollway.net with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We'll respond within 48 hours.

## Code of Conduct

Be professional, respectful, and focused on technical merit. We're here to build stuff.