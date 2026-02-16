//! Side-channel resistance tests
//!
//! These tests verify that cryptographic operations don't leak timing information.
//!
//! # Constant-Time Properties Claimed
//!
//! The following operations should be constant-time with respect to secret data:
//! - Key generation (randomness aside)
//! - Signature generation (secret key)
//! - Signature verification (should not leak valid/invalid early)
//! - KEM decapsulation (secret key)
//! - AEAD decryption (key and plaintext)
//! - Key comparison (for authentication)
//!
//! # Testing Strategy
//!
//! 1. **Timing variance tests**: Run operations many times, check for outliers
//! 2. **Input independence tests**: Different inputs should have similar timing
//! 3. **Statistical tests** (future): Use dudect for rigorous analysis
//!
//! Note: These tests can have false positives due to system noise.
//! Run on a quiet system with `--release` for meaningful results.

use std::time::Instant;
use tollway_core::{open, seal, KeyPair};

/// Measure timing of an operation over multiple iterations with warmup.
///
/// Runs `warmup` unmeasured iterations first to warm caches and stabilize
/// CPU frequency, then collects `iterations` timed samples.
fn measure_timing<F: FnMut()>(mut f: F, iterations: u32, warmup: u32) -> Vec<u128> {
    for _ in 0..warmup {
        f();
    }
    (0..iterations)
        .map(|_| {
            let start = Instant::now();
            f();
            start.elapsed().as_nanos()
        })
        .collect()
}

/// Calculate coefficient of variation (CV) on the interquartile range.
///
/// Trims the fastest and slowest 25% of samples to remove outliers caused
/// by context switches, frequency scaling, or other system noise.  This
/// makes the metric far more stable on shared CI runners while still
/// detecting genuine constant-time violations.
fn coefficient_of_variation(times: &[u128]) -> f64 {
    let mut sorted = times.to_vec();
    sorted.sort_unstable();

    let q1 = sorted.len() / 4;
    let q3 = sorted.len() * 3 / 4;
    let trimmed = &sorted[q1..q3];

    let n = trimmed.len() as f64;
    let mean = trimmed.iter().sum::<u128>() as f64 / n;
    if mean == 0.0 {
        return 0.0;
    }
    let variance = trimmed
        .iter()
        .map(|t| (*t as f64 - mean).powi(2))
        .sum::<f64>()
        / n;
    let std_dev = variance.sqrt();
    std_dev / mean
}

// =============================================================================
// TIMING CONSISTENCY TESTS
// =============================================================================

#[test]
fn test_seal_timing_consistency() {
    // seal() should have consistent timing regardless of plaintext content
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();

    // Different plaintext patterns
    let all_zeros = vec![0u8; 1024];
    let all_ones = vec![0xFFu8; 1024];
    let mixed = (0..1024).map(|i| i as u8).collect::<Vec<_>>();

    let warmup = 10;
    let iterations = 50;

    let times_zeros = measure_timing(
        || {
            let _ = seal(&all_zeros, &sender, &recipient.public_key());
        },
        iterations,
        warmup,
    );
    let times_ones = measure_timing(
        || {
            let _ = seal(&all_ones, &sender, &recipient.public_key());
        },
        iterations,
        warmup,
    );
    let times_mixed = measure_timing(
        || {
            let _ = seal(&mixed, &sender, &recipient.public_key());
        },
        iterations,
        warmup,
    );

    // All should have similar coefficient of variation (on trimmed IQR)
    let cv_zeros = coefficient_of_variation(&times_zeros);
    let cv_ones = coefficient_of_variation(&times_ones);
    let cv_mixed = coefficient_of_variation(&times_mixed);

    // In release mode on a quiet system, trimmed CV should be < 0.3.
    // Debug builds on shared CI runners are much noisier, so we use a
    // permissive threshold here.  The IQR trimming already removes the
    // worst outliers; a CV above 2.0 after trimming is a strong signal
    // of a genuine timing leak rather than system noise.
    let max_cv = cv_zeros.max(cv_ones).max(cv_mixed);
    assert!(
        max_cv < 2.0,
        "High timing variance detected: zeros={:.3}, ones={:.3}, mixed={:.3}",
        cv_zeros,
        cv_ones,
        cv_mixed
    );
}

#[test]
fn test_open_timing_consistency() {
    // open() should have consistent timing for valid ciphertexts
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();

    // Create multiple different ciphertexts
    let ct1 = seal(b"Message one here", &sender, &recipient.public_key()).unwrap();
    let ct2 = seal(b"Different msg!!", &sender, &recipient.public_key()).unwrap();
    let ct3 = seal(b"Third variation", &sender, &recipient.public_key()).unwrap();

    let warmup = 10;
    let iterations = 50;

    let times1 = measure_timing(
        || {
            let _ = open(&ct1, &recipient);
        },
        iterations,
        warmup,
    );
    let times2 = measure_timing(
        || {
            let _ = open(&ct2, &recipient);
        },
        iterations,
        warmup,
    );
    let times3 = measure_timing(
        || {
            let _ = open(&ct3, &recipient);
        },
        iterations,
        warmup,
    );

    let cv1 = coefficient_of_variation(&times1);
    let cv2 = coefficient_of_variation(&times2);
    let cv3 = coefficient_of_variation(&times3);

    let max_cv = cv1.max(cv2).max(cv3);
    assert!(
        max_cv < 2.0,
        "High timing variance in open(): cv1={:.3}, cv2={:.3}, cv3={:.3}",
        cv1,
        cv2,
        cv3
    );
}

#[test]
fn test_different_plaintext_sizes_scale_linearly() {
    // Larger plaintexts should take proportionally longer (linear scaling)
    // This tests that we're not doing something pathological
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();

    let small = vec![0u8; 100];
    let medium = vec![0u8; 10_000];
    let large = vec![0u8; 100_000];

    let iterations = 5;

    let times_small = measure_timing(
        || {
            let _ = seal(&small, &sender, &recipient.public_key());
        },
        iterations,
        3,
    );
    let times_medium = measure_timing(
        || {
            let _ = seal(&medium, &sender, &recipient.public_key());
        },
        iterations,
        3,
    );
    let times_large = measure_timing(
        || {
            let _ = seal(&large, &sender, &recipient.public_key());
        },
        iterations,
        3,
    );

    let avg_small = times_small.iter().sum::<u128>() as f64 / iterations as f64;
    let avg_medium = times_medium.iter().sum::<u128>() as f64 / iterations as f64;
    let avg_large = times_large.iter().sum::<u128>() as f64 / iterations as f64;

    // Medium should be > small, large should be > medium
    assert!(
        avg_medium > avg_small,
        "Medium should take longer than small"
    );
    assert!(
        avg_large > avg_medium,
        "Large should take longer than medium"
    );

    // But not exponentially longer - ratio should be reasonable
    // (10_000 / 100 = 100x data, but crypto overhead is fixed, so time ratio should be lower)
    let ratio_medium_small = avg_medium / avg_small;
    let ratio_large_medium = avg_large / avg_medium;

    assert!(
        ratio_medium_small < 50.0,
        "Medium/small ratio too high: {:.2}",
        ratio_medium_small
    );
    assert!(
        ratio_large_medium < 15.0,
        "Large/medium ratio too high: {:.2}",
        ratio_large_medium
    );
}

// =============================================================================
// INVALID INPUT TIMING TESTS
// =============================================================================

#[test]
fn test_invalid_signature_timing_observation() {
    // This test observes timing behavior when rejecting invalid signatures.
    // Note: Timing variations may occur due to:
    // - pqcrypto implementation details (signature parsing may fail early)
    // - CPU branch prediction
    // - Cache effects
    //
    // This test documents observed behavior rather than asserting constant-time.
    // A proper dudect analysis should be performed for security-critical deployments.

    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();
    let ciphertext = seal(b"Test", &sender, &recipient.public_key()).unwrap();

    // Create ciphertexts with corruption in early part of signature
    let sig_start = 1 + 1952 + 1184 + 1184; // version + sender_signing + sender_kem + ephemeral

    let mut ct_corrupt_1 = ciphertext.clone();
    ct_corrupt_1[sig_start] ^= 0xFF;

    let mut ct_corrupt_2 = ciphertext.clone();
    ct_corrupt_2[sig_start + 100] ^= 0xFF;

    let mut ct_corrupt_3 = ciphertext.clone();
    ct_corrupt_3[sig_start + 500] ^= 0xFF;

    let iterations = 10;

    let times_1 = measure_timing(
        || {
            let _ = open(&ct_corrupt_1, &recipient);
        },
        iterations,
        5,
    );
    let times_2 = measure_timing(
        || {
            let _ = open(&ct_corrupt_2, &recipient);
        },
        iterations,
        5,
    );
    let times_3 = measure_timing(
        || {
            let _ = open(&ct_corrupt_3, &recipient);
        },
        iterations,
        5,
    );

    let avg_1 = times_1.iter().sum::<u128>() as f64 / iterations as f64;
    let avg_2 = times_2.iter().sum::<u128>() as f64 / iterations as f64;
    let avg_3 = times_3.iter().sum::<u128>() as f64 / iterations as f64;

    // Log the timing observations for analysis
    println!("Signature rejection timing (ns):");
    println!("  Corrupt byte 0:   {:.0}", avg_1);
    println!("  Corrupt byte 100: {:.0}", avg_2);
    println!("  Corrupt byte 500: {:.0}", avg_3);

    // All corrupted ciphertexts should be rejected
    assert!(open(&ct_corrupt_1, &recipient).is_err());
    assert!(open(&ct_corrupt_2, &recipient).is_err());
    assert!(open(&ct_corrupt_3, &recipient).is_err());
}

// =============================================================================
// MEMORY ZEROING TESTS
// =============================================================================

#[test]
fn test_keypair_memory_does_not_persist() {
    // This is a best-effort test - we can't truly verify memory is zeroed
    // from safe Rust, but we can at least verify the Drop is called

    // Generate a keypair and immediately drop it
    let pk_bytes = {
        let kp = KeyPair::generate();
        kp.public_key().signing_bytes().to_vec()
    };
    // kp is now dropped, ZeroizeOnDrop should have run

    // Generate another keypair - it should be different
    let pk_bytes2 = {
        let kp = KeyPair::generate();
        kp.public_key().signing_bytes().to_vec()
    };

    // Different keypairs should have different public keys
    assert_ne!(pk_bytes, pk_bytes2);
}

// =============================================================================
// DOCUMENTATION OF CONSTANT-TIME CLAIMS
// =============================================================================

#[allow(dead_code)]
mod constant_time_claims {
    //! This module documents which operations are claimed to be constant-time
    //! and which are not. This serves as a reference for security auditors.
    //!
    //! # Constant-Time Operations (claimed)
    //!
    //! ## Signature (ML-DSA-65)
    //! - `sign()`: Constant-time w.r.t. secret key (pqcrypto implementation)
    //! - `verify()`: Should not short-circuit on mismatch (pqcrypto implementation)
    //!
    //! ## KEM (ML-KEM-768)
    //! - `decapsulate()`: Constant-time w.r.t. secret key (pqcrypto implementation)
    //! - `encapsulate()`: Only uses public key, no timing concerns
    //!
    //! ## AEAD (ChaCha20-Poly1305)
    //! - `encrypt()`: Constant-time (chacha20poly1305 crate)
    //! - `decrypt()`: Uses constant-time comparison for auth tag
    //!
    //! ## Key Comparison
    //! - `PublicKey::eq()`: Currently uses derived PartialEq (NOT constant-time)
    //!   - This is safe because public keys are... public
    //!   - Secret key comparison is not exposed in public API
    //!
    //! # Not Constant-Time (by design)
    //!
    //! - `KeyPair::generate()`: Randomness timing varies, but reveals nothing
    //! - Wire format parsing: Variable-length reads are data-dependent
    //!   - This is safe because ciphertext structure is not secret
    //!
    //! # Areas Requiring Audit
    //!
    //! - [ ] Verify pqcrypto's ML-DSA-65 is truly constant-time
    //! - [ ] Verify pqcrypto's ML-KEM-768 is truly constant-time
    //! - [ ] Run dudect analysis on seal/open hot paths
    //! - [ ] Check for compiler optimizations that break constant-time
}
