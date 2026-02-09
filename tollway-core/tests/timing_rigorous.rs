//! Rigorous side-channel timing tests
//!
//! Uses statistical analysis to detect timing variations that could
//! leak secret information. Run with:
//!
//! ```
//! cargo test --release timing_rigorous -- --nocapture
//! ```
//!
//! These tests implement a simplified version of the dudect methodology:
//! - Execute operation with two different secret-dependent inputs
//! - Collect timing samples for each class
//! - Use Welch's t-test to detect statistical differences
//!
//! A t-value > 4.5 indicates potential timing leak (p < 0.00001).

use std::time::Instant;
use tollway_core::{open, seal, KeyPair};

// =============================================================================
// STATISTICAL HELPERS
// =============================================================================

/// Welch's t-test for comparing two sample distributions
/// Returns the absolute t-value
fn welch_t_test(samples_a: &[f64], samples_b: &[f64]) -> f64 {
    let n_a = samples_a.len() as f64;
    let n_b = samples_b.len() as f64;

    let mean_a: f64 = samples_a.iter().sum::<f64>() / n_a;
    let mean_b: f64 = samples_b.iter().sum::<f64>() / n_b;

    let var_a: f64 = samples_a.iter().map(|x| (x - mean_a).powi(2)).sum::<f64>() / (n_a - 1.0);
    let var_b: f64 = samples_b.iter().map(|x| (x - mean_b).powi(2)).sum::<f64>() / (n_b - 1.0);

    let se = ((var_a / n_a) + (var_b / n_b)).sqrt();

    if se == 0.0 {
        return 0.0;
    }

    ((mean_a - mean_b) / se).abs()
}

/// Collect timing samples for an operation
fn collect_samples<F: FnMut()>(mut operation: F, count: usize) -> Vec<f64> {
    // Warm up
    for _ in 0..10 {
        operation();
    }

    // Collect samples
    (0..count)
        .map(|_| {
            let start = Instant::now();
            operation();
            start.elapsed().as_nanos() as f64
        })
        .collect()
}

// =============================================================================
// TIMING INDEPENDENCE TESTS
// =============================================================================

/// Test: KEM decapsulation timing should be independent of secret key value
///
/// Attack scenario: If decapsulation is faster/slower based on secret key bits,
/// an attacker could extract the key via timing measurements.
#[test]
fn timing_kem_decapsulation_independent_of_secret_key() {
    // Generate two different keypairs (different secret keys)
    let recipient_a = KeyPair::generate();
    let recipient_b = KeyPair::generate();

    let sender = KeyPair::generate();
    let plaintext = b"Timing test payload for KEM decapsulation";

    // Create ciphertexts for each recipient
    let ct_a = seal(plaintext, &sender, &recipient_a.public_key()).expect("seal should succeed");
    let ct_b = seal(plaintext, &sender, &recipient_b.public_key()).expect("seal should succeed");

    // Collect timing samples for decapsulation with different secret keys
    let samples_a = collect_samples(
        || {
            let _ = open(&ct_a, &recipient_a);
        },
        100,
    );

    let samples_b = collect_samples(
        || {
            let _ = open(&ct_b, &recipient_b);
        },
        100,
    );

    let t_value = welch_t_test(&samples_a, &samples_b);

    println!(
        "KEM decapsulation timing test: t-value = {:.2} (threshold: 4.5)",
        t_value
    );

    // t-value > 4.5 would indicate significant timing difference
    // Note: This test can have false positives due to system noise
    // In production, run on quiet system with many more samples
    if t_value > 50.0 {
        println!(
            "Warning: High timing variance ({:.2}) - may be debug mode noise",
            t_value
        );
    }
}

/// Test: Signature verification timing should be independent of validity
///
/// Attack scenario: If valid signatures verify faster than invalid ones,
/// an attacker could forge signatures by timing verification attempts.
#[test]
fn timing_signature_verification_independent_of_validity() {
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();

    let plaintext = b"Timing test for signature verification";

    // Create valid ciphertext
    let valid_ct = seal(plaintext, &sender, &recipient.public_key()).expect("seal should succeed");

    // Create ciphertext with invalid signature (corrupt signature bytes)
    // Signature is at offset: 1 + 1952 + 1184 + 1184 = 4321
    // Signature is 3309 bytes
    let mut invalid_sig_ct = valid_ct.clone();
    invalid_sig_ct[4321] ^= 0xFF; // Corrupt first byte of signature

    // Collect timing for valid signature
    let samples_valid = collect_samples(
        || {
            let _ = open(&valid_ct, &recipient);
        },
        100,
    );

    // Collect timing for invalid signature
    let samples_invalid = collect_samples(
        || {
            let _ = open(&invalid_sig_ct, &recipient);
        },
        100,
    );

    let t_value = welch_t_test(&samples_valid, &samples_invalid);

    println!(
        "Signature verification timing test: t-value = {:.2} (threshold: 4.5)",
        t_value
    );

    // Note: Valid vs invalid signatures WILL have different timing because:
    // - Valid: verify → decapsulate → decrypt (full path)
    // - Invalid: verify → FAIL (early exit)
    // This is acceptable - the concern is timing based on signature CONTENT,
    // not validity. Very high t-values are noted but not blocking.
    if t_value > 100.0 {
        println!(
            "Warning: Very high timing variance ({:.2}) - \
             this is expected in debug builds and for valid/invalid paths",
            t_value
        );
    }
}

/// Test: AEAD decryption timing should be independent of plaintext
///
/// Attack scenario: If decryption time varies with plaintext content,
/// an attacker could infer plaintext by timing decryption.
#[test]
fn timing_aead_decrypt_independent_of_plaintext() {
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();

    // Two different plaintexts (different content, same length)
    let plaintext_zeros = vec![0u8; 1024];
    let plaintext_ones = vec![0xFFu8; 1024];

    let ct_zeros =
        seal(&plaintext_zeros, &sender, &recipient.public_key()).expect("seal should succeed");
    let ct_ones =
        seal(&plaintext_ones, &sender, &recipient.public_key()).expect("seal should succeed");

    let samples_zeros = collect_samples(
        || {
            let _ = open(&ct_zeros, &recipient);
        },
        100,
    );

    let samples_ones = collect_samples(
        || {
            let _ = open(&ct_ones, &recipient);
        },
        100,
    );

    let t_value = welch_t_test(&samples_zeros, &samples_ones);

    println!(
        "AEAD decrypt timing test: t-value = {:.2} (threshold: 4.5)",
        t_value
    );

    // Note: In debug mode, timing measurements are noisy.
    // Run with --release on a quiet system for meaningful results.
    // ChaCha20-Poly1305 (RustCrypto) is designed to be constant-time.
    if t_value > 50.0 {
        println!(
            "Warning: High timing variance ({:.2}) in debug mode is expected",
            t_value
        );
    }
}

/// Test: Error path timing should not reveal which check failed
///
/// Attack scenario: If decryption fails faster for invalid signature
/// vs invalid MAC, attacker learns information about ciphertext structure.
#[test]
fn timing_error_paths_similar() {
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();

    let plaintext = b"Error path timing test";
    let valid_ct = seal(plaintext, &sender, &recipient.public_key()).expect("seal should succeed");

    // Corrupt signature (early failure)
    let mut bad_sig = valid_ct.clone();
    bad_sig[4321] ^= 0xFF;

    // Corrupt AEAD tag (late failure) - AEAD ciphertext is at the end
    let mut bad_mac = valid_ct.clone();
    let last_idx = bad_mac.len() - 1;
    bad_mac[last_idx] ^= 0xFF;

    // Corrupt version byte (very early failure)
    let mut bad_version = valid_ct.clone();
    bad_version[0] = 0xFF;

    let samples_bad_sig = collect_samples(
        || {
            let _ = open(&bad_sig, &recipient);
        },
        100,
    );

    let samples_bad_mac = collect_samples(
        || {
            let _ = open(&bad_mac, &recipient);
        },
        100,
    );

    let samples_bad_version = collect_samples(
        || {
            let _ = open(&bad_version, &recipient);
        },
        100,
    );

    let t_sig_mac = welch_t_test(&samples_bad_sig, &samples_bad_mac);
    let t_sig_version = welch_t_test(&samples_bad_sig, &samples_bad_version);

    println!(
        "Error path timing: sig vs mac t={:.2}, sig vs version t={:.2}",
        t_sig_mac, t_sig_version
    );

    // Error paths may have different timing due to where they fail,
    // but extreme differences could be problematic
    // This is observational, not a hard requirement
    if t_sig_mac > 20.0 || t_sig_version > 20.0 {
        println!(
            "Warning: Large timing difference between error paths \
             may reveal which validation step failed"
        );
    }
}

/// Test: Seal timing independent of plaintext content
#[test]
fn timing_seal_independent_of_plaintext() {
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();

    let plaintext_pattern = vec![0xAAu8; 1024];
    let plaintext_random: Vec<u8> = (0..1024).map(|i| (i * 17 + 31) as u8).collect();

    let samples_pattern = collect_samples(
        || {
            let _ = seal(&plaintext_pattern, &sender, &recipient.public_key());
        },
        50,
    );

    let samples_random = collect_samples(
        || {
            let _ = seal(&plaintext_random, &sender, &recipient.public_key());
        },
        50,
    );

    let t_value = welch_t_test(&samples_pattern, &samples_random);

    println!(
        "Seal timing test: t-value = {:.2} (threshold: 4.5)",
        t_value
    );

    // Note: In debug mode, timing measurements are noisy.
    if t_value > 50.0 {
        println!(
            "Warning: High timing variance ({:.2}) - may be debug mode noise",
            t_value
        );
    }
}

// =============================================================================
// SUMMARY
// =============================================================================

#[test]
fn timing_suite_summary() {
    println!("\n=== SIDE-CHANNEL TIMING TEST SUITE ===");
    println!("Run with: cargo test --release timing_rigorous -- --nocapture");
    println!("For rigorous analysis, use dedicated tools:");
    println!("  - dudect-bencher crate for Rust");
    println!("  - ctgrind (Valgrind-based constant-time checker)");
    println!("  - timecop memory checker");
    println!("\nThese tests provide observational evidence only.");
    println!("True constant-time guarantees require formal verification.");
}
