//! Constant-time operations for side-channel resistance.
//!
//! This module wraps the [`subtle`] crate to provide constant-time
//! comparison and conditional selection on byte slices. These
//! primitives are essential for avoiding timing oracles when
//! verifying MACs, ciphertexts, or other secret-dependent data.
//!
//! **Caveat:** The *lengths* of the slices are **not** hidden --
//! only the *contents* are compared / selected in constant time.
//! In this protocol the lengths are public (fixed by the wire
//! format), so this is acceptable.

pub use subtle::Choice;

use subtle::{ConditionallySelectable, ConstantTimeEq};

/// Compares two byte slices in constant time.
///
/// Returns `true` if `a` and `b` are equal, `false` otherwise.
/// If the slices differ in length the function returns `false`
/// immediately (the length check itself is **not** constant-time,
/// but lengths are not secret in this protocol).
#[inline]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Constant-time conditional select between two equal-length byte slices.
///
/// If `condition` is `true`, returns a copy of `a`; otherwise returns
/// a copy of `b`. The select is performed byte-by-byte using
/// [`subtle::ConditionallySelectable`], so the branch is invisible
/// to a timing observer.
///
/// # Panics
///
/// Panics if `a.len() != b.len()`.
#[inline]
pub fn ct_select(condition: bool, a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(
        a.len(),
        b.len(),
        "ct_select: slices must be the same length"
    );

    let choice = if condition {
        Choice::from(1u8)
    } else {
        Choice::from(0u8)
    };

    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| u8::conditional_select(&y, &x, choice))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_equal_slices() {
        let a = b"hello world";
        let b = b"hello world";
        assert!(ct_eq(a, b));
    }

    #[test]
    fn ct_eq_different_slices() {
        let a = b"hello world";
        let b = b"hello worlD";
        assert!(!ct_eq(a, b));
    }

    #[test]
    fn ct_eq_different_lengths() {
        let a = b"short";
        let b = b"longer";
        assert!(!ct_eq(a, b));
    }

    #[test]
    fn ct_eq_empty_slices() {
        let a: &[u8] = b"";
        let b: &[u8] = b"";
        assert!(ct_eq(a, b));
    }

    #[test]
    fn ct_select_true_returns_a() {
        let a = b"alpha";
        let b = b"bravo";
        let result = ct_select(true, a, b);
        assert_eq!(result, b"alpha");
    }

    #[test]
    fn ct_select_false_returns_b() {
        let a = b"alpha";
        let b = b"bravo";
        let result = ct_select(false, a, b);
        assert_eq!(result, b"bravo");
    }

    #[test]
    #[should_panic(expected = "ct_select: slices must be the same length")]
    fn ct_select_panics_on_length_mismatch() {
        ct_select(true, b"short", b"longer");
    }
}
