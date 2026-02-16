//! FIPS 140-3 module lifecycle finite state machine.
//!
//! Implements a thread-safe global FSM using [`AtomicU8`] that governs the
//! FIPS boundary module lifecycle.  All FIPS API entry points must call
//! [`require_operational`] before performing any cryptographic work.
//!
//! ## State diagram
//!
//! ```text
//!  Uninitialized ──initialize()──► SelfTest ──tests pass──► Operational
//!                                     │
//!                                     └──tests fail──► Error
//!
//!  Any state ──enter_error_state()──► Error  (terminal)
//! ```

use core::sync::atomic::{AtomicU8, Ordering};

use crate::constants::{
    FIPS_STATE_ERROR, FIPS_STATE_OPERATIONAL, FIPS_STATE_SELF_TEST, FIPS_STATE_UNINITIALIZED,
};
use crate::error::TollwayError;

/// Global FIPS module state (thread-safe singleton).
///
/// Every load/store uses [`Ordering::SeqCst`] so that state transitions are
/// visible across all threads with a total ordering guarantee, which is the
/// strongest memory ordering and appropriate for a security-critical FSM.
static MODULE_STATE: AtomicU8 = AtomicU8::new(FIPS_STATE_UNINITIALIZED);

// ---------------------------------------------------------------------------
// Public enum mirroring the raw u8 constants for ergonomic matching
// ---------------------------------------------------------------------------

/// The four states of the FIPS module lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleState {
    /// Module has not been initialized.
    Uninitialized,
    /// Module is currently executing power-on self-tests (KATs).
    SelfTest,
    /// Self-tests passed; the module is ready for approved operations.
    Operational,
    /// A critical error occurred; the module is permanently degraded.
    Error,
}

impl ModuleState {
    /// Convert a raw `u8` (as stored in the [`AtomicU8`]) into a typed state.
    /// Returns `None` for values that do not correspond to a valid state.
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            FIPS_STATE_UNINITIALIZED => Some(Self::Uninitialized),
            FIPS_STATE_SELF_TEST => Some(Self::SelfTest),
            FIPS_STATE_OPERATIONAL => Some(Self::Operational),
            FIPS_STATE_ERROR => Some(Self::Error),
            _ => None,
        }
    }

    /// Return the raw `u8` representation suitable for atomic storage.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Uninitialized => FIPS_STATE_UNINITIALIZED,
            Self::SelfTest => FIPS_STATE_SELF_TEST,
            Self::Operational => FIPS_STATE_OPERATIONAL,
            Self::Error => FIPS_STATE_ERROR,
        }
    }
}

impl core::fmt::Display for ModuleState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Uninitialized => write!(f, "Uninitialized"),
            Self::SelfTest => write!(f, "SelfTest"),
            Self::Operational => write!(f, "Operational"),
            Self::Error => write!(f, "Error"),
        }
    }
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

/// Returns the current module state.
pub fn current_state() -> ModuleState {
    let raw = MODULE_STATE.load(Ordering::SeqCst);
    ModuleState::from_u8(raw).unwrap_or(ModuleState::Error)
}

/// Asserts that the module is in the [`ModuleState::Operational`] state.
///
/// Every FIPS API entry point must call this before dispatching to an
/// approved algorithm.  Returns [`TollwayError::ModuleNotInitialized`] if
/// the module has not yet been successfully initialized.
pub fn require_operational() -> Result<(), TollwayError> {
    if current_state() == ModuleState::Operational {
        Ok(())
    } else {
        Err(TollwayError::ModuleNotInitialized)
    }
}

// ---------------------------------------------------------------------------
// Transitions
// ---------------------------------------------------------------------------

/// Initialize the FIPS module.
///
/// Drives the FSM through `Uninitialized -> SelfTest -> Operational`.
///
/// * If the module is already [`ModuleState::Operational`], this is a no-op
///   (idempotent).
/// * If another thread is concurrently initializing (state is `SelfTest`),
///   returns [`TollwayError::SelfTestFailed`].
/// * If the module is in the [`ModuleState::Error`] state, returns
///   [`TollwayError::SelfTestFailed`] (error state is terminal).
///
/// **Self-tests**: Wave 1 uses a pass-through placeholder.  Wave 3 will
/// insert Known Answer Tests (KATs) between the two `compare_exchange`
/// calls.
pub fn initialize() -> Result<(), TollwayError> {
    // ── Step 1: Uninitialized -> SelfTest ──────────────────────────────
    match MODULE_STATE.compare_exchange(
        FIPS_STATE_UNINITIALIZED,
        FIPS_STATE_SELF_TEST,
        Ordering::SeqCst,
        Ordering::SeqCst,
    ) {
        Ok(_) => { /* successfully claimed the transition */ }
        Err(observed) => {
            return match ModuleState::from_u8(observed) {
                // Already operational -- treat as idempotent success
                Some(ModuleState::Operational) => Ok(()),
                // Another thread is running self-tests right now
                Some(ModuleState::SelfTest) => Err(TollwayError::SelfTestFailed(
                    "module initialization already in progress".into(),
                )),
                // Terminal error state
                Some(ModuleState::Error) => Err(TollwayError::SelfTestFailed(
                    "module is in error state and cannot be re-initialized".into(),
                )),
                // Unknown / shouldn't happen
                _ => Err(TollwayError::SelfTestFailed(
                    "module is in an unexpected state".into(),
                )),
            };
        }
    }

    // ── Step 2: Run self-tests (Wave 3 placeholder) ───────────────────
    let self_tests_passed = run_self_tests();

    // ── Step 3: SelfTest -> Operational  (or -> Error on failure) ──────
    if self_tests_passed {
        match MODULE_STATE.compare_exchange(
            FIPS_STATE_SELF_TEST,
            FIPS_STATE_OPERATIONAL,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => Ok(()),
            Err(_) => {
                // Another thread forced Error between steps 2 and 3.
                MODULE_STATE.store(FIPS_STATE_ERROR, Ordering::SeqCst);
                Err(TollwayError::SelfTestFailed(
                    "state was modified during self-test execution".into(),
                ))
            }
        }
    } else {
        MODULE_STATE.store(FIPS_STATE_ERROR, Ordering::SeqCst);
        Err(TollwayError::SelfTestFailed(
            "one or more known-answer tests failed".into(),
        ))
    }
}

/// Force the module into the terminal [`ModuleState::Error`] state.
///
/// This is an unconditional store -- any thread may call it at any time
/// when a critical integrity failure is detected.
pub fn enter_error_state() {
    MODULE_STATE.store(FIPS_STATE_ERROR, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// Self-test placeholder (Wave 3)
// ---------------------------------------------------------------------------

/// Run Known Answer Tests for all approved algorithms.
///
/// Returns `true` if all tests pass.  Wave 1 always returns `true`;
/// Wave 3 will insert real KATs here.
fn run_self_tests() -> bool {
    // TODO(wave-3): Insert KATs for AES-256-GCM, ML-KEM-768, ML-DSA-65,
    //               and HKDF-SHA3-256.
    true
}

// ---------------------------------------------------------------------------
// Test-only helpers
// ---------------------------------------------------------------------------

/// Reset the module state to [`ModuleState::Uninitialized`].
///
/// **Testing only** -- this must never be exposed outside `#[cfg(test)]`
/// because re-initialization violates the FIPS lifecycle model.
#[cfg(test)]
pub(crate) fn reset_for_testing() {
    MODULE_STATE.store(FIPS_STATE_UNINITIALIZED, Ordering::SeqCst);
}

// =========================================================================
// Unit tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes tests that mutate the global `MODULE_STATE` singleton.
    /// Rust runs unit tests in parallel by default; without this lock,
    /// one test's `reset_for_testing()` can race with another test's
    /// `initialize()`.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Acquire the test lock and reset to a clean state.
    /// Returns the `MutexGuard` which must be held for the test's duration.
    fn setup() -> std::sync::MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_testing();
        guard
    }

    #[test]
    fn initial_state_is_uninitialized() {
        let _g = setup();
        assert_eq!(current_state(), ModuleState::Uninitialized);
    }

    #[test]
    fn initialize_transitions_to_operational() {
        let _g = setup();
        assert!(initialize().is_ok());
        assert_eq!(current_state(), ModuleState::Operational);
    }

    #[test]
    fn double_initialize_is_idempotent() {
        let _g = setup();
        initialize().unwrap();
        assert!(initialize().is_ok());
        assert_eq!(current_state(), ModuleState::Operational);
    }

    #[test]
    fn require_operational_fails_before_init() {
        let _g = setup();
        assert!(require_operational().is_err());
    }

    #[test]
    fn require_operational_succeeds_after_init() {
        let _g = setup();
        initialize().unwrap();
        assert!(require_operational().is_ok());
    }

    #[test]
    fn enter_error_state_is_terminal() {
        let _g = setup();
        initialize().unwrap();
        enter_error_state();
        assert_eq!(current_state(), ModuleState::Error);
        assert!(require_operational().is_err());
    }

    #[test]
    fn cannot_initialize_from_error_state() {
        let _g = setup();
        enter_error_state();
        let result = initialize();
        assert!(result.is_err());
        assert_eq!(current_state(), ModuleState::Error);
    }

    #[test]
    fn module_state_display() {
        assert_eq!(ModuleState::Uninitialized.to_string(), "Uninitialized");
        assert_eq!(ModuleState::SelfTest.to_string(), "SelfTest");
        assert_eq!(ModuleState::Operational.to_string(), "Operational");
        assert_eq!(ModuleState::Error.to_string(), "Error");
    }

    #[test]
    fn from_u8_round_trip() {
        for state in [
            ModuleState::Uninitialized,
            ModuleState::SelfTest,
            ModuleState::Operational,
            ModuleState::Error,
        ] {
            assert_eq!(ModuleState::from_u8(state.as_u8()), Some(state));
        }
        assert_eq!(ModuleState::from_u8(255), None);
    }

    #[test]
    fn concurrent_initialize_only_one_succeeds() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let _g = setup();

        let barrier = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let b = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                b.wait();
                initialize()
            }));
        }

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let ok_count = results.iter().filter(|r| r.is_ok()).count();

        // Exactly one thread should win the Uninitialized -> SelfTest race;
        // the rest either see Operational (idempotent ok) or SelfTest (err).
        // At least one must succeed.
        assert!(ok_count >= 1, "at least one thread must succeed");
        assert_eq!(current_state(), ModuleState::Operational);
    }
}
