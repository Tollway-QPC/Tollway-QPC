//! FIPS 140-3 boundary module.
//!
//! This module is only compiled when the `fips` feature is enabled.
//! It provides:
//!
//! - **`state`** -- A thread-safe finite state machine governing the module
//!   lifecycle (`Uninitialized -> SelfTest -> Operational | Error`).
//!
//! Future waves will add:
//! - `approved` -- Approved algorithm registry and service restrictions.
//! - Public API wrappers (`seal`, `open`, `generate_keypair`) that enforce
//!   FSM state checks before dispatching to approved algorithms.

pub mod state;

pub use state::{current_state, enter_error_state, initialize, require_operational, ModuleState};
