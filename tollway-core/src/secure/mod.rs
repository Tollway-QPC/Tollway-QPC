//! Secure memory handling and constant-time operations

/// This module provides utilities for secure memory handling and constant-time operations to prevent side-channel attacks. It includes functions for securely zeroing memory, comparing byte slices in constant time, and other related operations.
pub mod constant_time;
/// Functions for securely handling sensitive data in memory, such as zeroing out buffers after use to prevent data leakage.
pub mod memory;
