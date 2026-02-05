// secure/memory.rs - Secure memory operations

// SecretBytes<N>: array wrapper with automatic zeroing on drop
// lock_memory(ptr, len): prevent swapping to disk
// unlock_memory(ptr, len): release memory lock
// implements: Zeroize trait for all secret types
