// storage/trait.rs - Storage abstraction

// trait Storage: get(id), put(id, data), delete(id), list()
// allows: swapping backends (memory, file, database, HSM)
// ensures: encryption at rest for all backends
