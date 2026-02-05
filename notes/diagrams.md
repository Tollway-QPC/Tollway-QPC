# High-Level Flow Diagrams

## Basic Seal/Open Flow (tollway-core)

``` text
User calls seal(plaintext, my_keypair, their_public_key)
    ↓
seal.rs::seal()
    → primitives/kem.rs::generate_ephemeral_keypair()
    → primitives/signature.rs::sign(ephemeral_pk, my_signing_sk)
    → primitives/kem.rs::encapsulate(their_kem_pk)
    → primitives/kdf.rs::derive_key(shared_secret, "AEAD_KEY")
    → primitives/aead.rs::encrypt(derived_key, plaintext)
    → secure/memory.rs::zero(ephemeral_sk)
    → wire/format.rs::build_ciphertext(components)
    ↓
Returns Ciphertext

User calls open(ciphertext, my_keypair)
    ↓
open.rs::open()
    → wire/format.rs::parse_ciphertext()
    → primitives/signature.rs::verify(ephemeral_pk, signature, sender_pk)
    → primitives/kem.rs::decapsulate(kem_ct, my_kem_sk)
    → primitives/kdf.rs::derive_key(shared_secret, "AEAD_KEY")
    → primitives/aead.rs::decrypt(derived_key, aead_ct)
    ↓
Returns (plaintext, verified_sender_pk)
```

## Identity-Based Flow (tollway-keys using tollway-core)

``` text
User creates KeyManager
    ↓
manager.rs::KeyManager::new(storage_backend, policy)
    → storage/file.rs::initialize_storage()
    → policy.rs::load_default_policy()
    ↓
KeyManager ready

User creates identity "alice"
    ↓
manager.rs::create_identity("alice")
    → tollway_core::KeyPair::generate()
    → metadata.rs::new_metadata(created_at: now)
    → identity.rs::new_identity(id, name, keypair, metadata)
    → storage/encryption.rs::encrypt_key_data(keypair)
    → storage/file.rs::put(id, encrypted_data)
    → audit.rs::emit(KEY_CREATED)
    ↓
Returns Identity

Alice seals to "bob"
    ↓
identity.rs::seal_to("bob", plaintext)
    → manager.rs::get_identity("bob") → bob_identity
    → tollway_core::seal(plaintext, alice_keypair, bob_public_key)
    → metadata.rs::update_usage(alice_id)
    → audit.rs::emit(SEAL_OPERATION)
    ↓
Returns Ciphertext

Bob opens from alice
    ↓
identity.rs::open_from(ciphertext)
    → tollway_core::open(ciphertext, bob_keypair)
    → manager.rs::get_identity_by_pk(sender_pk) → alice_identity
    → metadata.rs::update_usage(bob_id)
    → audit.rs::emit(OPEN_OPERATION)
    ↓
Returns (plaintext, "alice")
```

## Key Rotation Flow

``` text
Background task or manual trigger
    ↓
manager.rs::rotate_expired_keys()
    → manager.rs::list_identities()
    → for each identity:
        → policy.rs::evaluate_policy(identity)
        → if expired or over usage limit:
            → rotation.rs::rotate_identity(identity)
                → tollway_core::KeyPair::generate()
                → metadata.rs::new_metadata(preserves creation history)
                → storage/encryption.rs::encrypt_new_keypair()
                → storage/file.rs::put(id, new_encrypted_data)
                → storage/file.rs::archive_old_key(id, grace_period)
                → audit.rs::emit(KEY_ROTATED)
    ↓
Returns list of rotated identity IDs
```

## Key Backup/Recovery Flow

``` text
User exports identity
    ↓
backup.rs::export_identity(id, passphrase)
    → manager.rs::get_identity(id)
    → primitives/kdf.rs::derive_key(passphrase, "BACKUP_KEY")
    → storage/encryption.rs::encrypt_key_data(keypair, backup_key)
    → wire/serialize.rs::serialize(encrypted_data + metadata)
    ↓
Returns encrypted backup blob

User imports identity
    ↓
backup.rs::import_identity(backup_blob, passphrase)
    → wire/serialize.rs::deserialize(backup_blob)
    → primitives/kdf.rs::derive_key(passphrase, "BACKUP_KEY")
    → storage/encryption.rs::decrypt_key_data(encrypted_data, backup_key)
    → manager.rs::create_identity(restored_name, restored_keypair)
    → audit.rs::emit(KEY_IMPORTED)
    ↓
Returns restored Identity
```

## Ciphertext Wire Format

``` text
┌─────────────────────────────────────────────────────────┐
│ Version (1 byte)                                        │
├─────────────────────────────────────────────────────────┤
│ Sender Signing Public Key (ML-DSA-65, 2592 bytes)      │
├─────────────────────────────────────────────────────────┤
│ Signature over Ephemeral KEM PK (ML-DSA-65, ~3309 B)   │
├─────────────────────────────────────────────────────────┤
│ Ephemeral KEM Public Key (ML-KEM-768, 1184 bytes)      │
├─────────────────────────────────────────────────────────┤
│ KEM Ciphertext (ML-KEM-768, 1088 bytes)                │
├─────────────────────────────────────────────────────────┤
│ AEAD Ciphertext (ChaCha20-Poly1305, plaintext_len + 16)│
└─────────────────────────────────────────────────────────┘

Total overhead: ~9,189 bytes + plaintext length
```

## Module Dependency Graph

``` text
tollway-keys
    ├─→ tollway-core (seal/open operations)
    ├─→ storage backends (trait-based)
    ├─→ audit logging (structured events)
    └─→ policy engine (rotation/expiration)

tollway-core
    ├─→ pqcrypto-kem (ML-KEM-768)
    ├─→ pqcrypto-sign (ML-DSA-65)
    ├─→ chacha20poly1305 (AEAD)
    ├─→ hkdf + sha3 (KDF)
    └─→ zeroize (secure memory)
```
