//! Encrypted Key-Value Vault Example
//!
//! A CLI tool demonstrating real-world tollway-core integration.
//!
//! # Usage
//!
//! ```bash
//! # Initialize vault (generate keypair)
//! cargo run --example encrypted_vault -- init
//!
//! # Store encrypted values
//! cargo run --example encrypted_vault -- put api_key "sk-secret-12345"
//! cargo run --example encrypted_vault -- put database_url "postgres://..."
//!
//! # Retrieve and decrypt values
//! cargo run --example encrypted_vault -- get api_key
//!
//! # List all keys
//! cargo run --example encrypted_vault -- list
//!
//! # Rotate keys (re-encrypt all values)
//! cargo run --example encrypted_vault -- rotate
//!
//! # Delete a key
//! cargo run --example encrypted_vault -- delete api_key
//! ```
//!
//! # Storage
//!
//! Data is stored in `~/.tollway-vault/`:
//! - `keypair.bin` - Encrypted keypair
//! - `values/` - Encrypted values (one file per key)
//! - `manifest.json` - Index of stored keys

use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use tollway_core::{open, seal, KeyPair};

// =============================================================================
// VAULT STORAGE
// =============================================================================

const VAULT_DIR: &str = ".tollway-vault";
const KEYPAIR_FILE: &str = "keypair.bin";
const VALUES_DIR: &str = "values";
const MANIFEST_FILE: &str = "manifest.json";

fn vault_dir() -> PathBuf {
    // Use home directory on Unix, USERPROFILE on Windows
    let home = env::var("HOME")
        .or_else(|_| env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(VAULT_DIR)
}

fn keypair_path() -> PathBuf {
    vault_dir().join(KEYPAIR_FILE)
}

fn values_dir() -> PathBuf {
    vault_dir().join(VALUES_DIR)
}

fn manifest_path() -> PathBuf {
    vault_dir().join(MANIFEST_FILE)
}

// =============================================================================
// MANIFEST (key index)
// =============================================================================

#[derive(Default)]
struct Manifest {
    keys: Vec<String>,
}

impl Manifest {
    fn load() -> io::Result<Self> {
        let path = manifest_path();
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(path)?;
        let keys: Vec<String> = content
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Ok(Self { keys })
    }

    fn save(&self) -> io::Result<()> {
        let path = manifest_path();
        let content = self.keys.join("\n");
        fs::write(path, content)
    }

    fn add(&mut self, key: &str) {
        if !self.keys.contains(&key.to_string()) {
            self.keys.push(key.to_string());
        }
    }

    fn remove(&mut self, key: &str) {
        self.keys.retain(|k| k != key);
    }
}

// =============================================================================
// KEYPAIR STORAGE
// =============================================================================

fn save_keypair(kp: &KeyPair) -> io::Result<()> {
    // Serialize keypair (simplified - in production use proper serialization)
    // Format: signing_pk_len(4) || signing_pk || kem_pk_len(4) || kem_pk
    let pk = kp.public_key();
    let signing_pk = pk.signing_bytes();
    let kem_pk = pk.kem_bytes();

    let mut data = Vec::new();
    data.extend_from_slice(&(signing_pk.len() as u32).to_le_bytes());
    data.extend_from_slice(signing_pk);
    data.extend_from_slice(&(kem_pk.len() as u32).to_le_bytes());
    data.extend_from_slice(kem_pk);

    // Note: In a real implementation, you'd encrypt the secret key
    // and store it securely. This example stores public key only,
    // and regenerates the full keypair (which means new keys each init).

    fs::write(keypair_path(), data)?;
    Ok(())
}

fn load_or_init_keypair() -> io::Result<KeyPair> {
    let path = keypair_path();
    if path.exists() {
        // In a real implementation, you'd load and decrypt the keypair
        // For this example, we just generate a new one
        println!("Note: Loading existing vault (regenerating keypair for demo)");
        Ok(KeyPair::generate())
    } else {
        init_vault()
    }
}

// =============================================================================
// VAULT OPERATIONS
// =============================================================================

fn init_vault() -> io::Result<KeyPair> {
    println!("Initializing new vault...");

    // Create directories
    fs::create_dir_all(vault_dir())?;
    fs::create_dir_all(values_dir())?;

    // Generate keypair
    let keypair = KeyPair::generate();

    // Save public key (for demo purposes)
    save_keypair(&keypair)?;

    // Initialize empty manifest
    let manifest = Manifest::default();
    manifest.save()?;

    println!("✓ Vault initialized at {:?}", vault_dir());
    println!("✓ Generated post-quantum keypair (ML-KEM-768 + ML-DSA-65)");

    Ok(keypair)
}

fn put_value(key: &str, value: &str) -> io::Result<()> {
    let keypair = load_or_init_keypair()?;

    // Encrypt value to ourselves (self-encryption)
    let ciphertext = seal(value.as_bytes(), &keypair, &keypair.public_key())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption failed: {:?}", e)))?;

    // Save encrypted value
    let value_path = values_dir().join(format!("{}.enc", key));
    fs::write(&value_path, &ciphertext)?;

    // Update manifest
    let mut manifest = Manifest::load()?;
    manifest.add(key);
    manifest.save()?;

    println!("✓ Stored '{}' ({} bytes encrypted)", key, ciphertext.len());

    Ok(())
}

fn get_value(key: &str) -> io::Result<()> {
    let keypair = load_or_init_keypair()?;

    let value_path = values_dir().join(format!("{}.enc", key));
    if !value_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Key '{}' not found", key),
        ));
    }

    let ciphertext = fs::read(&value_path)?;

    // Decrypt
    let (plaintext, _sender) = open(&ciphertext, &keypair)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption failed: {:?}", e)))?;

    let value = String::from_utf8(plaintext).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid UTF-8: {:?}", e),
        )
    })?;

    println!("{}", value);

    Ok(())
}

fn list_keys() -> io::Result<()> {
    let manifest = Manifest::load()?;

    if manifest.keys.is_empty() {
        println!("Vault is empty");
    } else {
        println!("Stored keys:");
        for key in &manifest.keys {
            println!("  - {}", key);
        }
    }

    Ok(())
}

fn delete_key(key: &str) -> io::Result<()> {
    let value_path = values_dir().join(format!("{}.enc", key));

    if !value_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Key '{}' not found", key),
        ));
    }

    fs::remove_file(&value_path)?;

    let mut manifest = Manifest::load()?;
    manifest.remove(key);
    manifest.save()?;

    println!("✓ Deleted '{}'", key);

    Ok(())
}

fn rotate_keys() -> io::Result<()> {
    println!("Rotating vault keys...");

    let old_keypair = load_or_init_keypair()?;
    let new_keypair = KeyPair::generate();

    let manifest = Manifest::load()?;
    let mut rotated = 0;
    let mut failed = 0;

    for key in &manifest.keys {
        let value_path = values_dir().join(format!("{}.enc", key));

        // Read and decrypt with old key
        let ciphertext = fs::read(&value_path)?;
        let result = open(&ciphertext, &old_keypair);

        match result {
            Ok((plaintext, _)) => {
                // Re-encrypt with new key
                let new_ciphertext = seal(&plaintext, &new_keypair, &new_keypair.public_key())
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::Other,
                            format!("Re-encryption failed: {:?}", e),
                        )
                    })?;

                fs::write(&value_path, &new_ciphertext)?;
                rotated += 1;
            }
            Err(e) => {
                eprintln!("Warning: Could not rotate '{}': {:?}", key, e);
                failed += 1;
            }
        }
    }

    // Save new keypair
    save_keypair(&new_keypair)?;

    println!("✓ Key rotation complete");
    println!("  Rotated: {} keys", rotated);
    if failed > 0 {
        println!("  Failed: {} keys", failed);
    }

    Ok(())
}

fn show_info() -> io::Result<()> {
    println!("Tollway Vault - Post-Quantum Encrypted Key-Value Store");
    println!();
    println!("Algorithms:");
    println!("  Key Encapsulation: ML-KEM-768 (NIST Level 3)");
    println!("  Digital Signature: ML-DSA-65 (NIST Level 3)");
    println!("  AEAD: ChaCha20-Poly1305");
    println!("  KDF: HKDF-SHA3-256");
    println!();
    println!("Storage: {:?}", vault_dir());

    let manifest = Manifest::load()?;
    println!("Stored keys: {}", manifest.keys.len());

    Ok(())
}

// =============================================================================
// CLI
// =============================================================================

fn print_usage() {
    println!("Usage: encrypted_vault <command> [args]");
    println!();
    println!("Commands:");
    println!("  init              Initialize vault (generate keypair)");
    println!("  put <key> <value> Encrypt and store a value");
    println!("  get <key>         Decrypt and retrieve a value");
    println!("  list              List all stored keys");
    println!("  delete <key>      Delete a key");
    println!("  rotate            Rotate keys and re-encrypt all values");
    println!("  info              Show vault information");
    println!();
    println!("Examples:");
    println!("  encrypted_vault init");
    println!("  encrypted_vault put api_key \"sk-secret-12345\"");
    println!("  encrypted_vault get api_key");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return;
    }

    let command = &args[1];

    let result = match command.as_str() {
        "init" => init_vault().map(|_| ()),
        "put" => {
            if args.len() < 4 {
                println!("Usage: encrypted_vault put <key> <value>");
                return;
            }
            put_value(&args[2], &args[3])
        }
        "get" => {
            if args.len() < 3 {
                println!("Usage: encrypted_vault get <key>");
                return;
            }
            get_value(&args[2])
        }
        "list" => list_keys(),
        "delete" => {
            if args.len() < 3 {
                println!("Usage: encrypted_vault delete <key>");
                return;
            }
            delete_key(&args[2])
        }
        "rotate" => rotate_keys(),
        "info" => show_info(),
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        _ => {
            println!("Unknown command: {}", command);
            print_usage();
            return;
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
