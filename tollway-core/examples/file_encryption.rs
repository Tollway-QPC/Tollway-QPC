//! File encryption example for tollway-core

use tollway_core::{open, seal, KeyPair};

fn main() {
    // Generate keypairs
    let sender_keypair = KeyPair::generate();
    let recipient_keypair = KeyPair::generate();

    // Read file to encrypt (or use sample data)
    let plaintext = b"This is the content of a file that we want to encrypt securely.";

    println!("Original file size: {} bytes", plaintext.len());

    // Encrypt the file
    let ciphertext = seal(plaintext, &sender_keypair, &recipient_keypair.public_key())
        .expect("Failed to encrypt file");

    println!("Encrypted size: {} bytes", ciphertext.len());
    println!("Overhead: {} bytes", ciphertext.len() - plaintext.len());

    // Decrypt the file
    let (decrypted, _sender_pk) =
        open(&ciphertext, &recipient_keypair).expect("Failed to decrypt file");

    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    println!("File decrypted and verified successfully!");
}
