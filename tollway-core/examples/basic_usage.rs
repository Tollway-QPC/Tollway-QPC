//! Basic usage example for tollway-core

use tollway_core::{open, seal, KeyPair};

fn main() {
    // Generate keypairs for sender and recipient
    let sender_keypair = KeyPair::generate();
    let recipient_keypair = KeyPair::generate();

    // Message to encrypt
    let plaintext = b"Hello, post-quantum world!";

    // Seal (encrypt + sign) the message
    let ciphertext =
        seal(plaintext, &sender_keypair, &recipient_keypair.public_key()).expect("Seal failed");

    println!("Plaintext: {:?}", String::from_utf8_lossy(plaintext));
    println!("Ciphertext length: {} bytes", ciphertext.len());

    // Open (decrypt + verify) the message
    let (decrypted, _sender_pk) = open(&ciphertext, &recipient_keypair).expect("Open failed");

    println!("Decrypted: {:?}", String::from_utf8_lossy(&decrypted));

    // Note: The returned sender_pk only contains the signing public key from the wire format.
    // The KEM public key field is empty in V1 format (would be obtained from a directory).
    // Signature verification happens inside open() - if it fails, open() returns an error.
    println!("Sender signature verified: true (open() succeeded)");

    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    println!("Success: Message round-tripped correctly!");
}
