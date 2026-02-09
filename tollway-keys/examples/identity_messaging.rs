pub fn main() {
    use tollway_core::{open, seal, KeyPair};

    // Generate keypairs for Alice and Bob
    let alice_keypair = KeyPair::generate();
    let bob_keypair = KeyPair::generate();

    // Alice wants to send a message to Bob
    let plaintext = b"Hello Bob, this is Alice!";
    let ciphertext =
        seal(plaintext, &alice_keypair, &bob_keypair.public_key()).expect("Encryption failed");

    // Bob receives the message and tries to open it
    match open(&ciphertext, &bob_keypair) {
        Ok((decrypted_plaintext, sender_public_key)) => {
            println!(
                "Bob successfully decrypted the message: {}",
                String::from_utf8_lossy(&decrypted_plaintext)
            );
            println!("Sender's public key: {:?}", sender_public_key);
        }
        Err(e) => {
            println!("Bob failed to decrypt the message: {:?}", e);
        }
    }
}
