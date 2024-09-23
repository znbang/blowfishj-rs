# blowfishj-rs

blowfishj-rs ports CTS encryption and decryption from blowfishj.

# Install

    cargo add --git https://github.com/znbang/blowfishj-rs.git

# Usage

```rust
use blowfishj_rs::{encrypt, decrypt};

fn main() {
    let password = "Pa$$w0rd";
    let plain_text = "Text to encrypt";
    let encrypted_text = encrypt(password, plain_text).unwrap();
    println!("Encrypted text: {}", encrypted_text);
    let decrypted_text = decrypt(password, &encrypted_text).unwrap();
    println!("Decrypted text: {}", decrypted_text);
}

```