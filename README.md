# tech_shield 
### wrapper for USB-dongle-devices (yubikeys/nitrokeys)
 
## Overview:

This GitHub project is maintained by TechShield and serves as a wrapper for the proposed crypto abstraction layer, facilitating access to a specific hardware security module (HSM) on attached USB-dongles (Yubikey). These dongles support secure key storage.

## Objective:

Our goal is to provice a user-friendly and secure way to access the functionality of the HSM without needing to worry about complex implementation details. The wrapper aims to simplify the use of the HSM for developers and provice a reliable abstraction layer.

## Features:

- Enables access to the HSM through a user-friendly abstraction layer.
- Supports secure storage and retrieval of keys.
- Provides functions for data encryption and decryption.
- Implements security mechanisms to ensure the confidentiality and integrity of data.

## Installation:

**In order for our solution to work, it is required that OpenSSL has been installed successfully.**

### Windows
[Download OpenSSL for Windows](https://www.heise.de/download/product/win32-openssl-47316/download/danke?id=eb9acc71-f52c-4329-a3cf-cf9bd9172d8c)

Make sure to set the environment variables correctly, e.g.: 

```sh
setx OPENSSL_DIR "C:\Program Files\OpenSSL-Win64"
setx OPENSSL_INCLUDE_DIR "C:\Program Files\OpenSSL-Win64\include"
setx OPENSSL_LIB_DIR "C:\Program Files\OpenSSL-Win64\lib"
```

### Linux

```
sudo apt-get install libssl-dev
```

## Usage:

Dependencies

To use the cryptographic functionalities, ensure you have the following dependencies in your Cargo.toml:

This module provides cryptographic operations for asymmetric keys on a YubiKey, including signing, encryption, decryption, and signature verification. Below are the usage examples for each provided method.

## Initialization

First, ensure you have a `YubiKeyProvider` instance initialized. This example assumes that you have a YubiKey device connected and appropriate libraries installed.

```rust
let yubi_key_provider = YubiKeyProvider {
    yubikey: Some(Arc::new(Mutex::new(Yubikey::new()))),
    key_algo: Some(AsymmetricEncryption::Rsa(KeyBits::Bits2048)),
    management_key: Some(vec![0x00; 24]),
    pin: Some("123456".to_string()),
    slot_id: Some(20),
};

To sign data using the YubiKey:
let data = b"Hello, world!";
let signature = yubi_key_provider.sign_data(data);
match signature {
    Ok(sig) => println!("Signature: {:?}", sig),
    Err(e) => println!("Error signing data: {:?}", e),
}

Decrypting Data
To decrypt data that was previously encrypted with the corresponding public key:
let encrypted_data = vec![...]; // Your encrypted data here
let decrypted_data = yubi_key_provider.decrypt_data(&encrypted_data);
match decrypted_data {
    Ok(data) => println!("Decrypted data: {:?}", String::from_utf8_lossy(&data)),
    Err(e) => println!("Error decrypting data: {:?}", e),
}

Encrypting Data
To encrypt data using the YubiKey:
let data = b"Secure this!";
let encrypted_data = yubi_key_provider.encrypt_data(data);
match encrypted_data {
    Ok(enc_data) => println!("Encrypted data: {:?}", enc_data),
    Err(e) => println!("Error encrypting data: {:?}", e),
}

Verifying a Signature
To verify a signature against the original data:
let original_data = b"Hello, world!";
let signature = vec![...]; // Your signature here
let verification = yubi_key_provider.verify_signature(original_data, &signature);
match verification {
    Ok(valid) => println!("Signature valid: {}", valid),
    Err(e) => println!("Error verifying signature: {:?}", e),
}





## Contribution:

We welcome contributions from the community. If you find any bugs, have suggestions for improvements or wish to add new features, feel free to create a pull request.

## License:

This project is released under the MIT License. For more information please refer to the [__LICENSE__](./LICENSE.md) file.

## Contact:

For any questions or suggestions, feel free to reach out to us using the GitHub issue feature or by sending an email to our team.

Thank you for your interest in our project!

TechShield
