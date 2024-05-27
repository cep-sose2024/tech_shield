use crate::yubikey::mod1::YubiKeyProvider;
#[cfg(test)]
#[allow(unused_imports)]
use common::crypto::KeyUsage;
#[test]
fn test_create_rsa_key() {
    let mut provider = YubiKeyProvider::new("test_rsa_key".to_string());

    provider
        .initialize_module("Rsa", KeyUsage::SignEncrypt)
        .expect("Failed to initialize module");
    provider.create_key().expect("Failed to create RSA key");
}

#[test]
fn test_create_ecc_key() {
    let mut provider = YubiKeyProvider::new("test_rsa_key".to_string());

    provider
        .initialize_module("Ecc", KeyUsage::SignEncrypt)
        .expect("Failed to initialize module");
    provider.create_key().expect("Failed to create RSA key");
}
