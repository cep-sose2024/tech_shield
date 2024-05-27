#[cfg(test)]
use super::YubiKeyProvider;
#[allow(unused_imports)]
use crate::{
    common::{
        crypto::{
            algorithms::encryption::{AsymmetricEncryption, EccSchemeAlgorithm},
            KeyUsage,
        },
        error::SecurityModuleError,
        traits::{module_provider::Provider, module_provider_config::ProviderConfig},
    },
    yubikey::{YubiKeyConfig, YubiKeyError},
};
use base64::{engine::general_purpose, Engine};
use tracing::instrument;
use yubikey::Error;
use yubikey::{piv::algorithm::AlgorithmId, piv::slot::SlotId, YubiKey};

#[test]
fn test_create_rsa_key() {
    let mut provider = YubiKeyProvider::new("test_rsa_key".to_string());
    /*
        let config = TpmConfig::new(
            AsymmetricEncryption::Rsa(KeyBits::Bits4096),
            BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512),
            Hash::Sha2(Sha2Bits::Sha256),
            vec![
                KeyUsage::SignEncrypt,
                KeyUsage::ClientAuth,
                KeyUsage::Decrypt,
                KeyUsage::CreateX509,
            ],
        );
    */
    provider
        .initialize_module("Rsa", KeyUsage::SignEncrypt)
        .expect("Failed to initialize module");
    provider.create_key().expect("Failed to create RSA key");
}

#[test]
fn test_create_ecc_key() {
    let mut provider = YubiKeyProvider::new("test_rsa_key".to_string());
    /*
        let config = TpmConfig::new(
            AsymmetricEncryption::Rsa(KeyBits::Bits4096),
            BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512),
            Hash::Sha2(Sha2Bits::Sha256),
            vec![
                KeyUsage::SignEncrypt,
                KeyUsage::ClientAuth,
                KeyUsage::Decrypt,
                KeyUsage::CreateX509,
            ],
        );
    */
    provider
        .initialize_module("Ecc", KeyUsage::SignEncrypt)
        .expect("Failed to initialize module");
    provider.create_key().expect("Failed to create RSA key");
}

#[test]
fn test_load_rsa_key() {
    let mut provider = TpmProvider::new("test_rsa_key".to_string());

    let config = TpmConfig::new(
        AsymmetricEncryption::Rsa(KeyBits::Bits4096),
        BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512),
        Hash::Sha2(Sha2Bits::Sha256),
        vec![
            KeyUsage::SignEncrypt,
            KeyUsage::ClientAuth,
            KeyUsage::Decrypt,
            KeyUsage::CreateX509,
        ],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .load_key("test_rsa_key", config)
        .expect("Failed to load RSA key");
}

#[test]
fn test_load_ecdsa_key() {
    let mut provider = TpmProvider::new("test_ecdsa_key".to_string());

    let config = TpmConfig::new(
        AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::Curve25519)),
        BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512),
        Hash::Sha2(Sha2Bits::Sha256),
        vec![
            KeyUsage::SignEncrypt,
            KeyUsage::ClientAuth,
            KeyUsage::Decrypt,
            KeyUsage::CreateX509,
        ],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .load_key("test_ecdsa_key", config)
        .expect("Failed to load ECDSA key");
}

#[test]
fn test_load_ecdh_key() {
    let mut provider = TpmProvider::new("test_ecdh_key".to_string());

    let config = TpmConfig::new(
        AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(EccCurves::Curve25519)),
        BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512),
        Hash::Sha2(Sha2Bits::Sha256),
        vec![KeyUsage::SignEncrypt, KeyUsage::Decrypt],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .load_key("test_ecdh_key", config)
        .expect("Failed to load ECDH key");
}
