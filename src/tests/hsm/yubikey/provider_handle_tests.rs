#[allow(unused_imports)]
use crate::common::{
    crypto::{
        algorithms::{
            encryption::{AsymmetricEncryption, BlockCiphers, EccCurves, EccSchemeAlgorithm},
            hashes::Hash,
        },
        KeyUsage,
    },
    traits::module_provider::Provider,
};
use crate::hsm::yubikey::YubiKeyProvider;
use crate::hsm::HsmProviderConfig;
#[cfg(feature = "yubi")]
#[test]
fn test_create_rsa_key() {
    let key_id = "test_rsa_key";
    let mut provider = YubiKeyProvider::new(key_id.to_string());

    let config = HsmProviderConfig::new(
        AsymmetricEncryption::Rsa(crate::common::crypto::algorithms::KeyBits::Bits1024),
        vec![KeyUsage::SignEncrypt],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .create_key(key_id, config)
        .expect("Failed to create RSA key");
}

#[cfg(feature = "yubi")]
#[test]
fn test_create_ecc_key() {
    let key_id = "test_ecc_key";

    let mut provider = YubiKeyProvider::new(key_id.to_string());

    let config = HsmProviderConfig::new(
        AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::P256)),
        vec![KeyUsage::SignEncrypt],
    );
    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .create_key(key_id, config)
        .expect("Failed to create ECC key");
}

#[test]
fn test_load_rsa_key() {
    let key_id = "test_rsa_key";
    let mut provider = YubiKeyProvider::new(key_id.to_string());

    let config = HsmProviderConfig::new(
        AsymmetricEncryption::Rsa(crate::common::crypto::algorithms::KeyBits::Bits2048),
        vec![KeyUsage::SignEncrypt],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .load_key("test_rsa_key", config)
        .expect("Failed to load RSA key");
}

#[test]
fn test_load_ecc_key() {
    let key_id = "test_ecc_key";

    let mut provider = YubiKeyProvider::new(key_id.to_string());

    let config = HsmProviderConfig::new(
        AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::P256)),
        vec![KeyUsage::SignEncrypt],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .load_key("test_ecc_key", config)
        .expect("Failed to load ECDSA key");
}

/*
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
*/
