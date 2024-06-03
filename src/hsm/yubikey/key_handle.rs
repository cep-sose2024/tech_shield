use super::YubiKeyProvider;
use crate::{
    common::{
        crypto::algorithms::{
            encryption::{AsymmetricEncryption, EccCurves, EccSchemeAlgorithm},
            KeyBits,
        },
        error::SecurityModuleError,
        traits::key_handle::KeyHandle,
    },
    hsm::core::error::HsmError,
};

use ::yubikey::piv;
use ::yubikey::{
    piv::{AlgorithmId, SlotId},
    MgmKey,
};
use base64::{engine::general_purpose, Engine};
use openssl::{
    ec::EcKey,
    hash::MessageDigest,
    pkey::PKey,
    rsa::{Padding, Rsa},
    sign::Verifier,
};
use rsa::sha2::Digest;
use sha2::Sha256;
use tracing::instrument;
use x509_cert::der::zeroize::Zeroizing;

/// Provides cryptographic operations for asymmetric keys on a YubiKey,
/// such as signing, encryption, decryption, and signature verification.

/// Signs data using the cryptographic key on a YubiKey.
///
/// This method hashes the input data using SHA-256 and then signs the hash.
///
/// # Arguments
///
/// * `data` - The data to be signed.
///
/// # Returns
///
/// A `Result` containing the signature as a `Vec<u8>` on success, or a `yubikey::Error` on failure.
///

impl KeyHandle for YubiKeyProvider {
    #[instrument]
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        let yubikey = self.yubikey.as_ref().unwrap();
        let mut yubikey = yubikey.lock().unwrap();
        let data = data.to_vec();
        let key_algo = self.key_algo.unwrap();

        // Input gets hashed with SHA-256
        let mut hasher = Sha256::new();
        hasher.update(data);
        let data = hasher.finalize();
        let data: &[u8] = &data;

        //TODO After PIN input implementation in App, insert code for re-authentication
        let verify = yubikey.verify_pin("123456".as_ref());
        if !verify.is_ok() {
            return Err(SecurityModuleError::Hsm(HsmError::DeviceSpecific(
                "PIN verification failed".to_string(),
            )));
        }
        let auth = yubikey.authenticate(MgmKey::default());
        if !auth.is_ok() {
            return Err(SecurityModuleError::Hsm(HsmError::DeviceSpecific(
                "Authentication  failed".to_string(),
            )));
        }
        match key_algo {
            /*
            AsymmetricEncryption::Rsa(KeyBits::Bits1024) => {
                // TODO, doesn´t work yet
            }
            AsymmetricEncryption::Rsa(KeyBits::Bits2048) => {
                // TODO, doesn´t work yet
            }
            */
            AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(EccCurves::P256)) => {
                // Sign data
                let signature = piv::sign_data(
                    &mut yubikey,
                    data,
                    AlgorithmId::EccP256,
                    SlotId::Retired(self.slot_id.unwrap()),
                );
                match signature {
                    Ok(buffer) => {
                        let signature = general_purpose::STANDARD.encode(&buffer);
                        let signature = general_purpose::STANDARD
                            .decode(signature)
                            .expect("Failed to decode signature");
                        Ok(signature)
                    }
                    Err(err) => Err(SecurityModuleError::Hsm(HsmError::DeviceSpecific(
                        err.to_string(),
                    ))),
                }
            }
            AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(EccCurves::P384)) => {
                // Sign data
                let signature = piv::sign_data(
                    &mut yubikey,
                    data,
                    AlgorithmId::EccP384,
                    SlotId::Retired(self.slot_id.unwrap()),
                );
                match signature {
                    Ok(buffer) => {
                        let signature = general_purpose::STANDARD.encode(&buffer);
                        let signature = general_purpose::STANDARD
                            .decode(signature)
                            .expect("Failed to decode signature");
                        Ok(signature)
                    }
                    Err(err) => Err(SecurityModuleError::Hsm(HsmError::DeviceSpecific(
                        err.to_string(),
                    ))),
                }
            }
            _ => {
                return Err(SecurityModuleError::Hsm(HsmError::DeviceSpecific(
                    "Key Algorithm not supported".to_string(),
                )));
            }
        }
    }

    /// Decrypts data encrypted with the corresponding public key on a YubiKey.
    /// Only works with PKCS#1 v1.5 padding.
    /// Utilizes the YubiKey API for decryption.
    ///
    /// # Arguments
    ///
    /// * `encrypted_data` - The data to be decrypted.
    ///
    /// # Returns
    ///
    /// A `Result` containing the decrypted data as a `Vec<u8>` on success, or a `yubikey::Error` on failure.
    #[instrument]
    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        let yubikey = self.yubikey.as_ref().unwrap();
        let mut yubikey = yubikey.lock().unwrap();
        let encrypted_data = general_purpose::STANDARD.decode(encrypted_data).unwrap();
        let input: &[u8] = &encrypted_data;
        let decrypted: Result<Zeroizing<Vec<u8>>, &str>;
        let key_algo = self.key_algo.unwrap();

        match key_algo {
            AsymmetricEncryption::Rsa(KeyBits::Bits1024) => {
                decrypted = piv::decrypt_data(
                    &mut yubikey,
                    input,
                    piv::AlgorithmId::Rsa1024,
                    piv::SlotId::Retired(self.slot_id.unwrap()),
                )
                .map_err(|_| "Failed to decrypt data");
            }
            AsymmetricEncryption::Rsa(KeyBits::Bits2048) => {
                decrypted = piv::decrypt_data(
                    &mut yubikey,
                    input,
                    piv::AlgorithmId::Rsa2048,
                    piv::SlotId::Retired(self.slot_id.unwrap()),
                )
                .map_err(|_| "Failed to decrypt data");
            }
            // The Yubikey do not support decryption with ECC:
            // https://docs.yubico.com/yesdk/users-manual/application-piv/apdu/auth-decrypt.html
            /*
            AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(EccCurves::P256)) => {

            }
            AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(EccCurves::P384)) => {

            }
            */
            _ => {
                return Err(SecurityModuleError::Hsm(HsmError::DeviceSpecific(
                    "Key Algorithm not supported".to_string(),
                )));
            }
        }
        fn remove_pkcs1_padding(buffer: &[u8]) -> Result<Vec<u8>, &'static str> {
            let mut pos = 2; // Start nach dem ersten Padding-Byte `0x02`
            if buffer[0] != 0 {
                return Err("Invalid padding");
            }
            // Überspringe alle non-zero Bytes
            while pos < buffer.len() && buffer[pos] != 0 {
                pos += 1;
            }
            if pos >= buffer.len() {
                return Err("No data after padding");
            }
            // Das erste `0x00` Byte überspringen, um die tatsächlichen Daten zu erhalten
            Ok(buffer[pos + 1..].to_vec())
        }
        match decrypted {
            Ok(buffer) => match remove_pkcs1_padding(&buffer) {
                Ok(data) => {
                    return Ok(data);
                }
                Err(err) => {
                    return Err(SecurityModuleError::Hsm(
                        crate::hsm::core::error::HsmError::DeviceSpecific(err.to_string()),
                    ));
                }
            },
            Err(err) => {
                return Err(SecurityModuleError::Hsm(
                    crate::hsm::core::error::HsmError::DeviceSpecific(err.to_string()),
                ));
            }
        }
    }

    /// Encrypts data with the cryptographic key on a YubiKey.
    ///
    /// Uses the YubiKey API for encryption.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to be encrypted.
    ///
    /// # Returns
    ///
    /// A `Result` containing the encrypted data as a `Vec<u8>` on success, or a `yubikey::Error` on failure.
    /// Möglicher Fehler: Müssen Daten vor dem returnen noch in Base64 umgewandelt werden?
    #[instrument]
    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        match self.key_algo.unwrap() {
            AsymmetricEncryption::Rsa(KeyBits::Bits1024)
            | AsymmetricEncryption::Rsa(KeyBits::Bits2048) => {
                let rsa = Rsa::public_key_from_pem(self.pkey.trim().as_bytes())
                    .map_err(|_| "failed to create RSA from public key PEM");
                let mut encrypted_data = vec![0; rsa.clone().unwrap().size() as usize];
                let _ = rsa
                    .map_err(|_| "")
                    .unwrap()
                    .public_encrypt(data, &mut encrypted_data, Padding::PKCS1)
                    .map_err(|_| "failed to encrypt data");
                Ok(encrypted_data)
                /*   match encrypted_data {
                    Ok(buffer) => buffer,
                    Err(err) => return Err(SecurityModuleError::Hsm("Failed to encrypt data")),
                } */
            }
            _ => {
                return Err(SecurityModuleError::Hsm(HsmError::DeviceSpecific(
                    "Key Algorithm not supported".to_string(),
                )));
            }
        }
    }

    /// Verifies a signature against the provided data using the YubiKey.
    ///
    /// This method hashes the input data using SHA-256 and then verifies the signature.
    ///
    /// # Arguments
    ///
    /// * `data` - The original data associated with the signature.
    /// * `signature` - The signature to be verified.
    ///
    /// # Returns
    ///
    /// A `Result` indicating whether the signature is valid (`true`) or not (`false`),
    /// or a `SecurityModuleError` on failure.
    #[instrument]
    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, SecurityModuleError> {
        match self.key_algo.unwrap() {
            AsymmetricEncryption::Rsa(KeyBits::Bits1024)
            | AsymmetricEncryption::Rsa(KeyBits::Bits2048) => {
                let rsa = Rsa::public_key_from_pem(self.pkey.trim().as_bytes())
                    .expect("failed to create RSA from public key PEM");
                let key_pkey = PKey::from_rsa(rsa).unwrap();

                let mut verifier = Verifier::new(MessageDigest::sha256(), &key_pkey)
                    .expect("failed to create verifier");
                verifier
                    .update(data)
                    .map_err(|_| "failed to update verifier")
                    .unwrap();
                if verifier
                    .verify(signature)
                    .expect("failed to verify signature")
                {
                    return Result::Ok(true);
                } else {
                    return Err(SecurityModuleError::Hsm(HsmError::DeviceSpecific(
                        "Signature verification failed".to_string(),
                    )));
                }
            }

            AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(EccCurves::P256))
            | AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(EccCurves::P384)) => {
                let ecc = EcKey::public_key_from_pem(self.pkey.trim().as_bytes())
                    .expect("failed to create ECC from public key PEM");
                let ecc = PKey::from_ec_key(ecc).expect("failed to create PKey from ECC");

                let mut verifier = Verifier::new(MessageDigest::sha256(), &ecc)
                    .expect("failed to create verifier");
                verifier
                    .update(data)
                    .map_err(|_| "failed to update verifier")
                    .unwrap();
                if verifier
                    .verify(signature)
                    .expect("failed to verify signature")
                {
                    return Result::Ok(true);
                } else {
                    return Err(SecurityModuleError::Hsm(HsmError::DeviceSpecific(
                        "Signature verification failed".to_string(),
                    )));
                }
            }
            _ => {
                return Err(SecurityModuleError::Hsm(HsmError::DeviceSpecific(
                    "Key Algorithm not supported".to_string(),
                )));
            }
        }
    }
}
