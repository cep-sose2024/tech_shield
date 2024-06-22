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

[dependencies]
yubikey = "0.5"
base64 = "0.13"
openssl = "0.10"
rsa = "0.5"
sha2 = "0.9"
tracing = "0.1"
x509-cert = "0.5"



#Example
Below is an example of how to use the YubiKeyProvider to sign data.

rust
Code kopieren
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
use yubikey::{piv, AlgorithmId, SlotId, MgmKey};
use base64::{engine::general_purpose, Engine};
use openssl::{ec::EcKey, hash::MessageDigest, pkey::PKey, rsa::{Padding, Rsa}, sign::Verifier};
use rsa::sha2::Digest;
use sha2::Sha256;
use tracing::instrument;
use x509_cert::der::zeroize::Zeroizing;

const BYTES_1024: usize = 128;
const BYTES_2048: usize = 256;

/// Provides cryptographic operations for asymmetric keys on a YubiKey.
pub struct YubiKeyProvider {
    yubikey: Option<Mutex<YubiKey>>,
    pin: Option<String>,
    management_key: Option<Vec<u8>>,
    key_algo: Option<AsymmetricEncryption>,
    slot_id: Option<u8>,
    pkey: String,
}

impl KeyHandle for YubiKeyProvider {
    /// Signs data using the cryptographic key on a YubiKey.
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
        let mut data: &[u8] = &data;

        // TODO: After PIN input implementation in App, insert code for re-authentication
        let verify = yubikey.verify_pin(self.pin.as_ref());
        if !verify.is_ok() {
            return Err(SecurityModuleError::Hsm(HsmError::DeviceSpecific(
                "PIN verification failed".to_string(),
            )));
        }
        let auth = yubikey.authenticate(MgmKey::new(self.management_key.unwrap()).unwrap());
        if !auth.is_ok() {
            return Err(SecurityModuleError::Hsm(HsmError::DeviceSpecific(
                "Authentication  failed".to_string(),
            )));
        }

        let signature: Result<Zeroizing<Vec<u8>>, yubikey::Error>;
        let mut vec_data: Vec<u8> = create_digest_info(data).unwrap();
        let algorithm_id: AlgorithmId;

        match key_algo {
            AsymmetricEncryption::Rsa(KeyBits::Bits1024) => {
                algorithm_id = AlgorithmId::Rsa1024;
                vec_data = apply_pkcs1v15_padding(&vec_data, BYTES_1024);
                data = &vec_data.as_slice();
            }
            AsymmetricEncryption::Rsa(KeyBits::Bits2048) => {
                algorithm_id = AlgorithmId::Rsa2048;
                vec_data = apply_pkcs1v15_padding(&vec_data, BYTES_2048);
                data = vec_data.as_slice();
            }

            AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::P256)) => {
                algorithm_id = AlgorithmId::EccP256;
            }
            AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::P384)) => {
                algorithm_id = AlgorithmId::EccP384;
            }
            _ => {
                return Err(SecurityModuleError::Hsm(HsmError::DeviceSpecific(
                    "Key Algorithm not supported".to_string(),
                )));
            }
        }
        signature = piv::sign_data(
            &mut yubikey,
            data,
            algorithm_id,
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
}





## Contribution:

We welcome contributions from the community. If you find any bugs, have suggestions for improvements or wish to add new features, feel free to create a pull request.

## License:

This project is released under the MIT License. For more information please refer to the [__LICENSE__](./LICENSE.md) file.

## Contact:

For any questions or suggestions, feel free to reach out to us using the GitHub issue feature or by sending an email to our team.

Thank you for your interest in our project!

TechShield
