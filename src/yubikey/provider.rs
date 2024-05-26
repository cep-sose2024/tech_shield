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

/// Implements the `Provider` trait, providing cryptographic operations utilizing a YubiKey.
///
/// This implementation interacts with a YubiKey device for key management and cryptographic
/// operations.
impl Provider for YubiKeyProvider {
    /// Creates a new cryptographic key identified by `key_id`.
    ///
    /// This method creates a persisted cryptographic key using the specified algorithm
    /// and identifier, making it retrievable for future operations. The key is created
    /// with the specified key usages and stored in the YubiKey.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string slice that uniquely identifies the key to be created.
    /// * `config` - A boxed `ProviderConfig` containing configuration details for the key.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(String)`, which represents the public key, indicating that the key was created successfully.
    /// On failure, it returns a `yubikey::Error`.
    #[instrument]
    fn create_key(
        &mut self,
        //key_id: &str, notwendig? self.key_id???
        //config: Box<dyn ProviderConfig>,
    ) -> Result<String, yubikey::Error> {
        match self.key_usage {
            "SignEncrypt" => {
                match self.key_algorithm {
                    "Rsa" => {
                        
                        let gen_key = piv::generate(
                            self.yubikey,
                            SlotId::KeyManagement,
                            AlgorithmId::RSA2048,
                            yubikey::PinPolicy::Default,
                            yubikey::TouchPolicy::Default,
                        );
                        
                        match gen_key {
                            Ok(()) =>  {
                            gen_key = gen_key.as_ref().unwrap().to_der().unwrap();
                            gen_key = general_purpose::STANDARD.encode(&gen_key);
                            gen_key = format!(
                            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----", gen_key.trim());
                            return gen_key
                            },
                            Err(err) => return Error::KeyError,
                        }
                    },
                    "Ecc" => {
                        // TODO, doesn´t work yet
                    },
                    "_" => Error::NotSupported,
                }
            },

            "_" => Error::NotSupported,
        }
    }
    /// Loads an existing cryptographic key identified by `key_id`.
    ///
    /// This method attempts to load a persisted cryptographic key by its identifier from the YubiKey.
    /// If successful, it sets the key usages and returns a handle to the key for further
    /// cryptographic operations.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string slice that uniquely identifies the key to be loaded.
    /// * `config` - A boxed `ProviderConfig` containing configuration details for the key.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(())`, indicating that the key was loaded successfully.
    /// On failure, it returns a `SecurityModuleError`.
    #[instrument]
    fn load_key(
        &mut self,
        key_id: &str,
        config: Box<dyn ProviderConfig>,
    ) -> Result<(), yubikey::Error> {
        // Method implementation goes here
    }

    /// Initializes the YubiKey module and returns a handle for cryptographic operations.
    ///
    /// This method initializes the YubiKey device and sets up the necessary environment
    /// for cryptographic operations.
    ///
    /// # Arguments
    ///
    /// * `key_algorithm` - The asymmetric encryption algorithm to be used for the key.
    /// * `hash` - An optional hash algorithm to be used with the key.
    /// * `key_usages` - A vector of `KeyUsage` values specifying the intended usages for the key.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(())`, indicating that the module was initialized successfully.
    /// On failure, it returns a Yubikey based `Error`.
    #[instrument]
    fn initialize_module(
        &mut self,
        key_algorithm: AsymmetricEncryption,
        hash: Option<Hash>,
        key_usages: Vec<KeyUsage>,
    ) -> Result<(), Error> {
        let yubikey = YubiKey::open().map_err(|_| Error::NotFound);
        yubikey
            .verify_pin("123456".as_ref())
            .map_err(|_| Error::WrongPin {
                tries: yubikey::get_pin_retries(),
            });
        self.yubikey = yubikey;
        self.key_algorithm = Some(key_algorithm);
        self.hash = hash;
        self.key_usages = Some(key_usages);
    }

    // Halbfertiger Code, kann benutzt werden wenn PIN-Abfrage in App implementiert wird
    /*
    #[instrument]
    fn initialize_module(
        &mut self,
        key_algorithm: AsymmetricEncryption,
        sym_algorithm: Option<BlockCiphers>,
        hash: Option<Hash>,
        key_usages: Vec<KeyUsage>,
        input: &str,
    ) -> Result<device, SecurityModuleError> {
        // Opens a connection to the yubikey device
        loop {
            let yubikey = YubiKey::open();
            if yubikey.is_ok() {
                let verify = device.verify_pin(input);
                if verify.is_ok() {
                    //successful login
                    return device;
                } else {
                    let count = device.get_pin_retries().unwrap();
                    // TODO: Implement PUK handling
                    if count == 0 {
                        return yubiKey::Error::PinLocked;
                        /*  let puk;
                        let pin_neu;
                        let change_puk = device.unblock_pin(puk.as_ref(), pin_neu.as_ref());
                        if change_puk.is_ok() {
                            return device;
                            */
                    }
                    return yubikey::Errror::WrongPin;
                }
            }
        }
    }
    */
}
