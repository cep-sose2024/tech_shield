use crate::common::crypto::{
    algorithms::{
        encryption::{AsymmetricEncryption, BlockCiphers, EccSchemeAlgorithm},
        hashes::{Hash, Sha2Bits},
    },
    KeyUsage,
};
use tracing::instrument;
use yubikey::YubiKey;

pub mod key_handle;
pub mod provider;

/// A YubiKey-based cryptographic provider for managing cryptographic keys and performing
/// cryptographic operations.
///
/// This provider leverages the YubiKey API to interact with a YubiKey device for operations
/// like signing, encryption, and decryption. It provides a secure and hardware-backed solution
/// for managing cryptographic keys and performing cryptographic operations.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct YubiKeyProvider {
    /// A unique identifier for the cryptographic key managed by this provider.
    pub(super) key_id: String,
    pub(super) yubikey: YubiKey,
    pub(super) key_algorithm: AsymmetricEncryption,
    pub(super) key_usages: Option<Vec<KeyUsage>>,
    pub(super) slot_id: SlotId,
}

impl YubiKeyProvider {
    /// Constructs a new `YubiKeyProvider`.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string identifier for the cryptographic key to be managed by this provider.
    ///
    /// # Returns
    ///
    /// A new instance of `YubiKeyProvider` with the specified `key_id`.
    #[instrument]
    pub fn new(
        key_id: String,
    ) -> Self {
        Self {
            key_id,
            yubikey: None,
            key_algorithm: None,
            key_usages: None,
            slot_id: None,
            // Initialize YubiKey specific fields here
        }
    }

    pub struct KeyHandle {
        pub (super) yubikey: YubiKey,
        pub (super) key_algorithm: String,
        pub (super) pkey: String,
    }

    impl KeyHandle for YubiKeyProvider {
        
        #[instrument]
        fn new(yubikey: YubiKey, key_algorithm: String, pkey: String) -> Self {
            Self {
                key_id,
                yubikey: None,
                key_algorithm: None,
                key_usages: None,
                slot_id: None,
                pkey: None,
            }
        }
    // Add YubiKey specific methods here
}
}
