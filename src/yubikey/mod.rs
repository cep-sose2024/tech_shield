use yubikey;

pub mod key_handle;
pub mod provider;

/// A HSM-based cryptographic provider for managing cryptographic keys and performing cryptrograpic operations.
/// 
/// This provider is based on the YubiKey hardware security module (HSM) and provides a set of cryptographic operations
/// like signing and decryption. It provides a secure and hardware-backend
/// implementation of cryptographic operations.
#[derive(Clone,Debug)]
pub struct YubiKeyProvider {
    /// A unigue identifier for the cryptographic key managed by this provider.
    key_id: String,
    pub(super) yubikey: Option<yubikey::YubiKey>,
    pub(super) key_handle: Option<???tbd???>,
    pub(super) handle: Option<yubikey::YubiKey>,
    pub(super) key_algo: Option<yubikey::piv::AlgorithmId>,
    pub(super) sym_algo: Option<yubikey::piv::AlgorithmId>,
    pub(super) hash: Option<yubikey::piv::AlgorithmId>,
    pub(super) key_usages: Option<Vec<yubikey::piv::SlotId>>,

}
impl YubiKeyProvider {
    /// Constructs a new 'YubikKeyProvider'
    /// 
    /// # Arguments
    /// 
    /// * 'key_id' - A string identifier for the cryptografic key to be managed by this provider.
    pub fn new(key_id: String) -> Self{
        Self {
            key_id,
            yubikey: None,
            key_handle: None,
            handle: None,
            key_algo: None,
            sym_algo: None,
            hash: None,
            key_usages: None,
        }
    }
}