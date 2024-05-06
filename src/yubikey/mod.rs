use yubikey;

pub mod key_handle;
pub mod provider;

#[derive(Clone,Debug)]
pub struct YubiKeyProvider {
    key_id: String,

    pub(super) yubikey: Option<yubikey::YubiKey>,

    pub(super) key_algo: Option<yubikey::piv::Algorithm>,

    pub(super) sym_algo: Option<yubikey::piv::Algorithm>,

    pub(super) hash: Option<yubikey::piv::Algorithm>,

    pub(super) key_usages: Option<Vec<yubikey::piv::KeyUsage>>,

}
impl YubiKeyProvider {
    pub fn new(key_id: String) {
        Self {
            key_id,
            yubikey: None,
            key_algo: None,
            sym_algo: None,
            hash: None,
            key_usages: None,
        }
    }
}