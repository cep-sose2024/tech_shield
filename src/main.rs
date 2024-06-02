use hsm::HsmProviderConfig;
use tech_shield::{hsm, SecurityModuleError};
//use crate::hsm::core::instance::HsmType;

use tech_shield::common::factory::{SecurityModule};
use tech_shield::hsm::core::instance::HsmType;

fn main() {
    println!("hallo");
    let key_id = "my_key_id".to_string();
    let sec_module: SecurityModule  = SecurityModule::Hsm(HsmType::from("yubikey"));
    let hsm_provider = tech_shield::SecModules::get_instance(key_id, sec_module, None);
    match hsm_provider.unwrap().lock().unwrap().initialize_module(){
        Ok(()) => println!("HSM module initialized successfully"),
        Err(e)=>println!("Failed to initialize HSM module: {:?}", e),
    }
    menu();
}

fn menu(){
    /*
    let yubikey = open_device();

    let pin = pin_eingabe();
    let mut yubikey = verify_pin(pin, yubikey);

    let _ = yubikey.authenticate(MgmKey::default());
    let mut rsa_pub_key = String::new();
    let mut encrypted = String::new();

    loop {
        println!("\n----------------------");
        println!("1. Generate Key");
        println!("2. Encrypt");
        println!("3. Decrypt");
        println!("4. Sign Data");
        println!("5. Verify Signature");
        println!("6. Show Metadata");
        println!("7. List Keys");
        println!("8. End");
        println!("9. load_key");
        println!("----------------------\n");
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);

        match input.to_string().trim() {
            "1" => {
                let cipher = AlgorithmId::Rsa2048;
                let generated_key = gen_key(&mut yubikey, cipher, SlotId::KeyManagement);
                rsa_pub_key = encode_key(generated_key.as_ref().unwrap().to_der().unwrap());
                println!("\n\nPEM-Key:\n\n{}", rsa_pub_key);
            }
            "2" => {
                encrypted = encrypt_rsa(rsa_pub_key.clone());
            }
            "3" => {
                decr_data_rsa(&mut yubikey, encrypted.clone());
            }
            "4" => {
                sign(&mut yubikey);
            }
            "5" => {
                if rsa_verify_signature() {
                    println!("Signature is valid.");
                } else {
                    println!("Signature is invalid.");
                }
            }
            "6" => {
                println!(
                    "{:?}",
                    yubikey::piv::metadata(&mut yubikey, piv::SlotId::KeyManagement)
                )
            }
            "7" => {
                let list = Key::list(&mut yubikey);
                println!("{:?}", list);
            }
            "8" => {
                break;
            }
            "9" => {
                let mut inbad = String::new();
                let _ = std::io::stdin().read_line(&mut inbad);
                let res = load_key(&mut yubikey, inbad.to_string().trim()).unwrap();
                println!("Load key: {:?}", res);
            }
            _ => {
                println!("\nUnknown Input!\n");
            }
        }
    }

     */
}
