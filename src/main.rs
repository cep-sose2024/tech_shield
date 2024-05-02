use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};
use pem::{encode, Pem};
use x509_cert::{
    der::{asn1::BitString, Encode},
    spki::SubjectPublicKeyInfoOwned,
};
use yubikey::{
    piv::{self, Key},
    MgmKey, YubiKey,
};

fn main() {
    menu();
}

fn menu() {
    let yubikey = open_device();

    let pin = pin_eingabe();
    let mut yubikey = verify_pin(pin, yubikey);

    let _ = yubikey.authenticate(MgmKey::default());

    loop {
        println!("\n----------------------");
        println!("1. Generate Key");
        println!("2. Encrypt");
        println!("3. Change Pin");
        println!("4. Change PUK");
        println!("5. End");
        println!("----------------------\n");
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);

        match input.to_string().trim() {
            "1" => {
                let generated_key = gen_key(&mut yubikey);
                let formatted_key = format_key(generated_key);
                encode_key(formatted_key);
            }
            "2" => {
                decr_data(&mut yubikey);
            }
            "5" => {
                break;
            }
            _ => {
                println!("\nUnknown Input!\n");
            }
        }
    }
}

fn decr_data(device: &mut YubiKey) {}

/* fn format_key2(generated_key: Option<BitString>) {
    let mut bit_vec: Vec<u8>;
    let laenge = generated_key.encoded_len();
    for i in laenge {
        if generated_key.chars.nth(i).unwrap().equals("[") {

        }
    }

   // let pem = Pem::new("Test", generated_key);
   // encode(&pem);
}}
*/
fn format_key(generated_key: Result<SubjectPublicKeyInfoOwned, yubikey::Error>) -> Vec<u8> {
    let value = generated_key.unwrap().subject_public_key;
    let raw = value.as_bytes();
    let raw_extracted = raw.unwrap();
    let raw_vec = raw_extracted.to_vec();
    return raw_vec;
}

fn encode_key(key: Vec<u8>) {
    let key_b64 = general_purpose::STANDARD.encode(&key);
    println!("\nBase 64: \n{}", key_b64);
    let pem = Pem::new("PUBLIC KEY", key);
    let pem_key = encode(&pem);
    println!("\nPEM-Key:{:?}", pem_key);
}

fn open_device() -> YubiKey {
    loop {
        println!("Please connect your Yubikey and press Enter.");
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);
        let yubikey = YubiKey::open();
        if yubikey.is_ok() {
            return yubikey.unwrap();
        } else {
            println!("No Yubikey found, please try again!\n\n")
        }
    }
}

fn pin_eingabe() -> String {
    println!("Please insert your 6-figures PIN:\n");
    let mut eingabe = String::new();
    let _ = std::io::stdin().read_line(&mut eingabe);
    let eingabe = eingabe.trim(); // Entfernen von Whitespace und Newline-Zeichen
    if eingabe == "123456" {
        println!("\nPlease change your standard PIN.\n");
    }
    eingabe.to_string() // RÃ¼ckgabe des bereinigten Strings
}

fn verify_pin(pin: String, mut device: YubiKey) -> YubiKey {
    let verify = device.verify_pin(pin.as_ref());
    if verify.is_ok() {
        println!("Login successful.");
        return device;
    } else {
        println!("Pin incorrect.");
        let count = device.get_pin_retries().unwrap();
        loop {
            println!("Please enter your PIN again.");
            let mut input = String::new();
            let _ = std::io::stdin().read_line(&mut input);
            let input = input.trim(); // Entfernen von Whitespace und Newline-Zeichen
            let ver = device.verify_pin(input.as_ref());
            if ver.is_ok() {
                println!("Login successful.");
                return device;
            }
            if count == 0 {
                println!("PUK is required. Please enter you 8-figures PUK:");
                let mut puk = String::new();
                let _ = std::io::stdin().read_line(&mut puk);
                let puk = puk.trim(); // Entfernen von Whitespace und Newline-Zeichen
                println!("Please enter your new PIN:");
                let mut pin_neu = String::new();
                let _ = std::io::stdin().read_line(&mut pin_neu);
                let pin_neu = pin_neu.trim(); // Entfernen von Whitespace und Newline-Zeichen
                let change_puk = device.unblock_pin(puk.as_ref(), pin_neu.as_ref());
                if change_puk.is_ok() {
                    println!("PIN changed successfully.");
                    println!("Login Successful.");
                    return device;
                }
            }
        }
    }
}

pub fn get_slot_list(device: &mut YubiKey) {
    let slot_list = Key::list(device);
    // let slot = slot_list.unwrap().slot();
    // println!("Slotliste {:?}", slot_list);
    for slot in &slot_list {
        println!("Iteration");
        println!("\nSlot Liste: {:?}", slot);
    }
}

pub fn gen_key(device: &mut YubiKey) -> Result<SubjectPublicKeyInfoOwned, yubikey::Error> {
    let gen_key = piv::generate(
        device,
        piv::SlotId::Authentication,
        piv::AlgorithmId::Rsa2048,
        yubikey::PinPolicy::Always,
        yubikey::TouchPolicy::Always,
    );
    return gen_key;
}