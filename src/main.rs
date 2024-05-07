use base64::{engine::general_purpose, Engine};

use x509_cert::{der::asn1::BitString, spki::SubjectPublicKeyInfoOwned};
use yubikey::{
    piv::{self, Key, RetiredSlotId, SlotId},
    MgmKey, YubiKey,
};
use encoding_rs::{Decoder, Encoding};
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
        println!("2. Decrypt");
        println!("3. Show Metadata");
        println!("4. List Keys");
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
            "3" => {
                println!(
                    "{:?}",
                    yubikey::piv::metadata(&mut yubikey, piv::SlotId::KeyManagement)
                )
            }
            "4" => {
                let list = Key::list(&mut yubikey);
                println!("{:?}", list);
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

fn decr_data(device: &mut YubiKey) {
    println!("\nPlease enter the encrypted data: \n");
    let mut encrypted = String::new();
    let _ = std::io::stdin().read_line(&mut encrypted);
    let encrypted_bytes = encrypted.trim_end().as_bytes();
    let encrypted_bytes_decoded = general_purpose::STANDARD.decode(encrypted_bytes).unwrap();
    let input: &[u8] = &encrypted_bytes_decoded;
    //    println!("{:?}", encrypted_bytes);
    let decrypted = piv::decrypt_data(
        device,
        input,
        piv::AlgorithmId::Rsa2048,
        piv::SlotId::KeyManagement,
    );
    match decrypted {
        Ok(buffer) => {
            let decoderf = Encoding::new_decoder(&'static self);
            let mut output = "";
            Decoder::decode_to_str(&mut self, &buffer, &mut output, last)
            println!("\nDecrypted (lossy): \n{}", string);
        }
        Err(err) => println!("\nFailed to decrypt: \n{:?}", err),
    }   
}

// Versuch ein Zertifikat zum Schlüssel hinzuzufügen, in der Hoffnung dass er deshalb nicht funktioniert
/* pub fn certify(
    device: &mut YubiKey,
    generated_key: Result<SubjectPublicKeyInfoOwned, yubikey::Error>,
) {
    let ser = device.serial();
    let x_ser = x509_cert::serial_number::SerialNumber::new(ser.to_string().as_bytes());
    let time = x509_cert::time::Validity::from_now(Duration::MAX);
    //   let extensions: &[x509_cert::ext::Extension] = &[];
    let gen_key_unwrapped = generated_key.unwrap();
    let subject = create_rdn();
    let extensions: &[x509_cert::ext::Extension] = &[];

    let gen_cert = certificate::Certificate::generate_self_signed(
        device,
        piv::SlotId::KeyManagement,
        x_ser.unwrap(),
        time.unwrap(),
        subject,
        gen_key_unwrapped,
        extensions,
    );
}

// Subject erstellen für generate_self_signed
pub fn create_rdn() -> RdnSequence {
    let vec: Vec<RdnSequence> = Vec::new();
    let set: SetOfVec<AttributeTypeAndValue> = SetOfVec::new();

    let oid_cn = ObjectIdentifier::new("2.5.4.3").unwrap();
    let name_byte = "Jannis".as_bytes();
    let name_box = Box::new(name_byte);
    let cn_value = AttributeValue::new(der::Tag::Utf8String, name_box).unwrap();

    let cn = format!(
        "oid: {},
        value: {},",
        oid_cn.to_string(),
        cn_value
    );

    let test = RdnSequence::from_str(&cn);
    match test {
        Ok(handle) => println!("Erfolgreich: {:?}", handle),
        Err(err) => println!("Failed: {:?}", err),
    };
    return test.unwrap();
}
*/

// Key aus SubjectPublicKeyInfoOwned extrahieren, damit es weiter verarbeitet werden kann
fn format_key(generated_key: Result<SubjectPublicKeyInfoOwned, yubikey::Error>) -> Vec<u8> {
    if let Ok(key_info) = generated_key {
        //     certify(&mut device, generated_key);
        let value = key_info.subject_public_key;
        let bytes = BitString::as_bytes(&value).unwrap();
        return bytes.to_vec();
    }
    println!("Fehler beim Zugriff auf den öffentlichen Schlüssel.");
    Vec::new() // Gib einen leeren Vektor zurück, wenn ein Fehler auftritt
}

// Key in PEM und base64 konvertieren
fn encode_key(key: Vec<u8>) {
    // KEy in Base64 umwandeln
    let key_b64 = general_purpose::STANDARD.encode(&key);
    let key_b64_new = format!("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A{:?}", key_b64);
    println!("\nPublic Key: \n\n{}", key_b64_new);
    /*    let pem = Pem::new("PUBLIC KEY", key);
        let pem_key = encode(&pem);
        println!("\nPEM-Key:{:?}", pem_key);
        let mut pem_key_new = pem_key.replace("\r", "");
        pem_key_new = pem_key_new.replace("\n", "");
        println!("\n New: {:?}", pem_key_new);

        let mut keys: Vec<String> = Vec::new();
        keys.push(pem_key);
        keys.push(pem_key_new);

        return keys;
    */
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
  /*   let all_slots = [
        RetiredSlotId::R1, RetiredSlotId::R2, RetiredSlotId::R3, RetiredSlotId::R4,
        RetiredSlotId::R5, RetiredSlotId::R6, RetiredSlotId::R7, RetiredSlotId::R8,
        RetiredSlotId::R9, RetiredSlotId::R10, RetiredSlotId::R11, RetiredSlotId::R12,
        RetiredSlotId::R13, RetiredSlotId::R14, RetiredSlotId::R15, RetiredSlotId::R16,
        RetiredSlotId::R17, RetiredSlotId::R18, RetiredSlotId::R19, RetiredSlotId::R20,
    ];
    */
    let gen_key = piv::generate(
        device,
        piv::SlotId::KeyManagement,
        piv::AlgorithmId::Rsa2048,
        yubikey::PinPolicy::Default,
        yubikey::TouchPolicy::Never,
    );
    return gen_key;
}
