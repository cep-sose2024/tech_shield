use base64::{engine::general_purpose, Engine};
use der::Encode;
use pad::PadStr;
use x509_cert::{der::asn1::BitString, spki::SubjectPublicKeyInfoOwned};
use yubikey::{
    piv::{self, AlgorithmId, Key, SlotId},
    MgmKey, YubiKey,
};
fn main() {
    menu();
}

//TEST

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
        println!("5. Sign Data");
        println!("6. End");
        println!("----------------------\n");
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);

        match input.to_string().trim() {
            "1" => {
                let cipher = AlgorithmId::Rsa2048;
                let generated_key = gen_key(&mut yubikey, cipher, SlotId::KeyManagement);
                let public_key = encode_key(generated_key.as_ref().unwrap().to_der().unwrap());
                
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
                sign(&mut yubikey);
            }
            "6" => {
                break;
            }
            _ => {
                println!("\nUnknown Input!\n");
            }
        }
    }
}

fn encrypt_rsa(rsa_string: String) -> String{
    println!("\nPlease enter the data to encrypt: \n");
    let mut data = String::new();
    let _ = std::io::stdin().read_line(&mut data);
    let data = data.trim();
    let data = data.as_bytes();

    let rsa = Rsa::public_key_from_pem(rsa_string.as_bytes()).expect("failed to create RSA from public key PEM");
    
    let mut encrypted_data = vec![0; rsa.size() as usize];
    rsa.public_encrypt(data, &mut encrypted_data, Padding::PKCS1)
        .expect("failed to encrypt data");
    let encrypted_data_base64 = general_purpose::STANDARD.encode(encrypted_data);
    println!("\n\nEncrypted Data: {:?}", encrypted_data_base64);
    encrypted_data_base64

} 

fn sign(device: &mut YubiKey) {
    println!("\nPlease enter the data to sign: \n");
    let data = String::new();
    let _ = std::io::stdin().read_line(&mut data.pad_to_width(245));
    let data = data.trim();
    let data = data.as_bytes();

    // new key for signing in Signature-Slot
    let generated_key = gen_key(device, AlgorithmId::Rsa2048, SlotId::Signature);
    let formatted_key = format_key(generated_key);
    encode_key(formatted_key);

    let signature = piv::sign_data(
        device,
        data,
        piv::AlgorithmId::Rsa2048,
        piv::SlotId::Signature,
    );
    match signature {
        Ok(buffer) => {
            let string = String::from_utf8_lossy(&buffer);
            println!("\nSignature (lossy): \n{}", string);
        }
        Err(err) => println!("\nFailed to sign: \n{:?}", err),
    }
}

fn decr_data_rsa(device: &mut YubiKey, enc: String) {

    let encrypted_bytes = enc.as_bytes();
    let encrypted_bytes_decoded = general_purpose::STANDARD.decode(encrypted_bytes).unwrap();
    let input: &[u8] = &encrypted_bytes_decoded;
    //    println!("{:?}", encrypted_bytes);
    let decrypted = piv::decrypt_data(
        device,
        input,
        piv::AlgorithmId::Rsa2048,
        piv::SlotId::KeyManagement,
    );
    
    ///Entfernt PKCS1-Padding von einem Byte-Array
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
        Ok(buffer) => {
            match remove_pkcs1_padding(&buffer) {
                Ok(data) => {
                    let string = String::from_utf8_lossy(&data);
                    println!("\nDecrypted (lossy): \n{}", string);
                },
                Err(err) => println!("Padding error: {}", err),
            }
        }
        Err(err) => println!("\nFailed to decrypt: \n{:?}", err),
    }
    
}

// Key aus SubjectPublicKeyInfoOwned extrahieren, damit es weiter verarbeitet werden kann
// Key aus SubjectPublicKeyInfoOwned extrahieren, damit es weiter verarbeitet werden kann
fn format_key(generated_key: Result<SubjectPublicKeyInfoOwned, yubikey::Error>) -> Vec<u8> {
    if let Ok(key_info) = generated_key {
        let value = key_info.subject_public_key;
        let bytes = BitString::as_bytes(&value).unwrap();
        let b_65 = general_purpose::STANDARD.encode(bytes); // Convert BitString to bytes before encoding
        println!("Key: {:?}", b_65);
        return bytes.to_vec();
    }
    println!("Fehler beim Zugriff auf den öffentlichen Schlüssel.");
    Vec::new() // Gib einen leeren Vektor zurück, wenn ein Fehler auftritt
}

// Key in PEM und base64 konvertieren
fn encode_key(key: Vec<u8>)  -> String {
    // KEy in Base64 umwandeln
    let key_b64 = general_purpose::STANDARD.encode(&key);
    let key_b64_new = format!("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A{}\n-----END PUBLIC KEY-----", key_b64);
    println!("\nPublic Key: \n\n{}", key_b64_new);
    key_b64_new
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
    /*
    println!("Please insert your 6-figures PIN:\n");
    let mut eingabe = String::new();
    let _ = std::io::stdin().read_line(&mut eingabe);
    let eingabe = eingabe.trim(); // Entfernen von Whitespace und Newline-Zeichen
    if eingabe == "123456" {
        println!("\nPlease change your standard PIN.\n");
    }
    eingabe.to_string() // RÃ¼ckgabe des bereinigten Strings
    */
    "123456".to_string()
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

pub fn gen_key(
    device: &mut YubiKey,
    cipher: AlgorithmId,
    slot: piv::SlotId,
) -> Result<SubjectPublicKeyInfoOwned, yubikey::Error> {
    let gen_key = piv::generate(
        device,
        slot,
        cipher,
        yubikey::PinPolicy::Default,
        yubikey::TouchPolicy::Never,
    );
    return gen_key;
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
