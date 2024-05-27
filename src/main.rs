use base64::{engine::general_purpose, Engine};
use der::{asn1, oid::ObjectIdentifier, Decode, Encode, Error};
use md5::{Digest, Md5};
use openssl::rsa::{Padding, Rsa};
use openssl::sign::Verifier as RSAVerifier;
use openssl::{hash::MessageDigest, pkey::PKey};
use ring::signature;
use rsa::sha2;
use sha2::Sha256;
use x509_cert::{der::asn1::BitString, spki::SubjectPublicKeyInfoOwned};
use yubikey::{
    piv::{self, AlgorithmId, Key, SlotId},
    MgmKey, YubiKey,
};
const SIGNATURE_SLOT: u32 = 0x005f_c10b;
const AUTHENTICATION_SLOT: u32 = 0x005f_c105;
const RETIRED_SLOT: [u32; 20] = [
    0x005f_c10d, 0x005f_c10e, 0x005f_c10f, 0x005f_c110,
    0x005f_c111, 0x005f_c112, 0x005f_c113, 0x005f_c114,
    0x005f_c115, 0x005f_c116, 0x005f_c117, 0x005f_c118,
    0x005f_c119, 0x005f_c11a, 0x005f_c11b, 0x005f_c11c,
    0x005f_c11d, 0x005f_c11e, 0x005f_c11f, 0x005f_c120,
];
const SECURITY_OBJECT: u32 = 0x005f_c106;
const DISCOVERY_OBJECT: u32 = 0x7e;
const ATTESTATION: u32 = 0x005f_ff01;

const MAX_KEYS: usize = RETIRED_SLOT.len();
//irgend eine key-id länge
const MAX_KEY_ID_LENGTH: usize = 20;
fn main() {
    menu();
}

//TEST

fn menu() {
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

            _ => {
                println!("\nUnknown Input!\n");
            }
        }
    }
}




fn get_oid(yubikey: &mut YubiKey, id: u8)->Result<u32, String>{
    let addressbook = yubikey.fetch_object(DISCOVERY_OBJECT).unwrap().to_vec();
    if let Some(index) = addressbook.iter().position(|&x| x== id){
        Ok(index as u32)
    }
    else {
        Err(String::from("ID not found"))
    }
}
fn get_key(yubikey: &mut YubiKey, key_id: &str)->Result<(),Error>{
    let oid = match get_oid(yubikey, key_id.as_bytes()[0]){
        Ok(zahl)=>zahl,
        Err(no_zahl)=>0_u32
    };
    let key = drop(fetch_key(yubikey, oid));
    Ok((key))
}
fn fetch_key(yubikey: &mut YubiKey, oid: u32)->Vec<u8>{
    let ausgelesen = yubikey.fetch_object(oid);
    let key = ausgelesen.unwrap().to_vec();
    //println!("\n\nKI: {:?}\n\n", ki);
    //let ret= SubjectPublicKeyInfo::from_der(&ki);
    return key;
}

fn verify_signature() {
    println!("\nPlease enter the public key: \n");
    let mut key = String::new();
    let _ = std::io::stdin().read_line(&mut key);
    let key_decoded = general_purpose::STANDARD
        .decode(key.trim().as_bytes())
        .unwrap();
    let key_u8: &[u8] = key_decoded.as_slice();

    println!("\nPlease enter the signature: \n");
    let mut signed = String::new();
    let _ = std::io::stdin().read_line(&mut signed);
    let signed_decoded = general_purpose::STANDARD
        .decode(signed.trim().as_bytes())
        .unwrap();
    let signed_u8: &[u8] = signed_decoded.as_slice();

    println!("\nPlease enter the raw data: \n");
    let mut raw = String::new();
    let _ = std::io::stdin().read_line(&mut raw);
    //let raw_u8: &[u8] = raw.trim().as_bytes();
    // muss gehasht werden???
    let raw_vec = raw.trim().as_bytes().to_vec();
    let raw_hashed = hash_data(raw_vec, "MD5");
    let raw_u8: &[u8] = &raw_hashed;

    let pubkey = signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, key_u8);

    let sign_result = pubkey.verify(&raw_u8, signed_u8);

    match sign_result {
        Ok(test) => println!("Signature is valid: {:?}", test),
        Err(err) => println!("Signature is invalid: {:?}", err),
    }
}

fn apply_pkcs1v15_padding(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding_length = block_size - data.len() - 3;
    let mut padded_data = Vec::with_capacity(block_size);
    padded_data.push(0x00);
    padded_data.push(0x01);
    for _ in 0..padding_length {
        padded_data.push(0xFF);
    }
    padded_data.push(0x00);
    padded_data.extend_from_slice(data);
    //println!("{:?}", padded_data);
    padded_data
}

/*fn remove_pkcs1_padding(signature: &[u8], length: usize) -> Vec<u8> {
    let total_length = signature.len(); // Gesamtlänge der Datenblockgröße für RSA2048
    let padding_length = total_length - length;

    if padding_length < total_length {
        signature[padding_length..].to_vec()
    } else {
        Vec::new() // Leere Vektor zurückgeben, wenn die Berechnung fehlschlägt
    }
}
*/
fn rsa_verify_signature(/*signature: &[u8], pkey: &PKey<Public> rsa_string: String*/) -> bool {
    // Public Key einlesen
    /*    println!("\nPlease enter the public Key: \n");
       let mut data = String::new();
       let _ = std::io::stdin().read_line(&mut data);
       let data = data.trim();
       let data = data.as_bytes();
    */
    // println!("{}", rsa_string);
    let rsa = "-----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAj6ONjVG9iQcViYth4DHnsLqa4ZMtu1wNIwn8QTmdLpbZeaiZbPoRGNPr6mobuNn4lLxMHq/wgOqneNNQmi6FMVv9TlqyaE0lEcAGiOjrLBNmnPxe5CZyWUssh1LeHQzAqLicaSqmqIY6Ig7QTm9YRd+y0jnkopPzk90wPyKdrd55jtgHMXEEImt1oSg29WxzrKHvcbH/dVxZkmJuDcLQx3g2zzkGZnuhiwOfX/1mQCM+UDYNZyrUegSDS3ITW0S+abukrEi9OKe3+iW3MP0BX6tITAW1IQ0I5cArvd93vzMc7WOz3qrajuqCVcaHad5AU9WwDsY79Vk89skmqydrUQIDAQAB
-----END PUBLIC KEY-----";
    let rsa =
        Rsa::public_key_from_pem(rsa.as_bytes()).expect("failed to create RSA from public key PEM");
    let key_pkey = PKey::from_rsa(rsa).unwrap();
    // Signatur einlesen
    /*     println!("\nPlease enter the signature: \n");
        let mut signed = String::new();
        let _ = std::io::stdin().read_line(&mut signed);
        let signed_decoded = general_purpose::STANDARD
            .decode(signed.trim())
            .unwrap();
        let signed_u8: &[u8] = signed_decoded.as_slice();
    */
    let signature: [u8; 256] = [
        93, 158, 218, 5, 89, 196, 44, 112, 225, 56, 227, 238, 194, 18, 55, 88, 129, 248, 121, 19,
        194, 65, 168, 5, 223, 63, 70, 39, 157, 65, 190, 201, 119, 194, 109, 79, 43, 126, 25, 233,
        113, 145, 34, 186, 166, 199, 12, 222, 176, 170, 70, 193, 171, 46, 149, 214, 167, 162, 56,
        23, 227, 157, 225, 125, 201, 27, 127, 142, 192, 234, 146, 203, 169, 139, 235, 125, 190,
        174, 235, 27, 116, 172, 223, 185, 29, 61, 162, 60, 189, 114, 253, 91, 141, 46, 201, 204,
        28, 230, 144, 226, 189, 215, 226, 2, 113, 114, 180, 68, 87, 118, 72, 164, 77, 178, 116,
        248, 72, 234, 22, 20, 45, 158, 61, 223, 208, 8, 30, 43, 203, 34, 212, 184, 183, 133, 235,
        73, 119, 9, 92, 156, 166, 239, 160, 249, 89, 37, 130, 62, 125, 240, 59, 234, 245, 219, 11,
        230, 117, 223, 39, 126, 204, 81, 94, 173, 54, 78, 13, 67, 63, 220, 113, 194, 222, 162, 28,
        255, 2, 185, 193, 73, 243, 65, 149, 140, 109, 63, 132, 183, 43, 138, 40, 253, 30, 40, 101,
        222, 16, 199, 216, 59, 228, 188, 175, 85, 32, 97, 214, 73, 238, 99, 94, 109, 207, 254, 198,
        104, 100, 76, 108, 166, 154, 6, 64, 68, 52, 250, 251, 57, 84, 71, 139, 60, 29, 86, 197,
        162, 50, 145, 68, 173, 175, 185, 116, 223, 156, 255, 97, 85, 74, 135, 59, 123, 4, 122, 238,
        156,
    ];
    let signature_u8: &[u8] = &signature;
    // Unsignierte Daten einlesen
    /*     println!("\nPlease enter the raw data: \n");
    let mut raw = String::new();
    let _ = std::io::stdin().read_line(&mut raw);
    */
    let raw = "Hello, World";
    let encrypted_bytes = raw.trim().as_bytes();

    // Signatur verifizieren
    let mut verifier =
        RSAVerifier::new(MessageDigest::sha256(), &key_pkey).expect("failed to create verifier");
    verifier
        .update(encrypted_bytes)
        .expect("failed to update verifier");
    verifier
        .verify(signature_u8)
        .expect("failed to verify signature")
}

// Daten hashen nach beliebigem Algorithmus
fn hash_data(data: Vec<u8>, hash_algo: &str) -> Vec<u8> {
    if hash_algo == "SHA256" {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let data = hasher.finalize();
        data.to_vec()
    } else if hash_algo == "MD5" {
        let mut hasher = Md5::new();
        hasher.update(data);
        let hashed = hasher.finalize();
        println!("{:?}", hashed);
        println!("{}", general_purpose::STANDARD.encode(&hashed));
        hashed.to_vec()
    } else {
        println!("Hash algorithm not supported.");
        Vec::new()
    }
}

fn sign(device: &mut YubiKey) {
    println!("\nPlease enter the data to sign: \n");
    let mut data = String::new();
    let _ = std::io::stdin().read_line(&mut data);

    //   let length = data.len();

    let data_vec = data.trim().as_bytes().to_vec();

    // Input wird gehasht
    let hashed = hash_data(data_vec, "SHA256");
    let hashed_u8: &[u8] = &hashed;

    // Padding wird zum Hash hinzugefügt
    let padded_data = apply_pkcs1v15_padding(hashed_u8, 256);

    let padded_u8: &[u8] = &padded_data;

    // new key for signing in Signature-Slot
    let generated_key = gen_key(device, AlgorithmId::Rsa2048, SlotId::Signature);
    let formatted_key = format_key(generated_key);
    encode_key(formatted_key);

    //TODO richtige Pineingabe einfügen
    let _ = device.verify_pin("123456".as_ref());
    let _ = device.authenticate(MgmKey::default());

    // Signatur durchführen
    let signature = piv::sign_data(
        device,
        padded_u8,
        piv::AlgorithmId::Rsa2048,
        piv::SlotId::Signature,
    );

    match signature {
        Ok(buffer) => {
            /* let signature_vec = buffer.to_vec();
            let signature_u8: &[u8] = signature_vec.as_slice();
            println!("\nSignature: \n{:?}", signature_u8);
            let unpadded = remove_pkcs1_padding(signature_u8, 32);
            println!("{:?}", general_purpose::STANDARD.encode(&unpadded));
            */
            println!(
                "\nSignature: \n\n{}",
                general_purpose::STANDARD.encode(&buffer)
            );
        }
        Err(err) => println!("\nFailed to sign: \n{:?}", err),
    }
}

fn encrypt_rsa(rsa_string: String) -> String {
    println!("\nPlease enter the data to encrypt: \n");
    let mut data = String::new();
    let _ = std::io::stdin().read_line(&mut data);
    let data = data.trim();
    let data = data.as_bytes();

    let rsa = Rsa::public_key_from_pem(rsa_string.as_bytes())
        .expect("failed to create RSA from public key PEM");

    let mut encrypted_data = vec![0; rsa.size() as usize];
    rsa.public_encrypt(data, &mut encrypted_data, Padding::PKCS1)
        .expect("failed to encrypt data");
    let encrypted_data_base64 = general_purpose::STANDARD.encode(encrypted_data);
    println!("\n\nEncrypted Data: {:?}", encrypted_data_base64);
    encrypted_data_base64
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
        Ok(buffer) => match remove_pkcs1_padding(&buffer) {
            Ok(data) => {
                let string = String::from_utf8_lossy(&data);
                println!("\nDecrypted (lossy): \n{}", string);
            }
            Err(err) => println!("Padding error: {}", err),
        },
        Err(err) => println!("\nFailed to decrypt: \n{:?}", err),
    }
}

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
fn encode_key(key: Vec<u8>) -> String {
    // KEy in Base64 umwandeln
    let mut key_b64 = general_purpose::STANDARD.encode(&key);
    key_b64 = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        key_b64.trim()
    );
    println!("\n\nPEM-Key:\n\n{}", key_b64);
    return key_b64;
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
