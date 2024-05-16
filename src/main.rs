use base64::{engine::general_purpose, Engine};
use der::Encode;
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

                println!("\nBase64-Key:\n\n{}", rsa_pub_key);
                rsa_pub_key = format!(
                    "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
                    rsa_pub_key.trim()
                );
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
fn rsa_verify_signature(/*signature: &[u8], pkey: &PKey<Public>*/) -> bool {
    // Public Key einlesen
    println!("\nPlease enter the public key: \n");
    let mut key = String::new();
    let _ = std::io::stdin().read_line(&mut key);
    let key_decoded = general_purpose::STANDARD
        .decode(key.trim().as_bytes())
        .unwrap();
    // Umwandlung in u8 -> PKey
    let key_u8: &[u8] = key_decoded.as_slice();
    let key_inst = openssl::rsa::Rsa::public_key_from_der(key_u8).unwrap();
    let key_pkey = PKey::from_rsa(key_inst).unwrap();

    // Signatur einlesen
    println!("\nPlease enter the signature: \n");
    let mut signed = String::new();
    let _ = std::io::stdin().read_line(&mut signed);
    let signed_decoded = general_purpose::STANDARD
        .decode(signed.trim().as_bytes())
        .unwrap();
    let signed_u8: &[u8] = signed_decoded.as_slice();

    // Unsignierte Daten einlesen
    println!("\nPlease enter the raw data: \n");
    let mut raw = String::new();
    let _ = std::io::stdin().read_line(&mut raw);
    let encrypted_bytes = raw.trim_end().as_bytes();

    // Signatur verifizieren
    let mut verifier =
        RSAVerifier::new(MessageDigest::sha256(), &key_pkey).expect("failed to create verifier");
    verifier
        .update(encrypted_bytes)
        .expect("failed to update verifier");
    verifier
        .verify(signed_u8)
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
    println!("RSA String:\n{}", rsa_string);
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
    let key_b64 = general_purpose::STANDARD.encode(&key);
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
