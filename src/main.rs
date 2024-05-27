use base64::{engine::general_purpose, Engine};
use md5::{Digest, Md5};
use openssl::ec::EcKey;
use openssl::ecdsa::EcdsaSigRef;
use openssl::pkey::{PKeyRef, Public};
use openssl::rsa::{Padding, Rsa};
use openssl::sign::Verifier;
use openssl::{hash::MessageDigest, pkey::PKey};
use openssl::{pkey, sign};
use ring::signature;
use rsa::sha2;
//use rsa::signature::Verifier;
use rsa::pss;
use sha2::Sha256;
use x509_cert::der::{self, Encode};
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
        println!("8. Save Object");
        println!("9. Load Object");
        println!("10. End");
        println!("----------------------\n");
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);

        match input.to_string().trim() {
            "1" => {
                println!("1. for RSA 2048, 2. for ECC 256");
                let mut cipher = String::new();
                let _ = std::io::stdin().read_line(&mut cipher);

                match cipher.to_string().trim() {
                    "1" => {
                        let cipher = AlgorithmId::Rsa2048;
                        let generated_key = gen_key(&mut yubikey, cipher, SlotId::KeyManagement);
                        rsa_pub_key = encode_key(generated_key.as_ref().unwrap().to_der().unwrap());
                        println!("\n\nPEM-Key:\n\n{}", rsa_pub_key);
                    }
                    "2" => {
                        let cipher = AlgorithmId::EccP256;
                        let generated_key = gen_key(&mut yubikey, cipher, SlotId::KeyManagement);
                        let ecc_pub_key =
                            encode_key(generated_key.as_ref().unwrap().to_der().unwrap());
                        println!("\n\nECC-Key:\n\n{}", ecc_pub_key);
                    }
                    _ => {
                        println!("\nUnknown Input!\n");
                    }
                }
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
                if input_verify_signature_ecc() {
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
                save_object(&mut yubikey);
            }
            "9" => {
                load_object(&mut yubikey);
            }
            "10" => {
                break;
            }

            _ => {
                println!("\nUnknown Input!\n");
            }
        }
    }
}

fn save_object(device: &mut YubiKey) {

    println!("\nPlease enter the ID where to save: \n");
    let mut id = String::new();
    let _ = std::io::stdin().read_line(&mut id);
    let parsed = id.parse::<u32>();
    let mut output: u32;
    match parsed {
        Ok(out) => {output = out;}
        Err(_) => {
            println!("ID must be a number.");
            return;
        }
    }

    let key_name = "test";
    let slot = "R1";
    let public_key = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuevHUr57tn1484nOQH48mtxc7KcauhYIbQsEnA1G9VZ8QlLTDx+QfQAjquBhlFrbRdoIVNUBKt2EVmjwjZdVndnfuxx7OPDKB/PYil2XoL4VaEliT9FyxQnV8usdEACmBe5sAXo9A0mkhbK/i3VYOZVjvac9bk2k+EtEyrFegCLrL8HjfdiHcj2eyCBqmKFIn4kAigAvFixiffb19kDMkDV/n6Hf9m7ZAZJW6lJ8uBxfEi7AM4gCDniDPHy9EfcXI4HY9vUFWWCrHEr6Aq7zXGin68Sx7G5Oj878hhMQ2H7JnCLWp/pOiPe2cQ2rE1j/kFLFdTzXhJR/K9oPx3+h0QIDAQAB
-----END PUBLIC KEY-----";
    let key_usage = "sign";
    
    let total_length = key_name.len() + 1 + slot.len() + 1 + key_usage.len() + 1 + public_key.len();
    let mut data = vec![0u8; total_length]; // Verwendung eines Vektors zur Initialisierung
    let data_slice: &mut [u8] = &mut data;

    // Kopieren der Daten in den Slice
    let mut offset = 0;
    data_slice[offset..offset + key_name.len()].copy_from_slice(key_name.as_bytes());
    offset += key_name.len();
    data_slice[offset] = 0;
    offset += 1;

    data_slice[offset..offset + slot.len()].copy_from_slice(slot.as_bytes());
    offset += slot.len();
    data_slice[offset] = 0;
    offset += 1;

    data_slice[offset..offset + key_usage.len()].copy_from_slice(key_usage.as_bytes());
    offset += key_usage.len();
    data_slice[offset] = 0;
    offset += 1;

    data_slice[offset..offset + public_key.len()].copy_from_slice(public_key.as_bytes());


    device.save_object(output, data_slice);

}

fn load_object(device: &mut YubiKey) {
    println!("\nPlease enter the ID where to load: \n");
    let mut id = String::new();
    let _ = std::io::stdin().read_line(&mut id);
    let parsed = id.parse::<u32>();
    let mut output: u32;
    match parsed {
        Ok(out) => {output = out;}
        Err(_) => {
            println!("ID must be a number.");
            return;
        }
    }
    
    let data = device.fetch_object(output);
    let output;
    match data {
        Ok(data) => {
            
        }
        Err(err) => {
            println!("Error: {:?}", err);
        }
    }


    let data = &output;

    let parts: Vec<&[u8]> = data.split(|&x| x == 0).collect();
    let key_name = std::str::from_utf8(parts[0]).unwrap();
    let slot = std::str::from_utf8(parts[1]).unwrap();
    let key_usage = std::str::from_utf8(parts[2]).unwrap();
    let public_key = std::str::from_utf8(parts[3]).unwrap();
}

#[warn(dead_code)]
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

fn input_verify_signature_ecc() -> bool {
    // Public Key
    let ecc = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtVB1xU4TnsQtkwyjjlbievbEM1P4j8a7ASQHYuxRZ7RPAbecYH/rZy8oxc9szz+w3GQmlAYkRcg2mJMgu3WEVg==\n-----END PUBLIC KEY-----";

    let ecc = EcKey::public_key_from_pem(ecc.trim().as_bytes()).expect("Fehler");
    let ecc = PKey::from_ec_key(ecc).expect("Fehler");
    /*let ecc = EcKey::public_key_from_pem(ecc.trim().as_bytes())
            .expect("failed to create RSA from public key PEM");
        let key_pkey = ecc.ec_key.unwrap();
    */
    // Signatur als Base64
    let signature = "MEUCIFOrea/ipZESd1RP1MJO7Sn8RSD4H5Z5ZiqKdxPyaTLMAiEA+7iu9YR23lyErrWF+q8SzKS5WrpdOxkj4AYENEf7UPg=";
    let signature = general_purpose::STANDARD
        .decode(signature.as_bytes())
        .unwrap();
    let signature_u8 = signature.as_slice();

    // Msg
    let raw = b"test";

    let mut verifier =
        Verifier::new(MessageDigest::sha256(), &ecc).expect("failed to create verifier");
    verifier.update(raw).expect("failed to update verifier");
    verifier
        .verify(signature_u8)
        .expect("failed to verify signature")
}

fn input_verify_signature() -> bool {
    /*
        // Public Key einlesen
        println!("\nPlease enter the public Key: \n");
        let mut data = String::new();
        let _ = std::io::stdin().read_line(&mut data);
        let rsa = Rsa::public_key_from_pem(data.trim().as_bytes())
            .expect("failed to create RSA from public key PEM");
        let key_pkey = PKey::from_rsa(rsa).unwrap();

        // Signatur einlesen
        println!("\nPlease enter the signature: \n");
        let mut signed = String::new();
        let _ = std::io::stdin().read_line(&mut signed);
        let signature = general_purpose::STANDARD
        .decode(signed.as_bytes())
        .unwrap();
        let signed_u8 = signature   .trim().as_bytes();

        // Unsignierte Daten einlesen
        println!("\nPlease enter the raw data: \n");
        let mut raw = String::new();
        let _ = std::io::stdin().read_line(&mut raw);
        let raw = raw.as_bytes();

        let verify = rsa_verify_signature(signed_u8, &key_pkey, raw);
        verify
    */
    ///////////////////////////////////////////////
    ////////////// Hardcoded //////////////////////
    ///////////////////////////////////////////////

    // Public Key
    let rsa = "-----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuevHUr57tn1484nOQH48mtxc7KcauhYIbQsEnA1G9VZ8QlLTDx+QfQAjquBhlFrbRdoIVNUBKt2EVmjwjZdVndnfuxx7OPDKB/PYil2XoL4VaEliT9FyxQnV8usdEACmBe5sAXo9A0mkhbK/i3VYOZVjvac9bk2k+EtEyrFegCLrL8HjfdiHcj2eyCBqmKFIn4kAigAvFixiffb19kDMkDV/n6Hf9m7ZAZJW6lJ8uBxfEi7AM4gCDniDPHy9EfcXI4HY9vUFWWCrHEr6Aq7zXGin68Sx7G5Oj878hhMQ2H7JnCLWp/pOiPe2cQ2rE1j/kFLFdTzXhJR/K9oPx3+h0QIDAQAB
-----END PUBLIC KEY-----    
    "
    ;

    let rsa = Rsa::public_key_from_pem(rsa.trim().as_bytes())
        .expect("failed to create RSA from public key PEM");
    let key_pkey = PKey::from_rsa(rsa).unwrap();
    /*
        // Signatur als Bytes
        let signature = [
            106, 110, 3, 220, 35, 146, 221, 88, 230, 118, 157, 167, 59, 178, 211, 24, 48, 72, 213, 85,
            175, 231, 3, 79, 21, 244, 152, 250, 105, 237, 220, 74, 43, 45, 216, 105, 183, 204, 131,
            149, 160, 252, 155, 208, 54, 138, 230, 122, 40, 126, 58, 23, 56, 221, 26, 7, 162, 47, 49,
            246, 152, 157, 55, 24, 160, 239, 147, 125, 35, 219, 143, 253, 103, 228, 156, 160, 99, 18,
            61, 119, 146, 236, 39, 53, 67, 130, 188, 147, 108, 168, 233, 34, 253, 176, 207, 46, 143,
            236, 24, 57, 8, 151, 179, 218, 239, 106, 174, 86, 156, 25, 4, 47, 182, 69, 21, 130, 94,
            212, 85, 118, 152, 152, 107, 126, 15, 238, 199, 82, 89, 202, 55, 223, 76, 214, 209, 233,
            178, 185, 24, 58, 144, 220, 188, 219, 230, 54, 121, 37, 123, 24, 153, 162, 158, 76, 66, 92,
            172, 35, 247, 248, 101, 111, 80, 136, 229, 1, 27, 133, 37, 228, 196, 145, 1, 172, 245, 96,
            154, 115, 224, 245, 159, 144, 185, 104, 142, 193, 241, 255, 17, 176, 249, 225, 91, 153,
            247, 16, 37, 10, 84, 111, 78, 190, 181, 158, 198, 124, 108, 33, 143, 139, 44, 125, 33, 140,
            29, 119, 134, 6, 195, 138, 154, 215, 184, 208, 47, 60, 56, 43, 29, 1, 0, 227, 253, 47, 77,
            6, 56, 189, 32, 169, 153, 134, 145, 5, 212, 47, 224, 50, 64, 227, 73, 1, 105, 223, 84, 7,
        ];
        let signature_u8: &[u8] = &signature;
    */
    // Signatur als Base64
    let signature = "nKfoSn3+tIgup24MnIQ32VRXBvwuaAvMBEJr6JqGsXvqVQy7Pr3Ya2zST3OuvV9C8BBjH1BalvNodWH74sYpc9Vcjm76r9UqthxrzsIeYiO9TLleZv2NaOTfGk5syVHe8vWyiIOXAaGVGRuflWXbcytqj9oTun5mp9s78dt84e6DhA70BCM/k/sf0ZHFbHyytRba5jcyCtcEzrenLbE/jx/8jh7mp3nb2r5lS9N5Z55LR9zzwcbh8VyfYCbidfjcYWzxGdIJKIQhnYAIAl2Fu0qTWr90mvm4t5mm+ShplidkStQavuSuqyYTJZhVICM2sPGY0W68IlIr7VrQzjM76Q==";
    let signature = general_purpose::STANDARD
        .decode(signature.as_bytes())
        .unwrap();
    let signature_u8 = signature.as_slice();

    // Msg
    let raw = "test";
    let encrypted_bytes = raw.as_bytes();

    let verify = rsa_verify_signature(signature_u8, &key_pkey, encrypted_bytes);
    verify
}

fn rsa_verify_signature(signature: &[u8], pkey: &PKey<Public>, rsa_string: &[u8]) -> bool {
    let mut verifier =
        Verifier::new(MessageDigest::sha256(), &pkey).expect("failed to create verifier");
    verifier
        .update(rsa_string)
        .expect("failed to update verifier");
    verifier
        .verify(signature)
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

    // habe ich geprüft: Umwandlung findet richtig statt
    let data_vec = data.trim().as_bytes().to_vec();
    println!("{:?}", data_vec);

    // Hashing wird richtig ausgeführt
    // Input wird gehasht
    let hashed = hash_data(data_vec, "SHA256");
    let hashed_u8: &[u8] = &hashed;

    println!("Hashed: {:?}", hashed_u8);
    println!("Hex: {:?}", hex::encode(hashed_u8));

    // Fehler im Padding selbst?
    // Padding wird zum Hash hinzugefügt
    //    let padded_data = apply_pkcs1v15_padding(hashed_u8, 256);
    //    println!("{:?}", padded_data);
    //    let padded_u8: &[u8] = &padded_data;

    // wenn ich das auskommentiere, wird selbe Signatur erzeugt -> Es wird nicht automatisch neuer Key generiert
    // new key for signing in Signature-Slot
    let generated_key = gen_key(device, AlgorithmId::EccP256, SlotId::Signature);
    //  let formatted_key = format_key(generated_key);
    let rsa_pub_key = encode_key(generated_key.as_ref().unwrap().to_der().unwrap());
    println!("\n\nPEM-Key:\n\n{}", rsa_pub_key);

    //TODO richtige Pineingabe einfügen
    let _ = device.verify_pin("123456".as_ref());
    let _ = device.authenticate(MgmKey::default());

    // Signatur durchführen
    let signature = piv::sign_data(
        device,
        hashed_u8,
        piv::AlgorithmId::EccP256,
        piv::SlotId::Signature,
    );

    match signature {
        Ok(buffer) => {
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
    //   println!("\n\nPEM-Key:\n\n{}", key_b64);
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
