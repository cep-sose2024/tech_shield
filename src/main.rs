use std::{f32::consts::E, io::Read, u32};

use base64::{engine::general_purpose, Engine};
use der::{asn1, oid::ObjectIdentifier, Decode, Encode, Error};
use picky_asn1::wrapper::ObjectIdentifierAsn1;
use picky_asn1_der::Asn1RawDer;
use x509_cert::spki::{SubjectPublicKeyInfo, SubjectPublicKeyInfoOwned};
use yubikey::{piv::{self, sign_data, AlgorithmId, Key, SlotId}, MgmKey, ObjectId, YubiKey};
//use pem::parse;
extern crate base64;
extern crate picky_asn1;
extern crate picky_asn1_der;
extern crate zeroize;
use zeroize::{Zeroize, Zeroizing};
use spki::SubjectPublicKeyInfo as leo;
use rsa::{RsaPrivateKey, BigUint};
//use crypto_layer;

//use picky_asn1::wrapper::ObjectIdentifierAsn1;
//use picky_asn1_der::Asn1Der;
//use picky_asn1_der::Asn1RawDer;

extern crate pkcs8;

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
//#####################################################
fn main() {
    let mut yubikey =  match open_device(){
        Ok(yubikey)=>yubikey,
        Err(e)=> {println!("{}",e); return;},
    };
    yubikey.authenticate(MgmKey::default());
    ///*
    //let gen_key = gen_key(&mut yubikey, piv::SlotId::Authentication, piv::AlgorithmId::Rsa2048);
    //println!("nicht formattiert: {:?}\n\n", &gen_key);
    //println!("formattiert: {}\n\n",format_key(gen_key));
    //let raw_in = "hohle birne hole bier ne? alla hopp, hoio arbeitszeiten rsa encryption projektsteuerung rsa decryption enter dencrypted text to base64(aga) dashborad startseite anmelden am asch maps youtube gmail devglan com enter public / private key bytebyteb";
    //let raw_in = raw_in.as_bytes();
    //let signiert = piv::sign_data(&mut yubikey, raw_in, piv::AlgorithmId::Rsa2048, piv::SlotId::Authentication);
    //println!("signiert: {:?}", signiert);

    /*////////
    let genn_key = gen_key.unwrap().to_der().as_ref().unwrap().to_vec();
    save_key(&mut yubikey, RETIRED_SLOT[0], genn_key);
    */////////



    //test rausholen
    ///*
    //clear_slot(&mut yubikey, None);
    println!("geckleared\n\n");
    for i in 0..20{
        println!("\nslot {i}: ");
        print!(" {:?}\n",yubikey.fetch_object(RETIRED_SLOT[i]));
    }

    println!("\nanfang: {:?}\n",gen_key(&mut yubikey, "omega".to_string(), piv::AlgorithmId::Rsa2048));
    let dada = fetch_key(&mut yubikey, AUTHENTICATION_SLOT);
    println!("Private Key: {:?}\n", dada);
    let dodo = fetch_key(&mut yubikey, RETIRED_SLOT[0]);
    println!("Public  Key: {:?}\n", dodo);

    /*
    let base64_encoded = base64::encode(dodo);
    let pem_string = format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", base64_encoded);
    println!("pem: \n{}\n",pem_string);

    let base64_encoded = base64::encode(dada);
    let pem_string = format!("-----BEGIN Private KEY-----\n{}\n-----END Private KEY-----\n", base64_encoded);
    println!("pem: \n{}\n",pem_string);
    */
    //println!("fetched: {:?}\n\n", format_key(Ok(dada)));
    //*/
    /*
        //test decrypt
        let encr_data = String::from("snsqtzqdXGfMyQfJCX4LZO6OPCxyWt4aY99IYtgm0GASYYMxf1lH3pyNrQ02MZ6pndiwHXlTCJDVdewF+312d1/Ou8szL+VZBzPbiAEN86HkfAaNF1dBVN+2zjCqVjO34TWSlcnhRgB51xOUx0V3LkRmLTTZjfbd8xQV6D/i9dDLuWOMBrM5LE69D0PGAH7uxdjrU5JDrUdgmMI5DleEo+ZHLqJMtofol0uhz17a4qtqbQa/I/WWgajP6sw4vtbMkHsAgle5jym548fmgMssH/Dmy09mDzNZM4LUUuL+1n9h7uaZbm60ZbILnu51LiKIIb0iwbRp3NYvQ1nwWylGOw==");
        let encr_data = encr_data.as_bytes();
        let decr_msg = decr_data(&mut yubikey, piv::SlotId::Authentication, piv::AlgorithmId::Rsa2048, encr_data);
        println!("decrypted: {:?}",decr_msg);
    */

    //*/
    //println!("{}",decr_data(&mut yubikey, piv::SlotId::Authentication, piv::AlgorithmId::Rsa2048, data));
    /*
    let uu = yubikey.fetch_object(AUTHENTICATION_SLOT);
    let uu = uu.unwrap().to_vec();
    let hex: String = uu.iter().map(|b| format!("{:04X}", b)).collect();
    let b64 = general_purpose::STANDARD.encode(&hex);
    println!("inhalt: {:?}\n\n",b64);
    */
    /*
    let data = vec![('c') as u8 ].to_vec();
    println!("signed {:?}", sign_datas(&mut yubikey, &data, piv::AlgorithmId::Rsa2048, piv::SlotId::Authentication));

    let message = b"Hello Markus";
    let signa = sign_datas(&mut yubikey, message, piv::AlgorithmId::Rsa2048, piv::SlotId::Authentication);
    println!("signiert {:?}", signa);
    */
    println!("fertig");

}

//fn load_key(&mut self, key_id: &str, key_algorithm: Asymmetric Encryption, sym_algorithm: Option<BlockCiphers>, hash: Option<Hash>, key_usages: Vec<KeyUsage>)->Result<(), SecurityModuleError>{}
/*let key = fetch_key(yubikey, oid );
    let key = key.to_der();
    let key = drop(key); */
fn get_key(yubikey: &mut YubiKey, key_id: &str)->Result<(),Error>{
    let oid = match get_oid(yubikey, key_id.as_bytes()[0]){
        Ok(zahl)=>zahl,
        Err(no_zahl)=>0_u32
    };
    let key = drop(fetch_key(yubikey, oid));
    Ok((key))
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

fn clear_slot(yubikey: &mut YubiKey, slot: Option<u32>){
    match slot{
        Some(address)=>{
            remv(address);
        },
        None=>{
            for address in RETIRED_SLOT{
                remv(address);
            }
        }
    }
}
fn write_addressbook(yubikey: &mut YubiKey, mut data: Vec<u8>){
    yubikey.save_object(DISCOVERY_OBJECT, &mut data);
}

fn remv(address: u32){
    let ptr = address as *mut u8;
    unsafe{
        std::ptr::write_bytes(ptr, 0, std::mem::size_of::<u8>());
    }
}

fn choose_slot(yubikey: &mut YubiKey)->u32{
    for i in 0..MAX_KEYS{
        if yubikey.fetch_object(RETIRED_SLOT[i]).unwrap().to_vec().is_empty(){
            return RETIRED_SLOT[i];
        }
    };
    clear_slot(yubikey, None);
    let mut new_addressbook: Vec<u8> = vec![0; 20];
    let new_addressbook_slice: &mut [u8] = &mut &mut new_addressbook[..];
    write_addressbook(yubikey, new_addressbook_slice.to_vec());
    RETIRED_SLOT[0]
}

fn save_key(yubikey: &mut YubiKey, id: String , mut key: Vec<u8>){
    //let mut keyy = key.to_vec();
    let id_as_bytes: &[u8] = id.as_bytes();
    let mut addressbook = yubikey.fetch_object(DISCOVERY_OBJECT).unwrap().to_vec();
    let mut i =0;
    loop {
        if addressbook[i] == 0{
            break;
        }
        i += 1;
    }
    let dest:u32 = RETIRED_SLOT[i];
    yubikey.save_object(dest,&mut key);
}
/* fn move_key(yubikey: &mut YubiKey, src:u32, dest:u32)->bool{
    let key = yubikey.fetch_object(src);

    //yubikey.save_object(key_as_vec, indata);

    return true;
}*/

//Result<SubjectPublicKeyInfoOwned, der::Error>
fn fetch_key(yubikey: &mut YubiKey, oid: u32)->Vec<u8>{
    let ausgelesen = yubikey.fetch_object(oid);
    let key = ausgelesen.unwrap().to_vec();
    //println!("\n\nKI: {:?}\n\n", ki);
    //let ret= SubjectPublicKeyInfo::from_der(&ki);
    return key;
}
/* fn build_private_key(bytes: Zeroizing<Vec<u8>>) -> Result<PrivateKey, Error> {
    // Extrahiere die einzelnen Teile des privaten Schlüssels aus dem Byte-Array
    // Beispiel: Modul, privater Exponent, öffentlicher Exponent, ...
    let modulus = BigUint::from_bytes_be(&bytes[2..130]);
    let private_exponent = BigUint::from_bytes_be(&bytes[134..266]);
    let public_exponent = BigUint::from_bytes_be(&bytes[270..274]);

    // Konstruiere den privaten Schlüssel aus den extrahierten Teilen
    let private_key = RsaPrivateKey::from_components(modulus, private_exponent)?;

    Ok(private_key)
}*/


//->Vec<u8>
fn sign_datas(yubikey: &mut YubiKey, data:&[u8] , algorithm:piv::AlgorithmId, slot:piv::SlotId)->Result<Zeroizing<Vec<u8>>, yubikey::Error>{
    let signature = piv::sign_data(yubikey,
                                   data,
                                   algorithm,
                                   slot);
    // let ret = signature.unwrap().as_slice().to_vec();
    // let ret = signature.unwrap().to_vec();
    return signature;
}

/*
let a = vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
let b = &a; // b: &Vec<u8>
let c: &[u8] = &a; // c: &[u8]
 */
// Vec<u8>
fn decr_data(yubikey: &mut YubiKey, slot:piv::SlotId, algorithm:piv::AlgorithmId, encr_data: &[u8]) ->Zeroizing<Vec<u8>>{
    let decrypted_data = piv::decrypt_data(yubikey, encr_data, algorithm, slot).unwrap();
    return decrypted_data;
}

fn format_key(gen_key: Result<SubjectPublicKeyInfoOwned, yubikey::Error>) -> String {
    //es wäre auch STANDRAD_NO_PAD möglich
    general_purpose::STANDARD.encode(gen_key.as_ref().unwrap().to_der().unwrap())
}

fn gen_key(yubikey:&mut YubiKey, key_id: String, algorithm:piv::AlgorithmId ) -> Result<SubjectPublicKeyInfoOwned, yubikey::Error>{

    let key_id_as_bytes: &[u8] = key_id.as_bytes();
    let mut addressbook = yubikey.fetch_object(DISCOVERY_OBJECT).unwrap().to_vec();
    let mut i =0;
    loop {
        if addressbook[i] == 0{
            break;
        }
        i += 1;
    }
    addressbook[i]=key_id_as_bytes[0];

    i+=1;
    let slot = match i {
        1 => piv::SlotId::Retired(piv::RetiredSlotId::R1),
        2 => piv::SlotId::Retired(piv::RetiredSlotId::R2),
        3 => piv::SlotId::Retired(piv::RetiredSlotId::R3),
        4 => piv::SlotId::Retired(piv::RetiredSlotId::R4),
        5 => piv::SlotId::Retired(piv::RetiredSlotId::R5),
        6 => piv::SlotId::Retired(piv::RetiredSlotId::R6),
        7 => piv::SlotId::Retired(piv::RetiredSlotId::R7),
        8 => piv::SlotId::Retired(piv::RetiredSlotId::R8),
        9 => piv::SlotId::Retired(piv::RetiredSlotId::R9),
        10 => piv::SlotId::Retired(piv::RetiredSlotId::R10),
        11 => piv::SlotId::Retired(piv::RetiredSlotId::R11),
        12 => piv::SlotId::Retired(piv::RetiredSlotId::R12),
        13 => piv::SlotId::Retired(piv::RetiredSlotId::R13),
        14 => piv::SlotId::Retired(piv::RetiredSlotId::R14),
        15 => piv::SlotId::Retired(piv::RetiredSlotId::R15),
        16 => piv::SlotId::Retired(piv::RetiredSlotId::R16),
        17 => piv::SlotId::Retired(piv::RetiredSlotId::R17),
        18 => piv::SlotId::Retired(piv::RetiredSlotId::R18),
        19 => piv::SlotId::Retired(piv::RetiredSlotId::R19),
        20 => piv::SlotId::Retired(piv::RetiredSlotId::R20),
        _ =>piv::SlotId::Signature
    };

    let gen_key = piv::generate(
        yubikey,
        slot,
        algorithm,
        yubikey::PinPolicy::Never,
        yubikey::TouchPolicy::Never);
    //bearbeiten
    return gen_key;
}

fn open_device() -> Result<YubiKey, String>{
    let yubikey = YubiKey::open();
    if yubikey.is_ok(){
        Ok(yubikey.unwrap())
    } else {
        Err(String::from("No YubiKey device was found."))
    }
}
/*
#[derive(Asn1Der)]
struct AlgorithmIdentifier{
    algorithm: ObjectIdentifierAsn1,
    parameters: Option<Asn1RawDer>
}
#[derive(Asn1Der)]
struct SubjectPublicKeyInfo{
    algorithm: AlgorithmIdentifier,
    subject_public_key: Asn1RawDer
}*/

//++++++++++++++++++++++++++++++temporär
/*
struct SecurityModule {
    keys: Vec<Key>
}
struct KeyKey {
    id: String,
    algorithm: AsymmetricEncryption,
    sym_algorithm: Option<BlockCiphers>,
    hash: Option<Hash>,
    usages: Vec<KeyUsage>,
}
impl SecurityModule{
    pub fn load_key(
        &mut self,
        key_id: &str,
        key_algorithm: AsymmetricEncryption,
        sym_algorithm: Option<BlockCiphers>,
        hash: Option<Hash>,
        key_usages: Vec<KeyUsage>,
    ) -> Result<(), SecurityModuleError> {
        // Überprüfen, ob der Schlüssel bereits existiert
        if self.keys.iter().any(|key| key.id == key_id) {
            return Err(SecurityModuleError::KeyAlreadyExists);
        }

        // Erstellen des neuen Schlüssels
        let new_key = KeyKey {
            id: key_id.to_string(),
            algorithm: key_algorithm,
            sym_algorithm,
            hash,
            usages: key_usages,
        };

        // Hinzufügen des neuen Schlüssels zur Liste der Schlüssel
        self.keys.push(new_key);

        Ok(())
    }
}
// Beispiel für die Definition von SecurityModuleError
#[derive(Debug)]
enum SecurityModuleError {
    KeyAlreadyExists,
    // Weitere Fehlerfälle hier hinzufügen
}

// Beispiel für die Definition der AsymmetricEncryption, BlockCiphers, Hash, KeyUsage
enum AsymmetricEncryption {
    RSA,
    ECDSA,
    // Weitere Algorithmen hier hinzufügen
}

enum BlockCiphers {
    AES,
    DES,
    // Weitere Algorithmen hier hinzufügen
}

enum Hash {
    SHA256,
    SHA512,
    // Weitere Algorithmen hier hinzufügen
}

enum KeyUsage {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    // Weitere Nutzungen hier hinzufügen
}
fn testen(){
    let mut sec = SecurityModule{keys: Vec::new()};
    match sec.load_key("key1",
    AsymmetricEncryption::RSA,
    Some(BlockCiphers::AES),
    Some(Hash::SHA256),
    vec![KeyUsage::Encrypt, KeyUsage::Sign]){
        Ok(())=>println!("Hat funktioniert"),
        Err(e)=> println!("Hat nicht funktioniert, ups {:?}",e)
    }
}
*/
//----------------------------------temporär
/*fn load_key(yubikey: &mut YubiKey, key_id: &str, key_algorithm: AsymmetricEncryption, sym_algorithm: Option<BlockCiphers>, hash: Option<Hash>, key_usages: Vec<KeyUsage>)->Result<(),SecurityModuleError>{
return
} */

/*let mut indata = gen_key.clone().unwrap().to_der().unwrap();
        let mut indata = indata.as_mut_slice();
        yubikey.save_object(RETIRED_SLOT[0], &mut indata); */