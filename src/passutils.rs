use std::{fs, io::{Error, ErrorKind}};
use rand::{rngs::OsRng, Rng, RngCore};
use openssl::{symm::{decrypt, encrypt, Cipher}, sha::Sha256};
use base64::{prelude::BASE64_STANDARD, Engine};

pub struct  PasswordEntry{
    pub key: [u8; 32],
    pub site_name: String,
    pub password: String
}

impl PasswordEntry{
    pub fn new(key: &[u8; 32], site_name: &String, password: &String) -> PasswordEntry{
        Self { key: key.clone(), site_name: site_name.to_string(), password: password.to_string() }
    }

    // encrypts the password and returns the base64-encoded ciphertext
    pub fn export_b64(&self) -> Result<String, Error>{
        let plaintext = format!("{}~{}", self.site_name, self.password);
        let ciphertext = encrypt_authenticated(&plaintext, &self.key)?;
        Ok(BASE64_STANDARD.encode(ciphertext))
    }
}

// finds the index of a password in a vector of PasswordEntries, given the site name
pub fn find_pw_index(passwords: &Vec<PasswordEntry>, target: &String) -> Option<usize>{
    for i in 0..passwords.len(){
        if passwords[i].site_name == *target{
            return Some(i);
        }
    }
    None
}

// genrates a new password of length n, using only characters in the provided charset, writes the password to the provided string
pub fn generate_password(n: u64, allow_lower: bool, allow_upper: bool, allow_digits: bool, allow_special: bool, password: &mut String){
    // determine the allowed character set
    let mut charset_str = String::new();
    if allow_lower{
        charset_str += "abcdefghijkmnopqrstuvwxyz";
    }
    if allow_upper{
        charset_str += "ABCDEFGHJIKLMNOPQRSTUVWXYZ";
    }
    if allow_digits{
        charset_str += "1234567890";
    }
    if allow_special{
        charset_str += "!@#$%^&*()-=+_\"';:,./\\"
    }
    let charset: Vec<char> = charset_str.chars().collect();
    let mut rng = OsRng;
    let len = charset.len();
    for _ in 0..n{
        password.push(charset[rng.gen_range(0..len)]);
    }
}

// generates a random 32-bit-key for encryption
pub fn generate_key(key: &mut [u8; 32]){
    let mut rng = OsRng;
    rng.fill_bytes(key);
}

// encrypts a plaintext string and returns the ciphertext as bytes, with the IV and a checksum prepended to it
fn encrypt_authenticated(plaintext_str: &String, key: &[u8; 32]) -> Result<Vec<u8>, Error>{
    let plaintext = plaintext_str.as_bytes();
    // create the cipher
    let mut rng = OsRng;
    let mut iv:[u8; 16] = [0; 16];
    rng.fill_bytes(&mut iv);
    let cipher = Cipher::aes_256_cbc();
    // encrypt the plaintext and return the ciphertext if encryption is succesful
    match  encrypt(cipher, key, Some(&iv), plaintext){
        Ok(mut ciphertext) => {
            // create a checksum of the plaintext
            let mut checksum_hash = Sha256::new();
            checksum_hash.update(plaintext);
            // append the checksum and iv to the ciphertext
            let mut result: Vec<u8> = checksum_hash.finish().into_iter().collect();
            result.append(&mut iv.into_iter().collect());
            result.append(&mut ciphertext);
            Ok(result)
        }
        Err(_) => {Err(Error::new( ErrorKind::InvalidData, "Failed to encrypt the plaintext"))}
    }
}

// decrypts a ciphertext in bytes, and returns the decrypted string
fn decrypt_authenticated(ciphertext: &Vec<u8>, key: &[u8; 32]) -> Result<String, Error>{
    if ciphertext.len() < 17{
        return  Err(Error::new(ErrorKind::InvalidData, "Invalid Ciphertext"));
    }
    // seperate the ciphertext  into its components
    let len = ciphertext.len();         
    let checksum = &ciphertext[0..32];
    let iv = &ciphertext[32..48];
    let ciphertext_raw: &[u8] = &ciphertext[48..len];
    // attempt to decrypt the ciphertext                        
    let cipher = Cipher::aes_256_cbc();
    let plaintext: Vec<u8>;
    match decrypt(cipher, key, Some(iv), ciphertext_raw) {
        Ok(tmp) => {plaintext = tmp}
        Err(_) => {return  Err(Error::new(ErrorKind::InvalidData, "Cannot decrypt the ciphertext"));}
    }
    // validate the checksum
    let mut plaintext_hash = Sha256::new();
    plaintext_hash.update(&plaintext);
    if plaintext_hash.finish() == checksum{
        Ok(String::from_utf8(plaintext).unwrap())
    }
    else{
        Err(Error::new(ErrorKind::InvalidInput, "Failed to decrypt the ciphertext (likely an invalid key)"))
    }
}

// decrypts an encrypted base64 string of a password and returns the correpsonding PassEntry
fn decrypt_password(ciphertext: String, key: &[u8; 32]) -> Result<PasswordEntry, Error>{
    let cipher_bytes: Vec<u8>;
    match BASE64_STANDARD.decode(ciphertext){
        Ok(tmp) => {cipher_bytes = tmp}
        Err(_) => {return Err(Error::new(ErrorKind::InvalidInput, "Invalid ciphertext string"))}
    }
    let plaintext = decrypt_authenticated(&cipher_bytes, key)?;
    let segments: Vec<&str> = plaintext.split("~").collect();
    if segments.len() != 2{
        Err(Error::new(ErrorKind::InvalidData, "Invalid password entry"))
    }
    else{
        Ok(PasswordEntry::new(&key, &segments[0].to_string(), &segments[1].to_string()))
    }
}

// encrypts a vector of password entries, and writes them to a file, along with the metadata
pub fn export_password_file(file_path: &String, master_password: String, passwords: Vec<PasswordEntry>) -> Result<(), Error>{
    // create a master key from the master password, as well as a random iv
    let mut rng = OsRng;
    let mut key_salt: [u8; 16] = [0; 16];
    let mut master_iv: [u8; 16] = [0; 16];
    rng.fill_bytes(&mut key_salt);
    rng.fill_bytes(&mut master_iv);
    let mut key_hash = Sha256::new();
    key_hash.update(master_password.as_bytes());
    key_hash.update(&key_salt);
    let master_key = key_hash.finish();
    // encrypt each password, storing the key and adding the ciphertext to a single string
    let mut password_list = String::new();
    let mut key_block: Vec<u8> = Vec::new();
    for i in passwords{
        key_block.append(&mut i.key.to_vec());
        password_list += format!("{};", i.export_b64()?).as_str();
    }
    // encrypt the key block
    let key_cipher = Cipher::aes_256_cbc();
    let kb_ciphertext: Vec<u8>;
    match encrypt(key_cipher, &master_key, Some(&master_iv), &key_block){
        Ok(tmp) => {kb_ciphertext = tmp}
        Err(_) => {return Err(Error::new(ErrorKind::InvalidData, "Invalid Password Keys"))}
    }
    // create a checksum of the master key
    let mut checksum_salt: [u8; 16] = [0; 16];
    rng.fill_bytes(&mut checksum_salt);
    let mut checksum_hash = Sha256::new();
    checksum_hash.update(&master_key);
    checksum_hash.update(&checksum_salt);
    let checksum = checksum_hash.finish();
    // create and base64 encode the file header
    let mut file_header: Vec<u8> = Vec::new();
    file_header.append(&mut master_iv.to_vec());
    file_header.append(&mut key_salt.to_vec());
    file_header.append(&mut checksum.to_vec());
    file_header.append(&mut checksum_salt.to_vec());
    let header_str = BASE64_STANDARD.encode(file_header);
    // write the data to the password file
    fs::write(file_path, format!("{};{};{}", header_str, BASE64_STANDARD.encode(kb_ciphertext), password_list))?;
    Ok(())
} 

pub fn import_password_file(file_path: &String, master_password: &String) -> Result<Vec<PasswordEntry>, Error>{
    let tmp: String;
    match fs::read_to_string(file_path) {
        Ok(content) => {tmp = content}
        Err(_) => {return  Err(Error::new(ErrorKind::InvalidInput, "Cannot read the password database file (Does it exist?)"));}
    }
    // parse the contents
    let segments: Vec<&str> = tmp.split(';').collect();
    if segments.len() < 2{
        return  Err(Error::new(ErrorKind::InvalidInput, "Invalid password database file"));
    }
    let header = BASE64_STANDARD.decode(segments[0]).expect("Invalid base64 string");
    let kb_ciphertext = BASE64_STANDARD.decode(segments[1]).expect("Invalid base64 string");
    // parse the header
    let iv = &header[0..16];
    let key_salt = &header[16..32];
    let checksum = &header[32..64];
    let checksum_salt = &header[64..header.len()];
    // hash the key
    let mut key_hash = Sha256::new();
    key_hash.update(master_password.as_bytes());
    key_hash.update(key_salt);
    let master_key = key_hash.finish();
    // validate the key
    let mut checksum_hash = Sha256::new();
    checksum_hash.update(&master_key);
    checksum_hash.update(&checksum_salt);
    let key_checksum = checksum_hash.finish();
    if checksum != key_checksum{
        return  Err(Error::new(ErrorKind::Other, "Incorrect password"));
    }
    // decrypt the key block
    let key_cipher = Cipher::aes_256_cbc();
    let keyblock: Vec<u8>;
    match decrypt(key_cipher, &master_key, Some(&iv), &kb_ciphertext) {
        Ok(tmp_bytes) => {keyblock = tmp_bytes}
        Err(_) => {return Err(Error::new(ErrorKind::Other, "Invalid key block"));}
    }
    // decrypt each password
    let mut passwords: Vec<PasswordEntry> = Vec::new();
    let keys: Vec<&[u8]> = keyblock.chunks(32).collect();
    let mut tmp_key: [u8; 32];
    for i in 0..keys.len(){
        tmp_key = keys[i].try_into().expect("Invalid Keyblock");
        passwords.push(decrypt_password(segments[i + 2].to_string(), &tmp_key)?);
    }
    Ok(passwords)
}