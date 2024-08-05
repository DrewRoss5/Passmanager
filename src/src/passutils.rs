use std::{fs, io::{Error, ErrorKind}};
use rand::{rngs::OsRng, Rng, RngCore};
use openssl::{symm::{decrypt, encrypt, Cipher}, sha::Sha256};
use base64::{prelude::BASE64_STANDARD, Engine};
use chrono;

// positions of the items in a vector of a password file heade
const IV_POS: usize = 0;
const KEY_SALT_POS: usize = 1;
const CHECKSUM_POS: usize = 2;
const CHECKSUM_SALT_POS: usize = 3;

pub struct  PasswordEntry{
    pub key: [u8; 32],
    pub site_name: String,
    pub password: String,
    pub create_date: String,
    pub modify_date: String,
    pub note: String,
    pub username: String,
    pub url: String
}

impl PasswordEntry{
    pub fn new(key: &[u8; 32], site_name: &String, password: &String, create_date: &String, modify_date: &String, note: &Option<String>, uname: &Option<String>, url: &Option<String>) -> PasswordEntry{
        // unwrap optional values before constructing the entry
        let note_str = unwrap_str(note);
        let user_str = unwrap_str(uname);
        let url_str  = unwrap_str(url);
        // return the entry
        Self { key: key.clone(), site_name: site_name.to_string(), password: password.to_string(), create_date: create_date.to_string(), modify_date: modify_date.to_string(), note: note_str, username: user_str, url: url_str}
    }

    // encrypts the password and returns the base64-encoded ciphertext
    pub fn export_b64(&self) -> Result<String, Error>{
        let plaintext = format!("{}~{}~{}~{}~{}~{}~{}", self.site_name, self.password, self.create_date, self.modify_date, self.note, self.username, self.url);
        let ciphertext = encrypt_authenticated(&plaintext, &self.key)?;
        Ok(BASE64_STANDARD.encode(ciphertext))
    }
}

// takes an option string and returns the string if Some or an empty string if None 
fn unwrap_str(string: &Option<String>) -> String{
    match string{
        Some(val) => {val.to_string()}
        None => {String::new()}
    }
}

// returns the current time, accurate to the second
pub fn get_time() -> String{
    let time = chrono::offset::Local::now().to_string();
    let tmp: Vec<&str> = time.split(".").collect();
    tmp[0].to_string()
}   

// parses the header of a password file
fn parse_header(file_header: &Vec<u8>) -> Result<Vec<&[u8]>, Error>{
    if file_header.len() != 80{
        return  Err(Error::new(ErrorKind::InvalidData, "Invalid password database header."));
    }
    let iv = &file_header[0..16];
    let key_salt = &file_header[16..32];
    let checksum = &file_header[32..64];
    let checksum_salt = &file_header[64..file_header.len()];
    Ok([iv, key_salt, checksum, checksum_salt].to_vec())
}

// ensures a password is valid, given the checksum, and returns the key if so
fn hash_key(master_password: &String, key_salt: &[u8], checksum_salt: &[u8], checksum: &[u8]) -> Result<[u8; 32], Error>{
    // hash the key 
    let mut key_hash = Sha256::new();
    key_hash.update(master_password.as_bytes());
    key_hash.update(key_salt);
    let master_key = key_hash.finish();
    // validate the key
    let mut checksum_hash = Sha256::new();
    checksum_hash.update(&master_key);
    checksum_hash.update(checksum_salt);
    match checksum == checksum_hash.finish(){
        true => {Ok(master_key)}
        false => {Err(Error::new(ErrorKind::InvalidInput, "Invalid password"))}
    }
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
    if segments.len() != 7{
        Err(Error::new(ErrorKind::InvalidData, "Invalid password entry"))
    }
    else{
        Ok(PasswordEntry::new(&key, &segments[0].to_string(), &segments[1].to_string(), &segments[2].to_string(), &segments[3].to_string(), &Some(segments[4].to_string()), &Some(segments[5].to_string()), &Some(segments[6].to_string())))
    }
}

// decrypts a password file, given the encrypted keyblock, and passwords
fn decrypt_password_file(master_key: &[u8], keyblock_b64: &str, header_segments: &Vec<&[u8]>, file_segments: &Vec<&str>) -> Result<Vec<PasswordEntry>, Error>{
    let kb_ciphertext = BASE64_STANDARD.decode(keyblock_b64).expect("Invalid key block");
    // attempt to decrypt the keyblock
    let key_cipher = Cipher::aes_256_cbc();
    let keyblock: Vec<u8>;
    match decrypt(key_cipher, &master_key, Some(&header_segments[IV_POS]), &kb_ciphertext) {
        Ok(tmp_bytes) => {keyblock = tmp_bytes}
        Err(_) => {return Err(Error::new(ErrorKind::Other, "Invalid key block"));}
    }
    // validate the size of the keyblock
    if keyblock.len() % 32 != 0{
        return  Err(Error::new(ErrorKind::InvalidData, "Invalid keyblock"));
    }
    // decrypt each password
    let mut passwords: Vec<PasswordEntry> = Vec::new();
    let keys: Vec<&[u8]> = keyblock.chunks(32).collect();
    let mut tmp_key: [u8; 32];
    for i in 0..keys.len(){
        tmp_key = keys[i].try_into().expect("Invalid Keyblock");
        passwords.push(decrypt_password(file_segments[i + 2].to_string(), &tmp_key)?);
    }
    Ok(passwords)
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
    let header_segments = parse_header(&header)?;
    // hash the key and decrpt the passwords
    let master_key = hash_key(master_password, header_segments[KEY_SALT_POS], header_segments[CHECKSUM_SALT_POS], header_segments[CHECKSUM_POS])?;
    decrypt_password_file(&master_key, segments[1], &header_segments, &segments)
}

// exports the key from a password file
pub fn export_file_key(password_file: &String, master_password: &String) -> Result<[u8; 32], Error>{
    // read the password file
    let file_contents: String;
    match fs::read_to_string(password_file){
        Ok(tmp) => {file_contents = tmp}
        Err(_) => {return Err(Error::new(ErrorKind::Other, "Failed to read the password file (does it exist?)"));}
    }
    let segments: Vec<&str> = file_contents.split(";").collect();
    let file_header = segments[0];
    let header_bytes = BASE64_STANDARD.decode(file_header).unwrap();
    let header_segments = parse_header(&header_bytes)?;
    hash_key(master_password, header_segments[KEY_SALT_POS], header_segments[CHECKSUM_SALT_POS], header_segments[CHECKSUM_POS])
}

// decrypts a password database file with the raw key as opposed to a master password
pub fn key_import_password_file(password_file: &String, key_file: &String) -> Result<Vec<PasswordEntry>, Error>{
    // read the key file
    let master_key: Vec<u8>;
    match fs::read(key_file){
        Ok(key) => {master_key = key}
        Err(_) => {return Err(Error::new(ErrorKind::InvalidData, "Invalid key file"))}
    }
    if master_key.len() != 32{
        return Err(Error::new(ErrorKind::InvalidData, "Invalid key file"))
    }
    // parse and decrypt the password file
    let pwdb_contents: String;
    match fs::read_to_string(password_file){
        Ok(tmp) => {pwdb_contents = tmp}
        Err(_) => {return Err(Error::new(ErrorKind::InvalidData, "Invalid password file"))}
    }
    let file_segments: Vec<&str> = pwdb_contents.split(";").collect();
    let file_header = BASE64_STANDARD.decode(file_segments[0]).expect("Invalid file header");
    let header_segments = parse_header(&file_header)?;
    decrypt_password_file(&master_key, file_segments[1], &header_segments, &file_segments)
}