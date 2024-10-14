use std::{
    fs::{remove_file, File},
    io::{Read, Write},
};

use chacha20::cipher::KeyIvInit;
use chacha20::ChaCha20;
use cipher::StreamCipher;

use sha2::{Digest, Sha256};

const DEFAULT_KEY: [u8; 32] = [0; 32];
const VALIDATRO_STRING: &[u8; 32] = b"123__string__123__32bits__(()())";
pub struct Cryptr {
    chacha: ChaCha20,
    key: String,
}
impl Cryptr {
    pub fn new(key: Option<&str>) -> Self {
        let default_key = String::from_utf8_lossy(DEFAULT_KEY.as_slice()).to_string();

        // Main String to be used
        let key = key.unwrap_or(default_key.as_str());

        // Create a Sha256 object for 32-byte hash
        let hash_key = &to_32_byte_hash(key);
        let nonce = &[0; 12];

        let chacha = ChaCha20::new(hash_key.into(), nonce.into());

        Self {
            chacha,
            key: String::from(key),
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut buffer = plaintext.to_vec();
        self.chacha.apply_keystream(&mut buffer);
        buffer.to_vec()
    }

    pub fn decrypt(&mut self, ciphertext: Vec<u8>) -> Vec<u8> {
        let mut buffer = ciphertext.clone();
        // verify key 
        self.chacha.apply_keystream(&mut buffer);
        buffer
    }

    pub fn get_key(&self) -> String {
        self.key.clone()
    }
}

pub struct FileCryptr {
    input_file: File,
    output_file: File, 
    key: String,
    output_file_path: String,
}

impl FileCryptr {
    pub fn new(input_file: String, output_file: String, key: String) -> Result<Self, String> {
        let files = __load_files(input_file, output_file.clone());
        if files.is_err() {
            return Err(files.err().unwrap().to_string());
        }
        let output_file_path = output_file;
        let (input_file, output_file) = files.unwrap();

        Ok(Self {
            input_file,
            output_file, 
            key,
            output_file_path
        })
    }

    pub fn encrypt(&mut self) -> Result<bool, String> {
        let mut cryptr = Cryptr::new(Some(self.key.as_str()));
        let mut contents = [0u8; 32];

        // Write validation string
        let ct = cryptr.encrypt(VALIDATRO_STRING);
        let is_ok = self.output_file.write(&ct);
        if is_ok.is_err() {
            return Err(is_ok.err().unwrap().to_string());
        }

        loop {
            let is_read = self.input_file.read(&mut contents);
            if is_read.is_err() {
                return Err(is_read.err().unwrap().to_string());
            }

            let is_read = is_read.unwrap();
            if is_read == 0 {
                break;
            } 
            let ct = cryptr.encrypt(&contents[..is_read]);
            let is_ok = self.output_file.write(&ct );
            if is_ok.is_err() {
                return Err(is_ok.err().unwrap().to_string());
            }
        }
        Ok(true)
    }
    pub fn decrypt(&mut self) -> Result<bool, String> {
        let mut cryptr = Cryptr::new(Some(self.key.as_str()));
        let mut contents = [0u8; 32];

        // Read validation string
        let is_read = self.input_file.read(&mut contents);
        if is_read.is_err() {
            return Err(is_read.err().unwrap().to_string());
        }
        
        let vs = cryptr.decrypt(contents.to_vec());
        let vs = String::from_utf8_lossy(&vs).to_string();
        // check validation string matches
        if vs != String::from_utf8_lossy(VALIDATRO_STRING).to_string() {
            // delete output file
            remove_file(self.output_file_path.as_str()).unwrap();
            return Err(String::from("Invalid key"));
        }
         
        loop {
            let is_read = self.input_file.read(&mut contents);
            if is_read.is_err() {
                return Err(is_read.err().unwrap().to_string());
            }

            let is_read = is_read.unwrap();
            if is_read == 0 {
                break;
            } 
            let ct = cryptr.decrypt(contents[..is_read].to_vec());
            let is_ok = self.output_file.write(&ct);
            if is_ok.is_err() {
                return Err(is_ok.err().unwrap().to_string());
            }
        }
        Ok(true)
    }
     
}

fn to_32_byte_hash(input: &str) -> [u8; 32] {
    // Create a Sha256 object
    let hash = Sha256::digest(input.as_bytes());
    let hash = hash.as_slice();
    let mut array: [u8; 32] = [0; 32];

    // Copy the hash into the array as a slice of bytes length 32
    array.clone_from_slice(hash);

    array
}
fn __load_files(input_file: String, output_file: String) -> Result<(File, File), String> {
    // read file contents with seeking 32 bytes
    let input_file = File::open(input_file.as_str());
    // output file write as u8 array
    let output_file = File::create(output_file.as_str());
    if input_file.is_err() {
        return Err(input_file.err().unwrap().to_string());
    }
    if output_file.is_err() {
        return Err(output_file.err().unwrap().to_string());
    }
    Ok((input_file.unwrap(), output_file.unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_key_works() {
        let plaintext = b"some  plaintext";
        let k = Some("some ke adfa df");

        let mut c = Cryptr::new(k);
        let ciphertext = c.decrypt(plaintext.to_vec());

        let mut c = Cryptr::new(Some(c.get_key().as_str()));
        let text = c.encrypt(&ciphertext);

        let text = text.as_slice();  
        assert_eq!(String::from_utf8_lossy(text), String::from_utf8_lossy(&plaintext.clone()));
    }
    #[test]
    fn different_key_does_not_works() {
        let plaintext = b"some  plaintext";
        let k = Some("some key");
        let mut c = Cryptr::new(k);
        let ciphertext = c.encrypt(plaintext);

        let k = Some("some keyx");
        let mut c = Cryptr::new(k);
        let text = c.decrypt(ciphertext);

        let text = text.as_slice();

        assert_ne!(plaintext, text);
    }
}
