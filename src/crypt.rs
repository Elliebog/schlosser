use aes_gcm::{AeadCore, Aes256Gcm, Error, Key, KeyInit, aead::{Aead, OsRng}};
use pbkdf2::{pbkdf2_hmac_array};
use sha2::Sha256;

/// The length of the initialization Vector designed to be used in PBKDF2 key generation
pub const IV_LENGTH: usize = 16;
const PBKDF2_ITERATIONS: usize = 300000;
const KEY_LENGTH: usize = 32;
pub const AES_NONCE_LENGTH: usize = 12;

pub struct EncryptedData {
    nonce: [u8; AES_NONCE_LENGTH],
    data: Vec<u8>
}

impl EncryptedData {
    fn new(nonce: [u8; AES_NONCE_LENGTH], data: Vec<u8>) -> Self {
       EncryptedData { nonce, data } 
    }
}

pub fn generate_user_key(password: String, iv: &[u8; IV_LENGTH]) -> [u8; KEY_LENGTH] {
      pbkdf2_hmac_array::<Sha256, KEY_LENGTH>(password.as_bytes(), iv, PBKDF2_ITERATIONS as u32)  
}

fn decrypt_region(data: &[u8], nonce: &[u8; AES_NONCE_LENGTH], key: &[u8]) -> Result<Vec<u8>, Error> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(&key);

    cipher.decrypt(nonce.into(), data)
}


fn encrypt_region(data: &[u8], key: &[u8]) -> Result<EncryptedData, Error> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    
    Ok(EncryptedData::new(nonce.into(), cipher.encrypt(&nonce, data)?))
}
