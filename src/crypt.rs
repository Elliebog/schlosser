use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, aead::{Aead, OsRng}};
use pbkdf2::{pbkdf2_hmac_array};
use sha2::Sha256;
use crate::error::CryptographyError;

/// The length of the initialization Vector designed to be used in PBKDF2 key generation
pub const IV_LENGTH: usize = 16;
const PBKDF2_ITERATIONS: usize = 300000;
const KEY_LENGTH: usize = 32;
pub const AES_NONCE_LENGTH: usize = 12;


/// Struct that holds the result of an encryption operation
#[derive(Debug)]
pub struct EncryptedData<const N: usize> {
    /// The nonce generated in the process
    nonce: [u8; AES_NONCE_LENGTH],
    /// The encrypted Data
    data: [u8; N]
}


/// Generate the user key using the PBKDF2 algorithm
pub fn generate_user_key(password: String, iv: &[u8; IV_LENGTH]) -> [u8; KEY_LENGTH] {
      pbkdf2_hmac_array::<Sha256, KEY_LENGTH>(password.as_bytes(), iv, PBKDF2_ITERATIONS as u32)  
}

/// Decrypt a region where N is the target amount of bytes (excluding authentication tag).
/// This function uses experimental features such as computations with const generics 
pub fn decrypt_region<const N: usize>(data: &[u8; N+16], nonce: &[u8; AES_NONCE_LENGTH], key: &[u8]) -> Result<[u8; N], CryptographyError> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    //Decrypt the target data and truncate to exclude the authentication tag
    let mut data = cipher.decrypt(nonce.into(), &data[..]).map_err(|_| CryptographyError::InauthenticTag)?;
    data.truncate(N);
    Ok(get_array_from_vec::<N, u8>(data)?)
}

/// Decrypt a region of dynamic size.
/// No size guarantee is provided on the returned result (Vector)
pub fn decrypt_region_dyn(data: Vec<u8>, nonce: &[u8; AES_NONCE_LENGTH], key: &[u8]) -> Result<Vec<u8>, CryptographyError> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    let data = cipher.decrypt(nonce.into(), &data[..]).map_err(|_| CryptographyError::InauthenticTag)?;
    Ok(data)
}

/// Encrypt a region with length N. This returns the encrypted data as well as the nonce used.
/// The resulting Data length will be N+16 bytes long. (Authentication tag) 
pub fn encrypt_region<const N: usize>(data: &[u8; N], key: &[u8]) -> Result<EncryptedData<{N+16}>, CryptographyError> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let encrypted_data = cipher.encrypt(&nonce, &data[..]).map_err(|_| CryptographyError::InauthenticTag)?;
    let encrypted_data = get_array_from_vec::<{N+16}, u8>(encrypted_data)?;
    
    Ok(EncryptedData {nonce: nonce.into(), data: encrypted_data})
}


/// Get an array from vector if spezifying a specific size
fn get_array_from_vec<const N: usize, T>(vec: Vec<T>) -> Result<[T; N], CryptographyError>
where Result<[T;N], CryptographyError>: Sized {
    vec.try_into().map_err(|v: Vec<T>| CryptographyError::InvalidLength { expected: N, actual: v.len()})
}
