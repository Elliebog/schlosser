use pbkdf2::hmac::{Hmac, Mac};
use sha2::{Sha256, digest::InvalidLength};

pub const HMAC_SIZE: usize = 32;
pub fn generate_hmac_code(data: &[u8], secret_key: &[u8]) -> Result<[u8; HMAC_SIZE], InvalidLength> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret_key)?;
    mac.update(data); 

    Ok(mac.finalize().into_bytes().into())
}

pub fn verify_hmac_code(target_mac: [u8; HMAC_SIZE], data: &[u8], secret_key: &[u8]) -> Result<bool, InvalidLength> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret_key)?;
    mac.update(data);

    match mac.verify(&target_mac.into()) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false)
    }
}

