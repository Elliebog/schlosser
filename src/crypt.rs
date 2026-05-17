use crate::vault;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key // Or `Aes128Gcm`
};

pub fn encrypt_data(data: String, vaultkey: Key<Aes256Gcm>) {
    
}
