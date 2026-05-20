use crate::crypt::{
    AES_NONCE_LENGTH, IV_LENGTH, decrypt_region, encrypt_region, generate_user_key,
};
use std::{
    fs::File,
    io::{BufRead, BufReader, Read, stdin},
    path::Path,
    string::FromUtf8Error,
};
const VAULT_SIGNATURE: u64 = 0x0000e111e0afbaca;
const VAULT_SIGNATURE_LENGTH: usize = 8;
const VAULT_VERSION: u8 = 1;
const VAULT_VERSION_LENGTH: usize = 1;
const VAULTNAME_LENGTH: usize = 128;
const VAULTKEY_LENGTH: usize = 32;
const VAULTENTRY_LENGTH: usize = 145;
const VAULTENTRYNAME_LENGTH: usize = 128;
const VAULTENTRYTYPE_LENGTH: usize = 1;
const DIRENTRY_SIZE_LENGTH: usize = 8;
const BLOCKID_LENGTH: usize = 8;
const SECRET_SIZE_LENGTH: usize = 8;
const VAULTTABLE_INFO_LENGTH: usize = 64; //512 bit
const ENCRYPTED_REGION_LENGTH: usize = VAULTKEY_LENGTH + VAULTTABLE_INFO_LENGTH; //Key + VTIE Length

/// Contextual Information about a schlosser vault also called a schlosser archive
#[derive(Debug)]
struct VaultContext {
    /// Version of the archive structure
    version: u8,
    /// Name of the Vault
    name: String,
    /// Encrypted Vault Key stored inside the schlosser vault file
    enc_vault_key: [u8; 256],
    /// The root vault entry
    root_entry: VaultEntry,
}

#[derive(Debug)]
struct HeaderInfo {
    /// Version specified in the header
    version: u8,
    /// Name of the vault archive
    name: String,
    /// Key Region nonce
    key_region_nonce: [u8; AES_NONCE_LENGTH],
    // Decrypted vault key
    vault_key: [u8; VAULTKEY_LENGTH],
    vault_table_size: u64,
}

/// A vault entry found in the vault entry table
/// Each entry is 128+8+8 bytes long
#[derive(Debug)]
enum VaultEntry {
    PasswordEntry {
        /// Name of the password
        password_name: String,
        /// Id of the secret block
        secret_block_id: u64,
    },
    SecretFileEntry {
        /// Name of the secret
        secret_name: String,
        /// Id of the starting secret block
        secret_block_id: u64,
        size: u64,
    },
    DirectoryEntry {
        /// Name of the directory
        directory_name: String,
        /// Entries that are in the directory
        children: Vec<VaultEntry>,
    },
}

enum ReadVaultFileError {
    ReadError(ReadFieldError, u64),
    ReadEntryError(ReadFieldError, u64),
    InvalidFile(String),
    ReadStdinError(std::io::Error),
    CryptographyError(String),
    CorruptedFileError(String),
}

enum ReadFieldError {
    ReadFileError(std::io::Error),
    ReadUtf8Error(FromUtf8Error),
    UnexpectedEOFError(String),
}

impl VaultContext {
    pub fn from_file(file_path: &str) -> Result<VaultContext, ReadVaultFileError> {
        let path = Path::new(file_path);
        let mut file = match File::open(&path) {
            Err(err) => panic!("Could not open file {}: {}", path.display(), err),
            Ok(file) => file,
        };
        let mut reader = BufReader::new(file);
        let offset: u64 = 0;
    }
}

fn read_header(reader: &mut BufReader<File>) -> Result<HeaderInfo, ReadVaultFileError> {
    let mut offset: u64 = 0;
    // Check if this file is meant to be a vault archive file
    let signature = u64::from_ne_bytes(
        read_field::<VAULT_SIGNATURE_LENGTH>(reader)
            .map_err(|e| ReadVaultFileError::ReadError(e, offset))?,
    );
    offset += VAULT_SIGNATURE_LENGTH as u64;

    if signature != VAULT_SIGNATURE {
        return Err(ReadVaultFileError::InvalidFile(String::from(
            "This file is not a vault file",
        )));
    }

    //Add a version field for future changes to the vault archive structure
    let version = read_field(reader).map_err(|e| ReadVaultFileError::ReadError(e, offset))?[0];
    offset += VAULT_VERSION_LENGTH as u64;
    if version != VAULT_VERSION {
        return Err(ReadVaultFileError::InvalidFile(String::from(
            "This file specifies a version not supported by schlosser",
        )));
    }

    let (bytes_read, vaultname) =
        read_string_field(reader).map_err(|e| ReadVaultFileError::ReadError(e, offset))?;
    offset += bytes_read as u64;

    let userkey_iv =
        read_field::<IV_LENGTH>(reader).map_err(|e| ReadVaultFileError::ReadError(e, offset))?;
    offset += IV_LENGTH as u64;

    //Generate user key based on information gathered
    let user_key = get_user_key(&userkey_iv).map_err(|e| ReadVaultFileError::ReadStdinError(e))?;

    //Get the keyregion nonce for decrypting the keyregion
    //The keyregion includes both the information about the vault table as well as the master key
    //This is done to save space in the header and save time on encryption
    let keyregion_nonce = read_field::<AES_NONCE_LENGTH>(reader)
        .map_err(|e| ReadVaultFileError::ReadError(e, offset))?;

    let keyregion = read_field::<ENCRYPTED_REGION_LENGTH>(reader)
        .map_err(|e| ReadVaultFileError::ReadError(e, offset))?;
    offset += ENCRYPTED_REGION_LENGTH as u64;

    
    let region_data = decrypt_region(&keyregion, &keyregion_nonce, &user_key).map_err(|e| {
        ReadVaultFileError::CryptographyError(
            "The keyregion is corrupted or was modified".to_owned(),
        )
    })?;
    
   Ok(HeaderInfo { 
       version, 
       name: vaultname, 
       key_region_nonce: keyregion_nonce, 
       vault_key: region_data[0..VAULTKEY_LENGTH], vault_table_size: () }) 
}

fn get_user_key(iv: &[u8; IV_LENGTH]) -> Result<[u8; VAULTKEY_LENGTH], std::io::Error> {
    let mut pwd: String = String::new();
    stdin().read_line(&mut pwd)?;

    Ok(generate_user_key(pwd, iv))
}

fn read_string_field(reader: &mut BufReader<File>) -> Result<(usize, String), ReadFieldError> {
    let mut buffer: Vec<u8> = Vec::new();
    //Read bytes until the string delimiter is found
    let read_bytes = reader
        .read_until(0x00, &mut buffer)
        .map_err(|e| ReadFieldError::ReadFileError(e))?;
    let field = String::from_utf8(buffer).map_err(|e| ReadFieldError::ReadUtf8Error(e))?;
    Ok((read_bytes, field))
}

fn read_field<const length: usize>(
    reader: &mut BufReader<File>,
) -> Result<[u8; length], ReadFieldError> {
    let mut buffer: [u8; length] = [0; length];
    let read_bytes = reader
        .read(&mut buffer)
        .map_err(|e| ReadFieldError::ReadFileError(e))?;
    if read_bytes < length {
        return Err(ReadFieldError::UnexpectedEOFError(String::from(
            "Encountered Unexpected end of file",
        )));
    }
    Ok(buffer)
}

fn read_entry(reader: &mut BufReader<File>) -> Result<VaultEntry, ReadFieldError> {
    //TODO IMPORTANT TOMORROW -> Convert this one time read with more read_fields because it makes
    //conversion down the line way easier and we're using a buffered reader anyway
    let entry = read_field::<VAULTENTRY_LENGTH>(reader)?;
    let offset = 0;
    let e_type = entry[0];
    offset += VAULTENTRYTYPE_LENGTH;
    let name = String::from_utf8(entry[offset..offset + VAULTENTRYNAME_LENGTH].to_vec())
        .map_err(|e| ReadFieldError::ReadUtf8Error(e))?;
    offset += VAULTENTRYNAME_LENGTH;
    match e_type {
        // Directory Entry
        0 => {
            let dir_entry = VaultEntry::DirectoryEntry {
                directory_name: name,
                children: Vec::new(),
            };
            let size = u64::from_ne_bytes(
                entry[offset..offset + DIRENTRY_SIZE_LENGTH]
                    .try_into()
                    .unwrap(),
            );
        }
        1 => {}
        2 => {}
    }
}
