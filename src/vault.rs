use crate::crypt::{
    AES_NONCE_LENGTH, IV_LENGTH, decrypt_region, decrypt_region_dyn, encrypt_region,
    generate_user_key,
};
use std::{
    collections::VecDeque,
    fs::File,
    io::{BufRead, BufReader, Read, stdin},
    path::Path,
    string::FromUtf8Error,
};
// General Constants
const AES_GCM_AUTH_TAG: usize = 16;
// Header Constants
const VAULT_SIGNATURE: u64 = 0x0000e111e0afbaca;
const VAULT_SIGNATURE_LENGTH: usize = 8;
const VAULT_VERSION: u8 = 1;
const VAULT_VERSION_LENGTH: usize = 1;
const VAULTNAME_LENGTH: usize = 128;
const VAULTKEY_LENGTH: usize = 32;
const VAULTTABLE_INFO_LENGTH: usize = 8; //512 bit
const ENCRYPTED_REGION_LENGTH: usize = VAULTKEY_LENGTH + VAULTTABLE_INFO_LENGTH + AES_GCM_AUTH_TAG; //Key + VT size + authentication TAGLength
// Vault Table Constants
const VAULTENTRY_LENGTH: usize = 157;
const VAULTENTRYNAME_LENGTH: usize = 128;
const VAULTENTRYTYPE_LENGTH: usize = 1;
const DIRENTRY_SIZE_LENGTH: usize = 8;
const BLOCKID_LENGTH: usize = 8;
const SECRET_SIZE_LENGTH: usize = 8;

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

/// Header Information of the archive file
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
    vault_table_nonce: [u8; AES_NONCE_LENGTH],
}

/// Entry that holds a password
#[derive(Debug)]
struct PasswordEntry {
    /// Name of the password
    password_name: String,
    /// Id of the secret block
    secret_block_id: u64,
}

/// Entry for an encrypted Secret File (like a recovery key or a keyfile, or any other kind of file
/// that needs to be kept secure)
#[derive(Debug)]
struct SecretFileEntry {
    /// Name of the secret
    secret_name: String,
    /// Id of the starting secret block
    secret_block_id: u64,
    size: u64,
}

/// Entry that represents a directory in the vault structure
#[derive(Debug)]
struct DirectoryEntry {
    /// Name of the directory
    directory_name: String,
    /// Entries that are in the directory
    children:  Vec<VaultEntry>,
}

/// A vault entry found in the vault entry table
/// Each entry is 128+8+8 bytes long
#[derive(Debug)]
enum VaultEntry {
    Password(PasswordEntry),
    Secret(SecretFileEntry),
    Directory(DirectoryEntry),
}

enum ReadVaultFileError {
    ReadError(ReadFieldError, u64),
    ReadEntryError(ReadFieldError, u64),
    InvalidFile(InvalidFileReasons),
    ReadStdinError(std::io::Error),
    InAuthenticTagError(),
    InvalidLengthError(),
}

enum InvalidFileReasons {
    InvalidSignature,
    UnsupportedVersion,
    NoRootEntry,
    InvalidEntryType,
}

enum ReadFieldError {
    ReadFileError(std::io::Error),
    ReadUtf8Error(FromUtf8Error),
    UnexpectedEOFError(),
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

/// Read the vault archive file header.
/// This expects the Bufreader to be at the start of the file
fn read_header(reader: &mut BufReader<File>) -> Result<HeaderInfo, ReadVaultFileError> {
    let mut offset: u64 = 0;
    // Check if this file is meant to be a vault archive file
    let signature = u64::from_ne_bytes(
        read_field::<VAULT_SIGNATURE_LENGTH>(reader)
            .map_err(|e| ReadVaultFileError::ReadError(e, offset))?,
    );
    offset += VAULT_SIGNATURE_LENGTH as u64;

    if signature != VAULT_SIGNATURE {
        return Err(ReadVaultFileError::InvalidFile(
            InvalidFileReasons::InvalidSignature,
        ));
    }

    //Add a version field for future changes to the vault archive structure
    let version = read_field::<VAULT_VERSION_LENGTH>(reader)
        .map_err(|e| ReadVaultFileError::ReadError(e, offset))?[0];
    offset += VAULT_VERSION_LENGTH as u64;
    if version != VAULT_VERSION {
        return Err(ReadVaultFileError::InvalidFile(
            InvalidFileReasons::UnsupportedVersion,
        ));
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

    offset += AES_NONCE_LENGTH as u64;

    let keyregion = read_field::<ENCRYPTED_REGION_LENGTH>(reader)
        .map_err(|e| ReadVaultFileError::ReadError(e, offset))?;
    offset += ENCRYPTED_REGION_LENGTH as u64;

    let region_data = decrypt_region::<{ ENCRYPTED_REGION_LENGTH - AES_GCM_AUTH_TAG }>(
        &keyregion,
        &keyregion_nonce,
        &user_key,
    )
    .map_err(|_| ReadVaultFileError::InAuthenticTagError())?;

    let vault_nonce = read_field::<AES_NONCE_LENGTH>(reader)
        .map_err(|e| ReadVaultFileError::ReadError(e, offset))?;

    Ok(HeaderInfo {
        version,
        name: vaultname,
        key_region_nonce: keyregion_nonce,
        vault_key: region_data[..VAULTKEY_LENGTH]
            .try_into()
            .map_err(|_| ReadVaultFileError::InvalidLengthError())?,
        vault_table_size: u64::from_ne_bytes(
            region_data[VAULTKEY_LENGTH + 1..]
                .try_into()
                .map_err(|_| ReadVaultFileError::InvalidLengthError())?,
        ),
        vault_table_nonce: vault_nonce,
    })
}

fn read_vault_table(
    reader: &mut BufReader<File>,
    header: &HeaderInfo,
) -> Result<VaultContext, ReadVaultFileError> {
    //Decrypt the vault table. The vault size stored in the header dictates the amount of entries in
    //the vault table. Each entry is 157 bytes long.
    let vault_table = read_dyn_field(reader, header.vault_table_size as usize * VAULTENTRY_LENGTH)
        .map_err(|e| ReadVaultFileError::ReadError(e, 0))?;
    let table = decrypt_region_dyn(vault_table, &header.vault_table_nonce, &header.vault_key)
        .map_err(|_| ReadVaultFileError::InAuthenticTagError())?;

    // Due to the nature of the tree structure that the table is structured in we employ an
    // iterative approach with a stack

    // Because the direntry does not have an entry for size a tuple is used
    // keeping track of the size during loading operations within the directory entry would cause
    // problems down the line when serializing the vault table during save operations
    let mut dir_stack: VecDeque<(u64, &mut DirectoryEntry)> = VecDeque::new();
    //First read the root entry (it will always be a directory entry called root)
    let mut root_entry = match &table[0] {
        0 => {
            let mut offset = 1;
            let name = String::from_utf8(table[offset..offset + VAULTENTRYNAME_LENGTH].to_vec())
                .map_err(|e| {
                    ReadVaultFileError::ReadEntryError(ReadFieldError::ReadUtf8Error(e), 0)
                })?;
            offset += VAULTENTRYNAME_LENGTH;

            let size = u64::from_ne_bytes(
                table[offset..offset + DIRENTRY_SIZE_LENGTH]
                    .try_into()
                    .map_err(|_| ReadVaultFileError::InvalidLengthError())?,
            );
            Ok((
                size,
                DirectoryEntry {
                    directory_name: name,
                    children: Vec::new(),
                },
            ))
        }
        _ => Err(ReadVaultFileError::InvalidFile(
            InvalidFileReasons::NoRootEntry,
        )),
    }?;
    dir_stack.push_front((root_entry.0, &mut root_entry.1));

    let cur_dir: &mut (u64, &mut DirectoryEntry) = dir_stack.front_mut().unwrap();
    let offset = VAULTENTRY_LENGTH;

    loop {
        let (dir_size, entry) = read_entry(table[offset + 1..offset + 1 + VAULTENTRY_LENGTH]
                .try_into()
                .map_err(|_| ReadVaultFileError::InvalidLengthError())?,
        )?;
        
        match entry {
            VaultEntry::Directory(dir) => {
                //add it to the current directory 
                let mut_dir = cur_dir.1.children.push_mut(VaultEntry::Directory(dir));
                //TODO: Find a way to resolve the double mutable borrow

                
            }
            VaultEntry::Password(pwd) => {

            }
            VaultEntry::Secret(sec) => {

            }
        } 
    }
}

fn read_entry(
    entry_data: [u8; VAULTENTRY_LENGTH],
) -> Result<(u64, VaultEntry), ReadVaultFileError> {
    match entry_data[0] {
        0 => {
            // Directory Entry
            let mut offset = 1;
            let name = String::from_utf8(entry_data[offset..offset + VAULTENTRY_LENGTH].to_vec())
                .map_err(|e| {
                ReadVaultFileError::ReadEntryError(ReadFieldError::ReadUtf8Error(e), 1)
            })?;
            offset += VAULTENTRY_LENGTH;
            let size = u64::from_ne_bytes(
                entry_data[offset..offset + DIRENTRY_SIZE_LENGTH]
                    .try_into()
                    .map_err(|_| ReadVaultFileError::InvalidLengthError())?,
            );
            Ok((
                size,
                VaultEntry::Directory(DirectoryEntry {
                    directory_name: name,
                    children: Vec::new(),
                }),
            ))
        }
        1 => {
            //Password Entry
            let mut offset = 1;
            let name = String::from_utf8(entry_data[offset..offset + VAULTENTRY_LENGTH].to_vec())
                .map_err(|e| {
                ReadVaultFileError::ReadEntryError(ReadFieldError::ReadUtf8Error(e), 1)
            })?;
            offset += VAULTENTRY_LENGTH;
            let blk_id = u64::from_ne_bytes(
                entry_data[offset..offset + BLOCKID_LENGTH]
                    .try_into()
                    .map_err(|_| ReadVaultFileError::InvalidLengthError())?,
            );
            Ok((
                0,
                VaultEntry::Password(PasswordEntry {
                    password_name: name,
                    secret_block_id: blk_id,
                }),
            ))
        }
        2 => {
            //Secret File Entry
            let mut offset = 1;
            let name = String::from_utf8(entry_data[offset..offset + VAULTENTRY_LENGTH].to_vec())
                .map_err(|e| {
                ReadVaultFileError::ReadEntryError(ReadFieldError::ReadUtf8Error(e), 1)
            })?;
            offset += VAULTENTRY_LENGTH;
            let blk_id = u64::from_ne_bytes(
                entry_data[offset..offset + BLOCKID_LENGTH]
                    .try_into()
                    .map_err(|_| ReadVaultFileError::InvalidLengthError())?,
            );
            let size = u64::from_ne_bytes(
                entry_data[offset..offset + SECRET_SIZE_LENGTH]
                    .try_into()
                    .map_err(|_| ReadVaultFileError::InvalidLengthError())?,
            );

            Ok((
                0,
                VaultEntry::Secret(SecretFileEntry {
                    secret_name: name,
                    secret_block_id: blk_id,
                    size,
                }),
            ))
        }
        _ => Err(ReadVaultFileError::InvalidFile(
            InvalidFileReasons::InvalidEntryType,
        )),
    }
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
        return Err(ReadFieldError::UnexpectedEOFError());
    }
    Ok(buffer)
}

/// Reads a field of size only known at compile time and returns the result
fn read_dyn_field(reader: &mut BufReader<File>, len: usize) -> Result<Vec<u8>, ReadFieldError> {
    let mut buffer: Vec<u8> = vec![0; len];
    let bytes_read = reader
        .read(&mut buffer)
        .map_err(|e| ReadFieldError::ReadFileError(e))?;
    if bytes_read < len {
        return Err(ReadFieldError::UnexpectedEOFError());
    }

    Ok(buffer)
}
