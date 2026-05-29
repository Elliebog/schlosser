use crate::crypt::{
    AES_NONCE_LENGTH, IV_LENGTH, decrypt_region, decrypt_region_dyn, generate_user_key,
};
use crate::error::{InvalidFileReasons, ReadFieldError, ReadVaultFileError, VaultManagementError};
use std::{
    collections::{HashMap, VecDeque},
    fs::File,
    io::{BufRead, BufReader, Read, stdin},
    path::Path,
};
use std::fmt::Write;

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
// Vault data constants
const HEADER_LENGTH: usize = VAULT_SIGNATURE_LENGTH
    + VAULT_VERSION_LENGTH
    + VAULTNAME_LENGTH
    + IV_LENGTH
    + AES_NONCE_LENGTH
    + ENCRYPTED_REGION_LENGTH;

/// Maint Entry point that manages vault information about a schlosser vault 
#[derive(Debug)]
struct VaultManager {
    /// Version of the archive structure
    version: u8,
    /// Name of the Vault
    name: String,
    /// Encrypted Vault Key stored inside the schlosser vault file
    enc_vault_key: [u8; VAULTKEY_LENGTH],
    /// Size of the vault info region (header + vault table)
    data_start: u64,
    /// The root vault entry
    root_entry: DirectoryEntry,
}

impl VaultManager {
    pub fn from_file(file_path: &str) -> Result<VaultManager, ReadVaultFileError> {
        let path = Path::new(file_path);
        let file = match File::open(path) {
            Err(err) => panic!("Could not open file {}: {}", path.display(), err),
            Ok(file) => file,
        };
        let mut reader = BufReader::new(file);
        let header_info: HeaderInfo = read_header(&mut reader)?;
        let root_entry: DirectoryEntry = read_vault_table(&mut reader, &header_info)?;
        Ok(VaultManager {
            version: header_info.version,
            name: header_info.name,
            enc_vault_key: header_info.vault_key,
            data_start: header_info.vault_table_size * VAULTENTRY_LENGTH as u64
                + HEADER_LENGTH as u64,
            root_entry,
        })
    }

    pub fn get_vault_info(&self) -> Result<String, VaultManagementError>{
        let mut out: String =  format!("{} Archive", self.name);
        write!(&mut out, "test").map_err(|_| VaultManagementError::WriteError)?;
        dire
    }
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
    children: HashMap<String, VaultEntry>,
}

/// A vault entry found in the vault entry table
/// Each entry is 128+8+8 bytes long
#[derive(Debug)]
enum VaultEntry {
    Password(PasswordEntry),
    Secret(SecretFileEntry),
    Directory(DirectoryEntry),
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

    let  vaultname_raw =
        read_field::<VAULTNAME_LENGTH>(reader).map_err(|e| ReadVaultFileError::ReadError(e, offset))?;
    let vaultname = String::from_utf8(vaultname_raw.to_vec());
    offset += VAULTNAME_LENGTH as u64;

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

/// Read the vault table using an iterative approach
/// Returns the root entry as a directory
/// If the table has an invalid structure (No Root Entry or incorrect sizes of directory entries)
/// InvalidFile errors are returned
fn read_vault_table(
    reader: &mut BufReader<File>,
    header: &HeaderInfo,
) -> Result<DirectoryEntry, ReadVaultFileError> {
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
    //
    //The dir_stack holds the state of the current reading. 0 = entries left to read, 1 = actual
    //directory entry
    let mut dir_stack: VecDeque<(u64, DirectoryEntry)> = VecDeque::new();

    let (root_size, root_entry) = read_entry(
        table[..VAULTENTRY_LENGTH]
            .try_into()
            .map_err(|_| ReadVaultFileError::InvalidLengthError())?,
    )?;
    match root_entry {
        VaultEntry::Directory(dir) => dir_stack.push_front((root_size, dir)),
        _ => {
            return Err(ReadVaultFileError::InvalidFile(
                InvalidFileReasons::NoRootEntry,
            ));
        }
    };

    let mut offset = VAULTENTRY_LENGTH;
    loop {
        let entry = read_entry(
            table[offset..offset + VAULTENTRY_LENGTH]
                .try_into()
                .map_err(|_| ReadVaultFileError::InvalidLengthError())?,
        )?;
        offset += VAULTENTRY_LENGTH;

        // save the newly created directory and push it to the queue after the current dir borrow
        let mut new_dir: Option<(u64, DirectoryEntry)> = None;
        // Because a repeated retrieval of the head of the queue is not wanted, scopes are used to
        // get around rusts restriction on double mutable borrows
        {
            let cur_dir = dir_stack.front_mut();
            if cur_dir.is_none() {
                break Err(ReadVaultFileError::InvalidFile(
                    InvalidFileReasons::InvalidVaultStructure,
                ));
            }
            let cur_dir = cur_dir.unwrap();
            match entry.1 {
                VaultEntry::Password(pwd) => {
                    cur_dir
                        .1
                        .children
                        .insert(pwd.password_name.clone(), VaultEntry::Password(pwd));
                }
                VaultEntry::Secret(sec) => {
                    cur_dir
                        .1
                        .children
                        .insert(sec.secret_name.clone(), VaultEntry::Secret(sec));
                }
                VaultEntry::Directory(dir) => new_dir = Some((entry.0, dir)),
            };

            cur_dir.0 -= 1;
        }

        if new_dir.is_some() {
            dir_stack.push_front(new_dir.unwrap());
        }

        // get the remaining size from the possibly new directory
        let remaining_size: u64 = {
            let dir = dir_stack.front_mut();
            if dir.is_none() {
                break Err(ReadVaultFileError::InvalidFile(
                    InvalidFileReasons::InvalidVaultStructure,
                ));
            }
            dir.unwrap().0
        };

        // if 0 => Current dir is finished add it to the previous layer as a child
        if remaining_size == 0 {
            if dir_stack.len() == 1 {
                // we are at root and we are finished
                break Ok(dir_stack.pop_front().unwrap().1);
            }
            let res_dir = dir_stack.pop_front();
            if res_dir.is_none() {
                break Err(ReadVaultFileError::InternalError(String::from(
                    "Vault table read",
                )));
            }
            let dir = res_dir.unwrap().1;
            {
                let cur_dir = dir_stack.front_mut();
                if cur_dir.is_none() {
                    break Err(ReadVaultFileError::InvalidFile(
                        InvalidFileReasons::InvalidVaultStructure,
                    ));
                }
                cur_dir
                    .unwrap()
                    .1
                    .children
                    .insert(dir.directory_name.clone(), VaultEntry::Directory(dir));
            }
        }
    }
}

/// Convert a raw u8 slice of length `VAULT_ENTRY_LENGTH` to a VaultEntry
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
                    children: HashMap::new(),
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

/// Get the user key based on an initialization vector using PBKDF2 algorithm
fn get_user_key(iv: &[u8; IV_LENGTH]) -> Result<[u8; VAULTKEY_LENGTH], std::io::Error> {
    let mut pwd: String = String::new();
    stdin().read_line(&mut pwd)?;

    Ok(generate_user_key(pwd, iv))
}

/// Read a field of specific size from a buffered reader and return the contents in a fixed size
/// array
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

/// Reads a field of size only known at compile time and returns the result as a vector of bytes
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
