use std::{
    fs::File,
    io::{self, BufRead, BufReader, Read},
    path::Path,
    string::FromUtf8Error,
};
const VAULT_SIGNATURE: u32 = 0x0000e111e0afbaca;
const VAULT_SIGNATURE_LENGTH: usize = 4;
const VAULT_VERSION: u8 = 1;
const VAULT_VERSION_LENGTH: usize = 1;
const VAULTNAME_LENGTH: usize = 128;
const VAULTKEY_LENGTH: usize = 256;
const VAULTENTRY_LENGTH: usize = 145;
const VAULTENTRYNAME_LENGTH: usize = 128;
const VAULTENTRYTYPE_LENGTH: usize = 1;
const DIRENTRY_SIZE_LENGTH: usize = 8;
const BLOCKID_LENGTH: usize = 8;
const SECRET_SIZE_LENGTH: usize = 8;
/// Contextual Information about a schlosser vault also called a schlosser archive
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

/// A vault entry found in the vault entry table
/// Each entry is 128+8+8 bytes long
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

        // Check if this file is meant to be a vault archive file
        let signature = u32::from_ne_bytes(
            read_field::<VAULT_SIGNATURE_LENGTH>(&mut reader)
                .map_err(|e| ReadVaultFileError::ReadError(e, offset))?,
        );
        offset += VAULT_SIGNATURE_LENGTH as u64;

        if signature != VAULT_SIGNATURE {
            return Err(ReadVaultFileError::InvalidFile(String::from(
                "This file is not a vault file",
            )));
        }

        //Add a version field for future changes to the vault archive structure
        let version =
            read_field(&mut reader).map_err(|e| ReadVaultFileError::ReadError(e, offset))?[0];
        offset += VAULT_VERSION_LENGTH as u64;
        if version != VAULT_VERSION {
            return Err(ReadVaultFileError::InvalidFile(String::from(
                "This file specifies a version not supported by schlosser",
            )));
        }

        let (bytes_read, name) =
            read_string_field(&mut reader).map_err(|e| ReadVaultFileError::ReadError(e, offset))?;
        offset += bytes_read as u64;

        let vault_key = read_field::<VAULTKEY_LENGTH>(&mut reader)
            .map_err(|e| ReadVaultFileError::ReadError(e, offset))?;
        offset += VAULTKEY_LENGTH as u64;
    }
}

fn read_table(reader: &mut BufReader<File>) -> Result<Vec<VaultEntry>, ReadVaultFileError> {
    //The structure of the entries
    //Directory Entry
    //Entry Type 1B: 0 = Directory, 1=Entry, 2=SecretEntry
    //Name 128B
    //Size 8B
    //Total = 137B
    //
    //Password Entry
    //Entry Type 1B
    //Name 128B
    //BlockId 8B
    //Total = 137B
    //
    //Secret Entry
    //Entry Type 1B
    //Name 128B
    //BlockId 8B
    //Size 8B
    // Total = 145B
    //
    let entry_id = 0;
    //read the first entry and panick if it is not a directory -> invalid file
    let entry = read_field::<VAULTENTRY_LENGTH>(reader)
        .map_err(|e| ReadVaultFileError::ReadEntryError(e, 0))?;
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
            let size = u64::from_ne_bytes(entry[offset..offset + DIRENTRY_SIZE_LENGTH].try_into().unwrap());
            
        }
        1 => {}
        2 => {}
    }
}
