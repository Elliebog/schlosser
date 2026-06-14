use bytes::{Bytes};

use crate::crypt::{
    AES_NONCE_LENGTH, IV_LENGTH, decrypt_region, decrypt_region_dyn,
     generate_user_key,
};
use crate::vault::entry::{
    DirectoryEntry, EncryptedEntry, Entry, EntryResult, PasswordEntry, SecretFileEntry, VaultEntry,
};
use crate::vault::error::{
    DeleteEntryError, EntryType, InvalidFileReasons,
    NewEntryError, Operation, ReadVaultFileError, RenameEntryError,
    RetrieveSecretError, VaultChangeEntryError, VaultError,
};
use crate::vault::utils::{BlockSet, VaultPath, read_dyn_field, read_field};
use std::io::{BufWriter, Seek, SeekFrom};
use std::{
    collections::{VecDeque},
    fs::File,
    io::{BufReader, stdin},
    path::Path,
};

// General Constants
pub const AES_GCM_AUTH_TAG: usize = 16;
// Header Constants
const VAULT_SIGNATURE: u64 = 0x0000e111e0afbaca;
const VAULT_SIGNATURE_LENGTH: usize = 8;
const VAULT_VERSION: u8 = 1;
const VAULT_VERSION_LENGTH: usize = 1;
pub const VAULTNAME_LENGTH: usize = 128;
const VAULTKEY_LENGTH: usize = 32;
const VAULTTABLE_INFO_LENGTH: usize = 8; //512 bit
const ENCRYPTED_REGION_LENGTH: usize = VAULTKEY_LENGTH + VAULTTABLE_INFO_LENGTH + AES_GCM_AUTH_TAG; //Key + VT size + authentication TAGLength
// Vault Table Constants
pub(crate) const PASSWORDENTRY_TYPE: u8 = 0;
pub(crate) const SECRETENTRY_TYPE: u8 = 1;
pub(crate) const DIRENTRY_TYPE: u8 = 2;
pub(crate) const VAULTENTRY_LENGTH: usize = 157;
pub const VAULTENTRYNAME_LENGTH: usize = 128;
const VAULTENTRYTYPE_LENGTH: usize = 1;
pub const DIRENTRY_SIZE_LENGTH: usize = 8;
pub const BLOCKID_LENGTH: usize = 8;
pub const SECRET_SIZE_LENGTH: usize = 8;
// Vault data constants
const HEADER_LENGTH: usize = VAULT_SIGNATURE_LENGTH
    + VAULT_VERSION_LENGTH
    + VAULTNAME_LENGTH
    + IV_LENGTH
    + AES_NONCE_LENGTH
    + ENCRYPTED_REGION_LENGTH;
pub(crate) const DATABLOCK_RAW_LENGTH: usize = 256;
pub(crate) const DATABLOCK_LENGTH: usize = DATABLOCK_RAW_LENGTH + AES_GCM_AUTH_TAG;
/// Maint Entry point that manages vault information about a schlosser vault
#[derive(Debug)]
struct VaultManager<'a> {
    /// Version of the archive structure
    version: u8,
    /// Name of the Vault
    name: String,
    /// Master vault Key
    vault_key: [u8; VAULTKEY_LENGTH],
    /// Size of the vault info region (header + vault table)
    data_start: u64,
    /// The root vault entry
    root_entry: DirectoryEntry,
    /// The path to the archive file
    vault_path: String,
    context: VaultChangeContext,
}

impl<'a> VaultManager<'a> {
    pub fn from_file(file_path: &str) -> Result<VaultManager, ReadVaultFileError> {
        let path = Path::new(file_path);
        let file = File::open(path).map_err(|e| ReadVaultFileError::FileError(e))?;
        let mut reader = BufReader::new(file);
        let header_info: HeaderInfo = read_header(&mut reader)?;
        let root_entry: DirectoryEntry = read_vault_table(&mut reader, &header_info)?;
        let context = VaultChangeContext::new(&root_entry);
        Ok(VaultManager {
            version: header_info.version,
            name: header_info.name,
            vault_key: header_info.vault_key,
            data_start: header_info.vault_table_size * VAULTENTRY_LENGTH as u64
                + HEADER_LENGTH as u64,
            root_entry,
            vault_path: file_path.to_owned(),
            context,
        })
    }

    pub fn get_vault_info(&self) -> Result<String, std::fmt::Error> {
        let mut out: String = format!("{} Archive", self.name);
        self.root_entry.get_directory_overview(0, &mut out)?;

        Ok(out)
    }

    pub fn retrieve_secret_entry(
        &self,
        entry_path: String,
    ) -> Result<EntryResult, RetrieveSecretError> {
        let vault_path = VaultPath::new(entry_path.clone());
        if vault_path.is_none() {
            return Err(RetrieveSecretError::InvalidVaultPath(entry_path));
        }
        let path = vault_path.unwrap();
        let file = File::open(Path::new(&self.vault_path))
            .map_err(|e| RetrieveSecretError::FileError(e))?;
        let mut reader = BufReader::new(file);

        let target_entry = self.root_entry.get_entry(path.parts().into(), &path)?;
        target_entry.retrieve_secret(&mut reader, self.data_start, &self.vault_key)
    }

    //TODO: Implement checksum checking for advanced security
    //TODO: Implement store features

    /// Writes the vault to the vault archive file
    pub fn save_vault(&self) -> Result<(), VaultError> {
        let file = File::open(Path::new(&self.vault_path))
            .map_err(|e| VaultError::ReadVaultError(ReadVaultFileError::ReadFileError(e)))?;
        let mut writer = BufWriter::new(file);
    }

    /// Returns a list of empty data blocks in the vault archive
    /// If there are no empty data blocks an empty vector is returned
    fn get_empty_data_blocks(&self) -> BlockSet {
        self.root_entry.occupied_datablocks()
    }

    pub fn rename(&mut self, entry_path: String, new_name: String) -> Result<(), RenameEntryError> {
        let path = VaultPath::new(entry_path.clone())
            .map_err(|e| RenameEntryError::InvalidVaultPath(e))?;
        self.root_entry
            .rename_entry(path.parts().into(), &path, new_name)
            .map_err(|e| RenameEntryError::VaultError(e));
        Ok(())
    }

    pub fn change_password(
        &mut self,
        entry_path: String,
        password: String,
    ) -> Result<(), VaultChangeEntryError> {
        let path = VaultPath::new(entry_path.clone())
            .map_err(|e| VaultChangeEntryError::InvalidVaultPath(e))?;
        let entry = self.root_entry.get_entry_mut(path.parts().into(), &path)?;

        match entry {
            VaultEntry::Password(pwd) => pwd
                .change_secret(&mut self.context, &self.vault_key, password)
                .map_err(|e| VaultChangeEntryError::VaultChangeError(e)),
            VaultEntry::Directory(_) => Err(VaultChangeEntryError::InvalidOperation(
                Operation::ChangePassword,
                EntryType::Directory,
            )),
            VaultEntry::Secret(_) => Err(VaultChangeEntryError::InvalidOperation(
                Operation::ChangePassword,
                EntryType::Secret,
            )),
        }
    }

    pub fn change_secret(
        &mut self,
        entry_path: String,
        secret_file_path: String,
    ) -> Result<(), VaultChangeEntryError> {
        let path = VaultPath::new(entry_path.clone())
            .map_err(|e| VaultChangeEntryError::InvalidVaultPath(e))?;

        let entry = self.root_entry.get_entry_mut(path.parts().into(), &path)?;

        match entry {
            VaultEntry::Password(_) => Err(VaultChangeEntryError::InvalidOperation(
                Operation::ChangeSecret,
                EntryType::Password,
            )),
            VaultEntry::Directory(_) => Err(VaultChangeEntryError::InvalidOperation(
                Operation::ChangeSecret,
                EntryType::Directory,
            )),
            VaultEntry::Secret(sec) => sec
                .change_secret(&mut self.context, &self.vault_key, secret_file_path)
                .map_err(|e| VaultChangeEntryError::VaultChangeError(e)),
        }
    }

    pub fn delete_entry(&mut self, entry_path: String) -> Result<(), DeleteEntryError> {
        let path = VaultPath::new(entry_path.clone())
            .map_err(|e| DeleteEntryError::InvalidVaultPath(e))?;
        self.root_entry
            .delete_entry(path.parts().into(), &path, &mut self.context)
            .map_err(|e| DeleteEntryError::VaultError(e))
    }

    pub fn new_directory(
        &mut self,
        dir_path: String,
        dir_name: String,
    ) -> Result<(), NewEntryError> {
        let entry = VaultEntry::Directory(
            DirectoryEntry::new(dir_name).map_err(|e| NewEntryError::NameLengthError(e))?,
        );
        let path = VaultPath::new(dir_path).map_err(|e| NewEntryError::InvalidVaultPath(e))?;
        if let Some(parent_path) = path.parent() {
            self.root_entry
                .new_entry(path.parts().into(), &parent_path, entry)
                .map_err(|e| NewEntryError::VaultError(e));
        }
        Ok(())
    }

    pub fn new_secret(
        &mut self,
        parent_path: String,
        secret_name: String,
        file_path: String,
    ) -> Result<(), NewEntryError> {
        let path = VaultPath::new(parent_path).map_err(|e| NewEntryError::InvalidVaultPath(e))?;
        let secret =
            SecretFileEntry::new(secret_name, file_path, &mut self.context, &self.vault_key)
                .map_err(|e| NewEntryError::VaultChangeError(e))?;
        self.root_entry
            .new_entry(path.parts().into(), &path, VaultEntry::Secret(secret))
            .map_err(|e| NewEntryError::VaultError(e))
    }

    pub fn new_password(
        &mut self,
        parent_path: String,
        password_name: String,
        password: String,
    ) -> Result<(), NewEntryError> {
        let path = VaultPath::new(parent_path).map_err(|e| NewEntryError::InvalidVaultPath(e))?;

        let password =
            PasswordEntry::new(password_name, password, &mut self.context, &self.vault_key)
                .map_err(|e| NewEntryError::VaultChangeError(e))?;

        self.root_entry
            .new_entry(path.parts().into(), &path, VaultEntry::Password(password))
            .map_err(|e| NewEntryError::VaultError(e))
    }
}

#[derive(Debug)]
pub struct DataBlockChange {
    start: u64,
    len: usize,
    data: Option<Bytes>,
}

impl DataBlockChange {
    pub fn new(start: u64, len: usize, data: Option<Bytes>) -> Self {
        DataBlockChange { start, len, data }
    }
}

#[derive(Debug)]
pub struct VaultChangeContext {
    pub changes: Vec<DataBlockChange>,
    pub empty_blocks: BlockSet,
}

impl VaultChangeContext {
    pub fn new(root_entry: &DirectoryEntry) -> Self {
        VaultChangeContext {
            changes: Vec::new(),
            empty_blocks: root_entry.occupied_datablocks(),
        }
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
    /// Decrypted vault key
    vault_key: [u8; VAULTKEY_LENGTH],
    vault_table_size: u64,
    vault_table_nonce: [u8; AES_NONCE_LENGTH],
}

/// Read the vault archive file header.
/// This expects the Bufreader to be at the start of the file
fn read_header(reader: &mut BufReader<File>) -> Result<HeaderInfo, ReadVaultFileError> {
    let mut offset: u64 = 0;
    // Check if this file is meant to be a vault archive file
    let signature = u64::from_ne_bytes(
        read_field::<VAULT_SIGNATURE_LENGTH>(reader)
            .map_err(|e| ReadVaultFileError::ReadFieldError(e, offset))?,
    );
    offset += VAULT_SIGNATURE_LENGTH as u64;

    if signature != VAULT_SIGNATURE {
        return Err(ReadVaultFileError::InvalidFile(
            InvalidFileReasons::WrongSignature,
        ));
    }

    //Add a version field for future changes to the vault archive structure
    let version = read_field::<VAULT_VERSION_LENGTH>(reader)
        .map_err(|e| ReadVaultFileError::ReadFieldError(e, offset))?[0];
    offset += VAULT_VERSION_LENGTH as u64;

    if version != VAULT_VERSION {
        return Err(ReadVaultFileError::InvalidFile(
            InvalidFileReasons::UnsupportedVersion,
        ));
    }

    let vaultname_raw = read_field::<VAULTNAME_LENGTH>(reader)
        .map_err(|e| ReadVaultFileError::ReadFieldError(e, offset))?;
    let vaultname = String::from_utf8(vaultname_raw.to_vec())
        .map_err(|e| ReadVaultFileError::UTF8Error(e, offset))?;
    offset += VAULTNAME_LENGTH as u64;

    let userkey_iv = read_field::<IV_LENGTH>(reader)
        .map_err(|e| ReadVaultFileError::ReadFieldError(e, offset))?;
    offset += IV_LENGTH as u64;

    //Generate user key based on information gathered
    let user_key =
        get_user_key(&userkey_iv).map_err(|e| ReadVaultFileError::ReadUserKeyError(e))?;

    //Get the keyregion nonce for decrypting the keyregion
    //The keyregion includes both the information about the vault table as well as the master key
    //This is done to save space in the header and save time on encryption
    let keyregion_nonce = read_field::<AES_NONCE_LENGTH>(reader)
        .map_err(|e| ReadVaultFileError::ReadFieldError(e, offset))?;

    offset += AES_NONCE_LENGTH as u64;

    let keyregion = read_field::<ENCRYPTED_REGION_LENGTH>(reader)
        .map_err(|e| ReadVaultFileError::ReadFieldError(e, offset))?;
    offset += ENCRYPTED_REGION_LENGTH as u64;

    let region_data = decrypt_region::<{ ENCRYPTED_REGION_LENGTH - AES_GCM_AUTH_TAG }>(
        &keyregion,
        &keyregion_nonce,
        &user_key,
    )
    .map_err(|e| ReadVaultFileError::CryptographyError(e))?;

    let vault_nonce = read_field::<AES_NONCE_LENGTH>(reader)
        .map_err(|e| ReadVaultFileError::ReadFieldError(e, offset))?;

    Ok(HeaderInfo {
        version,
        name: vaultname,
        key_region_nonce: keyregion_nonce,
        // unwrap because if this assumption is not true we need to panic
        vault_key: region_data[..VAULTKEY_LENGTH].try_into().unwrap(),
        vault_table_size: u64::from_ne_bytes(
            region_data[VAULTKEY_LENGTH + 1..].try_into().unwrap(),
        ),
        vault_table_nonce: vault_nonce,
    })
}

/// Read the vault table using an iterative approach
/// Returns the root entry as a directory
/// Header is the constructed header from read_header.
/// the reader is to be positioned at the start of the vault table
/// If the table has an invalid structure (No Root Entry or incorrect sizes of directory entries)
/// InvalidFile errors are returned
fn read_vault_table(
    reader: &mut BufReader<File>,
    header: &HeaderInfo,
) -> Result<DirectoryEntry, ReadVaultFileError> {
    let offset = reader
        .seek(SeekFrom::Current(0))
        .map_err(|e| ReadVaultFileError::FileError(e))?;
    //Decrypt the vault table. The vault size stored in the header dictates the amount of entries in
    //the vault table. Each entry is 157 bytes long.
    let vault_table = read_dyn_field(reader, header.vault_table_size as usize * VAULTENTRY_LENGTH)
        .map_err(|e| ReadVaultFileError::ReadFieldError(e, offset))?;
    let table = decrypt_region_dyn(vault_table, &header.vault_table_nonce, &header.vault_key)
        .map_err(|e| ReadVaultFileError::CryptographyError(e))?;

    // Due to the nature of the tree structure that the table is structured in we employ an
    // iterative approach with a stack

    // Because the direntry does not have an entry for size a tuple is used
    // keeping track of the size during loading operations within the directory entry would cause
    // problems down the line when serializing the vault table during save operations
    //
    //The dir_stack holds the state of the current reading. 0 = entries left to read, 1 = actual
    //directory entry
    let mut dir_stack: VecDeque<(u64, DirectoryEntry)> = VecDeque::new();

    // If it doesn't fit we need to panic as it is an implementation problem with misconfigured const's
    let (root_size, root_entry) = read_entry(table[..VAULTENTRY_LENGTH].try_into().unwrap())?;
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
                .unwrap(),
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
                    cur_dir.1.add_vaultentry(VaultEntry::Password(pwd));
                }
                VaultEntry::Secret(sec) => {
                    cur_dir.1.add_vaultentry(VaultEntry::Secret(sec));
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
            let res_dir = dir_stack.pop_front().unwrap();
            let dir = res_dir.1;
            {
                let cur_dir = dir_stack.front_mut();
                cur_dir
                    .unwrap()
                    .1
                    .add_vaultentry(VaultEntry::Directory(dir));
            }
        }
    }
}

/// Convert a raw u8 slice of length `VAULT_ENTRY_LENGTH` to a VaultEntry
fn read_entry(
    entry_data: [u8; VAULTENTRY_LENGTH],
) -> Result<(u64, VaultEntry), ReadVaultFileError> {
    match entry_data[0] {
        DIRENTRY_TYPE => {
            // Directory Entry
            let entry = DirectoryEntry::build_entry(entry_data)?;
            Ok((entry.0, VaultEntry::Directory(entry.1)))
        }
        PASSWORDENTRY_TYPE => {
            //Password Entry
            let entry = PasswordEntry::build_entry(entry_data)?;
            Ok((entry.0, VaultEntry::Password(entry.1)))
        }
        SECRETENTRY_TYPE => {
            //Secret File Entry
            let entry = SecretFileEntry::build_entry(entry_data)?;
            Ok((entry.0, VaultEntry::Secret(entry.1)))
        }
        _ => Err(ReadVaultFileError::InvalidFile(
            InvalidFileReasons::UnkownEntryType,
        )),
    }
}

/// Get the user key based on an initialization vector using PBKDF2 algorithm
fn get_user_key(iv: &[u8; IV_LENGTH]) -> Result<[u8; VAULTKEY_LENGTH], std::io::Error> {
    let mut pwd: String = String::new();
    stdin().read_line(&mut pwd)?;

    Ok(generate_user_key(pwd, iv))
}
