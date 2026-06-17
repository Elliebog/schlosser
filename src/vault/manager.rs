use bytes::{Buf, BufMut, Bytes, BytesMut};
use zeroize::Zeroize;

use crate::crypt::{AES_NONCE_LENGTH, IV_LENGTH, KEY_LENGTH, decrypt_region, decrypt_region_dyn, generate_user_key};
use crate::vault::entry::{
    DirectoryEntry, EncryptedEntry, Entry, EntryResult, PasswordEntry, SecretFileEntry, VaultEntry,
};
use crate::vault::error::{
    DeleteEntryError, EntryType, InvalidFileReasons, NewEntryError, Operation, ReadVaultFileError, RenameEntryError, RetrieveKeyError, RetrieveSecretError, VaultChangeEntryError, VaultError
};
use crate::vault::utils::{BlockSet, VaultPath, read_dyn_field, read_field};
use std::io::{BufWriter, Seek, SeekFrom};
use std::{
    collections::VecDeque,
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
const VAULTKEY_ENC_LENGTH: usize = VAULTKEY_LENGTH + AES_GCM_AUTH_TAG;
const VAULTTABLE_SIZE_LENGTH: usize = 8; //64 bit for u64

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
    + VAULTKEY_ENC_LENGTH
    + AES_NONCE_LENGTH;
pub(crate) const DATABLOCK_RAW_LENGTH: usize = 256;
pub(crate) const DATABLOCK_LENGTH: usize = DATABLOCK_RAW_LENGTH + AES_GCM_AUTH_TAG;

/// Maint Entry point that manages vault information about a schlosser vault
#[derive(Debug)]
struct VaultManager {
    /// Info regarding the header section
    header: HeaderInfo,
    /// The root vault entry
    root_entry: DirectoryEntry,
    /// The path to the archive file
    vault_path: String,
    /// internal context for tracking changes to the vault
    context: VaultChangeContext,
}

impl VaultManager {
    pub fn from_file(file_path: String) -> Result<VaultManager, ReadVaultFileError> {
        let path = Path::new(&file_path);
        let file = File::open(path).map_err(|e| ReadVaultFileError::FileError(e))?;
        let mut reader = BufReader::new(file);
        let header_info: HeaderInfo = HeaderInfo::build_header(&mut reader)?;
        let root_entry: DirectoryEntry = read_vault_table(&mut reader, &header_info)?;
        let context = VaultChangeContext::new(&root_entry);
        Ok(VaultManager {
            header: header_info,
            root_entry,
            vault_path: file_path,
            context,
        })
    }

    pub fn get_vault_info(&self) -> Result<String, std::fmt::Error> {
        let mut out: String = format!("{} Archive", self.header.name);
        self.root_entry.get_directory_overview(0, &mut out)?;

        Ok(out)
    }

    pub fn retrieve_secret_entry(
        &self,
        entry_path: String,
    ) -> Result<EntryResult, RetrieveSecretError> {
        let path = VaultPath::new(entry_path.clone())
            .map_err(|e| RetrieveSecretError::InvalidVaultPath(e))?;
        let file = File::open(Path::new(&self.vault_path))
            .map_err(|e| RetrieveSecretError::FileError(e))?;
        let mut reader = BufReader::new(file);

        let target_entry = self.root_entry.get_entry(path.parts().into(), &path)?;
        let mut vaultkey = self.header.retrieve_key().map_err(|e| RetrieveSecretError::RetrieveKeyError(e))?;
        let res = target_entry.retrieve_secret(&mut reader, self.header.calculate_data_start(), &vaultkey);
        // Remove vaultkey from memory before returning the result
        vaultkey.zeroize();
        res
    }

    /// Writes the vault to the vault archive file
    pub fn save_vault(&self) -> Result<(), VaultError> {
        let file = File::open(Path::new(&self.vault_path))
            .map_err(|e| VaultError::ReadVaultError(ReadVaultFileError::FileError(e)))?;
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
            VaultEntry::Password(pwd) => {
                let mut vault_key = self.header.retrieve_key().map_err(|e| VaultChangeEntryError::RetrieveKeyError(e))?;
                let res = pwd
                .change_secret(&mut self.context, &vault_key, password)
                .map_err(|e| VaultChangeEntryError::VaultChangeError(e));
                vault_key.zeroize();
                res
            },
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
            VaultEntry::Secret(sec) => {
                let mut vault_key = self.header.retrieve_key().map_err(|e| VaultChangeEntryError::RetrieveKeyError(e))?;
                let res = sec
                .change_secret(&mut self.context, &vault_key, secret_file_path)
                .map_err(|e| VaultChangeEntryError::VaultChangeError(e));
                vault_key.zeroize();
                res
            },
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
        let mut vault_key = self.header.retrieve_key().map_err(|e| NewEntryError::RetrieveKeyError(e))?;
        let secret = 
            SecretFileEntry::new(secret_name, file_path, &mut self.context, &vault_key)
                .map_err(|e| NewEntryError::VaultChangeError(e))?;
        let res = self.root_entry
            .new_entry(path.parts().into(), &path, VaultEntry::Secret(secret))
            .map_err(|e| NewEntryError::VaultError(e));
        vault_key.zeroize();
        res
    }

    pub fn new_password(
        &mut self,
        parent_path: String,
        password_name: String,
        password: String,
    ) -> Result<(), NewEntryError> {
        let path = VaultPath::new(parent_path).map_err(|e| NewEntryError::InvalidVaultPath(e))?;

        let mut vault_key = self.header.retrieve_key().map_err(|e| NewEntryError::RetrieveKeyError(e))?;
        let password =
            PasswordEntry::new(password_name, password, &mut self.context, &vault_key)
                .map_err(|e| NewEntryError::VaultChangeError(e))?;

        let res = self.root_entry
            .new_entry(path.parts().into(), &path, VaultEntry::Password(password))
            .map_err(|e| NewEntryError::VaultError(e));
        vault_key.zeroize();
        res
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
    /// User key initialization vector
    userkey_iv: [u8; IV_LENGTH],
    /// Key Region nonce
    vaultkey_nonce: [u8; AES_NONCE_LENGTH],
    /// Encrypted VaultKey (includes authentication tag)
    enc_vaultkey: [u8; VAULTKEY_ENC_LENGTH],
    /// Size of the vault table
    vault_table_size: u64,
    /// Nonce used for encrypting the vault table
    vault_table_nonce: [u8; AES_NONCE_LENGTH],
}

impl HeaderInfo {
    /// Serialize this header for storage in the vault archive file
    fn serialize(&self) -> [u8; HEADER_LENGTH] {
        let mut header_data = BytesMut::zeroed(HEADER_LENGTH);
        header_data.put_u64(VAULT_SIGNATURE);
        header_data.put_u8(self.version);

        let name_bytes = self.name.as_bytes();
        header_data.put_slice(name_bytes);
        // advance because we are using fixed length strings in the format
        header_data.advance(VAULTNAME_LENGTH - name_bytes.len());

        header_data.put_slice(&self.userkey_iv);
        header_data.put_slice(&self.enc_vaultkey);
        header_data.put_u64(self.vault_table_size);
        header_data.put_slice(&self.vault_table_nonce);
        header_data.as_array().unwrap().to_owned()
    }

    /// Get the key encrypted in the header using the supplied password. Uses pbkdf2_hmac to
    /// generate a key which is then used to decrypt the vault master key
    fn retrieve_key(&self) -> Result<[u8; KEY_LENGTH], RetrieveKeyError>{
        let mut pwd: String = String::new();
        stdin().read_line(&mut pwd).map_err(|e| RetrieveKeyError::StdinError(e))?;

        let user_key = generate_user_key(pwd, &self.userkey_iv);
        let vault_key = decrypt_region::<KEY_LENGTH>(&self.enc_vaultkey, &self.vaultkey_nonce, &user_key);
        vault_key.map_err(|e| RetrieveKeyError::DecryptError(e))
    }

    /// Read the vault archive file header.
    /// This expects the Bufreader to be at the start of the file
    fn build_header(reader: &mut BufReader<File>) -> Result<Self, ReadVaultFileError> {
        let mut offset: u64 = 0;
        // Check if this file is meant to be a vault archive file
        let signature = u64::from_be_bytes(
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

        //Get the keyregion nonce for decrypting the keyregion
        let keyregion_nonce = read_field::<AES_NONCE_LENGTH>(reader)
            .map_err(|e| ReadVaultFileError::ReadFieldError(e, offset))?;

        offset += AES_NONCE_LENGTH as u64;

        let keyarr = read_field::<VAULTKEY_ENC_LENGTH>(reader)
            .map_err(|e| ReadVaultFileError::ReadFieldError(e, offset))?;
        offset += VAULTKEY_ENC_LENGTH as u64;

        let vaulttable_size = read_field::<VAULTTABLE_SIZE_LENGTH>(reader)
            .map_err(|e| ReadVaultFileError::ReadFieldError(e, offset))?;
        offset += VAULTTABLE_SIZE_LENGTH as u64;

        let vault_nonce = read_field::<AES_NONCE_LENGTH>(reader)
            .map_err(|e| ReadVaultFileError::ReadFieldError(e, offset))?;

        Ok(HeaderInfo {
            version,
            name: vaultname,
            userkey_iv,
            vaultkey_nonce: keyregion_nonce,
            enc_vaultkey: keyarr,
            vault_table_size: u64::from_be_bytes(vaulttable_size),
            vault_table_nonce: vault_nonce,
        })
    }

    /// Calculate the offset of the datablock section
    fn calculate_data_start(&self) -> u64 {
        HEADER_LENGTH as u64 + self.vault_table_size * VAULTENTRY_LENGTH as u64
    }
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
    let mut vault_key = header.retrieve_key().map_err(|e| ReadVaultFileError::RetrieveKeyError(e))?;
    let table = decrypt_region_dyn(vault_table, &header.vault_table_nonce, &vault_key)
        .map_err(|e| ReadVaultFileError::CryptographyError(e))?;
    // Immediately wipe the master vault key from memory to avoid possible core-dump attacks
    vault_key.zeroize();

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
