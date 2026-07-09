use bytes::{Buf, BufMut, Bytes, BytesMut};
use zeroize::Zeroize;

use crate::crypt::{
    AES_NONCE_LENGTH, IV_LENGTH, KEY_LENGTH, decrypt_region, decrypt_region_dyn, generate_user_key,
};
use crate::vault::entry::{
    DirectoryEntry, EncryptedEntry, Entry, EntryResult, PasswordEntry, SecretFileEntry, VaultEntry,
};
use crate::vault::error::{
    DeleteEntryError, EntryType, InvalidFileReasons, NewEntryError,
    Operation, RenameEntryError, RetrieveKeyError, RetrieveSecretError,
    SaveVaultError, VaultChangeEntryError,
};
use crate::vault::utils::{BlockSet, VaultContext, VaultPath, read_dyn_field, read_field};
use std::fs::OpenOptions;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::{
    collections::VecDeque,
    fs::File,
    io::{BufReader, stdin},
    path::Path,
};

// General Constants
pub const AES_GCM_AUTH_TAG: usize = 16;
pub const VAULTNAME_LENGTH: usize = 128;
//
// Vault Table Constants
pub const ENTRYTYPE_LENGTH: usize = 1;
pub(crate) const PASSWORDENTRY_TYPE: u8 = 0;
pub(crate) const SECRETENTRY_TYPE: u8 = 1;
pub(crate) const DIRENTRY_TYPE: u8 = 2;
pub(crate) const VAULTENTRY_LENGTH: usize = 177;
pub const VAULTENTRYNAME_LENGTH: usize = 128;
const VAULTENTRYTYPE_LENGTH: usize = 1;
pub const BLOCKID_LENGTH: usize = 8;
pub const SECRET_SIZE_LENGTH: usize = 8;
// Vault data constants
pub const DATABLOCK_RAW_LENGTH: usize = 256;
pub const DATABLOCK_LENGTH: usize = DATABLOCK_RAW_LENGTH + AES_GCM_AUTH_TAG;
pub const NEXT_OFFSET: usize = ENTRYTYPE_LENGTH;

/// Maint Entry point that manages vault information about a schlosser vault
#[derive(Debug)]
pub struct VaultManager {
    /// The root vault entry
    root_entry: DirectoryEntry,
    /// internal context for tracking changes to the vault
    context: VaultContext,
}

impl VaultManager {
    pub fn from_file(file_path: String) -> Result<VaultManager, ReadVaultFileError> {
        let path = Path::new(&file_path);
        let file = File::open(path).map_err(|e| ReadVaultFileError::FileError(e))?;
        let mut reader = BufReader::new(file);
        let header_info: HeaderInfo = HeaderInfo::build_header(&mut reader)?;
        let root_entry: DirectoryEntry = read_vault_table(&mut reader, &header_info)?;
        //TODO handle vaultcontext locking error
        let context = VaultContext::new(file_path, &root_entry);
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

    fn retrieve_secret_entry(
        &self,
        entry_path: &String,
    ) -> Result<EntryResult, RetrieveSecretError> {
        let path = VaultPath::new(entry_path.clone())
            .map_err(|e| RetrieveSecretError::InvalidVaultPath(e))?;
        let file = File::open(Path::new(&self.vault_path))
            .map_err(|e| RetrieveSecretError::FileError(e))?;
        let mut reader = BufReader::new(file);

        let target_entry = self.root_entry.get_entry(path.parts().into(), &path)?;
        let mut vaultkey = self
            .header
            .retrieve_key()
            .map_err(|e| RetrieveSecretError::RetrieveKeyError(e))?;
        let res = target_entry.retrieve_secret(
            &mut reader,
            self.header.calculate_data_start(),
            &vaultkey,
        );
        // Remove vaultkey from memory before returning the result
        vaultkey.zeroize();
        res
    }

    /// Writes the vault to the vault archive file
    pub fn save_vault(&mut self) -> Result<(), SaveVaultError> {
        // encrypt vaulttable first as the nonce needs to be stored in the header
        let vault_table = self
            .get_encrypted_vaulttable()
            .map_err(|e| SaveVaultError::EncryptVaultTableError(e))?;
        self.header.vault_table_nonce = vault_table.nonce;

        let header_data = self.header.serialize();
        let file = OpenOptions::new()
            .write(true)
            .append(false)
            .open(self.vault_path);
        let file = File::open(self.vault_path).map_err(|e| SaveVaultError::FileError(e))?;
        let writer = BufWriter::new(file);

        // write header and vaulttable
        writer.write(&header_data);
        writer.write(&vault_table.data.to_vec());
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
                let mut vault_key = self
                    .header
                    .retrieve_key()
                    .map_err(|e| VaultChangeEntryError::RetrieveKeyError(e))?;
                let res = pwd
                    .change_secret(&mut self.context, &vault_key, password)
                    .map_err(|e| VaultChangeEntryError::VaultChangeError(e));
                vault_key.zeroize();
                res
            }
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
                let mut vault_key = self
                    .header
                    .retrieve_key()
                    .map_err(|e| VaultChangeEntryError::RetrieveKeyError(e))?;
                let res = sec
                    .change_secret(&mut self.context, &vault_key, secret_file_path)
                    .map_err(|e| VaultChangeEntryError::VaultChangeError(e));
                vault_key.zeroize();
                res
            }
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
        let mut vault_key = self
            .header
            .retrieve_key()
            .map_err(|e| NewEntryError::RetrieveKeyError(e))?;
        let secret = SecretFileEntry::new(secret_name, file_path, &mut self.context, &vault_key)
            .map_err(|e| NewEntryError::VaultChangeError(e))?;
        let res = self
            .root_entry
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

        let mut vault_key = self
            .header
            .retrieve_key()
            .map_err(|e| NewEntryError::RetrieveKeyError(e))?;
        let password = PasswordEntry::new(password_name, password, &mut self.context, &vault_key)
            .map_err(|e| NewEntryError::VaultChangeError(e))?;

        let res = self
            .root_entry
            .new_entry(path.parts().into(), &path, VaultEntry::Password(password))
            .map_err(|e| NewEntryError::VaultError(e));
        vault_key.zeroize();
        res
    }
}

#[derive(Debug)]
pub enum DataBlockChange {
    ChangeBlock { start: u64, len: usize, data: Bytes },
    ChangeNext(i64),
    Zeroize { start: u64, len: usize },
}

impl DataBlockChange {
    pub fn new(start: u64, len: usize, data: Option<Bytes>) -> Self {
        DataBlockChange { start, len, data }
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
    let mut vault_key = header
        .retrieve_key()
        .map_err(|e| ReadVaultFileError::RetrieveKeyError(e))?;
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
