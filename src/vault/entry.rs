use std::{
    collections::{HashMap, VecDeque},
    fmt::Write,
    fs::File,
    io::BufReader,
    vec::IntoIter,
};

use bytes::{BufMut, Bytes, BytesMut};

use crate::{
    crypt::{AES_NONCE_LENGTH, EncryptFileError, encrypt_file, encrypt_region},
    vault::{
        error::{
            EntryType, NameLengthExceededError, Operation, ReadVaultFileError, RetrieveSecretError,
            SerializationError, VaultChangeError, VaultError,
        },
        manager::{
            BLOCKID_LENGTH, DATABLOCK_LENGTH, DIRENTRY_SIZE_LENGTH, DIRENTRY_TYPE, DataBlockChange,
            PASSWORDENTRY_TYPE, SECRET_SIZE_LENGTH, SECRETENTRY_TYPE, VAULTENTRY_LENGTH,
            VAULTENTRYNAME_LENGTH, VAULTNAME_LENGTH, VaultChangeContext,
        },
        utils::{BlockRange, BlockSet, VaultPath, read_data_block, read_dyn_data_block},
    },
};
// Vault string constants
const V_CONNECTOR: &str = "│\t";
const LITERAL: &str = "├─ ";
const END_LITERAL: &str = "└ ";

/// An Enum representing the result of an entry secret retrieval
pub enum EntryResult {
    Password(String),
    Secret(Bytes),
    Directory(String),
}

/// A trait that defines functions for entries that contain secrets to implement.
/// This trait is not used dynamically for references in Vaultentries but rather just gives a
/// baseline of functions for entries to implement
/// In the future this trait and VaultEntry may need to be refactored if a lot of new types need to
/// be added
pub trait EncryptedEntry<I, O> {
    fn retrieve_secret(
        &self,
        reader: &mut BufReader<File>,
        data_start: u64,
        key: &[u8],
    ) -> Result<O, RetrieveSecretError>;

    fn new(
        name: String,
        input: I,
        context: &mut VaultChangeContext,
        key: &[u8],
    ) -> Result<Self, VaultChangeError>
    where
        Self: Sized;
    fn change_secret(
        &mut self,
        context: &mut VaultChangeContext,
        key: &[u8],
        new_input: I,
    ) -> Result<(), VaultChangeError>;
}

/// Basic trait that every trait should implement
/// The same caveats as for `EncryptedEntry<T>` trait apply
pub trait Entry {
    fn display(&self) -> String;
    fn serialize(&self) -> Result<[u8; VAULTENTRY_LENGTH], SerializationError>;
    fn build_entry(data: [u8; VAULTENTRY_LENGTH]) -> Result<(u64, Self), ReadVaultFileError>
    where
        Self: Sized;
    fn rename(&mut self, new_name: String) -> Result<(), NameLengthExceededError>;
    fn occupied_datablocks(&self) -> BlockSet;
}

/// Entry that holds a password
#[derive(Debug, PartialEq, Eq)]
pub struct PasswordEntry {
    /// Name of the password
    password_name: String,
    /// Id of the secret block
    secret_block_id: u64,
    /// Nonce used for decryption of the datablock
    nonce: [u8; AES_NONCE_LENGTH],
}

impl EncryptedEntry<String, String> for PasswordEntry {
    fn retrieve_secret(
        &self,
        reader: &mut BufReader<File>,
        data_start: u64,
        key: &[u8],
    ) -> Result<String, RetrieveSecretError> {
        let data_block_start = data_start + self.secret_block_id * DATABLOCK_LENGTH as u64;
        let data = read_data_block(reader, data_block_start, key, &self.nonce)?;

        // Passwords are encrypted by first padding the field with 0's
        // To get the original password we discard anything that is not ascii
        String::from_utf8(data.to_vec()).map_err(|e| RetrieveSecretError::UTF8Error(e))
    }

    fn new(
        name: String,
        input: String,
        context: &mut VaultChangeContext,
        key: &[u8],
    ) -> Result<Self, VaultChangeError> {
        if name.len() > VAULTENTRY_LENGTH {
            return Err(VaultChangeError::ExceededNameLength(
                NameLengthExceededError { len: name.len() },
            ));
        }
        let mut data = BytesMut::zeroed(DATABLOCK_LENGTH);
        data.put_slice(input.as_bytes());
        let arr = match data.as_array::<DATABLOCK_LENGTH>() {
            // Can happen because maybe the string was not properly checked
            None => Err(VaultChangeError::InputTooLarge),
            Some(a) => Ok(a),
        }?;
        let enc_data = encrypt_region(arr, key)?;
        let block = context.empty_blocks.occupy(1);
        let entry = PasswordEntry {
            password_name: name,
            secret_block_id: block.start,
            nonce: enc_data.nonce,
        };
        let change = DataBlockChange::new(
            block.start,
            block.len(),
            Some(Bytes::copy_from_slice(&enc_data.data)),
        );
        context.changes.push(change);
        Ok(entry)
    }

    fn change_secret(
        &mut self,
        context: &mut VaultChangeContext,
        key: &[u8],
        new_input: String,
    ) -> Result<(), VaultChangeError> {
        let mut data = BytesMut::zeroed(DATABLOCK_LENGTH);
        data.put_slice(new_input.as_bytes());
        let arr = match data.as_array::<DATABLOCK_LENGTH>() {
            // Can happen because maybe the string was not properly checked
            None => Err(VaultChangeError::InputTooLarge),
            Some(a) => Ok(a),
        }?;
        let enc_data = encrypt_region(arr, key)?;
        let block = context.empty_blocks.occupy(1);
        self.nonce = enc_data.nonce;
        self.secret_block_id = block.start;
        context.changes.push(DataBlockChange::new(
            block.start,
            block.len(),
            Some(Bytes::copy_from_slice(&enc_data.data)),
        ));
        Ok(())
    }
}

impl Entry for PasswordEntry {
    fn display(&self) -> String {
        format!("{} (Password)", self.password_name)
    }

    fn serialize(&self) -> Result<[u8; VAULTENTRY_LENGTH], SerializationError> {
        let mut entry = BytesMut::zeroed(VAULTENTRY_LENGTH);
        entry.put_u8(PASSWORDENTRY_TYPE);
        entry.put(self.password_name.as_bytes());
        entry.put_u64(self.secret_block_id);
        entry.put(&self.nonce[..]);
        // Extra insurance if string manipulation was not handled properly
        match entry.as_array::<VAULTENTRY_LENGTH>() {
            Some(e) => Ok(e.to_owned()),
            None => Err(SerializationError::InvalidLength),
        }
    }

    fn rename(&mut self, new_name: String) -> Result<(), NameLengthExceededError> {
        if new_name.len() > VAULTNAME_LENGTH {
            Err(NameLengthExceededError {
                len: new_name.len(),
            })
        } else {
            self.password_name = new_name;
            Ok(())
        }
    }

    fn occupied_datablocks(&self) -> BlockSet {
        let mut blocks = BlockSet::new();
        blocks.put(BlockRange::new(self.secret_block_id, 1));
        blocks
    }

    fn build_entry(data: [u8; VAULTENTRY_LENGTH]) -> Result<(u64, Self), ReadVaultFileError>
    where
        Self: Sized,
    {
        //Password Entry
        let mut offset: usize = 1;
        let name = String::from_utf8(data[offset..offset + VAULTENTRY_LENGTH].to_vec())
            .map_err(|e| ReadVaultFileError::UTF8Error(e, offset as u64))?;
        offset += VAULTENTRYNAME_LENGTH;
        // Because array of Copy types are copied when doing a slice this does not consume the
        // entry_data array
        let blk_id = u64::from_ne_bytes(data[offset..offset + BLOCKID_LENGTH].try_into().unwrap());
        offset += BLOCKID_LENGTH;
        let nonce: [u8; AES_NONCE_LENGTH] =
            data[offset..offset + AES_NONCE_LENGTH].try_into().unwrap();
        Ok((
            0,
            PasswordEntry {
                password_name: name,
                secret_block_id: blk_id,
                nonce,
            },
        ))
    }
}

/// Entry for an encrypted Secret File (like a recovery key or a keyfile, or any other kind of file
/// that needs to be kept secure)
#[derive(Debug, PartialEq, Eq)]
pub struct SecretFileEntry {
    /// Name of the secret
    secret_name: String,
    /// Id of the starting secret block
    pub secret_block_id: u64,
    /// Length of the secret file
    pub size: u64,
    /// Nonce used for decryption of the datablocks
    pub nonce: [u8; AES_NONCE_LENGTH],
}

impl EncryptedEntry<String, Bytes> for SecretFileEntry {
    fn retrieve_secret(
        &self,
        reader: &mut BufReader<File>,
        data_start: u64,
        key: &[u8],
    ) -> Result<Bytes, RetrieveSecretError> {
        let data_start = data_start + self.secret_block_id * DATABLOCK_LENGTH as u64;
        let data = read_dyn_data_block(
            reader,
            data_start,
            key,
            &self.nonce,
            self.size as usize * DATABLOCK_LENGTH,
        )?;
        Ok(Bytes::from(data))
    }

    fn new(
        name: String,
        input: String,
        context: &mut VaultChangeContext,
        key: &[u8],
    ) -> Result<Self, VaultChangeError> {
        if name.len() > VAULTNAME_LENGTH {
            return Err(VaultChangeError::ExceededNameLength(
                NameLengthExceededError { len: name.len() },
            ));
        }
        let data = encrypt_file(input, key).map_err(|e| match e {
            EncryptFileError::CryptoError(e) => VaultChangeError::CryptographyError(e),
            EncryptFileError::FileError(e) => VaultChangeError::FileError(e),
        })?;
        let block = context
            .empty_blocks
            .occupy(data.data.len() / DATABLOCK_LENGTH);
        let entry = SecretFileEntry {
            secret_name: name,
            secret_block_id: block.start,
            size: block.len() as u64,
            nonce: data.nonce,
        };

        context.changes.push(DataBlockChange::new(
            block.start,
            block.len(),
            Some(data.data),
        ));
        Ok(entry)
    }

    fn change_secret(
        &mut self,
        context: &mut VaultChangeContext,
        key: &[u8],
        new_input: String,
    ) -> Result<(), VaultChangeError> {
        let data = encrypt_file(new_input, key).map_err(|e| match e {
            EncryptFileError::CryptoError(e) => VaultChangeError::CryptographyError(e),
            EncryptFileError::FileError(e) => VaultChangeError::FileError(e),
        })?;

        let block_len = (data.data.len() / DATABLOCK_LENGTH) as u64;

        if block_len > self.size {
            //mark empty and occupy new
            let curr_block = BlockRange::new(self.secret_block_id, self.size as usize);
            context.changes.push(DataBlockChange::new(
                curr_block.start,
                curr_block.len(),
                None,
            ));
            context.empty_blocks.put(curr_block);

            let new_block = context.empty_blocks.occupy(block_len as usize);
            context.changes.push(DataBlockChange::new(
                new_block.start,
                new_block.len(),
                Some(data.data),
            ));
            self.secret_block_id = new_block.start;
            self.size = new_block.len() as u64;
        } else if block_len == self.size {
            //replace in place
            context.changes.push(DataBlockChange::new(
                self.secret_block_id,
                self.size as usize,
                Some(data.data),
            ));
        } else {
            //shrink
            let diff = self.size - block_len;
            let empty_block = BlockRange::new(self.secret_block_id + block_len, diff as usize);
            context.changes.push(DataBlockChange::new(
                empty_block.start,
                empty_block.len(),
                None,
            ));
            context.empty_blocks.put(empty_block);
            context.changes.push(DataBlockChange::new(
                self.secret_block_id,
                block_len as usize,
                Some(data.data),
            ));
        }
        Ok(())
    }
}

impl Entry for SecretFileEntry {
    fn display(&self) -> String {
        format!("{} (File)", self.secret_name)
    }

    fn serialize(&self) -> Result<[u8; VAULTENTRY_LENGTH], SerializationError> {
        let mut bytes: BytesMut = BytesMut::zeroed(VAULTENTRY_LENGTH);
        bytes.put_u8(SECRETENTRY_TYPE);
        bytes.put(self.secret_name.as_bytes());
        bytes.put_u64(self.secret_block_id);
        bytes.put_u64(self.size);
        bytes.put(&self.nonce[..]);
        match bytes.as_array::<VAULTENTRY_LENGTH>() {
            Some(e) => Ok(e.to_owned()),
            None => Err(SerializationError::InvalidLength),
        }
    }

    fn build_entry(data: [u8; VAULTENTRY_LENGTH]) -> Result<(u64, Self), ReadVaultFileError>
    where
        Self: Sized,
    {
        //Secret File Entry
        let mut offset = 1;
        let name = String::from_utf8(data[offset..offset + VAULTENTRY_LENGTH].to_vec())
            .map_err(|e| ReadVaultFileError::UTF8Error(e, offset as u64))?;
        offset += VAULTENTRYNAME_LENGTH;
        // Because array of Copy types are copied when doing a slice this does not consume the
        // entry_data array
        let blk_id = u64::from_ne_bytes(data[offset..offset + BLOCKID_LENGTH].try_into().unwrap());
        offset += BLOCKID_LENGTH;
        let size = u64::from_ne_bytes(
            data[offset..offset + SECRET_SIZE_LENGTH]
                .try_into()
                .unwrap(),
        );
        offset += SECRET_SIZE_LENGTH;
        let nonce: [u8; AES_NONCE_LENGTH] =
            data[offset..offset + AES_NONCE_LENGTH].try_into().unwrap();
        Ok((0, SecretFileEntry {
            secret_name: name,
            secret_block_id: blk_id,
            size,
            nonce,
        }))
    }

    fn rename(&mut self, new_name: String) -> Result<(), NameLengthExceededError> {
        if new_name.len() > VAULTNAME_LENGTH {
            Err(NameLengthExceededError {
                len: new_name.len(),
            })
        } else {
            self.secret_name = new_name;
            Ok(())
        }
    }

    fn occupied_datablocks(&self) -> BlockSet {
        let mut blocks = BlockSet::new();
        blocks.put(BlockRange::new(self.secret_block_id, self.size as usize));
        blocks
    }
}

/// Entry that represents a directory in the vault structure
#[derive(Debug)]
pub struct DirectoryEntry {
    /// Name of the directory
    pub directory_name: String,
    /// Entries that are in the directory. A Hashmap is used to facilitate faster password and
    /// secret lookups
    children: HashMap<String, VaultEntry>,
}

impl PartialEq for DirectoryEntry {
    fn eq(&self, other: &Self) -> bool {
        if self.directory_name != self.directory_name {
            return false;
        }
        let other_values: Vec<&VaultEntry> = other.children.values().collect();
        let self_values: Vec<&VaultEntry> = self.children.values().collect();
        other_values == self_values
    }
}
impl Eq for DirectoryEntry {}

impl Entry for DirectoryEntry {
    fn display(&self) -> String {
        format!("{}: {} Items", self.directory_name, self.children.len())
    }

    fn serialize(&self) -> Result<[u8; VAULTENTRY_LENGTH], SerializationError> {
        let mut bytes: BytesMut = BytesMut::zeroed(VAULTENTRY_LENGTH);
        bytes.put_u8(DIRENTRY_TYPE);
        bytes.put(self.directory_name.as_bytes());
        bytes.put_u64(self.children.len() as u64);
        match bytes.as_array::<VAULTENTRY_LENGTH>() {
            Some(e) => Ok(e.to_owned()),
            None => Err(SerializationError::InvalidLength),
        }
    }

    fn build_entry(data: [u8; VAULTENTRY_LENGTH]) -> Result<(u64, Self), ReadVaultFileError>
    where
        Self: Sized,
    {
        // Directory Entry
        let mut offset: usize = 1;
        let name = String::from_utf8(data[offset..offset + VAULTENTRY_LENGTH].to_vec())
            .map_err(|e| ReadVaultFileError::UTF8Error(e, offset as u64))?;
        offset += VAULTENTRYNAME_LENGTH;
        // Because array of Copy types are copied when doing a slice this does not consume the
        // entry_data array
        let size = u64::from_ne_bytes(
            data[offset..offset + DIRENTRY_SIZE_LENGTH]
                .try_into()
                .unwrap(),
        );
        Ok((
            size,
            DirectoryEntry {
                directory_name: name,
                children: HashMap::new(),
            },
        ))
    }

    fn rename(&mut self, new_name: String) -> Result<(), NameLengthExceededError> {
        if new_name.len() > VAULTNAME_LENGTH {
            Err(NameLengthExceededError {
                len: new_name.len(),
            })
        } else {
            self.directory_name = new_name;
            Ok(())
        }
    }

    fn occupied_datablocks(&self) -> BlockSet {
        let mut blocks = BlockSet::new();
        for entry in self.children.values() {
            entry
                .occupied_blocks()
                .into_iter()
                .for_each(|b| blocks.put(b));
        }
        blocks
    }
}

impl DirectoryEntry {
    pub fn new(dir_name: String) -> Result<Self, NameLengthExceededError> {
        if dir_name.len() > VAULTNAME_LENGTH {
            Err(NameLengthExceededError {
                len: dir_name.len(),
            })
        } else {
            Ok(DirectoryEntry {
                children: HashMap::new(),
                directory_name: dir_name,
            })
        }
    }

    pub fn get_sorted_children(&self) -> Vec<&VaultEntry> {
        let mut entries: Vec<&VaultEntry> = self.children.values().collect();
        entries.sort();
        entries
    }

    pub fn get_directory_overview(
        &self,
        depth: u64,
        buffer: &mut String,
    ) -> Result<(), std::fmt::Error> {
        write!(
            buffer,
            "{} {}",
            build_prefix_str(depth, false),
            self.display()
        )?;
        let children = self.get_sorted_children();
        let len = children.len();
        for (i, entry) in children.into_iter().enumerate() {
            let is_last = i == len - 1;
            match entry {
                VaultEntry::Password(pwd) => write!(
                    buffer,
                    "{} {}\n",
                    build_prefix_str(depth, is_last),
                    pwd.display()
                )?,
                VaultEntry::Secret(sec) => write!(
                    buffer,
                    "{} {}\n",
                    build_prefix_str(depth, is_last),
                    sec.display()
                )?,
                VaultEntry::Directory(dir) => {
                    dir.get_directory_overview(depth + 1, buffer)?;
                }
            }
        }
        Ok(())
    }

    pub fn get_children(&self) -> Vec<&VaultEntry> {
        self.children.values().collect()
    }

    pub fn sorted_iter(&self) -> IntoIter<&VaultEntry> {
        let sorted_entries = self.get_sorted_children();
        let mut res: Vec<&VaultEntry> = Vec::new();
        for entry in sorted_entries {
            res.push(entry);
            if let VaultEntry::Directory(dir) = entry {
                dir.sorted_iter().for_each(|e| res.push(e));
            }
        }
        res.into_iter()
    }

    pub fn iter(&self) -> IntoIter<&VaultEntry> {
        let entries = self.get_children();
        let mut res: Vec<&VaultEntry> = Vec::new();
        for entry in entries {
            res.push(entry);
            if let VaultEntry::Directory(dir) = entry {
                dir.iter().for_each(|e| res.push(e));
            }
        }
        res.into_iter()
    }

    /// Gets a reference to an entry that exists within the hierarchy of this directory
    /// Returns an immutable borrow of the VaultEntry enum within the parent directories hashmap
    /// Returns: ['VaultEntry::EntryNotFound'] if the function fails to find the entry with the
    /// specified path
    pub fn get_entry(
        &self,
        mut path: VecDeque<&str>,
        total_path: &VaultPath,
    ) -> Result<&VaultEntry, VaultError> {
        let name = match path.pop_front() {
            None => Err(VaultError::EntryNotFound(total_path.clone())),
            Some(n) => Ok(n),
        }?;
        let entry = match self.children.get(name) {
            None => Err(VaultError::EntryNotFound(total_path.clone())),
            Some(e) => Ok(e),
        }?;

        if path.is_empty() {
            Ok(entry)
        } else if let VaultEntry::Directory(dir) = entry {
            dir.get_entry(path, &total_path)
        } else {
            Err(VaultError::EntryNotFound(total_path.clone()))
        }
    }

    pub fn get_entry_mut(
        &mut self,
        mut path: VecDeque<&str>,
        total_path: &VaultPath,
    ) -> Result<&mut VaultEntry, VaultError> {
        let name = match path.pop_front() {
            None => Err(VaultError::EntryNotFound(total_path.clone())),
            Some(n) => Ok(n),
        }?;
        let entry = match self.children.get_mut(name) {
            None => Err(VaultError::EntryNotFound(total_path.clone())),
            Some(e) => Ok(e),
        }?;

        if path.is_empty() {
            Ok(entry)
        } else {
            if let VaultEntry::Directory(dir) = entry {
                dir.get_entry_mut(path, total_path)
            } else {
                Err(VaultError::EntryNotFound(total_path.clone()))
            }
        }
    }

    /// Renames an entry and updates the entry in the directory and subdirectories
    pub fn rename_entry(
        &mut self,
        mut path: VecDeque<&str>,
        total_path: &VaultPath,
        new_name: String,
    ) -> Result<(), VaultError> {
        // pop next name
        let name = match path.pop_front() {
            None => Err(VaultError::EntryNotFound(total_path.clone())),
            Some(n) => Ok(n),
        }?;

        if !self.children.contains_key(name) {
            return Err(VaultError::EntryNotFound(total_path.clone()));
        };

        if path.is_empty() {
            //Check if name conforms with name length restrictions
            if new_name.len() > VAULTNAME_LENGTH {
                return Err(VaultError::NameError(NameLengthExceededError {
                    len: new_name.len(),
                }));
            }

            if self.children.contains_key(&new_name) {
                Err(VaultError::DuplicateEntry(new_name.clone()))
            } else {
                // Verified already that it exists. can unwrap
                let mut new_entry = self.children.remove(name).unwrap();
                // Rename always succeeds because we check it earlier to avoid ugly interactions
                // with remove
                new_entry.rename(new_name.clone());
                self.children.insert(new_name, new_entry);
                Ok(())
            }
        } else if let VaultEntry::Directory(dir) = self.children.get_mut(name).as_mut().unwrap() {
            dir.rename_entry(path, total_path, new_name)
        } else {
            Err(VaultError::EntryNotFound(total_path.clone()))
        }
    }

    pub fn delete_entry(
        &mut self,
        mut path: VecDeque<&str>,
        total_path: &VaultPath,
        context: &mut VaultChangeContext,
    ) -> Result<(), VaultError> {
        let name = match path.pop_front() {
            None => Err(VaultError::EntryNotFound(total_path.clone())),
            Some(n) => Ok(n),
        }?;

        if !self.children.contains_key(name) {
            return Err(VaultError::EntryNotFound(total_path.clone()));
        }

        if path.is_empty() {
            if let Some(entry) = self.children.remove(name) {
                for block in entry.occupied_blocks().into_iter() {
                    context
                        .changes
                        .push(DataBlockChange::new(block.start, block.len(), None));
                }
            }
            Ok(())
        } else if let VaultEntry::Directory(dir) = self.children.get_mut(name).as_mut().unwrap() {
            dir.delete_entry(path, total_path, context)
        } else {
            Err(VaultError::EntryNotFound(total_path.clone()))
        }
    }

    pub fn new_entry(
        &mut self,
        mut path: VecDeque<&str>,
        parent_path: &VaultPath,
        new_entry: VaultEntry,
    ) -> Result<(), VaultError> {
        if path.len() == 1 {
            //This is the parent directory -> Add it as a direct child
            self.children
                .insert(path.pop_front().unwrap().to_string(), new_entry);
            Ok(())
        } else {
            let name = match path.pop_front() {
                None => Err(VaultError::EntryNotFound(parent_path.clone())),
                Some(n) => Ok(n),
            }?;

            let entry = match self.children.get_mut(name) {
                None => Err(VaultError::EntryNotFound(parent_path.clone())),
                Some(e) => Ok(e),
            }?;

            if let VaultEntry::Directory(dir) = entry {
                dir.new_entry(path, parent_path, new_entry)
            } else {
                Err(VaultError::EntryNotFound(parent_path.clone()))
            }
        }
    }

    /// Adds a VaultEntry directly without the overhead of looking for possible matches in
    /// subdirectory based on VaultPaths
    pub fn add_vaultentry(&mut self, new_entry: VaultEntry) -> Result<(), VaultError> {
        let name = new_entry.name().clone();
        match self.children.insert(new_entry.name().clone(), new_entry) {
            None => Ok(()),
            Some(_) => Err(VaultError::DuplicateEntry(name)),
        }
    }
}

/// A vault entry found in the vault entry table
/// Each entry is 128+8+8 bytes long
#[derive(Debug, PartialEq, Eq)]
pub enum VaultEntry {
    Password(PasswordEntry),
    Secret(SecretFileEntry),
    Directory(DirectoryEntry),
}

impl VaultEntry {
    pub fn display(&self) -> String {
        match self {
            Self::Password(pwd) => pwd.display(),
            Self::Secret(sec) => sec.display(),
            Self::Directory(dir) => dir.display(),
        }
    }

    pub fn serialize(&self) -> Result<[u8; VAULTENTRY_LENGTH], SerializationError> {
        match self {
            VaultEntry::Password(pwd) => pwd.serialize(),
            VaultEntry::Secret(sec) => sec.serialize(),
            VaultEntry::Directory(dir) => dir.serialize(),
        }
    }

    pub fn retrieve_secret(
        &self,
        reader: &mut BufReader<File>,
        data_start: u64,
        key: &[u8],
    ) -> Result<EntryResult, RetrieveSecretError> {
        match self {
            VaultEntry::Password(pwd) => Ok(EntryResult::Password(
                pwd.retrieve_secret(reader, data_start, key)?,
            )),
            VaultEntry::Secret(sec) => Ok(EntryResult::Secret(
                sec.retrieve_secret(reader, data_start, key)?,
            )),
            VaultEntry::Directory(_) => Err(RetrieveSecretError::InvalidOperation(
                Operation::RetrieveSecret,
                EntryType::Directory,
            )),
        }
    }

    pub fn rename(&mut self, new_name: String) -> Result<(), NameLengthExceededError> {
        match self {
            Self::Directory(dir) => dir.rename(new_name),
            Self::Secret(sec) => sec.rename(new_name),
            Self::Password(pwd) => pwd.rename(new_name),
        };
    }

    pub fn name(&self) -> &String {
        match self {
            VaultEntry::Directory(dir) => &dir.directory_name,
            VaultEntry::Secret(sec) => &sec.secret_name,
            VaultEntry::Password(pwd) => &pwd.password_name,
        }
    }

    pub fn occupied_blocks(&self) -> BlockSet {
        match self {
            Self::Secret(sec) => sec.occupied_datablocks(),
            Self::Password(pwd) => pwd.occupied_datablocks(),
            Self::Directory(dir) => dir.occupied_datablocks(),
        }
    }
}

impl VaultEntry {
    fn is_directory(&self) -> bool {
        match &self {
            VaultEntry::Directory(_) => true,
            _ => false,
        }
    }
}
impl PartialOrd for VaultEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VaultEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (VaultEntry::Password(pwd1), VaultEntry::Password(pwd2)) => {
                pwd1.password_name.cmp(&pwd2.password_name)
            }
            (VaultEntry::Password(pwd), VaultEntry::Secret(sec)) => {
                pwd.password_name.cmp(&sec.secret_name)
            }
            (VaultEntry::Password(pwd), VaultEntry::Directory(dir)) => {
                pwd.password_name.cmp(&dir.directory_name)
            }
            (VaultEntry::Secret(sec), VaultEntry::Password(pwd)) => {
                sec.secret_name.cmp(&pwd.password_name)
            }
            (VaultEntry::Secret(sec1), VaultEntry::Secret(sec2)) => {
                sec1.secret_name.cmp(&sec2.secret_name)
            }
            (VaultEntry::Secret(sec), VaultEntry::Directory(dir)) => {
                sec.secret_name.cmp(&dir.directory_name)
            }
            (VaultEntry::Directory(dir), VaultEntry::Password(pwd)) => {
                dir.directory_name.cmp(&pwd.password_name)
            }
            (VaultEntry::Directory(dir), VaultEntry::Secret(sec)) => {
                dir.directory_name.cmp(&sec.secret_name)
            }
            (VaultEntry::Directory(dir1), VaultEntry::Directory(dir2)) => {
                dir1.directory_name.cmp(&dir2.directory_name)
            }
        }
    }
}

fn build_prefix_str(depth: u64, end_leaf: bool) -> String {
    let mut prefix = String::new();
    if end_leaf {
        prefix.insert_str(0, END_LITERAL);
    } else {
        prefix.insert_str(0, LITERAL);
    }

    for _ in 0..depth {
        prefix.insert_str(0, V_CONNECTOR);
    }
    prefix
}
