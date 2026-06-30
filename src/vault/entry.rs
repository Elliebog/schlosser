use std::{
    collections::{HashMap, VecDeque},
    fmt::Write,
    fs::File,
    io::BufReader,
    vec::IntoIter,
};

use bytes::{BufMut, Bytes, BytesMut};

use crate::{
    crypt::{AES_NONCE_LENGTH, EncryptFileError, decrypt_region, encrypt_file, encrypt_region},
    vault::{
        error::{
            EntryType, NameLengthExceededError, Operation, ReadVaultFileError, RenameError,
            RetrieveSecretError, SerializationError, VaultChangeError, VaultError,
        },
        manager::{
            AES_GCM_AUTH_TAG, BLOCKID_LENGTH, DATABLOCK_LENGTH, DIRENTRY_SIZE_LENGTH,
            DIRENTRY_TYPE, DataBlockChange, PASSWORDENTRY_TYPE, SECRET_SIZE_LENGTH,
            SECRETENTRY_TYPE, VAULTENTRY_LENGTH, VAULTENTRYNAME_LENGTH, VAULTNAME_LENGTH,
            VaultChangeContext,
        },
        utils::{BlockRange, BlockSet, VaultPath, read_data_block, read_dyn_data_block},
    },
};
// Vault string constants
const V_CONNECTOR: &str = "│\t";
const LITERAL: &str = "├─ ";
const END_LITERAL: &str = "└ ";

const PWDENTRY_ENC_LENGTH: usize = VAULTENTRYNAME_LENGTH + BLOCKID_LENGTH * 2 + AES_NONCE_LENGTH;
const SECENTRY_ENC_LENGTH: usize =
    VAULTENTRYNAME_LENGTH + BLOCKID_LENGTH * 2 + SECRET_SIZE_LENGTH + AES_NONCE_LENGTH;

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
    /// Displays general information about the entry
    fn display(&self) -> String;
    /// Serializes the entry into an array that fits inside a datablock
    fn serialize(&self, key: &[u8]) -> Result<[u8; DATABLOCK_LENGTH], SerializationError>;
    fn build_entry(
        data: [u8; VAULTENTRY_LENGTH],
        key: &[u8],
        entry_block: u64,
    ) -> Result<(u64, Self), ReadVaultFileError>
    where
        Self: Sized;
    fn rename(
        &mut self,
        new_name: String,
        key: &[u8],
        context: &mut VaultChangeContext,
    ) -> Result<(), RenameError>;
    fn occupied_datablocks(&self) -> BlockSet;
}

/// Entry that holds a password
/// The entry follows the following structure in the file (differs from in memory significantly):
/// Type - The type of the directory entry (u8)
/// Nonce - The nonce for the direntry block ([u8, 12])
/// Name - Name of the directory entry ([u8, 128])
/// Next - index of the next directory entry block (i64)
/// block - Block Id of the password block (u64)
/// block_nonce - Nonce of the password block ([u8, 12])
/// auth tag - Authentication tag of the encrypted fields (everything is encrypted except type and
/// nonce) ([u8; 12])
#[derive(Debug, PartialEq, Eq)]
pub struct PasswordEntry {
    /// Name of the password
    name: [u8; VAULTENTRYNAME_LENGTH],
    /// The block id of the entry
    block: u64,
    /// Index of the next directory entry block in directory (-1 if end of directory)
    next: i64,
    /// Id of the password block
    pwd_block: u64,
    /// Nonce used for decryption of the datablock
    pwd_block_nonce: [u8; AES_NONCE_LENGTH],
}

impl EncryptedEntry<String, String> for PasswordEntry {
    fn retrieve_secret(
        &self,
        reader: &mut BufReader<File>,
        data_start: u64,
        key: &[u8],
    ) -> Result<String, RetrieveSecretError> {
        if self.pwd_block > 0 {
            return Err(RetrieveSecretError::InvalidDataBlockError(self.pwd_block));
        }
        // Overflow cannot happen as the cap on u64 is so high it will never be reached
        let datablock_offset = data_start + self.pwd_block as u64 * DATABLOCK_LENGTH as u64;
        let data = read_data_block(reader, datablock_offset, key, &self.pwd_block_nonce)?;

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
        if name.len() > VAULTENTRYNAME_LENGTH {
            return Err(VaultChangeError::ExceededNameLength(
                NameLengthExceededError { len: name.len() },
            ));
        }
        //convert name to u8 buffer
        let mut namebuffer = BytesMut::zeroed(VAULTENTRYNAME_LENGTH);
        namebuffer.put(name.as_bytes());
        let buffer = namebuffer.freeze();

        let mut data = BytesMut::zeroed(DATABLOCK_LENGTH);
        data.put_slice(input.as_bytes());
        let arr = match data.as_array::<DATABLOCK_LENGTH>() {
            // Can happen because maybe the string was not properly checked
            None => Err(VaultChangeError::InputTooLarge),
            Some(a) => Ok(a),
        }?;

        let enc_data = encrypt_region(arr, key)?;
        let pwd_block = context.empty_blocks.occupy(1);
        let entry_block = context.empty_blocks.occupy(1);
        let entry = PasswordEntry {
            name: buffer.as_array().unwrap().to_owned(),
            block: entry_block.start,
            next: -1,
            pwd_block: pwd_block.start,
            pwd_block_nonce: enc_data.nonce,
        };

        // Push DataBlock first and password entry block after
        context.changes.push(DataBlockChange::ChangeBlock {
            start: entry.pwd_block,
            len: 1,
            data: Bytes::copy_from_slice(&enc_data.data),
        });
        let serialized_entry = entry
            .serialize(key)
            .map_err(|e| VaultChangeError::SerializeError(e))?;
        context.changes.push(DataBlockChange::ChangeBlock {
            start: entry.block,
            len: 1,
            data: Bytes::copy_from_slice(&serialized_entry),
        });
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

        // Because this is a password we can change in place
        let enc_data = encrypt_region(arr, key)?;
        self.pwd_block_nonce = enc_data.nonce;
        context.changes.push(DataBlockChange::new(
            self.pwd_block,
            1,
            Some(Bytes::copy_from_slice(&enc_data.data)),
        ));
        Ok(())
    }
}

impl Entry for PasswordEntry {
    fn display(&self) -> String {
        format!(
            "{} (Password)",
            String::from_utf8(self.name.to_vec()).unwrap()
        )
    }

    fn serialize(&self, key: &[u8]) -> Result<[u8; DATABLOCK_LENGTH], SerializationError> {
        let mut enc_section = BytesMut::zeroed(PWDENTRY_ENC_LENGTH);
        enc_section.put_slice(&self.name);
        enc_section.put_i64(self.next);
        enc_section.put_u64(self.pwd_block);
        enc_section.put_slice(&self.pwd_block_nonce);

        let arr = encrypt_region(enc_section.as_array::<PWDENTRY_ENC_LENGTH>().unwrap(), key)
            .map_err(|e| SerializationError::EncryptError(e))?;

        let mut entry = BytesMut::zeroed(DATABLOCK_LENGTH);
        entry.put_u8(PASSWORDENTRY_TYPE);
        entry.put_slice(&arr.nonce);
        entry.put_slice(&arr.data);
        Ok(entry.freeze().as_array().unwrap().to_owned())
    }

    fn rename(
        &mut self,
        new_name: String,
        key: &[u8],
        context: &mut VaultChangeContext,
    ) -> Result<(), RenameError> {
        if new_name.len() > VAULTNAME_LENGTH {
            Err(RenameError::NameError(NameLengthExceededError {
                len: new_name.len(),
            }))
        } else {
            //convert name to u8 buffer
            let mut namebuffer = BytesMut::zeroed(VAULTENTRYNAME_LENGTH);
            namebuffer.put(new_name.as_bytes());
            let buffer = namebuffer.freeze();

            self.name = buffer.as_array().unwrap().to_owned();

            let new_entry = self
                .serialize(key)
                .map_err(|e| RenameError::SerializationError(e))?;
            context.changes.push(DataBlockChange::ChangeBlock {
                start: self.block,
                len: 1,
                data: Bytes::copy_from_slice(&new_entry),
            });
            Ok(())
        }
    }

    fn occupied_datablocks(&self) -> BlockSet {
        let mut blocks = BlockSet::new();
        blocks.put(BlockRange::new(self.pwd_block, 1));
        blocks.put(BlockRange::new(self.block, 1));
        blocks
    }

    fn build_entry(
        data: [u8; VAULTENTRY_LENGTH],
        key: &[u8],
        entry_block: u64,
    ) -> Result<(u64, Self), ReadVaultFileError>
    where
        Self: Sized,
    {
        //Password Entry
        let mut offset: usize = 1;
        // build_entry function starts after the type of entry has been determined
        // can safely unwrap because we always take at least AES_NONCE_LENGTH items and it is
        // guaranteed to have space due to fixed array length
        let nonce: &[u8; AES_NONCE_LENGTH] =
            &data[offset..offset + AES_NONCE_LENGTH].try_into().unwrap();
        offset += AES_NONCE_LENGTH;
        let entry_data: [u8; PWDENTRY_ENC_LENGTH - AES_GCM_AUTH_TAG] = decrypt_region(
            &data[offset..offset + PWDENTRY_ENC_LENGTH]
                .try_into()
                .unwrap(),
            nonce,
            key,
        )
        .map_err(|e| ReadVaultFileError::CryptographyError(e))?;

        offset = 0;
        // Get the decrypted fields and build struct
        // use a BytesMut buffer because the converted string does not have the same length
        let mut namebuffer = BytesMut::zeroed(VAULTENTRYNAME_LENGTH);
        //check if name is valid utf8
        let name = String::from_utf8(entry_data[offset..offset + VAULTENTRYNAME_LENGTH].to_vec())
            .map_err(|e| ReadVaultFileError::UTF8Error(e, offset as u64))?;
        offset += VAULTENTRYNAME_LENGTH;
        namebuffer.put_slice(name.as_bytes());

        let mut next_blk_buf = [0u8; BLOCKID_LENGTH];
        next_blk_buf.copy_from_slice(&entry_data[offset..offset + BLOCKID_LENGTH]);
        let next_blk = i64::from_be_bytes(next_blk_buf);
        offset += BLOCKID_LENGTH;

        let mut pwd_blk_buf = [0u8; BLOCKID_LENGTH];
        pwd_blk_buf.copy_from_slice(&entry_data[offset..offset + BLOCKID_LENGTH]);
        let pwd_blk_id = u64::from_ne_bytes(pwd_blk_buf);
        offset += BLOCKID_LENGTH;

        let mut pwd_nonce_buf = [0u8; AES_NONCE_LENGTH];
        pwd_nonce_buf.copy_from_slice(&entry_data[offset..offset + BLOCKID_LENGTH]);
        Ok((
            0,
            PasswordEntry {
                name: *namebuffer.freeze().as_array().unwrap(),
                block: entry_block,
                next: next_blk,
                pwd_block: pwd_blk_id,
                pwd_block_nonce: pwd_nonce_buf,
            },
        ))
    }
}

/// Entry for an encrypted Secret File (like a recovery key or a keyfile, or any other kind of file
/// that needs to be kept secure)
/// Structure of the SecretFileEntry in the vault archive file
/// Type - Type of entry (u8)
/// Nonce - Nonce used for encryption of the block entry ([u8; 12])
/// Name - Name of the entry ([u8; 128])
/// Next - Next block in directory order (i64)
/// SecretStart - Block Id of the starting block (u64)
/// SecretSize - Nr of Blocks that belong to the block (u64)
/// SecretNonce - Nonce for the block encryption ([u8; 12])
/// auth tag - Authentication tag of the encrypted fields (everything is encrypted except type and
/// nonce)
///
/// The secret block is a continuous block in memory that is encrypted in its entirety
#[derive(Debug, PartialEq, Eq)]
pub struct SecretFileEntry {
    /// Id of the block containing the entry
    block: u64,
    /// Name of the secret
    name: [u8; VAULTENTRYNAME_LENGTH],
    /// Id of the next directory entry block in the directory
    next: i64,
    /// Block Id of the starting block
    start: u64,
    /// Nr of blocks that make up the secret
    size: u64,
    /// Nonce used for encryption of the block
    nonce: [u8; AES_NONCE_LENGTH],
}

impl EncryptedEntry<String, Bytes> for SecretFileEntry {
    fn retrieve_secret(
        &self,
        reader: &mut BufReader<File>,
        data_start: u64,
        key: &[u8],
    ) -> Result<Bytes, RetrieveSecretError> {
        let data_start = data_start + self.start * DATABLOCK_LENGTH as u64;
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
        let entry_block = context.empty_blocks.occupy(1);
        let secret_block = context
            .empty_blocks
            .occupy(data.data.len() / DATABLOCK_LENGTH);

        let mut namebuffer = BytesMut::zeroed(VAULTENTRYNAME_LENGTH);
        namebuffer.put_slice(name.as_bytes());

        let entry = SecretFileEntry {
            block: entry_block.start,
            name: *namebuffer.freeze().as_array().unwrap(),
            next: -1,
            start: secret_block.start,
            size: secret_block.len() as u64,
            nonce: data.nonce,
        };

        context.changes.push(DataBlockChange::ChangeBlock {
            start: entry.start,
            len: entry.size as usize,
            data: data.data,
        });
        let entry_data = entry
            .serialize(key)
            .map_err(|e| VaultChangeError::SerializeError(e))?;
        context.changes.push(DataBlockChange::ChangeBlock {
            start: entry.block,
            len: 1,
            data: Bytes::copy_from_slice(&entry_data),
        });
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
            let curr_block = BlockRange::new(self.start, self.size as usize);
            context.changes.push(DataBlockChange::new(
                curr_block.start,
                curr_block.len(),
                None,
            ));
            context.empty_blocks.put(curr_block);

            let new_block = context.empty_blocks.occupy(block_len as usize);
            context.changes.push(DataBlockChange::ChangeBlock {
                start: new_block.start,
                len: new_block.len(),
                data: data.data,
            });

            self.start = new_block.start;
            self.size = new_block.len() as u64;
            let new_entry = self
                .serialize(key)
                .map_err(|e| VaultChangeError::SerializeError(e))?;
            context.changes.push(DataBlockChange::ChangeBlock {
                start: self.block,
                len: 1,
                data: Bytes::copy_from_slice(&new_entry),
            });
        } else if block_len == self.size {
            //replace in place
            context.changes.push(DataBlockChange::ChangeBlock {
                start: self.start,
                len: self.size as usize,
                data: data.data,
            });
        } else {
            //shrink
            let diff = self.size - block_len;
            let empty_block = BlockRange::new(self.start + block_len, diff as usize);
            self.size = block_len;
            context.changes.push(DataBlockChange::Zeroize {
                start: empty_block.start,
                len: empty_block.len(),
            });
            context.empty_blocks.put(empty_block);
            context.changes.push(DataBlockChange::ChangeBlock {
                start: self.start,
                len: self.size as usize,
                data: data.data,
            });

            let new_entry = self
                .serialize(key)
                .map_err(|e| VaultChangeError::SerializeError(e))?;
            context.changes.push(DataBlockChange::ChangeBlock {
                start: self.block,
                len: 1,
                data: Bytes::copy_from_slice(&new_entry),
            });
        }
        Ok(())
    }
}

impl Entry for SecretFileEntry {
    fn display(&self) -> String {
        format!("{} (File)", String::from_utf8(self.name.to_vec()).unwrap())
    }

    fn serialize(&self, key: &[u8]) -> Result<[u8; DATABLOCK_LENGTH], SerializationError> {
        let mut enc_bytes = BytesMut::zeroed(SECENTRY_ENC_LENGTH);
        enc_bytes.put_slice(&self.name);
        enc_bytes.put_i64(self.next);
        enc_bytes.put_u64(self.start);
        enc_bytes.put_u64(self.size);
        enc_bytes.put_slice(&self.nonce);

        let data = encrypt_region(enc_bytes.freeze().as_array::<SECENTRY_ENC_LENGTH>().unwrap(), key)
            .map_err(|e| SerializationError::EncryptError(e))?;

        let mut bytes: BytesMut = BytesMut::zeroed(DATABLOCK_LENGTH);
        bytes.put_u8(SECRETENTRY_TYPE);
        bytes.put_slice(&data.nonce);
        bytes.put_slice(&data.data);
        match bytes.as_array::<DATABLOCK_LENGTH>() {
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
        Ok((
            0,
            SecretFileEntry {
                secret_name: name,
                secret_block_id: blk_id,
                size,
                nonce,
            },
        ))
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
    block: DirectoryEntryBlock,
}

impl PartialEq for DirectoryEntry {
    fn eq(&self, other: &Self) -> bool {
        if self.directory_name != self.directory_name {
            return false;
        }
        let other_values: Vec<&VaultEntry> = other.children.values().collect();
        let self_values: Vec<&VaultEntry> = self.children.values().collect();
        other_values == self_values && self.block == other.block
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

    pub fn serialize_dir(&self) -> Result<Bytes, SerializationError> {
        let mut bytes = BytesMut::with_capacity(VAULTENTRY_LENGTH * self.children.len());
        // Serialize self
        bytes.put_slice(&self.serialize()?);
        for entry in self.children.values() {
            if let VaultEntry::Directory(dir) = entry {
                let subdir_bytes = dir.serialize_dir()?;
                // bytes only has space for self.children.len() amount of vault entries -> Reserve
                // space for sub-directory contents.
                // serialize_dir includes the directory entry and not just the subdirectory contents
                // -> but the space for directory entry exists -> only reserve subdir content bytes
                bytes.reserve(subdir_bytes.len() - VAULTENTRY_LENGTH);
                bytes.put(subdir_bytes);
            } else {
                bytes.put_slice(&entry.serialize()?);
            }
        }
        Ok(bytes.freeze())
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
        }
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
