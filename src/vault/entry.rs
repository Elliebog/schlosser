use std::{
    collections::{HashMap, VecDeque},
    fmt::Write,
    vec::IntoIter,
};

use bytes::{BufMut, Bytes, BytesMut};

use crate::{
    crypt::{
        AES_NONCE_LENGTH, EncryptFileError, decrypt_region, decrypt_region_dyn, encrypt_file,
        encrypt_region,
    },
    vault::{
        error::{
            BuildEntryError, BuildVaultError, EntryType, FileChangeError, NameLengthExceededError,
            Operation, RenameError, RetrieveEntryError, RetrieveSecretError, SerializationError,
            VaultChangeError, VaultError,
        },
        manager::{
            AES_GCM_AUTH_TAG, BLOCKID_LENGTH, DATABLOCK_LENGTH, DATABLOCK_RAW_LENGTH,
            DIRENTRY_TYPE, PASSWORDENTRY_TYPE, SECRET_SIZE_LENGTH, SECRETENTRY_TYPE,
            VAULTENTRY_LENGTH, VAULTENTRYNAME_LENGTH, VAULTNAME_LENGTH,
        },
        utils::{BlockRange, BlockSet, DataBlockEntry, VaultContext, VaultPath},
    },
};
// Vault string constants
const V_CONNECTOR: &str = "│\t";
const LITERAL: &str = "├─ ";
const END_LITERAL: &str = "└ ";

const PWDENTRY_ENC_LENGTH: usize = VAULTENTRYNAME_LENGTH + BLOCKID_LENGTH + AES_NONCE_LENGTH;
const SECENTRY_ENC_LENGTH: usize =
    VAULTENTRYNAME_LENGTH + BLOCKID_LENGTH + SECRET_SIZE_LENGTH + AES_NONCE_LENGTH;
const DIRENTRY_ENC_LENGTH: usize = VAULTENTRYNAME_LENGTH + BLOCKID_LENGTH;

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
        context: &mut VaultContext,
        key: &[u8],
    ) -> Result<O, RetrieveSecretError>;

    fn new(
        name: String,
        input: I,
        context: &mut VaultContext,
        key: &[u8],
    ) -> Result<Self, VaultChangeError>
    where
        Self: Sized;
    fn change_secret(
        &mut self,
        context: &mut VaultContext,
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
        data: DataBlockEntry,
        key: &[u8],
        entry_block: u64,
    ) -> Result<Self, BuildEntryError>
    where
        Self: Sized;
    fn rename(
        &mut self,
        new_name: String,
        key: &[u8],
        context: &mut VaultContext,
    ) -> Result<(), RenameError>;
    fn occupied_datablocks(&self) -> BlockSet;
    fn entry_datablock(&self) -> u64;
    fn get_name(&self) -> String;
    fn get_next(&self) -> i64;
}

/// Entry that holds a password
/// The entry follows the following structure in the file (differs from in memory significantly):
/// Type - The type of the directory entry (u8)
/// Next - index of the next directory entry block (i64)
/// Nonce - The nonce for the direntry block ([u8, 12])
/// Name - Name of the directory entry ([u8, 128])
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
        context: &mut VaultContext,
        key: &[u8],
    ) -> Result<String, RetrieveSecretError> {
        // Overflow cannot happen as the cap on u64 is so high it will never be reached
        let enc_datablock = context
            .read_datablock(self.pwd_block)
            .map_err(|e| RetrieveSecretError::VaultFileError(e))?;
        let data: [u8; DATABLOCK_RAW_LENGTH] =
            decrypt_region(&enc_datablock, &self.pwd_block_nonce, key)
                .map_err(|e| RetrieveSecretError::DecryptError(e))?;

        // Passwords are encrypted by first padding the field with 0's
        // To get the original password we discard anything that is not ascii
        String::from_utf8(data.to_vec()).map_err(|e| RetrieveSecretError::UTF8Error(e))
    }

    fn new(
        name: String,
        input: String,
        context: &mut VaultContext,
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

        let enc_pwd_data = encrypt_region(arr, key)?;
        let pwd_block = context
            .new_block(Bytes::copy_from_slice(&enc_pwd_data.data))
            .map_err(|e| VaultChangeError::FileChangeError(e))?;

        let mut entry = PasswordEntry {
            name: buffer.as_array().unwrap().to_owned(),
            // Unimportant because block is not used for serialization and only used for internal
            // stuff
            block: 0,
            next: -1,
            pwd_block: pwd_block.start,
            pwd_block_nonce: enc_pwd_data.nonce,
        };
        let serialized_entry = entry
            .serialize(key)
            .map_err(|e| VaultChangeError::SerializeError(e))?;
        let entry_block = context
            .new_block(Bytes::copy_from_slice(&serialized_entry))
            .map_err(|e| VaultChangeError::FileChangeError(e))?;

        entry.block = entry_block.start;
        Ok(entry)
    }

    fn change_secret(
        &mut self,
        context: &mut VaultContext,
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
        context.change_data(self.pwd_block, Bytes::copy_from_slice(&enc_data.data));
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
        enc_section.put_u64(self.pwd_block);
        enc_section.put_slice(&self.pwd_block_nonce);

        let arr = encrypt_region(enc_section.as_array::<PWDENTRY_ENC_LENGTH>().unwrap(), key)
            .map_err(|e| SerializationError::EncryptError(e))?;

        let mut entry = BytesMut::zeroed(DATABLOCK_LENGTH);
        entry.put_u8(PASSWORDENTRY_TYPE);
        entry.put_i64(self.next);
        entry.put_slice(&arr.nonce);
        entry.put_slice(&arr.data);
        Ok(entry.freeze().as_array().unwrap().to_owned())
    }

    fn rename(
        &mut self,
        new_name: String,
        key: &[u8],
        context: &mut VaultContext,
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
            context.change_data(self.block, Bytes::copy_from_slice(&new_entry));
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
        data: DataBlockEntry,
        key: &[u8],
        entry_block: u64,
    ) -> Result<Self, BuildEntryError>
    where
        Self: Sized,
    {
        //Password Entry

        let entry_data: [u8; PWDENTRY_ENC_LENGTH] = decrypt_region(
            &data.data[..PWDENTRY_ENC_LENGTH + AES_GCM_AUTH_TAG]
                .try_into()
                .unwrap(),
            &data.nonce,
            key,
        )
        .map_err(|e| BuildEntryError::CryptographyError(e))?;

        let mut offset = 0;
        // Get the decrypted fields and build struct
        // use a BytesMut buffer because the converted string does not have the same length
        let mut namebuffer = BytesMut::zeroed(VAULTENTRYNAME_LENGTH);
        //check if name is valid utf8
        let name = String::from_utf8(entry_data[offset..offset + VAULTENTRYNAME_LENGTH].to_vec())
            .map_err(|e| BuildEntryError::UTF8Error(e, offset as u64))?;
        offset += VAULTENTRYNAME_LENGTH;
        namebuffer.put_slice(name.as_bytes());

        let mut pwd_blk_buf = [0u8; BLOCKID_LENGTH];
        pwd_blk_buf.copy_from_slice(&entry_data[offset..offset + BLOCKID_LENGTH]);
        let pwd_blk_id = u64::from_ne_bytes(pwd_blk_buf);
        offset += BLOCKID_LENGTH;

        let mut pwd_nonce_buf = [0u8; AES_NONCE_LENGTH];
        pwd_nonce_buf.copy_from_slice(&entry_data[offset..offset + BLOCKID_LENGTH]);
        Ok(PasswordEntry {
            name: *namebuffer.freeze().as_array().unwrap(),
            block: entry_block,
            next: data.next,
            pwd_block: pwd_blk_id,
            pwd_block_nonce: pwd_nonce_buf,
        })
    }

    fn entry_datablock(&self) -> u64 {
        self.block
    }

    fn get_name(&self) -> String {
        String::from_utf8(self.name.to_vec()).unwrap()
    }

    fn get_next(&self) -> i64 {
        self.next
    }
}

/// Entry for an encrypted Secret File (like a recovery key or a keyfile, or any other kind of file
/// that needs to be kept secure)
/// Structure of the SecretFileEntry in the vault archive file
/// Type - Type of entry (u8)
/// Next - Next block in directory order (i64)
/// Nonce - Nonce used for encryption of the block entry ([u8; 12])
/// Name - Name of the entry ([u8; 128])
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
        context: &mut VaultContext,
        key: &[u8],
    ) -> Result<Bytes, RetrieveSecretError> {
        let enc_datablock = context
            .read_dyn_datablock(BlockRange::new(self.start, self.size as usize))
            .map_err(|e| RetrieveSecretError::VaultFileError(e))?;
        let data = decrypt_region_dyn(enc_datablock.to_vec(), &self.nonce, key)
            .map_err(|e| RetrieveSecretError::DecryptError(e))?;
        Ok(Bytes::from(data))
    }

    fn new(
        name: String,
        input: String,
        context: &mut VaultContext,
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

        let secret_blk = context
            .new_block(data.data)
            .map_err(|e| VaultChangeError::FileChangeError(e))?;

        let mut namebuffer = BytesMut::zeroed(VAULTENTRYNAME_LENGTH);
        namebuffer.put_slice(name.as_bytes());

        let mut entry = SecretFileEntry {
            block: 0,
            name: *namebuffer.freeze().as_array().unwrap(),
            next: -1,
            start: secret_blk.start,
            size: secret_blk.len() as u64,
            nonce: data.nonce,
        };

        let serialized_entry = entry
            .serialize(key)
            .map_err(|e| VaultChangeError::SerializeError(e))?;
        let entry_blk = context
            .new_block(Bytes::copy_from_slice(&serialized_entry))
            .map_err(|e| VaultChangeError::FileChangeError(e))?;
        entry.block = entry_blk.start;
        Ok(entry)
    }

    fn change_secret(
        &mut self,
        context: &mut VaultContext,
        key: &[u8],
        new_input: String,
    ) -> Result<(), VaultChangeError> {
        let data = encrypt_file(new_input, key).map_err(|e| match e {
            EncryptFileError::CryptoError(e) => VaultChangeError::CryptographyError(e),
            EncryptFileError::FileError(e) => VaultChangeError::FileError(e),
        })?;

        let new_block = context
            .change_dyn_block(BlockRange::new(self.start, self.size as usize), data.data)
            .map_err(|e| VaultChangeError::FileChangeError(e))?;
        if let Some(block) = new_block {
            self.start = block.start;
            self.size = block.len() as u64;

            let serialized_entry = self
                .serialize(key)
                .map_err(|e| VaultChangeError::SerializeError(e))?;
            context
                .change_data(self.block, Bytes::copy_from_slice(&serialized_entry))
                .map_err(|e| VaultChangeError::FileChangeError(e));
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
        enc_bytes.put_u64(self.start);
        enc_bytes.put_u64(self.size);
        enc_bytes.put_slice(&self.nonce);

        let data = encrypt_region(
            enc_bytes
                .freeze()
                .as_array::<SECENTRY_ENC_LENGTH>()
                .unwrap(),
            key,
        )
        .map_err(|e| SerializationError::EncryptError(e))?;

        let mut bytes: BytesMut = BytesMut::zeroed(DATABLOCK_LENGTH);
        bytes.put_u8(SECRETENTRY_TYPE);
        bytes.put_i64(self.next);
        bytes.put_slice(&data.nonce);
        bytes.put_slice(&data.data);
        match bytes.as_array::<DATABLOCK_LENGTH>() {
            Some(e) => Ok(e.to_owned()),
            None => Err(SerializationError::InvalidLength),
        }
    }

    fn build_entry(
        data: DataBlockEntry,
        key: &[u8],
        entry_block: u64,
    ) -> Result<Self, BuildEntryError>
    where
        Self: Sized,
    {
        //Secret File Entry
        let entry = decrypt_region::<SECENTRY_ENC_LENGTH>(
            &data.data[..SECENTRY_ENC_LENGTH + AES_GCM_AUTH_TAG]
                .try_into()
                .unwrap(),
            &data.nonce,
            key,
        )
        .map_err(|e| BuildEntryError::CryptographyError(e))?;

        let mut offset = 0;
        let mut namebuf = BytesMut::zeroed(VAULTENTRYNAME_LENGTH);
        // make sure it is valid utf8
        let name = String::from_utf8(entry[offset..offset + VAULTENTRY_LENGTH].to_vec())
            .map_err(|e| BuildEntryError::UTF8Error(e, offset as u64))?;
        namebuf.put_slice(name.as_bytes());
        offset += VAULTENTRYNAME_LENGTH;

        let mut start_buf = [0u8; BLOCKID_LENGTH];
        start_buf.copy_from_slice(&entry[offset..offset + BLOCKID_LENGTH]);
        let start_blk = u64::from_be_bytes(start_buf);
        offset += BLOCKID_LENGTH;

        let mut size_buf = [0u8; BLOCKID_LENGTH];
        size_buf.copy_from_slice(&entry[offset..offset + BLOCKID_LENGTH]);
        let blk_size = u64::from_be_bytes(size_buf);
        offset += BLOCKID_LENGTH;

        let mut nonce_buf = [0u8; AES_NONCE_LENGTH];
        nonce_buf.copy_from_slice(&entry[offset..offset + AES_NONCE_LENGTH]);

        Ok(SecretFileEntry {
            name: *namebuf.freeze().as_array().unwrap(),
            block: entry_block,
            next: data.next,
            start: start_blk,
            size: blk_size,
            nonce: nonce_buf,
        })
    }

    fn rename(
        &mut self,
        new_name: String,
        key: &[u8],
        context: &mut VaultContext,
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

            self.name = *buffer.as_array().unwrap();
            let data = self
                .serialize(key)
                .map_err(|e| RenameError::SerializationError(e))?;
            context.change_data(self.block, Bytes::copy_from_slice(&data));
            Ok(())
        }
    }

    fn occupied_datablocks(&self) -> BlockSet {
        let mut blocks = BlockSet::new();
        blocks.put(BlockRange::new(self.start, self.size as usize));
        blocks.put(BlockRange::new(self.block, 1));
        blocks
    }

    fn entry_datablock(&self) -> u64 {
        self.block
    }

    fn get_name(&self) -> String {
        String::from_utf8(self.name.to_vec()).unwrap()
    }

    fn get_next(&self) -> i64 {
        self.next
    }
}

/// Entry that represents a directory in the vault structure
/// Structure in vault archive:
/// Type - Type of the entry (u8)
/// Next - next entry in directory order (i64)
/// Nonce - Nonce for the entry encryption ([u8; 12])
/// Name - Name of the directory ([u8; 128])
/// child - First Child Block (i64)
/// auth_tag - Authentication tag for the encryption ([u8; 16])
///
/// The directory holds the entries aas its children in an array
/// it is indexed by a hashmap
#[derive(Debug, PartialEq, Eq)]
pub struct DirectoryEntry {
    /// Name of the directory
    pub name: [u8; VAULTENTRYNAME_LENGTH],
    /// Block the entry resides in
    block: u64,
    /// Block of the next entry
    next: i64,
    /// Block of the first child
    first_child: i64,
    children: Vec<VaultEntry>,
    map: HashMap<String, usize>,
}

impl Entry for DirectoryEntry {
    fn display(&self) -> String {
        format!(
            "{}: {} Items",
            String::from_utf8(self.name.to_vec()).unwrap(),
            self.children.len()
        )
    }

    fn serialize(&self, key: &[u8]) -> Result<[u8; DATABLOCK_LENGTH], SerializationError> {
        let mut bytes = BytesMut::zeroed(DIRENTRY_ENC_LENGTH);
        bytes.put_slice(&self.name);
        bytes.put_i64(self.first_child);

        let enc_entry =
            encrypt_region::<DIRENTRY_ENC_LENGTH>(bytes.freeze().as_array().unwrap(), key)
                .map_err(|e| SerializationError::EncryptError(e))?;

        let mut data = BytesMut::zeroed(DATABLOCK_LENGTH);
        data.put_u8(DIRENTRY_TYPE);
        data.put_i64(self.next);
        data.put_slice(&enc_entry.nonce);
        data.put_slice(&enc_entry.data);

        Ok(*data.freeze().as_array().unwrap())
    }

    fn build_entry(
        data: DataBlockEntry,
        key: &[u8],
        entry_block: u64,
    ) -> Result<Self, BuildEntryError>
    where
        Self: Sized,
    {
        let entry = decrypt_region::<PWDENTRY_ENC_LENGTH>(
            &data.data[..DIRENTRY_ENC_LENGTH].try_into().unwrap(),
            &data.nonce,
            key,
        )
        .map_err(|e| BuildEntryError::CryptographyError(e))?;

        let mut offset = 0;
        let mut namebuf = BytesMut::zeroed(VAULTENTRYNAME_LENGTH);
        let name = String::from_utf8(entry[offset..offset + VAULTENTRY_LENGTH].to_vec())
            .map_err(|e| BuildEntryError::UTF8Error(e, offset as u64))?;
        offset += VAULTENTRYNAME_LENGTH;
        namebuf.put_slice(name.as_bytes());

        let mut child_buf = [0u8; BLOCKID_LENGTH];
        child_buf.copy_from_slice(&entry[offset..offset + BLOCKID_LENGTH]);
        let child = i64::from_be_bytes(child_buf);

        Ok(DirectoryEntry {
            name: *namebuf.freeze().as_array().unwrap(),
            block: entry_block,
            next: data.next,
            first_child: child,
            children: Vec::new(),
            map: HashMap::new(),
        })
    }

    fn rename(
        &mut self,
        new_name: String,
        key: &[u8],
        context: &mut VaultContext,
    ) -> Result<(), RenameError> {
        if new_name.len() > VAULTNAME_LENGTH {
            Err(RenameError::NameError(NameLengthExceededError {
                len: new_name.len(),
            }))
        } else {
            let mut namebuf = BytesMut::zeroed(VAULTENTRYNAME_LENGTH);
            namebuf.put_slice(new_name.as_bytes());
            self.name = *namebuf.freeze().as_array().unwrap();

            let new_entry = self
                .serialize(key)
                .map_err(|e| RenameError::SerializationError(e))?;
            context
                .change_data(self.block, Bytes::copy_from_slice(&new_entry))
                .map_err(|e| VaultChangeError::FileChangeError(e));
            Ok(())
        }
    }

    fn occupied_datablocks(&self) -> BlockSet {
        let mut blocks = BlockSet::new();
        for entry in &self.children {
            entry
                .occupied_blocks()
                .into_iter()
                .for_each(|b| blocks.put(b));
        }
        blocks.put(BlockRange::new(self.block, 1));
        blocks
    }

    fn entry_datablock(&self) -> u64 {
        self.block
    }

    fn get_name(&self) -> String {
        String::from_utf8(self.name.to_vec()).unwrap()
    }

    fn get_next(&self) -> i64 {
        self.next
    }
}

impl DirectoryEntry {
    pub fn new(
        dir_name: String,
        key: &[u8],
        context: &mut VaultContext,
    ) -> Result<Self, VaultChangeError> {
        if dir_name.len() > VAULTENTRYNAME_LENGTH {
            Err(VaultChangeError::ExceededNameLength(
                NameLengthExceededError {
                    len: dir_name.len(),
                },
            ))
        } else {
            let mut namebuf = BytesMut::zeroed(VAULTENTRYNAME_LENGTH);
            namebuf.put_slice(dir_name.as_bytes());

            let mut entry = DirectoryEntry {
                name: *namebuf.as_array().unwrap(),
                block: 0,
                next: -1,
                first_child: -1,
                children: Vec::new(),
                map: HashMap::new(),
            };

            let serialized_entry = entry
                .serialize(key)
                .map_err(|e| VaultChangeError::SerializeError(e))?;
            let block = context
                .new_block(Bytes::copy_from_slice(&serialized_entry))
                .map_err(|e| VaultChangeError::FileChangeError(e))?;
            entry.block = block.start;
            Ok(entry)
        }
    }

    pub fn init_root() -> DirectoryEntry {
        let mut namebuf = BytesMut::zeroed(VAULTENTRYNAME_LENGTH);
        namebuf.put_slice("root".as_bytes());
        DirectoryEntry {
            name: *namebuf.as_array().unwrap(),
            block: 0,
            next: -1, 
            first_child: -1,
            children: Vec::new(),
            map: HashMap::new(),
        }
    }

    pub fn get_sorted_children(&self) -> Vec<&VaultEntry> {
        let mut entries: Vec<&VaultEntry> = Vec::new();
        self.children.iter().for_each(|e| entries.push(&e));
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

    pub fn get_children(&self) -> &Vec<VaultEntry> {
        &self.children
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
        let child_id = match self.map.get(name) {
            None => Err(VaultError::EntryNotFound(total_path.clone())),
            Some(e) => Ok(e),
        }?;
        let entry = &self.children[child_id.clone()];

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
        let child_id = match self.map.get(name) {
            None => Err(VaultError::EntryNotFound(total_path.clone())),
            Some(e) => Ok(e),
        }?;
        let entry = &mut self.children[child_id.clone()];

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
        context: &mut VaultContext,
        key: &[u8],
    ) -> Result<(), VaultChangeError> {
        // pop next name
        let name = match path.pop_front() {
            None => Err(VaultChangeError::VaultError(VaultError::EntryNotFound(
                total_path.clone(),
            ))),
            Some(n) => Ok(n),
        }?;

        if !self.map.contains_key(name) {
            return Err(VaultChangeError::VaultError(VaultError::EntryNotFound(
                total_path.clone(),
            )));
        };

        if path.is_empty() {
            //Check if name conforms with name length restrictions
            if new_name.len() > VAULTNAME_LENGTH {
                return Err(VaultChangeError::VaultError(VaultError::NameError(
                    NameLengthExceededError {
                        len: new_name.len(),
                    },
                )));
            }

            if self.map.contains_key(&new_name) {
                Err(VaultChangeError::VaultError(VaultError::DuplicateEntry(
                    new_name.clone(),
                )))
            } else {
                // Verified already that it exists. can unwrap
                let index = self.map.get(&new_name).unwrap().clone();
                let entry = &mut self.children[index];
                entry.rename(new_name.clone(), key, context);
                self.map.remove(name);
                self.map.insert(new_name, index);
                Ok(())
            }
        } else if let VaultEntry::Directory(dir) =
            &mut self.children[self.map.get(name).unwrap().clone()]
        {
            dir.rename_entry(path, total_path, new_name, context, key)
        } else {
            Err(VaultChangeError::VaultError(VaultError::EntryNotFound(
                total_path.clone(),
            )))
        }
    }

    pub fn delete_entry(
        &mut self,
        mut path: VecDeque<&str>,
        total_path: &VaultPath,
        context: &mut VaultContext,
    ) -> Result<(), VaultChangeError> {
        let name = match path.pop_front() {
            None => Err(VaultChangeError::VaultError(VaultError::EntryNotFound(
                total_path.clone(),
            ))),
            Some(n) => Ok(n),
        }?;

        if !self.map.contains_key(name) {
            return Err(VaultChangeError::VaultError(VaultError::EntryNotFound(
                total_path.clone(),
            )));
        }

        if path.is_empty() {
            let index = self.map.get(name).unwrap().clone();

            if index == 0 {
                self.first_child = self.children[0].entry_block() as i64;
            } else {
                let next: i64 = match self.children.get(index + 1) {
                    None => -1,
                    Some(entry) => entry.entry_block() as i64,
                };
                self.children[index - 1].change_next(next, context);
            }
            let entry = self.children.remove(index);
            self.map.remove(name);
            for range in entry.occupied_blocks().into_iter() {
                context
                    .delete_block(range)
                    .map_err(|e| VaultChangeError::FileChangeError(e))?
            }
            Ok(())
        } else if let VaultEntry::Directory(dir) =
            &mut self.children[self.map.get(name).unwrap().clone()]
        {
            dir.delete_entry(path, total_path, context)
        } else {
            Err(VaultChangeError::VaultError(VaultError::EntryNotFound(
                total_path.clone(),
            )))
        }
    }

    pub fn new_entry(
        &mut self,
        mut path: VecDeque<&str>,
        parent_path: &VaultPath,
        new_entry: VaultEntry,
        context: &mut VaultContext,
        key: &[u8],
    ) -> Result<(), VaultError> {
        if path.len() == 1 {
            let last_index = self.children.len() - 1;
            //This is the parent directory -> Add it as a direct child
            self.children[last_index].change_next(new_entry.entry_block() as i64, context);
            self.map.insert(new_entry.name(), last_index + 1);
            self.children.push(new_entry);
            Ok(())
        } else {
            let name = match path.pop_front() {
                None => Err(VaultError::EntryNotFound(parent_path.clone())),
                Some(n) => Ok(n),
            }?;

            let entry = match self.map.get(name) {
                None => Err(VaultError::EntryNotFound(parent_path.clone())),
                Some(e) => Ok(&mut self.children[e.clone()]),
            }?;

            if let VaultEntry::Directory(dir) = entry {
                dir.new_entry(path, parent_path, new_entry, context, key)
            } else {
                Err(VaultError::EntryNotFound(parent_path.clone()))
            }
        }
    }

    pub fn build_entry_rec(
        start_block: u64,
        context: &mut VaultContext,
        key: &[u8],
    ) -> Result<Self, BuildVaultError> {
        // create the directory entry from the current block
        let datablock = context
            .read_entry(start_block)
            .map_err(|e| BuildVaultError::VaultFileError(e))?;
        if datablock.entry_type != DIRENTRY_TYPE {
            return Err(BuildVaultError::InvalidEntryType);
        }

        let mut dir_entry = DirectoryEntry::build_entry(datablock, key, start_block)
            .map_err(|e| BuildVaultError::BuildEntryError(e))?;

        let mut curr_block = dir_entry.first_child;
        loop {
            if curr_block < 0 {
                break Ok(dir_entry);
            } else {
                let datablock = context
                    .read_entry(curr_block as u64)
                    .map_err(|e| BuildVaultError::VaultFileError(e))?;
                let entry =
                    match datablock.entry_type {
                        PASSWORDENTRY_TYPE => Ok(VaultEntry::Password(
                            PasswordEntry::build_entry(datablock, key, curr_block as u64)
                                .map_err(|e| BuildVaultError::BuildEntryError(e))?,
                        )),
                        SECRETENTRY_TYPE => Ok(VaultEntry::Secret(
                            SecretFileEntry::build_entry(datablock, key, curr_block as u64)
                                .map_err(|e| BuildVaultError::BuildEntryError(e))?,
                        )),
                        DIRENTRY_TYPE => Ok(VaultEntry::Directory(
                            DirectoryEntry::build_entry_rec(curr_block as u64, context, key)?,
                        )),
                        _ => Err(BuildVaultError::InvalidEntryType),
                    }?;
                curr_block = entry.next();
                dir_entry.children.push(entry);
            }
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

    pub fn name(&self) -> String {
        match self {
            VaultEntry::Password(pwd) => pwd.get_name(),
            VaultEntry::Secret(sec) => sec.get_name(),
            VaultEntry::Directory(dir) => dir.get_name(),
        }
    }

    pub fn next(&self) -> i64 {
        match self {
            VaultEntry::Password(pwd) => pwd.get_next(),
            VaultEntry::Secret(sec) => sec.get_next(),
            VaultEntry::Directory(dir) => dir.get_next(),
        }
    }

    pub fn serialize(&self, key: &[u8]) -> Result<[u8; DATABLOCK_LENGTH], SerializationError> {
        match self {
            VaultEntry::Password(pwd) => pwd.serialize(key),
            VaultEntry::Secret(sec) => sec.serialize(key),
            VaultEntry::Directory(dir) => dir.serialize(key),
        }
    }

    pub fn retrieve_secret(
        &self,
        context: &mut VaultContext,
        key: &[u8],
    ) -> Result<EntryResult, RetrieveEntryError> {
        match self {
            VaultEntry::Password(pwd) => Ok(EntryResult::Password(
                pwd.retrieve_secret(context, key)
                    .map_err(|e| RetrieveEntryError::Secret(e))?,
            )),
            VaultEntry::Secret(sec) => Ok(EntryResult::Secret(
                sec.retrieve_secret(context, key)
                    .map_err(|e| RetrieveEntryError::Secret(e))?,
            )),
            VaultEntry::Directory(_) => Err(RetrieveEntryError::InvalidOperation(
                Operation::RetrieveSecret,
                EntryType::Directory,
            )),
        }
    }

    pub fn rename(
        &mut self,
        new_name: String,
        key: &[u8],
        context: &mut VaultContext,
    ) -> Result<(), RenameError> {
        match self {
            Self::Directory(dir) => dir.rename(new_name, key, context),
            Self::Secret(sec) => sec.rename(new_name, key, context),
            Self::Password(pwd) => pwd.rename(new_name, key, context),
        }
    }

    pub fn occupied_blocks(&self) -> BlockSet {
        match self {
            Self::Secret(sec) => sec.occupied_datablocks(),
            Self::Password(pwd) => pwd.occupied_datablocks(),
            Self::Directory(dir) => dir.occupied_datablocks(),
        }
    }

    pub fn entry_block(&self) -> u64 {
        match self {
            Self::Secret(sec) => sec.entry_datablock(),
            Self::Password(pwd) => pwd.entry_datablock(),
            Self::Directory(dir) => dir.entry_datablock(),
        }
    }

    pub fn change_next(
        &mut self,
        next_blk: i64,
        context: &mut VaultContext,
    ) -> Result<(), FileChangeError> {
        match self {
            Self::Secret(sec) => context.change_next(sec.block, next_blk),
            Self::Password(pwd) => context.change_next(pwd.block, next_blk),
            Self::Directory(dir) => context.change_next(dir.block, next_blk),
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
            (VaultEntry::Password(pwd1), VaultEntry::Password(pwd2)) => pwd1.name.cmp(&pwd2.name),
            (VaultEntry::Password(pwd), VaultEntry::Secret(sec)) => pwd.name.cmp(&sec.name),
            (VaultEntry::Password(pwd), VaultEntry::Directory(dir)) => pwd.name.cmp(&dir.name),
            (VaultEntry::Secret(sec), VaultEntry::Password(pwd)) => sec.name.cmp(&pwd.name),
            (VaultEntry::Secret(sec1), VaultEntry::Secret(sec2)) => sec1.name.cmp(&sec2.name),
            (VaultEntry::Secret(sec), VaultEntry::Directory(dir)) => sec.name.cmp(&dir.name),
            (VaultEntry::Directory(dir), VaultEntry::Password(pwd)) => dir.name.cmp(&pwd.name),
            (VaultEntry::Directory(dir), VaultEntry::Secret(sec)) => dir.name.cmp(&sec.name),
            (VaultEntry::Directory(dir1), VaultEntry::Directory(dir2)) => dir1.name.cmp(&dir2.name),
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
