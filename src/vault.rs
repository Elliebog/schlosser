use bytes::{BufMut, Bytes, BytesMut};

use crate::crypt::{
    AES_NONCE_LENGTH, EncryptedDataArr, IV_LENGTH, decrypt_region, decrypt_region_dyn,
    encrypt_dyn_region, encrypt_region, generate_user_key,
};
use crate::error::{
    InvalidFileReasons, OperationType, ReadFieldError, ReadVaultFileError, VaultEntryType,
    VaultError,
};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fmt::Write;
use std::io::{BufWriter, Seek, SeekFrom};
use std::vec::IntoIter;
use std::{
    collections::{HashMap, VecDeque},
    fs::File,
    io::{BufReader, Read, stdin},
    path::Path,
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
const PASSWORDENTRY_TYPE: u8 = 0;
const SECRETENTRY_TYPE: u8 = 1;
const DIRENTRY_TYPE: u8 = 2;
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
const DATABLOCK_RAW_LENGTH: usize = 256;
const DATABLOCK_LENGTH: usize = DATABLOCK_RAW_LENGTH + AES_GCM_AUTH_TAG;
// Vault string constants
const V_CONNECTOR: &str = "│\t";
const LITERAL: &str = "├─ ";
const END_LITERAL: &str = "└ ";

/// Maint Entry point that manages vault information about a schlosser vault
#[derive(Debug)]
struct VaultManager {
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
    /// A buffer that holds all planned data block changes
    buffered_changes: Vec<DataBlockChange>,
    /// A collection for internal purposes that tracks the empty blocks inside a vault archive.
    /// An Option as it is initialized only when needed in vault modification operations
    empty_blocks: Option<BlockSet>,
}

impl VaultManager {
    pub fn from_file(file_path: &str) -> Result<VaultManager, ReadVaultFileError> {
        let path = Path::new(file_path);
        let file = File::open(path).map_err(|e| ReadVaultFileError::ReadFileError(e))?;
        let mut reader = BufReader::new(file);
        let header_info: HeaderInfo = read_header(&mut reader)?;
        let root_entry: DirectoryEntry = read_vault_table(&mut reader, &header_info)?;
        Ok(VaultManager {
            version: header_info.version,
            name: header_info.name,
            vault_key: header_info.vault_key,
            data_start: header_info.vault_table_size * VAULTENTRY_LENGTH as u64
                + HEADER_LENGTH as u64,
            root_entry,
            vault_path: file_path.to_owned(),
            buffered_changes: Vec::new(),
            empty_blocks: None,
        })
    }

    pub fn get_vault_info(&self) -> Result<String, VaultError> {
        let mut out: String = format!("{} Archive", self.name);

        // Use the DirectoryEntry Iterator for easy traversal
        // Iterate through the directory and gather information
        // Entries are normally not sorted
        let mut sorted_dir_stack: VecDeque<IntoIter<&VaultEntry>> = VecDeque::new();
        self.root_entry.get_sorted_children();
        // A consuming Iterator is used which holds the values after sorting
        sorted_dir_stack.push_front(self.root_entry.get_sorted_children().into_iter());

        loop {
            let cur_dir = sorted_dir_stack.front_mut();
            if cur_dir.is_none() {
                //break if there is no more directories -> finished
                break;
            }

            let cur_dir = cur_dir.unwrap();
            let entry = cur_dir.next();
            // get is_empty earlier due to our usage of sorted_dir_stack alter (borrow-checker issue)
            let is_empty = cur_dir.len() == 0;
            if entry.is_none() {
                // Directory is finished
                sorted_dir_stack.pop_front();
            } else {
                let entry = entry.unwrap();
                if let VaultEntry::Directory(dir) = entry {
                    sorted_dir_stack.push_front(dir.get_sorted_children().into_iter());
                }
                // build a prefix string to give a pretty view
                // similar-ish to `pstree`
                let prefix_str = build_prefix_str(sorted_dir_stack.len() as u64 - 1, is_empty);
                write!(&mut out, "{} {}", prefix_str, entry.display())
                    .map_err(|_| VaultError::WriteError)?;
            }
        }
        Ok(out)
    }

    pub fn retrieve_entry(&self, entry_path: String) -> Result<EntryResult, VaultError> {
        let file = File::open(Path::new(&self.vault_path))
            .map_err(|e| VaultError::VaultError(ReadVaultFileError::ReadFileError(e)))?;
        let mut reader = BufReader::new(file);

        let target_entry = self.get_entry(&entry_path)?;
        target_entry
            .retrieve_secret(&mut reader, self.data_start, &self.vault_key)
            .map_err(|e| VaultError::VaultError(e))
    }

    //TODO: Implement checksum checking for advanced security
    //TODO: Implement store features

    /// Writes the vault to the vault archive file
    pub fn save_vault(&self) -> VaultError {
        let file = File::open(Path::new(&self.vault_path))
            .map_err(|e| VaultError::VaultError(ReadVaultFileError::ReadFileError(e)))?;
        let mut writer = BufWriter::new(file);
    }

    /// Returns a list of empty data blocks in the vault archive
    /// If there are no empty data blocks an empty vector is returned
    fn get_empty_data_blocks(&self) -> BlockSet {
        let mut empty_blocks: Vec<BlockRange> = Vec::new();

        let mut dir_stack: Vec<&DirectoryEntry> = Vec::new();
        // In this iteration it is irrelevant in what order we consume the entries -> Use the
        // easiest and lowest space consuming implementation
        // A Binary Heap is used to sort the collection of block ids to not waste time on later
        // contains calls in the empty block finding
        let mut data_block_ids: BinaryHeap<Reverse<u64>> = BinaryHeap::new();
        while let Some(dir) = dir_stack.pop() {
            for entry in dir.get_children() {
                match entry {
                    VaultEntry::Password(pwd) => data_block_ids.push(Reverse(pwd.secret_block_id)),
                    VaultEntry::Secret(sec) => {
                        // Secret entries can take up more than one block
                        for i in 0..sec.size {
                            data_block_ids.push(Reverse(sec.secret_block_id + i))
                        }
                    }
                    VaultEntry::Directory(subdir) => dir_stack.push(subdir),
                };
            }
        }

        // Work with an option to avoid ugly problems with i64 and u64 incompatability
        let mut last_block_id: Option<u64> = None;
        while let Some(block_id) = data_block_ids.pop() {
            let diff = match last_block_id {
                Some(val) => block_id.0 - (val + 1),
                None => block_id.0,
            };
            if diff > 0 {
                match last_block_id {
                    Some(val) => empty_blocks.push(BlockRange::new(val + 1, diff as usize)),
                    None => empty_blocks.push(BlockRange::new(0, diff as usize)),
                }
            }
            last_block_id = Some(block_id.0);
        }
        BlockSet::from(empty_blocks)
    }

    pub fn rename(&mut self, entry_path: String, new_name: String) -> Result<(), VaultError> {
        let path: VecDeque<&str> = entry_path.split('/').collect();
        self.root_entry.rename_entry(path, &entry_path, new_name);
        Ok(())
    }

    pub fn change_password(
        &mut self,
        entry_path: String,
        password: String,
    ) -> Result<(), VaultError> {
        if self.empty_blocks.is_none() {
            self.empty_blocks = Some(self.get_empty_data_blocks())
        };

        //encrypt data and add to changes
        let mut raw_data: BytesMut = BytesMut::zeroed(DATABLOCK_RAW_LENGTH);
        raw_data.put(password.as_bytes());
        let data: EncryptedDataArr<DATABLOCK_LENGTH> = encrypt_region(
            raw_data
                .freeze()
                .as_array::<DATABLOCK_RAW_LENGTH>()
                .unwrap(),
            &self.vault_key,
        )?;
        let path = entry_path.split('/').collect();
        let entry = self.root_entry.get_entry_mut(path, &entry_path)?;
        if let VaultEntry::Password(pwd) = entry {
            pwd.nonce = data.nonce;
            self.buffered_changes.push(DataBlockChange::new(
                pwd.secret_block_id,
                1,
                Bytes::copy_from_slice(&data.data[..]),
            ));
            Ok(())
        } else if let VaultEntry::Directory(_) = entry {
            Err(VaultError::InvalidOperation(
                OperationType::ChangePassword,
                VaultEntryType::Directory,
            ))
        } else {
            Err(VaultError::InvalidOperation(
                OperationType::ChangePassword,
                VaultEntryType::Secret,
            ))
        }
    }

    pub fn change_secret(
        &mut self,
        entry_path: String,
        secret_file_path: String,
    ) -> Result<(), VaultError> {
        if self.empty_blocks.is_none() {
            self.empty_blocks = Some(self.get_empty_data_blocks());
        }
        let entry = self
            .root_entry
            .get_entry_mut(entry_path.split('/').collect(), &entry_path)?;
        let secret: &mut SecretFileEntry = match entry {
            VaultEntry::Secret(sec) => Ok(sec),
            VaultEntry::Password(_) => Err(VaultError::InvalidOperation(
                OperationType::ChangeSecret,
                VaultEntryType::Password,
            )),
            VaultEntry::Directory(_) => Err(VaultError::InvalidOperation(
                OperationType::ChangeSecret,
                VaultEntryType::Directory,
            )),
        }?;

        //read file and encrypt
        let path = Path::new(&secret_file_path);
        let mut file = File::open(path)
            .map_err(|e| VaultError::ReadVaultError(ReadVaultFileError::from(e)))?;
        let mut filedata: Vec<u8> = Vec::new();
        let read_bytes = file
            .read_to_end(&mut filedata)
            .map_err(|e| VaultError::ReadVaultError(ReadVaultFileError::from(e)))?;

        //align data to be round_up((read_bytes+AES_GCM_AUTH_TAG) / DATABLOCK_LENGTH)
        let block_len: usize = (read_bytes + AES_GCM_AUTH_TAG).div_ceil(DATABLOCK_LENGTH);

        //prepare data block and encrypt
        let mut data = BytesMut::zeroed(block_len);
        data.put_slice(&filedata[..]);
        let enc_data = encrypt_dyn_region(data.freeze(), &self.vault_key)?;

        if secret.size as usize > block_len {
            // Reduced the BlockRange -> mark the rest as empty blocks

            self.empty_blocks.as_mut().unwrap().put(BlockRange::new(
                secret.secret_block_id + block_len as u64,
                block_len - secret.size as usize,
            ));
            secret.size = block_len as u64;
            let mut new_data = BytesMut::from(enc_data.data);
            new_data.resize(secret.size as usize, 0);
            self.buffered_changes.push(DataBlockChange::new(
                secret.secret_block_id,
                secret.size as usize,
                new_data.freeze(),
            ));
        } else if secret.size as usize == block_len {
            //Can edit inplace
            self.buffered_changes.push(DataBlockChange::new(
                secret.secret_block_id,
                secret.size as usize,
                enc_data.data,
            ));
        } else {
            //Increased size -> TODO Mark current BlockRange as empty and find new spot
            
        }
        Ok(())
    }
}

// pub fn change_secret(
//     &mut self,
//     entry_path: String,
//     data: Bytes,
// ) -> Result<(), VaultError> {
//     let size: usize = data.len() / DATABLOCK_LENGTH;
//     let entry = self.manager.get_entry(&entry_path)?;
//
//     let cur_block_range = match entry {
//         VaultEntry::Directory(_) => Err( VaultError::InvalidOperation(
//             OperationType::ChangeSecret,
//             VaultEntryType::Directory,
//         )),
//         VaultEntry::Password(_) => Err( VaultError::InvalidOperation(
//             OperationType::ChangeSecret,
//             VaultEntryType::Password,
//         )),
//         VaultEntry::Secret(sec) => Ok(BlockRange::new(sec.secret_block_id, sec.size as usize)),
//     }?;
//
//     let diff: i64 = (cur_block_range.len() as i64) - (size as i64);
//     let change = if diff < 0 {
//         // New Size is bigger than old size -> We have to relocate the entire block range
//         // 1. Mark the current block range the secret occupies as empty blocks
//         // 2. Search through the Blocks and occupy the next available space
//         self.empty_blocks.put(cur_block_range);
//         let new_range = self.empty_blocks.occupy(size);
//         VaultChange::ChangeSecret {
//             entry_path,
//             change: DataBlockChange::new(new_range.start, new_range.len(), data),
//             entry_new_size: new_range.len()
//         }
//     } else if diff == 0 {
//         VaultChange::ChangeSecret {
//             entry_path,
//             change: DataBlockChange::new(cur_block_range.start, size, data),
//             entry_new_size: size,
//         }
//     } else {
//         self.empty_blocks
//             .put(BlockRange::new(cur_block_range.end + 1, diff as usize));
//         // Modify DataBlockChange to also erase the old data
//         let mut block_data = BytesMut::zeroed(cur_block_range.len() * DATABLOCK_LENGTH);
//         block_data.put(data);
//         VaultChange::ChangeSecret {
//             entry_path,
//             change: DataBlockChange {
//                 start: cur_block_range.start,
//                 len: cur_block_range.len(),
//                 data: block_data.freeze(),
//             },
//             entry_new_size: size,
//         }
//     };
//     self.changes.push(change);
//     Ok(())
// }
//
// pub fn new_dir(&mut self, dir_path: String) {
//     self.changes.push(VaultChange::NewDir { entry_path: dir_path });
// }

#[derive(Debug, PartialEq, Eq, Clone)]
struct BlockRange {
    start: u64,
    end: u64,
}

impl PartialOrd for BlockRange {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.start.partial_cmp(&other.start)
    }
}

impl Ord for BlockRange {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.start.cmp(&other.start)
    }
}

impl BlockRange {
    fn new(start: u64, len: usize) -> Self {
        BlockRange {
            start,
            end: start - 1 + (len as u64),
        }
    }

    fn len(&self) -> usize {
        (self.end - self.start) as usize
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    fn merge_block(&self, other: &Self) -> Self {
        BlockRange {
            start: std::cmp::min(self.start, other.start),
            end: std::cmp::max(self.end, other.end),
        }
    }
}

// It is not optimized for speed efficiency as it is primarily used for the EmptyBlock management
// We just need something that can manage itself and do the necessary merging operations
// Empty Blocks shouldn't become very big. Should that be the case one day -> Revisit this
/// A struct for managing a set of BlockRanges
#[derive(Debug)]
struct BlockSet {
    blocks: Vec<BlockRange>,
}

impl BlockSet {
    fn new() -> Self {
        BlockSet { blocks: Vec::new() }
    }

    /// Put a new BlockRange into the Blockset and merge blocks if they overlap
    fn put(&mut self, block: BlockRange) {
        // get 1st overlap and combine. Then combine until one interval does no longer overlap
        let mut i: usize = 0;
        let mut check_overlap = false;
        loop {
            if i >= self.blocks.len() {
                // Block needs to be appended at end
                // This needs to be a clone because of the borrow checker
                self.blocks.push(block.clone());
                break;
            }
            if check_overlap {
                //Check if the next block region overlaps with the newly created one
                if !self.blocks[i].overlaps(&self.blocks[i + 1]) {
                    break;
                }
                // we need to merge again
                let next_block = self.blocks.remove(i + 1);
                self.blocks[i] = self.blocks[i].merge_block(&next_block);
                // avoid increment
                continue;
            }
            if self.blocks[i].overlaps(&block) {
                self.blocks[i] = block.merge_block(&self.blocks[i]);
                check_overlap = true;
                // Continue to avoid i increment
                continue;
            } else if block.start < self.blocks[i].start {
                // No overlaps -> just insert
                self.blocks.insert(i, block);
                break;
            }
            i += 1;
        }
    }
    /// Finds an empty slot where a BlockRange can be inserted. It automatically marks the returned
    /// slot to be filled and removes it from its internal empty blocks
    fn occupy(&mut self, req_block_size: usize) -> BlockRange {
        let mut target_index = None;
        for (i, block) in self.blocks.iter().enumerate() {
            if block.len() >= req_block_size {
                target_index = Some(i);
                break;
            }
        }
        match target_index {
            None => BlockRange::new(self.blocks[self.blocks.len() - 1].end + 1, req_block_size),
            Some(i) => {
                let start = self.blocks[i].start;
                let len = self.blocks[i].len();
                if len > req_block_size {
                    self.blocks[i].start = start + req_block_size as u64;
                    self.blocks[i].end = (len - req_block_size) as u64;
                } else {
                    self.blocks.remove(i);
                }
                BlockRange::new(start, req_block_size)
            }
        }
    }
}

impl From<Vec<BlockRange>> for BlockSet {
    fn from(value: Vec<BlockRange>) -> Self {
        BlockSet { blocks: value }
    }
}

// /// Merges Block Ranges that can be merged. Expects the vector to already be sorted ascending
// /// returns the merged vec
// fn merge_blocks(empty_blocks: &mut Vec<BlockRange>) {
//     let mut curr_index: usize = 0;
//     loop {
//         //Check if next position is at the end of current block region
//         let block = match empty_blocks.get(curr_index) {
//             Some(blk) => blk,
//             None => break,
//         };
//         let next_block = match empty_blocks.get(curr_index + 1) {
//             Some(blk) => blk,
//             None => break,
//         }
//         .clone();
//         if next_block.start == block.start + block.len {
//             // We need to merge
//             let block_mut = match empty_blocks.get_mut(curr_index) {
//                 Some(blk) => blk,
//                 None => break,
//             };
//
//             block_mut.len += next_block.len;
//             empty_blocks.remove(curr_index + 1);
//         } else {
//             curr_index += 1;
//         }
//     }
// }

#[derive(Debug)]
struct DataBlockChange {
    start: u64,
    len: usize,
    data: Bytes,
}

impl DataBlockChange {
    fn new(start: u64, len: usize, data: Bytes) -> Self {
        DataBlockChange { start, len, data }
    }
}

/// An Enum representing the result of an entry secret retrieval
enum EntryResult {
    Password(String),
    Secret(Bytes),
    Directory(String),
}

/// A trait that defines functions for entries that contain secrets to implement.
/// This trait is not used dynamically for references in Vaultentries but rather just gives a
/// baseline of functions for entries to implement
/// In the future this trait and VaultEntry may need to be refactored if a lot of new types need to
/// be added
trait EncryptedEntry<T> {
    fn retrieve_secret(
        &self,
        reader: &mut BufReader<File>,
        data_start: u64,
        key: &[u8],
    ) -> Result<T, ReadVaultFileError>;
}

/// Basic trait that every trait should implement
/// The same caveats as for `EncryptedEntry<T>` trait apply
trait Entry {
    fn display(&self) -> String;
    fn serialize(&self) -> Result<[u8; VAULTENTRY_LENGTH], ReadVaultFileError>;
    fn rename(&mut self, new_name: String);
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

/// Entry that holds a password
#[derive(Debug, PartialEq, Eq)]
struct PasswordEntry {
    /// Name of the password
    password_name: String,
    /// Id of the secret block
    secret_block_id: u64,
    /// Nonce used for decryption of the datablock
    nonce: [u8; AES_NONCE_LENGTH],
}

impl EncryptedEntry<String> for PasswordEntry {
    fn retrieve_secret(
        &self,
        reader: &mut BufReader<File>,
        data_start: u64,
        key: &[u8],
    ) -> Result<String, ReadVaultFileError> {
        let data_block_start = data_start + self.secret_block_id * DATABLOCK_LENGTH as u64;
        let data = read_data_block(reader, data_block_start, key, &self.nonce)?;

        // Passwords are encrypted by first padding the field with 0's
        // To get the original password we discard anything that is not ascii
        String::from_utf8(data.to_vec())
            .map_err(|e| ReadVaultFileError::ReadError(ReadFieldError::ReadUtf8Error(e), 0))
    }
}

impl Entry for PasswordEntry {
    fn display(&self) -> String {
        format!("{} (Password)", self.password_name)
    }

    fn serialize(&self) -> Result<[u8; VAULTENTRY_LENGTH], ReadVaultFileError> {
        let mut entry = BytesMut::zeroed(VAULTENTRY_LENGTH);
        entry.put_u8(PASSWORDENTRY_TYPE);
        entry.put(self.password_name.as_bytes());
        entry.put_u64(self.secret_block_id);
        entry.put(&self.nonce[..]);
        match entry.as_array::<VAULTENTRY_LENGTH>() {
            Some(e) => Ok(e.to_owned()),
            None => Err(ReadVaultFileError::InvalidLengthError()),
        }
    }

    fn rename(&mut self, new_name: String) {
        self.password_name = new_name;
    }
}

/// Entry for an encrypted Secret File (like a recovery key or a keyfile, or any other kind of file
/// that needs to be kept secure)
#[derive(Debug, PartialEq, Eq)]
struct SecretFileEntry {
    /// Name of the secret
    secret_name: String,
    /// Id of the starting secret block
    secret_block_id: u64,
    /// Length of the secret file
    size: u64,
    /// Nonce used for decryption of the datablocks
    nonce: [u8; AES_NONCE_LENGTH],
}

impl EncryptedEntry<Bytes> for SecretFileEntry {
    fn retrieve_secret(
        &self,
        reader: &mut BufReader<File>,
        data_start: u64,
        key: &[u8],
    ) -> Result<Bytes, ReadVaultFileError> {
        let mut bytes: BytesMut = BytesMut::zeroed(self.size as usize * DATABLOCK_RAW_LENGTH);
        for i in 0..self.size {
            let data_start = data_start + (self.secret_block_id + i) * DATABLOCK_LENGTH as u64;
            let data = read_data_block(reader, data_start, key, &self.nonce)?;
            bytes.put(&data[..]);
        }

        Ok(bytes.freeze())
    }
}

impl Entry for SecretFileEntry {
    fn display(&self) -> String {
        format!("{} (File)", self.secret_name)
    }

    fn serialize(&self) -> Result<[u8; VAULTENTRY_LENGTH], ReadVaultFileError> {
        let mut bytes: BytesMut = BytesMut::zeroed(VAULTENTRY_LENGTH);
        bytes.put_u8(SECRETENTRY_TYPE);
        bytes.put(self.secret_name.as_bytes());
        bytes.put_u64(self.secret_block_id);
        bytes.put_u64(self.size);
        bytes.put(&self.nonce[..]);
        match bytes.as_array::<VAULTENTRY_LENGTH>() {
            Some(e) => Ok(e.to_owned()),
            None => Err(ReadVaultFileError::InvalidLengthError()),
        }
    }

    fn rename(&mut self, new_name: String) {
        self.secret_name = new_name;
    }
}

/// Entry that represents a directory in the vault structure
#[derive(Debug)]
struct DirectoryEntry {
    /// Name of the directory
    directory_name: String,
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

    fn serialize(&self) -> Result<[u8; VAULTENTRY_LENGTH], ReadVaultFileError> {
        let mut bytes: BytesMut = BytesMut::zeroed(VAULTENTRY_LENGTH);
        bytes.put_u8(DIRENTRY_TYPE);
        bytes.put(self.directory_name.as_bytes());
        bytes.put_u64(self.children.len() as u64);
        match bytes.as_array::<VAULTENTRY_LENGTH>() {
            Some(e) => Ok(e.to_owned()),
            None => Err(ReadVaultFileError::InvalidLengthError()),
        }
    }

    fn rename(&mut self, new_name: String) {
        self.directory_name = new_name;
    }
}

impl DirectoryEntry {
    fn get_sorted_children(&self) -> Vec<&VaultEntry> {
        let mut entries: Vec<&VaultEntry> = self.children.values().collect();
        entries.sort();
        entries
    }

    fn get_directory_overview(&self, depth: u64, buffer: &mut String) -> Result<(), VaultError> {
        write!(
            buffer,
            "{} {}",
            build_prefix_str(depth, false),
            self.display()
        )
        .map_err(|_| VaultError::WriteStdoutError)?;
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
                )
                .map_err(|_| VaultError::WriteStdoutError)?,
                VaultEntry::Secret(sec) => write!(
                    buffer,
                    "{} {}\n",
                    build_prefix_str(depth, is_last),
                    sec.display()
                )
                .map_err(|_| VaultError::WriteStdoutError)?,
                VaultEntry::Directory(dir) => {
                    dir.get_directory_overview(depth + 1, buffer)?;
                }
            }
        }
        Ok(())
    }

    fn get_children(&self) -> Vec<&VaultEntry> {
        self.children.values().collect()
    }

    fn sorted_iter(&self) -> IntoIter<&VaultEntry> {
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

    fn iter(&self) -> IntoIter<&VaultEntry> {
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

    fn get_entry(
        &self,
        mut path: VecDeque<&str>,
        &total_path: &String,
    ) -> Result<&VaultEntry, VaultError> {
        // pop next name
        let name_opt = path.pop_front();
        let name = match name_opt {
            None => Err(VaultError::EntryNotFound(total_path.clone())),
            Some(n) => Ok(n),
        }?;
        let entry_opt = self.children.get(name);
        let entry = match entry_opt {
            None => Err(VaultError::EntryNotFound(total_path.clone())),
            Some(e) => Ok(e),
        }?;

        if path.is_empty() {
            Ok(entry)
        } else {
            if let VaultEntry::Directory(dir) = entry {
                dir.get_entry(path, &total_path)
            } else {
                Err(VaultError::EntryNotFound(total_path.clone()))
            }
        }
    }

    fn get_entry_mut(
        &mut self,
        mut path: VecDeque<&str>,
        total_path: &String,
    ) -> Result<&mut VaultEntry, VaultError> {
        // pop next name
        let name_opt = path.pop_front();
        let name = match name_opt {
            None => Err(VaultError::EntryNotFound(total_path.clone())),
            Some(n) => Ok(n),
        }?;
        let entry_opt = self.children.get_mut(name);
        let entry = match entry_opt {
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

    /// Renames an entry and updates the entry in
    fn rename_entry(
        &mut self,
        mut path: VecDeque<&str>,
        total_path: &String,
        new_name: String,
    ) -> Result<(), VaultError> {
        // pop next name
        let name_opt = path.pop_front();
        let name = match name_opt {
            None => Err(VaultError::EntryNotFound(total_path.clone())),
            Some(n) => Ok(n),
        }?;

        let entry_opt = self.children.get_mut(name);
        let entry = match entry_opt {
            None => Err(VaultError::EntryNotFound(total_path.clone())),
            Some(e) => Ok(e),
        }?;

        if path.is_empty() {
            let name = entry.name().clone();
            if self.children.contains_key(&new_name) {
                Err(VaultError::DuplicateEntryError(new_name.clone()))
            } else {
                // clone to avoid the mutable borrow living on
                let mut new_entry = self.children.remove(&name).unwrap();
                new_entry.rename(new_name.clone());
                self.children.insert(new_name, new_entry);
                Ok(())
            }
        } else {
            if let VaultEntry::Directory(dir) = entry {
                dir.rename_entry(path, total_path, new_name)
            } else {
                Err(VaultError::EntryNotFound(total_path.clone()))
            }
        }
    }
}

/// A vault entry found in the vault entry table
/// Each entry is 128+8+8 bytes long
#[derive(Debug, PartialEq, Eq)]
enum VaultEntry {
    Password(PasswordEntry),
    Secret(SecretFileEntry),
    Directory(DirectoryEntry),
}

impl VaultEntry {
    fn display(&self) -> String {
        match self {
            Self::Password(pwd) => pwd.display(),
            Self::Secret(sec) => sec.display(),
            Self::Directory(dir) => dir.display(),
        }
    }

    fn serialize(&self) -> Result<[u8; VAULTENTRY_LENGTH], ReadVaultFileError> {
        match self {
            VaultEntry::Password(pwd) => pwd.serialize(),
            VaultEntry::Secret(sec) => sec.serialize(),
            VaultEntry::Directory(dir) => dir.serialize(),
        }
    }

    fn retrieve_secret(
        &self,
        reader: &mut BufReader<File>,
        data_start: u64,
        key: &[u8],
    ) -> Result<EntryResult, VaultError> {
        match self {
            VaultEntry::Password(pwd) => Ok(EntryResult::Password(
                pwd.retrieve_secret(reader, data_start, key)?,
            )),
            VaultEntry::Secret(sec) => Ok(EntryResult::Secret(
                sec.retrieve_secret(reader, data_start, key)?,
            )),
            VaultEntry::Directory(dir) => Err(VaultError::InvalidOperation(
                OperationType::RetrieveSecret,
                VaultEntryType::Directory,
            )),
        }
    }

    fn rename(&mut self, new_name: String) {
        match self {
            Self::Directory(dir) => dir.rename(new_name),
            Self::Secret(sec) => sec.rename(new_name),
            Self::Password(pwd) => pwd.rename(new_name),
        }
    }

    fn name(&self) -> &String {
        match self {
            VaultEntry::Directory(dir) => &dir.directory_name,
            VaultEntry::Secret(sec) => &sec.secret_name,
            VaultEntry::Password(pwd) => &pwd.password_name,
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

    let vaultname_raw = read_field::<VAULTNAME_LENGTH>(reader)
        .map_err(|e| ReadVaultFileError::ReadError(e, offset))?;
    let vaultname = String::from_utf8(vaultname_raw.to_vec())
        .map_err(|e| ReadVaultFileError::ReadError(ReadFieldError::ReadUtf8Error(e), offset))?;
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
        DIRENTRY_TYPE => {
            // Directory Entry
            let mut offset: usize = 1;
            let name = String::from_utf8(entry_data[offset..offset + VAULTENTRY_LENGTH].to_vec())
                .map_err(|e| {
                ReadVaultFileError::ReadEntryError(ReadFieldError::ReadUtf8Error(e), offset as u64)
            })?;
            offset += VAULTENTRYNAME_LENGTH;
            // Because array of Copy types are copied when doing a slice this does not consume the
            // entry_data array
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
        PASSWORDENTRY_TYPE => {
            //Password Entry
            let mut offset: usize = 1;
            let name = String::from_utf8(entry_data[offset..offset + VAULTENTRY_LENGTH].to_vec())
                .map_err(|e| {
                ReadVaultFileError::ReadEntryError(ReadFieldError::ReadUtf8Error(e), 1)
            })?;
            offset += VAULTENTRYNAME_LENGTH;
            // Because array of Copy types are copied when doing a slice this does not consume the
            // entry_data array
            let blk_id = u64::from_ne_bytes(
                entry_data[offset..offset + BLOCKID_LENGTH]
                    .try_into()
                    .map_err(|_| ReadVaultFileError::InvalidLengthError())?,
            );
            offset += BLOCKID_LENGTH;
            let nonce: [u8; AES_NONCE_LENGTH] = entry_data[offset..offset + AES_NONCE_LENGTH]
                .try_into()
                .map_err(|_| ReadVaultFileError::InvalidLengthError())?;
            Ok((
                0,
                VaultEntry::Password(PasswordEntry {
                    password_name: name,
                    secret_block_id: blk_id,
                    nonce,
                }),
            ))
        }
        SECRETENTRY_TYPE => {
            //Secret File Entry
            let mut offset = 1;
            let name = String::from_utf8(entry_data[offset..offset + VAULTENTRY_LENGTH].to_vec())
                .map_err(|e| {
                ReadVaultFileError::ReadEntryError(ReadFieldError::ReadUtf8Error(e), 1)
            })?;
            offset += VAULTENTRYNAME_LENGTH;
            // Because array of Copy types are copied when doing a slice this does not consume the
            // entry_data array
            let blk_id = u64::from_ne_bytes(
                entry_data[offset..offset + BLOCKID_LENGTH]
                    .try_into()
                    .map_err(|_| ReadVaultFileError::InvalidLengthError())?,
            );
            offset += BLOCKID_LENGTH;
            let size = u64::from_ne_bytes(
                entry_data[offset..offset + SECRET_SIZE_LENGTH]
                    .try_into()
                    .map_err(|_| ReadVaultFileError::InvalidLengthError())?,
            );
            offset += SECRET_SIZE_LENGTH;
            let nonce: [u8; AES_NONCE_LENGTH] = entry_data[offset..offset + AES_NONCE_LENGTH]
                .try_into()
                .map_err(|_| ReadVaultFileError::InvalidLengthError())?;
            Ok((
                0,
                VaultEntry::Secret(SecretFileEntry {
                    secret_name: name,
                    secret_block_id: blk_id,
                    size,
                    nonce,
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

/// Reads a data block from the data section of the vault archive
/// the is expected to be instantiated on the vault file
/// `data_blocK-start` is the offset in bytes from file start to target data block start
/// The key is the AES-GCM key used to decrypt the file
/// The nonce is used for AES-GCM encryption
fn read_data_block(
    reader: &mut BufReader<File>,
    data_block_start: u64,
    key: &[u8],
    nonce: &[u8; AES_NONCE_LENGTH],
) -> Result<[u8; DATABLOCK_RAW_LENGTH], ReadVaultFileError> {
    let offset = reader
        .seek(SeekFrom::Start(data_block_start))
        .map_err(|e| ReadVaultFileError::ReadFileError(e))?;
    let enc_data_res = read_field::<DATABLOCK_LENGTH>(reader)
        .map_err(|e| ReadVaultFileError::ReadError(e, offset))?;
    let data = decrypt_region::<DATABLOCK_RAW_LENGTH>(&enc_data_res, &nonce, key)
        .map_err(|_| ReadVaultFileError::InAuthenticTagError())?;
    Ok(data)
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
