use std::{
    fs::{File, OpenOptions, TryLockError},
    io::{BufReader, Read, Seek, SeekFrom, Write, stdin},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use zeroize::Zeroize;

use crate::{
    crypt::{
        AES_NONCE_LENGTH, IV_LENGTH, KEY_LENGTH, decrypt_region, decrypt_region_dyn,
        generate_user_key,
    },
    vault::{
        entry::{DirectoryEntry, Entry},
        error::{
            FileChangeError, InitVaultContextError, InvalidFileReasons, InvalidVaultPathError,
            ReadHeaderError, RetrieveKeyError, SeekFileError,
            VaultFileError, VaultLockError,
        },
        manager::{
            AES_GCM_AUTH_TAG, BLOCKID_LENGTH, DATABLOCK_LENGTH,
            ENTRYTYPE_LENGTH, NEXT_OFFSET, VAULTNAME_LENGTH,
        },
    },
};

const ENTRY_ENC_LENGTH: usize =
    DATABLOCK_LENGTH - ENTRYTYPE_LENGTH - BLOCKID_LENGTH - AES_NONCE_LENGTH;
// Header Constants
const VAULT_SIGNATURE: u64 = 0x0000e111e0afbaca;
const VAULT_SIGNATURE_LENGTH: usize = 8;
const VAULT_VERSION: u8 = 1;
const VAULT_VERSION_LENGTH: usize = 1;

const VAULTKEY_ENC_LENGTH: usize = KEY_LENGTH + AES_GCM_AUTH_TAG;
pub const VAULTHEADER_LENGTH: usize = VAULT_SIGNATURE_LENGTH
    + VAULT_VERSION_LENGTH
    + VAULTNAME_LENGTH
    + IV_LENGTH
    + AES_NONCE_LENGTH
    + VAULTKEY_ENC_LENGTH;

/// Header Information of the archive file
#[derive(Debug)]
pub struct HeaderInfo {
    /// Version specified in the header
    version: u8,
    /// Name of the vault archive
    name: [u8; VAULTNAME_LENGTH],
    /// User key initialization vector
    userkey_iv: [u8; IV_LENGTH],
    /// Key Region nonce
    vaultkey_nonce: [u8; AES_NONCE_LENGTH],
    /// Encrypted VaultKey (includes authentication tag)
    enc_vaultkey: [u8; VAULTKEY_ENC_LENGTH],
}

impl HeaderInfo {
    /// Serialize this header for storage in the vault archive file
    fn serialize(&self) -> [u8; VAULTHEADER_LENGTH] {
        let mut header_data = BytesMut::zeroed(VAULTHEADER_LENGTH);
        header_data.put_u64(VAULT_SIGNATURE);
        header_data.put_u8(self.version);
        header_data.put_slice(&self.name);
        header_data.put_slice(&self.userkey_iv);
        header_data.put_slice(&self.enc_vaultkey);
        header_data.as_array().unwrap().to_owned()
    }

    /// Get the key encrypted in the header using the supplied password. Uses pbkdf2_hmac to
    /// generate a key which is then used to decrypt the vault master key
    pub fn retrieve_key(&self) -> Result<[u8; KEY_LENGTH], RetrieveKeyError> {
        let mut pwd: String = String::new();
        stdin()
            .read_line(&mut pwd)
            .map_err(|e| RetrieveKeyError::StdinError(e))?;

        let user_key = generate_user_key(pwd, &self.userkey_iv);
        let vault_key =
            decrypt_region::<KEY_LENGTH>(&self.enc_vaultkey, &self.vaultkey_nonce, &user_key);
        vault_key.map_err(|e| RetrieveKeyError::DecryptError(e))
    }

    /// Read the vault archive file header.
    /// This expects the Bufreader to be at the start of the file
    fn build_header(header_data: [u8; VAULTHEADER_LENGTH]) -> Result<Self, ReadHeaderError> {
        let mut offset = 0;
        // Check if this file is meant to be a vault archive file
        let mut signature_buf = [0u8; VAULT_SIGNATURE_LENGTH];
        signature_buf.copy_from_slice(&header_data[offset..offset + VAULT_SIGNATURE_LENGTH]);
        let signature = u64::from_be_bytes(signature_buf);
        offset += VAULT_SIGNATURE_LENGTH;

        if signature != VAULT_SIGNATURE {
            return Err(ReadHeaderError::InvalidFileError(
                InvalidFileReasons::WrongSignature,
            ));
        }

        //Add a version field for future changes to the vault archive structure
        let mut version_buf = [0u8; VAULT_VERSION_LENGTH];
        version_buf.copy_from_slice(&header_data[offset..offset + VAULT_VERSION_LENGTH]);
        let version = u8::from_be_bytes(version_buf);
        offset += VAULT_VERSION_LENGTH;

        if version != VAULT_VERSION {
            return Err(ReadHeaderError::InvalidFileError(
                InvalidFileReasons::UnsupportedVersion,
            ));
        }

        // Perform UTF8 Check to be sure no attacker is trying smth funny
        let mut vaultname_buf = BytesMut::zeroed(VAULTNAME_LENGTH);
        let vaultname = String::from_utf8(header_data[offset..offset+VAULTNAME_LENGTH].to_vec())
            .map_err(|e| ReadHeaderError::UTF8Error(e))?;
        vaultname_buf.put_slice(vaultname.as_bytes());
        offset += VAULTNAME_LENGTH;

        let mut userkey_iv = [0u8; IV_LENGTH];
        userkey_iv.copy_from_slice(&header_data[offset..offset + IV_LENGTH]);
        offset += IV_LENGTH;

        //Get the keyregion nonce for decrypting the keyregion
        let mut key_nonce = [0u8; AES_NONCE_LENGTH];
        key_nonce.copy_from_slice(&header_data[offset..offset + AES_NONCE_LENGTH]);
        offset += AES_NONCE_LENGTH;

        let mut encrypted_key = [0u8; VAULTKEY_ENC_LENGTH];
        encrypted_key.copy_from_slice(&header_data[offset..offset + VAULTKEY_ENC_LENGTH]);

        Ok(HeaderInfo {
            version,
            name: *vaultname_buf.as_array().unwrap(),
            userkey_iv,
            vaultkey_nonce: key_nonce,
            enc_vaultkey: encrypted_key,
        })
    }

    pub fn get_name(&self) -> String {
       String::from_utf8(self.name.to_vec()).unwrap()
    }
}

/// A struct which handles vault changes. Interacts directly with the vault file
#[derive(Debug)]
pub struct VaultContext {
    vault_file: File,
    empty_blocks: BlockSet,
}

impl VaultContext {
    /// Create a new Vaultcontext from a vaultfile
    /// This function establishes the lock on the vaultfile and also returns the root Directory
    /// because this function needs to establish a collection of empty blocks for vault changes
    /// Empty blocks can only be calculated using an a root directory
    /// Returns a VaultLockError if the file does not exist or the vault lock could not be acquired
    pub fn new(
        vault_file: String,
    ) -> Result<(Self, DirectoryEntry, HeaderInfo), InitVaultContextError> {
        // acquire a lock on the vault file. No other instance should be able to access the vault
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .append(false)
            .open(&vault_file)
            .map_err(|e| InitVaultContextError::VaultLockError(VaultLockError::FileError(e)))?;
        match file.try_lock() {
            Ok(()) => {
                let mut header = [0u8; VAULTHEADER_LENGTH];
                let read_bytes = file.read(&mut header).map_err(|e| {
                    InitVaultContextError::ReadHeaderError(ReadHeaderError::FileError(e))
                })?;
                if read_bytes < VAULTHEADER_LENGTH {
                    return Err(InitVaultContextError::ReadHeaderError(
                        ReadHeaderError::UnexpectedEOF,
                    ));
                }
                let mut context = VaultContext {
                    vault_file: file,
                    empty_blocks: BlockSet::new(),
                };
                let header = HeaderInfo::build_header(header)
                        .map_err(|e| InitVaultContextError::ReadHeaderError(e))?;
                let mut key = header.retrieve_key().map_err(|e| InitVaultContextError::RetrieveKeyError(e))?; 
                let root = DirectoryEntry::build_entry_rec(0, &mut context, &key)
                    .map_err(|e| InitVaultContextError::BuildVaultError(e))?;
                context.empty_blocks = root.occupied_datablocks().get_empty_space();
                key.zeroize(); 
                Ok((context, root, header))
            }
            Err(TryLockError::WouldBlock) => Err(InitVaultContextError::VaultLockError(
                VaultLockError::VaultBusy,
            )),
            Err(TryLockError::Error(e)) => Err(InitVaultContextError::VaultLockError(
                VaultLockError::FileError(e),
            )),
        }
    }

    /// Changes the next value of an entry block.
    /// Returns an error if the block cannot be found or the was a general file error
    /// Assumes that the block is an entry block
    pub fn change_next(&mut self, block: u64, new_value: i64) -> Result<(), FileChangeError> {
        self.jump_to_block(block)
            .map_err(|e| FileChangeError::SeekFileError(e))?;
        self.vault_file
            .seek(SeekFrom::Current(NEXT_OFFSET as i64))
            .map_err(|e| FileChangeError::FileError(e));
        self.vault_file.write(&new_value.to_be_bytes());
        Ok(())
    }

    /// Changes a datablock (or multiple datablocks depending on length of data)
    /// Panics if data length is not a multiple of DATABLOCK_LENGTH
    /// This method assumes you are only changing the data and keeping the blockrange the same.
    /// If shrinking/growing is needed use [`change_dyn_data`]
    pub fn change_data(&mut self, block: u64, data: Bytes) -> Result<(), FileChangeError> {
        self.jump_to_block(block)
            .map_err(|e| FileChangeError::SeekFileError(e))?;
        if data.len() % DATABLOCK_LENGTH != 0 {
            panic!("Provided data length is not a multiple of DATABLOCK_LENGTH")
        }
        self.vault_file.write(&data);
        Ok(())
    }

    /// Create a new block with size determined by the amount of bytes in data (has to be a multiple
    /// of DATABLOCK_LENGTH)
    pub fn new_block(&mut self, data: Bytes) -> Result<BlockRange, FileChangeError> {
        if data.len() % DATABLOCK_LENGTH != 0 {
            panic!("Provided data length is not a multiple of DATABLOCK_LENGTH")
        }

        let block_len = data.len() / DATABLOCK_LENGTH;
        let new_block = self.empty_blocks.occupy(block_len);

        let offset = VAULTHEADER_LENGTH as u64 + new_block.start * DATABLOCK_LENGTH as u64;
        let file_end = self
            .vault_file
            .seek(SeekFrom::End(0))
            .map_err(|e| FileChangeError::FileError(e))?;

        if offset >= file_end {
            self.vault_file.write(&data);
        } else {
            self.vault_file
                .seek(SeekFrom::Start(offset))
                .map_err(|e| FileChangeError::FileError(e))?;
            self.vault_file
                .write(&data)
                .map_err(|e| FileChangeError::FileError(e))?;
        }
        Ok(new_block)
    }

    /// Deletes a block, by zeroize-ing its contents and adding it to the internal empty block
    /// Blockset
    pub fn delete_block(&mut self, block: BlockRange) -> Result<(), FileChangeError> {
        self.jump_to_block(block.start)
            .map_err(|e| FileChangeError::SeekFileError(e))?;
        let new_data = BytesMut::zeroed(block.len() * DATABLOCK_LENGTH);
        self.vault_file.write(&new_data.freeze());
        self.empty_blocks.put(block);
        Ok(())
    }

    /// Changes the data of a dynamic block (Multiblock structure)
    /// Returns a BlockRange if it the datablock grew/shrinked due to size constraints
    /// Returns None if the datablock is not moved
    pub fn change_dyn_block(
        &mut self,
        old_block: BlockRange,
        data: Bytes,
    ) -> Result<Option<BlockRange>, FileChangeError> {
        if data.len() % DATABLOCK_LENGTH != 0 {
            panic!("Provided data length is not a multiple of DATABLOCK_LENGTH")
        }

        let block_len = data.len() / DATABLOCK_LENGTH;
        if block_len == old_block.len() {
            self.change_data(old_block.start, data);
            Ok(None)
        } else if block_len > old_block.len() {
            //mark old as empty
            self.delete_block(old_block)?;
            self.new_block(data).map(|e| Some(e))
        } else {
            let diff = old_block.len() - block_len;
            self.delete_block(BlockRange::new(old_block.start + block_len as u64, diff));
            self.change_data(old_block.start, data);
            Ok(Some(BlockRange::new(old_block.start, block_len)))
        }
    }

    /// Read a raw datablock from the vault file
    /// returns an error on io failures or unexpected EOF or Invalid datablock ids
    pub fn read_datablock(&mut self, block: u64) -> Result<[u8; DATABLOCK_LENGTH], VaultFileError> {
        self.jump_to_block(block)
            .map_err(|e| VaultFileError::SeekFileError(e))?;
        let mut buf = [0u8; DATABLOCK_LENGTH];
        let bytes_read = self
            .vault_file
            .read(&mut buf)
            .map_err(|e| VaultFileError::FileError(e))?;
        if bytes_read < DATABLOCK_LENGTH {
            Err(VaultFileError::UnexpectedEOF)
        } else {
            Ok(buf)
        }
    }

    /// Read a multi-datablock structure from the vault file
    /// returns an error on io failures, unexpected EOF or invalid datablock ids
    pub fn read_dyn_datablock(&mut self, block: BlockRange) -> Result<Bytes, VaultFileError> {
        self.jump_to_block(block.start)
            .map_err(|e| VaultFileError::SeekFileError(e))?;
        let mut bytes = BytesMut::zeroed(DATABLOCK_LENGTH * block.len());
        let bytes_read = self
            .vault_file
            .read(&mut bytes)
            .map_err(|e| VaultFileError::FileError(e))?;
        if bytes_read < DATABLOCK_LENGTH * block.len() {
            Err(VaultFileError::UnexpectedEOF)
        } else {
            Ok(bytes.freeze())
        }
    }

    /// Reads a datablock containing an entry and decomposes it into its common structure
    /// returns an error on io failures, unexpected EOF or invalid datablock ids
    pub fn read_entry(&mut self, block: u64) -> Result<DataBlockEntry, VaultFileError> {
        self.jump_to_block(block)
            .map_err(|e| VaultFileError::SeekFileError(e))?;
        let mut buf = [0u8; DATABLOCK_LENGTH];
        let bytes_read = self
            .vault_file
            .read(&mut buf)
            .map_err(|e| VaultFileError::FileError(e))?;
        if bytes_read < DATABLOCK_LENGTH {
            Err(VaultFileError::UnexpectedEOF)
        } else {
            let mut offset = 0;

            let mut entrytype_buf = [0u8; ENTRYTYPE_LENGTH];
            entrytype_buf.copy_from_slice(&buf[offset..offset + ENTRYTYPE_LENGTH]);
            let entrytype = u8::from_be_bytes(entrytype_buf);
            offset += ENTRYTYPE_LENGTH;

            let mut next_buf = [0u8; BLOCKID_LENGTH];
            next_buf.copy_from_slice(&buf[offset..offset + BLOCKID_LENGTH]);
            let next = i64::from_be_bytes(next_buf);
            offset += BLOCKID_LENGTH;

            let mut nonce = [0u8; AES_NONCE_LENGTH];
            nonce.copy_from_slice(&buf[offset..offset + AES_NONCE_LENGTH]);
            offset += AES_NONCE_LENGTH;

            let mut data_buf = [0u8; ENTRY_ENC_LENGTH];
            data_buf.copy_from_slice(&buf[offset..offset + ENTRY_ENC_LENGTH]);

            Ok(DataBlockEntry {
                entry_type: entrytype,
                next,
                nonce,
                data: data_buf,
            })
        }
    }

    /// Internal function that seeks to a certain block offset
    fn jump_to_block(&mut self, block: u64) -> Result<(), SeekFileError> {
        let block_offset = VAULTHEADER_LENGTH as u64 + block * DATABLOCK_LENGTH as u64;
        let file_len = self
            .vault_file
            .seek(SeekFrom::End(0))
            .map_err(|e| SeekFileError::FileError(e))? as u64;

        if file_len < block_offset {
            Err(SeekFileError::BlockNotFound(block))
        } else {
            Ok(())
        }
    }

    fn retrieve_key(&self) -> Result<[u8; KEY_LENGTH], RetrieveKeyError> {
        self.header.retrieve_key()
    }
}

/// A structure summarizing the most essential fields of a Datablock entry (password, secretfile
/// entry, directory entry)
pub struct DataBlockEntry {
    pub entry_type: u8,
    pub next: i64,
    pub nonce: [u8; AES_NONCE_LENGTH],
    pub data: [u8; ENTRY_ENC_LENGTH],
}

/// A very primitive structure used to represent Paths inside of the vault. It only supports global
/// paths and performs minimal checks on robustness
#[derive(Debug, Clone)]
pub struct VaultPath {
    path: String,
}

impl VaultPath {
    pub fn new(path: String) -> Result<Self, InvalidVaultPathError> {
        //Check that is is a valid VaultPath in terms of syntax
        //Syntax =>
        // '/' is the first character
        //  no / shall follow a /
        let mut was_sep = false;
        for (i, character) in path.char_indices() {
            if i == 0 && character != '/' {
                return Err(InvalidVaultPathError { path });
            }

            if character == '/' {
                if was_sep {
                    return Err(InvalidVaultPathError { path });
                } else {
                    was_sep = true;
                }
            }
        }
        Ok(Self { path })
    }

    /// Gets the entry name of this path. (If one exists)
    pub fn name(&self) -> Option<&str> {
        let last = self.path.rfind('/').unwrap();
        self.path.get(last + 1..)
    }

    pub fn into_string(self) -> String {
        self.path
    }

    pub fn parts(&self) -> Vec<&str> {
        self.path.split('/').collect()
    }

    pub fn into_parent(mut self) -> Option<Self> {
        //always exists because we guarantee it with string checking in VaultPath::new()
        let last = self.path.rfind('/').unwrap();
        if last == 0 && self.path.len() == 1 {
            // We are at root
            None
        } else {
            self.path.truncate(last);
            Some(Self { path: self.path })
        }
    }

    pub fn parent(&self) -> Option<Self> {
        let last = self.path.rfind('/').unwrap();
        if last == 0 && self.path.len() == 1 {
            None
        } else {
            let mut new_str = self.path.clone();
            new_str.truncate(last);
            Some(Self { path: new_str })
        }
    }
}

// It is not optimized for speed efficiency as it is primarily used for the EmptyBlock management
// We just need something that can manage itself and do the necessary merging operations
// Empty Blocks shouldn't become very big. Should that be the case one day -> Revisit this
/// A struct for managing a set of BlockRanges
#[derive(Debug)]
pub struct BlockSet {
    blocks: Vec<BlockRange>,
}

impl BlockSet {
    pub fn new() -> Self {
        BlockSet { blocks: Vec::new() }
    }

    /// Creates a new Blockset by gathering all empty blocks between the blocks of self
    pub fn get_empty_space(&self) -> BlockSet {
        let mut curr_block: u64 = 0;
        let mut empty_blocks = BlockSet::new();
        for block in self.blocks.iter() {
            if curr_block == block.start {
                curr_block += block.len() as u64;
            } else {
                let diff = match block.start.checked_sub(curr_block) {
                    None => panic!("BlockSet encountered an internal error"),
                    Some(v) => v,
                };
                empty_blocks.put(BlockRange::new(curr_block, diff as usize));
                curr_block += diff;
            }
        }
        empty_blocks
    }

    /// Put a new BlockRange into the Blockset and merge blocks if they overlap
    pub fn put(&mut self, block: BlockRange) {
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
    pub fn occupy(&mut self, req_block_size: usize) -> BlockRange {
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

impl IntoIterator for BlockSet {
    type Item = BlockRange;
    type IntoIter = std::vec::IntoIter<BlockRange>;
    fn into_iter(self) -> Self::IntoIter {
        self.blocks.into_iter()
    }
}

impl From<Vec<BlockRange>> for BlockSet {
    fn from(value: Vec<BlockRange>) -> Self {
        BlockSet { blocks: value }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BlockRange {
    pub start: u64,
    pub end: u64,
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
    pub fn new(start: u64, len: usize) -> Self {
        BlockRange {
            start,
            end: start - 1 + (len as u64),
        }
    }

    pub fn len(&self) -> usize {
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
