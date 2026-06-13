use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
};

use crate::{
    crypt::{AES_NONCE_LENGTH, decrypt_region, decrypt_region_dyn},
    vault::{
        error::{InvalidVaultPathError, ReadDataBlockError, ReadFieldError},
        manager::{DATABLOCK_LENGTH, DATABLOCK_RAW_LENGTH},
    },
};

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
        self.path.get(last+1..)
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

/// Reads a data block from the data section of the vault archive
/// the is expected to be instantiated on the vault file
/// `data_blocK-start` is the offset in bytes from file start to target data block start
/// The key is the AES-GCM key used to decrypt the file
/// The nonce is used for AES-GCM encryption
pub fn read_data_block(
    reader: &mut BufReader<File>,
    data_block_start: u64,
    key: &[u8],
    nonce: &[u8; AES_NONCE_LENGTH],
) -> Result<[u8; DATABLOCK_RAW_LENGTH], ReadDataBlockError> {
    let offset = reader
        .seek(SeekFrom::Start(data_block_start))
        .map_err(|e| ReadDataBlockError::FileError(e, 0))?;
    let enc_data_res = read_field::<DATABLOCK_LENGTH>(reader).map_err(|e| match e {
        ReadFieldError::UnexpectedEOFError => ReadDataBlockError::UnexpectedEOF(offset),
        ReadFieldError::FileError(e) => ReadDataBlockError::FileError(e, offset),
    })?;
    let data = decrypt_region::<DATABLOCK_RAW_LENGTH>(&enc_data_res, &nonce, key)
        .map_err(|e| ReadDataBlockError::CryptoError(e))?;
    Ok(data)
}

/// Reads a data block of dynamic length from the block section of the vault archive.
/// data_block_start is the offset in bytes from file start
/// The key is the AES-GCM key used to decrypt the file
/// The nonce is used for AES-GCM encryption
pub fn read_dyn_data_block(
    reader: &mut BufReader<File>,
    data_block_start: u64,
    key: &[u8],
    nonce: &[u8; AES_NONCE_LENGTH],
    len: usize,
) -> Result<Vec<u8>, ReadDataBlockError> {
    let offset = reader
        .seek(SeekFrom::Start(data_block_start))
        .map_err(|e| ReadDataBlockError::FileError(e, 0))?;
    let enc_data = read_dyn_field(reader, len).map_err(|e| match e {
        ReadFieldError::UnexpectedEOFError => ReadDataBlockError::UnexpectedEOF(offset),
        ReadFieldError::FileError(e) => ReadDataBlockError::FileError(e, offset),
    })?;
    let data =
        decrypt_region_dyn(enc_data, nonce, key).map_err(|e| ReadDataBlockError::CryptoError(e))?;
    Ok(data)
}

/// Read a field of specific size from a buffered reader and return the contents in a fixed size
/// array
pub fn read_field<const length: usize>(
    reader: &mut BufReader<File>,
) -> Result<[u8; length], ReadFieldError> {
    let mut buffer: [u8; length] = [0; length];
    let read_bytes = reader
        .read(&mut buffer)
        .map_err(|e| ReadFieldError::FileError(e))?;
    if read_bytes < length {
        return Err(ReadFieldError::UnexpectedEOFError);
    }
    Ok(buffer)
}

/// Reads a field of size only known at compile time and returns the result as a vector of bytes
pub fn read_dyn_field(reader: &mut BufReader<File>, len: usize) -> Result<Vec<u8>, ReadFieldError> {
    let mut buffer: Vec<u8> = vec![0; len];
    let bytes_read = reader
        .read(&mut buffer)
        .map_err(|e| ReadFieldError::FileError(e))?;
    if bytes_read < len {
        return Err(ReadFieldError::UnexpectedEOFError);
    }

    Ok(buffer)
}
