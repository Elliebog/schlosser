use std::string::FromUtf8Error;

use crate::{crypt::CryptographyError, vault::utils::VaultPath};

pub enum ReadVaultFileError {
    FileError(std::io::Error),
}

pub enum RetrieveSecretError {
    InvalidVaultPath(String),
    VaultError(VaultError),
    FileError(std::io::Error),
    UTF8Error(FromUtf8Error),
    DataBlockError(ReadDataBlockError),
    InvalidOperation(Operation, EntryType)
}

impl From<VaultError> for RetrieveSecretError {
    fn from(value: VaultError) -> Self {
        RetrieveSecretError::VaultError(value)
    }
}

impl From<ReadDataBlockError> for RetrieveSecretError {
    fn from(value: ReadDataBlockError) -> Self {
        RetrieveSecretError::DataBlockError(value)
    }
}

pub enum Operation {
    RetrieveSecret,
    ChangePassword,
    ChangeSecret,
}

pub enum EntryType {
    Directory, 
    Password,
    Secret
}

pub enum RenameEntryError {
    InvalidVaultPath(InvalidVaultPathError),
    VaultError(VaultError)
}

pub enum DeleteEntryError {
    InvalidVaultPath(InvalidVaultPathError),
    VaultError(VaultError)
}

pub enum NewEntryError {
    VaultError(VaultError),
    NameError(NameLengthExceededError),
    InvalidVaultPath(InvalidVaultPathError),
    VaultChangeError(VaultChangeError)
}

pub struct InvalidVaultPathError {
     pub path: String
}

pub struct NameLengthExceededError {
    pub len: usize
}

pub enum VaultChangeEntryError {
    VaultChangeError(VaultChangeError),
    InvalidVaultPath(InvalidVaultPathError),
    VaultError(VaultError),
    InvalidOperation(Operation, EntryType)
}

impl From<VaultError> for VaultChangeEntryError {
    fn from(value: VaultError) -> Self {
        VaultChangeEntryError::VaultError(value)
    }
}

impl From<VaultChangeError> for VaultChangeEntryError {
    fn from(value: VaultChangeError) -> Self {
        VaultChangeEntryError::VaultChangeError(value)
    }
}

pub enum ReadDataBlockError {
    FileError(std::io::Error, u64),
    UnexpectedEOF(u64),
    CryptoError(CryptographyError),
}

pub enum ReadStringFieldError {
    FileError(std::io::Error),
    ReadUtf8Error(FromUtf8Error),
    UnexpectedEOFError,
}

pub enum ReadFieldError {
    FileError(std::io::Error),
    UnexpectedEOFError,
}

pub enum VaultChangeError {
    InputTooLarge,
    FileError(std::io::Error),
    CryptographyError(CryptographyError),
}

impl From<CryptographyError> for VaultChangeError {
    fn from(value: CryptographyError) -> Self {
        VaultChangeError::CryptographyError(value)
    }
}

pub enum SerializationError {
    InvalidLength,
}

pub enum VaultError{
    EntryNotFound(VaultPath),
    DuplicateEntry(String), 
    ExceededNameLength(usize),
}


