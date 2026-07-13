use std::{string::FromUtf8Error};

use memsecurity::MemSecurityErr;

use crate::{crypt::CryptographyError, vault::utils::VaultPath};


pub enum RetrieveSecretError {
    UTF8Error(FromUtf8Error),
    VaultFileError(VaultFileError),
    DecryptError(CryptographyError)
}
pub enum RetrieveEntryError {
    InvalidOperation(Operation, EntryType),
    SecretError(RetrieveSecretError),
    InvalidVaultPath(InvalidVaultPathError),
    GetEntryError(VaultError),
    RetrieveKeyError(MemSecurityErr)
}

pub enum Operation {
    RetrieveSecret,
    ChangePassword,
    ChangeSecret, }

pub enum EntryType {
    Directory,
    Password,
    Secret,
}

pub enum RenameEntryError {
    RetrieveKeyError(MemSecurityErr),
    InvalidVaultPath(InvalidVaultPathError),
    VaultError(VaultChangeError),
}

pub enum RenameError {
    SerializationError(SerializationError),
    NameError(NameLengthExceededError),
}

pub enum DeleteEntryError {
    InvalidVaultPath(InvalidVaultPathError),
    VaultError(VaultChangeError),
}

pub enum NewEntryError {
    VaultError(VaultError),
    NameLengthError(NameLengthExceededError),
    InvalidVaultPath(InvalidVaultPathError),
    VaultChangeError(VaultChangeError),
    RetrieveKeyError(MemSecurityErr),
}

#[derive(Debug)]
pub struct InvalidVaultPathError {
    pub path: String,
}

#[derive(Debug)]
pub struct NameLengthExceededError {
    pub len: usize,
}

pub enum VaultChangeEntryError {
    VaultChangeError(VaultChangeError),
    InvalidVaultPath(InvalidVaultPathError),
    VaultError(VaultError),
    InvalidOperation(Operation, EntryType),
    RetrieveKeyError(MemSecurityErr),
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
    FileError(std::io::Error),
    InputTooLarge,
    CryptographyError(CryptographyError),
    ExceededNameLength(NameLengthExceededError),
    SerializeError(SerializationError),
    VaultError(VaultError),
    FileChangeError(FileChangeError),
}

impl From<CryptographyError> for VaultChangeError {
    fn from(value: CryptographyError) -> Self {
        VaultChangeError::CryptographyError(value)
    }
}

pub enum SerializationError {
    InvalidLength,
    EncryptError(CryptographyError),
}

pub enum VaultError {
    NameError(NameLengthExceededError),
    EntryNotFound(VaultPath),
    DuplicateEntry(String),
}

pub enum RetrieveKeyError {
    StdinError(std::io::Error),
    CryptError(CryptographyError),
}

pub enum SaveVaultError {
    FileError(std::io::Error),
}

pub enum FileChangeError {
    SeekFileError(SeekFileError),
    FileError(std::io::Error),
}

pub enum VaultLockError {
    FileError(std::io::Error),
    VaultBusy,
}

pub enum VaultFileError {
    CryptographyError(CryptographyError),
    FileError(std::io::Error),
    SeekFileError(SeekFileError),
    UnexpectedEOF,
}

pub enum BuildVaultError {
    VaultFileError(VaultFileError),
    BuildEntryError(BuildEntryError),
    InvalidEntryType,
}

pub enum SeekFileError {
    BlockNotFound(u64),
    FileError(std::io::Error),
}

pub enum BuildEntryError {
    UTF8Error(FromUtf8Error, u64),
    CryptographyError(CryptographyError),
}

pub enum InitVaultContextError {
    BuildVaultError(BuildVaultError),
    VaultLockError(VaultLockError),
    ReadHeaderError(ReadHeaderError),
    RetrieveKeyError(RetrieveKeyError),
    EncryptedMemError(MemSecurityErr),
}

pub enum ReadHeaderError {
    FileError(std::io::Error),
    InvalidFileError(InvalidFileReasons),
    UTF8Error(FromUtf8Error),
    UnexpectedEOF,
}

pub enum InvalidFileReasons {
    WrongSignature,
    UnsupportedVersion,
}

pub enum CreateVaultContextError {
    NewVaultFileError(std::io::Error),
    KeyError(RetrieveKeyError),
    SerializationError(SerializationError),
    InitVaultContextError(InitVaultContextError),
    InitVaultFileError(std::io::Error),
    EncryptedMemError(MemSecurityErr)
}
