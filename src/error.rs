use core::fmt;
use std::string::FromUtf8Error;
pub enum CryptographyError {
    InauthenticTag,
    InvalidLength { expected: usize, actual: usize },
    InternalError(aes_gcm::Error),
}

impl fmt::Display for CryptographyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InauthenticTag => write!(f, "Authentication tag corrupted"),
            Self::InvalidLength { expected, actual } => write!(
                f,
                "Mismatch when converting data: expected {} but got {}",
                expected, actual
            ),
        }
    }
}

pub enum ReadVaultFileError {
    ReadFileError(std::io::Error),
    ReadEntryError(ReadFieldError, Option<u64>),
    InvalidFile(InvalidFileReasons),
    ReadStdinError(std::io::Error),
    InAuthenticTagError(),
    InvalidLengthError(),
    InternalError(String),
}

impl From<std::io::Error> for ReadVaultFileError {
    fn from(value: std::io::Error) -> Self {
        Self::ReadFileError(value)
    }
}

pub enum InvalidFileReasons {
    InvalidSignature,
    UnsupportedVersion,
    NoRootEntry,
    InvalidVaultStructure,
    InvalidEntryType,
}

pub enum ReadFieldError {
    ReadFileError(std::io::Error),
    ReadUtf8Error(FromUtf8Error),
    UnexpectedEOFError(),
}

pub enum VaultError {
    WriteError,
    WriteStdoutError,
    EntryNotFound(String),
    ReadVaultError(ReadVaultFileError),
    InvalidOperation(OperationType, VaultEntryType),
    InvalidLengthError(),
    DuplicateEntryError(String),
    CryptographyError(CryptographyError)
}

impl From<CryptographyError> for VaultError {
    fn from(value: CryptographyError) -> Self {
        VaultError::CryptographyError(value)
    }
}

impl From<ReadVaultFileError> for VaultError {
    fn from(value: ReadVaultFileError) -> Self {
        VaultError::ReadVaultError(value)
    }
}

pub enum OperationType {
    Rename,
    ChangePassword,
    ChangeSecret,
    NewEntry,
    RetrieveSecret,
}

pub enum VaultEntryType {
    Password, 
    Secret,
    Directory
}

pub enum InvalidBlockRegionError {
    Overlap,
}
