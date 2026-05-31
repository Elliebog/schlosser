use core::fmt;
use std::string::FromUtf8Error;
pub enum CryptographyError {
    InauthenticTag,
    InvalidLength{
        expected: usize,
        actual: usize,
    }
}


impl fmt::Display for CryptographyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InauthenticTag => 
                write!(f, "Authentication tag corrupted"),
            Self::InvalidLength { expected, actual } => 
                write!(f, "Mismatch when converting data: expected {} but got {}", expected, actual)
        }
    }
}

pub enum ReadVaultFileError {
    ReadError(ReadFieldError, u64),
    ReadFileError(std::io::Error),
    ReadEntryError(ReadFieldError, u64),
    InvalidFile(InvalidFileReasons),
    ReadStdinError(std::io::Error),
    InAuthenticTagError(),
    InvalidLengthError(),
    InternalError(String),
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

pub enum VaultManagementError {
    WriteError,
    EntryNotFound(String),
    VaultError(ReadVaultFileError)
}
