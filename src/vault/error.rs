use thiserror::Error;

use crate::crypt::CryptographyError;
#[derive(Error, Debug)]
#[error("String is not a VaultPath: {path}")]
pub struct InvalidVaultPathError {
    pub path: String
}
#[derive(Error, Debug)]
pub enum VaultFileError {
    #[error("FileIO error in Vaultfile interaction")]
    File(#[from] std::io::Error),
    #[error("Block at position {0} does not exist")]
    InvalidBlockPosition(u64),
    #[error("Encountered Unexpected EOF during read operation")]
    UnexpectedEOF,
    #[error("Vaultfile is busy")]
    VaultBusy,
}

#[derive(Error, Debug)]
pub enum InvalidHeaderData {
    #[error("The version {0} of the schlosser vault format is not supported")]
    UnsupportedVersion(u8),
    #[error("This vault file is not a vault file or the signature is corrupted")]
    InvalidSignature,
}

#[derive(Error, Debug)]
pub enum RetrieveVaultKeyError {
    #[error("Could not read password from stdin")]
    ReadPwd(#[from] std::io::Error),
    #[error("Could not decrypt vault key")]
    Decrypt(#[from] CryptographyError)
}

#[derive(Error, Debug)]
pub enum HeaderError {
    #[error("Header has incorrect data")]
    InvalidHeaderData(#[from] InvalidHeaderData),
    #[error("Cryptography Error while encrypting header-key information")]
    InitHeader(#[from] CryptographyError),
    #[error("Could not retrieve vault key")]
    RetrieveVaultKey(#[from] RetrieveVaultKeyError)
}

