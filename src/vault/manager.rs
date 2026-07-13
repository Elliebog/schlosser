use memsecurity::EncryptedMem;
use zeroize::Zeroize;

use crate::crypt::{KEY_LENGTH};
use crate::vault::entry::{
    DirectoryEntry, EncryptedEntry, Entry, EntryResult, PasswordEntry, SecretFileEntry, VaultEntry,
};
use crate::vault::error::{
    DeleteEntryError, EntryType, InitVaultContextError, NewEntryError,
    Operation, RenameEntryError, RetrieveEntryError,
    VaultChangeEntryError,
};
use crate::vault::utils::{BlockSet, VaultContext, VaultPath};

// General Constants
pub const AES_GCM_AUTH_TAG: usize = 16;
pub const VAULTNAME_LENGTH: usize = 128;
//
// Vault Table Constants
pub const ENTRYTYPE_LENGTH: usize = 1;
pub(crate) const PASSWORDENTRY_TYPE: u8 = 0;
pub(crate) const SECRETENTRY_TYPE: u8 = 1;
pub(crate) const DIRENTRY_TYPE: u8 = 2;
pub(crate) const VAULTENTRY_LENGTH: usize = 177;
pub const VAULTENTRYNAME_LENGTH: usize = 128;
const VAULTENTRYTYPE_LENGTH: usize = 1;
pub const BLOCKID_LENGTH: usize = 8;
pub const SECRET_SIZE_LENGTH: usize = 8;
// Vault data constants
pub const DATABLOCK_RAW_LENGTH: usize = 256;
pub const DATABLOCK_LENGTH: usize = DATABLOCK_RAW_LENGTH + AES_GCM_AUTH_TAG;
pub const NEXT_OFFSET: usize = ENTRYTYPE_LENGTH;

/// Maint Entry point that manages vault information about a schlosser vault
#[derive(Debug)]
pub struct VaultManager {
    /// Name of the vault
    name: String,
    vaultkey: EncryptedMem,
    /// The root vault entry
    root: DirectoryEntry,
    /// internal context for tracking changes to the vault
    context: VaultContext,
}

impl VaultManager {
    pub fn from_file(file_path: String) -> Result<VaultManager, InitVaultContextError> {
        let (context, root, header, mut key) = VaultContext::new(file_path)?;
        let mut enc_mem = EncryptedMem::new();
        enc_mem
            .encrypt(&key)
            .map_err(|e| InitVaultContextError::EncryptedMemError(e))?;
        key.zeroize();
        Ok(VaultManager {
            name: header.get_name(),
            vaultkey: enc_mem,
            root,
            context,
        })
    }

    pub fn get_vault_info(&self) -> Result<String, std::fmt::Error> {
        let mut out: String = format!("{} Archive", self.name);
        self.root.get_directory_overview(0, &mut out)?;

        Ok(out)
    }

    fn retrieve_secret_entry(
        &mut self,
        entry_path: &String,
    ) -> Result<EntryResult, RetrieveEntryError> {
        let path = VaultPath::new(entry_path.clone())
            .map_err(|e| RetrieveEntryError::InvalidVaultPath(e))?;
        let target_entry = self
            .root
            .get_entry(path.parts().into(), &path)
            .map_err(|e| RetrieveEntryError::GetEntryError(e))?;
        // The keys dont need to be zeroized after this operation as it is done automatically due to
        // it being ZeroizeBytes
        let temp_key = self
            .vaultkey
            .decrypt()
            .map_err(|e| RetrieveEntryError::RetrieveKeyError(e))?;
        let key = temp_key.expose_borrowed().as_array::<KEY_LENGTH>().unwrap();

        let res = target_entry.retrieve_secret(&mut self.context, key);
        res
    }

    /// Returns a list of empty data blocks in the vault archive
    /// If there are no empty data blocks an empty vector is returned
    fn get_empty_data_blocks(&self) -> BlockSet {
        self.root.occupied_datablocks()
    }

    pub fn rename(&mut self, entry_path: String, new_name: String) -> Result<(), RenameEntryError> {
        let path = VaultPath::new(entry_path.clone())
            .map_err(|e| RenameEntryError::InvalidVaultPath(e))?;
        let temp_key = self
            .vaultkey
            .decrypt()
            .map_err(|e| RenameEntryError::RetrieveKeyError(e))?;
        let key = temp_key.expose_borrowed().as_array::<KEY_LENGTH>().unwrap();

        self.root
            .rename_entry(path.parts().into(), &path, new_name, &mut self.context, key)
            .map_err(|e| RenameEntryError::VaultError(e));
        Ok(())
    }

    pub fn change_password(
        &mut self,
        entry_path: String,
        password: String,
    ) -> Result<(), VaultChangeEntryError> {
        let path = VaultPath::new(entry_path.clone())
            .map_err(|e| VaultChangeEntryError::InvalidVaultPath(e))?;
        let entry = self.root.get_entry_mut(path.parts().into(), &path)?;

        match entry {
            VaultEntry::Password(pwd) => {
                let temp_key = self
                    .vaultkey
                    .decrypt()
                    .map_err(|e| VaultChangeEntryError::RetrieveKeyError(e))?;
                let key = temp_key.expose_borrowed().as_array::<KEY_LENGTH>().unwrap();
                let res = pwd
                    .change_secret(&mut self.context, key, password)
                    .map_err(|e| VaultChangeEntryError::VaultChangeError(e));
                res
            }
            VaultEntry::Directory(_) => Err(VaultChangeEntryError::InvalidOperation(
                Operation::ChangePassword,
                EntryType::Directory,
            )),
            VaultEntry::Secret(_) => Err(VaultChangeEntryError::InvalidOperation(
                Operation::ChangePassword,
                EntryType::Secret,
            )),
        }
    }

    pub fn change_secret(
        &mut self,
        entry_path: String,
        secret_file_path: String,
    ) -> Result<(), VaultChangeEntryError> {
        let path = VaultPath::new(entry_path.clone())
            .map_err(|e| VaultChangeEntryError::InvalidVaultPath(e))?;

        let entry = self.root.get_entry_mut(path.parts().into(), &path)?;

        match entry {
            VaultEntry::Password(_) => Err(VaultChangeEntryError::InvalidOperation(
                Operation::ChangeSecret,
                EntryType::Password,
            )),
            VaultEntry::Directory(_) => Err(VaultChangeEntryError::InvalidOperation(
                Operation::ChangeSecret,
                EntryType::Directory,
            )),
            VaultEntry::Secret(sec) => {
                let temp_key = self
                    .vaultkey
                    .decrypt()
                    .map_err(|e| VaultChangeEntryError::RetrieveKeyError(e))?;
                let key = temp_key.expose_borrowed().as_array::<KEY_LENGTH>().unwrap();
                let res = sec
                    .change_secret(&mut self.context, key, secret_file_path)
                    .map_err(|e| VaultChangeEntryError::VaultChangeError(e));
                res
            }
        }
    }

    pub fn delete_entry(&mut self, entry_path: String) -> Result<(), DeleteEntryError> {
        let path = VaultPath::new(entry_path.clone())
            .map_err(|e| DeleteEntryError::InvalidVaultPath(e))?;
        self.root
            .delete_entry(path.parts().into(), &path, &mut self.context)
            .map_err(|e| DeleteEntryError::VaultError(e))
    }

    pub fn new_directory(
        &mut self,
        dir_path: String,
        dir_name: String,
    ) -> Result<(), NewEntryError> {
        let temp_key = self
            .vaultkey
            .decrypt()
            .map_err(|e| NewEntryError::RetrieveKeyError(e))?;
        let key = temp_key.expose_borrowed().as_array::<KEY_LENGTH>().unwrap();
        let entry = VaultEntry::Directory(
            DirectoryEntry::new(dir_name, key, &mut self.context)
                .map_err(|e| NewEntryError::VaultChangeError(e))?,
        );
        let path = VaultPath::new(dir_path).map_err(|e| NewEntryError::InvalidVaultPath(e))?;
        if let Some(parent_path) = path.parent() {
            self.root
                .new_entry(
                    path.parts().into(),
                    &parent_path,
                    entry,
                    &mut self.context,
                    key,
                )
                .map_err(|e| NewEntryError::VaultError(e));
        }
        Ok(())
    }

    pub fn new_secret(
        &mut self,
        parent_path: String,
        secret_name: String,
        file_path: String,
    ) -> Result<(), NewEntryError> {
        let path = VaultPath::new(parent_path).map_err(|e| NewEntryError::InvalidVaultPath(e))?;
        let temp_key = self
            .vaultkey
            .decrypt()
            .map_err(|e| NewEntryError::RetrieveKeyError(e))?;
        let key = temp_key.expose_borrowed().as_array::<KEY_LENGTH>().unwrap();
        let secret = SecretFileEntry::new(secret_name, file_path, &mut self.context, key)
            .map_err(|e| NewEntryError::VaultChangeError(e))?;
        let res = self
            .root
            .new_entry(
                path.parts().into(),
                &path,
                VaultEntry::Secret(secret),
                &mut self.context,
                key,
            )
            .map_err(|e| NewEntryError::VaultError(e));
        res
    }

    pub fn new_password(
        &mut self,
        parent_path: String,
        password_name: String,
        password: String,
    ) -> Result<(), NewEntryError> {
        let path = VaultPath::new(parent_path).map_err(|e| NewEntryError::InvalidVaultPath(e))?;
        let temp_key = self
            .vaultkey
            .decrypt()
            .map_err(|e| NewEntryError::RetrieveKeyError(e))?;
        let key = temp_key.expose_borrowed().as_array::<KEY_LENGTH>().unwrap();

        let password = PasswordEntry::new(password_name, password, &mut self.context, key)
            .map_err(|e| NewEntryError::VaultChangeError(e))?;

        let res = self
            .root
            .new_entry(path.parts().into(), &path, VaultEntry::Password(password), &mut self.context, key)
            .map_err(|e| NewEntryError::VaultError(e));
        res
    }
}
