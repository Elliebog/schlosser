#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use crate::vault::error::EntryType;
mod crypt;
mod vault;

enum VaultCommand {
    ShowVaultInfo { filter: String },
    DeleteEntry { entry: String },
    ChangeEntry { entry: String },
    NewEntry { entry_type: EntryType, name: String } 
}

/// Enum that dictates all commands that are not vault-content modification
enum Command {
    InitVault { file_path: String },
    OpenVault { file_path: String },
}

fn main() {
    println!("Hello, world!");
}
