use std::fs;
use std::path::Path;

use zeroize::Zeroizing;

use crate::error::{IceVaultError, Result};
use crate::vault::crypto::decrypt_vault;
use crate::vault::model::VaultPayload;

pub fn run(vault_filter: Option<&str>, vault_path: &Path) -> Result<()> {
    if !vault_path.exists() {
        return Err(IceVaultError::VaultNotFound);
    }

    let password = Zeroizing::new(rpassword::prompt_password("Master password: ")?.into_bytes());

    let blob = fs::read(vault_path)?;
    let json_bytes = decrypt_vault(&blob, &password)?;
    let payload: VaultPayload = serde_json::from_slice(&json_bytes)?;

    let paths = payload.list_paths(vault_filter);

    if paths.is_empty() {
        println!("(no secrets found)");
    } else {
        for p in &paths {
            println!("{p}");
        }
    }

    Ok(())
}
