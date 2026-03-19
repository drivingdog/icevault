use std::fs;
use std::path::Path;

use zeroize::Zeroizing;

use crate::error::{IceVaultError, Result};
use crate::reference::IvRef;
use crate::vault::crypto::{decrypt_vault, encrypt_vault};
use crate::vault::model::VaultPayload;

pub fn run(path_str: &str, vault_path: &Path) -> Result<()> {
    if !vault_path.exists() {
        return Err(IceVaultError::VaultNotFound);
    }

    let iv_ref = IvRef::parse_path(path_str)?;
    let password = Zeroizing::new(rpassword::prompt_password("Master password: ")?.into_bytes());

    let blob = fs::read(vault_path)?;
    let json_bytes = decrypt_vault(&blob, &password)?;
    let mut payload: VaultPayload = serde_json::from_slice(&json_bytes)?;

    if !payload.delete(&iv_ref) {
        return Err(IceVaultError::SecretNotFound(path_str.to_string()));
    }

    let new_json = Zeroizing::new(serde_json::to_vec(&payload)?);
    let new_blob = encrypt_vault(&new_json, &password)?;

    let tmp = vault_path.with_extension("ice.tmp");
    fs::write(&tmp, &new_blob)?;
    fs::rename(&tmp, vault_path)?;

    println!("Deleted: {path_str}");
    Ok(())
}
