use std::fs;
use std::path::Path;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{IceVaultError, Result};
use crate::vault::crypto::encrypt_vault;
use crate::vault::model::VaultPayload;

pub fn run(vault_path: &Path) -> Result<()> {
    if vault_path.exists() {
        return Err(IceVaultError::VaultAlreadyExists(vault_path.to_owned()));
    }

    let pw1 = rpassword::prompt_password("Master password: ")?;
    let pw2 = rpassword::prompt_password("Confirm password: ")?;

    // Constant-time comparison to prevent timing side-channel attacks
    let mismatch = pw1.as_bytes().ct_eq(pw2.as_bytes()).unwrap_u8() == 0;
    if mismatch {
        let mut b1 = pw1.into_bytes();
        let mut b2 = pw2.into_bytes();
        b1.zeroize();
        b2.zeroize();
        return Err(IceVaultError::PasswordMismatch);
    }

    // pw2 consumed and zeroized immediately; pw1 becomes the active password
    let mut pw2_bytes = pw2.into_bytes();
    pw2_bytes.zeroize();
    let pw = Zeroizing::new(pw1.into_bytes());

    let payload = VaultPayload::default();
    let json = Zeroizing::new(serde_json::to_vec(&payload)?);
    let blob = encrypt_vault(&json, &pw)?;

    if let Some(parent) = vault_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp = vault_path.with_extension("ice.tmp");
    fs::write(&tmp, &blob)?;
    fs::rename(&tmp, vault_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(vault_path, fs::Permissions::from_mode(0o600))?;
    }

    println!("Vault initialized at {}", vault_path.display());
    Ok(())
}
