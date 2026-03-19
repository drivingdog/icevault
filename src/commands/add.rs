use std::fs;
use std::path::Path;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{IceVaultError, Result};
use crate::reference::IvRef;
use crate::vault::crypto::{decrypt_vault, encrypt_vault};
use crate::vault::model::{SecretValue, VaultPayload};

pub fn run(path_str: &str, vault_path: &Path) -> Result<()> {
    if !vault_path.exists() {
        return Err(IceVaultError::VaultNotFound);
    }

    let iv_ref = IvRef::parse_path(path_str)?;

    // Prompt for secret value with hidden input — never touches shell history or process args
    let v1 = rpassword::prompt_password("Secret value:   ")?;
    let v2 = rpassword::prompt_password("Confirm value:  ")?;

    let mismatch = v1.as_bytes().ct_eq(v2.as_bytes()).unwrap_u8() == 0;
    if mismatch {
        let mut b1 = v1.into_bytes();
        let mut b2 = v2.into_bytes();
        b1.zeroize();
        b2.zeroize();
        return Err(IceVaultError::PasswordMismatch);
    }

    let mut v2_bytes = v2.into_bytes();
    v2_bytes.zeroize();
    let secret = Zeroizing::new(v1);

    let password = Zeroizing::new(rpassword::prompt_password("Master password: ")?.into_bytes());

    let blob = fs::read(vault_path)?;
    let json_bytes = decrypt_vault(&blob, &password)?;
    let mut payload: VaultPayload = serde_json::from_slice(&json_bytes)?;

    payload.insert(&iv_ref, SecretValue((*secret).clone()));

    let new_json = Zeroizing::new(serde_json::to_vec(&payload)?);
    let new_blob = encrypt_vault(&new_json, &password)?;

    let tmp = vault_path.with_extension("ice.tmp");
    fs::write(&tmp, &new_blob)?;
    fs::rename(&tmp, vault_path)?;

    println!("Stored: {path_str}");
    Ok(())
}
