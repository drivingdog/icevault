use std::fs;
use std::path::Path;

use zeroize::Zeroizing;

use crate::env_file::{parse_env_file, EnvValue};
use crate::error::{IceVaultError, Result};
use crate::vault::crypto::decrypt_vault;
use crate::vault::model::VaultPayload;

pub fn run(env_file: &Path, confirm: bool, vault_path: &Path) -> Result<()> {
    if !confirm {
        eprintln!("WARNING: This command prints secret values to stdout.");
        eprintln!("Use --confirm to proceed. Do NOT run this in CI logs.");
        std::process::exit(1);
    }

    eprintln!("WARNING: Printing secret values to stdout.");

    let entries = parse_env_file(env_file)?;
    let needs_vault = entries.iter().any(|e| matches!(e.value, EnvValue::IvRef(_)));

    let payload: Option<VaultPayload> = if needs_vault {
        if !vault_path.exists() {
            return Err(IceVaultError::VaultNotFound);
        }
        let password =
            Zeroizing::new(rpassword::prompt_password("Master password: ")?.into_bytes());
        let blob = fs::read(vault_path)?;
        let json_bytes = decrypt_vault(&blob, &password)?;
        let p: VaultPayload = serde_json::from_slice(&json_bytes)?;
        Some(p)
    } else {
        None
    };

    for entry in &entries {
        match &entry.value {
            EnvValue::Plain(sv) => {
                println!("{}={}", entry.key, sv.0);
            }
            EnvValue::IvRef(iv_ref) => {
                let secret = payload
                    .as_ref()
                    .unwrap()
                    .lookup(iv_ref)
                    .ok_or_else(|| IceVaultError::SecretNotFound(iv_ref.to_string()))?;
                println!("{}={}", entry.key, secret.0);
            }
        }
    }

    Ok(())
}
