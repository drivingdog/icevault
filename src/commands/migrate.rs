use std::fs;
use std::path::Path;

use zeroize::Zeroizing;

use crate::error::{IceVaultError, Result};
use crate::reference::IvRef;
use crate::vault::crypto::{decrypt_vault, encrypt_vault};
use crate::vault::model::{SecretValue, VaultPayload};

pub fn run(env_file: &Path, prefix: &str, vault_path: &Path) -> Result<()> {
    // Validate prefix format: Vault/Category
    let parts: Vec<&str> = prefix.splitn(2, '/').collect();
    if parts.len() != 2 || parts.iter().any(|p| p.is_empty()) {
        eprintln!("error: --prefix must be in format Vault/Category (e.g. Ecommerce/Development)");
        std::process::exit(1);
    }
    let vault_name = parts[0];
    let category = parts[1];

    // Read the original .env file — wrap in Zeroizing so plaintext secrets are wiped on drop
    let content = Zeroizing::new(fs::read_to_string(env_file)?);

    // Determine output path: same directory, filename + ".ice"
    let out_path = {
        let fname = env_file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(".env");
        env_file
            .parent()
            .unwrap_or(Path::new("."))
            .join(format!("{fname}.ice"))
    };

    if !vault_path.exists() {
        return Err(IceVaultError::VaultNotFound);
    }

    let password = Zeroizing::new(rpassword::prompt_password("Master password: ")?.into_bytes());
    let blob = fs::read(vault_path)?;
    let json_bytes = decrypt_vault(&blob, &password)?;
    let mut payload: VaultPayload = serde_json::from_slice(&json_bytes)?;

    let mut out_lines: Vec<String> = Vec::new();
    let mut migrated_paths: Vec<String> = Vec::new();
    let mut skipped = 0usize;

    for line in content.lines() {
        let trimmed = line.trim();

        // Preserve blank lines and comments as-is
        if trimmed.is_empty() || trimmed.starts_with('#') {
            out_lines.push(line.to_string());
            continue;
        }

        // Find KEY=value split
        let Some(eq_pos) = line.find('=') else {
            out_lines.push(line.to_string());
            continue;
        };

        let key = line[..eq_pos].trim();
        let raw_value = line[eq_pos + 1..].trim();
        let value = unquote(raw_value);

        // Skip empty values and already-migrated references
        if value.is_empty() || value.starts_with("iv://") {
            out_lines.push(line.to_string());
            skipped += 1;
            continue;
        }

        // Vault key: lowercase of the env variable name
        let vault_key = key.to_lowercase();
        let iv_path = format!("{vault_name}/{category}/{vault_key}");

        // Store in vault (wrapped in Zeroizing so it's wiped after insert)
        let secret = Zeroizing::new(value.to_string());
        payload.insert_by_path(&iv_path, SecretValue((*secret).clone()))?;

        // Write iv:// reference line to output
        out_lines.push(format!("{key}=\"iv://{iv_path}\""));
        migrated_paths.push(iv_path);
    }

    if migrated_paths.is_empty() {
        println!("Nothing to migrate — no plain values found in {}", env_file.display());
        return Ok(());
    }

    // Re-encrypt vault with new secrets
    let new_json = Zeroizing::new(serde_json::to_vec(&payload)?);
    let new_blob = encrypt_vault(&new_json, &password)?;

    let tmp = vault_path.with_extension("ice.tmp");
    fs::write(&tmp, &new_blob)?;
    fs::rename(&tmp, vault_path)?;

    // Write .env.ice output file atomically (tmp + rename)
    let out_content = out_lines.join("\n") + "\n";
    let tmp_out = out_path.with_extension("tmp");
    fs::write(&tmp_out, &out_content)?;
    fs::rename(&tmp_out, &out_path)?;

    // --- Verification: re-read vault and confirm every migrated secret is present ---
    let verify_blob = fs::read(vault_path)?;
    let verify_json = decrypt_vault(&verify_blob, &password)?;
    let verify_payload: VaultPayload = serde_json::from_slice(&verify_json)?;

    println!();
    println!("Verifying migrated secrets...");
    let mut all_ok = true;
    for iv_path in &migrated_paths {
        let found = IvRef::parse_path(iv_path)
            .ok()
            .and_then(|r| verify_payload.lookup(&r))
            .is_some();

        if found {
            println!("  OK  {iv_path}");
        } else {
            println!("  FAIL  {iv_path}");
            all_ok = false;
        }
    }

    println!();
    println!("Migrated:  {} secret(s) → {vault_name}/{category}/", migrated_paths.len());
    println!("Created:   {}", out_path.display());
    if skipped > 0 {
        println!("Skipped:   {skipped} (empty or already iv:// references)");
    }

    // --- Post-migration warning ---
    println!();
    if all_ok && !migrated_paths.is_empty() {
        println!("All secrets verified in vault.");
        println!();
        println!("NEXT STEPS:");
        println!("  1. Test your app with the new file:");
        println!("       icevault run --env-file={} -- <your command>", out_path.display());
        println!();
        println!("  2. Once confirmed working, securely delete the original file:");
        println!("       icevault shred --file={}", env_file.display());
        println!();
        println!("WARNING: {} still contains real secret values.", env_file.display());
        println!("         Do NOT commit it. Delete it securely once verified.");
    } else if !migrated_paths.is_empty() {
        eprintln!();
        eprintln!("WARNING: Some secrets failed verification. Do NOT delete the original file.");
        eprintln!("         Check the vault and try again.");
        std::process::exit(1);
    }

    Ok(())
}

fn unquote(s: &str) -> &str {
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"'))
            || (s.starts_with('\'') && s.ends_with('\'')))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}
