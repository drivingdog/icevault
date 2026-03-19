use std::fs;
use std::path::Path;

use zeroize::Zeroizing;

use crate::env_file::{parse_env_file, EnvValue};
use crate::error::{IceVaultError, Result};
use crate::vault::crypto::decrypt_vault;
use crate::vault::model::{SecretValue, VaultPayload};

/// Read master password from ICEVAULT_PASSWORD env var if set,
/// otherwise prompt interactively. Always returns a Zeroizing wrapper.
fn read_password() -> std::io::Result<Zeroizing<Vec<u8>>> {
    if let Ok(pw) = std::env::var("ICEVAULT_PASSWORD") {
        let result = Zeroizing::new(pw.into_bytes());
        // Remove from env immediately so child processes never inherit the master password
        std::env::remove_var("ICEVAULT_PASSWORD");
        return Ok(result);
    }
    Ok(Zeroizing::new(
        rpassword::prompt_password("Master password: ")?.into_bytes(),
    ))
}

pub fn run(env_file: &Path, cmd_args: &[String], vault_path: &Path) -> Result<()> {
    if cmd_args.is_empty() {
        eprintln!("error: no command specified after --");
        std::process::exit(1);
    }

    let entries = parse_env_file(env_file)?;
    let needs_vault = entries.iter().any(|e| matches!(e.value, EnvValue::IvRef(_)));

    let payload: Option<VaultPayload> = if needs_vault {
        if !vault_path.exists() {
            return Err(IceVaultError::VaultNotFound);
        }
        let password = read_password()?;
        let blob = fs::read(vault_path)?;
        let json_bytes = decrypt_vault(&blob, &password)?;
        let p: VaultPayload = serde_json::from_slice(&json_bytes)?;
        Some(p)
    } else {
        None
    };

    // Resolve all references into owned Vec so we can zeroize after spawn (Windows)
    let mut resolved: Vec<(String, SecretValue)> = Vec::new();
    for entry in &entries {
        match &entry.value {
            EnvValue::Plain(sv) => {
                resolved.push((entry.key.clone(), sv.clone()));
            }
            EnvValue::IvRef(iv_ref) => {
                let secret = payload
                    .as_ref()
                    .unwrap()
                    .lookup(iv_ref)
                    .ok_or_else(|| IceVaultError::SecretNotFound(iv_ref.to_string()))?
                    .clone();
                resolved.push((entry.key.clone(), secret));
            }
        }
    }

    let cmd = &cmd_args[0];
    let args = &cmd_args[1..];

    exec_with_env(cmd, args, &mut resolved)
}

#[cfg(unix)]
fn exec_with_env(cmd: &str, args: &[String], env: &mut Vec<(String, SecretValue)>) -> Result<()> {
    use std::os::unix::process::CommandExt;

    let mut command = std::process::Command::new(cmd);
    command.args(args);
    for (k, v) in env.iter() {
        command.env(k, &v.0);
    }

    // exec() replaces the current process image via execve(2).
    // On success it never returns — the OS reclaims all memory including secrets.
    let err = command.exec();
    Err(IceVaultError::ExecFailed(err))
}

#[cfg(not(unix))]
fn exec_with_env(cmd: &str, args: &[String], env: &mut Vec<(String, SecretValue)>) -> Result<()> {
    use zeroize::Zeroize;

    // Try direct execution first — avoids cmd.exe metacharacter reinterpretation.
    // This works for .exe binaries (node, python, cargo, etc.).
    let mut command = std::process::Command::new(cmd);
    command.args(args);
    for (k, v) in env.iter() {
        command.env(k, &v.0);
    }

    let child_result = command.spawn();
    let mut child = match child_result {
        Ok(child) => child,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Binary not found — retry via cmd.exe.
            // Necessary for .cmd batch files (npm, npx, pnpm, etc.) which
            // CreateProcess cannot resolve without the shell.
            let mut fallback = std::process::Command::new("cmd");
            fallback.arg("/c").arg(cmd).args(args);
            for (k, v) in env.iter() {
                fallback.env(k, &v.0);
            }
            fallback.spawn().map_err(IceVaultError::ExecFailed)?
        }
        Err(e) => return Err(IceVaultError::ExecFailed(e)),
    };

    // Zeroize the original secrets in the parent immediately after spawn.
    // The child already has its own address space with the env vars copied in.
    for (_, v) in env.iter_mut() {
        v.0.zeroize();
    }

    let status = child.wait()?;
    std::process::exit(status.code().unwrap_or(1));
}
