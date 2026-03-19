use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{IceVaultError, Result};
use crate::reference::IvRef;

/// The plaintext payload stored inside the encrypted vault.
/// Layout: vaults[vault_name][category][key] = SecretValue
#[derive(Serialize, Deserialize, Default)]
pub struct VaultPayload {
    pub vaults: HashMap<String, HashMap<String, HashMap<String, SecretValue>>>,
}

impl VaultPayload {
    pub fn lookup(&self, r: &IvRef) -> Option<&SecretValue> {
        self.vaults
            .get(&r.vault)?
            .get(&r.category)?
            .get(&r.key)
    }

    pub fn insert(&mut self, r: &IvRef, value: SecretValue) {
        self.vaults
            .entry(r.vault.clone())
            .or_default()
            .entry(r.category.clone())
            .or_default()
            .insert(r.key.clone(), value);
    }

    /// Insert a secret using a raw "Vault/Category/Key" path string.
    /// Used by migrate where paths are constructed dynamically.
    /// Returns an error if path does not have exactly 3 parts.
    pub fn insert_by_path(&mut self, path: &str, value: SecretValue) -> Result<()> {
        let parts: Vec<&str> = path.splitn(3, '/').collect();
        if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
            return Err(IceVaultError::InvalidReference(path.to_string()));
        }
        self.vaults
            .entry(parts[0].to_string())
            .or_default()
            .entry(parts[1].to_string())
            .or_default()
            .insert(parts[2].to_string(), value);
        Ok(())
    }

    pub fn delete(&mut self, r: &IvRef) -> bool {
        self.vaults
            .get_mut(&r.vault)
            .and_then(|c| c.get_mut(&r.category))
            .map(|keys| keys.remove(&r.key).is_some())
            .unwrap_or(false)
    }

    /// List all paths as "Vault/Category/Key" strings.
    /// Optionally filter by vault name.
    pub fn list_paths(&self, vault_filter: Option<&str>) -> Vec<String> {
        let mut paths: Vec<String> = self
            .vaults
            .iter()
            .filter(|(v, _)| vault_filter.map_or(true, |f| v.as_str() == f))
            .flat_map(|(v, cats)| {
                cats.iter().flat_map(move |(cat, keys)| {
                    keys.keys().map(move |k| format!("{v}/{cat}/{k}"))
                })
            })
            .collect();
        paths.sort();
        paths
    }
}

/// Manually zeroize the VaultPayload before dropping.
/// HashMap doesn't implement Zeroize so we walk the tree manually.
/// The intermediate .clear() calls are omitted — the HashMaps drop naturally
/// after all SecretValue strings have been zeroized.
impl Drop for VaultPayload {
    fn drop(&mut self) {
        for cats in self.vaults.values_mut() {
            for keys in cats.values_mut() {
                for secret in keys.values_mut() {
                    secret.0.zeroize();
                }
            }
        }
    }
}

/// A secret value — newtype over String.
/// Debug prints [REDACTED] to prevent accidental logging.
/// Zeroize wipes the inner String on drop.
#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretValue(pub String);

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
