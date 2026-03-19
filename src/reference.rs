use std::fmt;

use crate::error::{IceVaultError, Result};

/// A parsed `iv://VaultName/Category/Key` reference.
#[derive(Debug, Clone)]
pub struct IvRef {
    pub vault: String,
    pub category: String,
    pub key: String,
}

impl IvRef {
    /// Parse `iv://VaultName/Category/Key`
    pub fn parse_uri(uri: &str) -> Result<Self> {
        let path = uri
            .strip_prefix("iv://")
            .ok_or_else(|| IceVaultError::InvalidReference(uri.to_string()))?;
        Self::parse_path(path)
    }

    /// Parse `VaultName/Category/Key` (no scheme prefix).
    /// Used by `icevault add` and `icevault delete`.
    pub fn parse_path(path: &str) -> Result<Self> {
        let parts: Vec<&str> = path.splitn(3, '/').collect();
        if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
            return Err(IceVaultError::InvalidReference(path.to_string()));
        }
        Ok(IvRef {
            vault: parts[0].to_string(),
            category: parts[1].to_string(),
            key: parts[2].to_string(),
        })
    }
}

impl fmt::Display for IvRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "iv://{}/{}/{}", self.vault, self.category, self.key)
    }
}
