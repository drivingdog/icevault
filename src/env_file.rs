use std::path::Path;

use zeroize::Zeroizing;

use crate::error::{IceVaultError, Result};
use crate::reference::IvRef;
use crate::vault::model::SecretValue;

pub struct EnvEntry {
    pub key: String,
    pub value: EnvValue,
}

pub enum EnvValue {
    /// Plain value — wrapped in SecretValue so it is zeroized on drop.
    Plain(SecretValue),
    IvRef(IvRef),
}

/// Parse a `.env` file into a list of entries.
/// - Blank lines and lines starting with `#` are skipped.
/// - Values wrapped in `"..."` or `'...'` are unquoted.
/// - Values starting with `iv://` become `EnvValue::IvRef`.
/// - File content is wrapped in Zeroizing so plaintext secrets are wiped on drop.
pub fn parse_env_file(path: &Path) -> Result<Vec<EnvEntry>> {
    let content = Zeroizing::new(std::fs::read_to_string(path)?);
    let mut entries = Vec::new();

    for (line_no, line) in content.lines().enumerate() {
        let line = line.trim();

        // Skip blank lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let eq_pos = line.find('=').ok_or_else(|| {
            IceVaultError::MalformedEnvLine(format!("line {}: {}", line_no + 1, line))
        })?;

        let key = line[..eq_pos].trim().to_string();
        let raw_value = line[eq_pos + 1..].trim();
        let value_str = unquote(raw_value);

        let value = if value_str.starts_with("iv://") {
            EnvValue::IvRef(IvRef::parse_uri(value_str)?)
        } else {
            EnvValue::Plain(SecretValue(value_str.to_string()))
        };

        entries.push(EnvEntry { key, value });
    }

    Ok(entries)
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
