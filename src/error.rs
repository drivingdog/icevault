use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum IceVaultError {
    VaultNotFound,
    VaultAlreadyExists(PathBuf),
    /// Wrong password OR corrupted vault — intentionally ambiguous
    WrongPassword,
    CorruptVault,
    SecretNotFound(String),
    InvalidReference(String),
    MalformedEnvLine(String),
    PasswordMismatch,
    ExecFailed(std::io::Error),
    Io(std::io::Error),
    Json(serde_json::Error),
    Crypto(String),
}

impl fmt::Display for IceVaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IceVaultError::VaultNotFound => {
                write!(f, "vault not found — run `icevault init` first")
            }
            IceVaultError::VaultAlreadyExists(p) => {
                write!(f, "vault already exists at {}", p.display())
            }
            IceVaultError::WrongPassword => {
                write!(f, "wrong master password or corrupted vault")
            }
            IceVaultError::CorruptVault => {
                write!(f, "vault file appears corrupted")
            }
            IceVaultError::SecretNotFound(path) => {
                write!(f, "secret not found: {path}")
            }
            IceVaultError::InvalidReference(r) => {
                write!(f, "invalid iv:// reference: {r}")
            }
            IceVaultError::MalformedEnvLine(line) => {
                write!(f, "malformed .env line: {line}")
            }
            IceVaultError::PasswordMismatch => {
                write!(f, "password confirmation did not match")
            }
            IceVaultError::ExecFailed(e) => {
                write!(f, "failed to execute command: {e}")
            }
            IceVaultError::Io(e) => write!(f, "io error: {e}"),
            IceVaultError::Json(e) => write!(f, "serialization error: {e}"),
            IceVaultError::Crypto(msg) => write!(f, "crypto error: {msg}"),
        }
    }
}

impl std::error::Error for IceVaultError {}

impl From<std::io::Error> for IceVaultError {
    fn from(e: std::io::Error) -> Self {
        IceVaultError::Io(e)
    }
}

impl From<serde_json::Error> for IceVaultError {
    fn from(e: serde_json::Error) -> Self {
        IceVaultError::Json(e)
    }
}

pub type Result<T> = std::result::Result<T, IceVaultError>;
