use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::{IceVaultError, Result};

pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

fn argon2_params() -> Result<Params> {
    Params::new(128 * 1024, 3, 1, Some(KEY_LEN))
        .map_err(|e| IceVaultError::Crypto(format!("invalid argon2 params: {e}")))
}

fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

/// Derive a 32-byte key from password + salt using Argon2id.
/// Returns Zeroizing wrapper so the key is wiped on drop.
pub fn derive_key(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut key_bytes = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params()?)
        .hash_password_into(password, salt, key_bytes.as_mut())
        .map_err(|e| IceVaultError::Crypto(format!("key derivation failed: {e}")))?;
    Ok(key_bytes)
}

/// Encrypt plaintext bytes. Returns: salt(32) || nonce(12) || ciphertext.
/// A fresh random salt and nonce are generated on every call.
pub fn encrypt_vault(plaintext: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    let salt: [u8; SALT_LEN] = rand_bytes();
    let nonce_bytes: [u8; NONCE_LEN] = rand_bytes();

    let key = derive_key(password, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| IceVaultError::Crypto(format!("encryption failed: {e}")))?;

    let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt vault blob (salt || nonce || ciphertext).
/// Returns Zeroizing<Vec<u8>> — plaintext JSON wiped on drop.
/// Wrong password or tampered file → IceVaultError::WrongPassword.
pub fn decrypt_vault(blob: &[u8], password: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    // Minimum: salt + nonce + 16-byte Poly1305 tag
    if blob.len() < SALT_LEN + NONCE_LEN + 16 {
        return Err(IceVaultError::CorruptVault);
    }

    let (salt_slice, rest) = blob.split_at(SALT_LEN);
    let (nonce_slice, ciphertext) = rest.split_at(NONCE_LEN);

    let salt: [u8; SALT_LEN] = salt_slice
        .try_into()
        .map_err(|_| IceVaultError::CorruptVault)?;
    let key = derive_key(password, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let nonce = Nonce::from_slice(nonce_slice);

    cipher
        .decrypt(nonce, ciphertext)
        .map(Zeroizing::new)
        .map_err(|_| IceVaultError::WrongPassword)
}
