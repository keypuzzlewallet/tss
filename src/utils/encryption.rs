#![allow(dead_code)]

use std::time::{SystemTime, UNIX_EPOCH};


use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::anyhow;
use base64::engine::general_purpose;
use base64::Engine;
use sha2::{Digest, Sha256};

fn derive_iv_from_nonce(nonce: u64) -> Vec<u8> {
    let mut iv = [0u8; 12];
    iv[4..].copy_from_slice(&nonce.to_be_bytes());
    iv.to_vec()
}

// sha-256 hash of the password
fn get_key_from_password(password: &str) -> Vec<u8> {
    let mut key = [0u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    key.copy_from_slice(&result);
    key.to_vec()
}

pub fn encrypt(plaintext: &str, password: &str) -> anyhow::Result<String> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
    return encrypt_with_nonce(plaintext, password, nonce);
}

pub fn encrypt_with_nonce(plaintext: &str, password: &str, nonce: u64) -> anyhow::Result<String> {
    let vec = get_key_from_password(password);
    let key = aes_gcm::Key::from_slice(&vec);
    let vec1 = derive_iv_from_nonce(nonce);
    let iv = Nonce::from_slice(&vec1);
    let cipher = Aes256Gcm::new(key);
    let encrypted = cipher
        .encrypt(&iv, plaintext.as_bytes())
        .map_err(|e| anyhow!("encryption failure: {}", e))?;
    return Ok(format!(
        "{}:{}",
        nonce,
        general_purpose::STANDARD.encode(encrypted)
    ));
}

pub fn decrypt(ciphertext: &str, password: &str) -> anyhow::Result<String> {
    let mut split = ciphertext.split(":");
    let nonce = split.next().expect("nonce not found").parse::<u64>()?;
    let ciphertext = split.next().expect("cipher not found");
    return decrypt_with_nonce(ciphertext, password, nonce);
}

pub fn decrypt_with_nonce(ciphertext: &str, password: &str, nonce: u64) -> anyhow::Result<String> {
    let vec = get_key_from_password(password);
    let key = aes_gcm::Key::from_slice(&vec);
    let vec1 = derive_iv_from_nonce(nonce);
    let iv = Nonce::from_slice(&vec1);
    let cipher = Aes256Gcm::new(&key);
    let decrypted = cipher
        .decrypt(
            &iv,
            general_purpose::STANDARD
                .decode(ciphertext.as_bytes())?
                .as_slice(),
        )
        .map_err(|e| anyhow!("decryption failure: {}", e))?;
    return Ok(String::from_utf8(decrypted)?);
}

#[cfg(test)]
mod test {
    #[test]
    fn test_encryption() {
        let plaintext = "hello";
        let password = "my-password";
        let ciphertext = super::encrypt_with_nonce(plaintext, password, 9999999).unwrap();
        assert_eq!("9999999:dYcX59XzlgaRJP82ogwUIb5zvxzX", ciphertext);
        let decrypted =
            super::decrypt_with_nonce("dYcX59XzlgaRJP82ogwUIb5zvxzX", password, 9999999).unwrap();
        assert_eq!(plaintext, decrypted);
    }
}
