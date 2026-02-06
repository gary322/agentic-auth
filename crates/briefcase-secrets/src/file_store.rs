use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use async_trait::async_trait;
use base64::Engine as _;
use briefcase_core::{Sensitive, util::sha256_hex};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt as _;
use tokio::io::AsyncWriteExt as _;
use zeroize::Zeroizing;

use crate::types::{SecretStore, SecretStoreError};

#[derive(Debug, Clone)]
pub struct FileSecretStoreOptions {
    pub root_dir: PathBuf,
    pub passphrase: String,
}

#[derive(Debug, Clone)]
pub struct FileSecretStore {
    root_dir: PathBuf,
    key: Zeroizing<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Meta {
    salt_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SecretRecord {
    id: String,
    nonce_b64: String,
    ciphertext_b64: String,
}

impl FileSecretStore {
    pub async fn open(opts: FileSecretStoreOptions) -> Result<Self, SecretStoreError> {
        tokio::fs::create_dir_all(&opts.root_dir)
            .await
            .map_err(|e| SecretStoreError::Backend(format!("create secrets dir error: {e}")))?;

        let meta_path = opts.root_dir.join("meta.json");
        let salt = if meta_path.exists() {
            read_meta(&meta_path).await?
        } else {
            let mut salt = [0u8; 16];
            rand::rng().fill_bytes(&mut salt);
            let meta = Meta {
                salt_b64: base64::engine::general_purpose::STANDARD.encode(salt),
            };
            let bytes = serde_json::to_vec_pretty(&meta)
                .map_err(|e| SecretStoreError::Backend(format!("meta json error: {e}")))?;
            write_atomic(&meta_path, &bytes).await?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    tokio::fs::set_permissions(&meta_path, std::fs::Permissions::from_mode(0o600))
                        .await;
            }
            salt
        };

        let key = derive_key(&opts.passphrase, &salt)?;
        Ok(Self {
            root_dir: opts.root_dir,
            key,
        })
    }

    fn path_for_id(&self, id: &str) -> Result<PathBuf, SecretStoreError> {
        validate_id(id)?;
        let file = sha256_hex(id.as_bytes());
        Ok(self.root_dir.join(file).with_extension("json"))
    }
}

#[async_trait]
impl SecretStore for FileSecretStore {
    async fn put(&self, id: &str, value: Sensitive<Vec<u8>>) -> Result<(), SecretStoreError> {
        let path = self.path_for_id(id)?;
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&self.key);
        let cipher = Aes256Gcm::new(key);
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);

        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: value.expose(),
                    aad: id.as_bytes(),
                },
            )
            .map_err(|_| SecretStoreError::Backend("encrypt failed".to_string()))?;

        let rec = SecretRecord {
            id: id.to_string(),
            nonce_b64: base64::engine::general_purpose::STANDARD.encode(nonce_bytes),
            ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(ciphertext),
        };
        let bytes = serde_json::to_vec(&rec)
            .map_err(|e| SecretStoreError::Backend(format!("secret json error: {e}")))?;
        write_atomic(&path, &bytes).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await;
        }
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<Sensitive<Vec<u8>>>, SecretStoreError> {
        let path = self.path_for_id(id)?;
        if !path.exists() {
            return Ok(None);
        }
        let bytes = tokio::fs::read(&path)
            .await
            .map_err(|e| SecretStoreError::Backend(format!("read secret error: {e}")))?;
        let rec: SecretRecord = serde_json::from_slice(&bytes)
            .map_err(|e| SecretStoreError::Backend(format!("secret json decode error: {e}")))?;
        if rec.id != id {
            return Err(SecretStoreError::Backend(
                "secret record id mismatch".to_string(),
            ));
        }
        let nonce_bytes = base64::engine::general_purpose::STANDARD
            .decode(rec.nonce_b64)
            .map_err(|e| SecretStoreError::Backend(format!("nonce base64 decode error: {e}")))?;
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(rec.ciphertext_b64)
            .map_err(|e| SecretStoreError::Backend(format!("cipher base64 decode error: {e}")))?;

        if nonce_bytes.len() != 12 {
            return Err(SecretStoreError::Backend("bad nonce length".to_string()));
        }
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&self.key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ciphertext,
                    aad: id.as_bytes(),
                },
            )
            .map_err(|_| SecretStoreError::Backend("decrypt failed".to_string()))?;
        Ok(Some(Sensitive(plaintext)))
    }

    async fn delete(&self, id: &str) -> Result<(), SecretStoreError> {
        let path = self.path_for_id(id)?;
        if !path.exists() {
            return Ok(());
        }
        tokio::fs::remove_file(&path)
            .await
            .map_err(|e| SecretStoreError::Backend(format!("remove secret error: {e}")))?;
        Ok(())
    }
}

fn validate_id(id: &str) -> Result<(), SecretStoreError> {
    let ok = !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    if ok {
        Ok(())
    } else {
        Err(SecretStoreError::InvalidId)
    }
}

async fn read_meta(meta_path: &Path) -> Result<[u8; 16], SecretStoreError> {
    let mut f = tokio::fs::File::open(meta_path)
        .await
        .map_err(|e| SecretStoreError::Backend(format!("open meta error: {e}")))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
        .await
        .map_err(|e| SecretStoreError::Backend(format!("read meta error: {e}")))?;
    let meta: Meta = serde_json::from_slice(&buf)
        .map_err(|e| SecretStoreError::Backend(format!("meta json error: {e}")))?;
    let salt_vec = base64::engine::general_purpose::STANDARD
        .decode(meta.salt_b64)
        .map_err(|e| SecretStoreError::Backend(format!("salt base64 decode error: {e}")))?;
    let salt: [u8; 16] = salt_vec
        .try_into()
        .map_err(|_| SecretStoreError::Backend("bad salt length".to_string()))?;
    Ok(salt)
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretStoreError> {
    // Defaults chosen to be reasonable on developer machines. Make configurable if needed.
    let argon2 = Argon2::default();
    let mut key = Zeroizing::new(vec![0u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| SecretStoreError::Backend(format!("kdf error: {e}")))?;
    Ok(key)
}

async fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), SecretStoreError> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = tokio::fs::File::create(&tmp)
            .await
            .map_err(|e| SecretStoreError::Backend(format!("create tmp error: {e}")))?;
        f.write_all(bytes)
            .await
            .map_err(|e| SecretStoreError::Backend(format!("write tmp error: {e}")))?;
        f.flush()
            .await
            .map_err(|e| SecretStoreError::Backend(format!("flush tmp error: {e}")))?;
    }
    tokio::fs::rename(&tmp, path)
        .await
        .map_err(|e| SecretStoreError::Backend(format!("rename tmp error: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip_file_secret_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSecretStore::open(FileSecretStoreOptions {
            root_dir: dir.path().join("secrets"),
            passphrase: "passphrase".to_string(),
        })
        .await
        .unwrap();

        store
            .put("provider.refresh_token", Sensitive(b"abc123".to_vec()))
            .await
            .unwrap();
        let got = store.get("provider.refresh_token").await.unwrap().unwrap();
        assert_eq!(got.expose(), b"abc123");
        store.delete("provider.refresh_token").await.unwrap();
        assert!(store.get("provider.refresh_token").await.unwrap().is_none());
    }
}
