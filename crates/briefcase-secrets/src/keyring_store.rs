use async_trait::async_trait;
use base64::Engine as _;
use briefcase_core::Sensitive;

use crate::types::{SecretStore, SecretStoreError};

#[derive(Debug, Clone)]
pub struct KeyringSecretStoreOptions {
    pub service: String,
}

#[derive(Debug)]
pub struct KeyringSecretStore {
    service: String,
}

impl KeyringSecretStore {
    pub fn new(opts: KeyringSecretStoreOptions) -> Self {
        Self {
            service: opts.service,
        }
    }

    fn entry(&self, id: &str) -> Result<keyring::Entry, SecretStoreError> {
        validate_id(id)?;
        keyring::Entry::new(&self.service, id)
            .map_err(|e| SecretStoreError::Backend(format!("keyring entry error: {e}")))
    }
}

#[async_trait]
impl SecretStore for KeyringSecretStore {
    async fn put(&self, id: &str, value: Sensitive<Vec<u8>>) -> Result<(), SecretStoreError> {
        let entry = self.entry(id)?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(value.expose());
        tokio::task::spawn_blocking(move || entry.set_password(&b64))
            .await
            .map_err(|e| SecretStoreError::Backend(format!("keyring join error: {e}")))?
            .map_err(|e| SecretStoreError::Backend(format!("keyring set error: {e}")))?;
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<Sensitive<Vec<u8>>>, SecretStoreError> {
        let entry = self.entry(id)?;
        let res = tokio::task::spawn_blocking(move || entry.get_password())
            .await
            .map_err(|e| SecretStoreError::Backend(format!("keyring join error: {e}")))?;

        match res {
            Ok(b64) => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .map_err(|e| SecretStoreError::Backend(format!("base64 decode error: {e}")))?;
                Ok(Some(Sensitive(bytes)))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(SecretStoreError::Backend(format!("keyring get error: {e}"))),
        }
    }

    async fn delete(&self, id: &str) -> Result<(), SecretStoreError> {
        let entry = self.entry(id)?;
        let res = tokio::task::spawn_blocking(move || entry.delete_password())
            .await
            .map_err(|e| SecretStoreError::Backend(format!("keyring join error: {e}")))?;
        match res {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(SecretStoreError::Backend(format!(
                "keyring delete error: {e}"
            ))),
        }
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
