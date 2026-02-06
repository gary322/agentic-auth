use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use briefcase_core::Sensitive;
use thiserror::Error;

use crate::file_store::{FileSecretStore, FileSecretStoreOptions};
use crate::keyring_store::{KeyringSecretStore, KeyringSecretStoreOptions};
use crate::memory_store::InMemorySecretStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretStoreKind {
    Keyring,
    File,
    Memory,
}

#[derive(Debug, Clone)]
pub struct SecretStoreOptions {
    pub kind: SecretStoreKind,
    pub data_dir: PathBuf,
    /// Required for `File` backend.
    pub passphrase: Option<String>,
}

#[derive(Debug, Error)]
pub enum SecretStoreError {
    #[error("secret backend error: {0}")]
    Backend(String),
    #[error("invalid secret id")]
    InvalidId,
}

#[async_trait]
pub trait SecretStore: Send + Sync {
    async fn put(&self, id: &str, value: Sensitive<Vec<u8>>) -> Result<(), SecretStoreError>;
    async fn get(&self, id: &str) -> Result<Option<Sensitive<Vec<u8>>>, SecretStoreError>;
    async fn delete(&self, id: &str) -> Result<(), SecretStoreError>;
}

pub async fn open_secret_store(
    opts: SecretStoreOptions,
) -> Result<Arc<dyn SecretStore>, SecretStoreError> {
    match opts.kind {
        SecretStoreKind::Keyring => Ok(Arc::new(KeyringSecretStore::new(
            KeyringSecretStoreOptions {
                service: "credential-briefcase".to_string(),
            },
        ))),
        SecretStoreKind::File => {
            let pass = opts.passphrase.ok_or_else(|| {
                SecretStoreError::Backend(
                    "missing passphrase for file secret store (set BRIEFCASE_MASTER_PASSPHRASE)"
                        .to_string(),
                )
            })?;
            Ok(Arc::new(
                FileSecretStore::open(FileSecretStoreOptions {
                    root_dir: opts.data_dir.join("secrets"),
                    passphrase: pass,
                })
                .await?,
            ))
        }
        SecretStoreKind::Memory => Ok(Arc::new(InMemorySecretStore::default())),
    }
}
