use std::collections::HashMap;

use async_trait::async_trait;
use briefcase_core::Sensitive;
use tokio::sync::Mutex;

use crate::types::{SecretStore, SecretStoreError};

#[derive(Default)]
pub struct InMemorySecretStore {
    map: Mutex<HashMap<String, Vec<u8>>>,
}

#[async_trait]
impl SecretStore for InMemorySecretStore {
    async fn put(&self, id: &str, value: Sensitive<Vec<u8>>) -> Result<(), SecretStoreError> {
        validate_id(id)?;
        self.map
            .lock()
            .await
            .insert(id.to_string(), value.into_inner());
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<Sensitive<Vec<u8>>>, SecretStoreError> {
        validate_id(id)?;
        Ok(self.map.lock().await.get(id).cloned().map(Sensitive))
    }

    async fn delete(&self, id: &str) -> Result<(), SecretStoreError> {
        validate_id(id)?;
        self.map.lock().await.remove(id);
        Ok(())
    }
}

fn validate_id(id: &str) -> Result<(), SecretStoreError> {
    // This is a conservative set. If callers need other chars, they should hash.
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
