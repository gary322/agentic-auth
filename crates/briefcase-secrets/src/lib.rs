//! Secret storage for the briefcase.
//!
//! Design constraints:
//! - secrets must not be accidentally logged (`Sensitive<T>`)
//! - secrets must not be exposed to untrusted agent runtimes
//! - support OS key stores by default, with an encrypted-file fallback

mod file_store;
mod keyring_store;
mod memory_store;
mod types;

pub use file_store::{FileSecretStore, FileSecretStoreOptions};
pub use keyring_store::{KeyringSecretStore, KeyringSecretStoreOptions};
pub use memory_store::InMemorySecretStore;
pub use types::{
    SecretStore, SecretStoreError, SecretStoreKind, SecretStoreOptions, open_secret_store,
};
