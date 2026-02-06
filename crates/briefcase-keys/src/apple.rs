//! Apple Keychain / Secure Enclave backend (macOS).
//!
//! This backend uses the system Security framework via the `security-framework` crate.
//!
//! Design:
//! - Keys are created as *permanent* Keychain items.
//! - Handles store a reference to the key using the key's **application label**
//!   (a hash of the public key) so we can look it up later without storing secrets.
//! - When available and permitted, keys are generated in the Secure Enclave; otherwise
//!   we fall back to generating a software-backed Keychain key.
//!
//! Notes:
//! - Secure Enclave keys on macOS typically require the Data Protection Keychain and
//!   appropriate code-signing entitlements. In CI and many dev environments this will
//!   fail; we fall back to the default file Keychain in those cases.

use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use base64::Engine as _;
use briefcase_core::Sensitive;
use briefcase_secrets::SecretStore;
use security_framework::item::{ItemSearchOptions, KeyClass, Limit, Reference, SearchResult};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use serde::{Deserialize, Serialize};
use tokio::task::{JoinError, spawn_blocking};
use uuid::Uuid;

use crate::{KeyAlgorithm, KeyBackendKind, KeyHandle, KeysError, Signer};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppleKeyMeta {
    // base64url-encoded bytes of kSecAttrApplicationLabel (hash of public key)
    application_label_b64: String,
    secure_enclave: bool,
}

impl AppleKeyMeta {
    fn application_label_bytes(&self) -> anyhow::Result<Vec<u8>> {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&self.application_label_b64)
            .context("decode apple application label b64")
    }
}

#[derive(Clone)]
pub struct AppleKeyManager {
    secrets: Arc<dyn SecretStore>,
}

impl AppleKeyManager {
    pub fn new(secrets: Arc<dyn SecretStore>) -> Self {
        Self { secrets }
    }

    pub async fn generate_p256(&self) -> anyhow::Result<KeyHandle> {
        let id = Uuid::new_v4().to_string();
        let label = format!("briefcase-{id}");

        let (app_label, secure_enclave) = spawn_blocking(move || create_p256_key_blocking(&label))
            .await
            .map_err(join_err)??;

        let meta = AppleKeyMeta {
            application_label_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(app_label),
            secure_enclave,
        };

        // Persist metadata after the key exists; if we fail to write metadata, delete the key.
        if let Err(e) = self
            .secrets
            .put(
                &meta_secret_id(&id),
                Sensitive(serde_json::to_vec(&meta).context("serialize apple key meta")?),
            )
            .await
        {
            let _ = spawn_blocking(move || delete_key_by_meta_blocking(&meta)).await;
            return Err(anyhow::Error::new(e)).context("store apple key meta");
        }

        Ok(KeyHandle::new(
            id,
            KeyAlgorithm::P256,
            KeyBackendKind::Apple,
        ))
    }

    pub fn signer(&self, handle: KeyHandle) -> Arc<dyn Signer> {
        Arc::new(AppleSigner {
            secrets: self.secrets.clone(),
            handle,
        })
    }

    pub async fn delete(&self, handle: &KeyHandle) -> anyhow::Result<()> {
        if handle.backend != KeyBackendKind::Apple {
            anyhow::bail!(KeysError::InvalidHandle);
        }

        let meta = self.load_meta(&handle.id).await?;
        let _ = spawn_blocking(move || delete_key_by_meta_blocking(&meta))
            .await
            .map_err(join_err)?;

        let _ = self.secrets.delete(&meta_secret_id(&handle.id)).await;
        Ok(())
    }

    async fn load_meta(&self, id: &str) -> anyhow::Result<AppleKeyMeta> {
        let Some(raw) = self
            .secrets
            .get(&meta_secret_id(id))
            .await
            .context("load apple meta")?
        else {
            anyhow::bail!(KeysError::UnknownKey);
        };
        serde_json::from_slice(&raw.into_inner()).context("decode apple meta")
    }
}

struct AppleSigner {
    secrets: Arc<dyn SecretStore>,
    handle: KeyHandle,
}

impl AppleSigner {
    async fn load_meta(&self) -> anyhow::Result<AppleKeyMeta> {
        let Some(raw) = self
            .secrets
            .get(&meta_secret_id(&self.handle.id))
            .await
            .context("load apple meta")?
        else {
            anyhow::bail!(KeysError::UnknownKey);
        };
        serde_json::from_slice(&raw.into_inner()).context("decode apple meta")
    }
}

#[async_trait]
impl Signer for AppleSigner {
    fn handle(&self) -> &KeyHandle {
        &self.handle
    }

    async fn public_key_bytes(&self) -> anyhow::Result<Vec<u8>> {
        if self.handle.algorithm != KeyAlgorithm::P256
            || self.handle.backend != KeyBackendKind::Apple
        {
            anyhow::bail!(KeysError::InvalidHandle);
        }

        let meta = self.load_meta().await?;
        spawn_blocking(move || public_key_bytes_blocking(&meta))
            .await
            .map_err(join_err)?
    }

    async fn public_jwk(&self) -> anyhow::Result<serde_json::Value> {
        let pk = self.public_key_bytes().await?;
        let point = p256::EncodedPoint::from_bytes(&pk).context("decode p256 point")?;
        let x = point.x().context("p256 missing x")?;
        let y = point.y().context("p256 missing y")?;
        Ok(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x),
            "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y),
        }))
    }

    async fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        if self.handle.algorithm != KeyAlgorithm::P256
            || self.handle.backend != KeyBackendKind::Apple
        {
            anyhow::bail!(KeysError::InvalidHandle);
        }

        let meta = self.load_meta().await?;
        let msg = msg.to_vec();
        spawn_blocking(move || sign_p256_blocking(&meta, &msg))
            .await
            .map_err(join_err)?
    }
}

fn join_err(e: JoinError) -> anyhow::Error {
    anyhow::anyhow!("apple task join error: {e}")
}

fn meta_secret_id(id: &str) -> String {
    format!("keys.apple.{id}.meta")
}

fn create_p256_key_blocking(label: &str) -> anyhow::Result<(Vec<u8>, bool)> {
    // Attempt Secure Enclave first (may fail due to missing entitlements).
    let secure_err = match create_p256_with_options(label, Token::SecureEnclave) {
        Ok((label_bytes, _key)) => return Ok((label_bytes, true)),
        Err(e) => e,
    };

    // Fallback to a software-backed Keychain key.
    match create_p256_with_options(label, Token::Software) {
        Ok((label_bytes, _key)) => Ok((label_bytes, false)),
        Err(fallback_err) => Err(anyhow::anyhow!(
            "secure enclave keygen failed: {secure_err}; fallback keygen failed: {fallback_err}"
        )),
    }
}

fn create_p256_with_options(label: &str, token: Token) -> anyhow::Result<(Vec<u8>, SecKey)> {
    let mut opts = GenerateKeyOptions::default();
    opts.set_key_type(KeyType::ec());
    opts.set_size_in_bits(256);
    opts.set_label(label.to_string());

    match token {
        Token::SecureEnclave => {
            // Secure Enclave keys should use the Data Protection Keychain on modern macOS.
            opts.set_location(security_framework::item::Location::DataProtectionKeychain);
        }
        Token::Software => {
            opts.set_location(security_framework::item::Location::DefaultFileKeychain);
        }
    }

    opts.set_token(token);

    // The key is created and stored in the keychain if `location` is set.
    let key = SecKey::generate(opts.to_dictionary())
        .map_err(|e| anyhow::anyhow!("seckey generate failed: {e}"))?;

    let app_label = key
        .application_label()
        .ok_or_else(|| anyhow::anyhow!("seckey missing application label"))?;

    Ok((app_label, key))
}

fn load_private_key_blocking(meta: &AppleKeyMeta) -> anyhow::Result<SecKey> {
    let app_label = meta.application_label_bytes()?;
    let results = ItemSearchOptions::new()
        .key_class(KeyClass::private())
        .application_label(&app_label)
        .load_refs(true)
        .limit(Limit::Max(1))
        .search()
        .context("keychain search")?;

    for r in results {
        if let SearchResult::Ref(Reference::Key(k)) = r {
            return Ok(k);
        }
    }

    anyhow::bail!(KeysError::UnknownKey);
}

fn public_key_bytes_blocking(meta: &AppleKeyMeta) -> anyhow::Result<Vec<u8>> {
    let key = load_private_key_blocking(meta)?;
    let public = key.public_key().context("key has no public key")?;
    let data = public
        .external_representation()
        .context("missing public key representation")?;
    Ok(data.to_vec())
}

fn sign_p256_blocking(meta: &AppleKeyMeta, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
    let key = load_private_key_blocking(meta)?;
    let der = key
        .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, msg)
        .map_err(|e| anyhow::anyhow!("seckey sign failed: {e}"))?;
    let sig = p256::ecdsa::Signature::from_der(&der).context("parse DER signature")?;
    Ok(sig.to_bytes().to_vec())
}

fn delete_key_by_meta_blocking(meta: &AppleKeyMeta) -> anyhow::Result<()> {
    let key = load_private_key_blocking(meta)?;
    key.delete().context("keychain delete")?;
    Ok(())
}
