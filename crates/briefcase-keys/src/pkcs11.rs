//! PKCS#11 key backend (HSM / TPM-backed HSMs / SoftHSM for CI).
//!
//! This backend is feature-gated (`briefcase-keys/pkcs11`) so default builds remain minimal.
//!
//! Design:
//! - The `KeyHandle` is an opaque id; key material never leaves the PKCS#11 provider.
//! - Per-key configuration (module path, token label, key label) and the user PIN are stored in
//!   `briefcase-secrets`. The PIN is never serialized into the handle.

use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use base64::Engine as _;
use briefcase_core::Sensitive;
use briefcase_secrets::SecretStore;
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as Pkcs11Error, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use tokio::task::JoinError;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{KeyAlgorithm, KeyBackendKind, KeyHandle, KeysError, Signer};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Pkcs11KeyMeta {
    module_path: String,
    token_label: String,
    key_label: String,
}

#[derive(Clone)]
pub struct Pkcs11KeyManager {
    secrets: Arc<dyn SecretStore>,
}

impl Pkcs11KeyManager {
    pub fn new(secrets: Arc<dyn SecretStore>) -> Self {
        Self { secrets }
    }

    /// Generates a non-exportable P-256 key inside the PKCS#11 token identified by `token_label`.
    ///
    /// The returned `KeyHandle` is opaque and serializable; the PIN never leaves the secret store.
    pub async fn generate_p256(
        &self,
        module_path: String,
        token_label: String,
        user_pin: Sensitive<String>,
    ) -> anyhow::Result<KeyHandle> {
        let id = Uuid::new_v4().to_string();
        let key_label = format!("briefcase-{id}");

        let meta = Pkcs11KeyMeta {
            module_path,
            token_label,
            key_label,
        };

        // Create key first, then persist metadata. If the metadata write fails we try to clean up.
        let pin = user_pin.0;
        create_p256_keypair(&meta, &pin).await?;

        if let Err(e) = self
            .secrets
            .put(
                &meta_secret_id(&id),
                Sensitive(serde_json::to_vec(&meta).context("serialize pkcs11 key meta")?),
            )
            .await
        {
            let _ = destroy_keypair(&meta, &pin).await;
            return Err(anyhow::Error::new(e)).context("store pkcs11 key meta");
        }
        if let Err(e) = self
            .secrets
            .put(&pin_secret_id(&id), Sensitive(pin.as_bytes().to_vec()))
            .await
        {
            let _ = destroy_keypair(&meta, &pin).await;
            let _ = self.secrets.delete(&meta_secret_id(&id)).await;
            return Err(anyhow::Error::new(e)).context("store pkcs11 user pin");
        }

        Ok(KeyHandle::new(
            id,
            KeyAlgorithm::P256,
            KeyBackendKind::Pkcs11,
        ))
    }

    pub fn signer(&self, handle: KeyHandle) -> Arc<dyn Signer> {
        Arc::new(Pkcs11Signer {
            secrets: self.secrets.clone(),
            handle,
        })
    }

    pub async fn delete(&self, handle: &KeyHandle) -> anyhow::Result<()> {
        if handle.backend != KeyBackendKind::Pkcs11 {
            anyhow::bail!(KeysError::InvalidHandle);
        }

        let meta = self.load_meta(&handle.id).await?;
        let pin = self.load_pin(&handle.id).await?;
        let _ = destroy_keypair(&meta, &pin).await;

        let _ = self.secrets.delete(&meta_secret_id(&handle.id)).await;
        let _ = self.secrets.delete(&pin_secret_id(&handle.id)).await;
        Ok(())
    }

    async fn load_meta(&self, id: &str) -> anyhow::Result<Pkcs11KeyMeta> {
        let Some(raw) = self
            .secrets
            .get(&meta_secret_id(id))
            .await
            .context("load pkcs11 meta")?
        else {
            anyhow::bail!(KeysError::UnknownKey);
        };
        serde_json::from_slice(&raw.into_inner()).context("decode pkcs11 meta")
    }

    async fn load_pin(&self, id: &str) -> anyhow::Result<Zeroizing<String>> {
        let Some(raw) = self
            .secrets
            .get(&pin_secret_id(id))
            .await
            .context("load pkcs11 pin")?
        else {
            anyhow::bail!(KeysError::UnknownKey);
        };
        let s = String::from_utf8(raw.into_inner()).context("pkcs11 pin must be utf-8")?;
        Ok(Zeroizing::new(s))
    }
}

struct Pkcs11Signer {
    secrets: Arc<dyn SecretStore>,
    handle: KeyHandle,
}

impl Pkcs11Signer {
    async fn load_meta(&self) -> anyhow::Result<Pkcs11KeyMeta> {
        let Some(raw) = self
            .secrets
            .get(&meta_secret_id(&self.handle.id))
            .await
            .context("load pkcs11 meta")?
        else {
            anyhow::bail!(KeysError::UnknownKey);
        };
        serde_json::from_slice(&raw.into_inner()).context("decode pkcs11 meta")
    }

    async fn load_pin(&self) -> anyhow::Result<Zeroizing<String>> {
        let Some(raw) = self
            .secrets
            .get(&pin_secret_id(&self.handle.id))
            .await
            .context("load pkcs11 pin")?
        else {
            anyhow::bail!(KeysError::UnknownKey);
        };
        let s = String::from_utf8(raw.into_inner()).context("pkcs11 pin must be utf-8")?;
        Ok(Zeroizing::new(s))
    }
}

#[async_trait]
impl Signer for Pkcs11Signer {
    fn handle(&self) -> &KeyHandle {
        &self.handle
    }

    async fn public_key_bytes(&self) -> anyhow::Result<Vec<u8>> {
        if self.handle.algorithm != KeyAlgorithm::P256
            || self.handle.backend != KeyBackendKind::Pkcs11
        {
            anyhow::bail!(KeysError::InvalidHandle);
        }

        let meta = self.load_meta().await?;
        let pin = self.load_pin().await?;
        tokio::task::spawn_blocking(move || load_public_key_bytes(&meta, &pin))
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
            || self.handle.backend != KeyBackendKind::Pkcs11
        {
            anyhow::bail!(KeysError::InvalidHandle);
        }

        let meta = self.load_meta().await?;
        let pin = self.load_pin().await?;
        let msg = msg.to_vec();

        tokio::task::spawn_blocking(move || sign_p256(&meta, &pin, &msg))
            .await
            .map_err(join_err)?
    }
}

fn join_err(e: JoinError) -> anyhow::Error {
    anyhow::anyhow!("pkcs11 task join error: {e}")
}

fn meta_secret_id(id: &str) -> String {
    format!("keys.pkcs11.{id}.meta")
}

fn pin_secret_id(id: &str) -> String {
    format!("keys.pkcs11.{id}.pin")
}

async fn create_p256_keypair(meta: &Pkcs11KeyMeta, pin: &str) -> anyhow::Result<()> {
    let meta = meta.clone();
    let pin = pin.to_string();
    tokio::task::spawn_blocking(move || create_p256_keypair_blocking(&meta, &pin))
        .await
        .map_err(join_err)?
}

async fn destroy_keypair(meta: &Pkcs11KeyMeta, pin: &str) -> anyhow::Result<()> {
    let meta = meta.clone();
    let pin = pin.to_string();
    tokio::task::spawn_blocking(move || destroy_keypair_blocking(&meta, &pin))
        .await
        .map_err(join_err)?
}

fn create_p256_keypair_blocking(meta: &Pkcs11KeyMeta, pin: &str) -> anyhow::Result<()> {
    let (pkcs11, session) = open_user_session(meta, pin)?;

    let secp256r1_oid: Vec<u8> = vec![0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    let label_bytes = meta.key_label.as_bytes().to_vec();

    let pub_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::KeyType(KeyType::EC),
        Attribute::Verify(true),
        Attribute::EcParams(secp256r1_oid),
        Attribute::Label(label_bytes.clone()),
        Attribute::Id(label_bytes.clone()),
    ];

    let priv_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
        Attribute::Label(label_bytes.clone()),
        Attribute::Id(label_bytes),
    ];

    let _ = session
        .generate_key_pair(
            &Mechanism::EccKeyPairGen,
            &pub_key_template,
            &priv_key_template,
        )
        .context("generate p256 keypair")?;

    let _ = session.close();
    let _ = pkcs11.finalize();
    Ok(())
}

fn destroy_keypair_blocking(meta: &Pkcs11KeyMeta, pin: &str) -> anyhow::Result<()> {
    let (pkcs11, session) = open_user_session(meta, pin)?;

    let label_bytes = meta.key_label.as_bytes().to_vec();

    for class in [ObjectClass::PUBLIC_KEY, ObjectClass::PRIVATE_KEY] {
        let objs = session
            .find_objects(&[
                Attribute::Class(class),
                Attribute::Label(label_bytes.clone()),
            ])
            .unwrap_or_default();
        for obj in objs {
            let _ = session.destroy_object(obj);
        }
    }

    let _ = session.close();
    let _ = pkcs11.finalize();
    Ok(())
}

fn load_public_key_bytes(meta: &Pkcs11KeyMeta, pin: &str) -> anyhow::Result<Vec<u8>> {
    let (pkcs11, session) = open_user_session(meta, pin)?;

    let label_bytes = meta.key_label.as_bytes().to_vec();
    let mut objs = session
        .find_objects(&[
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Label(label_bytes),
        ])
        .context("find public key")?;
    let obj = objs
        .pop()
        .ok_or_else(|| anyhow::anyhow!(KeysError::UnknownKey))?;

    let ec_point_attr = session
        .get_attributes(obj, &[AttributeType::EcPoint])
        .context("get public key EC_POINT")?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing EC_POINT attribute"))?;

    let raw = match ec_point_attr {
        Attribute::EcPoint(v) => v,
        _ => anyhow::bail!("unexpected EC_POINT attribute type"),
    };

    let point = decode_ec_point(&raw).context("decode EC_POINT")?;

    let _ = session.close();
    let _ = pkcs11.finalize();
    Ok(point)
}

fn sign_p256(meta: &Pkcs11KeyMeta, pin: &str, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
    let (pkcs11, session) = open_user_session(meta, pin)?;

    let label_bytes = meta.key_label.as_bytes().to_vec();
    let mut objs = session
        .find_objects(&[
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(label_bytes),
        ])
        .context("find private key")?;
    let obj = objs
        .pop()
        .ok_or_else(|| anyhow::anyhow!(KeysError::UnknownKey))?;

    // CKM_ECDSA expects the pre-hashed message. Hash with SHA-256 and return a raw (r||s)
    // signature, matching JWS ES256 requirements.
    let digest = sha2::Sha256::digest(msg);
    let sig = session
        .sign(&Mechanism::Ecdsa, obj, &digest)
        .context("pkcs11 sign")?;

    let _ = session.close();
    let _ = pkcs11.finalize();
    Ok(sig)
}

fn open_user_session(
    meta: &Pkcs11KeyMeta,
    pin: &str,
) -> anyhow::Result<(Pkcs11, cryptoki::session::Session)> {
    let pkcs11 =
        Pkcs11::new(&meta.module_path).with_context(|| format!("load {}", meta.module_path))?;

    match pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) => {}
        Err(Pkcs11Error::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
        Err(e) => return Err(anyhow::Error::new(e)).context("pkcs11 initialize"),
    }

    let slot = find_slot_by_label(&pkcs11, &meta.token_label).context("find token slot")?;
    let session = pkcs11.open_rw_session(slot).context("open rw session")?;

    let pin = AuthPin::new(pin.to_string().into());
    session
        .login(UserType::User, Some(&pin))
        .context("pkcs11 login")?;

    Ok((pkcs11, session))
}

fn find_slot_by_label(pkcs11: &Pkcs11, token_label: &str) -> anyhow::Result<cryptoki::slot::Slot> {
    for slot in pkcs11.get_slots_with_token().context("list slots")? {
        if let Ok(info) = pkcs11.get_token_info(slot) {
            if info.label() == token_label {
                return Ok(slot);
            }
        }
    }
    anyhow::bail!("no PKCS#11 slot with token label {token_label:?}")
}

fn decode_ec_point(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    // SoftHSM typically returns CKA_EC_POINT as DER OCTET STRING wrapping the uncompressed point.
    if bytes.len() == 65 && bytes.first() == Some(&0x04) {
        return Ok(bytes.to_vec());
    }
    if bytes.len() >= 3 && bytes[0] == 0x04 {
        // DER length can be short-form or 0x81 long-form for small-ish values.
        let (len, off) = if bytes[1] & 0x80 == 0 {
            (bytes[1] as usize, 2usize)
        } else if bytes[1] == 0x81 && bytes.len() >= 3 {
            (bytes[2] as usize, 3usize)
        } else {
            anyhow::bail!("unsupported DER length encoding for EC_POINT");
        };
        if bytes.len() != off + len {
            anyhow::bail!("invalid DER OCTET STRING length for EC_POINT");
        }
        let inner = &bytes[off..];
        if inner.len() == 65 && inner.first() == Some(&0x04) {
            return Ok(inner.to_vec());
        }
    }
    anyhow::bail!("unexpected EC_POINT encoding (len={})", bytes.len())
}
