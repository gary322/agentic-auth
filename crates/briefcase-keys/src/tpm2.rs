//! TPM2-backed key backend (Linux).
//!
//! This backend shells out to `tpm2-tools` so we can validate key creation + signing against
//! `swtpm` in CI without pulling in unstable FFI bindings. It is intentionally conservative:
//! - keys are referenced by **persistent TPM handles**
//! - signatures are converted to JWS-compatible raw `(r||s)` for ES256
//!
//! Requirements:
//! - `tpm2_createprimary`, `tpm2_evictcontrol`, `tpm2_readpublic`, `tpm2_sign` available in `PATH`
//! - caller provides a `TPM2TOOLS_TCTI` string (stored in the key metadata)

use std::process::Command;
use std::sync::Arc;
use std::{collections::HashSet, ops::RangeInclusive};

use anyhow::Context as _;
use async_trait::async_trait;
use base64::Engine as _;
use briefcase_core::Sensitive;
use briefcase_secrets::SecretStore;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use tokio::task::{JoinError, spawn_blocking};
use uuid::Uuid;

use crate::{KeyAlgorithm, KeyBackendKind, KeyHandle, KeysError, Signer};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Tpm2KeyMeta {
    tcti: String,
    persistent_handle: u32,
}

#[derive(Clone)]
pub struct Tpm2KeyManager {
    secrets: Arc<dyn SecretStore>,
}

impl Tpm2KeyManager {
    pub fn new(secrets: Arc<dyn SecretStore>) -> Self {
        Self { secrets }
    }

    pub async fn generate_p256(&self, tcti: String) -> anyhow::Result<KeyHandle> {
        let id = Uuid::new_v4().to_string();

        let persistent_handle =
            create_persistent_p256_signing_key(tcti.clone(), id.clone()).await?;
        let meta = Tpm2KeyMeta {
            tcti,
            persistent_handle,
        };

        self.secrets
            .put(
                &meta_secret_id(&id),
                Sensitive(serde_json::to_vec(&meta).context("serialize tpm2 meta")?),
            )
            .await
            .context("store tpm2 meta")?;

        Ok(KeyHandle::new(id, KeyAlgorithm::P256, KeyBackendKind::Tpm2))
    }

    pub fn signer(&self, handle: KeyHandle) -> Arc<dyn Signer> {
        Arc::new(Tpm2Signer {
            secrets: self.secrets.clone(),
            handle,
        })
    }

    pub async fn delete(&self, handle: &KeyHandle) -> anyhow::Result<()> {
        if handle.backend != KeyBackendKind::Tpm2 {
            anyhow::bail!(KeysError::InvalidHandle);
        }

        let meta = self.load_meta(&handle.id).await?;
        let _ = delete_persistent_key(&meta).await;

        let _ = self.secrets.delete(&meta_secret_id(&handle.id)).await;
        Ok(())
    }

    async fn load_meta(&self, id: &str) -> anyhow::Result<Tpm2KeyMeta> {
        let Some(raw) = self
            .secrets
            .get(&meta_secret_id(id))
            .await
            .context("load tpm2 meta")?
        else {
            anyhow::bail!(KeysError::UnknownKey);
        };
        serde_json::from_slice(&raw.into_inner()).context("decode tpm2 meta")
    }
}

struct Tpm2Signer {
    secrets: Arc<dyn SecretStore>,
    handle: KeyHandle,
}

impl Tpm2Signer {
    async fn load_meta(&self) -> anyhow::Result<Tpm2KeyMeta> {
        let Some(raw) = self
            .secrets
            .get(&meta_secret_id(&self.handle.id))
            .await
            .context("load tpm2 meta")?
        else {
            anyhow::bail!(KeysError::UnknownKey);
        };
        serde_json::from_slice(&raw.into_inner()).context("decode tpm2 meta")
    }
}

#[async_trait]
impl Signer for Tpm2Signer {
    fn handle(&self) -> &KeyHandle {
        &self.handle
    }

    async fn public_key_bytes(&self) -> anyhow::Result<Vec<u8>> {
        if self.handle.algorithm != KeyAlgorithm::P256
            || self.handle.backend != KeyBackendKind::Tpm2
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
            || self.handle.backend != KeyBackendKind::Tpm2
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
    anyhow::anyhow!("tpm2 task join error: {e}")
}

fn meta_secret_id(id: &str) -> String {
    format!("keys.tpm2.{id}.meta")
}

// swtpm appears to enforce a narrower persistent handle range than physical TPMs.
// We stick to the conservative range below for CI stability.
const PERSISTENT_HANDLE_RANGE: RangeInclusive<u32> = 0x8100_0001..=0x8100_FFFF;

fn derive_handle_seed(id: &str) -> u16 {
    let digest = sha2::Sha256::digest(id.as_bytes());
    let mut v = u16::from_be_bytes(digest[0..2].try_into().expect("2 bytes"));
    if v == 0 {
        v = 1;
    }
    v
}

async fn create_persistent_p256_signing_key(tcti: String, seed_id: String) -> anyhow::Result<u32> {
    spawn_blocking(move || create_persistent_p256_signing_key_blocking(&tcti, &seed_id))
        .await
        .map_err(join_err)?
}

fn create_persistent_p256_signing_key_blocking(tcti: &str, seed_id: &str) -> anyhow::Result<u32> {
    // Create a primary signing key and persist it. This keeps the loaded-object footprint minimal,
    // which is important for some `swtpm` configurations.
    let tmp = tempfile::tempdir().context("create temp dir")?;
    let ctx_path = tmp.path().join("primary.ctx");

    run(
        tcti,
        "tpm2_createprimary",
        &[
            "-C",
            "o",
            "-G",
            "ecc",
            "-a",
            "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign",
            "-c",
            ctx_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("ctx path not utf-8"))?,
        ],
    )
    .context("tpm2_createprimary")?;

    // Pick a persistent handle in a conservative range and retry on collisions/out-of-range.
    let used = list_persistent_handles(tcti).unwrap_or_default();
    let mut handle = allocate_persistent_handle(seed_id, &used);

    for _ in 0..PERSISTENT_HANDLE_RANGE.clone().count() {
        let handle_s = fmt_handle(handle);
        let res = run(
            tcti,
            "tpm2_evictcontrol",
            &[
                "-C",
                "o",
                "-c",
                ctx_path
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("ctx path not utf-8"))?,
                &handle_s,
            ],
        );

        match res {
            Ok(_) => return Ok(handle),
            Err(e) => {
                // swtpm/tpm2-tools may report "out of allowed range" for handles it doesn't like;
                // it can also race with other keys. Keep trying within the conservative range.
                let msg = e.to_string();
                if msg.contains("out of allowed range")
                    || msg.contains("already")
                    || msg.contains("defined")
                {
                    handle = next_persistent_handle(handle);
                    continue;
                }
                return Err(e).context("tpm2_evictcontrol persist");
            }
        }
    }

    anyhow::bail!("no available TPM2 persistent handles in conservative range")
}

async fn delete_persistent_key(meta: &Tpm2KeyMeta) -> anyhow::Result<()> {
    let meta = meta.clone();
    spawn_blocking(move || delete_persistent_key_blocking(&meta))
        .await
        .map_err(join_err)?
}

fn delete_persistent_key_blocking(meta: &Tpm2KeyMeta) -> anyhow::Result<()> {
    let handle = fmt_handle(meta.persistent_handle);
    run(&meta.tcti, "tpm2_evictcontrol", &["-C", "o", "-c", &handle])
        .context("tpm2_evictcontrol evict")?;
    Ok(())
}

fn public_key_bytes_blocking(meta: &Tpm2KeyMeta) -> anyhow::Result<Vec<u8>> {
    let handle = fmt_handle(meta.persistent_handle);
    let out = run(&meta.tcti, "tpm2_readpublic", &["-c", &handle]).context("tpm2_readpublic")?;

    // Parse `x:` and `y:` lines from the tool output.
    let mut x_hex: Option<String> = None;
    let mut y_hex: Option<String> = None;
    for line in out.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("x:") {
            x_hex = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("y:") {
            y_hex = Some(rest.trim().to_string());
        }
    }

    let x = hex::decode(x_hex.ok_or_else(|| anyhow::anyhow!("missing x"))?).context("hex x")?;
    let y = hex::decode(y_hex.ok_or_else(|| anyhow::anyhow!("missing y"))?).context("hex y")?;

    if x.len() != 32 || y.len() != 32 {
        anyhow::bail!(
            "unexpected P-256 public key size x={}, y={}",
            x.len(),
            y.len()
        );
    }

    let mut out = Vec::with_capacity(65);
    out.push(0x04);
    out.extend_from_slice(&x);
    out.extend_from_slice(&y);
    Ok(out)
}

fn sign_p256_blocking(meta: &Tpm2KeyMeta, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
    let handle = fmt_handle(meta.persistent_handle);
    let digest = sha2::Sha256::digest(msg);

    let tmp = tempfile::tempdir().context("create temp dir")?;
    let digest_path = tmp.path().join("digest.bin");
    let sig_path = tmp.path().join("sig.bin");

    std::fs::write(&digest_path, digest).context("write digest")?;

    run(
        &meta.tcti,
        "tpm2_sign",
        &[
            "-c",
            &handle,
            "-g",
            "sha256",
            "-d",
            "-f",
            "plain",
            "-o",
            sig_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("sig path not utf-8"))?,
            digest_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("digest path not utf-8"))?,
        ],
    )
    .context("tpm2_sign")?;

    let der = std::fs::read(&sig_path).context("read signature")?;
    let sig = p256::ecdsa::Signature::from_der(&der).context("parse DER signature")?;
    Ok(sig.to_bytes().to_vec())
}

fn fmt_handle(handle: u32) -> String {
    format!("0x{handle:08x}")
}

fn list_persistent_handles(tcti: &str) -> anyhow::Result<HashSet<u32>> {
    let out = run(tcti, "tpm2_getcap", &["handles-persistent"])
        .context("tpm2_getcap handles-persistent")?;
    let mut handles = HashSet::new();
    for line in out.lines() {
        let line = line.trim().trim_start_matches('-').trim();
        let Some(hex) = line.strip_prefix("0x") else {
            continue;
        };
        if let Ok(v) = u32::from_str_radix(hex, 16) {
            handles.insert(v);
        }
    }
    Ok(handles)
}

fn allocate_persistent_handle(seed_id: &str, used: &HashSet<u32>) -> u32 {
    let seed = derive_handle_seed(seed_id) as u32;
    let base = *PERSISTENT_HANDLE_RANGE.start();
    let max = *PERSISTENT_HANDLE_RANGE.end();

    let mut h = (base & 0xFFFF_0000) | seed;
    if h < base {
        h = base;
    }
    if h > max {
        h = base;
    }

    // Try seed-derived handle first, then linearly probe.
    for _ in 0..PERSISTENT_HANDLE_RANGE.clone().count() {
        if !used.contains(&h) {
            return h;
        }
        h = next_persistent_handle(h);
    }

    // Fallback: return base (caller will bail after retries).
    base
}

fn next_persistent_handle(h: u32) -> u32 {
    let base = *PERSISTENT_HANDLE_RANGE.start();
    let max = *PERSISTENT_HANDLE_RANGE.end();
    if h >= max { base } else { h + 1 }
}

fn run(tcti: &str, bin: &str, args: &[&str]) -> anyhow::Result<String> {
    let output = Command::new(bin)
        .env("TPM2TOOLS_TCTI", tcti)
        .args(args)
        .output()
        .with_context(|| format!("spawn {bin}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!(
            "{bin} failed status={} stdout={} stderr={}",
            output.status,
            stdout.trim(),
            stderr.trim()
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
