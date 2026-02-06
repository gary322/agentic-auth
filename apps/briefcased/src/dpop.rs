use anyhow::Context as _;
use base64::Engine as _;
use briefcase_keys::{KeyAlgorithm, Signer};
use chrono::Utc;
use sha2::Digest as _;
use url::Url;
use uuid::Uuid;

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256_b64url(msg: &[u8]) -> String {
    let digest = sha2::Sha256::digest(msg);
    b64url(&digest)
}

fn jws_alg_for_key(alg: &KeyAlgorithm) -> &'static str {
    match alg {
        KeyAlgorithm::Ed25519 => "EdDSA",
        KeyAlgorithm::P256 => "ES256",
    }
}

async fn dpop_proof_internal(
    signer: &dyn Signer,
    htu: &Url,
    htm: &str,
    access_token: Option<&str>,
) -> anyhow::Result<String> {
    let jwk = signer.public_jwk().await.context("get dpop jwk")?;
    let alg = jws_alg_for_key(&signer.handle().algorithm);

    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": alg,
        "jwk": jwk,
    });

    let mut u = htu.clone();
    u.set_fragment(None);

    let iat = Utc::now().timestamp();
    let jti = Uuid::new_v4().to_string();

    let mut claims = serde_json::Map::new();
    claims.insert("htu".to_string(), serde_json::Value::String(u.to_string()));
    claims.insert(
        "htm".to_string(),
        serde_json::Value::String(htm.to_uppercase()),
    );
    claims.insert("iat".to_string(), serde_json::Value::Number(iat.into()));
    claims.insert("jti".to_string(), serde_json::Value::String(jti));
    if let Some(at) = access_token {
        claims.insert(
            "ath".to_string(),
            serde_json::Value::String(sha256_b64url(at.as_bytes())),
        );
    }
    let payload = serde_json::Value::Object(claims);

    let header_b64 = b64url(&serde_json::to_vec(&header).context("serialize dpop header")?);
    let payload_b64 = b64url(&serde_json::to_vec(&payload).context("serialize dpop payload")?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = signer
        .sign(signing_input.as_bytes())
        .await
        .context("sign dpop jwt")?;
    let sig_b64 = b64url(&sig);
    Ok(format!("{signing_input}.{sig_b64}"))
}

pub async fn dpop_proof_for_token_endpoint(
    signer: &dyn Signer,
    token_endpoint: &Url,
) -> anyhow::Result<String> {
    dpop_proof_internal(signer, token_endpoint, "POST", None).await
}

pub async fn dpop_proof_for_resource_request(
    signer: &dyn Signer,
    resource_url: &Url,
    method: &str,
    access_token: &str,
) -> anyhow::Result<String> {
    dpop_proof_internal(signer, resource_url, method, Some(access_token)).await
}
