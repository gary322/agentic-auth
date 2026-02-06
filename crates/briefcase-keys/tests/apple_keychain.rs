#![cfg(all(feature = "apple", target_os = "macos"))]

use std::sync::Arc;

use anyhow::Context as _;
use briefcase_keys::KeyAlgorithm;
use briefcase_keys::apple::AppleKeyManager;
use p256::ecdsa::signature::Verifier as _;

#[tokio::test]
async fn apple_p256_sign_and_verify_round_trip() -> anyhow::Result<()> {
    let secrets = Arc::new(briefcase_secrets::InMemorySecretStore::default());
    let km = AppleKeyManager::new(secrets);

    let handle = km.generate_p256().await?;
    assert_eq!(handle.algorithm, KeyAlgorithm::P256);

    let signer = km.signer(handle.clone());

    let msg = b"hello apple keychain";
    let sig_bytes = signer.sign(msg).await?;
    assert_eq!(sig_bytes.len(), 64);

    let pk_bytes = signer.public_key_bytes().await?;
    let point = p256::EncodedPoint::from_bytes(&pk_bytes).context("decode p256 point")?;
    let verifying =
        p256::ecdsa::VerifyingKey::from_encoded_point(&point).context("verifying key")?;

    let sig = p256::ecdsa::Signature::from_slice(&sig_bytes).context("decode raw signature")?;
    verifying.verify(msg, &sig).context("verify signature")?;

    km.delete(&handle).await?;
    Ok(())
}
