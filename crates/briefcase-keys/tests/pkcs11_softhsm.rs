#![cfg(all(feature = "pkcs11", target_os = "linux"))]

use std::sync::Arc;

use anyhow::Context as _;
use briefcase_core::Sensitive;
use briefcase_keys::KeyAlgorithm;
use briefcase_keys::pkcs11::Pkcs11KeyManager;
use p256::ecdsa::signature::Verifier as _;

#[tokio::test]
async fn pkcs11_p256_sign_and_verify_with_softhsm() -> anyhow::Result<()> {
    let Ok(module_path) = std::env::var("BRIEFCASE_PKCS11_MODULE") else {
        eprintln!("skipping: BRIEFCASE_PKCS11_MODULE not set");
        return Ok(());
    };
    let Ok(token_label) = std::env::var("BRIEFCASE_PKCS11_TOKEN_LABEL") else {
        eprintln!("skipping: BRIEFCASE_PKCS11_TOKEN_LABEL not set");
        return Ok(());
    };
    let Ok(user_pin) = std::env::var("BRIEFCASE_PKCS11_USER_PIN") else {
        eprintln!("skipping: BRIEFCASE_PKCS11_USER_PIN not set");
        return Ok(());
    };

    let secrets = Arc::new(briefcase_secrets::InMemorySecretStore::default());
    let km = Pkcs11KeyManager::new(secrets);

    let handle = km
        .generate_p256(module_path, token_label, Sensitive(user_pin))
        .await?;
    assert_eq!(handle.algorithm, KeyAlgorithm::P256);

    let signer = km.signer(handle.clone());

    let msg = b"hello pkcs11";
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
