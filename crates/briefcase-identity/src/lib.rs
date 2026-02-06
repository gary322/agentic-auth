//! Identity primitives for the briefcase.
//!
//! v1 scope:
//! - Generate a `did:key` for Ed25519 (sufficient for "holder DID" identifiers)
//! - Keep private key bytes as a `Sensitive`/secret-store payload (callers own storage)

use bs58::Alphabet;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore as _;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("invalid signing key")]
    InvalidSigningKey,
}

#[derive(Debug, Clone)]
pub struct DidKeyEd25519 {
    pub did: String,
    pub verifying_key: VerifyingKey,
    /// 32-byte Ed25519 secret key seed. Callers should store this in the secret store.
    pub secret_key_seed: Zeroizing<[u8; 32]>,
}

impl DidKeyEd25519 {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);

        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        let did = did_key_for_ed25519(&verifying_key);
        Self {
            did,
            verifying_key,
            secret_key_seed: Zeroizing::new(seed),
        }
    }

    pub fn from_secret_key_seed(seed: [u8; 32]) -> Result<Self, IdentityError> {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            did: did_key_for_ed25519(&verifying_key),
            verifying_key,
            secret_key_seed: Zeroizing::new(seed),
        })
    }
}

/// Creates a `did:key` DID string for an Ed25519 public key.
///
/// Spec reference: did:key uses multicodec + multibase(base58btc).
/// For Ed25519 public keys, the multicodec prefix is 0xED 0x01.
pub fn did_key_for_ed25519(verifying_key: &VerifyingKey) -> String {
    let mut bytes = [0u8; 34];
    bytes[0] = 0xED;
    bytes[1] = 0x01;
    bytes[2..].copy_from_slice(verifying_key.as_bytes());
    let encoded = bs58::encode(bytes)
        .with_alphabet(Alphabet::BITCOIN)
        .into_string();
    format!("did:key:z{encoded}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize as _;

    #[test]
    fn did_key_round_trip_seed() {
        let id = DidKeyEd25519::generate();
        let seed = *id.secret_key_seed;
        let id2 = DidKeyEd25519::from_secret_key_seed(seed).unwrap();
        assert_eq!(id.did, id2.did);
        assert_eq!(id.verifying_key.as_bytes(), id2.verifying_key.as_bytes());
    }

    #[test]
    fn did_key_is_stable_for_pubkey() {
        let id = DidKeyEd25519::generate();
        let did2 = did_key_for_ed25519(&id.verifying_key);
        assert_eq!(id.did, did2);
        assert!(id.did.starts_with("did:key:z"));
    }

    #[test]
    fn did_key_encodes_multicodec_prefix() {
        // Ensure the multicodec prefix round-trips (0xED01).
        let id = DidKeyEd25519::generate();
        let multibase = id.did.strip_prefix("did:key:z").unwrap();
        let decoded = bs58::decode(multibase)
            .with_alphabet(Alphabet::BITCOIN)
            .into_vec()
            .unwrap();
        assert_eq!(decoded.len(), 34);
        assert_eq!(hex::encode(&decoded[..2]), "ed01");
    }

    #[test]
    fn seed_zeroizes_on_drop() {
        let mut seed = Zeroizing::new([7u8; 32]);
        seed.zeroize();
        assert_eq!(&seed[..], &[0u8; 32]);
    }
}
