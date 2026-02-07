//! x402 protocol support (challenge parsing and payment payload encoding).
//!
//! This module intentionally focuses on:
//! - HTTP transport headers: `PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE`, `PAYMENT-RESPONSE`
//! - Core JSON types: `PaymentRequired`, `PaymentPayload`, `SettlementResponse`
//! - A minimal "exact/eip155/eip3009" signing + verification helper (used by the payment helper)

use anyhow::Context as _;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

const MAX_HEADER_B64_LEN: usize = 64 * 1024; // avoid header-induced memory blowups

// Use lowercase constants because `http::HeaderName::from_static` requires it and the HTTP header
// name space is case-insensitive.
pub const HEADER_PAYMENT_REQUIRED: &str = "payment-required";
pub const HEADER_PAYMENT_SIGNATURE: &str = "payment-signature";
pub const HEADER_PAYMENT_RESPONSE: &str = "payment-response";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequired {
    pub x402_version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub resource: ResourceInfo,
    pub accepts: Vec<PaymentRequirements>,
    #[serde(default)]
    pub extensions: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceInfo {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    pub scheme: String,
    pub network: String,
    pub amount: String,
    pub asset: String,
    pub pay_to: String,
    pub max_timeout_seconds: i64,
    #[serde(default)]
    pub extra: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload {
    pub x402_version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceInfo>,
    pub accepted: PaymentRequirements,
    pub payload: serde_json::Value,
    #[serde(default)]
    pub extensions: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SettlementResponse {
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    pub transaction: String,
    pub network: String,
}

pub fn encode_payment_required_b64(v: &PaymentRequired) -> anyhow::Result<String> {
    let json = serde_json::to_vec(v).context("encode PaymentRequired")?;
    Ok(base64::engine::general_purpose::STANDARD.encode(json))
}

pub fn decode_payment_required_b64(v: &str) -> anyhow::Result<PaymentRequired> {
    decode_b64_json(v, "PaymentRequired")
}

pub fn encode_payment_payload_b64(v: &PaymentPayload) -> anyhow::Result<String> {
    let json = serde_json::to_vec(v).context("encode PaymentPayload")?;
    Ok(base64::engine::general_purpose::STANDARD.encode(json))
}

pub fn decode_payment_payload_b64(v: &str) -> anyhow::Result<PaymentPayload> {
    decode_b64_json(v, "PaymentPayload")
}

pub fn encode_settlement_response_b64(v: &SettlementResponse) -> anyhow::Result<String> {
    let json = serde_json::to_vec(v).context("encode SettlementResponse")?;
    Ok(base64::engine::general_purpose::STANDARD.encode(json))
}

pub fn decode_settlement_response_b64(v: &str) -> anyhow::Result<SettlementResponse> {
    decode_b64_json(v, "SettlementResponse")
}

fn decode_b64_json<T: for<'de> Deserialize<'de>>(v: &str, ty: &'static str) -> anyhow::Result<T> {
    let trimmed = v.trim();
    if trimmed.len() > MAX_HEADER_B64_LEN {
        anyhow::bail!("{ty} header too large");
    }

    // Accept both padded and unpadded base64. Some transports/proxies strip padding.
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed))
        .context("base64 decode")?;
    serde_json::from_slice(&bytes).with_context(|| format!("decode {ty} json"))
}

pub mod evm {
    use super::*;

    use rand::RngCore as _;
    use secp256k1::ecdsa::{RecoverableSignature, RecoveryId, Signature};
    use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
    use sha3::Digest as _;

    const EIP712_DOMAIN_TYPE: &str =
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
    const TRANSFER_WITH_AUTH_TYPE: &str = "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "camelCase")]
    pub struct Eip3009Authorization {
        pub from: String,
        pub to: String,
        pub value: String,
        pub valid_after: String,
        pub valid_before: String,
        pub nonce: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "camelCase")]
    pub struct ExactEvmEip3009Payload {
        pub signature: String,
        pub authorization: Eip3009Authorization,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ExactEvmExtra {
        #[serde(default)]
        asset_transfer_method: Option<String>,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        version: Option<String>,
    }

    pub fn select_exact_eip3009(req: &PaymentRequired) -> anyhow::Result<PaymentRequirements> {
        for r in &req.accepts {
            if r.scheme != "exact" {
                continue;
            }
            if !r.network.starts_with("eip155:") {
                continue;
            }
            let extra: ExactEvmExtra =
                serde_json::from_value(r.extra.clone()).unwrap_or(ExactEvmExtra {
                    asset_transfer_method: None,
                    name: None,
                    version: None,
                });
            match extra.asset_transfer_method.as_deref() {
                None | Some("eip3009") => return Ok(r.clone()),
                Some(_) => continue,
            }
        }
        anyhow::bail!("no supported x402 accepts entry (need exact/eip155/eip3009)");
    }

    pub fn payment_signature_b64_for_eip3009(
        sk: &SecretKey,
        required: &PaymentRequired,
    ) -> anyhow::Result<String> {
        let accepted = select_exact_eip3009(required)?;
        let payload = build_payment_payload_eip3009(sk, required, accepted)?;
        encode_payment_payload_b64(&payload)
    }

    pub fn build_payment_payload_eip3009(
        sk: &SecretKey,
        required: &PaymentRequired,
        accepted: PaymentRequirements,
    ) -> anyhow::Result<PaymentPayload> {
        // Extract EIP-712 domain info from `extra`.
        let extra: ExactEvmExtra =
            serde_json::from_value(accepted.extra.clone()).context("parse accepted.extra")?;
        let name = extra.name.context("accepted.extra.name required")?;
        let version = extra.version.context("accepted.extra.version required")?;

        let chain_id = parse_chain_id(&accepted.network)?;
        let verifying_contract = parse_address(&accepted.asset).context("accepted.asset")?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock before unix epoch")?
            .as_secs();
        let valid_after = now.saturating_sub(5);
        let valid_before = now
            .saturating_add(accepted.max_timeout_seconds.max(1) as u64)
            .max(valid_after.saturating_add(1));

        let from = address_from_secret_key(sk);
        let to = accepted.pay_to.clone();
        let value = accepted.amount.clone();
        let nonce = random_nonce_hex();

        let auth = Eip3009Authorization {
            from: from.clone(),
            to,
            value,
            valid_after: valid_after.to_string(),
            valid_before: valid_before.to_string(),
            nonce,
        };

        let digest = eip3009_digest(&name, &version, chain_id, verifying_contract, &auth)?;
        let sig = sign_digest(sk, digest)?;

        let scheme_payload = ExactEvmEip3009Payload {
            signature: sig,
            authorization: auth,
        };

        Ok(PaymentPayload {
            x402_version: required.x402_version,
            resource: Some(required.resource.clone()),
            accepted,
            payload: serde_json::to_value(scheme_payload).context("encode scheme payload")?,
            extensions: required.extensions.clone(),
        })
    }

    pub fn verify_eip3009_payload(
        required: &PaymentRequired,
        payment_payload: &PaymentPayload,
    ) -> anyhow::Result<String> {
        if payment_payload.x402_version != required.x402_version {
            anyhow::bail!("x402 version mismatch");
        }

        let extra: ExactEvmExtra = serde_json::from_value(payment_payload.accepted.extra.clone())
            .context("parse accepted.extra")?;
        let name = extra.name.context("accepted.extra.name required")?;
        let version = extra.version.context("accepted.extra.version required")?;

        let chain_id = parse_chain_id(&payment_payload.accepted.network)?;
        let verifying_contract =
            parse_address(&payment_payload.accepted.asset).context("accepted.asset")?;

        let scheme_payload: ExactEvmEip3009Payload =
            serde_json::from_value(payment_payload.payload.clone()).context("parse payload")?;

        // Verify required fields match.
        if payment_payload.accepted.scheme != "exact" {
            anyhow::bail!("unsupported scheme");
        }
        if scheme_payload.authorization.to != payment_payload.accepted.pay_to {
            anyhow::bail!("authorization.to does not match pay_to");
        }
        if scheme_payload.authorization.value != payment_payload.accepted.amount {
            anyhow::bail!("authorization.value does not match amount");
        }

        let digest = eip3009_digest(
            &name,
            &version,
            chain_id,
            verifying_contract,
            &scheme_payload.authorization,
        )?;
        let recovered = recover_address(digest, &scheme_payload.signature)?;
        if !eq_address(&recovered, &scheme_payload.authorization.from) {
            anyhow::bail!("signature does not recover to authorization.from");
        }
        Ok(recovered)
    }

    fn parse_chain_id(network: &str) -> anyhow::Result<u64> {
        let (_, rest) = network
            .split_once(':')
            .with_context(|| format!("invalid CAIP-2 network: {network}"))?;
        rest.parse::<u64>()
            .with_context(|| format!("parse chain id from network: {network}"))
    }

    fn eq_address(a: &str, b: &str) -> bool {
        a.trim().eq_ignore_ascii_case(b.trim())
    }

    fn parse_address(addr: &str) -> anyhow::Result<[u8; 20]> {
        let s = addr.trim().strip_prefix("0x").unwrap_or(addr.trim());
        let bytes = hex::decode(s).context("hex decode")?;
        if bytes.len() != 20 {
            anyhow::bail!("expected 20-byte address");
        }
        let mut out = [0u8; 20];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    fn address_from_secret_key(sk: &SecretKey) -> String {
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, sk);
        let addr = address_from_pubkey(&pk);
        format!("0x{}", hex::encode(addr))
    }

    fn address_from_pubkey(pk: &PublicKey) -> [u8; 20] {
        let uncompressed = pk.serialize_uncompressed();
        let hash = keccak256(&uncompressed[1..]); // strip 0x04 prefix
        let mut out = [0u8; 20];
        out.copy_from_slice(&hash[12..]);
        out
    }

    fn random_nonce_hex() -> String {
        let mut buf = [0u8; 32];
        rand::rng().fill_bytes(&mut buf);
        format!("0x{}", hex::encode(buf))
    }

    fn keccak256(bytes: &[u8]) -> [u8; 32] {
        let mut h = sha3::Keccak256::new();
        h.update(bytes);
        let out = h.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        arr
    }

    fn type_hash(s: &str) -> [u8; 32] {
        keccak256(s.as_bytes())
    }

    fn hash_string(s: &str) -> [u8; 32] {
        keccak256(s.as_bytes())
    }

    fn abi_encode_words(words: &[[u8; 32]]) -> Vec<u8> {
        let mut out = Vec::with_capacity(words.len() * 32);
        for w in words {
            out.extend_from_slice(w);
        }
        out
    }

    fn word_address(addr: [u8; 20]) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&addr);
        w
    }

    fn word_u256_dec(dec: &str) -> anyhow::Result<[u8; 32]> {
        let mut out = [0u8; 32];
        u256_from_dec_str_into(dec, &mut out)?;
        Ok(out)
    }

    fn word_u256_u64(v: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..].copy_from_slice(&v.to_be_bytes());
        out
    }

    fn word_bytes32(hex_0x: &str) -> anyhow::Result<[u8; 32]> {
        let s = hex_0x.trim().strip_prefix("0x").unwrap_or(hex_0x.trim());
        let bytes = hex::decode(s).context("hex decode bytes32")?;
        if bytes.len() != 32 {
            anyhow::bail!("expected 32-byte value");
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    fn domain_separator(
        name: &str,
        version: &str,
        chain_id: u64,
        verifying_contract: [u8; 20],
    ) -> [u8; 32] {
        let words = [
            type_hash(EIP712_DOMAIN_TYPE),
            hash_string(name),
            hash_string(version),
            word_u256_u64(chain_id),
            word_address(verifying_contract),
        ];
        keccak256(&abi_encode_words(&words))
    }

    fn transfer_with_auth_hash(auth: &Eip3009Authorization) -> anyhow::Result<[u8; 32]> {
        let from = parse_address(&auth.from).context("authorization.from")?;
        let to = parse_address(&auth.to).context("authorization.to")?;
        let value = word_u256_dec(&auth.value).context("authorization.value")?;
        let valid_after = word_u256_dec(&auth.valid_after).context("authorization.validAfter")?;
        let valid_before =
            word_u256_dec(&auth.valid_before).context("authorization.validBefore")?;
        let nonce = word_bytes32(&auth.nonce).context("authorization.nonce")?;

        let words = [
            type_hash(TRANSFER_WITH_AUTH_TYPE),
            word_address(from),
            word_address(to),
            value,
            valid_after,
            valid_before,
            nonce,
        ];
        Ok(keccak256(&abi_encode_words(&words)))
    }

    fn eip3009_digest(
        name: &str,
        version: &str,
        chain_id: u64,
        verifying_contract: [u8; 20],
        auth: &Eip3009Authorization,
    ) -> anyhow::Result<[u8; 32]> {
        let ds = domain_separator(name, version, chain_id, verifying_contract);
        let sh = transfer_with_auth_hash(auth)?;
        let mut pre = Vec::with_capacity(2 + 32 + 32);
        pre.extend_from_slice(&[0x19, 0x01]);
        pre.extend_from_slice(&ds);
        pre.extend_from_slice(&sh);
        Ok(keccak256(&pre))
    }

    fn sign_digest(sk: &SecretKey, digest: [u8; 32]) -> anyhow::Result<String> {
        let secp = Secp256k1::new();
        let msg = Message::from_digest(digest);

        // Ethereum contracts typically only accept recovery IDs 0/1 (v=27/28). The
        // "x overflow" bit (recid 2/3) is vanishingly rare, but in case we ever hit it we
        // re-sign with additional noncedata until we get a compatible recovery ID.
        let (mut recid, mut compact) = {
            let mut tries = 0usize;
            loop {
                let sig = if tries == 0 {
                    secp.sign_ecdsa_recoverable(msg, sk)
                } else {
                    let mut noncedata = [0u8; 32];
                    rand::rng().fill_bytes(&mut noncedata);
                    secp.sign_ecdsa_recoverable_with_noncedata(msg, sk, &noncedata)
                };
                let (recid, compact) = sig.serialize_compact();
                let recid_i32: i32 = recid.into();
                if recid_i32 < 2 {
                    break (recid, compact);
                }
                tries += 1;
                if tries > 5 {
                    anyhow::bail!("unexpected recovery id {recid_i32} (wanted 0/1)");
                }
            }
        };

        // Ensure low-S to match common on-chain ECDSA libraries (e.g., OpenZeppelin ECDSA).
        let mut stdsig = Signature::from_compact(&compact).context("signature from compact")?;
        let before = compact;
        stdsig.normalize_s();
        compact = stdsig.serialize_compact();
        if compact != before {
            // Flipping `s` flips the parity bit of the recovery id.
            let recid_i32: i32 = recid.into();
            let flipped = recid_i32 ^ 1;
            recid = RecoveryId::try_from(flipped).context("flip recovery id")?;
        }

        let recid_i32: i32 = recid.into();
        if recid_i32 >= 2 {
            anyhow::bail!("unsupported recovery id after normalization: {recid_i32}");
        }
        let v: u8 = (recid_i32 as u8).saturating_add(27);
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&compact);
        out[64] = v;
        Ok(format!("0x{}", hex::encode(out)))
    }

    fn recover_address(digest: [u8; 32], signature_hex: &str) -> anyhow::Result<String> {
        let sig65 = parse_sig65(signature_hex)?;
        let (sig64, v) = sig65.split_at(64);
        let recid_i32 = match v[0] {
            0 | 1 => v[0] as i32,
            27 | 28 => (v[0] - 27) as i32,
            other => anyhow::bail!("unsupported recovery id: {other}"),
        };
        let recid = RecoveryId::try_from(recid_i32).context("recovery id")?;
        let sig = RecoverableSignature::from_compact(sig64, recid).context("recoverable sig")?;

        let secp = Secp256k1::new();
        let msg = Message::from_digest(digest);
        let pk = secp.recover_ecdsa(msg, &sig).context("recover pubkey")?;
        let addr = address_from_pubkey(&pk);
        Ok(format!("0x{}", hex::encode(addr)))
    }

    fn parse_sig65(sig_hex: &str) -> anyhow::Result<Vec<u8>> {
        let s = sig_hex.trim().strip_prefix("0x").unwrap_or(sig_hex.trim());
        let bytes = hex::decode(s).context("hex decode signature")?;
        if bytes.len() != 65 {
            anyhow::bail!("expected 65-byte signature");
        }
        Ok(bytes)
    }

    fn u256_from_dec_str_into(s: &str, out: &mut [u8; 32]) -> anyhow::Result<()> {
        let s = s.trim();
        if s.is_empty() {
            anyhow::bail!("empty number");
        }
        if s.starts_with('-') {
            anyhow::bail!("negative number");
        }
        *out = [0u8; 32];
        for ch in s.chars() {
            let d = ch.to_digit(10).context("non-decimal digit")? as u8;
            mul_small(out, 10)?;
            add_small(out, d)?;
        }
        Ok(())
    }

    fn mul_small(n: &mut [u8; 32], m: u8) -> anyhow::Result<()> {
        let mut carry: u16 = 0;
        for b in n.iter_mut().rev() {
            let v = (*b as u16) * (m as u16) + carry;
            *b = (v & 0xff) as u8;
            carry = v >> 8;
        }
        if carry != 0 {
            anyhow::bail!("u256 overflow");
        }
        Ok(())
    }

    fn add_small(n: &mut [u8; 32], a: u8) -> anyhow::Result<()> {
        let mut carry: u16 = a as u16;
        for b in n.iter_mut().rev() {
            if carry == 0 {
                break;
            }
            let v = (*b as u16) + carry;
            *b = (v & 0xff) as u8;
            carry = v >> 8;
        }
        if carry != 0 {
            anyhow::bail!("u256 overflow");
        }
        Ok(())
    }
}
