//! Revocation primitives for "portable briefcase" flows.
//!
//! v0.1 scope:
//! - Parse `BitstringStatusListEntry` from a JWT VC payload (best-effort).
//! - Parse a dereferenced `BitstringStatusListCredential` JSON document.
//! - Decode `credentialSubject.encodedList` (multibase base64url + gzip).
//! - Read status bits/values using the spec-defined MSB0 indexing.

use anyhow::{Context as _, Result};
use base64::Engine as _;
use flate2::read::GzDecoder;
use serde_json::Value;
use std::io::Read as _;
use url::Url;

pub const MULTIBASE_BASE64URL_NO_PAD_PREFIX: char = 'u';

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitstringStatusListEntry {
    pub status_purpose: String,
    pub status_list_index: usize,
    pub status_list_credential: Url,
}

impl BitstringStatusListEntry {
    /// Parse a `BitstringStatusListEntry` from a JWT payload.
    ///
    /// This is best-effort and does not verify the JWT signature; callers must treat
    /// the returned fields as untrusted until the VC itself has been verified by a
    /// trusted verifier (typically the provider).
    pub fn parse_from_vc_jwt(vc_jwt: &str) -> Result<Option<Self>> {
        let Some(payload) = decode_jwt_payload_json(vc_jwt)? else {
            return Ok(None);
        };

        let status = payload
            .get("credentialStatus")
            .or_else(|| payload.get("vc").and_then(|vc| vc.get("credentialStatus")));
        let Some(status) = status else {
            return Ok(None);
        };

        let status = match status {
            Value::Array(v) => v.first().context("credentialStatus array is empty")?,
            Value::Object(_) => status,
            _ => anyhow::bail!("credentialStatus must be an object or array"),
        };

        let ty = status
            .get("type")
            .and_then(|v| v.as_str())
            .context("credentialStatus.type missing")?;
        if ty != "BitstringStatusListEntry" {
            return Ok(None);
        }

        let status_purpose = status
            .get("statusPurpose")
            .and_then(|v| v.as_str())
            .context("credentialStatus.statusPurpose missing")?
            .to_string();

        let status_list_index = status
            .get("statusListIndex")
            .and_then(|v| v.as_str())
            .context("credentialStatus.statusListIndex missing")?
            .parse::<usize>()
            .context("parse credentialStatus.statusListIndex")?;

        let status_list_credential = status
            .get("statusListCredential")
            .and_then(|v| v.as_str())
            .context("credentialStatus.statusListCredential missing")?;
        let status_list_credential =
            Url::parse(status_list_credential).context("parse statusListCredential url")?;

        Ok(Some(Self {
            status_purpose,
            status_list_index,
            status_list_credential,
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitstringStatusListCredential {
    pub encoded_list: String,
    pub status_purpose: String,
    pub status_size: usize,
    pub ttl_ms: Option<u64>,
}

impl BitstringStatusListCredential {
    pub fn parse_from_json(doc: &Value) -> Result<Self> {
        let subj = doc
            .get("credentialSubject")
            .context("credentialSubject missing")?;
        let subj = subj
            .as_object()
            .context("credentialSubject must be an object")?;

        let encoded_list = subj
            .get("encodedList")
            .and_then(|v| v.as_str())
            .context("credentialSubject.encodedList missing")?
            .to_string();

        let status_purpose = subj
            .get("statusPurpose")
            .and_then(|v| v.as_str())
            .context("credentialSubject.statusPurpose missing")?
            .to_string();

        let status_size = subj.get("statusSize").and_then(|v| v.as_u64()).unwrap_or(1);
        let status_size = usize::try_from(status_size).context("statusSize overflows usize")?;
        if status_size == 0 || status_size > 64 {
            anyhow::bail!("unsupported statusSize: {status_size}");
        }

        let ttl_ms = subj.get("ttl").and_then(|v| v.as_u64());

        Ok(Self {
            encoded_list,
            status_purpose,
            status_size,
            ttl_ms,
        })
    }
}

pub fn decode_jwt_payload_json(jwt: &str) -> Result<Option<Value>> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Ok(None);
    }
    let payload_b64 = parts[1];
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .context("base64url decode jwt payload")?;
    let v: Value = serde_json::from_slice(&payload_bytes).context("parse jwt payload json")?;
    Ok(Some(v))
}

pub fn decode_encoded_list_multibase_gzip(encoded_list: &str) -> Result<Vec<u8>> {
    let mut chars = encoded_list.chars();
    let prefix = chars
        .next()
        .context("encodedList missing multibase prefix")?;
    if prefix != MULTIBASE_BASE64URL_NO_PAD_PREFIX {
        anyhow::bail!("unsupported multibase prefix: {prefix}");
    }
    let b64 = chars.as_str();
    let gz = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .context("base64url decode encodedList")?;

    let mut decoder = GzDecoder::new(gz.as_slice());
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .context("gzip decode encodedList")?;
    Ok(out)
}

/// Read a status value from a MSB0 bitstring.
///
/// Spec rule: index 0 is the left-most bit (MSB) of the first byte.
pub fn read_status_value_msb0(bitstring: &[u8], index: usize, status_size: usize) -> Result<u64> {
    if status_size == 0 || status_size > 64 {
        anyhow::bail!("unsupported status_size: {status_size}");
    }

    let start_bit = index
        .checked_mul(status_size)
        .context("status index overflow")?;
    let end_bit = start_bit
        .checked_add(status_size)
        .context("status index overflow")?;
    let total_bits = bitstring.len().saturating_mul(8);
    if end_bit > total_bits {
        anyhow::bail!("status index out of range");
    }

    let mut v: u64 = 0;
    for i in 0..status_size {
        let bit = get_bit_msb0(bitstring, start_bit + i)?;
        v = (v << 1) | u64::from(bit);
    }
    Ok(v)
}

fn get_bit_msb0(bitstring: &[u8], bit_index: usize) -> Result<u8> {
    let byte_idx = bit_index / 8;
    let bit_in_byte = bit_index % 8;
    let b = *bitstring.get(byte_idx).context("bit index out of range")?;
    Ok((b >> (7 - bit_in_byte)) & 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use pretty_assertions::assert_eq;
    use std::io::Write as _;

    #[test]
    fn msb0_bit_order_matches_spec_text() -> Result<()> {
        // Byte: 1010_0000
        let bs = [0b1010_0000u8];
        assert_eq!(read_status_value_msb0(&bs, 0, 1)?, 1);
        assert_eq!(read_status_value_msb0(&bs, 1, 1)?, 0);
        assert_eq!(read_status_value_msb0(&bs, 2, 1)?, 1);
        assert_eq!(read_status_value_msb0(&bs, 3, 1)?, 0);
        Ok(())
    }

    #[test]
    fn encoded_list_round_trips_gzip_and_base64url() -> Result<()> {
        let raw = vec![0u8, 1u8, 2u8, 3u8, 254u8, 255u8];

        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&raw)?;
        let gz = enc.finish()?;

        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(gz);
        let encoded = format!("{}{}", MULTIBASE_BASE64URL_NO_PAD_PREFIX, b64);

        let out = decode_encoded_list_multibase_gzip(&encoded)?;
        assert_eq!(out, raw);
        Ok(())
    }
}
