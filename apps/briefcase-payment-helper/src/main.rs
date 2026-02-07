use std::io::{Read as _, Write as _};
use std::path::PathBuf;

use anyhow::Context as _;
use briefcase_payments::helper_protocol::{PaymentHelperRequest, PaymentHelperResponse};
use clap::Parser;
use secp256k1::SecretKey;

#[derive(Debug, Parser)]
#[command(
    name = "briefcase-payment-helper",
    version,
    about = "External wallet/payment helper"
)]
struct Args {
    /// EVM private key as hex (32 bytes, with or without 0x prefix).
    ///
    /// WARNING: passing secrets via environment variables is convenient but not ideal for
    /// production deployments. Prefer a file-based secret reference and lock down permissions.
    #[arg(long, env = "BRIEFCASE_X402_EVM_PRIVATE_KEY_HEX")]
    evm_private_key_hex: Option<String>,

    /// Read EVM private key from a file (hex, with or without 0x prefix).
    #[arg(long, env = "BRIEFCASE_X402_EVM_PRIVATE_KEY_FILE")]
    evm_private_key_file: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .context("read stdin")?;
    if input.len() > 1024 * 1024 {
        anyhow::bail!("request too large");
    }

    let req: PaymentHelperRequest =
        serde_json::from_slice(&input).context("decode PaymentHelperRequest")?;

    let resp = handle_request(&args, req)?;
    let out = serde_json::to_vec(&resp).context("encode PaymentHelperResponse")?;
    std::io::stdout().write_all(&out).context("write stdout")?;
    Ok(())
}

fn handle_request(args: &Args, req: PaymentHelperRequest) -> anyhow::Result<PaymentHelperResponse> {
    match req {
        PaymentHelperRequest::X402V2 {
            payment_required, ..
        } => {
            let sk = load_evm_secret_key(args)?;
            let b64 = briefcase_payments::x402::evm::payment_signature_b64_for_eip3009(
                &sk,
                &payment_required,
            )?;
            Ok(PaymentHelperResponse::X402V2 {
                payment_signature_b64: b64,
            })
        }
        PaymentHelperRequest::X402 { .. } => {
            anyhow::bail!("legacy x402 is not supported by this helper (use daemon demo backend)")
        }
        PaymentHelperRequest::L402 { .. } => anyhow::bail!("l402 is not supported by this helper"),
    }
}

fn load_evm_secret_key(args: &Args) -> anyhow::Result<SecretKey> {
    let raw = if let Some(v) = args.evm_private_key_hex.as_deref() {
        v.to_string()
    } else if let Some(p) = &args.evm_private_key_file {
        std::fs::read_to_string(p).with_context(|| format!("read key file {}", p.display()))?
    } else {
        anyhow::bail!(
            "missing EVM key: set BRIEFCASE_X402_EVM_PRIVATE_KEY_HEX or BRIEFCASE_X402_EVM_PRIVATE_KEY_FILE"
        )
    };

    let s = raw.trim().strip_prefix("0x").unwrap_or(raw.trim());
    let bytes = hex::decode(s).context("hex decode evm private key")?;
    if bytes.len() != 32 {
        anyhow::bail!("expected 32-byte EVM private key");
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    SecretKey::from_byte_array(arr).context("parse secp256k1 secret key")
}
