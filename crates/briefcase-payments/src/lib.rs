//! Payment rails and adapters.
//!
//! Design goals:
//! - Keep the LLM untrusted: payment proofs / preimages never flow through the agent runtime.
//! - Make "how to pay" pluggable: the default backend is a demo HTTP flow; production deployments
//!   can delegate payment to an external helper program.

use std::collections::HashMap;
use std::process::Stdio;
use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "rail", rename_all = "snake_case")]
pub enum PaymentChallenge {
    X402 {
        payment_id: String,
        payment_url: String,
        amount_microusd: i64,
    },
    L402 {
        invoice: String,
        macaroon: String,
        amount_microusd: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentProof {
    X402 { proof: String },
    L402 { macaroon: String, preimage: String },
}

pub fn format_www_authenticate(challenge: &PaymentChallenge) -> String {
    match challenge {
        PaymentChallenge::X402 {
            payment_id,
            payment_url,
            amount_microusd,
        } => format!(
            "X402 payment_id=\"{payment_id}\", payment_url=\"{payment_url}\", amount_microusd={amount_microusd}"
        ),
        PaymentChallenge::L402 {
            invoice,
            macaroon,
            amount_microusd,
        } => format!(
            "L402 invoice=\"{invoice}\", macaroon=\"{macaroon}\", amount_microusd={amount_microusd}"
        ),
    }
}

pub fn parse_www_authenticate(value: &str) -> anyhow::Result<PaymentChallenge> {
    let v = value.trim();
    let (scheme, rest) = v.split_once(' ').context("missing auth scheme")?;
    let params = parse_kv_params(rest);

    match scheme {
        s if s.eq_ignore_ascii_case("x402") => Ok(PaymentChallenge::X402 {
            payment_id: params
                .get("payment_id")
                .cloned()
                .context("missing payment_id")?,
            payment_url: params
                .get("payment_url")
                .cloned()
                .context("missing payment_url")?,
            amount_microusd: params
                .get("amount_microusd")
                .context("missing amount_microusd")?
                .parse()
                .context("parse amount_microusd")?,
        }),
        s if s.eq_ignore_ascii_case("l402") => Ok(PaymentChallenge::L402 {
            invoice: params.get("invoice").cloned().context("missing invoice")?,
            macaroon: params
                .get("macaroon")
                .cloned()
                .context("missing macaroon")?,
            amount_microusd: params
                .get("amount_microusd")
                .context("missing amount_microusd")?
                .parse()
                .context("parse amount_microusd")?,
        }),
        other => anyhow::bail!("unsupported www-authenticate scheme: {other}"),
    }
}

fn parse_kv_params(s: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for part in s.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let Some((k, v)) = p.split_once('=') else {
            continue;
        };
        let key = k.trim().to_string();
        let mut val = v.trim().to_string();
        if val.starts_with('"') && val.ends_with('"') && val.len() >= 2 {
            val = val[1..val.len() - 1].to_string();
        }
        out.insert(key, val);
    }
    out
}

#[async_trait]
pub trait PaymentBackend: Send + Sync {
    async fn pay(
        &self,
        provider_base_url: &Url,
        challenge: PaymentChallenge,
    ) -> anyhow::Result<PaymentProof>;
}

#[derive(Clone)]
pub struct HttpDemoPaymentBackend {
    http: reqwest::Client,
}

impl HttpDemoPaymentBackend {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(20))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .context("build reqwest client")?,
        })
    }

    fn same_origin(a: &Url, b: &Url) -> bool {
        a.scheme() == b.scheme()
            && a.host_str() == b.host_str()
            && a.port_or_known_default() == b.port_or_known_default()
    }

    fn resolve_payment_url(
        &self,
        provider_base_url: &Url,
        payment_url: &str,
    ) -> anyhow::Result<Url> {
        if payment_url.starts_with("http://") || payment_url.starts_with("https://") {
            let u = Url::parse(payment_url).context("parse payment_url")?;
            if !Self::same_origin(provider_base_url, &u) {
                anyhow::bail!("payment_url not same-origin as provider_base_url");
            }
            return Ok(u);
        }

        provider_base_url
            .join(payment_url)
            .context("join relative payment_url")
    }
}

#[derive(Debug, Serialize)]
struct X402PayRequest<'a> {
    payment_id: &'a str,
}

#[derive(Debug, Deserialize)]
struct X402PayResponse {
    proof: String,
}

#[derive(Debug, Serialize)]
struct L402PayRequest<'a> {
    invoice: &'a str,
}

#[derive(Debug, Deserialize)]
struct L402PayResponse {
    preimage: String,
}

#[async_trait]
impl PaymentBackend for HttpDemoPaymentBackend {
    async fn pay(
        &self,
        provider_base_url: &Url,
        challenge: PaymentChallenge,
    ) -> anyhow::Result<PaymentProof> {
        match challenge {
            PaymentChallenge::X402 {
                payment_id,
                payment_url,
                ..
            } => {
                let url = self.resolve_payment_url(provider_base_url, &payment_url)?;
                let resp = self
                    .http
                    .post(url)
                    .json(&X402PayRequest {
                        payment_id: &payment_id,
                    })
                    .send()
                    .await
                    .context("x402 payment request")?;
                if !resp.status().is_success() {
                    anyhow::bail!("x402 payment failed: {}", resp.status());
                }
                let pr = resp
                    .json::<X402PayResponse>()
                    .await
                    .context("parse x402 pay response")?;
                Ok(PaymentProof::X402 { proof: pr.proof })
            }
            PaymentChallenge::L402 {
                invoice, macaroon, ..
            } => {
                let url = provider_base_url
                    .join("/l402/pay")
                    .context("join /l402/pay")?;
                let resp = self
                    .http
                    .post(url)
                    .json(&L402PayRequest { invoice: &invoice })
                    .send()
                    .await
                    .context("l402 payment request")?;
                if !resp.status().is_success() {
                    anyhow::bail!("l402 payment failed: {}", resp.status());
                }
                let pr = resp
                    .json::<L402PayResponse>()
                    .await
                    .context("parse l402 pay response")?;
                Ok(PaymentProof::L402 {
                    macaroon,
                    preimage: pr.preimage,
                })
            }
        }
    }
}

#[derive(Clone)]
pub struct CommandPaymentBackend {
    program: String,
    args: Vec<String>,
    timeout: Duration,
}

impl CommandPaymentBackend {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "rail", rename_all = "snake_case")]
enum PaymentHelperRequest {
    X402 {
        provider_base_url: String,
        payment_id: String,
        payment_url: String,
        amount_microusd: i64,
    },
    L402 {
        provider_base_url: String,
        invoice: String,
        macaroon: String,
        amount_microusd: i64,
    },
}

impl PaymentHelperRequest {
    fn from_challenge(provider_base_url: &Url, ch: PaymentChallenge) -> Self {
        match ch {
            PaymentChallenge::X402 {
                payment_id,
                payment_url,
                amount_microusd,
            } => Self::X402 {
                provider_base_url: provider_base_url.to_string(),
                payment_id,
                payment_url,
                amount_microusd,
            },
            PaymentChallenge::L402 {
                invoice,
                macaroon,
                amount_microusd,
            } => Self::L402 {
                provider_base_url: provider_base_url.to_string(),
                invoice,
                macaroon,
                amount_microusd,
            },
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "rail", rename_all = "snake_case")]
enum PaymentHelperResponse {
    X402 { proof: String },
    L402 { preimage: String },
}

#[async_trait]
impl PaymentBackend for CommandPaymentBackend {
    async fn pay(
        &self,
        provider_base_url: &Url,
        challenge: PaymentChallenge,
    ) -> anyhow::Result<PaymentProof> {
        let req = PaymentHelperRequest::from_challenge(provider_base_url, challenge.clone());
        let input = serde_json::to_vec(&req).context("encode payment helper request")?;

        let mut cmd = tokio::process::Command::new(&self.program);
        cmd.args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().context("spawn payment helper")?;
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt as _;
            stdin
                .write_all(&input)
                .await
                .context("write payment helper stdin")?;
        }

        let out = tokio::time::timeout(self.timeout, child.wait_with_output())
            .await
            .context("payment helper timeout")?
            .context("wait payment helper")?;

        if !out.status.success() {
            // Avoid accidentally leaking sensitive material (preimages, proofs) via logs.
            anyhow::bail!("payment helper failed with status {}", out.status);
        }

        let resp: PaymentHelperResponse =
            serde_json::from_slice(&out.stdout).context("decode payment helper response")?;

        match (challenge, resp) {
            (PaymentChallenge::X402 { .. }, PaymentHelperResponse::X402 { proof }) => {
                Ok(PaymentProof::X402 { proof })
            }
            (PaymentChallenge::L402 { macaroon, .. }, PaymentHelperResponse::L402 { preimage }) => {
                Ok(PaymentProof::L402 { macaroon, preimage })
            }
            (PaymentChallenge::X402 { .. }, PaymentHelperResponse::L402 { .. })
            | (PaymentChallenge::L402 { .. }, PaymentHelperResponse::X402 { .. }) => {
                anyhow::bail!("payment helper rail mismatch")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn www_auth_round_trip_x402() {
        let ch = PaymentChallenge::X402 {
            payment_id: "p1".to_string(),
            payment_url: "/pay".to_string(),
            amount_microusd: 2000,
        };
        let h = format_www_authenticate(&ch);
        let parsed = parse_www_authenticate(&h).unwrap();
        assert_eq!(parsed, ch);
    }

    #[test]
    fn www_auth_round_trip_l402() {
        let ch = PaymentChallenge::L402 {
            invoice: "lnbc_demo".to_string(),
            macaroon: "mac".to_string(),
            amount_microusd: 123,
        };
        let h = format_www_authenticate(&ch);
        let parsed = parse_www_authenticate(&h).unwrap();
        assert_eq!(parsed, ch);
    }
}
