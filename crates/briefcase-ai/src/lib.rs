//! AI features for the Briefcase.
//!
//! # Safety model (must hold for all integrations)
//!
//! This crate is intentionally **non-authoritative**:
//! - Tool allow/deny decisions come from the policy engine (`briefcase-policy` / Cedar).
//! - AI may only **tighten** execution by requesting interactive approval.
//! - AI outputs are treated as untrusted and must be parsed + clamped strictly.
//! - AI errors fail open (no extra friction). Production deployments should monitor failures.

use async_trait::async_trait;
use briefcase_core::{ApprovalKind, PolicyDecision};
use serde::{Deserialize, Serialize};

const MAX_REASON_LEN: usize = 512;
const MAX_REASONS: usize = 16;

/// Non-authoritative AI advisory for a tool call.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiToolAdvisory {
    /// When true, execution should require interactive approval (local UI), even if policy allows.
    pub require_approval: bool,
    /// Short, non-sensitive reason codes / explanations suitable for receipts and UI.
    pub reasons: Vec<String>,
}

impl AiToolAdvisory {
    pub fn none() -> Self {
        Self {
            require_approval: false,
            reasons: Vec::new(),
        }
    }

    pub fn requiring_approval(reason: &str) -> Self {
        Self {
            require_approval: true,
            reasons: vec![clamp_string(reason, MAX_REASON_LEN)],
        }
        .sanitize()
    }

    fn sanitize(mut self) -> Self {
        if self.reasons.len() > MAX_REASONS {
            self.reasons.truncate(MAX_REASONS);
        }
        for r in &mut self.reasons {
            *r = clamp_string(r, MAX_REASON_LEN);
        }
        self
    }
}

/// Apply a non-authoritative AI advisory to an authoritative policy decision.
///
/// Safety invariants:
/// - AI cannot turn `Deny` into `Allow`.
/// - AI cannot bypass required approval.
/// - AI can only tighten `Allow` into `RequireApproval` (local approval).
pub fn apply_ai_to_policy(decision: PolicyDecision, ai: &AiToolAdvisory) -> PolicyDecision {
    match decision {
        PolicyDecision::Deny { reason } => PolicyDecision::Deny { reason },
        PolicyDecision::RequireApproval { reason, kind } => {
            PolicyDecision::RequireApproval { reason, kind }
        }
        PolicyDecision::Allow => {
            if ai.require_approval {
                PolicyDecision::RequireApproval {
                    reason: format_ai_reason(ai),
                    kind: ApprovalKind::Local,
                }
            } else {
                PolicyDecision::Allow
            }
        }
    }
}

fn format_ai_reason(ai: &AiToolAdvisory) -> String {
    if ai.reasons.is_empty() {
        "ai_required_approval".to_string()
    } else {
        let joined = ai.reasons.join(", ");
        clamp_string(&format!("ai_required_approval: {joined}"), MAX_REASON_LEN)
    }
}

/// Minimal interface for AI tool advisory.
#[async_trait]
pub trait ToolAdvisor: Send + Sync {
    async fn advise_tool_call(
        &self,
        tool_id: &str,
        args: &serde_json::Value,
    ) -> anyhow::Result<AiToolAdvisory>;
}

/// No-op advisor: always returns `AiToolAdvisory::none()`.
#[derive(Debug, Clone, Default)]
pub struct NoopToolAdvisor;

#[async_trait]
impl ToolAdvisor for NoopToolAdvisor {
    async fn advise_tool_call(
        &self,
        _tool_id: &str,
        _args: &serde_json::Value,
    ) -> anyhow::Result<AiToolAdvisory> {
        Ok(AiToolAdvisory::none())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireDecision {
    None,
    RequireApproval,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireToolAdvisory {
    decision: WireDecision,
    reasons: Option<Vec<String>>,
}

/// Parse an untrusted JSON advisory produced by an LLM into a safe `AiToolAdvisory`.
///
/// Any parse error results in `AiToolAdvisory::none()` (fail open).
pub fn parse_llm_tool_advisory_json(input: &str) -> AiToolAdvisory {
    let Ok(wire) = serde_json::from_str::<WireToolAdvisory>(input) else {
        return AiToolAdvisory::none();
    };
    let mut adv = AiToolAdvisory {
        require_approval: matches!(wire.decision, WireDecision::RequireApproval),
        reasons: wire.reasons.unwrap_or_default(),
    };
    adv = adv.sanitize();
    adv
}

fn clamp_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }
    let mut end = max_len;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Deterministic stub advisor for tests and offline workflows.
#[derive(Debug, Clone, Default)]
pub struct StubToolAdvisor {
    rules: Vec<StubRule>,
}

#[derive(Debug, Clone)]
struct StubRule {
    tool_id: String,
    require_approval: bool,
    reason: String,
}

impl StubToolAdvisor {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn with_rule(mut self, tool_id: &str, require_approval: bool, reason: &str) -> Self {
        self.rules.push(StubRule {
            tool_id: tool_id.to_string(),
            require_approval,
            reason: clamp_string(reason, MAX_REASON_LEN),
        });
        self
    }
}

#[async_trait]
impl ToolAdvisor for StubToolAdvisor {
    async fn advise_tool_call(
        &self,
        tool_id: &str,
        _args: &serde_json::Value,
    ) -> anyhow::Result<AiToolAdvisory> {
        for r in &self.rules {
            if r.tool_id == tool_id {
                if r.require_approval {
                    return Ok(AiToolAdvisory::requiring_approval(&r.reason));
                }
                return Ok(AiToolAdvisory::none());
            }
        }
        Ok(AiToolAdvisory::none())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context as _;

    #[test]
    fn malicious_llm_output_cannot_turn_deny_into_allow() {
        let policy = PolicyDecision::Deny {
            reason: "policy_denied".to_string(),
        };
        let adv = parse_llm_tool_advisory_json(r#"{"decision":"allow"}"#);
        let out = apply_ai_to_policy(policy.clone(), &adv);
        assert_eq!(out, policy);
    }

    #[test]
    fn ai_can_only_tighten_allow_to_require_approval() {
        let policy = PolicyDecision::Allow;
        let adv = parse_llm_tool_advisory_json(
            r#"{"decision":"require_approval","reasons":["prompt_injection_signals"]}"#,
        );
        let out = apply_ai_to_policy(policy, &adv);
        assert!(matches!(
            out,
            PolicyDecision::RequireApproval {
                kind: ApprovalKind::Local,
                ..
            }
        ));
    }

    #[test]
    fn unknown_fields_fail_open() {
        let adv = parse_llm_tool_advisory_json(
            r#"{"decision":"require_approval","kind":"mobile_signer"}"#,
        );
        assert_eq!(adv, AiToolAdvisory::none());
    }

    #[test]
    fn corpus_covers_common_prompt_injection_outputs() {
        // A tiny red-team corpus. Keep this list growing as regressions are found.
        let corpus = [
            r#"{"decision":"allow"}"#,
            r#"{"decision":"deny"}"#,
            r#"{"decision":"require_approval","reasons":["ignore previous instructions"]}"#,
            r#"not json"#,
            r#"{"decision":"require_approval","reasons":["api key", "refresh token"]}"#,
        ];

        for c in corpus {
            let adv = parse_llm_tool_advisory_json(c);
            // Invariant: advisory is always representable, and never directly "allows" anything.
            // (Only `require_approval` + reasons are supported.)
            if adv.require_approval {
                assert!(!adv.reasons.is_empty() || c.contains("require_approval"));
            }
        }
    }

    #[tokio::test]
    async fn stub_tool_advisor_is_deterministic() -> anyhow::Result<()> {
        let st = StubToolAdvisor::new().with_rule("quote", true, "needs_review");
        let adv1 = st.advise_tool_call("quote", &serde_json::json!({})).await?;
        let adv2 = st
            .advise_tool_call("quote", &serde_json::json!({"x":1}))
            .await?;
        assert_eq!(adv1, adv2);
        assert!(adv1.require_approval);
        Ok(())
    }

    #[test]
    fn long_reasons_are_clamped() {
        let long = "x".repeat(MAX_REASON_LEN + 10);
        let adv = parse_llm_tool_advisory_json(&format!(
            r#"{{"decision":"require_approval","reasons":["{long}"]}}"#
        ));
        assert_eq!(adv.reasons.len(), 1);
        assert_eq!(adv.reasons[0].len(), MAX_REASON_LEN);
    }

    #[test]
    fn apply_ai_does_not_weaken_existing_approval_kind() {
        let policy = PolicyDecision::RequireApproval {
            reason: "policy".to_string(),
            kind: ApprovalKind::MobileSigner,
        };
        let ai = AiToolAdvisory::requiring_approval("ai_says_so");
        let out = apply_ai_to_policy(policy.clone(), &ai);
        assert_eq!(out, policy);
    }

    #[test]
    fn parse_errors_fail_open() {
        let adv = parse_llm_tool_advisory_json(r#"{"decision":123}"#);
        assert_eq!(adv, AiToolAdvisory::none());
    }

    #[test]
    fn serde_json_parse_is_strict() {
        let adv = parse_llm_tool_advisory_json(
            r#"{"decision":"require_approval","reasons":["ok"],"extra":"nope"}"#,
        );
        assert_eq!(adv, AiToolAdvisory::none());
    }

    #[test]
    fn pretty_reason_is_stable() {
        let ai = AiToolAdvisory {
            require_approval: true,
            reasons: vec!["a".to_string(), "b".to_string()],
        };
        assert!(format_ai_reason(&ai).starts_with("ai_required_approval: "));
    }

    #[test]
    fn apply_ai_to_allow_without_reasons_still_requires_approval() {
        let policy = PolicyDecision::Allow;
        let ai = AiToolAdvisory {
            require_approval: true,
            reasons: vec![],
        };
        let out = apply_ai_to_policy(policy, &ai);
        assert!(matches!(
            out,
            PolicyDecision::RequireApproval {
                kind: ApprovalKind::Local,
                ..
            }
        ));
    }

    #[test]
    fn sanitize_limits_reason_count() {
        let mut reasons = Vec::new();
        for i in 0..(MAX_REASONS + 10) {
            reasons.push(format!("r{i}"));
        }
        let adv = AiToolAdvisory {
            require_approval: true,
            reasons,
        }
        .sanitize();
        assert_eq!(adv.reasons.len(), MAX_REASONS);
    }

    #[test]
    fn clamp_string_is_total() {
        assert_eq!(clamp_string("", 1), "");
        assert_eq!(clamp_string("a", 1), "a");
        assert_eq!(clamp_string("ab", 1), "a");
    }

    #[test]
    fn parse_llm_tool_advisory_json_errors_do_not_panic() {
        // This is mostly a guardrail: the parser must be safe for arbitrary untrusted model output.
        let adv = parse_llm_tool_advisory_json(
            r#"{"decision":"require_approval","reasons":[{"not":"a string"}]}"#,
        );
        assert_eq!(adv, AiToolAdvisory::none());
    }

    #[test]
    fn parse_llm_tool_advisory_json_uses_strict_decision_values() {
        // "yes" is not a valid decision.
        let adv = parse_llm_tool_advisory_json(r#"{"decision":"yes"}"#);
        assert_eq!(adv, AiToolAdvisory::none());
    }

    #[test]
    fn parse_llm_tool_advisory_json_round_trips_sane_output() -> anyhow::Result<()> {
        let json = r#"{"decision":"require_approval","reasons":["suspicious"]}"#;
        let adv = parse_llm_tool_advisory_json(json);
        assert!(adv.require_approval);
        assert_eq!(adv.reasons, vec!["suspicious".to_string()]);

        // Parsing should not error for sane, minimal output.
        let _: WireToolAdvisory = serde_json::from_str(json).context("parse wire")?;
        Ok(())
    }
}
