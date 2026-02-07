use anyhow::Context as _;
use axum::Json;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use briefcase_ai::CopilotApprovalSummaryInput;
use briefcase_api::types::{
    ErrorResponse, PolicyApplyResponse, PolicyCompileRequest, PolicyCompileResponse,
    PolicyDiffLine, PolicyDiffOp, PolicyGetResponse, PolicyProposal,
};
use briefcase_core::{ApprovalKind, ApprovalRequest, util::sha256_hex};
use briefcase_policy::{CedarPolicyEngine, CedarPolicyEngineOptions};
use chrono::Utc;
use similar::{ChangeTag, TextDiff};
use uuid::Uuid;

use crate::app::AppState;

const POLICY_APPROVAL_TOOL_ID: &str = "policy.apply";

pub async fn policy_get(
    State(state): State<AppState>,
) -> Result<Json<PolicyGetResponse>, (StatusCode, Json<ErrorResponse>)> {
    let rec = state
        .db
        .policy()
        .await
        .map_err(internal_error)?
        .ok_or_else(|| internal_error(anyhow::anyhow!("missing policy record")))?;

    Ok(Json(PolicyGetResponse {
        policy_text: rec.policy_text,
        policy_hash_hex: rec.policy_hash_hex,
        updated_at_rfc3339: rec.updated_at.to_rfc3339(),
    }))
}

pub async fn policy_compile(
    State(state): State<AppState>,
    Json(req): Json<PolicyCompileRequest>,
) -> Result<Json<PolicyCompileResponse>, (StatusCode, Json<ErrorResponse>)> {
    let prompt = req.prompt.trim().to_string();
    if prompt.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: "invalid_prompt".to_string(),
                message: "prompt is empty".to_string(),
            }),
        ));
    }

    let cur = state
        .db
        .policy()
        .await
        .map_err(internal_error)?
        .ok_or_else(|| internal_error(anyhow::anyhow!("missing policy record")))?;

    let proposed_policy_text = match compile_stub(&prompt) {
        Ok(v) => v,
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    code: "compile_failed".to_string(),
                    message: format!("{e:#}"),
                }),
            ));
        }
    };

    // Validate Cedar parses before accepting the proposal.
    CedarPolicyEngine::new(CedarPolicyEngineOptions {
        policy_text: proposed_policy_text.clone(),
    })
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: "invalid_cedar".to_string(),
                message: format!("{e}"),
            }),
        )
    })?;

    let base_hash = cur.policy_hash_hex.clone();
    let proposed_hash = sha256_hex(proposed_policy_text.as_bytes());
    let diff = diff_lines(&cur.policy_text, &proposed_policy_text);
    let diff_json = serde_json::to_string(&diff)
        .context("serialize diff")
        .map_err(internal_error)?;

    let proposal_rec = state
        .db
        .create_policy_proposal(
            &prompt,
            &base_hash,
            &proposed_policy_text,
            &proposed_hash,
            &diff_json,
        )
        .await
        .map_err(internal_error)?;

    let proposal = PolicyProposal {
        id: proposal_rec.id,
        created_at_rfc3339: proposal_rec.created_at.to_rfc3339(),
        expires_at_rfc3339: proposal_rec.expires_at.to_rfc3339(),
        prompt: proposal_rec.prompt,
        base_policy_hash_hex: proposal_rec.base_policy_hash_hex,
        proposed_policy_hash_hex: proposal_rec.proposed_policy_hash_hex,
        diff,
        proposed_policy_text: proposal_rec.proposed_policy_text,
    };

    Ok(Json(PolicyCompileResponse { proposal }))
}

pub async fn policy_apply(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
) -> Result<Json<PolicyApplyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let Some(mut proposal) = state.db.policy_proposal(id).await.map_err(internal_error)? else {
        return Ok(Json(PolicyApplyResponse::Denied {
            reason: "proposal_not_found".to_string(),
        }));
    };

    let cur = state
        .db
        .policy()
        .await
        .map_err(internal_error)?
        .ok_or_else(|| internal_error(anyhow::anyhow!("missing policy record")))?;
    if cur.policy_hash_hex != proposal.base_policy_hash_hex {
        return Ok(Json(PolicyApplyResponse::Denied {
            reason: "stale_proposal".to_string(),
        }));
    }

    let approval_args = serde_json::json!({
        "proposal_id": proposal.id,
        "base_policy_hash_hex": proposal.base_policy_hash_hex,
        "proposed_policy_hash_hex": proposal.proposed_policy_hash_hex,
    });

    // If an approval exists and has been satisfied, apply the policy.
    if let Some(approval_id) = proposal.approval_id {
        if state
            .db
            .is_approval_valid_for_call(approval_id, POLICY_APPROVAL_TOOL_ID, &approval_args)
            .await
            .map_err(internal_error)?
        {
            return apply_approved_policy(&state, proposal).await;
        }

        // If the approval is still pending, return it.
        if let Some(pending) = find_pending_approval(&state, approval_id).await? {
            return Ok(Json(PolicyApplyResponse::ApprovalRequired {
                approval: pending,
            }));
        }
    }

    // Create (or recreate) an approval request and store its ID on the proposal.
    let diff: Vec<PolicyDiffLine> =
        serde_json::from_str(&proposal.diff_json).unwrap_or_else(|_| Vec::new());
    let (diff_preview, truncated) = diff_preview(&diff, 120);
    let copilot_summary =
        briefcase_ai::copilot_summary_for_approval(&CopilotApprovalSummaryInput {
            tool_id: POLICY_APPROVAL_TOOL_ID.to_string(),
            category: "admin".to_string(),
            reason: "policy change requires confirmation".to_string(),
            approval_kind: "local".to_string(),
            net_access: false,
            fs_access: false,
            estimated_cost_usd: None,
        });
    let summary = serde_json::json!({
        "kind": "policy_apply",
        "proposal_id": proposal.id,
        "prompt": proposal.prompt,
        "base_policy_hash_hex": proposal.base_policy_hash_hex,
        "proposed_policy_hash_hex": proposal.proposed_policy_hash_hex,
        "diff_preview": diff_preview,
        "diff_truncated": truncated,
        "copilot_summary": copilot_summary,
    });

    let approval = state
        .db
        .create_approval_with_summary(
            POLICY_APPROVAL_TOOL_ID,
            "policy change requires confirmation",
            ApprovalKind::Local,
            &approval_args,
            Some(summary),
        )
        .await
        .map_err(internal_error)?;

    state
        .db
        .set_policy_proposal_approval_id(proposal.id, approval.id)
        .await
        .map_err(internal_error)?;
    proposal.approval_id = Some(approval.id);

    Ok(Json(PolicyApplyResponse::ApprovalRequired { approval }))
}

async fn apply_approved_policy(
    state: &AppState,
    proposal: crate::db::PolicyProposalRecord,
) -> Result<Json<PolicyApplyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let engine = CedarPolicyEngine::new(CedarPolicyEngineOptions {
        policy_text: proposal.proposed_policy_text.clone(),
    })
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: "invalid_cedar".to_string(),
                message: format!("{e}"),
            }),
        )
    })?;

    let rec = state
        .db
        .upsert_policy(&proposal.proposed_policy_text)
        .await
        .map_err(internal_error)?;

    *state.policy.write().await = std::sync::Arc::new(engine);

    let ts = Utc::now().to_rfc3339();
    let _ = state
        .receipts
        .append(serde_json::json!({
            "kind": "policy_update",
            "proposal_id": proposal.id,
            "base_policy_hash_hex": proposal.base_policy_hash_hex,
            "proposed_policy_hash_hex": proposal.proposed_policy_hash_hex,
            "policy_hash_hex": rec.policy_hash_hex,
            "approval_id": proposal.approval_id,
            "ts": ts,
        }))
        .await;

    state
        .db
        .delete_policy_proposal(proposal.id)
        .await
        .map_err(internal_error)?;

    Ok(Json(PolicyApplyResponse::Applied {
        policy_hash_hex: rec.policy_hash_hex,
        updated_at_rfc3339: rec.updated_at.to_rfc3339(),
    }))
}

async fn find_pending_approval(
    state: &AppState,
    id: Uuid,
) -> Result<Option<ApprovalRequest>, (StatusCode, Json<ErrorResponse>)> {
    let approvals = state.db.list_approvals().await.map_err(internal_error)?;
    Ok(approvals.into_iter().find(|a| a.id == id))
}

fn diff_preview(diff: &[PolicyDiffLine], max_lines: usize) -> (Vec<PolicyDiffLine>, bool) {
    if diff.len() <= max_lines {
        return (diff.to_vec(), false);
    }
    (diff[..max_lines].to_vec(), true)
}

fn diff_lines(old: &str, new: &str) -> Vec<PolicyDiffLine> {
    let diff = TextDiff::from_lines(old, new);
    diff.iter_all_changes()
        .map(|c| {
            let op = match c.tag() {
                ChangeTag::Equal => PolicyDiffOp::Context,
                ChangeTag::Insert => PolicyDiffOp::Add,
                ChangeTag::Delete => PolicyDiffOp::Remove,
            };
            let text = c.value().trim_end_matches('\n').to_string();
            PolicyDiffLine { op, text }
        })
        .collect()
}

fn compile_stub(prompt: &str) -> anyhow::Result<String> {
    let p = prompt.trim();
    if p.starts_with("cedar:") {
        return Ok(p.trim_start_matches("cedar:").trim().to_string());
    }
    if p.eq_ignore_ascii_case("default") || p.eq_ignore_ascii_case("reset") {
        return Ok(CedarPolicyEngineOptions::default_policies().policy_text);
    }
    if p.to_ascii_lowercase().contains("strict") {
        return Ok(strict_policy_text());
    }
    if p.to_ascii_lowercase().contains("relaxed") {
        return Ok(relaxed_policy_text());
    }

    anyhow::bail!("unsupported prompt (try: default | strict | relaxed | cedar:<cedar>)")
}

fn strict_policy_text() -> String {
    r#"
// Strict: all tool calls require approval (no CallWithoutApproval permits).
permit(principal, action == Action::"Call", resource)
when { resource.category != "admin" };

forbid(principal, action == Action::"Call", resource)
when { resource.category == "admin" };

// Allow calls without a mobile signer unless this is a "high risk write".
permit(principal, action == Action::"CallWithoutSigner", resource)
when {
  !(resource.is_write && (resource.net_access || resource.fs_access))
};
"#
    .trim()
    .to_string()
}

fn relaxed_policy_text() -> String {
    r#"
// Relaxed: raise the no-approval budget for read tools.
permit(principal, action == Action::"Call", resource)
when { resource.category != "admin" };

forbid(principal, action == Action::"Call", resource)
when { resource.category == "admin" };

permit(principal, action == Action::"CallWithoutApproval", resource)
when {
  resource.category == "read" &&
  resource.cost_microusd <= 1000000
};

permit(principal, action == Action::"CallWithoutSigner", resource)
when {
  !(resource.is_write && (resource.net_access || resource.fs_access))
};
"#
    .trim()
    .to_string()
}

fn internal_error(e: anyhow::Error) -> (StatusCode, Json<ErrorResponse>) {
    tracing::error!(error = %e, "policy endpoint failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            code: "internal_error".to_string(),
            message: "internal error".to_string(),
        }),
    )
}
