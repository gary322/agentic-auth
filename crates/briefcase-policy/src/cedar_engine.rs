use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use anyhow::Context as _;
use briefcase_core::{PolicyDecision, ToolCategory, ToolSpec};
use cedar_policy::{
    Authorizer, Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, PolicySet, Request,
    RestrictedExpression,
};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct CedarPolicyEngineOptions {
    /// Cedar policies as a single string.
    pub policy_text: String,
}

impl CedarPolicyEngineOptions {
    pub fn default_policies() -> Self {
        // NOTE: Cedar has only allow/deny. We encode "approval required" by evaluating
        // a stricter action (CallWithoutApproval). If Call is permitted but
        // CallWithoutApproval is forbidden, the caller must obtain approval.
        //
        // Defaults:
        // - allow calling all tools except category=="admin"
        // - require approval for write tools OR cost > $0.01
        Self {
            policy_text: r#"
// Allow calling any non-admin tool.
permit(principal, action == Action::"Call", resource)
when { resource.category != "admin" };

// Forbid all admin tools.
forbid(principal, action == Action::"Call", resource)
when { resource.category == "admin" };

// Allow calls without approval only for cheap read tools.
permit(principal, action == Action::"CallWithoutApproval", resource)
when {
  resource.category == "read" &&
  resource.cost_microusd <= 10000
};
"#
            .to_string(),
        }
    }
}

#[derive(Debug)]
pub struct CedarPolicyEngine {
    authorizer: Authorizer,
    policies: PolicySet,
}

#[derive(Debug, Error)]
pub enum CedarPolicyEngineError {
    #[error("invalid cedar policy: {0}")]
    Policy(Box<cedar_policy::ParseErrors>),
    #[error("cedar evaluation error: {0}")]
    Eval(String),
    #[error("other error: {0}")]
    Other(#[from] anyhow::Error),
}

impl From<cedar_policy::ParseErrors> for CedarPolicyEngineError {
    fn from(value: cedar_policy::ParseErrors) -> Self {
        Self::Policy(Box::new(value))
    }
}

impl CedarPolicyEngine {
    pub fn new(opts: CedarPolicyEngineOptions) -> Result<Self, CedarPolicyEngineError> {
        let policies = PolicySet::from_str(&opts.policy_text)?;
        Ok(Self {
            authorizer: Authorizer::new(),
            policies,
        })
    }

    pub fn decide(
        &self,
        principal: &str,
        tool: &ToolSpec,
    ) -> Result<PolicyDecision, CedarPolicyEngineError> {
        let entities = Entities::from_entities([tool_entity(tool)?], None)
            .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?;

        let principal = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("User")
                .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?,
            EntityId::from_str(principal)
                .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?,
        );
        let resource = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Tool")
                .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?,
            EntityId::from_str(&tool.id)
                .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?,
        );

        let ctx = Context::empty();

        let call = make_request(principal.clone(), resource.clone(), "Call", ctx.clone())?;
        let call_decision = self
            .authorizer
            .is_authorized(&call, &self.policies, &entities);
        if call_decision.decision() == cedar_policy::Decision::Deny {
            return Ok(PolicyDecision::Deny {
                reason: "policy denied tool call".to_string(),
            });
        }

        let call_wo_approval = make_request(principal, resource, "CallWithoutApproval", ctx)?;
        let wo_decision =
            self.authorizer
                .is_authorized(&call_wo_approval, &self.policies, &entities);

        if wo_decision.decision() == cedar_policy::Decision::Allow {
            return Ok(PolicyDecision::Allow);
        }

        Ok(PolicyDecision::RequireApproval {
            reason: "tool call requires approval".to_string(),
        })
    }
}

fn make_request(
    principal: EntityUid,
    resource: EntityUid,
    action_id: &str,
    ctx: Context,
) -> Result<Request, CedarPolicyEngineError> {
    let action = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("Action")
            .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?,
        EntityId::from_str(action_id)
            .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?,
    );

    Request::new(principal, action, resource, ctx, None)
        .map_err(|e| CedarPolicyEngineError::Eval(format!("{e}")))
}

fn tool_entity(tool: &ToolSpec) -> Result<Entity, CedarPolicyEngineError> {
    // Cedar numeric type is Long. Use micro-USD as integer to avoid floats.
    let cost_microusd: i64 = (tool.cost.estimated_usd * 1_000_000.0).round() as i64;

    let mut attrs = HashMap::new();
    attrs.insert(
        "category".to_string(),
        RestrictedExpression::from_str(&format!("\"{}\"", tool.category.as_str()))
            .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?,
    );
    attrs.insert(
        "cost_microusd".to_string(),
        RestrictedExpression::from_str(&cost_microusd.to_string())
            .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?,
    );
    attrs.insert(
        "is_write".to_string(),
        RestrictedExpression::from_str(if matches!(tool.category, ToolCategory::Write) {
            "true"
        } else {
            "false"
        })
        .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?,
    );

    let uid = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("Tool")
            .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?,
        EntityId::from_str(&tool.id)
            .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?,
    );

    Entity::new(uid, attrs, HashSet::new())
        .with_context(|| format!("build cedar entity for tool {}", tool.id))
        .map_err(CedarPolicyEngineError::Other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use briefcase_core::{OutputFirewall, ToolCost};

    fn tool(id: &str, category: ToolCategory, cost: f64) -> ToolSpec {
        ToolSpec {
            id: id.to_string(),
            name: id.to_string(),
            description: id.to_string(),
            input_schema: serde_json::json!({"type":"object"}),
            output_schema: serde_json::json!({"type":"object"}),
            category,
            cost: ToolCost {
                estimated_usd: cost,
            },
            output_firewall: OutputFirewall::allow_all(),
        }
    }

    #[test]
    fn cheap_read_is_allowed_without_approval() {
        let engine = CedarPolicyEngine::new(CedarPolicyEngineOptions::default_policies()).unwrap();
        let d = engine
            .decide("me", &tool("echo", ToolCategory::Read, 0.0))
            .unwrap();
        assert_eq!(d, PolicyDecision::Allow);
    }

    #[test]
    fn write_requires_approval() {
        let engine = CedarPolicyEngine::new(CedarPolicyEngineOptions::default_policies()).unwrap();
        let d = engine
            .decide("me", &tool("write", ToolCategory::Write, 0.0))
            .unwrap();
        assert!(matches!(d, PolicyDecision::RequireApproval { .. }));
    }

    #[test]
    fn admin_is_denied() {
        let engine = CedarPolicyEngine::new(CedarPolicyEngineOptions::default_policies()).unwrap();
        let d = engine
            .decide("me", &tool("admin", ToolCategory::Admin, 0.0))
            .unwrap();
        assert!(matches!(d, PolicyDecision::Deny { .. }));
    }
}
