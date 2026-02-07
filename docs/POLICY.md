# Policy

## Cedar Model

Cedar itself is allow/deny only. This codebase derives **"approval required"** by evaluating two actions:

- `Action::"Call"`: base permission to call a tool.
- `Action::"CallWithoutApproval"`: stricter permission to call without interactive approval.
- `Action::"CallWithoutSigner"`: stricter permission to call without a paired mobile signer.

Decision:

- if `Call` is denied: tool call is denied
- if `Call` is allowed and `CallWithoutApproval` is allowed: tool call proceeds
- if `Call` is allowed but `CallWithoutApproval` is denied: tool call requires approval:
  - if `CallWithoutSigner` is allowed: approval can be satisfied locally (`kind=local`)
  - if `CallWithoutSigner` is denied: approval must be satisfied by a mobile signer (`kind=mobile_signer`)

## Default Policy (v0.1)

In `crates/briefcase-policy`:

- deny `admin` tools
- allow calling non-admin tools
- allow calling without approval only for cheap `read` tools (<= $0.01)
- require a mobile signer only for "high risk writes": tools where:
  - `category == write`, and
  - the tool has network egress and/or filesystem access configured via its `ToolManifest`.

## Budgets

Budgets are enforced in `briefcased`:

- per-category daily caps (micro-USD integers)
- defaults:
  - `read`: $3/day
  - `write`: $0/day (forces approval for any paid write tool)
  - `admin`: $0/day

## VC Revocation (Status Unknown)

If a stored VC includes a Bitstring Status List entry and the status list cannot be fetched/parsed, `briefcased` treats the status as **unknown** and applies one of two behaviors:

- `require_approval` (default): return `approval_required` for the tool call.
- `deny`: fail closed with `denied` (`reason=vc_status_unknown`).

Configure via `BRIEFCASE_VC_STATUS_UNKNOWN_MODE`.
