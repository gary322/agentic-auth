# Threat Model (v0.1)

## Assumptions

- The LLM is untrusted and may be prompt-injected.
- Tool outputs are untrusted (output poisoning).
- The local machine is the trust boundary; other local processes should not gain access to secrets by default.

## Goals

- Never provide raw long-lived secrets (refresh tokens, private keys) to the agent runtime.
- Minimize blast radius with approvals, budgets, and short-lived capability tokens.
- Provide auditability via tamper-evident receipts.

## Key Controls Implemented

- **Local auth token**: `briefcased` requires `Authorization: Bearer <token>` for its API. Token is stored on disk with restrictive permissions on Unix.
- **Secret storage**: refresh tokens and private key seeds are stored via `briefcase-secrets` (keyring by default; encrypted-file backend supported).
- **Policy gating**: Cedar allow/deny + derived "require approval" via a stricter action.
- **Risk scoring**: non-authoritative heuristics (and optional HTTP classifier) can require approval for suspicious calls.
- **Budgets**: category-based daily limits; overruns require approval.
- **Schema validation**: tool args validated against JSON Schema before execution.
- **Output firewall**: allowlisted paths for tool output where configured.
- **Receipts**: every tool call produces a chained-hash receipt record.
- **Capability tokens**: provider issues short-lived JWTs with caveats (`max_calls`, TTL) and optional PoP binding + replay defense.
- **Local UI proxy**: `briefcase-ui` proxies to the daemon and enforces a per-process CSRF token for write actions.

## Known Gaps / Planned Hardening

- UI hardening beyond CSRF token (origin binding / DNS rebinding defenses) is planned.
- Stronger tool isolation (per-tool egress allowlists, sandboxing) is planned; v0.1 already disables redirects and rejects non-loopback HTTP providers.
- Named pipe support (Windows) is planned; current default is Unix socket on Unix.
