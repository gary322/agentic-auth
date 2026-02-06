# Design: portable-briefcase-v1

## Overview

Implement a local-first "credential briefcase" where:

- an untrusted agent runtime connects only to a single MCP gateway,
- all tool execution happens inside a trusted daemon that owns secrets, payments, and policy enforcement,
- results are redacted and all actions are auditable via tamper-evident receipts.

v1 focuses on a production-grade reference implementation with a demo provider gateway.

## Architecture

```mermaid
graph TB
  Agent[Untrusted agent / LLM runtime]
  MCP[mcp-gateway (only MCP server)]
  Daemon[briefcased (daemon)]
  Secrets[Secret store (keyring/file)]
  DB[(SQLite metadata)]
  Receipts[(Receipt chain)]
  Provider[agent-access-gateway (provider reference)]
  API[Upstream API/tool]

  Agent --> MCP
  MCP --> Daemon
  Daemon --> Secrets
  Daemon --> DB
  Daemon --> Receipts
  Daemon --> Provider
  Provider --> API
```

## Key components

- `briefcased`
  - Owns credentials and keys (refresh tokens, key seeds).
  - Enforces Cedar policy, budgets, approvals.
  - Executes connectors (HTTP in v1) and applies output firewalling.
  - Emits receipts in a hash chain with a verification API.
- `mcp-gateway`
  - Exposes tool list + tool call over stdio JSON-RPC (MCP-like subset).
  - Forwards to daemon; does not hold secrets.
- `briefcase-cli`
  - Trusted admin tool: approvals, receipts verify, OAuth onboarding, VC fetch.
- `briefcase-ui`
  - Local UI proxy: approvals + receipts + provider status; includes CSRF token for write actions.
- `agent-access-gateway`
  - Demo provider-side gateway:
    - OAuth 2.1 + PKCE (authorization code + refresh token rotation)
    - VC issuance (JWT entitlement) and verification
    - 402 challenges (demo x402/l402)
    - capability token issuance (JWT) + metering

## Data model / state (daemon)

- SQLite (`apps/briefcased/src/db.rs`)
  - `approvals` (pending approvals, args-bound hash)
  - `budgets` + `spend_events`
  - `providers` (v1: seeded `demo` provider with base URL)
  - `identity` (holder DID)
  - `vcs` (provider -> VC JWT + expiry)
- Secret store (`crates/briefcase-secrets`)
  - `oauth.<provider>.refresh_token` (bytes)
  - `identity.ed25519_sk` (32-byte seed)
- Receipts (`crates/briefcase-receipts`)
  - `receipts` table with `(prev_hash, hash, event_json)`; verifiable chain.

## Interfaces / APIs

Daemon HTTP API (local-only by default):

- Tools
  - `GET /v1/tools`
  - `POST /v1/tools/call`
- Approvals
  - `GET /v1/approvals`
  - `POST /v1/approvals/{id}/approve`
- Receipts
  - `GET /v1/receipts`
  - `POST /v1/receipts/verify`
- Identity / Providers (admin)
  - `GET /v1/identity`
  - `GET /v1/providers`
  - `POST /v1/providers/{id}/oauth/exchange`
  - `POST /v1/providers/{id}/vc/fetch`

Provider gateway API (demo):

- `GET /oauth/authorize` (PKCE)
- `POST /oauth/token` (authorization_code + refresh_token)
- `POST /vc/issue`
- `POST /token` (capability issuance via OAuth / VC / payments)
- `GET /api/quote` (capability-protected API)

## Failure modes & error handling

- Secret store unavailable: daemon must fail closed for any operation that requires secrets (OAuth/identity).
- Provider errors: return `CallToolResponse::Error` with a stable message; receipts still record the attempt when appropriate.
- Approval mismatch/expiry: tool call denied with `invalid_or_expired_approval`.
- Receipt verification failure: `POST /v1/receipts/verify` returns non-2xx with an error code.

## Security & privacy

- Never return raw secrets via tool outputs or admin endpoints.
- Avoid logging secrets: use `Sensitive<T>` for secret-bearing values.
- Tool outputs are filtered via output firewall allowlist when configured.
- UI proxy includes a CSRF token requirement for write actions.

## Test strategy

- Unit tests
  - secret store file backend round-trip
  - receipt chain verify
  - DID key derivation stability
- Integration tests (daemon)
  - tool call + approvals
  - paid tool call (402 challenge flow)
  - OAuth exchange + VC fetch + tool call without payment
- CI
  - `cargo fmt --check`
  - `cargo clippy -- -D warnings`
  - `cargo test`

## Rollout / migration plan

- DB migrations are additive via `CREATE TABLE IF NOT EXISTS` in `Db::init()`.
- Capabilities, OAuth, and VC profiles are documented; external providers can replace the demo gateway.

