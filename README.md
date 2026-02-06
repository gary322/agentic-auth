# Credential Briefcase

Local-first credentials, payments, policy, and audit receipts for tool-using agents.

## What This Is

This repo implements the core system described in `sop.txt`:

- The **LLM is treated as untrusted**.
- The agent connects to **one** MCP server (`mcp-gateway`).
- Tool calls are routed to a local daemon (`briefcased`) that owns:
  - credentials and keys (v0.1: scaffolding + safe storage boundaries)
  - a Cedar-based allow/deny + approval gate
  - budgets (category-based daily caps)
  - payment rails (x402 + l402 behind a `briefcase-payments` interface)
  - non-authoritative risk scoring (can require approval, never bypass policy)
  - tamper-evident audit receipts (hash chained)
- Providers can run a reference gateway (`agent-access-gateway`) that:
  - challenges with HTTP 402,
  - verifies proofs,
  - supports OAuth 2.1 + PKCE (demo),
  - issues demo VC entitlements,
  - issues short-lived **capability tokens** (JWT),
  - optionally binds capabilities to a client key (PoP) and enforces replay defenses,
  - meters usage.

## Components

- `apps/briefcased`: local daemon (policy, budgets, receipts, connectors)
- `apps/mcp-gateway`: the single MCP surface for agents (stdio JSON-RPC)
- `apps/briefcase-cli`: admin CLI (tools, approvals, receipts)
- `apps/briefcase-ui`: local web UI (approvals, receipts, provider status)
- `apps/agent-access-gateway`: provider-side reference gateway (HTTP 402 + capability tokens)

Shared crates:

- `crates/briefcase-core`: shared types + redaction helpers
- `crates/briefcase-api`: daemon API contract + client
- `crates/briefcase-secrets`: secret storage backends (keyring + encrypted file + in-memory)
- `crates/briefcase-identity`: `did:key` generation (Ed25519)
- `crates/briefcase-payments`: x402/l402 challenge parsing + payment backends (demo HTTP + command helper)
- `crates/briefcase-policy`: Cedar policy engine wrapper
- `crates/briefcase-receipts`: tamper-evident receipts store
- `crates/briefcase-risk`: non-authoritative risk scoring (heuristics + optional HTTP classifier)

## Quickstart (Local Demo)

1. Start the provider reference gateway (port `9099` by default):

```bash
cargo run -p agent-access-gateway
```

2. Start the daemon (Unix socket by default on macOS/Linux).

For a portable local demo (works in headless environments), use the encrypted-file secret backend:

```bash
export BRIEFCASE_SECRET_BACKEND=file
export BRIEFCASE_MASTER_PASSPHRASE='dev-passphrase-change-me'
cargo run -p briefcased
```

If you want OS keychain storage instead, omit those env vars (defaults to `keyring`).

```bash
cargo run -p briefcased
```

3. List tools:

```bash
cargo run -p briefcase-cli -- tools list
```

4. Call a read tool:

```bash
cargo run -p briefcase-cli -- tools call echo --args-json '{"text":"hello"}'
```

5. Call a write tool (requires approval by default):

```bash
cargo run -p briefcase-cli -- tools call note_add --args-json '{"text":"a note"}'
cargo run -p briefcase-cli -- approvals list
cargo run -p briefcase-cli -- approvals approve <APPROVAL_UUID>
cargo run -p briefcase-cli -- tools call note_add --args-json '{"text":"a note"}' --approval-token <APPROVAL_UUID>
```

6. Call the paid tool (demo x402 flow + capability token):

```bash
cargo run -p briefcase-cli -- tools call quote --args-json '{"symbol":"AAPL"}'
```

7. Optional: do OAuth login and fetch a VC entitlement (then `quote` avoids payments):

```bash
cargo run -p briefcase-cli -- providers oauth-login --id demo
cargo run -p briefcase-cli -- providers vc-fetch --id demo
cargo run -p briefcase-cli -- tools call quote --args-json '{"symbol":"AAPL"}'
```

8. Optional: start the local UI (defaults to `127.0.0.1:8787`):

```bash
cargo run -p briefcase-ui
```

9. Run all tests (includes an end-to-end test in `briefcased`):

```bash
cargo test
```

## Security Model (v0.1)

- The agent never receives daemon auth tokens, refresh tokens, or private keys.
- The daemon enforces:
  - schema validation of tool args
  - Cedar policy (allow/deny + approval gating)
  - non-authoritative risk scoring (approval-only tightening)
  - budgets
  - output firewalling (allowlist paths)
  - receipts for every tool call

See `docs/THREAT_MODEL.md`.

## License

Apache-2.0. See `LICENSE`.
