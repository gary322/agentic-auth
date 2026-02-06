# Tasks: portable-briefcase-v1

## Phase 0: Repo Foundation (Completed)

- [x] Monorepo scaffolding with Rust workspace + CI
  - **Files**: `Cargo.toml`, `.github/workflows/ci.yml`, `rust-toolchain.toml`
  - **Verify**: `cargo fmt --check` + `cargo clippy --all-targets -- -D warnings` + `cargo test`

- [x] Daemon core with policy/budget/approvals/receipts
  - **Files**: `apps/briefcased/src/app.rs`, `apps/briefcased/src/db.rs`, `crates/briefcase-policy`, `crates/briefcase-receipts`
  - **Verify**: `cargo test`

- [x] MCP gateway forwarding to daemon
  - **Files**: `apps/mcp-gateway`
  - **Verify**: `cargo test`

## Phase 1: Secrets + Identity (Completed)

- [x] Secret store abstraction (keyring + encrypted file + memory)
  - **Files**: `crates/briefcase-secrets`
  - **Verify**: `cargo test -p briefcase-secrets`

- [x] Holder identity generation (`did:key` Ed25519)
  - **Files**: `crates/briefcase-identity`, `apps/briefcased/src/app.rs`, `apps/briefcased/src/db.rs`
  - **Done when**: daemon exposes `GET /v1/identity` and persists DID + secret key seed
  - **Verify**: `cargo test -p briefcase-identity`

## Phase 2: OAuth + VC Entitlements (Completed)

- [x] Provider gateway OAuth + VC endpoints (demo)
  - **Files**: `apps/agent-access-gateway/src/main.rs`
  - **Done when**: `/oauth/authorize`, `/oauth/token`, `/vc/issue`, `/token` work end-to-end
  - **Verify**: `cargo test`

- [x] Daemon OAuth exchange + VC fetch endpoints
  - **Files**: `apps/briefcased/src/app.rs`, `apps/briefcased/src/db.rs`
  - **Verify**: `cargo test`

- [x] CLI onboarding commands (PKCE loopback) + VC fetch
  - **Files**: `apps/briefcase-cli/src/main.rs`, `crates/briefcase-api/src/client.rs`, `crates/briefcase-api/src/types.rs`
  - **Verify**: `cargo test`

- [x] Auth strategy selection (VC > OAuth > payment)
  - **Files**: `apps/briefcased/src/provider.rs`
  - **Verify**: daemon e2e test `e2e_oauth_and_vc_avoid_payment`

## Phase 3: UI (Completed)

- [x] Local UI proxy for approvals/receipts/provider status
  - **Files**: `apps/briefcase-ui/src/main.rs`
  - **Done when**: Approvals can be listed + approved; receipts visible; provider status visible
  - **Verify**: `cargo test` + manual smoke (`cargo run -p briefcase-ui`)

## Phase 4: Receipts Verification (Completed)

- [x] Expose receipts chain verification via daemon API + CLI
  - **Files**: `apps/briefcased/src/app.rs`, `crates/briefcase-api/src/client.rs`, `apps/briefcase-cli/src/main.rs`
  - **Verify**: `cargo test` and `briefcase receipts verify` succeeds

## Phase 5: Production Hardening (Completed)

- [x] Provider registry + multi-provider support
  - **Do**: make providers first-class (add/update/remove), allow multiple connectors, remove hard-coded `demo` assumptions
  - **Done when**: tools can target a provider by ID, and onboarding is per-provider

- [x] Real x402 and real L402 integrations behind a stable `PaymentRail` interface
  - **Do**: extract payment codepaths to a crate (`briefcase-payments`), add mock + real backends

- [x] Capability PoP binding (DPoP-like) and replay defenses
  - **Do**: bind capabilities to client key; store minimal key material in secret store; verify on provider gateway

- [x] Tool isolation (egress allowlists + sandboxing)
  - **Do**: per-tool allowed domains; deny-by-default network; optional sandbox for tool execution

- [x] Risk scoring / prompt injection heuristics and tests
  - **Do**: add a non-authoritative classifier; never let it override policy engine decisions

- [x] Packaging + signed releases
  - **Do**: systemd/launchd/windows service units; release artifacts + checksums
