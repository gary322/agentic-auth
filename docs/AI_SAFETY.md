# AI Safety (Non-Authoritative By Design)

This repo treats the LLM as **untrusted**.

The Briefcase (`briefcased`) owns secrets, keys, payments, policy enforcement, and audit receipts. Any AI integration is an **optional advisory layer** that must never weaken enforcement.

## Hard Invariants

1. **Policy is authoritative**
   - Allow/deny comes from the policy engine (`briefcase-policy` / Cedar).
   - AI outputs never grant permissions.

2. **AI can only tighten**
   - The only enforcement impact AI is allowed to have is: **require interactive approval** for a tool call that policy would otherwise allow.
   - AI cannot bypass an approval requirement and cannot change an approval kind (local vs mobile signer).

3. **Untrusted outputs are parsed strictly**
   - All model outputs are treated as attacker-controlled text.
   - We accept only a narrowly-scoped JSON shape and deny unknown fields/values.
   - Any parse failure must **fail open** (no added friction), never “default allow” beyond what policy already allows.

4. **No raw secrets to AI**
   - Never send OAuth refresh tokens, capability tokens, private keys, payment proofs/preimages, or other secrets to any model endpoint.
   - Prefer structured, minimal inputs (tool IDs, sanitized args, receipts metadata).

## Where This Is Enforced In Code

- `crates/briefcase-ai/`
  - `apply_ai_to_policy(...)` encodes the “AI can only tighten” invariant.
  - `parse_llm_tool_advisory_json(...)` is strict and fails open.
  - Tests include a small red-team corpus of malicious model outputs.

## Operational Guidance

- Treat any AI endpoint as a separate trust domain.
- Log AI failures as *non-fatal* events (for monitoring), but do not block tool execution solely due to AI outage.
- Expand the red-team corpus whenever new prompt-injection / bypass patterns are discovered.

