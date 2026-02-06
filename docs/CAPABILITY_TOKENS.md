# Capability Tokens (v0.1)

## Purpose

Providers should return **short-lived, caveated capability tokens** to minimize blast radius:

- short TTL (minutes)
- endpoint/tool scope
- max calls / max bytes
- proof-of-possession (PoP) binding

## Reference Implementation

`apps/agent-access-gateway` issues JWT capability tokens with:

- `exp` / `iat`
- `jti` (usage metering key)
- `scope` (e.g. `quote`)
- `max_calls`
- `cost_microusd` (for demo metering)
- `pop_pk_b64` (optional): Ed25519 public key (base64url-no-pad) that must sign each request

`briefcased` caches capability tokens and uses them to call the provider.

## PoP Binding (v0.1)

To bind a capability to a client key (DPoP-like):

1. `briefcased` includes `x-briefcase-pop-pub: <pk_b64url>` on `/token` requests.
2. The provider mints a capability with `pop_pk_b64`.
3. For each protected API call, the client includes:

- `x-briefcase-pop-ver: 1`
- `x-briefcase-pop-ts: <unix_seconds>`
- `x-briefcase-pop-nonce: <random_b64url>`
- `x-briefcase-pop-sig: <ed25519_sig_b64url>`

Signature message:

```
v1\n<METHOD>\n<PATH?QUERY>\n<TS>\n<NONCE>\n<SHA256_B64URL(CAPABILITY_JWT)>
```

The provider verifies the signature and enforces nonce uniqueness to prevent replay.

## Planned / Future

- macaroon-like caveats and attenuation profiles
