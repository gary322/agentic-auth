# Releasing

This repository is a monorepo. The release tag (`vX.Y.Z`) is intended to be the **single version** for all shipped artifacts:

- Rust binaries (`briefcased`, `mcp-gateway`, `briefcase-cli`, `briefcase-ui`, `agent-access-gateway`)
- (future) browser extension package
- (future) mobile signer apps
- (future) enterprise control plane container images

## Current releases (v0.1.x)

Rust artifacts are built and published by GitHub Actions when a tag `v*` is pushed.

## Versioning policy

- Public APIs/configs follow SemVer.
- `main` is always releasable (CI must stay green).
- Releases are cut from an annotated tag on `main`.

## Cut a release (Rust-only today)

1. Ensure `main` is green in CI.
2. Bump the workspace version in `Cargo.toml` (and regenerate `Cargo.lock`):
   - `cargo update -w` is not required; keep dependency churn separate.
3. Commit the version bump.
4. Tag and push:

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

The `release` workflow will:

- build the binaries on Linux/macOS/Windows
- package them into OS archives
- generate `SHA256SUMS.txt`
- sign artifacts using keyless Sigstore `cosign sign-blob`
- publish a GitHub Release

## Future: multi-artifact release

When the extension/mobile/control-plane are added, the release workflow will be expanded to:

- build and package extension artifacts
- build mobile apps in CI (build/test; distribution depends on platform)
- build and push signed container images for the control plane

