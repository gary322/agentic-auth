# Packaging

This folder contains **reference** service definitions for running `briefcased` as a background service.

Notes:

- `briefcased` is **local-first** and defaults to local-only IPC (Unix socket on Unix).
- You should configure secret storage and budgets/policy before enabling unattended payments.
- These are templates; adapt paths and environment variables for your environment.

## systemd (Linux)

See `packaging/systemd/briefcased.service`.

## launchd (macOS)

See `packaging/launchd/com.briefcase.briefcased.plist`.

