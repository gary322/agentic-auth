# Contributing

## Development Setup

Requirements:

- Rust stable (see `rust-toolchain.toml` if present)
- `cargo` (fmt, clippy)

Commands:

```bash
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

## Pull Requests

- Keep changes focused.
- Add tests for behavioral changes.
- Do not log secrets (auth tokens, refresh tokens, payment proofs).

## Code Style

- Run `cargo fmt` before pushing.
- Keep error messages actionable and avoid leaking sensitive input.

