# Credential Briefcase dev tasks.
#
# `just` is optional; CI does not depend on it. Install: https://github.com/casey/just

set dotenv-load := true

default:
  @just --list

ci:
  @just rust-ci
  @just node-ci

rust-ci:
  cargo fmt --all -- --check
  cargo clippy --all-targets --all-features -- -D warnings
  cargo test --all

node-ci:
  # No-op if the monorepo has no Node workspace yet.
  @if [ -f package.json ]; then \
    corepack enable; \
    pnpm install --frozen-lockfile; \
    pnpm -r gen; \
    git diff --exit-code; \
    pnpm -r lint; \
    pnpm -r test; \
  else \
    echo "node-ci: skipped (no package.json)"; \
  fi

gen:
  @if [ -f package.json ]; then \
    corepack enable; \
    pnpm install --frozen-lockfile; \
    pnpm -r gen; \
  else \
    echo "gen: skipped (no package.json)"; \
  fi

