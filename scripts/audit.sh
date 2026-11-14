#!/usr/bin/env bash
# Auditoría local de Quipu: espejo del CI para correr antes de publicar.
#   ./scripts/audit.sh
set -euo pipefail

export PATH="$HOME/.cargo/bin:$PATH"

echo "== build =="
cargo build --all-targets

echo "== tests =="
cargo test --all-targets

echo "== clippy (deny warnings) =="
cargo clippy --all-targets -- -D warnings

echo "== cargo-audit (RustSec) =="
if ! command -v cargo-audit >/dev/null 2>&1; then
  echo "cargo-audit no instalado; instalando..."
  cargo install cargo-audit --locked
fi
cargo audit

echo "== OK: todo verde =="
