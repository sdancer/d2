#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec cargo run --manifest-path "$root/native-egui/Cargo.toml" -- "$@"
