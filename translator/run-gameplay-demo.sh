#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
artifact="${D2_ARTIFACT_DIR:-$root/build/diablo-linked-gameplay}"

if [[ ! -f "$artifact/linked.wasm" ]]; then
  echo "missing gameplay artifact: $artifact/linked.wasm" >&2
  echo "build it with the full link-translate command in README.md" >&2
  exit 1
fi

export D2_MAIN_ROUNDS="${D2_MAIN_ROUNDS:-400}"
export D2_AUTO_CLICKS="${D2_AUTO_CLICKS:-400,208,350;400,280,470;690,555,650;250,290,660}"
export D2_AUTO_TEXT="${D2_AUTO_TEXT:-Current,580}"
export D2_FRAMEBUFFER_PPM="${D2_FRAMEBUFFER_PPM:-$root/build/diablo-gameplay.ppm}"

exec node "$root/runtime/run-linked.mjs" \
  "$artifact/linked.wasm" \
  "$artifact/linked-translation.json" \
  "$root/build/diablo-link-compact.json" \
  "$root/../extracted" \
  "$root/build/runtime-files/diablo2"
