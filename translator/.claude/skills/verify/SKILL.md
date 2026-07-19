---
name: verify-translator
description: Drive the d2wasm CLI and linked Wasm runtime end to end.
---

# Verify the translator runtime surface

Use the project virtualenv so `lief` and `capstone` are available:

```sh
export PATH="$PWD/.venv/bin:$PATH"
```

For the complete hermetic CLI/runtime flow, run:

```sh
./tests/smoke.sh
```

For workspace changes, drive the two-module fixture through these user-visible stages:

1. Build `tests/smoke-api.s` and `tests/smoke-linked.c`, then run `d2wasm.py link` with `tests/smoke-linked-map.json`.
2. Run ordinary `link-translate` and retain `linked.c` as the reference.
3. Run `link-translate --debug-db ... --work-item-budget 1`; expect exit 3 and a checkpoint summary.
4. Re-run without the budget; compare `linked.c` byte-for-byte with the reference.
5. Run `runtime/run-linked.mjs`; require JSON `result: 42` and `status: 0`.
6. Re-run `--debug-db-only`; immutable revision counts must not increase.
7. Probe `--work-item-budget` without `--debug-db`; expect a concise error and exit 2.

For migration behavior, copy `build/diablo-debug.sqlite` to a temporary path and open the copy through `link-translate --debug-db <copy> --debug-db-only --work-item-budget 1`. Confirm `PRAGMA user_version=2`, `metadata.schema_version=2`, compatibility block counts are retained, and integrity/foreign-key checks pass. Never verify migration against the original database in place.
