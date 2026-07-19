from __future__ import annotations

from typing import Any, Iterable, Mapping

from .workspace import TranslationStore, canonical_json, stable_hash, _utc_now


PROMOTION_ORDER = [
    "explained",
    "implemented",
    "locally_equivalent",
    "scenario_equivalent",
    "accepted",
]


def ingest_trace(
    store: TranslationStore,
    run_id: str,
    events: Iterable[Mapping[str, Any]],
    *,
    kind: str,
    seed: int = 0,
    virtual_time: int = 0,
    inputs: Mapping[str, Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> str:
    event_rows = list(events)
    trace_run_id = stable_hash(
        "d2wasm-trace-run-v1", run_id, kind, seed, virtual_time, inputs or {}, event_rows
    )
    now = _utc_now()
    with store.transaction(immediate=True):
        store.connection.execute(
            """INSERT OR IGNORE INTO trace_runs
               (trace_run_id, run_id, kind, seed, virtual_time, input_json,
                metadata_json, started_at, finished_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                trace_run_id,
                run_id,
                kind,
                int(seed),
                int(virtual_time),
                canonical_json(inputs or {}),
                canonical_json(metadata or {}),
                now,
                now,
            ),
        )
        store.connection.executemany(
            """INSERT OR IGNORE INTO trace_events
               (trace_run_id, sequence, kind, source_va, target_va, aux, payload_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    trace_run_id,
                    index,
                    str(event.get("kind", "unknown")),
                    event.get("source"),
                    event.get("target"),
                    event.get("aux"),
                    canonical_json(event),
                )
                for index, event in enumerate(event_rows)
            ],
        )
    return trace_run_id


def persist_snapshot(
    store: TranslationStore,
    run_id: str,
    snapshot: Mapping[str, Any],
) -> str:
    snapshot_id = stable_hash("d2wasm-snapshot-v1", run_id, snapshot)
    with store.transaction(immediate=True):
        store.connection.execute(
            """INSERT OR IGNORE INTO snapshots
               (snapshot_id, run_id, content_hash, cpu_json, memory_json,
                runtime_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                snapshot_id,
                run_id,
                stable_hash("d2wasm-snapshot-content-v1", snapshot),
                canonical_json({"statePointer": snapshot.get("statePointer"), "cpu": snapshot.get("cpu")}),
                canonical_json(snapshot.get("memory", [])),
                canonical_json(snapshot.get("runtime", {})),
                _utc_now(),
            ),
        )
    return snapshot_id


def register_replacement(
    store: TranslationStore,
    run_id: str,
    entry_va: int,
    *,
    function_id: str | None = None,
    implementation_id: str | None = None,
    kind: int = 1,
    value: int = 0,
    stack_cleanup: int = 0,
    enabled: bool = True,
) -> str:
    binding_id = stable_hash("d2wasm-replacement-binding-v1", run_id, int(entry_va))
    with store.transaction(immediate=True):
        store.connection.execute(
            """INSERT INTO replacement_bindings
               (binding_id, run_id, function_id, entry_va, implementation_id,
                replacement_kind, replacement_value, stack_cleanup, enabled, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(run_id, entry_va) DO UPDATE SET
                 function_id=excluded.function_id,
                 implementation_id=excluded.implementation_id,
                 replacement_kind=excluded.replacement_kind,
                 replacement_value=excluded.replacement_value,
                 stack_cleanup=excluded.stack_cleanup,
                 enabled=excluded.enabled""",
            (
                binding_id,
                run_id,
                function_id,
                int(entry_va),
                implementation_id,
                int(kind),
                int(value),
                int(stack_cleanup),
                int(enabled),
                _utc_now(),
            ),
        )
    return binding_id


def persist_equivalence(
    store: TranslationStore,
    run_id: str,
    result: Mapping[str, Any],
    *,
    name: str,
    function_id: str | None = None,
    implementation_id: str | None = None,
    input_request: Mapping[str, Any] | None = None,
) -> dict[str, str]:
    snapshot_id = persist_snapshot(store, run_id, result.get("snapshot", {}))
    test_case_id = stable_hash("d2wasm-test-case-v1", run_id, name, function_id, input_request or {})
    reference_trace_id = ingest_trace(
        store,
        run_id,
        result.get("reference", {}).get("trace", []),
        kind="reference",
        inputs=input_request,
    )
    replacement_trace_id = ingest_trace(
        store,
        run_id,
        result.get("replacement", {}).get("trace", []),
        kind="replacement",
        inputs=input_request,
    )
    validation_run_id = stable_hash(
        "d2wasm-validation-run-v1", test_case_id, implementation_id, result
    )
    equivalence_result_id = stable_hash(
        "d2wasm-equivalence-result-v1", validation_run_id, bool(result.get("equivalent"))
    )
    now = _utc_now()
    with store.transaction(immediate=True):
        store.connection.execute(
            """INSERT OR IGNORE INTO test_cases
               (test_case_id, run_id, function_id, name, input_snapshot_id,
                input_json, expected_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                test_case_id,
                run_id,
                function_id,
                name,
                snapshot_id,
                canonical_json(input_request or {}),
                canonical_json(result.get("reference", {})),
                now,
            ),
        )
        store.connection.execute(
            """INSERT OR IGNORE INTO validation_runs
               (validation_run_id, run_id, test_case_id, implementation_id,
                reference_trace_run_id, replacement_trace_run_id, status,
                started_at, finished_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                validation_run_id,
                run_id,
                test_case_id,
                implementation_id,
                reference_trace_id,
                replacement_trace_id,
                "equivalent" if result.get("equivalent") else "mismatch",
                now,
                now,
            ),
        )
        store.connection.execute(
            """INSERT OR IGNORE INTO equivalence_results
               (equivalence_result_id, validation_run_id, equivalent, return_json,
                register_diff_json, memory_diff_json, event_diff_json,
                counterexample_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                equivalence_result_id,
                validation_run_id,
                int(bool(result.get("equivalent"))),
                canonical_json(
                    {
                        "reference": result.get("reference", {}).get("result"),
                        "replacement": result.get("replacement", {}).get("result"),
                    }
                ),
                canonical_json(result.get("registerDiff", {})),
                canonical_json(result.get("memoryDiff", [])),
                canonical_json(result.get("eventDiff", [])),
                canonical_json({} if result.get("equivalent") else result),
                now,
            ),
        )
        if function_id:
            target_status = "locally_equivalent" if result.get("equivalent") else "implemented"
            store.connection.execute(
                "UPDATE functions SET status=? WHERE function_id=?",
                (target_status, function_id),
            )
    return {
        "snapshot_id": snapshot_id,
        "test_case_id": test_case_id,
        "validation_run_id": validation_run_id,
        "equivalence_result_id": equivalence_result_id,
    }


def promote_function(
    store: TranslationStore,
    function_id: str,
    target: str,
) -> None:
    if target not in PROMOTION_ORDER:
        raise ValueError(f"invalid promotion state: {target}")
    row = store.connection.execute(
        "SELECT status FROM functions WHERE function_id=?", (function_id,)
    ).fetchone()
    if row is None:
        raise KeyError(f"unknown function: {function_id}")
    current = str(row[0])
    current_index = PROMOTION_ORDER.index(current) if current in PROMOTION_ORDER else -1
    if PROMOTION_ORDER.index(target) > current_index + 1:
        raise ValueError(f"cannot promote directly from {current} to {target}")
    with store.transaction(immediate=True):
        store.connection.execute(
            "UPDATE functions SET status=? WHERE function_id=?",
            (target, function_id),
        )
