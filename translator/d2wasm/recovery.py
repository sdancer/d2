from __future__ import annotations

from collections import Counter, deque
from typing import Any

from .workspace import TranslationStore, canonical_json, stable_hash, _utc_now


RECOVERY_ALGORITHM_VERSION = "1"
_INTRAPROCEDURAL_EDGES = {
    "branch",
    "branch_fallthrough",
    "jump",
    "jump_table",
    "fallthrough",
    "call_fallthrough",
}
_CALL_EDGES = {"call", "import_call", "import_jump"}


def recover_functions(
    store: TranslationStore,
    run_id: str,
    module_version_id: str,
) -> dict[str, Any]:
    revisions = store.load_selected_revisions(
        run_id, module_version_id=module_version_id
    )
    by_rva = {int(revision["rva"]): revision for revision in revisions}
    module = store.connection.execute(
        "SELECT * FROM module_versions WHERE module_version_id=?",
        (module_version_id,),
    ).fetchone()
    if module is None:
        raise KeyError(f"unknown module version: {module_version_id}")
    load_base = int(module["load_base"])
    input_hash = stable_hash(
        "d2wasm-function-recovery-input-v1",
        [(int(item["rva"]), item["revision_id"]) for item in revisions],
    )
    recovery_version_id = stable_hash(
        "d2wasm-function-recovery-v1",
        run_id,
        module_version_id,
        RECOVERY_ALGORITHM_VERSION,
        input_hash,
    )

    entries: dict[int, tuple[str, float, dict[str, Any]]] = {}
    for row in store.connection.execute(
        """SELECT rva, kind, confidence, details_json FROM root_facts
           WHERE run_id=? AND module_version_id=? AND accepted=1""",
        (run_id, module_version_id),
    ):
        rva = int(row["rva"])
        if rva in by_rva:
            entries[rva] = (
                str(row["kind"]),
                float(row["confidence"] if row["confidence"] is not None else 0.8),
                __import__("json").loads(str(row["details_json"])),
            )
    for revision in revisions:
        for edge in revision["edges"]:
            target_rva = edge.get("target_rva")
            if (
                edge.get("kind") in _CALL_EDGES
                and edge.get("target_module_version_id") == module_version_id
                and target_rva is not None
                and int(target_rva) in by_rva
            ):
                entries.setdefault(int(target_rva), ("direct_call", 0.9, {}))
    if not entries and revisions:
        first = min(by_rva)
        entries[first] = ("provisional", 0.4, {})

    export_names = {
        int(row["rva"]): str(row["name"])
        for row in store.connection.execute(
            """SELECT export.rva, export.name FROM exports AS export
               WHERE export.module_id=? AND export.name IS NOT NULL""",
            (int(module["compatibility_module_id"]),),
        )
    }
    entry_set = set(entries)
    memberships: dict[int, set[str]] = {}
    recovered: list[dict[str, Any]] = []

    for entry_rva, (entry_kind, confidence, details) in sorted(entries.items()):
        function_id = stable_hash(
            "d2wasm-function-v1",
            run_id,
            module_version_id,
            recovery_version_id,
            entry_rva,
        )
        queue = deque([entry_rva])
        visited: set[int] = set()
        while queue:
            rva = queue.popleft()
            if rva in visited or rva not in by_rva:
                continue
            if rva != entry_rva and rva in entry_set:
                continue
            visited.add(rva)
            for edge in by_rva[rva]["edges"]:
                target = edge.get("target_rva")
                if (
                    target is not None
                    and edge.get("target_module_version_id") == module_version_id
                    and edge.get("kind") in _INTRAPROCEDURAL_EDGES
                ):
                    queue.append(int(target))
        for rva in visited:
            memberships.setdefault(rva, set()).add(function_id)
        recovered.append(
            {
                "function_id": function_id,
                "entry_rva": entry_rva,
                "entry_kind": entry_kind,
                "confidence": confidence,
                "details": details,
                "name": export_names.get(entry_rva),
                "blocks": visited,
            }
        )

    now = _utc_now()
    with store.transaction(immediate=True):
        store.connection.execute(
            """INSERT OR IGNORE INTO recovery_versions
               (recovery_version_id, run_id, algorithm_version, input_hash, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (
                recovery_version_id,
                run_id,
                RECOVERY_ALGORITHM_VERSION,
                input_hash,
                now,
            ),
        )
        for function in recovered:
            purpose = (
                f"Exported function {function['name']}"
                if function["name"]
                else f"Recovered function at RVA 0x{function['entry_rva']:08x}"
            )
            store.connection.execute(
                """INSERT OR IGNORE INTO functions
                   (function_id, run_id, module_version_id, recovery_version_id,
                    primary_entry_rva, name, confidence, status, purpose, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'recovered', ?, ?)""",
                (
                    function["function_id"],
                    run_id,
                    module_version_id,
                    recovery_version_id,
                    function["entry_rva"],
                    function["name"],
                    function["confidence"],
                    purpose,
                    now,
                ),
            )
            store.connection.execute(
                """INSERT OR IGNORE INTO function_entries
                   (function_id, rva, va, kind, confidence)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    function["function_id"],
                    function["entry_rva"],
                    load_base + function["entry_rva"],
                    function["entry_kind"],
                    function["confidence"],
                ),
            )
            for block_rva in sorted(function["blocks"]):
                block_key_id = stable_hash(
                    "d2wasm-block-v2", module_version_id, block_rva
                )
                revision = by_rva[block_rva]
                role = "entry" if block_rva == function["entry_rva"] else "body"
                if len(memberships.get(block_rva, ())) > 1:
                    role = "shared_tail"
                elif (
                    len(function["blocks"]) == 1
                    and revision["terminator"] in {"jump", "import_jump"}
                ):
                    role = "thunk"
                store.connection.execute(
                    """INSERT OR REPLACE INTO function_blocks
                       (function_id, block_key_id, role, confidence)
                       VALUES (?, ?, ?, ?)""",
                    (function["function_id"], block_key_id, role, function["confidence"]),
                )

        entry_to_function = {
            int(function["entry_rva"]): str(function["function_id"])
            for function in recovered
        }
        for function in recovered:
            for block_rva in function["blocks"]:
                revision = by_rva[block_rva]
                for edge in revision["edges"]:
                    if edge.get("kind") not in _CALL_EDGES:
                        continue
                    target_rva = edge.get("target_rva")
                    callee = (
                        entry_to_function.get(int(target_rva))
                        if target_rva is not None
                        and edge.get("target_module_version_id") == module_version_id
                        else None
                    )
                    store.connection.execute(
                        """INSERT OR IGNORE INTO function_calls
                           (caller_function_id, callee_function_id, source_rva,
                            target_module_version_id, target_rva, kind, confidence)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (
                            function["function_id"],
                            callee,
                            int(edge.get("source_instruction_rva") or block_rva),
                            edge.get("target_module_version_id"),
                            target_rva,
                            str(edge["kind"]),
                            1.0 if edge.get("resolution") in {"resolved_executable", "internal_import"} else 0.5,
                        ),
                    )

    role_counts = Counter(
        row[0]
        for row in store.connection.execute(
            """SELECT role FROM function_blocks AS membership
               JOIN functions AS function ON function.function_id=membership.function_id
               WHERE function.run_id=? AND function.module_version_id=?
                 AND function.recovery_version_id=?""",
            (run_id, module_version_id, recovery_version_id),
        )
    )
    return {
        "recovery_version_id": recovery_version_id,
        "function_count": len(recovered),
        "entry_count": len(entries),
        "role_counts": dict(role_counts),
        "input_hash": input_hash,
    }


def recover_all_functions(store: TranslationStore, run_id: str) -> dict[str, Any]:
    modules = [
        str(row[0])
        for row in store.connection.execute(
            """SELECT DISTINCT block.module_version_id
               FROM run_block_selections AS selected
               JOIN block_keys AS block ON block.block_key_id=selected.block_key_id
               WHERE selected.run_id=? ORDER BY block.module_version_id""",
            (run_id,),
        )
    ]
    reports = [recover_functions(store, run_id, module_id) for module_id in modules]
    return {
        "modules": reports,
        "function_count": sum(report["function_count"] for report in reports),
    }
