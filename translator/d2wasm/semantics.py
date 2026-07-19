from __future__ import annotations

import json
from typing import Any, Mapping

from .workspace import TranslationStore, canonical_json, stable_hash, _utc_now


SEMANTIC_SCHEMA_VERSION = 1


def _artifact(
    store: TranslationStore,
    run_id: str,
    scope_type: str,
    scope_id: str,
    level: str,
    content: Mapping[str, Any],
    provenance: Mapping[str, Any],
    *,
    markdown: str | None = None,
    confidence: float = 1.0,
    reviewer_status: str = "unreviewed",
    state: str = "complete",
) -> str:
    input_hash = stable_hash("d2wasm-semantic-input-v1", provenance)
    content_hash = stable_hash("d2wasm-semantic-content-v1", content)
    artifact_id = stable_hash(
        "d2wasm-semantic-artifact-v1",
        run_id,
        scope_type,
        scope_id,
        level,
        input_hash,
        content_hash,
    )
    previous = store.connection.execute(
        """SELECT artifact_id FROM semantic_artifacts
           WHERE run_id=? AND scope_type=? AND scope_id=? AND level=?
           ORDER BY created_at DESC LIMIT 1""",
        (run_id, scope_type, scope_id, level),
    ).fetchone()
    with store.transaction(immediate=True):
        store.connection.execute(
            """INSERT OR IGNORE INTO semantic_artifacts
               (artifact_id, run_id, scope_type, scope_id, level, schema_version,
                input_hash, content_hash, content_json, markdown, provenance_json,
                confidence, reviewer_status, state, supersedes_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                artifact_id,
                run_id,
                scope_type,
                scope_id,
                level,
                SEMANTIC_SCHEMA_VERSION,
                input_hash,
                content_hash,
                canonical_json(content),
                markdown,
                canonical_json(provenance),
                confidence,
                reviewer_status,
                state,
                str(previous[0]) if previous is not None and previous[0] != artifact_id else None,
                _utc_now(),
            ),
        )
    return artifact_id


def _equation(instruction: Mapping[str, Any]) -> str | None:
    mnemonic = str(instruction["mnemonic"])
    operands = str(instruction.get("op_str", ""))
    if mnemonic == "add":
        return f"{operands.split(',')[0]} := ({operands}) mod 2^width"
    if mnemonic == "sub":
        return f"{operands.split(',')[0]} := subtraction({operands}) mod 2^width"
    if mnemonic in {"and", "or", "xor"}:
        return f"{operands.split(',')[0]} := bitwise_{mnemonic}({operands})"
    if mnemonic in {"shl", "shr", "sar", "rol", "ror"}:
        return f"{operands.split(',')[0]} := {mnemonic}({operands}) with x86 count masking"
    if mnemonic in {"imul", "mul"}:
        return f"product := multiply({operands}) mod 2^width"
    return None


def _rust_source(function: Mapping[str, Any], instructions: list[dict[str, Any]]) -> tuple[str, str]:
    name = function.get("name") or f"fn_{int(function['primary_entry_rva']):08x}"
    rust_name = "".join(character if character.isalnum() else "_" for character in str(name)).lower()
    meaningful = [item for item in instructions if item["mnemonic"] not in {"nop", "int3"}]
    if (
        len(meaningful) >= 2
        and meaningful[-1]["mnemonic"] == "ret"
        and meaningful[-2]["mnemonic"] == "mov"
        and meaningful[-2]["op_str"].lower().startswith("eax, ")
    ):
        immediate = meaningful[-2]["op_str"].split(",", 1)[1].strip()
        try:
            value = int(immediate, 0) & 0xFFFF_FFFF
        except ValueError:
            value = None
        if value is not None:
            return (
                f"pub fn {rust_name}(state: &mut CpuState, _memory: &mut [u8]) -> Result<(), Trap> {{\n"
                f"    state.eax = 0x{value:08x};\n"
                "    state.return_from_guest()?;\n"
                "    Ok(())\n"
                "}\n",
                "generated",
            )
    lines = [
        f"pub fn {rust_name}(_state: &mut CpuState, _memory: &mut [u8]) -> Result<(), Trap> {{",
        "    // Structured specification exists, but this implementation requires review.",
        "    Err(Trap::NeedsReview)",
        "}",
        "",
    ]
    return "\n".join(lines), "needs_review"


def translate_function_semantics(
    store: TranslationStore,
    run_id: str,
    function_id: str,
) -> dict[str, Any]:
    function = store.connection.execute(
        "SELECT * FROM functions WHERE function_id=? AND run_id=?",
        (function_id, run_id),
    ).fetchone()
    if function is None:
        raise KeyError(f"unknown function: {function_id}")
    revision_ids = [
        str(row[0])
        for row in store.connection.execute(
            """SELECT selected.revision_id
               FROM function_blocks AS membership
               JOIN run_block_selections AS selected
                 ON selected.block_key_id=membership.block_key_id
               WHERE membership.function_id=? AND selected.run_id=?
               ORDER BY membership.role='entry' DESC, selected.revision_id""",
            (function_id, run_id),
        )
    ]
    revisions = [store.load_revision(revision_id) for revision_id in revision_ids]
    instructions = [item for revision in revisions for item in revision["instructions"]]
    edges = [item for revision in revisions for item in revision["edges"]]
    provenance = {
        "function_id": function_id,
        "revision_ids": revision_ids,
        "instruction_ranges": [
            {
                "start_rva": int(revision["rva"]),
                "end_rva": (
                    int(revision["instructions"][-1]["rva"])
                    + int(revision["instructions"][-1]["size"])
                    if revision["instructions"]
                    else int(revision["rva"])
                ),
            }
            for revision in revisions
        ],
    }

    l0 = {
        "kind": "machine_facts",
        "address_width": 32,
        "wrapping": "two_complement_mod_2^32",
        "instructions": [
            {
                "rva": int(item["rva"]),
                "size": int(item["size"]),
                "bytes": bytes(item["bytes"]).hex(),
                "mnemonic": item["mnemonic"],
                "operands": item["op_str"],
            }
            for item in instructions
        ],
        "edges": edges,
    }
    l0_id = _artifact(store, run_id, "function", function_id, "L0", l0, provenance)

    l1_ops = []
    for index, item in enumerate(instructions):
        mnemonic = str(item["mnemonic"])
        l1_ops.append(
            {
                "id": f"t{index}",
                "opcode": mnemonic,
                "operands": item["op_str"],
                "width": int(item["size"]) * 8,
                "effects": {
                    "control": mnemonic.startswith("j") or mnemonic in {"call", "ret"},
                    "memory": "[" in str(item["op_str"]),
                    "flags": mnemonic in {"add", "sub", "cmp", "test", "and", "or", "xor", "shl", "shr", "sar"},
                },
                "provenance": {"rva": int(item["rva"])},
            }
        )
    l1 = {"kind": "micro_ir", "temporaries": l1_ops, "explicit_side_effects": True}
    l1_id = _artifact(store, run_id, "function", function_id, "L1", l1, provenance)

    back_edges = [
        edge
        for edge in edges
        if edge.get("target_rva") is not None
        and edge.get("source_instruction_rva") is not None
        and int(edge["target_rva"]) <= int(edge["source_instruction_rva"])
    ]
    calls = [edge for edge in edges if edge.get("kind") in {"call", "import_call", "import_jump"}]
    l2 = {
        "kind": "structured_algorithm",
        "entry_rva": int(function["primary_entry_rva"]),
        "blocks": [
            {
                "rva": int(revision["rva"]),
                "terminator": revision["terminator"],
                "successors": [edge.get("target_rva") for edge in revision["edges"]],
            }
            for revision in revisions
        ],
        "loops": [
            {
                "header_rva": int(edge["target_rva"]),
                "back_edge_rva": int(edge["source_instruction_rva"]),
            }
            for edge in back_edges
        ],
        "calls": calls,
        "state_machine": len(back_edges) > 1 and len(calls) > 1,
    }
    l2_id = _artifact(store, run_id, "function", function_id, "L2", l2, provenance)

    equations = [equation for item in instructions if (equation := _equation(item))]
    memory_instructions = [item for item in instructions if "[" in str(item["op_str"])]
    purpose = str(function["purpose"] or f"Function at RVA 0x{int(function['primary_entry_rva']):08x}")
    pseudocode = [
        f"block_0x{int(revision['rva']):08x}: {revision['terminator']}"
        for revision in revisions
    ]
    blockers = []
    if any(revision.get("unsupported_reason") for revision in revisions):
        blockers.append("contains unsupported or unresolved machine semantics")
    l3 = {
        "kind": "semantic_specification",
        "purpose": purpose,
        "calling_convention": "x86-32 preserved; stack cleanup inferred per return/import",
        "inputs": ["register state", "stack arguments", "guest memory", "global runtime state"],
        "outputs": ["eax/register results", "flags", "guest-memory effects", "external events"],
        "memory": {
            "access_count": len(memory_instructions),
            "instructions": [int(item["rva"]) for item in memory_instructions],
        },
        "equations": equations,
        "pseudocode": pseudocode,
        "preconditions": ["mapped guest stack", "valid guest pointers for observed memory operands"],
        "postconditions": ["32-bit wrapping and x86 flags match L0/L1 facts"],
        "invariants": [
            "stack return address remains ABI-valid",
            *[
                f"loop at 0x{int(edge['target_rva']):08x} preserves explicit guest state"
                for edge in back_edges
            ],
        ],
        "external_dependencies": calls,
        "uncertainty": blockers,
        "provenance": provenance,
    }
    markdown = (
        f"# {function['name'] or f'Function 0x{int(function['primary_entry_rva']):08x}'}\n\n"
        f"{purpose}\n\n"
        "## Pseudocode\n\n"
        + "\n".join(f"- `{line}`" for line in pseudocode)
        + "\n\n## Equations\n\n"
        + ("\n".join(f"- `{equation}`" for equation in equations) or "- None inferred")
        + "\n"
    )
    l3_id = _artifact(
        store,
        run_id,
        "function",
        function_id,
        "L3",
        l3,
        provenance,
        markdown=markdown,
        confidence=float(function["confidence"]),
        state="blocked" if blockers else "complete",
    )

    rust_source, implementation_status = _rust_source(dict(function), instructions)
    l4 = {
        "kind": "reimplementation",
        "language": "rust",
        "source": rust_source,
        "status": implementation_status,
        "semantic_specification_id": l3_id,
    }
    l4_id = _artifact(
        store,
        run_id,
        "function",
        function_id,
        "L4",
        l4,
        provenance,
        markdown=f"```rust\n{rust_source}```\n",
        confidence=1.0 if implementation_status == "generated" else 0.5,
        state=implementation_status,
    )
    implementation_id = stable_hash("d2wasm-implementation-v1", function_id, rust_source)
    with store.transaction(immediate=True):
        store.connection.execute(
            """INSERT OR IGNORE INTO implementation_artifacts
               (implementation_id, run_id, function_id, language, source_hash,
                source, semantic_artifact_id, status, created_at)
               VALUES (?, ?, ?, 'rust', ?, ?, ?, ?, ?)""",
            (
                implementation_id,
                run_id,
                function_id,
                stable_hash("d2wasm-source-v1", rust_source),
                rust_source,
                l3_id,
                implementation_status,
                _utc_now(),
            ),
        )
        for kind, statement in (
            ("purpose", {"text": purpose}),
            ("calling_convention", {"text": l3["calling_convention"]}),
            ("memory_effects", l3["memory"]),
            ("invariants", {"items": l3["invariants"]}),
        ):
            fact_id = stable_hash("d2wasm-semantic-fact-v1", l3_id, kind, statement)
            store.connection.execute(
                """INSERT OR IGNORE INTO semantic_facts
                   (fact_id, artifact_id, kind, statement_json, provenance_json,
                    confidence, reviewer_status, assumptions_json, questions_json)
                   VALUES (?, ?, ?, ?, ?, ?, 'unreviewed', '[]', ?)""",
                (
                    fact_id,
                    l3_id,
                    kind,
                    canonical_json(statement),
                    canonical_json(provenance),
                    float(function["confidence"]),
                    canonical_json(blockers),
                ),
            )
    return {
        "function_id": function_id,
        "artifacts": {"L0": l0_id, "L1": l1_id, "L2": l2_id, "L3": l3_id, "L4": l4_id},
        "implementation_id": implementation_id,
        "implementation_status": implementation_status,
        "blockers": blockers,
    }


def translate_all_semantics(store: TranslationStore, run_id: str) -> dict[str, Any]:
    function_ids = [
        str(row[0])
        for row in store.connection.execute(
            "SELECT function_id FROM functions WHERE run_id=? ORDER BY module_version_id, primary_entry_rva",
            (run_id,),
        )
    ]
    reports = [translate_function_semantics(store, run_id, function_id) for function_id in function_ids]
    return {
        "function_count": len(reports),
        "generated_implementations": sum(report["implementation_status"] == "generated" for report in reports),
        "needs_review": sum(report["implementation_status"] != "generated" for report in reports),
        "blocked_specs": sum(bool(report["blockers"]) for report in reports),
    }
