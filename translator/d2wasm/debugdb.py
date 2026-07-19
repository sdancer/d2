from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Iterable

from capstone import CS_GRP_CALL, CS_GRP_JUMP
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

from .analysis import classify_executable_bytes, summarize_graph_accounting
from .cfg import Block
from .pe import PEImage
from .workspace import TranslationStore


SCHEMA_VERSION = 1


@dataclass(frozen=True)
class DebugUnit:
    runtime_name: str
    source: str
    load_base: int
    roots: tuple[int, ...]
    image: PEImage
    blocks: dict[int, Block]


SCHEMA = """
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE modules (
    id INTEGER PRIMARY KEY,
    runtime_name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    source TEXT NOT NULL,
    image_base INTEGER NOT NULL,
    load_base INTEGER NOT NULL,
    image_size INTEGER NOT NULL,
    entry_rva INTEGER NOT NULL,
    entry_va INTEGER NOT NULL
);

CREATE TABLE sections (
    module_id INTEGER NOT NULL REFERENCES modules(id),
    name TEXT NOT NULL,
    rva INTEGER NOT NULL,
    va INTEGER NOT NULL,
    virtual_size INTEGER NOT NULL,
    file_size INTEGER NOT NULL,
    executable INTEGER NOT NULL,
    PRIMARY KEY (module_id, rva)
) WITHOUT ROWID;

CREATE TABLE roots (
    module_id INTEGER NOT NULL REFERENCES modules(id),
    rva INTEGER NOT NULL,
    va INTEGER NOT NULL,
    PRIMARY KEY (module_id, rva)
) WITHOUT ROWID;

CREATE TABLE blocks (
    va INTEGER PRIMARY KEY,
    module_id INTEGER NOT NULL REFERENCES modules(id),
    rva INTEGER NOT NULL,
    terminator TEXT NOT NULL,
    instruction_count INTEGER NOT NULL,
    unsupported_reason TEXT,
    import_library TEXT,
    import_name TEXT,
    import_ordinal INTEGER
);

CREATE TABLE instructions (
    id INTEGER PRIMARY KEY,
    va INTEGER NOT NULL,
    module_id INTEGER NOT NULL REFERENCES modules(id),
    block_va INTEGER NOT NULL REFERENCES blocks(va),
    rva INTEGER NOT NULL,
    sequence INTEGER NOT NULL,
    size INTEGER NOT NULL,
    bytes BLOB NOT NULL,
    mnemonic TEXT NOT NULL,
    op_str TEXT NOT NULL,
    UNIQUE (block_va, sequence)
);

CREATE TABLE edges (
    source_block_va INTEGER NOT NULL REFERENCES blocks(va),
    source_instruction_va INTEGER NOT NULL,
    target_block_va INTEGER NOT NULL,
    kind TEXT NOT NULL,
    PRIMARY KEY (source_block_va, target_block_va, kind)
) WITHOUT ROWID;

CREATE TABLE xrefs (
    source_va INTEGER NOT NULL,
    target_va INTEGER NOT NULL,
    kind TEXT NOT NULL,
    operand_index INTEGER NOT NULL DEFAULT -1,
    target_module_id INTEGER REFERENCES modules(id),
    PRIMARY KEY (source_va, target_va, kind, operand_index)
) WITHOUT ROWID;

CREATE TABLE imports (
    module_id INTEGER NOT NULL REFERENCES modules(id),
    library TEXT NOT NULL COLLATE NOCASE,
    name TEXT,
    ordinal INTEGER,
    iat_rva INTEGER NOT NULL,
    iat_va INTEGER NOT NULL,
    target_module_id INTEGER REFERENCES modules(id),
    target_va INTEGER,
    resolved INTEGER NOT NULL,
    PRIMARY KEY (module_id, iat_rva)
) WITHOUT ROWID;

CREATE TABLE exports (
    module_id INTEGER NOT NULL REFERENCES modules(id),
    name TEXT,
    ordinal INTEGER NOT NULL,
    rva INTEGER NOT NULL,
    va INTEGER NOT NULL,
    PRIMARY KEY (module_id, ordinal)
) WITHOUT ROWID;

CREATE TABLE strings (
    module_id INTEGER NOT NULL REFERENCES modules(id),
    va INTEGER NOT NULL,
    rva INTEGER NOT NULL,
    encoding TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (module_id, va, encoding)
) WITHOUT ROWID;

CREATE INDEX instructions_block ON instructions(block_va, sequence);
CREATE INDEX instructions_va ON instructions(va);
CREATE INDEX instructions_mnemonic ON instructions(mnemonic);
CREATE INDEX edges_target ON edges(target_block_va, kind);
CREATE INDEX xrefs_target ON xrefs(target_va, kind);
CREATE INDEX xrefs_source ON xrefs(source_va, kind);
CREATE INDEX strings_value ON strings(value);
CREATE INDEX imports_symbol ON imports(library, name, ordinal);
CREATE INDEX exports_name ON exports(name);

CREATE VIEW call_xrefs AS
SELECT DISTINCT x.source_va, x.target_va, source.runtime_name AS source_module,
       target.runtime_name AS target_module
FROM xrefs AS x
JOIN instructions AS instruction ON instruction.va = x.source_va
JOIN modules AS source ON source.id = instruction.module_id
LEFT JOIN modules AS target ON target.id = x.target_module_id
WHERE x.kind IN ('call', 'import_call');

CREATE VIEW string_xrefs AS
SELECT DISTINCT x.source_va, x.target_va, source.runtime_name AS source_module,
       string.value, string.encoding
FROM xrefs AS x
JOIN instructions AS instruction ON instruction.va = x.source_va
JOIN modules AS source ON source.id = instruction.module_id
JOIN strings AS string ON string.va = x.target_va
WHERE x.kind = 'data';
"""


def _module_for_va(
    ranges: list[tuple[int, int, int]], value: int
) -> tuple[int, int, int] | None:
    return next((item for item in ranges if item[0] <= value < item[1]), None)


def _linked_target(
    preferred_ranges: list[tuple[int, int, int, int]], value: int
) -> int:
    for start, end, load_base, _ in preferred_ranges:
        if start <= value < end:
            return load_base + value - start
    return value & 0xFFFF_FFFF


def _edge_kinds(block: Block) -> list[str]:
    count = len(block.successors)
    if block.terminator == "call" and count == 2:
        return ["call", "call_fallthrough"]
    if block.terminator == "conditional" and count == 2:
        return ["branch", "branch_fallthrough"]
    if block.terminator == "jump_table":
        return ["jump_table"] * count
    if block.terminator in ("jump", "fallthrough"):
        return [block.terminator] * count
    return [block.terminator] * count


def extract_strings(image: PEImage) -> Iterable[tuple[int, str, str]]:
    for section in image.binary.sections:
        if section in image.executable_sections():
            continue
        content = bytes(section.content)
        section_rva = int(section.virtual_address)
        for match in re.finditer(rb"[\x20-\x7e]{4,}", content):
            yield section_rva + match.start(), "ascii", match.group().decode("ascii")
        for match in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", content):
            yield (
                section_rva + match.start(),
                "utf16le",
                match.group().decode("utf-16le"),
            )


def _extract_strings(unit: DebugUnit) -> Iterable[tuple[int, int, str, str]]:
    for rva, encoding, value in extract_strings(unit.image):
        yield unit.load_base + rva, rva, encoding, value


def _write_debug_database_v1(
    path: Path,
    manifest: dict[str, Any],
    units: list[DebugUnit],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            "PRAGMA journal_mode=OFF;\n"
            "PRAGMA synchronous=OFF;\n"
            "PRAGMA temp_store=MEMORY;\n"
            "PRAGMA locking_mode=EXCLUSIVE;\n"
            + SCHEMA
        )
        connection.execute("BEGIN")
        connection.executemany(
            "INSERT INTO metadata(key, value) VALUES (?, ?)",
            [
                ("schema_version", str(SCHEMA_VERSION)),
                ("entry_va", str(int(manifest["entry_va"]))),
                ("link_manifest_schema", str(manifest.get("schema_version", ""))),
            ],
        )
        for module_id, unit in enumerate(units, 1):
            connection.execute(
                """INSERT INTO modules
                   (id, runtime_name, source, image_base, load_base, image_size,
                    entry_rva, entry_va)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    module_id,
                    unit.runtime_name,
                    unit.source,
                    unit.image.image_base,
                    unit.load_base,
                    unit.image.size_of_image,
                    unit.image.entry_rva,
                    unit.load_base + unit.image.entry_rva,
                ),
            )

        module_ids = {unit.runtime_name.lower(): index for index, unit in enumerate(units, 1)}
        linked_ranges = [
            (unit.load_base, unit.load_base + unit.image.size_of_image, module_id)
            for module_id, unit in enumerate(units, 1)
        ]
        preferred_ranges = [
            (
                unit.image.image_base,
                unit.image.image_base + unit.image.size_of_image,
                unit.load_base,
                module_id,
            )
            for module_id, unit in enumerate(units, 1)
        ]

        internal_bindings: dict[tuple[str, str, str], dict[str, Any]] = {}
        for binding in manifest.get("internal_bindings", []):
            symbol = binding["name"] or f"#{binding['ordinal']}"
            internal_bindings[
                (
                    binding["importer"].lower(),
                    binding["library"].lower(),
                    symbol,
                )
            ] = binding

        for module_id, unit in enumerate(units, 1):
            executable = set(unit.image.executable_sections())
            connection.executemany(
                """INSERT INTO sections
                   (module_id, name, rva, va, virtual_size, file_size, executable)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        module_id,
                        section.name,
                        int(section.virtual_address),
                        unit.load_base + int(section.virtual_address),
                        int(section.virtual_size),
                        len(section.content),
                        int(section in executable),
                    )
                    for section in unit.image.binary.sections
                ],
            )
            connection.executemany(
                "INSERT INTO roots(module_id, rva, va) VALUES (?, ?, ?)",
                [(module_id, root, unit.load_base + root) for root in unit.roots],
            )
            connection.executemany(
                """INSERT INTO exports(module_id, name, ordinal, rva, va)
                   VALUES (?, ?, ?, ?, ?)""",
                [
                    (
                        module_id,
                        export.get("name"),
                        int(export["ordinal"]),
                        int(export["rva"]),
                        unit.load_base + int(export["rva"]),
                    )
                    for export in next(
                        item["exports"]
                        for item in manifest["modules"]
                        if item["runtime_name"].lower() == unit.runtime_name.lower()
                    )
                ],
            )

            import_rows = []
            for symbol in unit.image.imports:
                key_name = symbol.name or f"#{symbol.ordinal}"
                binding = internal_bindings.get(
                    (unit.runtime_name.lower(), symbol.library.lower(), key_name)
                )
                target_module_id = (
                    module_ids.get(binding["target_module"].lower()) if binding else None
                )
                target_va = int(binding["target_va"]) if binding else None
                import_rows.append(
                    (
                        module_id,
                        symbol.library,
                        symbol.name,
                        symbol.ordinal,
                        symbol.iat_rva,
                        unit.load_base + symbol.iat_rva,
                        target_module_id,
                        target_va,
                        int(binding is not None),
                    )
                )
            connection.executemany(
                """INSERT INTO imports
                   (module_id, library, name, ordinal, iat_rva, iat_va,
                    target_module_id, target_va, resolved)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                import_rows,
            )

            block_rows = []
            instruction_rows = []
            edge_rows = []
            xref_rows: set[tuple[int, int, str, int, int | None]] = set()
            for block in unit.blocks.values():
                block_va = unit.load_base + block.rva
                imported = block.imported_call
                block_rows.append(
                    (
                        block_va,
                        module_id,
                        block.rva,
                        block.terminator,
                        len(block.instructions),
                        block.unsupported_reason,
                        imported.library if imported else None,
                        imported.name if imported else None,
                        imported.ordinal if imported else None,
                    )
                )
                for sequence, instruction in enumerate(block.instructions):
                    rva = int(instruction.address) - unit.image.image_base
                    va = unit.load_base + rva
                    instruction_rows.append(
                        (
                            va,
                            module_id,
                            block_va,
                            rva,
                            sequence,
                            int(instruction.size),
                            bytes(instruction.bytes),
                            instruction.mnemonic,
                            instruction.op_str,
                        )
                    )
                    is_control = instruction.group(CS_GRP_CALL) or instruction.group(
                        CS_GRP_JUMP
                    )
                    for operand_index, operand in enumerate(instruction.operands):
                        target = None
                        if operand.type == X86_OP_IMM and not is_control:
                            target = _linked_target(preferred_ranges, int(operand.imm))
                        elif (
                            operand.type == X86_OP_MEM
                            and int(operand.mem.base) == 0
                            and int(operand.mem.index) == 0
                        ):
                            target = _linked_target(preferred_ranges, int(operand.mem.disp))
                        if target is None:
                            continue
                        target_range = _module_for_va(linked_ranges, target)
                        if target_range is not None:
                            xref_rows.add(
                                (va, target, "data", operand_index, target_range[2])
                            )

                if not block.instructions:
                    continue
                source_instruction_va = unit.load_base + (
                    int(block.instructions[-1].address) - unit.image.image_base
                )
                for target_rva, kind in zip(block.successors, _edge_kinds(block)):
                    target_va = unit.load_base + target_rva
                    edge_rows.append((block_va, source_instruction_va, target_va, kind))
                    if kind in ("call", "branch", "jump", "jump_table"):
                        target_range = _module_for_va(linked_ranges, target_va)
                        xref_rows.add(
                            (
                                source_instruction_va,
                                target_va,
                                kind,
                                -1,
                                target_range[2] if target_range else None,
                            )
                        )
                if imported is not None:
                    symbol = imported.name or f"#{imported.ordinal}"
                    binding = internal_bindings.get(
                        (unit.runtime_name.lower(), imported.library.lower(), symbol)
                    )
                    if binding:
                        target_va = int(binding["target_va"])
                        target_module_id = module_ids.get(
                            binding["target_module"].lower()
                        )
                    else:
                        target_va = unit.load_base + imported.iat_rva
                        target_module_id = module_id
                    xref_rows.add(
                        (
                            source_instruction_va,
                            target_va,
                            "import_call",
                            -1,
                            target_module_id,
                        )
                    )

            connection.executemany(
                """INSERT INTO blocks
                   (va, module_id, rva, terminator, instruction_count,
                    unsupported_reason, import_library, import_name, import_ordinal)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                block_rows,
            )
            connection.executemany(
                """INSERT INTO instructions
                   (va, module_id, block_va, rva, sequence, size, bytes, mnemonic, op_str)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                instruction_rows,
            )
            connection.executemany(
                """INSERT INTO edges
                   (source_block_va, source_instruction_va, target_block_va, kind)
                   VALUES (?, ?, ?, ?)""",
                edge_rows,
            )
            connection.executemany(
                """INSERT INTO xrefs
                   (source_va, target_va, kind, operand_index, target_module_id)
                   VALUES (?, ?, ?, ?, ?)""",
                xref_rows,
            )
            connection.executemany(
                """INSERT OR IGNORE INTO strings
                   (module_id, va, rva, encoding, value) VALUES (?, ?, ?, ?, ?)""",
                [
                    (module_id, va, rva, encoding, value)
                    for va, rva, encoding, value in _extract_strings(unit)
                ],
            )

        connection.execute(
            "INSERT INTO metadata(key, value) VALUES (?, ?)",
            (
                "summary",
                json.dumps(
                    {
                        "modules": len(units),
                        "blocks": sum(len(unit.blocks) for unit in units),
                        "instructions": sum(
                            len(block.instructions)
                            for unit in units
                            for block in unit.blocks.values()
                        ),
                    },
                    sort_keys=True,
                ),
            ),
        )
        connection.commit()
        connection.execute("PRAGMA optimize")
    finally:
        connection.close()


def write_debug_database(
    path: Path,
    manifest: dict[str, Any],
    units: list[DebugUnit],
) -> None:
    """Persist a supplied graph through the durable schema-v2 workspace API."""

    with TranslationStore(path) as store:
        project_id = store.register_project(manifest, name=path.stem)
        module_versions: dict[str, str] = {}
        for unit in units:
            inventory = unit.image.inventory(unit.runtime_name)
            module_versions[unit.runtime_name.lower()] = store.register_module(
                project_id,
                {
                    **inventory,
                    "runtime_name": unit.runtime_name,
                    "source": unit.source,
                    "load_base": unit.load_base,
                },
                binary_data=unit.image.data,
                inventory=inventory,
            )
        for unit in units:
            store.register_static_inventory(
                module_versions[unit.runtime_name.lower()],
                unit.image.inventory(unit.runtime_name),
                internal_bindings=manifest.get("internal_bindings", []),
                strings=extract_strings(unit.image),
            )

        tool_version_id = store.register_tool_version(
            "debugdb-compatibility-writer", "2", options={"source": "DebugUnit"}
        )
        roots_input = {
            unit.runtime_name: list(unit.roots) for unit in units
        }
        run_id = store.register_analysis_run(
            project_id,
            tool_version_id,
            {"mode": "compatibility_import"},
            {"roots": roots_input},
            status="running",
        )
        for unit in units:
            module_version_id = module_versions[unit.runtime_name.lower()]
            for root in unit.roots:
                accepted = unit.image.is_executable_rva(root)
                store.register_root_fact(
                    run_id,
                    module_version_id,
                    root,
                    "compatibility_root",
                    confidence=1.0,
                    accepted=accepted,
                    resolution=(
                        "resolved_executable"
                        if accepted
                        else (
                            "non_executable"
                            if unit.image.section_for_rva(root) is not None
                            else "unmapped"
                        )
                    ),
                )

        linked_ranges = [
            (
                unit.load_base,
                unit.load_base + unit.image.size_of_image,
                module_versions[unit.runtime_name.lower()],
            )
            for unit in units
        ]
        internal_bindings: dict[tuple[str, str, str], dict[str, Any]] = {}
        for binding in manifest.get("internal_bindings", []):
            symbol = binding["name"] or f"#{binding['ordinal']}"
            internal_bindings[
                (
                    binding["importer"].lower(),
                    binding["library"].lower(),
                    symbol,
                )
            ] = binding

        for unit in units:
            module_version_id = module_versions[unit.runtime_name.lower()]
            unit_preferred_ranges = [
                (
                    unit.image.image_base,
                    unit.image.image_base + unit.image.size_of_image,
                    unit.load_base,
                    module_version_id,
                )
            ]
            for block in unit.blocks.values():
                edges = []
                xrefs = []
                source_rva = (
                    int(block.instructions[-1].address) - unit.image.image_base
                    if block.instructions
                    else block.rva
                )
                for target_rva, kind in zip(block.successors, _edge_kinds(block)):
                    edges.append(
                        {
                            "source_instruction_rva": source_rva,
                            "target_module_version_id": module_version_id,
                            "target_rva": target_rva,
                            "kind": kind,
                            "evidence_kind": "compatibility_graph",
                            "resolution": (
                                "resolved_executable"
                                if target_rva in unit.blocks
                                else "pending"
                            ),
                        }
                    )
                    if kind in ("call", "branch", "jump", "jump_table"):
                        xrefs.append(
                            {
                                "source_rva": source_rva,
                                "target_module_version_id": module_version_id,
                                "target_rva": target_rva,
                                "target_va": unit.load_base + target_rva,
                                "kind": kind,
                            }
                        )
                for instruction in block.instructions:
                    instruction_rva = int(instruction.address) - unit.image.image_base
                    is_control = instruction.group(CS_GRP_CALL) or instruction.group(
                        CS_GRP_JUMP
                    )
                    for operand_index, operand in enumerate(instruction.operands):
                        target = None
                        if operand.type == X86_OP_IMM and not is_control:
                            target = _linked_target(unit_preferred_ranges, int(operand.imm))
                        elif (
                            operand.type == X86_OP_MEM
                            and int(operand.mem.base) == 0
                            and int(operand.mem.index) == 0
                        ):
                            target = _linked_target(
                                unit_preferred_ranges, int(operand.mem.disp)
                            )
                        if target is None:
                            continue
                        target_range = _module_for_va(linked_ranges, target)
                        if target_range is not None:
                            xrefs.append(
                                {
                                    "source_rva": instruction_rva,
                                    "target_module_version_id": target_range[2],
                                    "target_rva": target - target_range[0],
                                    "target_va": target,
                                    "kind": "data",
                                    "operand_index": operand_index,
                                }
                            )
                imported = block.imported_call
                if imported is not None and block.instructions:
                    symbol = imported.name or f"#{imported.ordinal}"
                    binding = internal_bindings.get(
                        (unit.runtime_name.lower(), imported.library.lower(), symbol)
                    )
                    if binding is not None:
                        target_va = int(binding["target_va"])
                        target_module_version_id = module_versions.get(
                            binding["target_module"].lower()
                        )
                        target_rva = int(binding["target_rva"])
                    else:
                        target_va = unit.load_base + imported.iat_rva
                        target_module_version_id = module_version_id
                        target_rva = imported.iat_rva
                    xrefs.append(
                        {
                            "source_rva": source_rva,
                            "target_module_version_id": target_module_version_id,
                            "target_rva": target_rva,
                            "target_va": target_va,
                            "kind": "import_call",
                        }
                    )
                store.persist_block_revision(
                    run_id,
                    module_version_id,
                    block.rva,
                    instructions=block.instructions,
                    edges=edges,
                    xrefs=xrefs,
                    terminator=block.terminator,
                    unsupported_reason=block.unsupported_reason,
                    imported_call=block.imported_call,
                    facts={"source": "DebugUnit"},
                    refresh_projection=False,
                )

            classifications, byte_metrics = classify_executable_bytes(
                unit.image,
                unit.blocks,
            )
            store.save_byte_classifications(
                run_id,
                module_version_id,
                [item.to_dict() for item in classifications],
                mapped_executable_bytes=byte_metrics["mapped_executable_bytes"],
            )
            stored_edges = [
                dict(row)
                for row in store.connection.execute(
                    """SELECT edge.* FROM run_block_selections AS selection
                       JOIN block_keys AS block
                         ON block.block_key_id=selection.block_key_id
                       JOIN revision_edges AS edge
                         ON edge.revision_id=selection.revision_id
                       WHERE selection.run_id=? AND block.module_version_id=?""",
                    (run_id, module_version_id),
                )
            ]
            metrics = summarize_graph_accounting(
                byte_metrics,
                unit.blocks,
                stored_edges,
                {"unfinished": 0, "blocked": 0},
            )
            store.save_graph_accounting(run_id, module_version_id, metrics)

        store.refresh_compatibility_projection(run_id)
        store.set_run_status(run_id, "completed")
        summary = {
            "modules": len(units),
            "blocks": sum(len(unit.blocks) for unit in units),
            "instructions": sum(
                len(block.instructions)
                for unit in units
                for block in unit.blocks.values()
            ),
        }
        with store.transaction(immediate=True):
            store.connection.execute(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES ('summary', ?)",
                (json.dumps(summary, sort_keys=True),),
            )
