from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Iterable, Iterator, Mapping, Sequence


DATABASE_SCHEMA_VERSION = 2
DEFAULT_BUSY_TIMEOUT_MS = 30_000
DEFAULT_LEASE_SECONDS = 300.0

WORK_STATES = frozenset(
    {
        "pending",
        "leased",
        "completed",
        "blocked",
        "unsupported",
        "ambiguous",
        "failed",
    }
)
TERMINAL_WORK_STATES = frozenset(
    {"completed", "blocked", "unsupported", "ambiguous", "failed"}
)
RETRYABLE_WORK_STATES = frozenset({"blocked", "unsupported", "ambiguous", "failed"})
BYTE_CLASSIFICATIONS = frozenset(
    {"confirmed_code", "probable_code", "embedded_data", "padding", "unresolved"}
)
EDGE_RESOLUTIONS = frozenset(
    {
        "resolved_executable",
        "pending",
        "internal_import",
        "external_import",
        "non_executable",
        "unmapped",
        "unresolved_indirect",
        "ambiguous",
        "blocked",
        "rejected",
    }
)

_NON_IDENTITY_MANIFEST_KEYS = frozenset(
    {
        "generated_at",
        "link_manifest",
        "output",
        "output_dir",
        "path",
        "source",
        "source_dir",
    }
)


class WorkspaceError(RuntimeError):
    """Base error for persistent translation workspace failures."""


class SchemaVersionError(WorkspaceError):
    """Raised when a database schema cannot be opened safely."""


class LeaseError(WorkspaceError):
    """Raised when a worker attempts to finish work it does not own."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, Mapping):
        return {
            str(key): _jsonable(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (set, frozenset)):
        normalized = [_jsonable(item) for item in value]
        return sorted(normalized, key=lambda item: canonical_json(item))
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"$bytes": bytes(value).hex()}
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("non-finite floats are not valid canonical data")
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if hasattr(value, "__dict__"):
        return _jsonable(vars(value))
    raise TypeError(f"cannot encode {type(value).__name__} as canonical JSON")


def canonical_json(value: Any) -> str:
    """Return a deterministic, UTF-8-safe JSON representation."""

    return json.dumps(
        _jsonable(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def stable_hash(domain: str, *values: Any) -> str:
    """Hash structured values with unambiguous framing and domain separation."""

    digest = sha256()
    encoded_domain = domain.encode("utf-8")
    digest.update(len(encoded_domain).to_bytes(4, "big"))
    digest.update(encoded_domain)
    for value in values:
        encoded = canonical_json(value).encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _merge_entry_states(
    left: Mapping[str, Any] | None,
    right: Mapping[str, Any] | None,
) -> dict[str, Any]:
    left = left or {}
    right = right or {}
    left_constants = dict(left.get("constants", {}))
    right_constants = dict(right.get("constants", {}))
    left_imports = dict(left.get("imports", {}))
    right_imports = dict(right.get("imports", {}))
    return {
        "constants": {
            register: value
            for register, value in left_constants.items()
            if right_constants.get(register) == value
        },
        "imports": {
            register: value
            for register, value in left_imports.items()
            if right_imports.get(register) == value
        },
    }


def canonical_manifest_data(value: Any) -> Any:
    """Remove location/report noise while retaining translation identity data."""

    if isinstance(value, Mapping):
        return {
            str(key): canonical_manifest_data(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            if str(key).lower() not in _NON_IDENTITY_MANIFEST_KEYS
        }
    if isinstance(value, (list, tuple)):
        return [canonical_manifest_data(item) for item in value]
    if isinstance(value, (set, frozenset)):
        result = [canonical_manifest_data(item) for item in value]
        return sorted(result, key=canonical_json)
    return _jsonable(value)


def project_identity(manifest: Mapping[str, Any]) -> str:
    return stable_hash("d2wasm-project-v2", canonical_manifest_data(manifest))


def binary_identity(binary_sha256: str) -> str:
    normalized = binary_sha256.lower()
    if len(normalized) != 64 or any(character not in "0123456789abcdef" for character in normalized):
        raise ValueError("binary SHA-256 must be 64 hexadecimal characters")
    return stable_hash("d2wasm-binary-v2", normalized)


def module_identity(
    project_id: str,
    runtime_name: str,
    binary_sha256: str,
    *,
    image_base: int,
    load_base: int,
    image_size: int,
    entry_rva: int,
) -> str:
    return stable_hash(
        "d2wasm-module-v2",
        project_id,
        runtime_name.casefold(),
        binary_sha256.lower(),
        int(image_base),
        int(load_base),
        int(image_size),
        int(entry_rva),
    )


def block_identity(module_version_id: str, rva: int) -> str:
    normalized_rva = int(rva)
    if not 0 <= normalized_rva <= 0xFFFF_FFFF:
        raise ValueError("block RVA must be an unsigned 32-bit value")
    return stable_hash("d2wasm-block-v2", module_version_id, normalized_rva)


def revision_identity(block_key_id: str, facts: Mapping[str, Any]) -> str:
    return stable_hash("d2wasm-block-revision-v2", block_key_id, facts)


_COMPATIBILITY_SCHEMA = """
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


_V2_SCHEMA = """
CREATE TABLE IF NOT EXISTS migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS projects (
    project_id TEXT PRIMARY KEY,
    name TEXT,
    manifest_hash TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL
) WITHOUT ROWID;
CREATE UNIQUE INDEX IF NOT EXISTS projects_manifest_hash ON projects(manifest_hash);

CREATE TABLE IF NOT EXISTS binary_images (
    binary_image_id TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL UNIQUE COLLATE NOCASE,
    byte_size INTEGER NOT NULL CHECK (byte_size >= 0),
    content_available INTEGER NOT NULL DEFAULT 0 CHECK (content_available IN (0, 1)),
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS module_versions (
    module_version_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    binary_image_id TEXT NOT NULL REFERENCES binary_images(binary_image_id),
    runtime_name TEXT NOT NULL COLLATE NOCASE,
    source TEXT NOT NULL,
    image_base INTEGER NOT NULL,
    load_base INTEGER NOT NULL,
    image_size INTEGER NOT NULL CHECK (image_size >= 0),
    entry_rva INTEGER NOT NULL,
    inventory_json TEXT NOT NULL,
    compatibility_module_id INTEGER REFERENCES modules(id),
    created_at TEXT NOT NULL,
    UNIQUE (project_id, runtime_name, binary_image_id, load_base)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS module_versions_runtime_name
    ON module_versions(project_id, runtime_name COLLATE NOCASE);

CREATE TABLE IF NOT EXISTS tool_versions (
    tool_version_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    executable_hash TEXT,
    options_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (name, version, executable_hash, options_json)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS analysis_runs (
    run_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    tool_version_id TEXT NOT NULL REFERENCES tool_versions(tool_version_id),
    configuration_hash TEXT NOT NULL,
    input_hash TEXT NOT NULL,
    configuration_json TEXT NOT NULL,
    input_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('created', 'running', 'paused', 'completed', 'failed', 'cancelled')
    ),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE (project_id, tool_version_id, configuration_hash, input_hash)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS analysis_runs_project ON analysis_runs(project_id, created_at);

CREATE TABLE IF NOT EXISTS root_facts (
    root_fact_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
    module_version_id TEXT NOT NULL REFERENCES module_versions(module_version_id),
    rva INTEGER NOT NULL,
    va INTEGER NOT NULL,
    kind TEXT NOT NULL,
    evidence TEXT NOT NULL,
    confidence REAL,
    accepted INTEGER NOT NULL CHECK (accepted IN (0, 1)),
    resolution TEXT NOT NULL,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS root_facts_target
    ON root_facts(run_id, module_version_id, rva);

CREATE TABLE IF NOT EXISTS work_items (
    work_item_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
    module_version_id TEXT NOT NULL REFERENCES module_versions(module_version_id),
    kind TEXT NOT NULL,
    item_key TEXT NOT NULL,
    target_rva INTEGER,
    entry_state_hash TEXT NOT NULL,
    entry_state_json TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    pending_entry_state_hash TEXT,
    pending_entry_state_json TEXT,
    pending_payload_json TEXT,
    state TEXT NOT NULL CHECK (
        state IN ('pending', 'leased', 'completed', 'blocked', 'unsupported', 'ambiguous', 'failed')
    ),
    priority INTEGER NOT NULL DEFAULT 0,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    retry_count INTEGER NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
    max_attempts INTEGER NOT NULL DEFAULT 0 CHECK (max_attempts >= 0),
    available_at REAL NOT NULL DEFAULT 0,
    lease_owner TEXT,
    lease_token TEXT,
    lease_expires_at REAL,
    last_error TEXT,
    selected_revision_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    finished_at TEXT,
    UNIQUE (run_id, module_version_id, kind, item_key)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS work_items_claim
    ON work_items(run_id, state, available_at, priority DESC, created_at);
CREATE INDEX IF NOT EXISTS work_items_lease ON work_items(state, lease_expires_at);
CREATE INDEX IF NOT EXISTS work_items_target
    ON work_items(run_id, module_version_id, target_rva, kind);

CREATE TABLE IF NOT EXISTS work_attempts (
    attempt_id INTEGER PRIMARY KEY,
    work_item_id TEXT NOT NULL REFERENCES work_items(work_item_id) ON DELETE CASCADE,
    attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
    worker_id TEXT NOT NULL,
    lease_token TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK (
        state IN ('leased', 'completed', 'blocked', 'unsupported', 'ambiguous',
                  'failed', 'expired', 'abandoned')
    ),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    error TEXT,
    result_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (work_item_id, attempt_number)
);
CREATE INDEX IF NOT EXISTS work_attempts_item
    ON work_attempts(work_item_id, attempt_number);

CREATE TABLE IF NOT EXISTS block_keys (
    block_key_id TEXT PRIMARY KEY,
    module_version_id TEXT NOT NULL REFERENCES module_versions(module_version_id),
    rva INTEGER NOT NULL,
    va INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (module_version_id, rva)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS block_revisions (
    revision_id TEXT PRIMARY KEY,
    block_key_id TEXT NOT NULL REFERENCES block_keys(block_key_id),
    revision_hash TEXT NOT NULL,
    entry_state_hash TEXT NOT NULL,
    entry_state_json TEXT NOT NULL,
    terminator TEXT NOT NULL,
    unsupported_reason TEXT,
    import_library TEXT,
    import_name TEXT,
    import_ordinal INTEGER,
    import_iat_rva INTEGER,
    instruction_count INTEGER NOT NULL CHECK (instruction_count >= 0),
    byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
    facts_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (block_key_id, revision_hash),
    UNIQUE (revision_id, block_key_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS block_revisions_key ON block_revisions(block_key_id, created_at);

CREATE TABLE IF NOT EXISTS revision_instructions (
    revision_id TEXT NOT NULL REFERENCES block_revisions(revision_id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    rva INTEGER NOT NULL,
    size INTEGER NOT NULL CHECK (size > 0),
    bytes BLOB NOT NULL,
    mnemonic TEXT NOT NULL,
    op_str TEXT NOT NULL,
    details_json TEXT NOT NULL,
    PRIMARY KEY (revision_id, sequence),
    UNIQUE (revision_id, rva)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS revision_edges (
    revision_id TEXT NOT NULL REFERENCES block_revisions(revision_id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    source_instruction_rva INTEGER,
    target_module_version_id TEXT REFERENCES module_versions(module_version_id),
    target_rva INTEGER,
    target_va INTEGER,
    kind TEXT NOT NULL,
    evidence_kind TEXT NOT NULL,
    resolution TEXT NOT NULL,
    operand_index INTEGER NOT NULL DEFAULT -1,
    table_slot_rva INTEGER,
    table_index INTEGER,
    details_json TEXT NOT NULL,
    PRIMARY KEY (revision_id, sequence)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS revision_edges_target
    ON revision_edges(target_module_version_id, target_rva, resolution);
CREATE INDEX IF NOT EXISTS revision_edges_resolution ON revision_edges(resolution, kind);

CREATE TABLE IF NOT EXISTS revision_xrefs (
    revision_id TEXT NOT NULL REFERENCES block_revisions(revision_id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    source_rva INTEGER NOT NULL,
    target_module_version_id TEXT REFERENCES module_versions(module_version_id),
    target_rva INTEGER,
    target_va INTEGER NOT NULL,
    kind TEXT NOT NULL,
    operand_index INTEGER NOT NULL DEFAULT -1,
    details_json TEXT NOT NULL,
    PRIMARY KEY (revision_id, sequence)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS revision_xrefs_target
    ON revision_xrefs(target_module_version_id, target_rva, kind);

CREATE TABLE IF NOT EXISTS run_block_selections (
    run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
    block_key_id TEXT NOT NULL REFERENCES block_keys(block_key_id),
    revision_id TEXT NOT NULL REFERENCES block_revisions(revision_id),
    selected_at TEXT NOT NULL,
    PRIMARY KEY (run_id, block_key_id),
    FOREIGN KEY (revision_id, block_key_id)
        REFERENCES block_revisions(revision_id, block_key_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS run_block_selections_revision
    ON run_block_selections(revision_id);

CREATE TABLE IF NOT EXISTS executable_byte_classifications (
    run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
    module_version_id TEXT NOT NULL REFERENCES module_versions(module_version_id),
    start_rva INTEGER NOT NULL,
    end_rva INTEGER NOT NULL,
    classification TEXT NOT NULL CHECK (
        classification IN ('confirmed_code', 'probable_code', 'embedded_data', 'padding', 'unresolved')
    ),
    evidence TEXT NOT NULL,
    details_json TEXT NOT NULL,
    PRIMARY KEY (run_id, module_version_id, start_rva, end_rva),
    CHECK (end_rva > start_rva)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS byte_classifications_category
    ON executable_byte_classifications(run_id, module_version_id, classification);

CREATE TABLE IF NOT EXISTS graph_accounting (
    run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
    module_version_id TEXT NOT NULL REFERENCES module_versions(module_version_id),
    mapped_executable_bytes INTEGER NOT NULL DEFAULT 0 CHECK (mapped_executable_bytes >= 0),
    classified_executable_bytes INTEGER NOT NULL DEFAULT 0 CHECK (classified_executable_bytes >= 0),
    confirmed_code_bytes INTEGER NOT NULL DEFAULT 0 CHECK (confirmed_code_bytes >= 0),
    probable_code_bytes INTEGER NOT NULL DEFAULT 0 CHECK (probable_code_bytes >= 0),
    embedded_data_bytes INTEGER NOT NULL DEFAULT 0 CHECK (embedded_data_bytes >= 0),
    padding_bytes INTEGER NOT NULL DEFAULT 0 CHECK (padding_bytes >= 0),
    unresolved_bytes INTEGER NOT NULL DEFAULT 0 CHECK (unresolved_bytes >= 0),
    resolved_direct_edges INTEGER NOT NULL DEFAULT 0 CHECK (resolved_direct_edges >= 0),
    rejected_direct_edges INTEGER NOT NULL DEFAULT 0 CHECK (rejected_direct_edges >= 0),
    unresolved_indirect_calls INTEGER NOT NULL DEFAULT 0 CHECK (unresolved_indirect_calls >= 0),
    unresolved_indirect_jumps INTEGER NOT NULL DEFAULT 0 CHECK (unresolved_indirect_jumps >= 0),
    blocked_targets INTEGER NOT NULL DEFAULT 0 CHECK (blocked_targets >= 0),
    overlaps_conflicts INTEGER NOT NULL DEFAULT 0 CHECK (overlaps_conflicts >= 0),
    selected_blocks INTEGER NOT NULL DEFAULT 0 CHECK (selected_blocks >= 0),
    selected_instructions INTEGER NOT NULL DEFAULT 0 CHECK (selected_instructions >= 0),
    pending_work INTEGER NOT NULL DEFAULT 0 CHECK (pending_work >= 0),
    metrics_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (run_id, module_version_id),
    CHECK (classified_executable_bytes = confirmed_code_bytes + probable_code_bytes +
           embedded_data_bytes + padding_bytes + unresolved_bytes)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS recovery_versions (
    recovery_version_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
    algorithm_version TEXT NOT NULL,
    input_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(run_id, algorithm_version, input_hash)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS functions (
    function_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
    module_version_id TEXT NOT NULL REFERENCES module_versions(module_version_id),
    recovery_version_id TEXT NOT NULL REFERENCES recovery_versions(recovery_version_id),
    primary_entry_rva INTEGER NOT NULL,
    name TEXT,
    confidence REAL NOT NULL,
    status TEXT NOT NULL,
    purpose TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(run_id, module_version_id, recovery_version_id, primary_entry_rva)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS functions_entry ON functions(module_version_id, primary_entry_rva);

CREATE TABLE IF NOT EXISTS function_entries (
    function_id TEXT NOT NULL REFERENCES functions(function_id) ON DELETE CASCADE,
    rva INTEGER NOT NULL,
    va INTEGER NOT NULL,
    kind TEXT NOT NULL,
    confidence REAL NOT NULL,
    PRIMARY KEY(function_id, rva)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS function_blocks (
    function_id TEXT NOT NULL REFERENCES functions(function_id) ON DELETE CASCADE,
    block_key_id TEXT NOT NULL REFERENCES block_keys(block_key_id),
    role TEXT NOT NULL,
    confidence REAL NOT NULL,
    PRIMARY KEY(function_id, block_key_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS function_blocks_block ON function_blocks(block_key_id);

CREATE TABLE IF NOT EXISTS function_calls (
    caller_function_id TEXT NOT NULL REFERENCES functions(function_id) ON DELETE CASCADE,
    callee_function_id TEXT REFERENCES functions(function_id) ON DELETE CASCADE,
    source_rva INTEGER NOT NULL,
    target_module_version_id TEXT REFERENCES module_versions(module_version_id),
    target_rva INTEGER,
    kind TEXT NOT NULL,
    confidence REAL NOT NULL,
    PRIMARY KEY(caller_function_id, source_rva, target_rva, kind)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS semantic_artifacts (
    artifact_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
    scope_type TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    level TEXT NOT NULL CHECK(level IN ('L0','L1','L2','L3','L4')),
    schema_version INTEGER NOT NULL,
    input_hash TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    content_json TEXT NOT NULL,
    markdown TEXT,
    provenance_json TEXT NOT NULL,
    confidence REAL NOT NULL,
    reviewer_status TEXT NOT NULL,
    state TEXT NOT NULL,
    supersedes_id TEXT REFERENCES semantic_artifacts(artifact_id),
    created_at TEXT NOT NULL,
    UNIQUE(run_id, scope_type, scope_id, level, input_hash, content_hash)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS semantic_artifacts_scope ON semantic_artifacts(run_id, scope_type, scope_id, level);

CREATE TABLE IF NOT EXISTS semantic_facts (
    fact_id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL REFERENCES semantic_artifacts(artifact_id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    statement_json TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    confidence REAL NOT NULL,
    reviewer_status TEXT NOT NULL,
    assumptions_json TEXT NOT NULL,
    questions_json TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS types (
    type_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    definition_json TEXT NOT NULL,
    confidence REAL NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS variables (
    variable_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
    scope_id TEXT NOT NULL,
    name TEXT NOT NULL,
    storage_json TEXT NOT NULL,
    type_id TEXT REFERENCES types(type_id),
    confidence REAL NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS memory_regions (
    memory_region_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
    module_version_id TEXT REFERENCES module_versions(module_version_id),
    name TEXT NOT NULL,
    start_va INTEGER NOT NULL,
    end_va INTEGER NOT NULL,
    permissions TEXT NOT NULL,
    classification TEXT NOT NULL,
    CHECK(end_va > start_va)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS algorithms (
    algorithm_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
    function_id TEXT REFERENCES functions(function_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    specification_json TEXT NOT NULL,
    confidence REAL NOT NULL,
    status TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS trace_runs (
    trace_run_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    seed INTEGER NOT NULL,
    virtual_time INTEGER NOT NULL,
    input_json TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS trace_events (
    trace_run_id TEXT NOT NULL REFERENCES trace_runs(trace_run_id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL,
    kind TEXT NOT NULL,
    source_va INTEGER,
    target_va INTEGER,
    aux INTEGER,
    payload_json TEXT NOT NULL,
    PRIMARY KEY(trace_run_id, sequence)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS trace_events_target ON trace_events(kind, target_va);

CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
    content_hash TEXT NOT NULL,
    cpu_json TEXT NOT NULL,
    memory_json TEXT NOT NULL,
    runtime_json TEXT NOT NULL,
    created_at TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS implementation_artifacts (
    implementation_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
    function_id TEXT REFERENCES functions(function_id) ON DELETE CASCADE,
    language TEXT NOT NULL,
    source_hash TEXT NOT NULL,
    source TEXT NOT NULL,
    semantic_artifact_id TEXT REFERENCES semantic_artifacts(artifact_id),
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS replacement_bindings (
    binding_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
    function_id TEXT REFERENCES functions(function_id) ON DELETE CASCADE,
    entry_va INTEGER NOT NULL,
    implementation_id TEXT REFERENCES implementation_artifacts(implementation_id),
    replacement_kind INTEGER NOT NULL,
    replacement_value INTEGER NOT NULL,
    stack_cleanup INTEGER NOT NULL,
    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
    created_at TEXT NOT NULL,
    UNIQUE(run_id, entry_va)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS test_cases (
    test_case_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
    function_id TEXT REFERENCES functions(function_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    input_snapshot_id TEXT REFERENCES snapshots(snapshot_id),
    input_json TEXT NOT NULL,
    expected_json TEXT NOT NULL,
    created_at TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS validation_runs (
    validation_run_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
    test_case_id TEXT REFERENCES test_cases(test_case_id),
    implementation_id TEXT REFERENCES implementation_artifacts(implementation_id),
    reference_trace_run_id TEXT REFERENCES trace_runs(trace_run_id),
    replacement_trace_run_id TEXT REFERENCES trace_runs(trace_run_id),
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS equivalence_results (
    equivalence_result_id TEXT PRIMARY KEY,
    validation_run_id TEXT NOT NULL REFERENCES validation_runs(validation_run_id) ON DELETE CASCADE,
    equivalent INTEGER NOT NULL CHECK(equivalent IN (0,1)),
    return_json TEXT NOT NULL,
    register_diff_json TEXT NOT NULL,
    memory_diff_json TEXT NOT NULL,
    event_diff_json TEXT NOT NULL,
    counterexample_json TEXT NOT NULL,
    created_at TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS coverage (
    run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
    function_id TEXT REFERENCES functions(function_id) ON DELETE CASCADE,
    metric TEXT NOT NULL,
    covered INTEGER NOT NULL,
    total INTEGER NOT NULL,
    details_json TEXT NOT NULL,
    PRIMARY KEY(run_id, function_id, metric)
) WITHOUT ROWID;
"""

_REQUIRED_COMPATIBILITY_TABLES = frozenset(
    {
        "metadata",
        "modules",
        "sections",
        "roots",
        "blocks",
        "instructions",
        "edges",
        "xrefs",
        "imports",
        "exports",
        "strings",
    }
)
_REQUIRED_COMPATIBILITY_VIEWS = frozenset({"call_xrefs", "string_xrefs"})
_REQUIRED_COLUMNS = {
    "modules": frozenset({"id", "runtime_name", "load_base", "image_size", "entry_rva"}),
    "analysis_runs": frozenset({"run_id", "project_id", "status", "input_hash"}),
    "work_items": frozenset(
        {
            "work_item_id",
            "run_id",
            "module_version_id",
            "entry_state_hash",
            "pending_entry_state_hash",
            "state",
            "lease_token",
            "lease_expires_at",
        }
    ),
    "block_revisions": frozenset(
        {"revision_id", "block_key_id", "entry_state_hash", "import_iat_rva"}
    ),
    "revision_edges": frozenset(
        {"revision_id", "target_rva", "resolution", "details_json"}
    ),
    "run_block_selections": frozenset({"run_id", "block_key_id", "revision_id"}),
    "executable_byte_classifications": frozenset(
        {"run_id", "module_version_id", "start_rva", "end_rva", "classification"}
    ),
}

_REQUIRED_V2_TABLES = frozenset(
    {
        "migrations",
        "projects",
        "binary_images",
        "module_versions",
        "tool_versions",
        "analysis_runs",
        "root_facts",
        "work_items",
        "work_attempts",
        "block_keys",
        "block_revisions",
        "revision_instructions",
        "revision_edges",
        "revision_xrefs",
        "run_block_selections",
        "executable_byte_classifications",
        "graph_accounting",
        "recovery_versions",
        "functions",
        "function_entries",
        "function_blocks",
        "function_calls",
        "semantic_artifacts",
        "semantic_facts",
        "trace_runs",
        "trace_events",
        "snapshots",
        "implementation_artifacts",
        "replacement_bindings",
        "test_cases",
        "validation_runs",
        "equivalence_results",
        "coverage",
    }
)


class TranslationStore:
    """Authoritative, resumable SQLite workspace for linked translation.

    The compatibility tables used by the original debug database remain a
    projection. Immutable revisions and run selections are the source of truth.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
        read_only: bool = False,
    ) -> None:
        self.path = Path(path)
        self.read_only = bool(read_only)
        if not self.read_only:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        uri = self.path.resolve().as_uri()
        if self.read_only:
            uri += "?mode=ro"
        self.connection = sqlite3.connect(
            uri,
            uri=True,
            isolation_level=None,
            timeout=max(0.0, busy_timeout_ms / 1000.0),
        )
        self.connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._transaction_depth = 0
        try:
            self._configure_connection(busy_timeout_ms)
            self._open_or_migrate()
        except Exception:
            self.connection.close()
            raise

    def __enter__(self) -> TranslationStore:
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    @property
    def schema_version(self) -> int:
        return int(self.connection.execute("PRAGMA user_version").fetchone()[0])

    def close(self) -> None:
        with self._lock:
            if self.connection is None:
                return
            if not self.read_only:
                try:
                    self.connection.execute("PRAGMA optimize")
                    self.connection.execute("PRAGMA wal_checkpoint(PASSIVE)")
                except sqlite3.Error:
                    pass
            self.connection.close()
            self.connection = None  # type: ignore[assignment]

    def _configure_connection(self, busy_timeout_ms: int) -> None:
        self.connection.execute(f"PRAGMA busy_timeout={max(0, int(busy_timeout_ms))}")
        self.connection.execute("PRAGMA foreign_keys=ON")
        if not self.read_only:
            journal_mode = str(
                self.connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            ).lower()
            if journal_mode != "wal":
                raise WorkspaceError(f"could not enable WAL journal mode: {journal_mode}")
            self.connection.execute("PRAGMA synchronous=FULL")
            self.connection.execute("PRAGMA wal_autocheckpoint=1000")
        self.connection.execute("PRAGMA temp_store=MEMORY")

    @contextmanager
    def transaction(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        """Run an atomic operation, nesting through SQLite savepoints."""

        with self._lock:
            depth = self._transaction_depth
            savepoint = f"translation_store_{depth}"
            if depth == 0:
                self.connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            else:
                self.connection.execute(f"SAVEPOINT {savepoint}")
            self._transaction_depth += 1
            try:
                yield self.connection
            except Exception:
                self._transaction_depth -= 1
                if depth == 0:
                    self.connection.execute("ROLLBACK")
                else:
                    self.connection.execute(f"ROLLBACK TO {savepoint}")
                    self.connection.execute(f"RELEASE {savepoint}")
                raise
            else:
                self._transaction_depth -= 1
                if depth == 0:
                    self.connection.execute("COMMIT")
                else:
                    self.connection.execute(f"RELEASE {savepoint}")

    def _table_names(self) -> set[str]:
        return {
            str(row[0])
            for row in self.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }

    def _metadata_version(self) -> int | None:
        if "metadata" not in self._table_names():
            return None
        row = self.connection.execute(
            "SELECT value FROM metadata WHERE key='schema_version'"
        ).fetchone()
        if row is None:
            return None
        try:
            return int(row[0])
        except (TypeError, ValueError) as error:
            raise SchemaVersionError("metadata.schema_version is not an integer") from error

    def _open_or_migrate(self) -> None:
        tables = self._table_names()
        user_version = self.schema_version
        metadata_version = self._metadata_version()

        if not tables:
            if self.read_only:
                raise SchemaVersionError("cannot initialize an empty read-only workspace")
            self._create_fresh_schema()
            return

        if user_version > DATABASE_SCHEMA_VERSION:
            raise SchemaVersionError(
                f"workspace schema {user_version} is newer than supported schema "
                f"{DATABASE_SCHEMA_VERSION}"
            )
        if user_version == DATABASE_SCHEMA_VERSION:
            if not self.read_only:
                self._run_schema_script(_V2_SCHEMA)
            self._validate_v2_schema()
            return
        if metadata_version == 1 and user_version in (0, 1):
            if self.read_only:
                raise SchemaVersionError("legacy schema v1 requires a writable migration")
            self._migrate_v1_to_v2()
            return
        if metadata_version == DATABASE_SCHEMA_VERSION and _REQUIRED_V2_TABLES <= tables:
            if self.read_only:
                raise SchemaVersionError("v2 workspace has an incomplete user_version marker")
            with self.transaction(immediate=True):
                self.connection.execute(f"PRAGMA user_version={DATABASE_SCHEMA_VERSION}")
            self._validate_v2_schema()
            return
        if user_version:
            raise SchemaVersionError(
                f"unsupported workspace schema {user_version}; expected v1 or v2"
            )
        raise SchemaVersionError(
            "database is neither empty, a debugdb v1 database, nor a schema-v2 workspace"
        )

    def _run_schema_script(self, script: str) -> None:
        try:
            self.connection.executescript("BEGIN IMMEDIATE;\n" + script + "\nCOMMIT;")
        except Exception:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise

    def _create_fresh_schema(self) -> None:
        initialization = f"""
INSERT INTO metadata(key, value) VALUES ('schema_version', '2');
INSERT INTO metadata(key, value) VALUES ('workspace', 'd2wasm');
INSERT INTO migrations(version, name, applied_at)
VALUES (1, 'debugdb compatibility schema', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
INSERT INTO migrations(version, name, applied_at)
VALUES (2, 'persistent translation workspace', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
PRAGMA user_version={DATABASE_SCHEMA_VERSION};
"""
        self._run_schema_script(
            _COMPATIBILITY_SCHEMA + "\n" + _V2_SCHEMA + "\n" + initialization
        )
        self._validate_v2_schema()

    def _validate_v2_schema(self) -> None:
        tables = self._table_names()
        missing = sorted(
            (_REQUIRED_COMPATIBILITY_TABLES | _REQUIRED_V2_TABLES) - tables
        )
        if missing:
            raise SchemaVersionError(
                "schema-v2 workspace is missing required tables: " + ", ".join(missing)
            )
        views = {
            str(row[0])
            for row in self.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='view'"
            )
        }
        missing_views = sorted(_REQUIRED_COMPATIBILITY_VIEWS - views)
        if missing_views:
            raise SchemaVersionError(
                "schema-v2 workspace is missing compatibility views: "
                + ", ".join(missing_views)
            )
        for table, required_columns in _REQUIRED_COLUMNS.items():
            columns = {
                str(row["name"])
                for row in self.connection.execute(f"PRAGMA table_info({table})")
            }
            missing_columns = sorted(required_columns - columns)
            if missing_columns:
                raise SchemaVersionError(
                    f"schema-v2 table {table} is missing columns: "
                    + ", ".join(missing_columns)
                )
        migration_versions = {
            int(row[0]) for row in self.connection.execute("SELECT version FROM migrations")
        }
        if not {1, DATABASE_SCHEMA_VERSION} <= migration_versions:
            raise SchemaVersionError("workspace migration history is incomplete")
        if self.schema_version != DATABASE_SCHEMA_VERSION:
            raise SchemaVersionError(
                f"workspace user_version is {self.schema_version}, expected {DATABASE_SCHEMA_VERSION}"
            )
        foreign_keys = int(self.connection.execute("PRAGMA foreign_keys").fetchone()[0])
        if not foreign_keys:
            raise WorkspaceError("SQLite foreign key enforcement is disabled")

    def _migrate_v1_to_v2(self) -> None:
        required = {
            "metadata",
            "modules",
            "sections",
            "roots",
            "blocks",
            "instructions",
            "edges",
            "xrefs",
            "imports",
            "exports",
            "strings",
        }
        missing = sorted(required - self._table_names())
        if missing:
            raise SchemaVersionError(
                "legacy debugdb v1 is missing required tables: " + ", ".join(missing)
            )
        self._run_schema_script(_V2_SCHEMA)
        with self.transaction(immediate=True):
            self._import_v1_rows()
            now = _utc_now()
            self.connection.executemany(
                "INSERT OR IGNORE INTO migrations(version, name, applied_at) VALUES (?, ?, ?)",
                [
                    (1, "legacy debugdb v1", now),
                    (2, "persistent translation workspace", now),
                ],
            )
            self.connection.execute(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES ('schema_version', ?)",
                (str(DATABASE_SCHEMA_VERSION),),
            )
            self.connection.execute(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES ('migrated_from', '1')"
            )
            self.connection.execute(f"PRAGMA user_version={DATABASE_SCHEMA_VERSION}")
        self._validate_v2_schema()

    def _import_v1_rows(self) -> None:
        module_rows = [dict(row) for row in self.connection.execute("SELECT * FROM modules ORDER BY id")]
        metadata = {
            str(row[0]): str(row[1])
            for row in self.connection.execute("SELECT key, value FROM metadata ORDER BY key")
        }
        manifest = {
            "legacy_schema": 1,
            "entry_va": metadata.get("entry_va"),
            "modules": [
                {
                    "runtime_name": row["runtime_name"],
                    "image_base": row["image_base"],
                    "load_base": row["load_base"],
                    "image_size": row["image_size"],
                    "entry_rva": row["entry_rva"],
                }
                for row in module_rows
            ],
        }
        project_id = project_identity(manifest)
        now = _utc_now()
        manifest_json = canonical_json(canonical_manifest_data(manifest))
        self.connection.execute(
            """INSERT OR IGNORE INTO projects
               (project_id, name, manifest_hash, manifest_json, metadata_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                project_id,
                "legacy debugdb v1",
                stable_hash("d2wasm-manifest-v2", canonical_manifest_data(manifest)),
                manifest_json,
                canonical_json({"migrated_from": 1}),
                now,
            ),
        )

        module_versions: dict[int, str] = {}
        for row in module_rows:
            descriptor = {
                "runtime_name": row["runtime_name"],
                "image_base": row["image_base"],
                "load_base": row["load_base"],
                "image_size": row["image_size"],
                "entry_rva": row["entry_rva"],
            }
            synthetic_sha = stable_hash("d2wasm-legacy-binary", descriptor)
            binary_image_id = binary_identity(synthetic_sha)
            self.connection.execute(
                """INSERT OR IGNORE INTO binary_images
                   (binary_image_id, sha256, byte_size, content_available, metadata_json, created_at)
                   VALUES (?, ?, ?, 0, ?, ?)""",
                (
                    binary_image_id,
                    synthetic_sha,
                    0,
                    canonical_json({"synthetic": True, "source": row["source"]}),
                    now,
                ),
            )
            module_version_id = module_identity(
                project_id,
                str(row["runtime_name"]),
                synthetic_sha,
                image_base=int(row["image_base"]),
                load_base=int(row["load_base"]),
                image_size=int(row["image_size"]),
                entry_rva=int(row["entry_rva"]),
            )
            self.connection.execute(
                """INSERT OR IGNORE INTO module_versions
                   (module_version_id, project_id, binary_image_id, runtime_name, source,
                    image_base, load_base, image_size, entry_rva, inventory_json,
                    compatibility_module_id, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    module_version_id,
                    project_id,
                    binary_image_id,
                    row["runtime_name"],
                    row["source"],
                    row["image_base"],
                    row["load_base"],
                    row["image_size"],
                    row["entry_rva"],
                    canonical_json({"migrated_from": "debugdb-v1"}),
                    row["id"],
                    now,
                ),
            )
            module_versions[int(row["id"])] = module_version_id

        tool_version_id = stable_hash(
            "d2wasm-tool-v2", "debugdb", "1", None, {"migration": True}
        )
        self.connection.execute(
            """INSERT OR IGNORE INTO tool_versions
               (tool_version_id, name, version, executable_hash, options_json, created_at)
               VALUES (?, 'debugdb', '1', NULL, ?, ?)""",
            (tool_version_id, canonical_json({"migration": True}), now),
        )
        root_input = [
            tuple(row)
            for row in self.connection.execute(
                "SELECT module_id, rva FROM roots ORDER BY module_id, rva"
            )
        ]
        configuration = {"migrated_from": "debugdb-v1"}
        input_data = {"roots": root_input}
        configuration_hash = stable_hash("d2wasm-run-configuration-v2", configuration)
        input_hash = stable_hash("d2wasm-run-input-v2", input_data)
        run_id = stable_hash(
            "d2wasm-analysis-run-v2",
            project_id,
            tool_version_id,
            configuration_hash,
            input_hash,
        )
        self.connection.execute(
            """INSERT OR IGNORE INTO analysis_runs
               (run_id, project_id, tool_version_id, configuration_hash, input_hash,
                configuration_json, input_json, status, created_at, updated_at, completed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'completed', ?, ?, ?)""",
            (
                run_id,
                project_id,
                tool_version_id,
                configuration_hash,
                input_hash,
                canonical_json(configuration),
                canonical_json(input_data),
                now,
                now,
                now,
            ),
        )

        module_by_va = [
            (
                int(row["load_base"]),
                int(row["load_base"]) + int(row["image_size"]),
                module_versions[int(row["id"])],
            )
            for row in module_rows
        ]
        module_info = {
            module_versions[int(row["id"])]: row for row in module_rows
        }
        for root in self.connection.execute(
            "SELECT module_id, rva, va FROM roots ORDER BY module_id, rva"
        ):
            module_version_id = module_versions[int(root["module_id"])]
            details_json = canonical_json({"migrated_from": "debugdb-v1"})
            root_fact_id = stable_hash(
                "d2wasm-root-fact-v2",
                run_id,
                module_version_id,
                int(root["rva"]),
                "legacy_root",
                "debugdb-v1",
                details_json,
            )
            self.connection.execute(
                """INSERT OR IGNORE INTO root_facts
                   (root_fact_id, run_id, module_version_id, rva, va, kind, evidence,
                    confidence, accepted, resolution, details_json, created_at)
                   VALUES (?, ?, ?, ?, ?, 'legacy_root', 'debugdb-v1', 1.0, 1,
                           'resolved_executable', ?, ?)""",
                (
                    root_fact_id,
                    run_id,
                    module_version_id,
                    int(root["rva"]),
                    int(root["va"]),
                    details_json,
                    now,
                ),
            )

        for block in self.connection.execute("SELECT * FROM blocks ORDER BY module_id, rva"):
            module_version_id = module_versions[int(block["module_id"])]
            module = module_info[module_version_id]
            instruction_rows = [
                {
                    "rva": int(row["rva"]),
                    "size": int(row["size"]),
                    "bytes": bytes(row["bytes"]),
                    "mnemonic": str(row["mnemonic"]),
                    "op_str": str(row["op_str"]),
                    "details": {"migrated_from": "debugdb-v1"},
                }
                for row in self.connection.execute(
                    "SELECT * FROM instructions WHERE block_va=? ORDER BY sequence",
                    (int(block["va"]),),
                )
            ]
            edge_rows = []
            for edge in self.connection.execute(
                "SELECT * FROM edges WHERE source_block_va=? ORDER BY kind, target_block_va",
                (int(block["va"]),),
            ):
                target_va = int(edge["target_block_va"])
                target_module_id = next(
                    (
                        candidate
                        for start, end, candidate in module_by_va
                        if start <= target_va < end
                    ),
                    None,
                )
                target_rva = None
                if target_module_id is not None:
                    target_rva = target_va - int(module_info[target_module_id]["load_base"])
                target_exists = self.connection.execute(
                    "SELECT 1 FROM blocks WHERE va=?", (target_va,)
                ).fetchone()
                edge_rows.append(
                    {
                        "source_instruction_rva": int(edge["source_instruction_va"])
                        - int(module["load_base"]),
                        "target_module_version_id": target_module_id,
                        "target_rva": target_rva,
                        "target_va": target_va,
                        "kind": str(edge["kind"]),
                        "evidence_kind": "debugdb-v1",
                        "resolution": "resolved_executable" if target_exists else "pending",
                        "operand_index": -1,
                        "details": {"migrated_from": "debugdb-v1"},
                    }
                )
            xref_rows = []
            for xref in self.connection.execute(
                """SELECT x.* FROM xrefs AS x
                   JOIN instructions AS i ON i.va=x.source_va
                   WHERE i.block_va=?
                   ORDER BY x.source_va, x.kind, x.operand_index, x.target_va""",
                (int(block["va"]),),
            ):
                target_module_id = (
                    module_versions.get(int(xref["target_module_id"]))
                    if xref["target_module_id"] is not None
                    else None
                )
                target_rva = None
                if target_module_id is not None:
                    target_rva = int(xref["target_va"]) - int(
                        module_info[target_module_id]["load_base"]
                    )
                xref_rows.append(
                    {
                        "source_rva": int(xref["source_va"]) - int(module["load_base"]),
                        "target_module_version_id": target_module_id,
                        "target_rva": target_rva,
                        "target_va": int(xref["target_va"]),
                        "kind": str(xref["kind"]),
                        "operand_index": int(xref["operand_index"]),
                        "details": {"migrated_from": "debugdb-v1"},
                    }
                )
            imported = None
            if block["import_library"] is not None:
                imported = {
                    "library": block["import_library"],
                    "name": block["import_name"],
                    "ordinal": block["import_ordinal"],
                }
            revision_id = self._persist_revision_rows(
                module_version_id=module_version_id,
                rva=int(block["rva"]),
                entry_state={},
                instructions=instruction_rows,
                edges=edge_rows,
                xrefs=xref_rows,
                terminator=str(block["terminator"]),
                unsupported_reason=block["unsupported_reason"],
                imported_call=imported,
                facts={"migrated_from": "debugdb-v1"},
            )
            block_key_id = block_identity(module_version_id, int(block["rva"]))
            self.connection.execute(
                """INSERT OR REPLACE INTO run_block_selections
                   (run_id, block_key_id, revision_id, selected_at) VALUES (?, ?, ?, ?)""",
                (run_id, block_key_id, revision_id, now),
            )

    def register_project(
        self,
        manifest: Mapping[str, Any],
        *,
        name: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> str:
        canonical = canonical_manifest_data(manifest)
        project_id = project_identity(manifest)
        manifest_hash = stable_hash("d2wasm-manifest-v2", canonical)
        with self.transaction(immediate=True):
            self.connection.execute(
                """INSERT INTO projects
                   (project_id, name, manifest_hash, manifest_json, metadata_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(project_id) DO UPDATE SET
                       name=COALESCE(excluded.name, projects.name),
                       metadata_json=excluded.metadata_json""",
                (
                    project_id,
                    name,
                    manifest_hash,
                    canonical_json(canonical),
                    canonical_json(metadata or {}),
                    _utc_now(),
                ),
            )
            self.connection.executemany(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
                [
                    ("entry_va", str(int(manifest.get("entry_va", 0)))),
                    ("link_manifest_schema", str(manifest.get("schema_version", ""))),
                    ("project_id", project_id),
                ],
            )
        return project_id

    def register_binary_image(
        self,
        content: bytes | bytearray | memoryview | Path | None = None,
        *,
        sha256_hex: str | None = None,
        byte_size: int | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> str:
        data: bytes | None
        if isinstance(content, Path):
            data = content.read_bytes()
        elif content is None:
            data = None
        else:
            data = bytes(content)
        if data is not None:
            actual_hash = sha256(data).hexdigest()
            if sha256_hex is not None and actual_hash != sha256_hex.lower():
                raise ValueError("supplied binary SHA-256 does not match content")
            sha256_hex = actual_hash
            byte_size = len(data)
        if sha256_hex is None:
            raise ValueError("binary content or sha256_hex is required")
        normalized_hash = sha256_hex.lower()
        binary_image_id = binary_identity(normalized_hash)
        size = int(byte_size or 0)
        if size < 0:
            raise ValueError("binary byte size cannot be negative")
        with self.transaction(immediate=True):
            self.connection.execute(
                """INSERT INTO binary_images
                   (binary_image_id, sha256, byte_size, content_available, metadata_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(binary_image_id) DO UPDATE SET
                       byte_size=CASE
                           WHEN binary_images.byte_size=0 THEN excluded.byte_size
                           ELSE binary_images.byte_size
                       END,
                       content_available=MAX(binary_images.content_available,
                                             excluded.content_available),
                       metadata_json=excluded.metadata_json""",
                (
                    binary_image_id,
                    normalized_hash,
                    size,
                    int(data is not None),
                    canonical_json(metadata or {}),
                    _utc_now(),
                ),
            )
        return binary_image_id

    def register_module(
        self,
        project_id: str,
        module: str | Mapping[str, Any],
        *,
        binary_image_id: str | None = None,
        binary_sha256: str | None = None,
        binary_data: bytes | bytearray | memoryview | Path | None = None,
        source: str | None = None,
        image_base: int | None = None,
        load_base: int | None = None,
        image_size: int | None = None,
        entry_rva: int | None = None,
        inventory: Mapping[str, Any] | None = None,
    ) -> str:
        record = dict(module) if isinstance(module, Mapping) else {}
        runtime_name = str(record.get("runtime_name", module))
        inventory_record = dict(inventory or record)
        source_value = str(source if source is not None else record.get("source", runtime_name))
        image_base_value = int(
            image_base if image_base is not None else record.get("image_base", 0)
        )
        load_base_value = int(
            load_base
            if load_base is not None
            else record.get("load_base", image_base_value)
        )
        image_size_value = int(
            image_size if image_size is not None else record.get("image_size", 0)
        )
        entry_rva_value = int(
            entry_rva if entry_rva is not None else record.get("entry_rva", 0)
        )
        binary_sha256 = binary_sha256 or record.get("sha256")
        if binary_image_id is None:
            binary_image_id = self.register_binary_image(
                binary_data,
                sha256_hex=str(binary_sha256) if binary_sha256 is not None else None,
                byte_size=record.get("file_size"),
                metadata={"runtime_name": runtime_name},
            )
        binary_row = self.connection.execute(
            "SELECT sha256 FROM binary_images WHERE binary_image_id=?", (binary_image_id,)
        ).fetchone()
        if binary_row is None:
            raise KeyError(f"unknown binary image: {binary_image_id}")
        module_version_id = module_identity(
            project_id,
            runtime_name,
            str(binary_row["sha256"]),
            image_base=image_base_value,
            load_base=load_base_value,
            image_size=image_size_value,
            entry_rva=entry_rva_value,
        )
        now = _utc_now()
        with self.transaction(immediate=True):
            self.connection.execute(
                """INSERT INTO modules
                   (runtime_name, source, image_base, load_base, image_size, entry_rva, entry_va)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(runtime_name) DO UPDATE SET
                       source=excluded.source,
                       image_base=excluded.image_base,
                       load_base=excluded.load_base,
                       image_size=excluded.image_size,
                       entry_rva=excluded.entry_rva,
                       entry_va=excluded.entry_va""",
                (
                    runtime_name,
                    source_value,
                    image_base_value,
                    load_base_value,
                    image_size_value,
                    entry_rva_value,
                    load_base_value + entry_rva_value,
                ),
            )
            compatibility_module_id = int(
                self.connection.execute(
                    "SELECT id FROM modules WHERE runtime_name=? COLLATE NOCASE",
                    (runtime_name,),
                ).fetchone()[0]
            )
            self.connection.execute(
                """INSERT INTO module_versions
                   (module_version_id, project_id, binary_image_id, runtime_name, source,
                    image_base, load_base, image_size, entry_rva, inventory_json,
                    compatibility_module_id, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(module_version_id) DO UPDATE SET
                       source=excluded.source,
                       inventory_json=excluded.inventory_json,
                       compatibility_module_id=excluded.compatibility_module_id""",
                (
                    module_version_id,
                    project_id,
                    binary_image_id,
                    runtime_name,
                    source_value,
                    image_base_value,
                    load_base_value,
                    image_size_value,
                    entry_rva_value,
                    canonical_json(inventory_record),
                    compatibility_module_id,
                    now,
                ),
            )
        if inventory_record:
            self.register_static_inventory(module_version_id, inventory_record)
        return module_version_id

    register_module_version = register_module

    def register_static_inventory(
        self,
        module_version_id: str,
        inventory: Mapping[str, Any],
        *,
        internal_bindings: Iterable[Mapping[str, Any]] = (),
        strings: Iterable[Mapping[str, Any] | Sequence[Any]] = (),
    ) -> None:
        module = self._module_row(module_version_id)
        module_id = int(module["compatibility_module_id"])
        load_base = int(module["load_base"])
        project_id = str(module["project_id"])
        bindings: dict[tuple[str, str], Mapping[str, Any]] = {}
        runtime_name = str(module["runtime_name"]).casefold()
        for binding in internal_bindings:
            importer = binding.get("importer")
            if importer is not None and str(importer).casefold() != runtime_name:
                continue
            symbol = str(binding.get("name") or f"#{binding.get('ordinal')}")
            bindings[(str(binding.get("library", "")).casefold(), symbol)] = binding
        with self.transaction(immediate=True):
            self.connection.execute(
                "UPDATE module_versions SET inventory_json=? WHERE module_version_id=?",
                (canonical_json(inventory), module_version_id),
            )
            self.connection.execute("DELETE FROM sections WHERE module_id=?", (module_id,))
            self.connection.executemany(
                """INSERT INTO sections
                   (module_id, name, rva, va, virtual_size, file_size, executable)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        module_id,
                        str(section.get("name", "")),
                        int(section["rva"]),
                        load_base + int(section["rva"]),
                        int(section.get("virtual_size", section.get("file_size", 0))),
                        int(section.get("file_size", 0)),
                        int(bool(section.get("executable", False))),
                    )
                    for section in inventory.get("sections", [])
                ],
            )
            self.connection.execute("DELETE FROM exports WHERE module_id=?", (module_id,))
            self.connection.executemany(
                """INSERT INTO exports(module_id, name, ordinal, rva, va)
                   VALUES (?, ?, ?, ?, ?)""",
                [
                    (
                        module_id,
                        export.get("name"),
                        int(export["ordinal"]),
                        int(export["rva"]),
                        load_base + int(export["rva"]),
                    )
                    for export in inventory.get("exports", [])
                ],
            )
            self.connection.execute("DELETE FROM imports WHERE module_id=?", (module_id,))
            import_rows = []
            for imported in inventory.get("imports", []):
                symbol = str(imported.get("name") or f"#{imported.get('ordinal')}")
                binding = bindings.get(
                    (str(imported.get("library", "")).casefold(), symbol)
                )
                target_module_id = None
                target_va = None
                if binding is not None:
                    target_name = binding.get("target_module")
                    target = self.connection.execute(
                        """SELECT compatibility_module_id FROM module_versions
                           WHERE project_id=? AND runtime_name=? COLLATE NOCASE
                           ORDER BY created_at DESC LIMIT 1""",
                        (project_id, target_name),
                    ).fetchone()
                    target_module_id = int(target[0]) if target is not None else None
                    target_va = (
                        int(binding["target_va"])
                        if binding.get("target_va") is not None
                        else None
                    )
                iat_rva = int(imported["iat_rva"])
                import_rows.append(
                    (
                        module_id,
                        str(imported["library"]),
                        imported.get("name"),
                        imported.get("ordinal"),
                        iat_rva,
                        load_base + iat_rva,
                        target_module_id,
                        target_va,
                        int(binding is not None),
                    )
                )
            self.connection.executemany(
                """INSERT INTO imports
                   (module_id, library, name, ordinal, iat_rva, iat_va,
                    target_module_id, target_va, resolved)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                import_rows,
            )
            if strings:
                self.connection.execute("DELETE FROM strings WHERE module_id=?", (module_id,))
                string_rows = []
                for item in strings:
                    if isinstance(item, Mapping):
                        rva = int(item["rva"])
                        encoding = str(item.get("encoding", "ascii"))
                        value = str(item["value"])
                    else:
                        rva, encoding, value = int(item[0]), str(item[1]), str(item[2])
                    string_rows.append((module_id, load_base + rva, rva, encoding, value))
                self.connection.executemany(
                    """INSERT OR IGNORE INTO strings
                       (module_id, va, rva, encoding, value) VALUES (?, ?, ?, ?, ?)""",
                    string_rows,
                )

    def register_tool_version(
        self,
        name: str,
        version: str,
        *,
        executable_hash: str | None = None,
        options: Mapping[str, Any] | None = None,
    ) -> str:
        option_data = options or {}
        tool_version_id = stable_hash(
            "d2wasm-tool-v2", name, version, executable_hash, option_data
        )
        with self.transaction(immediate=True):
            self.connection.execute(
                """INSERT OR IGNORE INTO tool_versions
                   (tool_version_id, name, version, executable_hash, options_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    tool_version_id,
                    name,
                    version,
                    executable_hash,
                    canonical_json(option_data),
                    _utc_now(),
                ),
            )
        return tool_version_id

    def register_analysis_run(
        self,
        project_id: str,
        tool_version_id: str,
        configuration: Mapping[str, Any] | None = None,
        inputs: Mapping[str, Any] | None = None,
        *,
        root_facts: Iterable[Mapping[str, Any]] = (),
        status: str = "running",
    ) -> str:
        if status not in {"created", "running", "paused", "completed", "failed", "cancelled"}:
            raise ValueError(f"invalid analysis run state: {status}")
        configuration_data = configuration or {}
        input_data = dict(inputs or {})
        roots = list(root_facts)
        if roots:
            input_data["root_facts"] = roots
        configuration_hash = stable_hash(
            "d2wasm-run-configuration-v2", configuration_data
        )
        input_hash = stable_hash("d2wasm-run-input-v2", input_data)
        run_id = stable_hash(
            "d2wasm-analysis-run-v2",
            project_id,
            tool_version_id,
            configuration_hash,
            input_hash,
        )
        now = _utc_now()
        with self.transaction(immediate=True):
            self.connection.execute(
                """INSERT INTO analysis_runs
                   (run_id, project_id, tool_version_id, configuration_hash, input_hash,
                    configuration_json, input_json, status, created_at, updated_at, completed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(run_id) DO UPDATE SET
                       updated_at=excluded.updated_at""",
                (
                    run_id,
                    project_id,
                    tool_version_id,
                    configuration_hash,
                    input_hash,
                    canonical_json(configuration_data),
                    canonical_json(input_data),
                    status,
                    now,
                    now,
                    now if status == "completed" else None,
                ),
            )
        return run_id

    register_run = register_analysis_run

    def set_run_status(self, run_id: str, status: str) -> None:
        if status not in {"created", "running", "paused", "completed", "failed", "cancelled"}:
            raise ValueError(f"invalid analysis run state: {status}")
        now = _utc_now()
        with self.transaction(immediate=True):
            cursor = self.connection.execute(
                """UPDATE analysis_runs
                   SET status=?, updated_at=?, completed_at=? WHERE run_id=?""",
                (status, now, now if status == "completed" else None, run_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(f"unknown analysis run: {run_id}")

    def register_root_fact(
        self,
        run_id: str,
        module_version_id: str,
        rva: int,
        kind: str,
        *,
        evidence: str | None = None,
        confidence: float | None = None,
        accepted: bool = True,
        resolution: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> str:
        self._validate_run_module(run_id, module_version_id)
        module = self._module_row(module_version_id)
        normalized_rva = int(rva)
        if not 0 <= normalized_rva <= 0xFFFF_FFFF:
            raise ValueError("root RVA must be an unsigned 32-bit value")
        details_json = canonical_json(details or {})
        evidence_value = evidence or kind
        resolution_value = resolution or (
            "resolved_executable" if accepted else "rejected"
        )
        if resolution_value not in EDGE_RESOLUTIONS:
            raise ValueError(f"invalid root resolution: {resolution_value}")
        root_fact_id = stable_hash(
            "d2wasm-root-fact-v2",
            run_id,
            module_version_id,
            normalized_rva,
            kind,
            evidence_value,
            confidence,
            bool(accepted),
            resolution_value,
            details_json,
        )
        with self.transaction(immediate=True):
            self.connection.execute(
                """INSERT OR IGNORE INTO root_facts
                   (root_fact_id, run_id, module_version_id, rva, va, kind, evidence,
                    confidence, accepted, resolution, details_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    root_fact_id,
                    run_id,
                    module_version_id,
                    int(rva),
                    int(module["load_base"]) + int(rva),
                    kind,
                    evidence_value,
                    confidence,
                    int(accepted),
                    resolution_value,
                    details_json,
                    _utc_now(),
                ),
            )
            if accepted:
                self.connection.execute(
                    "INSERT OR IGNORE INTO roots(module_id, rva, va) VALUES (?, ?, ?)",
                    (
                        int(module["compatibility_module_id"]),
                        int(rva),
                        int(module["load_base"]) + int(rva),
                    ),
                )
        return root_fact_id

    def register_root_facts(
        self,
        run_id: str,
        facts: Iterable[Mapping[str, Any]],
    ) -> list[str]:
        result = []
        for fact in facts:
            result.append(
                self.register_root_fact(
                    run_id,
                    str(fact["module_version_id"]),
                    int(fact["rva"]),
                    str(fact["kind"]),
                    evidence=fact.get("evidence"),
                    confidence=fact.get("confidence"),
                    accepted=bool(fact.get("accepted", True)),
                    resolution=fact.get("resolution"),
                    details=fact.get("details"),
                )
            )
        return result

    def enqueue_work(
        self,
        run_id: str,
        module_version_id: str,
        target_rva: int | None,
        *,
        kind: str = "discover_block",
        priority: int = 0,
        entry_state: Mapping[str, Any] | None = None,
        payload: Mapping[str, Any] | None = None,
        state: str = "pending",
        error: str | None = None,
        max_attempts: int = 0,
        available_at: float = 0.0,
        item_key: str | None = None,
    ) -> str:
        with self.transaction(immediate=True):
            return self._enqueue_work(
                run_id,
                module_version_id,
                target_rva,
                kind=kind,
                priority=priority,
                entry_state=entry_state,
                payload=payload,
                state=state,
                error=error,
                max_attempts=max_attempts,
                available_at=available_at,
                item_key=item_key,
            )

    enqueue_work_item = enqueue_work

    def _enqueue_work(
        self,
        run_id: str,
        module_version_id: str,
        target_rva: int | None,
        *,
        kind: str,
        priority: int,
        entry_state: Mapping[str, Any] | None,
        payload: Mapping[str, Any] | None,
        state: str,
        error: str | None,
        max_attempts: int,
        available_at: float,
        item_key: str | None,
    ) -> str:
        if state not in WORK_STATES - {"leased"}:
            raise ValueError(f"invalid initial work state: {state}")
        entry_data = entry_state or {}
        payload_data = payload or {}
        entry_state_hash = stable_hash("d2wasm-entry-state-v2", entry_data)
        if item_key is not None:
            key = item_key
        elif kind == "discover_block" and target_rva is not None:
            key = stable_hash("d2wasm-block-work-v2", int(target_rva))
        else:
            key = stable_hash(
                "d2wasm-work-key-v2", kind, target_rva, entry_state_hash, payload_data
            )
        work_item_id = stable_hash(
            "d2wasm-work-item-v2", run_id, module_version_id, kind, key
        )
        now = _utc_now()
        finished_at = now if state in TERMINAL_WORK_STATES else None
        self.connection.execute(
            """INSERT INTO work_items
               (work_item_id, run_id, module_version_id, kind, item_key, target_rva,
                entry_state_hash, entry_state_json, payload_json, state, priority,
                max_attempts, available_at, last_error, created_at, updated_at, finished_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(run_id, module_version_id, kind, item_key) DO UPDATE SET
                   pending_entry_state_hash=CASE
                       WHEN work_items.state='leased'
                        AND work_items.entry_state_hash<>excluded.entry_state_hash
                           THEN excluded.entry_state_hash
                       ELSE work_items.pending_entry_state_hash
                   END,
                   pending_entry_state_json=CASE
                       WHEN work_items.state='leased'
                        AND work_items.entry_state_hash<>excluded.entry_state_hash
                           THEN excluded.entry_state_json
                       ELSE work_items.pending_entry_state_json
                   END,
                   pending_payload_json=CASE
                       WHEN work_items.state='leased'
                        AND work_items.entry_state_hash<>excluded.entry_state_hash
                           THEN excluded.payload_json
                       ELSE work_items.pending_payload_json
                   END,
                   entry_state_hash=CASE WHEN work_items.state='leased'
                       THEN work_items.entry_state_hash ELSE excluded.entry_state_hash END,
                   entry_state_json=CASE WHEN work_items.state='leased'
                       THEN work_items.entry_state_json ELSE excluded.entry_state_json END,
                   payload_json=CASE WHEN work_items.state='leased'
                       THEN work_items.payload_json ELSE excluded.payload_json END,
                   state=CASE
                       WHEN work_items.state='leased' THEN work_items.state
                       WHEN work_items.entry_state_hash<>excluded.entry_state_hash THEN 'pending'
                       ELSE work_items.state
                   END,
                   priority=MAX(work_items.priority, excluded.priority),
                   max_attempts=MAX(work_items.max_attempts, excluded.max_attempts),
                   available_at=CASE
                       WHEN work_items.entry_state_hash<>excluded.entry_state_hash
                           THEN excluded.available_at
                       ELSE work_items.available_at
                   END,
                   last_error=CASE
                       WHEN work_items.entry_state_hash<>excluded.entry_state_hash THEN NULL
                       ELSE work_items.last_error
                   END,
                   finished_at=CASE
                       WHEN work_items.entry_state_hash<>excluded.entry_state_hash THEN NULL
                       ELSE work_items.finished_at
                   END,
                   updated_at=excluded.updated_at""",
            (
                work_item_id,
                run_id,
                module_version_id,
                kind,
                key,
                target_rva,
                entry_state_hash,
                canonical_json(entry_data),
                canonical_json(payload_data),
                state,
                int(priority),
                max(0, int(max_attempts)),
                float(available_at),
                error,
                now,
                now,
                finished_at,
            ),
        )
        row = self.connection.execute(
            """SELECT work_item_id FROM work_items
               WHERE run_id=? AND module_version_id=? AND kind=? AND item_key=?""",
            (run_id, module_version_id, kind, key),
        ).fetchone()
        return str(row[0])

    def enqueue_work_batch(self, items: Iterable[Mapping[str, Any]]) -> list[str]:
        item_rows = list(items)
        with self.transaction(immediate=True):
            return [
                self._enqueue_work(
                    str(item["run_id"]),
                    str(item["module_version_id"]),
                    item.get("target_rva"),
                    kind=str(item.get("kind", "discover_block")),
                    priority=int(item.get("priority", 0)),
                    entry_state=item.get("entry_state"),
                    payload=item.get("payload"),
                    state=str(item.get("state", "pending")),
                    error=item.get("error"),
                    max_attempts=int(item.get("max_attempts", 0)),
                    available_at=float(item.get("available_at", 0.0)),
                    item_key=item.get("item_key"),
                )
                for item in item_rows
            ]

    def claim_work(
        self,
        run_id: str,
        worker_id: str,
        *,
        lease_seconds: float = DEFAULT_LEASE_SECONDS,
        module_version_id: str | None = None,
        kinds: Iterable[str] | None = None,
        now: float | None = None,
    ) -> dict[str, Any] | None:
        timestamp = time.time() if now is None else float(now)
        lease_seconds = float(lease_seconds)
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        with self.transaction(immediate=True):
            self._recover_expired_leases(timestamp, run_id=run_id)
            clauses = ["run_id=?", "state='pending'", "available_at<=?"]
            parameters: list[Any] = [run_id, timestamp]
            if module_version_id is not None:
                clauses.append("module_version_id=?")
                parameters.append(module_version_id)
            kind_values = tuple(kinds or ())
            if kind_values:
                clauses.append("kind IN (" + ",".join("?" for _ in kind_values) + ")")
                parameters.extend(kind_values)
            row = self.connection.execute(
                """SELECT * FROM work_items WHERE """
                + " AND ".join(clauses)
                + """ ORDER BY priority DESC, created_at, work_item_id LIMIT 1""",
                parameters,
            ).fetchone()
            if row is None:
                return None
            attempt_number = int(row["attempt_count"]) + 1
            lease_token = stable_hash(
                "d2wasm-work-lease-v2",
                row["work_item_id"],
                attempt_number,
                worker_id,
                timestamp,
                time.time_ns(),
            )
            expires_at = timestamp + lease_seconds
            updated = self.connection.execute(
                """UPDATE work_items
                   SET state='leased', attempt_count=?, lease_owner=?, lease_token=?,
                       lease_expires_at=?, updated_at=?, finished_at=NULL
                   WHERE work_item_id=? AND state='pending'""",
                (
                    attempt_number,
                    worker_id,
                    lease_token,
                    expires_at,
                    _utc_now(),
                    row["work_item_id"],
                ),
            )
            if updated.rowcount != 1:
                return None
            cursor = self.connection.execute(
                """INSERT INTO work_attempts
                   (work_item_id, attempt_number, worker_id, lease_token, state, started_at)
                   VALUES (?, ?, ?, ?, 'leased', ?)""",
                (
                    row["work_item_id"],
                    attempt_number,
                    worker_id,
                    lease_token,
                    _utc_now(),
                ),
            )
            claimed = dict(row)
            claimed.update(
                {
                    "state": "leased",
                    "attempt_count": attempt_number,
                    "attempt_id": int(cursor.lastrowid),
                    "lease_owner": worker_id,
                    "lease_token": lease_token,
                    "lease_expires_at": expires_at,
                    "entry_state": json.loads(str(row["entry_state_json"])),
                    "payload": json.loads(str(row["payload_json"])),
                }
            )
            return claimed

    claim_work_item = claim_work

    def finish_work(
        self,
        work_item_id: str,
        lease_token: str,
        *,
        state: str = "completed",
        error: str | None = None,
        result: Mapping[str, Any] | None = None,
        revision_id: str | None = None,
    ) -> None:
        if state not in TERMINAL_WORK_STATES:
            raise ValueError(f"invalid terminal work state: {state}")
        now = _utc_now()
        with self.transaction(immediate=True):
            row = self.connection.execute(
                """SELECT state, lease_token, pending_entry_state_hash,
                          pending_entry_state_json, pending_payload_json
                   FROM work_items WHERE work_item_id=?""",
                (work_item_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown work item: {work_item_id}")
            if row["state"] != "leased" or row["lease_token"] != lease_token:
                raise LeaseError(f"work item {work_item_id} is not owned by this lease")
            attempt = self.connection.execute(
                """UPDATE work_attempts
                   SET state=?, finished_at=?, error=?, result_json=?
                   WHERE work_item_id=? AND lease_token=? AND finished_at IS NULL""",
                (
                    state,
                    now,
                    error,
                    canonical_json(result or {}),
                    work_item_id,
                    lease_token,
                ),
            )
            if attempt.rowcount != 1:
                raise LeaseError(f"active attempt for {work_item_id} was not found")
            if row["pending_entry_state_hash"] is not None:
                self.connection.execute(
                    """UPDATE work_items
                       SET state='pending',
                           entry_state_hash=pending_entry_state_hash,
                           entry_state_json=pending_entry_state_json,
                           payload_json=COALESCE(pending_payload_json, payload_json),
                           pending_entry_state_hash=NULL,
                           pending_entry_state_json=NULL,
                           pending_payload_json=NULL,
                           lease_owner=NULL, lease_token=NULL, lease_expires_at=NULL,
                           last_error=NULL,
                           selected_revision_id=COALESCE(?, selected_revision_id),
                           updated_at=?, finished_at=NULL
                       WHERE work_item_id=?""",
                    (revision_id, now, work_item_id),
                )
            else:
                self.connection.execute(
                    """UPDATE work_items
                       SET state=?, lease_owner=NULL, lease_token=NULL,
                           lease_expires_at=NULL, last_error=?,
                           selected_revision_id=COALESCE(?, selected_revision_id),
                           updated_at=?, finished_at=?
                       WHERE work_item_id=?""",
                    (state, error, revision_id, now, now, work_item_id),
                )

    finish_work_item = finish_work

    def retry_work(
        self,
        *,
        work_item_id: str | None = None,
        run_id: str | None = None,
        states: Iterable[str] = ("failed",),
        available_at: float = 0.0,
    ) -> int:
        if work_item_id is None and run_id is None:
            raise ValueError("work_item_id or run_id is required")
        retry_states = tuple(dict.fromkeys(states))
        if not retry_states or any(state not in RETRYABLE_WORK_STATES for state in retry_states):
            raise ValueError("retry states must be retryable terminal states")
        clauses = ["state IN (" + ",".join("?" for _ in retry_states) + ")"]
        parameters: list[Any] = list(retry_states)
        if work_item_id is not None:
            clauses.append("work_item_id=?")
            parameters.append(work_item_id)
        if run_id is not None:
            clauses.append("run_id=?")
            parameters.append(run_id)
        with self.transaction(immediate=True):
            cursor = self.connection.execute(
                """UPDATE work_items
                   SET state='pending', retry_count=retry_count+1, available_at=?,
                       lease_owner=NULL, lease_token=NULL, lease_expires_at=NULL,
                       updated_at=?, finished_at=NULL
                   WHERE """
                + " AND ".join(clauses),
                [float(available_at), _utc_now(), *parameters],
            )
            return int(cursor.rowcount)

    retry_failed_work = retry_work

    def recover_expired_leases(
        self,
        *,
        now: float | None = None,
        run_id: str | None = None,
    ) -> int:
        with self.transaction(immediate=True):
            return self._recover_expired_leases(
                time.time() if now is None else float(now), run_id=run_id
            )

    def _recover_expired_leases(self, now: float, *, run_id: str | None) -> int:
        clauses = ["state='leased'", "lease_expires_at IS NOT NULL", "lease_expires_at<=?"]
        parameters: list[Any] = [now]
        if run_id is not None:
            clauses.append("run_id=?")
            parameters.append(run_id)
        rows = list(
            self.connection.execute(
                "SELECT * FROM work_items WHERE " + " AND ".join(clauses), parameters
            )
        )
        timestamp = _utc_now()
        for row in rows:
            exhausted = bool(
                int(row["max_attempts"]) > 0
                and int(row["attempt_count"]) >= int(row["max_attempts"])
            )
            next_state = "failed" if exhausted else "pending"
            self.connection.execute(
                """UPDATE work_attempts
                   SET state='expired', finished_at=?, error=COALESCE(error, 'lease expired')
                   WHERE work_item_id=? AND lease_token=? AND finished_at IS NULL""",
                (timestamp, row["work_item_id"], row["lease_token"]),
            )
            self.connection.execute(
                """UPDATE work_items
                   SET state=CASE WHEN pending_entry_state_hash IS NOT NULL
                                  THEN 'pending' ELSE ? END,
                       entry_state_hash=COALESCE(pending_entry_state_hash, entry_state_hash),
                       entry_state_json=COALESCE(pending_entry_state_json, entry_state_json),
                       payload_json=COALESCE(pending_payload_json, payload_json),
                       pending_entry_state_hash=NULL,
                       pending_entry_state_json=NULL,
                       pending_payload_json=NULL,
                       lease_owner=NULL, lease_token=NULL, lease_expires_at=NULL,
                       last_error='lease expired', updated_at=?,
                       finished_at=CASE WHEN pending_entry_state_hash IS NOT NULL
                                        THEN NULL ELSE ? END
                   WHERE work_item_id=? AND state='leased' AND lease_token=?""",
                (
                    next_state,
                    timestamp,
                    timestamp if exhausted else None,
                    row["work_item_id"],
                    row["lease_token"],
                ),
            )
        return len(rows)

    def reconcile_work(
        self,
        run_id: str,
        *,
        module_version_id: str | None = None,
        priority: int = 0,
        resolutions: Iterable[str] = ("resolved_executable", "pending"),
    ) -> int:
        resolution_values = tuple(dict.fromkeys(resolutions))
        if not resolution_values:
            return 0
        module_clause = ""
        parameters: list[Any] = [run_id]
        if module_version_id is not None:
            module_clause = " AND bk.module_version_id=?"
            parameters.append(module_version_id)
        parameters.extend(resolution_values)
        with self.transaction(immediate=True):
            rows = list(
                self.connection.execute(
                    """SELECT DISTINCT
                              COALESCE(e.target_module_version_id, bk.module_version_id)
                                  AS module_version_id,
                              e.target_rva,
                              e.details_json
                       FROM run_block_selections AS selection
                       JOIN block_keys AS bk ON bk.block_key_id=selection.block_key_id
                       JOIN revision_edges AS e ON e.revision_id=selection.revision_id
                       WHERE selection.run_id=?"""
                    + module_clause
                    + """ AND e.target_rva IS NOT NULL
                         AND e.resolution IN ("""
                    + ",".join("?" for _ in resolution_values)
                    + ")",
                    parameters,
                )
            )
            inserted = 0
            for row in rows:
                module_id = str(row["module_version_id"])
                target_rva = int(row["target_rva"])
                details = json.loads(str(row["details_json"]))
                incoming_state = details.get("entry_state", {})
                selected = self.connection.execute(
                    """SELECT revision.entry_state_json
                       FROM run_block_selections AS selection
                       JOIN block_keys AS key ON key.block_key_id=selection.block_key_id
                       JOIN block_revisions AS revision
                         ON revision.revision_id=selection.revision_id
                       WHERE selection.run_id=? AND key.module_version_id=? AND key.rva=?""",
                    (run_id, module_id, target_rva),
                ).fetchone()
                if selected is not None:
                    selected_state = json.loads(str(selected["entry_state_json"]))
                    merged_state = _merge_entry_states(selected_state, incoming_state)
                    if merged_state == selected_state:
                        continue
                    incoming_state = merged_state
                item_key = stable_hash("d2wasm-block-work-v2", target_rva)
                exists = self.connection.execute(
                    """SELECT 1 FROM work_items
                       WHERE run_id=? AND module_version_id=?
                         AND kind='discover_block' AND item_key=?""",
                    (run_id, module_id, item_key),
                ).fetchone()
                self._enqueue_work(
                    run_id,
                    module_id,
                    target_rva,
                    kind="discover_block",
                    priority=priority,
                    entry_state=incoming_state,
                    payload={"reconciled": True},
                    state="pending",
                    error=None,
                    max_attempts=0,
                    available_at=0.0,
                    item_key=item_key,
                )
                if exists is None:
                    inserted += 1
            return inserted

    reconcile_successor_work = reconcile_work

    def persist_block_revision(
        self,
        run_id: str,
        module_version_id: str,
        rva: int,
        *,
        entry_state: Mapping[str, Any] | None = None,
        instructions: Iterable[Any] = (),
        edges: Iterable[Any] = (),
        xrefs: Iterable[Any] = (),
        terminator: str = "fallthrough",
        unsupported_reason: str | None = None,
        imported_call: Any | None = None,
        facts: Mapping[str, Any] | None = None,
        select: bool = True,
        refresh_projection: bool = True,
    ) -> str:
        module = self._module_row(module_version_id)
        normalized_instructions = self._normalize_instructions(module, instructions)
        normalized_edges = self._normalize_edges(
            module_version_id, module, normalized_instructions, edges
        )
        normalized_xrefs = self._normalize_xrefs(module, xrefs)
        with self.transaction(immediate=True):
            revision_id = self._persist_revision_rows(
                module_version_id=module_version_id,
                rva=int(rva),
                entry_state=entry_state or {},
                instructions=normalized_instructions,
                edges=normalized_edges,
                xrefs=normalized_xrefs,
                terminator=terminator,
                unsupported_reason=unsupported_reason,
                imported_call=self._normalize_import(imported_call),
                facts=facts or {},
            )
            if select:
                self.connection.execute(
                    """INSERT INTO run_block_selections
                       (run_id, block_key_id, revision_id, selected_at)
                       VALUES (?, ?, ?, ?)
                       ON CONFLICT(run_id, block_key_id) DO UPDATE SET
                           revision_id=excluded.revision_id,
                           selected_at=excluded.selected_at""",
                    (
                        run_id,
                        block_identity(module_version_id, int(rva)),
                        revision_id,
                        _utc_now(),
                    ),
                )
        if select and refresh_projection:
            self.refresh_compatibility_projection(run_id, module_version_id=module_version_id)
        return revision_id

    persist_revision = persist_block_revision

    def persist_claimed_block(
        self,
        work_item_id: str,
        lease_token: str,
        run_id: str,
        module_version_id: str,
        rva: int,
        *,
        entry_state: Mapping[str, Any] | None = None,
        instructions: Iterable[Any] = (),
        edges: Iterable[Any] = (),
        xrefs: Iterable[Any] = (),
        terminator: str = "fallthrough",
        unsupported_reason: str | None = None,
        imported_call: Any | None = None,
        facts: Mapping[str, Any] | None = None,
        related_revisions: Iterable[Mapping[str, Any]] = (),
    ) -> str:
        """Atomically select a revision and finish the lease that produced it."""

        with self.transaction(immediate=True):
            lease = self.connection.execute(
                "SELECT state, lease_token FROM work_items WHERE work_item_id=?",
                (work_item_id,),
            ).fetchone()
            if (
                lease is None
                or lease["state"] != "leased"
                or lease["lease_token"] != lease_token
            ):
                raise LeaseError(f"work item {work_item_id} is not owned by this lease")
            for related in related_revisions:
                self.persist_block_revision(
                    run_id,
                    str(related.get("module_version_id", module_version_id)),
                    int(related["rva"]),
                    entry_state=related.get("entry_state"),
                    instructions=related.get("instructions", ()),
                    edges=related.get("edges", ()),
                    xrefs=related.get("xrefs", ()),
                    terminator=str(related.get("terminator", "fallthrough")),
                    unsupported_reason=related.get("unsupported_reason"),
                    imported_call=related.get("imported_call"),
                    facts=related.get("facts"),
                    refresh_projection=False,
                )
            revision_id = self.persist_block_revision(
                run_id,
                module_version_id,
                rva,
                entry_state=entry_state,
                instructions=instructions,
                edges=edges,
                xrefs=xrefs,
                terminator=terminator,
                unsupported_reason=unsupported_reason,
                imported_call=imported_call,
                facts=facts,
                refresh_projection=False,
            )
            self.finish_work(
                work_item_id,
                lease_token,
                state="completed",
                revision_id=revision_id,
            )
        return revision_id

    def _persist_revision_rows(
        self,
        *,
        module_version_id: str,
        rva: int,
        entry_state: Mapping[str, Any],
        instructions: Sequence[Mapping[str, Any]],
        edges: Sequence[Mapping[str, Any]],
        xrefs: Sequence[Mapping[str, Any]],
        terminator: str,
        unsupported_reason: str | None,
        imported_call: Mapping[str, Any] | None,
        facts: Mapping[str, Any],
    ) -> str:
        module = self._module_row(module_version_id)
        block_key_id = block_identity(module_version_id, rva)
        now = _utc_now()
        self.connection.execute(
            """INSERT OR IGNORE INTO block_keys
               (block_key_id, module_version_id, rva, va, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (block_key_id, module_version_id, rva, int(module["load_base"]) + rva, now),
        )
        entry_state_hash = stable_hash("d2wasm-entry-state-v2", entry_state)
        import_data = imported_call or {}
        revision_facts = {
            "entry_state": entry_state,
            "instructions": [self._hashable_instruction(item) for item in instructions],
            "edges": list(edges),
            "xrefs": list(xrefs),
            "terminator": terminator,
            "unsupported_reason": unsupported_reason,
            "imported_call": import_data,
            "facts": facts,
        }
        revision_id = revision_identity(block_key_id, revision_facts)
        byte_length = sum(int(item["size"]) for item in instructions)
        cursor = self.connection.execute(
            """INSERT OR IGNORE INTO block_revisions
               (revision_id, block_key_id, revision_hash, entry_state_hash,
                entry_state_json, terminator, unsupported_reason, import_library,
                import_name, import_ordinal, import_iat_rva, instruction_count,
                byte_length, facts_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                revision_id,
                block_key_id,
                revision_id,
                entry_state_hash,
                canonical_json(entry_state),
                terminator,
                unsupported_reason,
                import_data.get("library"),
                import_data.get("name"),
                import_data.get("ordinal"),
                import_data.get("iat_rva"),
                len(instructions),
                byte_length,
                canonical_json(facts),
                now,
            ),
        )
        if cursor.rowcount:
            self.connection.executemany(
                """INSERT INTO revision_instructions
                   (revision_id, sequence, rva, size, bytes, mnemonic, op_str, details_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        revision_id,
                        index,
                        int(item["rva"]),
                        int(item["size"]),
                        bytes(item["bytes"]),
                        str(item["mnemonic"]),
                        str(item.get("op_str", "")),
                        canonical_json(item.get("details", {})),
                    )
                    for index, item in enumerate(instructions)
                ],
            )
            self.connection.executemany(
                """INSERT INTO revision_edges
                   (revision_id, sequence, source_instruction_rva,
                    target_module_version_id, target_rva, target_va, kind,
                    evidence_kind, resolution, operand_index, table_slot_rva,
                    table_index, details_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        revision_id,
                        index,
                        item.get("source_instruction_rva"),
                        item.get("target_module_version_id"),
                        item.get("target_rva"),
                        item.get("target_va"),
                        str(item["kind"]),
                        str(item.get("evidence_kind", "unknown")),
                        str(item.get("resolution", "unresolved_indirect")),
                        int(item.get("operand_index", -1)),
                        item.get("table_slot_rva"),
                        item.get("table_index"),
                        canonical_json(item.get("details", {})),
                    )
                    for index, item in enumerate(edges)
                ],
            )
            self.connection.executemany(
                """INSERT INTO revision_xrefs
                   (revision_id, sequence, source_rva, target_module_version_id,
                    target_rva, target_va, kind, operand_index, details_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        revision_id,
                        index,
                        int(item["source_rva"]),
                        item.get("target_module_version_id"),
                        item.get("target_rva"),
                        int(item["target_va"]),
                        str(item["kind"]),
                        int(item.get("operand_index", -1)),
                        canonical_json(item.get("details", {})),
                    )
                    for index, item in enumerate(xrefs)
                ],
            )
        return revision_id

    def select_block_revision(
        self,
        run_id: str,
        revision_id: str,
        *,
        refresh_projection: bool = True,
    ) -> None:
        row = self.connection.execute(
            """SELECT revision.block_key_id, key.module_version_id
               FROM block_revisions AS revision
               JOIN block_keys AS key ON key.block_key_id=revision.block_key_id
               WHERE revision.revision_id=?""",
            (revision_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"unknown block revision: {revision_id}")
        with self.transaction(immediate=True):
            self.connection.execute(
                """INSERT INTO run_block_selections
                   (run_id, block_key_id, revision_id, selected_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(run_id, block_key_id) DO UPDATE SET
                       revision_id=excluded.revision_id,
                       selected_at=excluded.selected_at""",
                (run_id, row["block_key_id"], revision_id, _utc_now()),
            )
        if refresh_projection:
            self.refresh_compatibility_projection(
                run_id, module_version_id=str(row["module_version_id"])
            )

    def clear_block_selection(self, run_id: str, module_version_id: str, rva: int) -> bool:
        block_key_id = block_identity(module_version_id, rva)
        with self.transaction(immediate=True):
            cursor = self.connection.execute(
                "DELETE FROM run_block_selections WHERE run_id=? AND block_key_id=?",
                (run_id, block_key_id),
            )
        if cursor.rowcount:
            self.refresh_compatibility_projection(run_id, module_version_id=module_version_id)
        return bool(cursor.rowcount)

    def refresh_compatibility_projection(
        self,
        run_id: str,
        *,
        module_version_id: str | None = None,
    ) -> None:
        # The legacy schema keys blocks and instructions by linked VA, so it can
        # represent only one selected graph. Rebuild the complete run even when a
        # caller supplies a module hint; a partial rebuild could strand or erase
        # cross-module edges.
        selections = list(
            self.connection.execute(
                """SELECT selection.revision_id, key.block_key_id, key.module_version_id,
                          key.rva AS block_rva, key.va AS block_va,
                          revision.terminator, revision.unsupported_reason,
                          revision.import_library, revision.import_name,
                          revision.import_ordinal, revision.instruction_count,
                          module.compatibility_module_id, module.load_base
                   FROM run_block_selections AS selection
                   JOIN block_keys AS key ON key.block_key_id=selection.block_key_id
                   JOIN block_revisions AS revision
                     ON revision.revision_id=selection.revision_id
                   JOIN module_versions AS module
                     ON module.module_version_id=key.module_version_id
                   WHERE selection.run_id=? ORDER BY key.va""",
                (run_id,),
            )
        )
        with self.transaction(immediate=True):
            self.connection.execute("DELETE FROM xrefs")
            self.connection.execute("DELETE FROM edges")
            self.connection.execute("DELETE FROM instructions")
            self.connection.execute("DELETE FROM blocks")
            self.connection.execute("DELETE FROM roots")
            self.connection.execute(
                """INSERT OR IGNORE INTO roots(module_id, rva, va)
                   SELECT module.compatibility_module_id, root.rva, root.va
                   FROM root_facts AS root
                   JOIN module_versions AS module
                     ON module.module_version_id=root.module_version_id
                   WHERE root.run_id=? AND root.accepted=1""",
                (run_id,),
            )

            self.connection.executemany(
                """INSERT INTO blocks
                   (va, module_id, rva, terminator, instruction_count,
                    unsupported_reason, import_library, import_name, import_ordinal)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        int(row["block_va"]),
                        int(row["compatibility_module_id"]),
                        int(row["block_rva"]),
                        str(row["terminator"]),
                        int(row["instruction_count"]),
                        row["unsupported_reason"],
                        row["import_library"],
                        row["import_name"],
                        row["import_ordinal"],
                    )
                    for row in selections
                ],
            )
            for selection in selections:
                instruction_rows = list(
                    self.connection.execute(
                        """SELECT * FROM revision_instructions
                           WHERE revision_id=? ORDER BY sequence""",
                        (selection["revision_id"],),
                    )
                )
                self.connection.executemany(
                    """INSERT INTO instructions
                       (va, module_id, block_va, rva, sequence, size, bytes, mnemonic, op_str)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    [
                        (
                            int(selection["load_base"]) + int(item["rva"]),
                            int(selection["compatibility_module_id"]),
                            int(selection["block_va"]),
                            int(item["rva"]),
                            int(item["sequence"]),
                            int(item["size"]),
                            bytes(item["bytes"]),
                            str(item["mnemonic"]),
                            str(item["op_str"]),
                        )
                        for item in instruction_rows
                    ],
                )

            projected_blocks = {
                int(row[0])
                for row in self.connection.execute("SELECT va FROM blocks")
            }
            module_rows = {
                str(row["module_version_id"]): row
                for row in self.connection.execute(
                    """SELECT module_version_id, compatibility_module_id, load_base
                       FROM module_versions"""
                )
            }
            for selection in selections:
                source_block_va = int(selection["block_va"])
                source_load_base = int(selection["load_base"])
                for edge in self.connection.execute(
                    "SELECT * FROM revision_edges WHERE revision_id=? ORDER BY sequence",
                    (selection["revision_id"],),
                ):
                    target_va = edge["target_va"]
                    target_module = module_rows.get(str(edge["target_module_version_id"]))
                    if target_va is None and target_module is not None and edge["target_rva"] is not None:
                        target_va = int(target_module["load_base"]) + int(edge["target_rva"])
                    if target_va is None or int(target_va) not in projected_blocks:
                        continue
                    source_instruction_rva = edge["source_instruction_rva"]
                    source_instruction_va = (
                        source_load_base + int(source_instruction_rva)
                        if source_instruction_rva is not None
                        else source_block_va
                    )
                    self.connection.execute(
                        """INSERT OR IGNORE INTO edges
                           (source_block_va, source_instruction_va, target_block_va, kind)
                           VALUES (?, ?, ?, ?)""",
                        (
                            source_block_va,
                            source_instruction_va,
                            int(target_va),
                            str(edge["kind"]),
                        ),
                    )
                for xref in self.connection.execute(
                    "SELECT * FROM revision_xrefs WHERE revision_id=? ORDER BY sequence",
                    (selection["revision_id"],),
                ):
                    target_module = module_rows.get(str(xref["target_module_version_id"]))
                    self.connection.execute(
                        """INSERT OR IGNORE INTO xrefs
                           (source_va, target_va, kind, operand_index, target_module_id)
                           VALUES (?, ?, ?, ?, ?)""",
                        (
                            source_load_base + int(xref["source_rva"]),
                            int(xref["target_va"]),
                            str(xref["kind"]),
                            int(xref["operand_index"]),
                            (
                                int(target_module["compatibility_module_id"])
                                if target_module is not None
                                else None
                            ),
                        ),
                    )
            summary = {
                "modules": len(
                    {str(selection["module_version_id"]) for selection in selections}
                ),
                "blocks": len(selections),
                "instructions": int(
                    self.connection.execute("SELECT COUNT(*) FROM instructions").fetchone()[0]
                ),
            }
            self.connection.execute(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES ('summary', ?)",
                (canonical_json(summary),),
            )

    refresh_compatibility = refresh_compatibility_projection

    def load_revision(self, revision_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            """SELECT revision.*, key.module_version_id, key.rva, key.va
               FROM block_revisions AS revision
               JOIN block_keys AS key ON key.block_key_id=revision.block_key_id
               WHERE revision.revision_id=?""",
            (revision_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"unknown block revision: {revision_id}")
        return self._revision_record(row)

    def load_selected_revisions(
        self,
        run_id: str,
        *,
        module_version_id: str | None = None,
    ) -> list[dict[str, Any]]:
        parameters: list[Any] = [run_id]
        module_clause = ""
        if module_version_id is not None:
            module_clause = " AND key.module_version_id=?"
            parameters.append(module_version_id)
        rows = list(
            self.connection.execute(
                """SELECT revision.*, key.module_version_id, key.rva, key.va
                   FROM run_block_selections AS selection
                   JOIN block_revisions AS revision
                     ON revision.revision_id=selection.revision_id
                   JOIN block_keys AS key ON key.block_key_id=selection.block_key_id
                   WHERE selection.run_id=?"""
                + module_clause
                + " ORDER BY key.va",
                parameters,
            )
        )
        records: dict[str, dict[str, Any]] = {}
        order = []
        for row in rows:
            record = dict(row)
            for key_name in ("entry_state_json", "facts_json"):
                record[key_name[:-5]] = json.loads(str(record[key_name]))
            record["instructions"] = []
            record["edges"] = []
            record["xrefs"] = []
            revision_id = str(record["revision_id"])
            records[revision_id] = record
            order.append(revision_id)
        if not records:
            return []

        child_parameters = list(parameters)
        for table, destination in (
            ("revision_instructions", "instructions"),
            ("revision_edges", "edges"),
            ("revision_xrefs", "xrefs"),
        ):
            for item in self.connection.execute(
                f"""SELECT child.* FROM run_block_selections AS selection
                    JOIN block_keys AS key ON key.block_key_id=selection.block_key_id
                    JOIN {table} AS child ON child.revision_id=selection.revision_id
                    WHERE selection.run_id=?"""
                + module_clause
                + " ORDER BY child.revision_id, child.sequence",
                child_parameters,
            ):
                value = dict(item)
                if "bytes" in value:
                    value["bytes"] = bytes(value["bytes"])
                if "details_json" in value:
                    value["details"] = json.loads(str(value.pop("details_json")))
                records[str(value["revision_id"])][destination].append(value)
        return [records[revision_id] for revision_id in order]

    load_revision_rows = load_selected_revisions

    def _revision_record(self, row: sqlite3.Row) -> dict[str, Any]:
        record = dict(row)
        for key in ("entry_state_json", "facts_json"):
            record[key[:-5]] = json.loads(str(record[key]))
        instructions = []
        for item in self.connection.execute(
            "SELECT * FROM revision_instructions WHERE revision_id=? ORDER BY sequence",
            (record["revision_id"],),
        ):
            value = dict(item)
            value["bytes"] = bytes(value["bytes"])
            value["details"] = json.loads(str(value.pop("details_json")))
            instructions.append(value)
        edges = []
        for item in self.connection.execute(
            "SELECT * FROM revision_edges WHERE revision_id=? ORDER BY sequence",
            (record["revision_id"],),
        ):
            value = dict(item)
            value["details"] = json.loads(str(value.pop("details_json")))
            edges.append(value)
        xrefs = []
        for item in self.connection.execute(
            "SELECT * FROM revision_xrefs WHERE revision_id=? ORDER BY sequence",
            (record["revision_id"],),
        ):
            value = dict(item)
            value["details"] = json.loads(str(value.pop("details_json")))
            xrefs.append(value)
        record["instructions"] = instructions
        record["edges"] = edges
        record["xrefs"] = xrefs
        return record

    def save_byte_classifications(
        self,
        run_id: str,
        module_version_id: str,
        classifications: Iterable[Mapping[str, Any] | Sequence[Any]],
        *,
        mapped_executable_bytes: int | None = None,
    ) -> dict[str, int]:
        normalized = []
        for item in classifications:
            if isinstance(item, Mapping):
                start = int(item.get("start_rva", item.get("start", 0)))
                end = int(item.get("end_rva", item.get("end", 0)))
                category = str(item.get("classification", item.get("category", "")))
                evidence = str(item.get("evidence", category))
                details = item.get("details", {})
            else:
                if len(item) < 3:
                    raise ValueError("classification tuples require start, end, and category")
                start, end, category = int(item[0]), int(item[1]), str(item[2])
                evidence = str(item[3]) if len(item) > 3 else category
                details = item[4] if len(item) > 4 else {}
            if category not in BYTE_CLASSIFICATIONS:
                raise ValueError(f"invalid executable byte classification: {category}")
            if end <= start:
                raise ValueError("classification ranges must be non-empty")
            normalized.append((start, end, category, evidence, details))
        normalized.sort(key=lambda row: (row[0], row[1], row[2]))
        previous_end = None
        for start, end, _, _, _ in normalized:
            if previous_end is not None and start < previous_end:
                raise ValueError("executable byte classifications overlap")
            previous_end = end

        module = self._module_row(module_version_id)
        executable_ranges = [
            (int(row["rva"]), int(row["rva"]) + max(
                int(row["virtual_size"]), int(row["file_size"])
            ))
            for row in self.connection.execute(
                """SELECT rva, virtual_size, file_size FROM sections
                   WHERE module_id=? AND executable=1 ORDER BY rva""",
                (int(module["compatibility_module_id"]),),
            )
            if max(int(row["virtual_size"]), int(row["file_size"])) > 0
        ]

        def merged_ranges(ranges: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
            merged: list[tuple[int, int]] = []
            for start, end in sorted(ranges):
                if not merged or start > merged[-1][1]:
                    merged.append((start, end))
                else:
                    merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            return merged

        expected_ranges = merged_ranges(executable_ranges)
        classified_ranges = merged_ranges((row[0], row[1]) for row in normalized)
        if expected_ranges and classified_ranges != expected_ranges:
            raise ValueError(
                "classifications must cover every mapped executable byte exactly once"
            )
        totals = {category: 0 for category in BYTE_CLASSIFICATIONS}
        for start, end, category, _, _ in normalized:
            totals[category] += end - start
        total = sum(totals.values())
        if mapped_executable_bytes is not None and total != int(mapped_executable_bytes):
            raise ValueError(
                f"classified executable bytes ({total}) do not equal mapped bytes "
                f"({int(mapped_executable_bytes)})"
            )
        with self.transaction(immediate=True):
            self.connection.execute(
                """DELETE FROM executable_byte_classifications
                   WHERE run_id=? AND module_version_id=?""",
                (run_id, module_version_id),
            )
            self.connection.executemany(
                """INSERT INTO executable_byte_classifications
                   (run_id, module_version_id, start_rva, end_rva, classification,
                    evidence, details_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        run_id,
                        module_version_id,
                        start,
                        end,
                        category,
                        evidence,
                        canonical_json(details),
                    )
                    for start, end, category, evidence, details in normalized
                ],
            )
        return {**totals, "total": total}

    save_classifications = save_byte_classifications

    def save_graph_accounting(
        self,
        run_id: str,
        module_version_id: str,
        metrics: Mapping[str, Any],
    ) -> None:
        category_totals = {
            str(row["classification"]): int(row["total"])
            for row in self.connection.execute(
                """SELECT classification, SUM(end_rva-start_rva) AS total
                   FROM executable_byte_classifications
                   WHERE run_id=? AND module_version_id=? GROUP BY classification""",
                (run_id, module_version_id),
            )
        }
        values = {
            "confirmed_code_bytes": category_totals.get("confirmed_code", 0),
            "probable_code_bytes": category_totals.get("probable_code", 0),
            "embedded_data_bytes": category_totals.get("embedded_data", 0),
            "padding_bytes": category_totals.get("padding", 0),
            "unresolved_bytes": category_totals.get("unresolved", 0),
        }
        classified = sum(values.values())
        mapped = int(metrics.get("mapped_executable_bytes", classified))
        explicit_classified = int(metrics.get("classified_executable_bytes", classified))
        if explicit_classified != classified:
            raise ValueError("classified byte total does not equal the category sum")
        if mapped != classified:
            raise ValueError("executable byte accounting is not exhaustive")
        columns = {
            "resolved_direct_edges": int(metrics.get("resolved_direct_edges", 0)),
            "rejected_direct_edges": int(metrics.get("rejected_direct_edges", 0)),
            "unresolved_indirect_calls": int(metrics.get("unresolved_indirect_calls", 0)),
            "unresolved_indirect_jumps": int(metrics.get("unresolved_indirect_jumps", 0)),
            "blocked_targets": int(metrics.get("blocked_targets", 0)),
            "overlaps_conflicts": int(metrics.get("overlaps_conflicts", 0)),
            "selected_blocks": int(metrics.get("selected_blocks", 0)),
            "selected_instructions": int(metrics.get("selected_instructions", 0)),
            "pending_work": int(metrics.get("pending_work", 0)),
        }
        if any(value < 0 for value in [mapped, classified, *values.values(), *columns.values()]):
            raise ValueError("graph accounting values cannot be negative")
        with self.transaction(immediate=True):
            self.connection.execute(
                """INSERT INTO graph_accounting
                   (run_id, module_version_id, mapped_executable_bytes,
                    classified_executable_bytes, confirmed_code_bytes,
                    probable_code_bytes, embedded_data_bytes, padding_bytes,
                    unresolved_bytes, resolved_direct_edges, rejected_direct_edges,
                    unresolved_indirect_calls, unresolved_indirect_jumps,
                    blocked_targets, overlaps_conflicts, selected_blocks,
                    selected_instructions, pending_work, metrics_json, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(run_id, module_version_id) DO UPDATE SET
                       mapped_executable_bytes=excluded.mapped_executable_bytes,
                       classified_executable_bytes=excluded.classified_executable_bytes,
                       confirmed_code_bytes=excluded.confirmed_code_bytes,
                       probable_code_bytes=excluded.probable_code_bytes,
                       embedded_data_bytes=excluded.embedded_data_bytes,
                       padding_bytes=excluded.padding_bytes,
                       unresolved_bytes=excluded.unresolved_bytes,
                       resolved_direct_edges=excluded.resolved_direct_edges,
                       rejected_direct_edges=excluded.rejected_direct_edges,
                       unresolved_indirect_calls=excluded.unresolved_indirect_calls,
                       unresolved_indirect_jumps=excluded.unresolved_indirect_jumps,
                       blocked_targets=excluded.blocked_targets,
                       overlaps_conflicts=excluded.overlaps_conflicts,
                       selected_blocks=excluded.selected_blocks,
                       selected_instructions=excluded.selected_instructions,
                       pending_work=excluded.pending_work,
                       metrics_json=excluded.metrics_json,
                       updated_at=excluded.updated_at""",
                (
                    run_id,
                    module_version_id,
                    mapped,
                    classified,
                    values["confirmed_code_bytes"],
                    values["probable_code_bytes"],
                    values["embedded_data_bytes"],
                    values["padding_bytes"],
                    values["unresolved_bytes"],
                    columns["resolved_direct_edges"],
                    columns["rejected_direct_edges"],
                    columns["unresolved_indirect_calls"],
                    columns["unresolved_indirect_jumps"],
                    columns["blocked_targets"],
                    columns["overlaps_conflicts"],
                    columns["selected_blocks"],
                    columns["selected_instructions"],
                    columns["pending_work"],
                    canonical_json(metrics),
                    _utc_now(),
                ),
            )

    save_accounting = save_graph_accounting

    def work_counts(self, run_id: str) -> dict[str, int]:
        counts = {state: 0 for state in sorted(WORK_STATES)}
        counts.update(
            {
                str(row["state"]): int(row["count"])
                for row in self.connection.execute(
                    """SELECT state, COUNT(*) AS count FROM work_items
                       WHERE run_id=? GROUP BY state""",
                    (run_id,),
                )
            }
        )
        counts["total"] = sum(counts[state] for state in WORK_STATES)
        counts["unfinished"] = counts["pending"] + counts["leased"]
        return counts

    def query_counts(self, run_id: str) -> dict[str, Any]:
        selected = self.connection.execute(
            """SELECT COUNT(*) AS blocks,
                      COALESCE(SUM(revision.instruction_count), 0) AS instructions
               FROM run_block_selections AS selection
               JOIN block_revisions AS revision
                 ON revision.revision_id=selection.revision_id
               WHERE selection.run_id=?""",
            (run_id,),
        ).fetchone()
        revisions = int(
            self.connection.execute(
                """SELECT COUNT(DISTINCT revision.revision_id)
                   FROM block_revisions AS revision
                   JOIN block_keys AS key ON key.block_key_id=revision.block_key_id
                   JOIN module_versions AS module
                     ON module.module_version_id=key.module_version_id
                   JOIN analysis_runs AS run ON run.project_id=module.project_id
                   WHERE run.run_id=?""",
                (run_id,),
            ).fetchone()[0]
        )
        edge_resolutions = {
            str(row["resolution"]): int(row["count"])
            for row in self.connection.execute(
                """SELECT edge.resolution, COUNT(*) AS count
                   FROM run_block_selections AS selection
                   JOIN revision_edges AS edge ON edge.revision_id=selection.revision_id
                   WHERE selection.run_id=? GROUP BY edge.resolution""",
                (run_id,),
            )
        }
        byte_totals = {
            str(row["classification"]): int(row["bytes"])
            for row in self.connection.execute(
                """SELECT classification, SUM(end_rva-start_rva) AS bytes
                   FROM executable_byte_classifications WHERE run_id=?
                   GROUP BY classification""",
                (run_id,),
            )
        }
        return {
            "selected_blocks": int(selected["blocks"]),
            "selected_instructions": int(selected["instructions"]),
            "immutable_revisions": revisions,
            "root_facts": int(
                self.connection.execute(
                    "SELECT COUNT(*) FROM root_facts WHERE run_id=?", (run_id,)
                ).fetchone()[0]
            ),
            "work": self.work_counts(run_id),
            "edge_resolutions": edge_resolutions,
            "byte_classifications": byte_totals,
        }

    counts = query_counts

    def integrity_check(self) -> dict[str, Any]:
        integrity = [str(row[0]) for row in self.connection.execute("PRAGMA integrity_check")]
        foreign_keys = [dict(row) for row in self.connection.execute("PRAGMA foreign_key_check")]
        return {
            "integrity": integrity,
            "foreign_key_violations": foreign_keys,
            "ok": integrity == ["ok"] and not foreign_keys,
        }

    def _validate_run_module(self, run_id: str, module_version_id: str) -> None:
        row = self.connection.execute(
            """SELECT 1 FROM analysis_runs AS run
               JOIN module_versions AS module ON module.project_id=run.project_id
               WHERE run.run_id=? AND module.module_version_id=?""",
            (run_id, module_version_id),
        ).fetchone()
        if row is None:
            raise ValueError(
                f"analysis run {run_id} and module {module_version_id} do not share a project"
            )

    def _module_row(self, module_version_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM module_versions WHERE module_version_id=?",
            (module_version_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"unknown module version: {module_version_id}")
        return row

    @staticmethod
    def _value(item: Any, name: str, default: Any = None) -> Any:
        if isinstance(item, Mapping):
            return item.get(name, default)
        return getattr(item, name, default)

    def _normalize_instructions(
        self, module: sqlite3.Row, instructions: Iterable[Any]
    ) -> list[dict[str, Any]]:
        result = []
        image_base = int(module["image_base"])
        for item in instructions:
            address = self._value(item, "address")
            rva = self._value(item, "rva")
            if rva is None:
                if address is None:
                    raise ValueError("stored instructions require an RVA or address")
                rva = int(address) - image_base
            raw_bytes = self._value(item, "bytes", b"")
            raw_bytes = bytes(raw_bytes)
            size = int(self._value(item, "size", len(raw_bytes)))
            if size <= 0 or len(raw_bytes) != size:
                raise ValueError("instruction byte length must equal its positive size")
            details = self._value(item, "details", {})
            result.append(
                {
                    "rva": int(rva),
                    "size": size,
                    "bytes": raw_bytes,
                    "mnemonic": str(self._value(item, "mnemonic", "")),
                    "op_str": str(self._value(item, "op_str", "")),
                    "details": details or {},
                }
            )
        for previous, current in zip(result, result[1:]):
            if int(current["rva"]) < int(previous["rva"]) + int(previous["size"]):
                raise ValueError("revision instructions overlap or are out of order")
        return result

    def _normalize_edges(
        self,
        module_version_id: str,
        module: sqlite3.Row,
        instructions: Sequence[Mapping[str, Any]],
        edges: Iterable[Any],
    ) -> list[dict[str, Any]]:
        result = []
        default_source = int(instructions[-1]["rva"]) if instructions else None
        for item in edges:
            if isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray, Mapping)):
                if len(item) < 2:
                    raise ValueError("edge tuples require target RVA and kind")
                item = {"target_rva": item[0], "kind": item[1]}
            target_module_id = self._value(
                item, "target_module_version_id", module_version_id
            )
            target_rva = self._value(item, "target_rva")
            target_va = self._value(item, "target_va")
            if target_va is None and target_rva is not None:
                target_module = self._module_row(str(target_module_id))
                target_va = int(target_module["load_base"]) + int(target_rva)
            resolution = self._value(item, "resolution")
            if resolution is None:
                resolution = (
                    "resolved_executable" if target_rva is not None else "unresolved_indirect"
                )
            result.append(
                {
                    "source_instruction_rva": self._value(
                        item, "source_instruction_rva", default_source
                    ),
                    "target_module_version_id": target_module_id,
                    "target_rva": int(target_rva) if target_rva is not None else None,
                    "target_va": int(target_va) if target_va is not None else None,
                    "kind": str(self._value(item, "kind", "unknown")),
                    "evidence_kind": str(
                        self._value(item, "evidence_kind", "decoder")
                    ),
                    "resolution": str(resolution),
                    "operand_index": int(self._value(item, "operand_index", -1)),
                    "table_slot_rva": self._value(item, "table_slot_rva"),
                    "table_index": self._value(item, "table_index"),
                    "details": self._value(item, "details", {}) or {},
                }
            )
        return result

    def _normalize_xrefs(
        self, module: sqlite3.Row, xrefs: Iterable[Any]
    ) -> list[dict[str, Any]]:
        result = []
        load_base = int(module["load_base"])
        for item in xrefs:
            source_rva = self._value(item, "source_rva")
            source_va = self._value(item, "source_va")
            if source_rva is None and source_va is not None:
                source_rva = int(source_va) - load_base
            if source_rva is None:
                raise ValueError("stored xrefs require source_rva or source_va")
            target_module_id = self._value(item, "target_module_version_id")
            target_rva = self._value(item, "target_rva")
            target_va = self._value(item, "target_va")
            if target_va is None and target_module_id is not None and target_rva is not None:
                target_module = self._module_row(str(target_module_id))
                target_va = int(target_module["load_base"]) + int(target_rva)
            if target_va is None:
                raise ValueError("stored xrefs require target_va or a target module/RVA")
            result.append(
                {
                    "source_rva": int(source_rva),
                    "target_module_version_id": target_module_id,
                    "target_rva": int(target_rva) if target_rva is not None else None,
                    "target_va": int(target_va),
                    "kind": str(self._value(item, "kind", "data")),
                    "operand_index": int(self._value(item, "operand_index", -1)),
                    "details": self._value(item, "details", {}) or {},
                }
            )
        return result

    @classmethod
    def _normalize_import(cls, imported_call: Any | None) -> dict[str, Any] | None:
        if imported_call is None:
            return None
        return {
            "library": cls._value(imported_call, "library"),
            "name": cls._value(imported_call, "name"),
            "ordinal": cls._value(imported_call, "ordinal"),
            "iat_rva": cls._value(imported_call, "iat_rva"),
        }

    @staticmethod
    def _hashable_instruction(item: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "rva": int(item["rva"]),
            "size": int(item["size"]),
            "bytes": bytes(item["bytes"]),
            "mnemonic": str(item["mnemonic"]),
            "op_str": str(item.get("op_str", "")),
            "details": item.get("details", {}),
        }


__all__ = [
    "BYTE_CLASSIFICATIONS",
    "DATABASE_SCHEMA_VERSION",
    "LeaseError",
    "RETRYABLE_WORK_STATES",
    "SchemaVersionError",
    "TERMINAL_WORK_STATES",
    "TranslationStore",
    "WORK_STATES",
    "WorkspaceError",
    "binary_identity",
    "block_identity",
    "canonical_json",
    "canonical_manifest_data",
    "module_identity",
    "project_identity",
    "revision_identity",
    "stable_hash",
]
