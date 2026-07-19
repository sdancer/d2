from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any

from .analysis import (
    classify_executable_bytes,
    instruction_surface,
    summarize_graph_accounting,
)
from .api import load_api_specs
from .cfg import EntryState, discover_cfg, discover_cfg_workspace
from .codegen import CGenerator, LinkedCGenerator, compile_wasm
from .debugdb import DebugUnit, extract_strings, write_debug_database
from .linker import plan_linked_image
from .pe import PEImage
from .recovery import recover_all_functions
from .semantics import translate_all_semantics
from .validation import persist_equivalence, promote_function, register_replacement
from .workspace import TranslationStore


SCHEMA_VERSION = 1


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def inventory(args: argparse.Namespace) -> int:
    source_dir: Path = args.source_dir
    filename_map: dict[str, str] = {}
    if args.filename_map:
        filename_map = json.loads(args.filename_map.read_text())
        paths = [source_dir / name for name in filename_map]
    else:
        paths = sorted(source_dir.glob("*.exe"))

    modules = []
    failures = []
    all_imports: Counter[str] = Counter()
    all_mnemonics: Counter[str] = Counter()
    runtime_names = {name.lower() for name in filename_map.values()}

    for path in paths:
        if not path.exists():
            failures.append({"source": path.name, "error": "missing file"})
            continue
        try:
            image = PEImage(path)
            module = image.inventory(filename_map.get(path.name))
            module["instruction_surface"] = instruction_surface(image)
            modules.append(module)
            all_mnemonics.update(module["instruction_surface"]["mnemonics"])
            all_imports.update(symbol.library.lower() for symbol in image.imports)
        except Exception as error:
            failures.append({"source": path.name, "error": str(error)})

    external_libraries = sorted(name for name in all_imports if name not in runtime_names)
    internal_libraries = sorted(name for name in all_imports if name in runtime_names)
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_dir": str(source_dir.resolve()),
        "modules": modules,
        "failures": failures,
        "summary": {
            "module_count": len(modules),
            "total_file_bytes": sum(module["file_size"] for module in modules),
            "total_executable_bytes": sum(module["instruction_surface"]["executable_bytes"] for module in modules),
            "total_instructions": sum(module["instruction_surface"]["instruction_count"] for module in modules),
            "internal_libraries": internal_libraries,
            "external_libraries": external_libraries,
            "library_import_counts": dict(sorted(all_imports.items())),
            "mnemonics": dict(sorted(all_mnemonics.items(), key=lambda item: (-item[1], item[0]))),
        },
    }
    write_json(args.output, report)
    print(
        f"Inventoried {len(modules)} PE modules, {report['summary']['total_instructions']} "
        f"decoded instructions -> {args.output}"
    )
    if failures:
        print(f"{len(failures)} input failures recorded in the report", file=sys.stderr)
        return 1
    return 0


def translate(args: argparse.Namespace) -> int:
    image = PEImage(args.executable)
    load_base = int(args.load_base, 0) if args.load_base else image.image_base
    roots = [image.entry_rva]
    if args.root:
        roots = [int(value, 0) for value in args.root]
    if args.relocation_roots:
        roots = list(dict.fromkeys(roots + image.relocation_code_roots()))
    blocks = discover_cfg(image, roots, max_blocks=args.max_blocks)
    api_specs = load_api_specs(args.api_spec)
    generator = CGenerator(
        image,
        blocks,
        api_specs,
        load_base=load_base,
        global_pc=args.global_pc,
    )
    source = generator.generate()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    source_path = args.output_dir / "lifted.c"
    wasm_path = args.output_dir / "lifted.wasm"
    report_path = args.output_dir / "translation.json"
    source_path.write_text(source)

    instruction_count = sum(len(block.instructions) for block in blocks.values())
    source_record = image.inventory()
    source_record.update(
        {
            "load_base": load_base,
            "relocation_delta": load_base - image.image_base,
            "relocation_entries": [
                {"rva": int(entry.address), "type": int(entry.type)}
                for block in image.binary.relocations
                for entry in block.entries
                if int(entry.type) != 0
            ],
        }
    )
    report = {
        "schema_version": SCHEMA_VERSION,
        "source": source_record,
        "roots": roots,
        "root_pcs": [load_base + root if args.global_pc else root for root in roots],
        "global_pc": args.global_pc,
        "block_count": len(blocks),
        "instruction_count": instruction_count,
        "block_limit_reached": len(blocks) >= args.max_blocks,
        "partial": bool(generator.unsupported),
        "terminators": dict(sorted(Counter(block.terminator for block in blocks.values()).items())),
        "unsupported": [
            {"rva": site.rva, "instruction": site.instruction, "reason": site.reason}
            for site in generator.unsupported
        ],
        "api_imports": [
            {
                "library": spec.library,
                "name": spec.name,
                "arg_bytes": spec.arg_bytes,
                "convention": spec.convention,
                "no_return": spec.no_return,
            }
            for spec in sorted(generator.used_apis.values(), key=lambda value: value.key)
        ],
        "artifacts": {"c": source_path.name, "wasm": wasm_path.name},
    }
    write_json(report_path, report)

    if generator.unsupported and not args.emit_partial:
        print(
            f"Discovered {len(blocks)} blocks / {instruction_count} instructions; "
            f"{len(generator.unsupported)} unsupported sites -> {report_path}",
            file=sys.stderr,
        )
        return 2
    if args.report_only:
        print(f"Lifted {len(blocks)} blocks / {instruction_count} instructions -> {source_path}")
        return 0

    initial_memory = max(16 * 1024 * 1024, ((load_base + image.size_of_image + 65535) // 65536) * 65536)
    compile_wasm(source_path, wasm_path, initial_memory, args.opt_level)
    qualifier = "partial " if generator.unsupported else ""
    print(f"Lifted {len(blocks)} blocks / {instruction_count} instructions -> {qualifier}{wasm_path}")
    if generator.unsupported:
        print(f"Artifact contains {len(generator.unsupported)} explicit unsupported traps; see {report_path}", file=sys.stderr)
        return 2
    return 0


def link(args: argparse.Namespace) -> int:
    filename_map = json.loads(args.filename_map.read_text())
    report = plan_linked_image(args.source_dir, filename_map, args.entry_module)
    write_json(args.output, report)
    summary = report["summary"]
    print(
        f"Planned {summary['module_count']} modules, {summary['relocated_module_count']} relocated, "
        f"{summary['internal_binding_count']} internal bindings -> {args.output}"
    )
    if report["unresolved_internal_imports"]:
        print(
            f"{len(report['unresolved_internal_imports'])} internal imports could not be resolved",
            file=sys.stderr,
        )
        return 2
    return 0


def _link_translate_workspace(args: argparse.Namespace) -> int:
    manifest = json.loads(args.link_manifest.read_text())
    api_specs = load_api_specs(args.api_spec)
    known_modules = {
        module["runtime_name"].lower(): module for module in manifest["modules"]
    }
    root_facts: dict[str, list[dict[str, Any]]] = {
        name: [] for name in known_modules
    }

    def add_root(
        module_name: str,
        rva: int,
        kind: str,
        details: dict[str, Any],
        priority: int,
        accepted: bool | None = None,
    ) -> None:
        root_facts[module_name.lower()].append(
            {
                "rva": int(rva),
                "kind": kind,
                "details": details,
                "priority": priority,
                "accepted": accepted,
            }
        )

    configured_roots = json.loads(args.roots_file.read_text()) if args.roots_file else {}
    for module_name, values in configured_roots.items():
        key = module_name.lower()
        if key not in known_modules:
            raise ValueError(f"unknown module in roots file: {module_name}")
        for value in values:
            rva = int(value, 0) if isinstance(value, str) else int(value)
            add_root(key, rva, "configured_file", {"file": str(args.roots_file)}, 70)
    for root in args.root or []:
        module_name, separator, rva_text = root.rpartition(":")
        key = module_name.lower()
        if not separator or key not in known_modules:
            choices = ", ".join(sorted(item["runtime_name"] for item in known_modules.values()))
            raise ValueError(f"linked root must be MODULE:RVA; known modules: {choices}")
        add_root(key, int(rva_text, 0), "configured_cli", {"argument": root}, 75)

    bindings_by_importer: dict[str, dict[str, int]] = {}
    for binding in manifest["internal_bindings"]:
        symbol = binding["name"] if binding["name"] else f"#{binding['ordinal']}"
        key = f"{binding['library'].lower()}!{symbol}"
        bindings_by_importer.setdefault(binding["importer"].lower(), {})[key] = int(
            binding["target_va"]
        )
        add_root(
            binding["target_module"],
            int(binding["target_rva"]),
            "internal_binding",
            {
                "importer": binding["importer"],
                "library": binding["library"],
                "name": binding["name"],
                "ordinal": binding["ordinal"],
                "iat_rva": int(binding["iat_rva"]),
            },
            90,
        )

    relocation_root_modules = {
        name.lower() for name in (args.relocation_roots_module or [])
    }
    unknown_relocation_modules = relocation_root_modules - set(known_modules)
    if unknown_relocation_modules:
        raise ValueError(
            f"unknown relocation-root modules: {', '.join(sorted(unknown_relocation_modules))}"
        )

    images: dict[str, PEImage] = {}
    executable_modules = []
    for module in manifest["modules"]:
        key = module["runtime_name"].lower()
        image = PEImage(args.source_dir / module["source"])
        if not image.executable_sections():
            continue
        images[key] = image
        executable_modules.append(module)
        add_root(key, image.entry_rva, "pe_entry", {}, 100)
        for export in module.get("exports", []):
            if int(export["rva"]):
                add_root(
                    key,
                    int(export["rva"]),
                    "pe_export",
                    {"name": export.get("name"), "ordinal": int(export["ordinal"])},
                    80,
                )
        if args.relocation_roots or key in relocation_root_modules:
            for fact in image.relocation_code_pointer_facts():
                if not image.is_mapped_rva(int(fact["target_rva"])):
                    continue
                add_root(
                    key,
                    int(fact["target_rva"]),
                    "relocation_code_pointer",
                    {
                        "slot_rva": int(fact["slot_rva"]),
                        "target_va": int(fact["target_va"]),
                        "resolution": fact["resolution"],
                    },
                    60,
                    accepted=fact["resolution"] == "resolved_executable",
                )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    debug_path = args.debug_db
    if not debug_path.is_absolute() and debug_path.parent == Path("."):
        debug_path = args.output_dir / debug_path

    units = []
    module_reports = []
    blocks_by_module: dict[str, dict[int, Any]] = {}
    with TranslationStore(debug_path) as store:
        project_id = store.register_project(
            manifest,
            name=Path(args.link_manifest).stem,
            metadata={"link_manifest": str(args.link_manifest.resolve())},
        )
        module_versions: dict[str, str] = {}
        for module in executable_modules:
            key = module["runtime_name"].lower()
            image = images[key]
            module_versions[key] = store.register_module(
                project_id,
                module,
                binary_data=image.data,
                inventory=image.inventory(module["runtime_name"]),
            )
        for module in executable_modules:
            key = module["runtime_name"].lower()
            image = images[key]
            store.register_static_inventory(
                module_versions[key],
                image.inventory(module["runtime_name"]),
                internal_bindings=manifest["internal_bindings"],
                strings=extract_strings(image),
            )
        workspace_bindings: dict[str, dict[str, dict[str, Any]]] = {}
        for binding in manifest["internal_bindings"]:
            target_key = binding["target_module"].lower()
            if target_key not in module_versions:
                continue
            symbol = binding["name"] or f"#{binding['ordinal']}"
            display_name = f"{binding['library'].lower()}!{symbol}"
            workspace_bindings.setdefault(binding["importer"].lower(), {})[
                display_name
            ] = {
                "target_module_version_id": module_versions[target_key],
                "target_rva": int(binding["target_rva"]),
                "target_va": int(binding["target_va"]),
            }
        workspace_linked_ranges = [
            (
                int(module["load_base"]),
                int(module["load_base"]) + images[module["runtime_name"].lower()].size_of_image,
                module_versions[module["runtime_name"].lower()],
            )
            for module in executable_modules
        ]

        tool_version_id = store.register_tool_version(
            "d2wasm-cfg",
            "2",
            options={"decoder": "capstone-x86-32"},
        )
        configuration = {
            "max_blocks_per_module": int(args.max_blocks_per_module),
            "relocation_roots": bool(args.relocation_roots),
            "relocation_roots_module": sorted(relocation_root_modules),
        }
        root_inputs = {
            key: [
                {
                    "rva": fact["rva"],
                    "kind": fact["kind"],
                    "details": fact["details"],
                }
                for fact in facts
            ]
            for key, facts in sorted(root_facts.items())
            if facts
        }
        run_id = store.register_analysis_run(
            project_id,
            tool_version_id,
            configuration,
            {"root_facts": root_inputs},
            status="running",
        )
        resumed = bool(
            store.connection.execute(
                "SELECT 1 FROM run_block_selections WHERE run_id=? LIMIT 1", (run_id,)
            ).fetchone()
        )
        store.set_run_status(run_id, "running")
        if args.retry_failed_work:
            store.retry_work(
                run_id=run_id,
                states=("blocked", "unsupported", "ambiguous", "failed"),
            )

        for key, facts in root_facts.items():
            if key not in module_versions:
                continue
            image = images[key]
            for fact in facts:
                accepted = (
                    image.is_executable_rva(int(fact["rva"]))
                    if fact.get("accepted") is None
                    else bool(fact["accepted"])
                )
                resolution = str(
                    fact["details"].get(
                        "resolution",
                        "resolved_executable"
                        if accepted
                        else (
                            "non_executable"
                            if image.is_mapped_rva(int(fact["rva"]))
                            else "unmapped"
                        ),
                    )
                )
                store.register_root_fact(
                    run_id,
                    module_versions[key],
                    int(fact["rva"]),
                    fact["kind"],
                    evidence=fact["kind"],
                    confidence=1.0,
                    accepted=accepted,
                    resolution=resolution,
                    details=fact["details"],
                )
                if accepted:
                    store.enqueue_work(
                        run_id,
                        module_versions[key],
                        int(fact["rva"]),
                        kind="discover_block",
                        priority=int(fact["priority"]),
                        entry_state=EntryState().to_dict(),
                        payload={"root_kind": fact["kind"]},
                    )

        remaining_budget = args.work_item_budget
        incomplete = False
        for module in executable_modules:
            key = module["runtime_name"].lower()
            before_attempts = int(
                store.connection.execute(
                    """SELECT COUNT(*) FROM work_attempts AS attempt
                       JOIN work_items AS item ON item.work_item_id=attempt.work_item_id
                       WHERE item.run_id=?""",
                    (run_id,),
                ).fetchone()[0]
            )
            blocks, work_counts, complete = discover_cfg_workspace(
                images[key],
                store,
                run_id,
                module_versions[key],
                max_blocks=args.max_blocks_per_module,
                work_item_budget=remaining_budget,
                worker_id="link-translate",
                load_base=int(module["load_base"]),
                internal_bindings=workspace_bindings.get(key),
                linked_ranges=workspace_linked_ranges,
            )
            after_attempts = int(
                store.connection.execute(
                    """SELECT COUNT(*) FROM work_attempts AS attempt
                       JOIN work_items AS item ON item.work_item_id=attempt.work_item_id
                       WHERE item.run_id=?""",
                    (run_id,),
                ).fetchone()[0]
            )
            if remaining_budget is not None:
                remaining_budget = max(0, remaining_budget - (after_attempts - before_attempts))
            blocks_by_module[key] = blocks
            if not complete:
                incomplete = True
                if remaining_budget == 0:
                    break
            revision_edges = [
                dict(row)
                for row in store.connection.execute(
                    """SELECT edge.* FROM run_block_selections AS selection
                       JOIN block_keys AS block ON block.block_key_id=selection.block_key_id
                       JOIN revision_edges AS edge ON edge.revision_id=selection.revision_id
                       WHERE selection.run_id=? AND block.module_version_id=?""",
                    (run_id, module_versions[key]),
                )
            ]
            embedded_ranges: list[tuple[int, int, str]] = []
            embedded_ranges.extend(
                (
                    int(edge["table_slot_rva"]),
                    int(edge["table_slot_rva"]) + 4,
                    "jump_table",
                )
                for edge in revision_edges
                if edge.get("table_slot_rva") is not None
            )
            classifications, byte_metrics = classify_executable_bytes(
                images[key], blocks, embedded_ranges=embedded_ranges
            )
            store.save_byte_classifications(
                run_id,
                module_versions[key],
                [item.to_dict() for item in classifications],
                mapped_executable_bytes=byte_metrics["mapped_executable_bytes"],
            )
            metrics = summarize_graph_accounting(
                byte_metrics, blocks, revision_edges, work_counts
            )
            metrics.update(
                {
                    "file_backed_executable_bytes": byte_metrics[
                        "file_backed_executable_bytes"
                    ],
                    "zero_fill_executable_bytes": byte_metrics[
                        "zero_fill_executable_bytes"
                    ],
                }
            )
            store.save_graph_accounting(run_id, module_versions[key], metrics)
            module_reports.append(
                {
                    "runtime_name": module["runtime_name"],
                    "source": module["source"],
                    "load_base": module["load_base"],
                    "roots": sorted({int(fact["rva"]) for fact in root_facts[key]}),
                    "block_count": len(blocks),
                    "instruction_count": sum(
                        len(block.instructions) for block in blocks.values()
                    ),
                    "block_limit_reached": work_counts["blocked"] > 0,
                    "work": work_counts,
                    "graph_accounting": metrics,
                }
            )

        if incomplete:
            store.refresh_compatibility_projection(run_id)
            store.set_run_status(run_id, "paused")
            counts = store.query_counts(run_id)
            print(
                f"Checkpointed analysis {run_id} in {debug_path}: "
                f"{counts['work']['completed']} completed / "
                f"{counts['work']['unfinished']} unfinished work items"
            )
            return 3

        store.refresh_compatibility_projection(run_id)
        function_recovery = recover_all_functions(store, run_id)
        semantic_translation = translate_all_semantics(store, run_id)
        store.set_run_status(run_id, "completed")
        integrity = store.integrity_check()
        if not integrity["ok"]:
            raise ValueError(f"workspace integrity check failed: {integrity}")
        workspace_counts = store.query_counts(run_id)
        workspace_counts["function_recovery"] = function_recovery
        workspace_counts["semantic_translation"] = semantic_translation

    terminal_blockers = sum(
        module["work"][state]
        for module in module_reports
        for state in ("blocked", "unsupported", "ambiguous", "failed")
    )
    if terminal_blockers and not args.debug_db_only and not args.emit_partial:
        print(
            f"Workspace analysis has {terminal_blockers} terminal discovery blockers; "
            "use --emit-partial to generate an inspectable artifact",
            file=sys.stderr,
        )
        return 2

    if args.debug_db_only:
        print(
            f"Indexed {workspace_counts['selected_blocks']} linked blocks into {debug_path} "
            f"(analysis {run_id})"
        )
        return 0

    for module in executable_modules:
        key = module["runtime_name"].lower()
        units.append(
            CGenerator(
                images[key],
                blocks_by_module[key],
                api_specs,
                load_base=int(module["load_base"]),
                global_pc=True,
                internal_targets=bindings_by_importer.get(key),
            )
        )
    generator = LinkedCGenerator(units)
    source = generator.generate()
    source_path = args.output_dir / "linked.c"
    wasm_path = args.output_dir / "linked.wasm"
    report_path = args.output_dir / "linked-translation.json"
    source_path.write_text(source)
    report = {
        "schema_version": SCHEMA_VERSION,
        "link_manifest": str(args.link_manifest.resolve()),
        "entry_va": manifest["entry_va"],
        "analysis_run_id": run_id,
        "resumed": resumed,
        "workspace": workspace_counts,
        "modules": module_reports,
        "block_count": sum(module["block_count"] for module in module_reports),
        "instruction_count": sum(module["instruction_count"] for module in module_reports),
        "unsupported": [
            {
                "module": module["runtime_name"],
                "rva": site.rva,
                "va": int(module["load_base"]) + site.rva,
                "instruction": site.instruction,
                "reason": site.reason,
            }
            for unit, module in zip(units, module_reports)
            for site in unit.unsupported
        ],
        "artifacts": {
            "c": source_path.name,
            "wasm": wasm_path.name,
            "debug_db": str(debug_path),
        },
    }
    write_json(report_path, report)
    if generator.unsupported and not args.emit_partial:
        print(
            f"Linked translation has {len(generator.unsupported)} unsupported sites -> {report_path}",
            file=sys.stderr,
        )
        return 2
    initial_memory = max(
        16 * 1024 * 1024,
        ((int(manifest["summary"]["highest_mapped_address"]) + 65535) // 65536)
        * 65536,
    )
    compile_wasm(source_path, wasm_path, initial_memory, args.opt_level)
    print(
        f"Linked {len(module_reports)} translated modules / {report['block_count']} blocks / "
        f"{report['instruction_count']} instructions -> {wasm_path}"
    )
    return 2 if generator.unsupported else 0


def link_translate(args: argparse.Namespace) -> int:
    if (args.work_item_budget is not None or args.retry_failed_work) and not args.debug_db:
        print(
            "error: --work-item-budget and --retry-failed-work require --debug-db",
            file=sys.stderr,
        )
        return 2
    if args.debug_db:
        return _link_translate_workspace(args)
    manifest = json.loads(args.link_manifest.read_text())
    api_specs = load_api_specs(args.api_spec)
    bindings_by_importer: dict[str, dict[str, int]] = {}
    roots_by_module: dict[str, set[int]] = {}
    known_modules = {module["runtime_name"].lower(): module["runtime_name"] for module in manifest["modules"]}
    configured_roots = json.loads(args.roots_file.read_text()) if args.roots_file else {}
    for module_name, values in configured_roots.items():
        key = module_name.lower()
        if key not in known_modules:
            raise ValueError(f"unknown module in roots file: {module_name}")
        roots_by_module.setdefault(key, set()).update(
            int(value, 0) if isinstance(value, str) else int(value) for value in values
        )
    for root in args.root or []:
        module_name, separator, rva_text = root.rpartition(":")
        key = module_name.lower()
        if not separator or key not in known_modules:
            choices = ", ".join(sorted(known_modules.values()))
            raise ValueError(f"linked root must be MODULE:RVA; known modules: {choices}")
        roots_by_module.setdefault(key, set()).add(int(rva_text, 0))
    for binding in manifest["internal_bindings"]:
        symbol = binding["name"] if binding["name"] else f"#{binding['ordinal']}"
        key = f"{binding['library'].lower()}!{symbol}"
        bindings_by_importer.setdefault(binding["importer"].lower(), {})[key] = int(binding["target_va"])
        roots_by_module.setdefault(binding["target_module"].lower(), set()).add(int(binding["target_rva"]))

    units = []
    debug_units = []
    module_reports = []
    relocation_root_modules = {name.lower() for name in (args.relocation_roots_module or [])}
    unknown_relocation_modules = relocation_root_modules - set(known_modules)
    if unknown_relocation_modules:
        raise ValueError(f"unknown relocation-root modules: {', '.join(sorted(unknown_relocation_modules))}")
    for module in manifest["modules"]:
        image = PEImage(args.source_dir / module["source"])
        if not image.executable_sections():
            continue
        roots = roots_by_module.setdefault(module["runtime_name"].lower(), set())
        roots.add(image.entry_rva)
        roots.update(int(item["rva"]) for item in module.get("exports", []) if int(item["rva"]))
        if args.relocation_roots or module["runtime_name"].lower() in relocation_root_modules:
            roots.update(image.relocation_code_roots())
        blocks = discover_cfg(image, sorted(roots), max_blocks=args.max_blocks_per_module)
        unit = CGenerator(
            image,
            blocks,
            api_specs,
            load_base=int(module["load_base"]),
            global_pc=True,
            internal_targets=bindings_by_importer.get(module["runtime_name"].lower()),
        )
        units.append(unit)
        debug_units.append(
            DebugUnit(
                runtime_name=module["runtime_name"],
                source=module["source"],
                load_base=int(module["load_base"]),
                roots=tuple(sorted(roots)),
                image=image,
                blocks=blocks,
            )
        )
        module_reports.append(
            {
                "runtime_name": module["runtime_name"],
                "source": module["source"],
                "load_base": module["load_base"],
                "roots": sorted(roots),
                "block_count": len(blocks),
                "instruction_count": sum(len(block.instructions) for block in blocks.values()),
                "block_limit_reached": len(blocks) >= args.max_blocks_per_module,
            }
        )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    debug_path = None
    if args.debug_db:
        debug_path = args.debug_db
        if not debug_path.is_absolute() and debug_path.parent == Path("."):
            debug_path = args.output_dir / debug_path
        write_debug_database(debug_path, manifest, debug_units)
    if args.debug_db_only:
        if debug_path is None:
            raise ValueError("--debug-db-only requires --debug-db")
        print(
            f"Indexed {sum(len(unit.blocks) for unit in debug_units)} linked blocks "
            f"into {debug_path}"
        )
        return 0

    generator = LinkedCGenerator(units)
    source = generator.generate()
    source_path = args.output_dir / "linked.c"
    wasm_path = args.output_dir / "linked.wasm"
    report_path = args.output_dir / "linked-translation.json"
    source_path.write_text(source)
    report = {
        "schema_version": SCHEMA_VERSION,
        "link_manifest": str(args.link_manifest.resolve()),
        "entry_va": manifest["entry_va"],
        "modules": module_reports,
        "block_count": sum(module["block_count"] for module in module_reports),
        "instruction_count": sum(module["instruction_count"] for module in module_reports),
        "unsupported": [
            {
                "module": module["runtime_name"],
                "rva": site.rva,
                "va": int(module["load_base"]) + site.rva,
                "instruction": site.instruction,
                "reason": site.reason,
            }
            for unit, module in zip(units, module_reports)
            for site in unit.unsupported
        ],
        "artifacts": {
            "c": source_path.name,
            "wasm": wasm_path.name,
            **({"debug_db": str(debug_path)} if debug_path else {}),
        },
    }
    write_json(report_path, report)
    if generator.unsupported and not args.emit_partial:
        print(f"Linked translation has {len(generator.unsupported)} unsupported sites -> {report_path}", file=sys.stderr)
        return 2
    initial_memory = max(
        16 * 1024 * 1024,
        ((int(manifest["summary"]["highest_mapped_address"]) + 65535) // 65536) * 65536,
    )
    compile_wasm(source_path, wasm_path, initial_memory, args.opt_level)
    print(
        f"Linked {len(module_reports)} translated modules / {report['block_count']} blocks / "
        f"{report['instruction_count']} instructions -> {wasm_path}"
    )
    return 2 if generator.unsupported else 0


def semantic_export(args: argparse.Namespace) -> int:
    with TranslationStore(args.debug_db) as store:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        rows = store.connection.execute(
            """SELECT artifact.*, function.name, function.primary_entry_rva
               FROM semantic_artifacts AS artifact
               LEFT JOIN functions AS function ON function.function_id=artifact.scope_id
               WHERE artifact.run_id=? AND artifact.level IN ('L3','L4')
               ORDER BY function.module_version_id, function.primary_entry_rva, artifact.level""",
            (args.run_id,),
        )
        count = 0
        for row in rows:
            name = row["name"] or f"fn_{int(row['primary_entry_rva'] or 0):08x}"
            safe = "".join(character if character.isalnum() else "_" for character in str(name))
            suffix = "md" if row["level"] == "L3" else "rs"
            content = row["markdown"] if row["level"] == "L3" else json.loads(row["content_json"])["source"]
            (args.output_dir / f"{safe}.{suffix}").write_text(str(content))
            count += 1
    print(f"Exported {count} semantic artifacts -> {args.output_dir}")
    return 0


def oracle_ingest(args: argparse.Namespace) -> int:
    result = json.loads(args.result.read_text())
    request = json.loads(args.request.read_text()) if args.request else {}
    with TranslationStore(args.debug_db) as store:
        implementation_id = args.implementation_id
        if args.entry_va is not None:
            register_replacement(
                store,
                args.run_id,
                int(args.entry_va, 0),
                function_id=args.function_id,
                implementation_id=implementation_id,
                kind=args.replacement_kind,
                value=int(args.replacement_value, 0),
                stack_cleanup=args.stack_cleanup,
            )
        identifiers = persist_equivalence(
            store,
            args.run_id,
            result,
            name=args.name,
            function_id=args.function_id,
            implementation_id=implementation_id,
            input_request=request,
        )
    print(json.dumps(identifiers, sort_keys=True))
    return 0 if result.get("equivalent") else 2


def promote(args: argparse.Namespace) -> int:
    with TranslationStore(args.debug_db) as store:
        promote_function(store, args.function_id, args.state)
    print(f"Promoted {args.function_id} -> {args.state}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="d2wasm", description="AOT PE32/i386 to WebAssembly translator harness")
    subparsers = parser.add_subparsers(dest="command", required=True)

    inventory_parser = subparsers.add_parser("inventory", help="inventory a PE module set")
    inventory_parser.add_argument("source_dir", type=Path)
    inventory_parser.add_argument("--filename-map", type=Path)
    inventory_parser.add_argument("--output", type=Path, required=True)
    inventory_parser.set_defaults(handler=inventory)

    link_parser = subparsers.add_parser("link", help="plan a collision-free linked PE address space")
    link_parser.add_argument("source_dir", type=Path)
    link_parser.add_argument("--filename-map", type=Path, required=True)
    link_parser.add_argument("--entry-module", required=True)
    link_parser.add_argument("--output", type=Path, required=True)
    link_parser.set_defaults(handler=link)

    linked_parser = subparsers.add_parser("link-translate", help="translate a planned multi-PE image into one Wasm module")
    linked_parser.add_argument("source_dir", type=Path)
    linked_parser.add_argument("--link-manifest", type=Path, required=True)
    linked_parser.add_argument("--output-dir", type=Path, required=True)
    linked_parser.add_argument("--max-blocks-per-module", type=int, default=100_000)
    linked_parser.add_argument(
        "--root",
        action="append",
        help="additional MODULE:RVA control-flow root (repeatable; useful for runtime-guided indirect targets)",
    )
    linked_parser.add_argument(
        "--roots-file",
        type=Path,
        help="JSON object mapping module names to lists of runtime-guided RVAs",
    )
    linked_parser.add_argument("--relocation-roots", action="store_true")
    linked_parser.add_argument(
        "--relocation-roots-module",
        action="append",
        help="seed PE-relocation-proven code pointers for one module (repeatable)",
    )
    linked_parser.add_argument("--emit-partial", action="store_true")
    linked_parser.add_argument(
        "--debug-db",
        type=Path,
        nargs="?",
        const=Path("linked-debug.sqlite"),
        help="write a SQLite sidecar containing instructions, CFG edges, and resolved xrefs",
    )
    linked_parser.add_argument(
        "--debug-db-only",
        action="store_true",
        help="discover linked code and write --debug-db without generating C or compiling Wasm",
    )
    linked_parser.add_argument(
        "--work-item-budget",
        type=int,
        help="process at most this many durable discovery items, then checkpoint and exit",
    )
    linked_parser.add_argument(
        "--retry-failed-work",
        action="store_true",
        help="explicitly retry blocked, unsupported, ambiguous, and failed work items",
    )
    linked_parser.add_argument(
        "--api-spec",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "api-spec.json",
    )
    linked_parser.add_argument("--opt-level", choices=("0", "1", "2", "3", "s", "z"), default="0")
    linked_parser.set_defaults(handler=link_translate)

    semantic_parser = subparsers.add_parser(
        "semantic-export", help="export recovered L3 specifications and L4 Rust sources"
    )
    semantic_parser.add_argument("--debug-db", type=Path, required=True)
    semantic_parser.add_argument("--run-id", required=True)
    semantic_parser.add_argument("--output-dir", type=Path, required=True)
    semantic_parser.set_defaults(handler=semantic_export)

    oracle_parser = subparsers.add_parser(
        "oracle-ingest", help="persist a differential-oracle result in the workspace"
    )
    oracle_parser.add_argument("--debug-db", type=Path, required=True)
    oracle_parser.add_argument("--run-id", required=True)
    oracle_parser.add_argument("--result", type=Path, required=True)
    oracle_parser.add_argument("--request", type=Path)
    oracle_parser.add_argument("--name", required=True)
    oracle_parser.add_argument("--function-id")
    oracle_parser.add_argument("--implementation-id")
    oracle_parser.add_argument("--entry-va")
    oracle_parser.add_argument("--replacement-kind", type=int, default=1)
    oracle_parser.add_argument("--replacement-value", default="0")
    oracle_parser.add_argument("--stack-cleanup", type=int, default=0)
    oracle_parser.set_defaults(handler=oracle_ingest)

    promote_parser = subparsers.add_parser(
        "promote-function", help="advance a function through equivalence acceptance states"
    )
    promote_parser.add_argument("--debug-db", type=Path, required=True)
    promote_parser.add_argument("--function-id", required=True)
    promote_parser.add_argument(
        "--state",
        choices=("explained", "implemented", "locally_equivalent", "scenario_equivalent", "accepted"),
        required=True,
    )
    promote_parser.set_defaults(handler=promote)

    translate_parser = subparsers.add_parser("translate", help="lift reachable x86 basic blocks")
    translate_parser.add_argument("executable", type=Path)
    translate_parser.add_argument("--output-dir", type=Path, required=True)
    translate_parser.add_argument("--root", action="append", help="RVA root (repeatable; defaults to PE entry point)")
    translate_parser.add_argument(
        "--relocation-roots",
        action="store_true",
        help="also seed all executable pointers proven by PE base relocations",
    )
    translate_parser.add_argument("--max-blocks", type=int, default=100_000)
    translate_parser.add_argument("--load-base", help="relocate the PE to this virtual base")
    translate_parser.add_argument(
        "--global-pc",
        action="store_true",
        help="use linked virtual addresses, rather than module-relative RVAs, as block PCs",
    )
    translate_parser.add_argument("--report-only", action="store_true")
    translate_parser.add_argument(
        "--emit-partial",
        action="store_true",
        help="compile an inspectable Wasm artifact with explicit traps at unsupported sites",
    )
    translate_parser.add_argument(
        "--opt-level",
        choices=("0", "1", "2", "3", "s", "z"),
        default="0",
        help="Clang optimization level (default: 0 for fast coverage builds)",
    )
    translate_parser.add_argument(
        "--api-spec",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "api-spec.json",
        help="typed direct-host API adapter registry",
    )
    translate_parser.set_defaults(handler=translate)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.handler(args))
