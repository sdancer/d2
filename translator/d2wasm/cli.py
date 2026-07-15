from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any

from .analysis import instruction_surface
from .api import load_api_specs
from .cfg import discover_cfg
from .codegen import CGenerator, LinkedCGenerator, compile_wasm
from .linker import plan_linked_image
from .pe import PEImage


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


def link_translate(args: argparse.Namespace) -> int:
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

    generator = LinkedCGenerator(units)
    source = generator.generate()
    args.output_dir.mkdir(parents=True, exist_ok=True)
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
        "artifacts": {"c": source_path.name, "wasm": wasm_path.name},
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
        "--api-spec",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "api-spec.json",
    )
    linked_parser.add_argument("--opt-level", choices=("0", "1", "2", "3", "s", "z"), default="0")
    linked_parser.set_defaults(handler=link_translate)

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
