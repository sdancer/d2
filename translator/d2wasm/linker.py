from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .pe import PEImage


ALIGNMENT = 0x10000
RELOC_REGION_START = 0x01000000
WASM32_LIMIT = 0x80000000


def align_up(value: int, alignment: int = ALIGNMENT) -> int:
    return (value + alignment - 1) & -alignment


@dataclass
class PlannedModule:
    runtime_name: str
    image: PEImage
    load_base: int = 0

    @property
    def end(self) -> int:
        return self.load_base + align_up(self.image.size_of_image)


def _overlaps(base: int, size: int, occupied: list[tuple[int, int]]) -> bool:
    end = base + align_up(size)
    return any(max(base, start) < min(end, stop) for start, stop in occupied)


def _next_free(start: int, size: int, occupied: list[tuple[int, int]]) -> int:
    candidate = align_up(start)
    while _overlaps(candidate, size, occupied):
        candidate = align_up(
            max(stop for begin, stop in occupied if max(candidate, begin) < min(candidate + align_up(size), stop))
        )
    if candidate + align_up(size) > WASM32_LIMIT:
        raise ValueError("linked PE address space exceeds the configured 2 GiB Wasm memory limit")
    return candidate


def _exports(image: PEImage) -> tuple[dict[str, int], dict[int, int], list[dict[str, Any]]]:
    names: dict[str, int] = {}
    ordinals: dict[int, int] = {}
    records = []
    if not image.binary.has_exports:
        return names, ordinals, records
    export = image.binary.get_export()
    if export is None:
        return names, ordinals, records
    for entry in export.entries:
        rva = int(entry.address)
        ordinal = int(entry.ordinal)
        name = entry.name or None
        if name:
            names[name] = rva
        ordinals[ordinal] = rva
        records.append({"name": name, "ordinal": ordinal, "rva": rva})
    return names, ordinals, records


def plan_linked_image(
    source_dir: Path,
    filename_map: dict[str, str],
    entry_module: str,
) -> dict[str, Any]:
    selected = []
    entry_lower = entry_module.lower()
    for source_name, runtime_name in filename_map.items():
        if runtime_name.lower().endswith(".exe") and runtime_name.lower() != entry_lower:
            continue
        selected.append(PlannedModule(runtime_name, PEImage(source_dir / source_name)))
    if not any(module.runtime_name.lower() == entry_lower for module in selected):
        raise ValueError(f"entry module is not present in filename map: {entry_module}")

    occupied: list[tuple[int, int]] = []
    entry = next(module for module in selected if module.runtime_name.lower() == entry_lower)
    # The process image keeps its linked base. Executable images without a
    # relocation directory would also be fixed. Resource-only PEs contain only
    # RVAs and can be compactly mapped without base fixups.
    fixed = [
        module
        for module in selected
        if module is entry
        or (not module.image.binary.has_relocations and module.image.executable_sections())
    ]
    for module in sorted(fixed, key=lambda value: (value.image.image_base, value.runtime_name.lower())):
        base = module.image.image_base
        if _overlaps(base, module.image.size_of_image, occupied):
            raise ValueError(f"non-relocatable module collision at 0x{base:08x}: {module.runtime_name}")
        module.load_base = base
        occupied.append((base, module.end))

    cursor = RELOC_REGION_START
    movable = [module for module in selected if module not in fixed]
    # Pack every DLL/resource PE into a low arena. This avoids reserving almost
    # 2 GiB merely because native Windows DLLs prefer addresses near 0x70000000.
    for module in sorted(movable, key=lambda value: value.runtime_name.lower()):
        module.load_base = _next_free(cursor, module.image.size_of_image, occupied)
        cursor = module.end
        occupied.append((module.load_base, module.end))

    module_by_name = {module.runtime_name.lower(): module for module in selected}
    export_maps = {
        module.runtime_name.lower(): _exports(module.image) for module in selected
    }
    bindings = []
    unresolved_internal = []
    external_imports = []
    for importer in selected:
        for symbol in importer.image.imports:
            target_module = module_by_name.get(symbol.library.lower())
            symbol_record = {
                "importer": importer.runtime_name,
                "library": symbol.library,
                "name": symbol.name,
                "ordinal": symbol.ordinal,
                "iat_rva": symbol.iat_rva,
            }
            if target_module is None:
                external_imports.append(symbol_record)
                continue
            by_name, by_ordinal, _ = export_maps[target_module.runtime_name.lower()]
            target_rva = by_name.get(symbol.name) if symbol.name else by_ordinal.get(symbol.ordinal or -1)
            if target_rva is None:
                unresolved_internal.append(symbol_record)
                continue
            bindings.append(
                {
                    **symbol_record,
                    "target_module": target_module.runtime_name,
                    "target_rva": target_rva,
                    "target_va": target_module.load_base + target_rva,
                }
            )

    modules = []
    for module in sorted(selected, key=lambda value: value.load_base):
        _, _, exports = export_maps[module.runtime_name.lower()]
        relocations = [
            {"rva": int(entry.address), "type": int(entry.type)}
            for block in module.image.binary.relocations
            for entry in block.entries
            if int(entry.type) != 0
        ]
        delta = module.load_base - module.image.image_base
        if delta and module.image.executable_sections() and not any(relocation["type"] == 3 for relocation in relocations):
            raise ValueError(f"module requires relocation but has no HIGHLOW entries: {module.runtime_name}")
        record = module.image.inventory(module.runtime_name)
        record.update(
            {
                "load_base": module.load_base,
                "relocation_delta": delta,
                "relocation_entries": relocations,
                "exports": exports,
            }
        )
        modules.append(record)

    return {
        "schema_version": 1,
        "entry_module": entry.runtime_name,
        "entry_va": entry.load_base + entry.image.entry_rva,
        "address_limit": WASM32_LIMIT,
        "modules": modules,
        "internal_bindings": bindings,
        "unresolved_internal_imports": unresolved_internal,
        "external_imports": external_imports,
        "summary": {
            "module_count": len(modules),
            "relocated_module_count": sum(module["relocation_delta"] != 0 for module in modules),
            "internal_binding_count": len(bindings),
            "unresolved_internal_count": len(unresolved_internal),
            "external_import_count": len(external_imports),
            "highest_mapped_address": max(module.load_base + module.image.size_of_image for module in selected),
        },
    }
