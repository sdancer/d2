from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import struct
from typing import Any

import lief


@dataclass(frozen=True)
class ImportSymbol:
    library: str
    name: str | None
    ordinal: int | None
    iat_rva: int

    @property
    def display_name(self) -> str:
        symbol = self.name if self.name else f"#{self.ordinal}"
        return f"{self.library.lower()}!{symbol}"


class PEImage:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        parsed = lief.PE.parse(str(path))
        if parsed is None:
            raise ValueError(f"not a PE file: {path}")
        if parsed.header.machine != lief.PE.Header.MACHINE_TYPES.I386:
            raise ValueError(f"only PE32/i386 is supported: {path}")
        self.binary = parsed
        self.image_base = int(parsed.optional_header.imagebase)
        self.entry_rva = int(parsed.optional_header.addressof_entrypoint)
        self.size_of_image = int(parsed.optional_header.sizeof_image)
        self.imports = self._read_imports()
        self.highlow_relocation_rvas = {
            int(entry.address)
            for block in parsed.relocations
            for entry in block.entries
            if int(entry.type) == 3
        }
        self.import_by_iat_va = {
            self.image_base + symbol.iat_rva: symbol for symbol in self.imports
        }

    def _read_imports(self) -> list[ImportSymbol]:
        result: list[ImportSymbol] = []
        for library in self.binary.imports:
            for entry in library.entries:
                result.append(
                    ImportSymbol(
                        library=library.name,
                        name=entry.name or None,
                        ordinal=int(entry.ordinal) if entry.is_ordinal else None,
                        iat_rva=int(entry.iat_address),
                    )
                )
        return result

    def executable_sections(self) -> list[Any]:
        execute = int(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE)
        return [s for s in self.binary.sections if int(s.characteristics) & execute]

    def is_executable_rva(self, rva: int) -> bool:
        section = self.section_for_rva(rva)
        if section is None:
            return False
        execute = int(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE)
        return bool(int(section.characteristics) & execute)

    def bytes_at_rva(self, rva: int, maximum: int) -> bytes:
        for section in self.binary.sections:
            start = int(section.virtual_address)
            content = bytes(section.content)
            end = start + len(content)
            if start <= rva < end:
                offset = rva - start
                return content[offset : offset + maximum]
        raise ValueError(f"RVA 0x{rva:08x} is not backed by file data in {self.path}")

    def section_for_rva(self, rva: int) -> Any | None:
        for section in self.binary.sections:
            start = int(section.virtual_address)
            size = max(int(section.virtual_size), len(section.content))
            if start <= rva < start + size:
                return section
        return None

    def inventory(self, runtime_name: str | None = None) -> dict[str, Any]:
        sections = []
        for section in self.binary.sections:
            sections.append(
                {
                    "name": section.name,
                    "rva": int(section.virtual_address),
                    "virtual_size": int(section.virtual_size),
                    "file_size": len(section.content),
                    "file_offset": int(section.pointerto_raw_data),
                    "characteristics": int(section.characteristics),
                    "executable": section in self.executable_sections(),
                }
            )

        exports = []
        if self.binary.has_exports:
            export = self.binary.get_export()
            if export is not None:
                for entry in export.entries:
                    exports.append(
                        {
                            "name": entry.name or None,
                            "ordinal": int(entry.ordinal),
                            "rva": int(entry.address),
                        }
                    )

        relocations = sum(len(block.entries) for block in self.binary.relocations)
        return {
            "source": self.path.name,
            "runtime_name": runtime_name or self.path.name,
            "sha256": sha256(self.data).hexdigest(),
            "file_size": len(self.data),
            "image_base": self.image_base,
            "image_size": self.size_of_image,
            "headers_size": int(self.binary.optional_header.sizeof_headers),
            "entry_rva": self.entry_rva,
            "sections": sections,
            "imports": [
                {
                    "library": symbol.library,
                    "name": symbol.name,
                    "ordinal": symbol.ordinal,
                    "iat_rva": symbol.iat_rva,
                }
                for symbol in self.imports
            ],
            "exports": exports,
            "relocations": relocations,
        }

    def relocation_code_roots(self) -> list[int]:
        """Return executable addresses stored in PE base-relocation slots.

        Absolute callback/vtable/function-pointer initializers must be relocated
        by a PE loader. That makes the relocation table a high-confidence root
        source for indirect AOT control flow without guessing from raw words.
        """

        roots = []
        for block in self.binary.relocations:
            for entry in block.entries:
                rva = int(entry.address)
                try:
                    target_va = struct.unpack("<I", self.bytes_at_rva(rva, 4))[0]
                except (ValueError, struct.error):
                    continue
                target = target_va - self.image_base
                if self.is_executable_rva(target):
                    roots.append(target)
        return list(dict.fromkeys(roots))

    def relocate_instruction_value(
        self,
        instruction: Any,
        field_offset: int,
        value: int,
        load_base: int,
    ) -> int:
        if not field_offset or load_base == self.image_base:
            return value & 0xFFFFFFFF
        instruction_rva = int(instruction.address) - self.image_base
        if instruction_rva + field_offset in self.highlow_relocation_rvas:
            return (value + load_base - self.image_base) & 0xFFFFFFFF
        return value & 0xFFFFFFFF
