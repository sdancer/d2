from __future__ import annotations

from collections import Counter
from typing import Any

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

from .pe import PEImage


def instruction_surface(image: PEImage) -> dict[str, Any]:
    """Linear-decode executable sections for a deterministic surface metric.

    This deliberately is not reachability.  It tells us which decoder/lifter
    work the complete module may require, while recursive translation reports
    separately describe code proven reachable from selected roots.
    """

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    histogram: Counter[str] = Counter()
    decoded_bytes = 0
    executable_bytes = 0
    invalid_bytes = 0

    for section in image.executable_sections():
        content = bytes(section.content)
        executable_bytes += len(content)
        offset = 0
        va = image.image_base + int(section.virtual_address)
        while offset < len(content):
            instruction = next(decoder.disasm(content[offset:], va + offset, 1), None)
            if instruction is None:
                invalid_bytes += 1
                offset += 1
                continue
            histogram[instruction.mnemonic] += 1
            decoded_bytes += instruction.size
            offset += instruction.size

    return {
        "executable_bytes": executable_bytes,
        "decoded_bytes": decoded_bytes,
        "invalid_bytes": invalid_bytes,
        "instruction_count": sum(histogram.values()),
        "mnemonics": dict(sorted(histogram.items(), key=lambda item: (-item[1], item[0]))),
    }
