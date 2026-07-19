from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

from .cfg import Block
from .pe import PEImage


@dataclass(frozen=True)
class ByteClassification:
    start_rva: int
    end_rva: int
    classification: str
    evidence: str
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "start_rva": self.start_rva,
            "end_rva": self.end_rva,
            "classification": self.classification,
            "evidence": self.evidence,
            "details": self.details,
        }


def instruction_surface(image: PEImage) -> dict[str, Any]:
    """Linear-decode executable sections for a deterministic surface metric.

    This deliberately is not reachability. It tells us which decoder/lifter
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


def _coalesce_region(
    start_rva: int,
    labels: list[str],
    evidence: list[str],
) -> list[ByteClassification]:
    if not labels:
        return []
    result = []
    start = 0
    for index in range(1, len(labels) + 1):
        if index < len(labels) and (
            labels[index] == labels[start] and evidence[index] == evidence[start]
        ):
            continue
        result.append(
            ByteClassification(
                start_rva=start_rva + start,
                end_rva=start_rva + index,
                classification=labels[start],
                evidence=evidence[start],
                details={},
            )
        )
        start = index
    return result


def classify_executable_bytes(
    image: PEImage,
    blocks: Mapping[int, Block],
    *,
    embedded_ranges: Iterable[tuple[int, int, str]] = (),
) -> tuple[list[ByteClassification], dict[str, int]]:
    """Classify every mapped executable byte without promoting sweep candidates."""

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    confirmed_spans = [
        (
            int(instruction.address) - image.image_base,
            int(instruction.address) - image.image_base + int(instruction.size),
        )
        for block in blocks.values()
        for instruction in block.instructions
    ]
    embedded = list(embedded_ranges)
    classifications: list[ByteClassification] = []
    conflicts = 0
    file_bytes = 0
    mapped_bytes = 0

    for region in image.executable_regions():
        region_start = int(region["start_rva"])
        file_end = int(region["file_end_rva"])
        mapped_end = int(region["mapped_end_rva"])
        size = mapped_end - region_start
        mapped_bytes += size
        file_bytes += file_end - region_start
        labels = ["unresolved"] * size
        evidence = ["unclassified"] * size
        confirmed_counts = [0] * size

        for span_start, span_end in confirmed_spans:
            start = max(span_start, region_start)
            end = min(span_end, mapped_end)
            for rva in range(start, end):
                offset = rva - region_start
                confirmed_counts[offset] += 1
                labels[offset] = "confirmed_code"
                evidence[offset] = "selected_block"
        conflicts += sum(1 for count in confirmed_counts if count > 1)

        for data_start, data_end, data_evidence in embedded:
            start = max(int(data_start), region_start)
            end = min(int(data_end), mapped_end)
            for rva in range(start, end):
                offset = rva - region_start
                if labels[offset] == "confirmed_code":
                    conflicts += 1
                    continue
                labels[offset] = "embedded_data"
                evidence[offset] = data_evidence

        try:
            file_content = image.bytes_at_rva(region_start, file_end - region_start)
        except ValueError:
            file_content = b""
        cursor = 0
        file_length = min(len(file_content), file_end - region_start)
        while cursor < file_length:
            if labels[cursor] != "unresolved":
                cursor += 1
                continue
            run_end = cursor
            while run_end < file_length and labels[run_end] == "unresolved":
                run_end += 1
            position = cursor
            while position < run_end:
                byte = file_content[position]
                padding_end = position + 1
                if byte in (0x00, 0x90, 0xCC):
                    while padding_end < run_end and file_content[padding_end] == byte:
                        padding_end += 1
                if padding_end - position >= 4:
                    for index in range(position, padding_end):
                        labels[index] = "padding"
                        evidence[index] = "repeated_alignment_byte"
                    position = padding_end
                    continue
                data = file_content[position : min(position + 15, run_end)]
                instruction = next(
                    decoder.disasm(data, image.image_base + region_start + position, 1),
                    None,
                )
                if instruction is None or position + instruction.size > run_end:
                    evidence[position] = "undecodable_gap"
                    position += 1
                    continue
                for index in range(position, position + int(instruction.size)):
                    labels[index] = "probable_code"
                    evidence[index] = "linear_gap_sweep"
                position += int(instruction.size)
            cursor = run_end

        for offset in range(file_length, size):
            if labels[offset] == "unresolved":
                evidence[offset] = "loader_zero_fill"
        classifications.extend(_coalesce_region(region_start, labels, evidence))

    classifications.sort(key=lambda item: (item.start_rva, item.end_rva))
    totals = Counter()
    previous_end = None
    for item in classifications:
        if previous_end is not None and item.start_rva < previous_end:
            raise ValueError("executable section classifications overlap")
        previous_end = item.end_rva
        totals[item.classification] += item.end_rva - item.start_rva
    classified_bytes = sum(totals.values())
    if classified_bytes != mapped_bytes:
        raise ValueError(
            f"classified {classified_bytes} executable bytes, expected {mapped_bytes}"
        )
    return classifications, {
        "mapped_executable_bytes": mapped_bytes,
        "file_backed_executable_bytes": file_bytes,
        "zero_fill_executable_bytes": mapped_bytes - file_bytes,
        "confirmed_code_bytes": totals["confirmed_code"],
        "probable_code_bytes": totals["probable_code"],
        "embedded_data_bytes": totals["embedded_data"],
        "padding_bytes": totals["padding"],
        "unresolved_bytes": totals["unresolved"],
        "overlaps_conflicts": conflicts,
    }


def summarize_graph_accounting(
    classifications: Mapping[str, int],
    blocks: Mapping[int, Block],
    edges: Iterable[Mapping[str, Any]],
    work_counts: Mapping[str, int],
) -> dict[str, int]:
    edge_rows = list(edges)
    resolved = {"resolved_executable", "internal_import", "external_import"}
    rejected = {"non_executable", "unmapped", "rejected"}
    metrics = {
        "mapped_executable_bytes": int(classifications["mapped_executable_bytes"]),
        "classified_executable_bytes": int(classifications["mapped_executable_bytes"]),
        "confirmed_code_bytes": int(classifications["confirmed_code_bytes"]),
        "probable_code_bytes": int(classifications["probable_code_bytes"]),
        "embedded_data_bytes": int(classifications["embedded_data_bytes"]),
        "padding_bytes": int(classifications["padding_bytes"]),
        "unresolved_bytes": int(classifications["unresolved_bytes"]),
        "resolved_direct_edges": sum(
            1 for edge in edge_rows if edge.get("resolution") in resolved
        ),
        "rejected_direct_edges": sum(
            1 for edge in edge_rows if edge.get("resolution") in rejected
        ),
        "unresolved_indirect_calls": sum(
            1
            for edge in edge_rows
            if edge.get("resolution") == "unresolved_indirect"
            and edge.get("kind") in {"call", "indirect_call"}
        ),
        "unresolved_indirect_jumps": sum(
            1
            for edge in edge_rows
            if edge.get("resolution") == "unresolved_indirect"
            and edge.get("kind") in {"jump", "return", "indirect_jump"}
        ),
        "blocked_targets": int(work_counts.get("blocked", 0)),
        "overlaps_conflicts": int(classifications.get("overlaps_conflicts", 0)),
        "selected_blocks": len(blocks),
        "selected_instructions": sum(
            len(block.instructions) for block in blocks.values()
        ),
        "pending_work": int(work_counts.get("unfinished", 0)),
    }
    category_sum = sum(
        metrics[key]
        for key in (
            "confirmed_code_bytes",
            "probable_code_bytes",
            "embedded_data_bytes",
            "padding_bytes",
            "unresolved_bytes",
        )
    )
    if category_sum != metrics["mapped_executable_bytes"]:
        raise ValueError("executable byte accounting is not exhaustive")
    return metrics
