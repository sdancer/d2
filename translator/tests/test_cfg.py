from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from d2wasm.analysis import classify_executable_bytes
from d2wasm.cfg import EntryState, decode_block
from d2wasm.pe import ImportSymbol


@dataclass
class FakeSection:
    virtual_address: int
    virtual_size: int
    content: bytes


class FakeImage:
    def __init__(self, content: bytes, executable_end: int | None = None):
        self.image_base = 0x1000
        self.content = content
        self.size_of_image = len(content)
        self.executable_end = len(content) if executable_end is None else executable_end
        self.import_by_iat_va = {}
        self.section = FakeSection(0, len(content), content)

    def bytes_at_rva(self, rva: int, maximum: int) -> bytes:
        if not 0 <= rva < len(self.content):
            raise ValueError(f"RVA 0x{rva:08x} is not backed")
        return self.content[rva : rva + maximum]

    def executable_regions(self):
        return [
            {
                "name": ".text",
                "start_rva": 0,
                "file_end_rva": len(self.content),
                "mapped_end_rva": self.size_of_image,
            }
        ]

    def is_executable_rva(self, rva: int) -> bool:
        return 0 <= rva < self.executable_end

    def is_mapped_rva(self, rva: int) -> bool:
        return 0 <= rva < self.size_of_image

    def section_for_rva(self, rva: int) -> FakeSection | None:
        return self.section if self.is_mapped_rva(rva) else None


class CfgTests(unittest.TestCase):
    def test_entry_state_only_retains_agreed_facts(self) -> None:
        imported = ImportSymbol("test.dll", "Callback", None, 0x200)
        left = EntryState({"eax": 1, "ebx": 2}, {"ecx": imported})
        right = EntryState({"eax": 1, "ebx": 3}, {"ecx": imported})
        merged = left.merged(right)
        self.assertEqual(merged.constants, {"eax": 1})
        self.assertEqual(merged.imports, {"ecx": imported})
        after_call = left.after_call()
        self.assertNotIn("eax", after_call.constants)
        self.assertNotIn("ecx", after_call.imports)
        self.assertEqual(after_call.constants["ebx"], 2)

    def test_direct_call_records_callee_and_fallthrough(self) -> None:
        # call RVA 6; ret; ret
        image = FakeImage(b"\xe8\x01\x00\x00\x00\xc3\xc3")
        result = decode_block(image, 0)
        self.assertEqual(result.block.terminator, "call")
        self.assertEqual(result.block.successors, [6, 5])
        self.assertEqual([edge.kind for edge in result.edges], ["call", "call_fallthrough"])
        self.assertTrue(all(edge.resolution == "resolved_executable" for edge in result.edges))
        self.assertEqual(result.successor_states[0][1], EntryState())

    def test_unmapped_direct_jump_is_explicit_not_a_successor(self) -> None:
        # jmp 0x2000 from 0x1000: displacement 0xffb after the five-byte opcode.
        image = FakeImage(b"\xe9\xfb\x0f\x00\x00")
        result = decode_block(image, 0)
        self.assertEqual(result.block.terminator, "indirect_jump")
        self.assertEqual(result.block.successors, [])
        self.assertEqual(result.edges[0].kind, "jump")
        self.assertEqual(result.edges[0].resolution, "unmapped")
        self.assertEqual(result.edges[0].target_va, 0x2000)

    def test_rejected_conditional_becomes_explicitly_invalid(self) -> None:
        image = FakeImage(b"\x75\x7f\xc3")
        result = decode_block(image, 0)
        self.assertEqual(result.block.terminator, "invalid")
        self.assertEqual(result.block.successors, [])
        self.assertIn("unmapped", result.block.unsupported_reason)
        self.assertEqual([edge.kind for edge in result.edges], ["branch", "branch_fallthrough"])

    def test_nop_alignment_run_is_padding_not_probable_code(self) -> None:
        image = FakeImage(b"\x90\x90\x90\x90\xc3")
        classifications, metrics = classify_executable_bytes(image, {})
        self.assertEqual(metrics["padding_bytes"], 4)
        self.assertEqual(metrics["probable_code_bytes"], 1)
        self.assertEqual(classifications[0].classification, "padding")

    def test_known_leader_stops_linear_decode(self) -> None:
        image = FakeImage(b"\x90\x90\xc3")
        result = decode_block(image, 0, leaders={1})
        self.assertEqual(len(result.block.instructions), 1)
        self.assertEqual(result.block.successors, [1])
        self.assertEqual(result.edges[0].evidence_kind, "known_leader")


if __name__ == "__main__":
    unittest.main()
