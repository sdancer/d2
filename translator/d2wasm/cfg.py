from __future__ import annotations

from bisect import bisect_right, insort
from dataclasses import dataclass, field
import json
import struct
from typing import Any, Iterable, Mapping

from capstone import CS_ARCH_X86, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from .pe import ImportSymbol, PEImage
from .workspace import stable_hash


@dataclass
class Block:
    rva: int
    instructions: list[Any]
    successors: list[int]
    terminator: str
    imported_call: ImportSymbol | None = None
    unsupported_reason: str | None = None


@dataclass(frozen=True)
class EntryState:
    constants: Mapping[str, int] = field(default_factory=dict)
    imports: Mapping[str, ImportSymbol] = field(default_factory=dict)

    def after_call(self) -> EntryState:
        constants = dict(self.constants)
        imports = dict(self.imports)
        for volatile in ("eax", "ecx", "edx"):
            constants.pop(volatile, None)
            imports.pop(volatile, None)
        return EntryState(constants, imports)

    def merged(self, other: EntryState) -> EntryState:
        return EntryState(
            {
                register: value
                for register, value in self.constants.items()
                if other.constants.get(register) == value
            },
            {
                register: symbol
                for register, symbol in self.imports.items()
                if other.imports.get(register) == symbol
            },
        )

    def to_dict(self, image_base: int | None = None) -> dict[str, Any]:
        result: dict[str, Any] = {
            "constants": {
                register: int(value) & 0xFFFF_FFFF
                for register, value in sorted(self.constants.items())
            },
            "imports": {
                register: {
                    "library": symbol.library,
                    "name": symbol.name,
                    "ordinal": symbol.ordinal,
                    "iat_rva": symbol.iat_rva,
                }
                for register, symbol in sorted(self.imports.items())
            },
        }
        if image_base is not None:
            result["image_base"] = int(image_base)
        return result

    @classmethod
    def from_dict(cls, value: Mapping[str, Any] | None) -> EntryState:
        value = value or {}
        return cls(
            {
                str(register): int(constant) & 0xFFFF_FFFF
                for register, constant in dict(value.get("constants", {})).items()
            },
            {
                str(register): ImportSymbol(
                    library=str(symbol["library"]),
                    name=symbol.get("name"),
                    ordinal=(
                        int(symbol["ordinal"])
                        if symbol.get("ordinal") is not None
                        else None
                    ),
                    iat_rva=int(symbol["iat_rva"]),
                )
                for register, symbol in dict(value.get("imports", {})).items()
            },
        )

    def digest(self) -> str:
        return stable_hash("d2wasm-entry-state-v2", self.to_dict())


@dataclass(frozen=True)
class ControlFlowFact:
    source_instruction_rva: int
    kind: str
    resolution: str
    evidence_kind: str
    target_rva: int | None = None
    target_va: int | None = None
    same_module: bool = True
    operand_index: int = -1
    table_slot_rva: int | None = None
    table_index: int | None = None
    expression: str | None = None
    target_state: EntryState | None = None

    def to_store(self, module_version_id: str) -> dict[str, Any]:
        details: dict[str, Any] = {}
        if self.expression is not None:
            details["expression"] = self.expression
        if self.target_state is not None:
            details["entry_state"] = self.target_state.to_dict()
        return {
            "source_instruction_rva": self.source_instruction_rva,
            "target_module_version_id": (
                module_version_id if self.same_module and self.target_rva is not None else None
            ),
            "target_rva": self.target_rva,
            "target_va": self.target_va if not self.same_module else None,
            "kind": self.kind,
            "evidence_kind": self.evidence_kind,
            "resolution": self.resolution,
            "operand_index": self.operand_index,
            "table_slot_rva": self.table_slot_rva,
            "table_index": self.table_index,
            "details": details,
        }


@dataclass
class DecodeResult:
    block: Block
    edges: list[ControlFlowFact]
    successor_states: list[tuple[int, EntryState]]


def _direct_target(instruction: Any, image: PEImage) -> int | None:
    if not instruction.operands or instruction.operands[0].type != X86_OP_IMM:
        return None
    return ((int(instruction.operands[0].imm) & 0xFFFF_FFFF) - image.image_base)


def _iat_call(instruction: Any, image: PEImage) -> ImportSymbol | None:
    if not instruction.operands or instruction.operands[0].type != X86_OP_MEM:
        return None
    memory = instruction.operands[0].mem
    if memory.base or memory.index:
        return None
    return image.import_by_iat_va.get(int(memory.disp) & 0xFFFF_FFFF)


REG_BASE = {
    "eax": "eax", "ax": "eax", "al": "eax", "ah": "eax",
    "ebx": "ebx", "bx": "ebx", "bl": "ebx", "bh": "ebx",
    "ecx": "ecx", "cx": "ecx", "cl": "ecx", "ch": "ecx",
    "edx": "edx", "dx": "edx", "dl": "edx", "dh": "edx",
    "esi": "esi", "si": "esi", "edi": "edi", "di": "edi",
    "ebp": "ebp", "bp": "ebp", "esp": "esp", "sp": "esp",
}


def _base_reg(instruction: Any, register: int) -> str | None:
    return REG_BASE.get(instruction.reg_name(register))


def _resolved_operand_fact(
    instruction: Any,
    image: PEImage,
    constants: Mapping[str, int],
    imported: Mapping[str, ImportSymbol],
) -> tuple[int | None, ImportSymbol | None, str, str]:
    if not instruction.operands:
        return None, None, "missing_operand", instruction.op_str
    operand = instruction.operands[0]
    if operand.type == X86_OP_IMM:
        return int(operand.imm) & 0xFFFF_FFFF, None, "direct_immediate", instruction.op_str
    if operand.type == X86_OP_REG:
        register = _base_reg(instruction, operand.reg)
        return (
            constants.get(register),
            imported.get(register),
            "constant_propagation" if register in constants else "register_indirect",
            instruction.op_str,
        )
    if operand.type == X86_OP_MEM:
        memory = operand.mem
        address = int(memory.disp) & 0xFFFF_FFFF
        if memory.base:
            base = _base_reg(instruction, memory.base)
            if base not in constants:
                return None, None, "memory_indirect", instruction.op_str
            address = (address + constants[base]) & 0xFFFF_FFFF
        if memory.index:
            index = _base_reg(instruction, memory.index)
            if index not in constants:
                return None, None, "memory_indirect", instruction.op_str
            address = (address + constants[index] * int(memory.scale)) & 0xFFFF_FFFF
        symbol = image.import_by_iat_va.get(address)
        return None, symbol, "iat" if symbol is not None else "memory_indirect", instruction.op_str
    return None, None, "unsupported_operand", instruction.op_str


def _resolved_operand(
    instruction: Any,
    image: PEImage,
    constants: dict[str, int],
    imported: dict[str, ImportSymbol],
) -> tuple[int | None, ImportSymbol | None]:
    target, symbol, _, _ = _resolved_operand_fact(
        instruction, image, constants, imported
    )
    return target, symbol


def _update_constants(
    instruction: Any,
    image: PEImage,
    constants: dict[str, int],
    imported: dict[str, ImportSymbol],
) -> None:
    try:
        _, writes = instruction.regs_access()
    except Exception:
        writes = []
    for register_id in writes:
        register = _base_reg(instruction, register_id)
        if register:
            constants.pop(register, None)
            imported.pop(register, None)

    operands = instruction.operands
    if (
        instruction.mnemonic == "mov"
        and len(operands) == 2
        and operands[0].type == X86_OP_REG
        and operands[0].size == 4
    ):
        destination = _base_reg(instruction, operands[0].reg)
        source = operands[1]
        if destination and source.type == X86_OP_IMM:
            constants[destination] = int(source.imm) & 0xFFFF_FFFF
        elif destination and source.type == X86_OP_REG:
            source_register = _base_reg(instruction, source.reg)
            if source_register in constants:
                constants[destination] = constants[source_register]
            if source_register in imported:
                imported[destination] = imported[source_register]
        elif destination and source.type == X86_OP_MEM:
            memory = source.mem
            if not memory.base and not memory.index:
                symbol = image.import_by_iat_va.get(int(memory.disp) & 0xFFFF_FFFF)
                if symbol:
                    imported[destination] = symbol
    elif (
        instruction.mnemonic == "lea"
        and len(operands) == 2
        and operands[0].type == X86_OP_REG
        and operands[1].type == X86_OP_MEM
    ):
        destination = _base_reg(instruction, operands[0].reg)
        memory = operands[1].mem
        if destination and not memory.base and not memory.index:
            constants[destination] = int(memory.disp) & 0xFFFF_FFFF


def _jump_table_facts(instruction: Any, image: PEImage) -> list[tuple[int, int, int]]:
    if not instruction.operands or instruction.operands[0].type != X86_OP_MEM:
        return []
    memory = instruction.operands[0].mem
    if memory.base or not memory.index or int(memory.scale) != 4:
        return []
    table_rva = (int(memory.disp) & 0xFFFF_FFFF) - image.image_base
    candidates: list[tuple[int, int, int]] = []
    # Optimized MSVC string/memory routines use both ordinary tables and
    # deliberately biased tables whose only legal indices are -8..-1 or 1..3.
    for index in range(-64, 256):
        slot_rva = table_rva + index * 4
        try:
            target_va = struct.unpack("<I", image.bytes_at_rva(slot_rva, 4))[0]
        except (ValueError, struct.error):
            continue
        target = target_va - image.image_base
        if image.is_executable_rva(target):
            candidates.append((index, slot_rva, target))
    runs: list[list[tuple[int, int, int]]] = []
    for candidate in candidates:
        if not runs or candidate[0] != runs[-1][-1][0] + 1:
            runs.append([candidate])
        else:
            runs[-1].append(candidate)
    runs = [run for run in runs if len(run) >= 2]
    if not runs:
        return []
    closest = min(runs, key=lambda run: min(abs(index) for index, _, _ in run))
    result = []
    seen = set()
    for index, slot_rva, target in closest:
        if target not in seen:
            result.append((index, slot_rva, target))
            seen.add(target)
    return result


def _jump_table_targets(instruction: Any, image: PEImage) -> list[int]:
    return [target for _, _, target in _jump_table_facts(instruction, image)]


def _target_resolution(image: PEImage, target_rva: int) -> str:
    if image.is_executable_rva(target_rva):
        return "resolved_executable"
    if image.is_mapped_rva(target_rva):
        return "non_executable"
    return "unmapped"


def decode_block(
    image: PEImage,
    start: int,
    entry_state: EntryState | Mapping[str, Any] | None = None,
    *,
    leaders: Iterable[int] = (),
) -> DecodeResult:
    """Decode one block and retain every control-flow outcome as a fact."""

    state = (
        entry_state
        if isinstance(entry_state, EntryState)
        else EntryState.from_dict(entry_state)
    )
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    known_leaders = set(leaders)
    instructions: list[Any] = []
    successors: list[int] = []
    successor_states: list[tuple[int, EntryState]] = []
    edges: list[ControlFlowFact] = []
    terminator = "fallthrough"
    imported_call = None
    unsupported = None
    cursor = int(start)
    constants = dict(state.constants)
    imported_registers = dict(state.imports)

    def append_successor(
        target: int,
        kind: str,
        source_rva: int,
        next_state: EntryState,
        *,
        evidence_kind: str,
        table_slot_rva: int | None = None,
        table_index: int | None = None,
    ) -> None:
        successors.append(target)
        successor_states.append((target, next_state))
        edges.append(
            ControlFlowFact(
                source_instruction_rva=source_rva,
                kind=kind,
                resolution="resolved_executable",
                evidence_kind=evidence_kind,
                target_rva=target,
                target_state=next_state,
                table_slot_rva=table_slot_rva,
                table_index=table_index,
            )
        )

    for _ in range(4096):
        if cursor != start and cursor in known_leaders:
            next_state = EntryState(dict(constants), dict(imported_registers))
            terminator = "fallthrough"
            append_successor(
                cursor,
                "fallthrough",
                int(instructions[-1].address) - image.image_base if instructions else start,
                next_state,
                evidence_kind="known_leader",
            )
            break
        try:
            data = image.bytes_at_rva(cursor, 15)
        except ValueError as error:
            unsupported = str(error)
            terminator = "invalid"
            break
        instruction = next(decoder.disasm(data, image.image_base + cursor, 1), None)
        if instruction is None:
            unsupported = f"invalid instruction at RVA 0x{cursor:08x}"
            terminator = "invalid"
            break
        instructions.append(instruction)
        source_rva = int(instruction.address) - image.image_base
        fallthrough = cursor + instruction.size
        current_state = EntryState(dict(constants), dict(imported_registers))

        if instruction.group(CS_GRP_RET):
            terminator = "ret"
            edges.append(
                ControlFlowFact(
                    source_instruction_rva=source_rva,
                    kind="return",
                    resolution="unresolved_indirect",
                    evidence_kind="ret",
                    expression=instruction.op_str,
                    same_module=False,
                )
            )
            break
        if instruction.group(CS_GRP_CALL):
            target_va, imported_call, evidence_kind, expression = _resolved_operand_fact(
                instruction, image, constants, imported_registers
            )
            target = target_va - image.image_base if target_va is not None else None
            if target is not None and image.is_executable_rva(target):
                terminator = "call"
                append_successor(
                    target,
                    "call",
                    source_rva,
                    EntryState(),
                    evidence_kind=evidence_kind,
                )
                append_successor(
                    fallthrough,
                    "call_fallthrough",
                    source_rva,
                    current_state.after_call(),
                    evidence_kind="fallthrough",
                )
            elif imported_call is not None:
                terminator = "import_call"
                edges.append(
                    ControlFlowFact(
                        source_instruction_rva=source_rva,
                        kind="import_call",
                        resolution="external_import",
                        evidence_kind=evidence_kind,
                        expression=imported_call.display_name,
                        same_module=False,
                    )
                )
                append_successor(
                    fallthrough,
                    "call_fallthrough",
                    source_rva,
                    current_state.after_call(),
                    evidence_kind="fallthrough",
                )
            else:
                terminator = "indirect_call"
                append_successor(
                    fallthrough,
                    "call_fallthrough",
                    source_rva,
                    current_state.after_call(),
                    evidence_kind="fallthrough",
                )
                resolution = (
                    _target_resolution(image, target) if target is not None else "unresolved_indirect"
                )
                edges.insert(
                    0,
                    ControlFlowFact(
                        source_instruction_rva=source_rva,
                        kind="call",
                        resolution=resolution,
                        evidence_kind=evidence_kind,
                        target_rva=target if target is not None and image.is_mapped_rva(target) else None,
                        target_va=target_va if target is not None and not image.is_mapped_rva(target) else None,
                        same_module=bool(target is not None and image.is_mapped_rva(target)),
                        expression=expression,
                    ),
                )
                unsupported = (
                    f"direct call target is {resolution.replace('_', ' ')}"
                    if target is not None
                    else "unresolved indirect call"
                )
            break
        if instruction.group(CS_GRP_JUMP):
            target_va, imported_jump, evidence_kind, expression = _resolved_operand_fact(
                instruction, image, constants, imported_registers
            )
            target = target_va - image.image_base if target_va is not None else None
            if imported_jump is not None:
                terminator = "import_jump"
                imported_call = imported_jump
                edges.append(
                    ControlFlowFact(
                        source_instruction_rva=source_rva,
                        kind="import_jump",
                        resolution="external_import",
                        evidence_kind=evidence_kind,
                        expression=imported_jump.display_name,
                        same_module=False,
                    )
                )
            elif target is None:
                table_targets = _jump_table_facts(instruction, image)
                if table_targets:
                    terminator = "jump_table"
                    queued_targets = set()
                    for index, slot_rva, table_target in table_targets:
                        fact = ControlFlowFact(
                            source_instruction_rva=source_rva,
                            kind="jump_table",
                            resolution="resolved_executable",
                            evidence_kind="jump_table",
                            target_rva=table_target,
                            target_state=current_state,
                            table_slot_rva=slot_rva,
                            table_index=index,
                        )
                        edges.append(fact)
                        if table_target not in queued_targets:
                            successors.append(table_target)
                            successor_states.append((table_target, current_state))
                            queued_targets.add(table_target)
                else:
                    terminator = "indirect_jump"
                    unsupported = "unresolved indirect jump"
                    edges.append(
                        ControlFlowFact(
                            source_instruction_rva=source_rva,
                            kind="jump",
                            resolution="unresolved_indirect",
                            evidence_kind=evidence_kind,
                            expression=expression,
                            same_module=False,
                        )
                    )
            elif instruction.mnemonic == "jmp":
                resolution = _target_resolution(image, target)
                if resolution == "resolved_executable":
                    terminator = "jump"
                    append_successor(
                        target,
                        "jump",
                        source_rva,
                        current_state,
                        evidence_kind=evidence_kind,
                    )
                else:
                    terminator = "indirect_jump"
                    unsupported = f"direct jump target is {resolution.replace('_', ' ')}"
                    edges.append(
                        ControlFlowFact(
                            source_instruction_rva=source_rva,
                            kind="jump",
                            resolution=resolution,
                            evidence_kind=evidence_kind,
                            target_rva=target if image.is_mapped_rva(target) else None,
                            target_va=target_va if not image.is_mapped_rva(target) else None,
                            same_module=image.is_mapped_rva(target),
                            expression=expression,
                        )
                    )
            else:
                terminator = "conditional"
                resolution = _target_resolution(image, target)
                if resolution == "resolved_executable":
                    append_successor(
                        target,
                        "branch",
                        source_rva,
                        current_state,
                        evidence_kind=evidence_kind,
                    )
                else:
                    edges.append(
                        ControlFlowFact(
                            source_instruction_rva=source_rva,
                            kind="branch",
                            resolution=resolution,
                            evidence_kind=evidence_kind,
                            target_rva=target if image.is_mapped_rva(target) else None,
                            target_va=target_va if not image.is_mapped_rva(target) else None,
                            same_module=image.is_mapped_rva(target),
                            expression=expression,
                        )
                    )
                    unsupported = f"conditional target is {resolution.replace('_', ' ')}"
                if image.is_executable_rva(fallthrough):
                    append_successor(
                        fallthrough,
                        "branch_fallthrough",
                        source_rva,
                        current_state,
                        evidence_kind="fallthrough",
                    )
                else:
                    edges.append(
                        ControlFlowFact(
                            source_instruction_rva=source_rva,
                            kind="branch_fallthrough",
                            resolution=_target_resolution(image, fallthrough),
                            evidence_kind="fallthrough",
                            target_rva=(
                                fallthrough if image.is_mapped_rva(fallthrough) else None
                            ),
                            target_va=(
                                image.image_base + fallthrough
                                if not image.is_mapped_rva(fallthrough)
                                else None
                            ),
                            same_module=image.is_mapped_rva(fallthrough),
                        )
                    )
                if unsupported is not None:
                    # Code generation requires both conditional successors. If
                    # either arm is invalid, keep its graph fact but emit an
                    # explicit unsupported block rather than a malformed CFG.
                    terminator = "invalid"
                    successors = []
            break
        _update_constants(instruction, image, constants, imported_registers)
        cursor = fallthrough
    else:
        terminator = "invalid"
        unsupported = "basic block exceeds 4096 instructions"

    return DecodeResult(
        block=Block(
            rva=int(start),
            instructions=instructions,
            successors=successors,
            terminator=terminator,
            imported_call=imported_call,
            unsupported_reason=unsupported,
        ),
        edges=edges,
        successor_states=successor_states,
    )


def discover_cfg(
    image: PEImage, roots: list[int], max_blocks: int = 100_000
) -> dict[int, Block]:
    pending = list(dict.fromkeys(roots))
    entry_states: dict[int, EntryState] = {root: EntryState() for root in roots}
    blocks: dict[int, Block] = {}

    def enqueue(target: int, state: EntryState) -> None:
        previous = entry_states.get(target)
        if previous is None:
            entry_states[target] = state
        else:
            merged = previous.merged(state)
            if merged != previous:
                entry_states[target] = merged
                # Facts only become less specific as new predecessors arrive.
                blocks.pop(target, None)
        pending.append(target)

    while pending and len(blocks) < max_blocks:
        start = pending.pop()
        if start in blocks or not image.is_executable_rva(start):
            continue
        result = decode_block(
            image,
            start,
            entry_states.get(start, EntryState()),
            leaders=entry_states,
        )
        blocks[start] = result.block
        # Reverse enqueue order to preserve the historical LIFO behavior: calls
        # visit the callee before their fallthrough path.
        for target, state in reversed(result.successor_states):
            enqueue(target, state)

    # A target may have been learned after an earlier block was decoded. Keep
    # the compatibility path normalized exactly as before.
    leaders = set(blocks)
    for block in blocks.values():
        for index, instruction in enumerate(block.instructions[1:], 1):
            rva = int(instruction.address) - image.image_base
            if rva not in leaders:
                continue
            block.instructions = block.instructions[:index]
            block.successors = [rva]
            block.terminator = "fallthrough"
            block.imported_call = None
            block.unsupported_reason = None
            break

    return blocks


def load_persisted_blocks(
    image: PEImage,
    revisions: Iterable[Mapping[str, Any]],
) -> tuple[dict[int, Block], dict[int, EntryState]]:
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    blocks: dict[int, Block] = {}
    entry_states: dict[int, EntryState] = {}
    for revision in revisions:
        rva = int(revision["rva"])
        instructions = []
        for stored in revision["instructions"]:
            raw = bytes(stored["bytes"])
            instruction = next(
                decoder.disasm(raw, image.image_base + int(stored["rva"]), 1), None
            )
            if (
                instruction is None
                or int(instruction.size) != int(stored["size"])
                or bytes(instruction.bytes) != raw
                or instruction.mnemonic != stored["mnemonic"]
            ):
                raise ValueError(
                    f"persisted instruction no longer decodes at RVA 0x{int(stored['rva']):08x}"
                )
            instructions.append(instruction)
        successors = [
            int(edge["target_rva"])
            for edge in revision["edges"]
            if edge.get("target_rva") is not None
            and edge.get("resolution") in {"resolved_executable", "pending"}
        ]
        imported = None
        if revision.get("import_library") is not None:
            imported = ImportSymbol(
                library=str(revision["import_library"]),
                name=revision.get("import_name"),
                ordinal=(
                    int(revision["import_ordinal"])
                    if revision.get("import_ordinal") is not None
                    else None
                ),
                iat_rva=int(revision.get("import_iat_rva") or 0),
            )
        blocks[rva] = Block(
            rva=rva,
            instructions=instructions,
            successors=successors,
            terminator=str(revision["terminator"]),
            imported_call=imported,
            unsupported_reason=revision.get("unsupported_reason"),
        )
        entry_states[rva] = EntryState.from_dict(revision.get("entry_state"))
    return blocks, entry_states


def _merge_queued_state(
    store: Any,
    run_id: str,
    module_version_id: str,
    target: int,
    state: EntryState,
) -> EntryState:
    row = store.connection.execute(
        """SELECT entry_state_json, pending_entry_state_json FROM work_items
           WHERE run_id=? AND module_version_id=? AND kind='discover_block'
             AND target_rva=?""",
        (run_id, module_version_id, int(target)),
    ).fetchone()
    if row is None:
        return state
    queued_json = row["pending_entry_state_json"] or row["entry_state_json"]
    return EntryState.from_dict(json.loads(str(queued_json))).merged(state)


def discover_cfg_workspace(
    image: PEImage,
    store: Any,
    run_id: str,
    module_version_id: str,
    *,
    max_blocks: int = 100_000,
    work_item_budget: int | None = None,
    worker_id: str = "d2wasm",
    load_base: int | None = None,
    internal_bindings: Mapping[str, Mapping[str, Any]] | None = None,
    linked_ranges: Iterable[tuple[int, int, str]] = (),
) -> tuple[dict[int, Block], dict[str, int], bool]:
    """Resume block discovery from a TranslationStore until its static fixpoint."""

    load_base = image.image_base if load_base is None else int(load_base)
    internal_bindings = internal_bindings or {}
    linked_ranges = tuple(linked_ranges)
    revisions = store.load_selected_revisions(
        run_id, module_version_id=module_version_id
    )
    blocks, selected_states = load_persisted_blocks(image, revisions)
    block_starts = sorted(blocks)
    block_ends = {
        start: (
            int(block.instructions[-1].address) - image.image_base
            + int(block.instructions[-1].size)
            if block.instructions
            else start
        )
        for start, block in blocks.items()
    }
    leaders = set(blocks)
    leaders.update(
        int(row[0])
        for row in store.connection.execute(
            """SELECT target_rva FROM work_items
               WHERE run_id=? AND module_version_id=? AND target_rva IS NOT NULL""",
            (run_id, module_version_id),
        )
    )

    def record_block(block: Block) -> None:
        if block.rva not in block_ends:
            insort(block_starts, block.rva)
        blocks[block.rva] = block
        block_ends[block.rva] = (
            int(block.instructions[-1].address) - image.image_base
            + int(block.instructions[-1].size)
            if block.instructions
            else block.rva
        )
        leaders.add(block.rva)

    def containing_block(target_rva: int) -> Block | None:
        index = bisect_right(block_starts, target_rva) - 1
        if index < 0:
            return None
        start = block_starts[index]
        if start < target_rva < block_ends[start]:
            return blocks[start]
        return None

    store.reconcile_work(run_id, module_version_id=module_version_id)
    processed = 0

    while work_item_budget is None or processed < work_item_budget:
        claimed = store.claim_work(
            run_id,
            worker_id,
            module_version_id=module_version_id,
            kinds=("discover_block",),
        )
        if claimed is None:
            break
        target = int(claimed["target_rva"])
        state = EntryState.from_dict(claimed["entry_state"])
        related_revisions: list[dict[str, Any]] = []

        if target not in blocks and len(blocks) >= max_blocks:
            store.finish_work(
                claimed["work_item_id"],
                claimed["lease_token"],
                state="blocked",
                error="max_blocks_per_module reached",
            )
            processed += 1
            continue
        if not image.is_executable_rva(target):
            store.finish_work(
                claimed["work_item_id"],
                claimed["lease_token"],
                state="unsupported",
                error=f"RVA 0x{target:08x} is not executable",
            )
            processed += 1
            continue

        # Normalize a late leader before decoding it. A target inside an
        # instruction remains an explicit ambiguity instead of a false split.
        containing = containing_block(target)
        if containing is not None:
            split_index = next(
                (
                    index
                    for index, instruction in enumerate(containing.instructions)
                    if int(instruction.address) - image.image_base == target
                ),
                None,
            )
            if split_index is None:
                store.finish_work(
                    claimed["work_item_id"],
                    claimed["lease_token"],
                    state="ambiguous",
                    error=f"RVA 0x{target:08x} lands inside an instruction",
                )
                processed += 1
                continue
            prefix_state = selected_states.get(containing.rva, EntryState())
            prefix_result = decode_block(
                image,
                containing.rva,
                prefix_state,
                leaders={target},
            )
            if not prefix_result.successor_states:
                store.finish_work(
                    claimed["work_item_id"],
                    claimed["lease_token"],
                    state="ambiguous",
                    error=f"could not derive prefix state for RVA 0x{target:08x}",
                )
                processed += 1
                continue
            prefix_exit_state = prefix_result.successor_states[0][1]
            state = state.merged(prefix_exit_state)
            related_revisions.append(
                {
                    "rva": prefix_result.block.rva,
                    "entry_state": prefix_state.to_dict(),
                    "instructions": prefix_result.block.instructions,
                    "edges": [
                        edge.to_store(module_version_id)
                        for edge in prefix_result.edges
                    ],
                    "terminator": prefix_result.block.terminator,
                    "facts": {"normalization": "late_leader", "leader_rva": target},
                }
            )

        result = decode_block(image, target, state, leaders=leaders)
        edge_rows = []
        for edge in result.edges:
            stored = edge.to_store(module_version_id)
            if edge.kind in {"import_call", "import_jump"} and result.block.imported_call:
                binding = internal_bindings.get(result.block.imported_call.display_name)
                if binding is not None:
                    stored.update(
                        {
                            "target_module_version_id": binding[
                                "target_module_version_id"
                            ],
                            "target_rva": int(binding["target_rva"]),
                            "target_va": int(binding["target_va"]),
                            "resolution": "internal_import",
                        }
                    )
            edge_rows.append(stored)
        control_xrefs = [
            {
                "source_rva": int(edge["source_instruction_rva"]),
                "target_module_version_id": edge.get("target_module_version_id"),
                "target_rva": edge.get("target_rva"),
                "target_va": edge.get("target_va"),
                "kind": edge["kind"],
                "operand_index": edge.get("operand_index", -1),
                "details": {"evidence_kind": edge.get("evidence_kind", "decoder")},
            }
            for edge in edge_rows
            if edge.get("target_rva") is not None or edge.get("target_va") is not None
        ]
        data_xrefs = []
        for instruction in result.block.instructions:
            if instruction.group(CS_GRP_CALL) or instruction.group(CS_GRP_JUMP):
                continue
            source_rva = int(instruction.address) - image.image_base
            for operand_index, operand in enumerate(instruction.operands):
                value = None
                if operand.type == X86_OP_IMM:
                    value = int(operand.imm) & 0xFFFF_FFFF
                elif (
                    operand.type == X86_OP_MEM
                    and int(operand.mem.base) == 0
                    and int(operand.mem.index) == 0
                ):
                    value = int(operand.mem.disp) & 0xFFFF_FFFF
                if value is None:
                    continue
                target_module_id = None
                target_rva = None
                target_va = value
                if image.image_base <= value < image.image_base + image.size_of_image:
                    target_module_id = module_version_id
                    target_rva = value - image.image_base
                    target_va = load_base + target_rva
                else:
                    for range_start, range_end, candidate_module_id in linked_ranges:
                        if range_start <= value < range_end:
                            target_module_id = candidate_module_id
                            target_rva = value - range_start
                            break
                if target_module_id is not None:
                    data_xrefs.append(
                        {
                            "source_rva": source_rva,
                            "target_module_version_id": target_module_id,
                            "target_rva": target_rva,
                            "target_va": target_va,
                            "kind": "data",
                            "operand_index": operand_index,
                            "details": {"evidence_kind": "absolute_operand"},
                        }
                    )
        revision_id = store.persist_claimed_block(
            claimed["work_item_id"],
            claimed["lease_token"],
            run_id,
            module_version_id,
            target,
            entry_state=state.to_dict(),
            instructions=result.block.instructions,
            edges=edge_rows,
            xrefs=[*control_xrefs, *data_xrefs],
            terminator=result.block.terminator,
            unsupported_reason=result.block.unsupported_reason,
            imported_call=result.block.imported_call,
            facts={"decoder": "capstone-x86-32", "entry_state_hash": state.digest()},
            related_revisions=related_revisions,
        )
        if related_revisions:
            record_block(prefix_result.block)
        record_block(result.block)
        selected_states[target] = state

        # Successor work is deliberately enqueued only after the block revision
        # and completed attempt have committed. reconcile_work repairs a crash in
        # this window from the persisted edge facts.
        successor_items = []
        for successor, successor_state in result.successor_states:
            leaders.add(successor)
            merged = _merge_queued_state(
                store,
                run_id,
                module_version_id,
                successor,
                successor_state,
            )
            successor_items.append(
                {
                    "run_id": run_id,
                    "module_version_id": module_version_id,
                    "target_rva": successor,
                    "kind": "discover_block",
                    "entry_state": merged.to_dict(),
                    "payload": {"source_rva": target},
                    "priority": (
                        1
                        if result.block.terminator == "call"
                        and successor == result.block.successors[0]
                        else 0
                    ),
                }
            )
        store.enqueue_work_batch(successor_items)
        processed += 1

    store.reconcile_work(run_id, module_version_id=module_version_id)
    counts = {
        str(row["state"]): int(row["count"])
        for row in store.connection.execute(
            """SELECT state, COUNT(*) AS count FROM work_items
               WHERE run_id=? AND module_version_id=? GROUP BY state""",
            (run_id, module_version_id),
        )
    }
    for state_name in (
        "pending",
        "leased",
        "completed",
        "blocked",
        "unsupported",
        "ambiguous",
        "failed",
    ):
        counts.setdefault(state_name, 0)
    counts["total"] = sum(counts.values())
    counts["unfinished"] = counts["pending"] + counts["leased"]
    complete = counts["unfinished"] == 0
    return blocks, counts, complete
