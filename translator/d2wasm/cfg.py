from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Any

from capstone import CS_ARCH_X86, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from .pe import ImportSymbol, PEImage


@dataclass
class Block:
    rva: int
    instructions: list[Any]
    successors: list[int]
    terminator: str
    imported_call: ImportSymbol | None = None
    unsupported_reason: str | None = None


def _direct_target(instruction: Any, image: PEImage) -> int | None:
    if not instruction.operands or instruction.operands[0].type != X86_OP_IMM:
        return None
    return int(instruction.operands[0].imm) - image.image_base


def _iat_call(instruction: Any, image: PEImage) -> ImportSymbol | None:
    if not instruction.operands or instruction.operands[0].type != X86_OP_MEM:
        return None
    memory = instruction.operands[0].mem
    if memory.base or memory.index:
        return None
    return image.import_by_iat_va.get(int(memory.disp) & 0xFFFFFFFF)


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


def _resolved_operand(
    instruction: Any,
    image: PEImage,
    constants: dict[str, int],
    imported: dict[str, ImportSymbol],
) -> tuple[int | None, ImportSymbol | None]:
    if not instruction.operands:
        return None, None
    operand = instruction.operands[0]
    if operand.type == X86_OP_IMM:
        return int(operand.imm), None
    if operand.type == X86_OP_REG:
        register = _base_reg(instruction, operand.reg)
        return constants.get(register), imported.get(register)
    if operand.type == X86_OP_MEM:
        memory = operand.mem
        address = int(memory.disp) & 0xFFFFFFFF
        if memory.base:
            base = _base_reg(instruction, memory.base)
            if base not in constants:
                return None, None
            address = (address + constants[base]) & 0xFFFFFFFF
        if memory.index:
            index = _base_reg(instruction, memory.index)
            if index not in constants:
                return None, None
            address = (address + constants[index] * int(memory.scale)) & 0xFFFFFFFF
        return None, image.import_by_iat_va.get(address)
    return None, None


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
    if instruction.mnemonic == "mov" and len(operands) == 2 and operands[0].type == X86_OP_REG and operands[0].size == 4:
        destination = _base_reg(instruction, operands[0].reg)
        source = operands[1]
        if destination and source.type == X86_OP_IMM:
            constants[destination] = int(source.imm) & 0xFFFFFFFF
        elif destination and source.type == X86_OP_REG:
            source_register = _base_reg(instruction, source.reg)
            if source_register in constants:
                constants[destination] = constants[source_register]
            if source_register in imported:
                imported[destination] = imported[source_register]
        elif destination and source.type == X86_OP_MEM:
            memory = source.mem
            if not memory.base and not memory.index:
                symbol = image.import_by_iat_va.get(int(memory.disp) & 0xFFFFFFFF)
                if symbol:
                    imported[destination] = symbol
    elif instruction.mnemonic == "lea" and len(operands) == 2 and operands[0].type == X86_OP_REG and operands[1].type == X86_OP_MEM:
        destination = _base_reg(instruction, operands[0].reg)
        memory = operands[1].mem
        if destination and not memory.base and not memory.index:
            constants[destination] = int(memory.disp) & 0xFFFFFFFF


def _jump_table_targets(instruction: Any, image: PEImage) -> list[int]:
    if not instruction.operands or instruction.operands[0].type != X86_OP_MEM:
        return []
    memory = instruction.operands[0].mem
    if memory.base or not memory.index or int(memory.scale) != 4:
        return []
    table_rva = (int(memory.disp) & 0xFFFFFFFF) - image.image_base
    candidates: list[tuple[int, int]] = []
    # Optimized MSVC string/memory routines use both ordinary tables and
    # deliberately biased tables whose only legal indices are -8..-1 or 1..3.
    # Find contiguous runs of code pointers around the encoded base rather
    # than assuming index zero is legal.
    for index in range(-64, 256):
        try:
            target_va = struct.unpack("<I", image.bytes_at_rva(table_rva + index * 4, 4))[0]
        except (ValueError, struct.error):
            continue
        target = target_va - image.image_base
        if image.is_executable_rva(target):
            candidates.append((index, target))
    runs: list[list[tuple[int, int]]] = []
    for candidate in candidates:
        if not runs or candidate[0] != runs[-1][-1][0] + 1:
            runs.append([candidate])
        else:
            runs[-1].append(candidate)
    runs = [run for run in runs if len(run) >= 2]
    if not runs:
        return []
    closest = min(runs, key=lambda run: min(abs(index) for index, _ in run))
    return list(dict.fromkeys(target for _, target in closest))


def discover_cfg(image: PEImage, roots: list[int], max_blocks: int = 100_000) -> dict[int, Block]:
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    pending = list(dict.fromkeys(roots))
    entry_states: dict[int, tuple[dict[str, int], dict[str, ImportSymbol]]] = {
        root: ({}, {}) for root in roots
    }
    blocks: dict[int, Block] = {}

    def enqueue(
        target: int,
        constants: dict[str, int],
        imported: dict[str, ImportSymbol],
        after_call: bool = False,
    ) -> None:
        next_constants = dict(constants)
        next_imported = dict(imported)
        if after_call:
            for volatile in ("eax", "ecx", "edx"):
                next_constants.pop(volatile, None)
                next_imported.pop(volatile, None)
        previous = entry_states.get(target)
        if previous is None:
            entry_states[target] = (next_constants, next_imported)
        else:
            merged_constants = {
                register: value
                for register, value in previous[0].items()
                if next_constants.get(register) == value
            }
            merged_imported = {
                register: symbol
                for register, symbol in previous[1].items()
                if next_imported.get(register) == symbol
            }
            merged = (merged_constants, merged_imported)
            if merged != previous:
                entry_states[target] = merged
                # Register facts only become less specific as new incoming
                # edges are found. Rebuild a block that was emitted from an
                # earlier, unsafely specific predecessor state and propagate
                # the weaker state through its successors.
                blocks.pop(target, None)
        pending.append(target)

    while pending and len(blocks) < max_blocks:
        start = pending.pop()
        if start in blocks or not image.is_executable_rva(start):
            continue
        instructions: list[Any] = []
        successors: list[int] = []
        terminator = "fallthrough"
        imported_call = None
        unsupported = None
        cursor = start
        state = entry_states.get(start, ({}, {}))
        constants = dict(state[0])
        imported_registers = dict(state[1])

        # Bound a malformed/data run while still allowing large compiler blocks.
        for _ in range(4096):
            if cursor != start and cursor in entry_states:
                terminator = "fallthrough"
                successors = [cursor]
                enqueue(cursor, constants, imported_registers)
                break
            try:
                data = image.bytes_at_rva(cursor, 15)
            except ValueError as error:
                unsupported = str(error)
                terminator = "invalid"
                break
            instruction = next(
                decoder.disasm(data, image.image_base + cursor, 1), None
            )
            if instruction is None:
                unsupported = f"invalid instruction at RVA 0x{cursor:08x}"
                terminator = "invalid"
                break
            instructions.append(instruction)
            fallthrough = cursor + instruction.size

            if instruction.group(CS_GRP_RET):
                terminator = "ret"
                break
            if instruction.group(CS_GRP_CALL):
                target_va, imported_call = _resolved_operand(
                    instruction, image, constants, imported_registers
                )
                target = target_va - image.image_base if target_va is not None else None
                if target is not None and image.is_executable_rva(target):
                    terminator = "call"
                    successors = [target, fallthrough]
                    # LIFO worklist: translate the callee first so a bounded
                    # partial artifact follows the executable startup path.
                    enqueue(fallthrough, constants, imported_registers, after_call=True)
                    # A direct callee can be reached from many call sites with
                    # different argument-register values.  Propagating one
                    # caller's register constants into its shared CFG makes
                    # later indirect calls unsoundly compile as direct calls.
                    enqueue(target, {}, {})
                elif imported_call is not None:
                    terminator = "import_call"
                    successors = [fallthrough]
                    enqueue(fallthrough, constants, imported_registers, after_call=True)
                else:
                    terminator = "indirect_call"
                    successors = [fallthrough]
                    enqueue(fallthrough, constants, imported_registers, after_call=True)
                    unsupported = "unresolved indirect call"
                break
            if instruction.group(CS_GRP_JUMP):
                target_va, imported_jump = _resolved_operand(
                    instruction, image, constants, imported_registers
                )
                target = target_va - image.image_base if target_va is not None else None
                if imported_jump is not None:
                    terminator = "import_jump"
                    imported_call = imported_jump
                elif target is None:
                    table_targets = _jump_table_targets(instruction, image)
                    if table_targets:
                        terminator = "jump_table"
                        successors = table_targets
                        for table_target in table_targets:
                            enqueue(table_target, constants, imported_registers)
                    else:
                        terminator = "indirect_jump"
                        unsupported = "unresolved indirect jump"
                elif instruction.mnemonic == "jmp":
                    terminator = "jump"
                    successors = [target]
                    enqueue(target, constants, imported_registers)
                else:
                    terminator = "conditional"
                    successors = [target, fallthrough]
                    enqueue(target, constants, imported_registers)
                    enqueue(fallthrough, constants, imported_registers)
                break
            _update_constants(instruction, image, constants, imported_registers)
            cursor = fallthrough
        else:
            terminator = "invalid"
            unsupported = "basic block exceeds 4096 instructions"

        blocks[start] = Block(
            rva=start,
            instructions=instructions,
            successors=successors,
            terminator=terminator,
            imported_call=imported_call,
            unsupported_reason=unsupported,
        )

    # Recursive discovery can learn that a branch targets the middle of a
    # block decoded earlier. Normalize every such leader into a unique block;
    # this prevents duplicated lifting and gives each x86 instruction one AOT
    # implementation site.
    leaders = set(blocks)
    for start, block in blocks.items():
        split_at = None
        for index, instruction in enumerate(block.instructions[1:], 1):
            rva = int(instruction.address) - image.image_base
            if rva in leaders:
                split_at = (index, rva)
                break
        if split_at is not None:
            index, target = split_at
            block.instructions = block.instructions[:index]
            block.successors = [target]
            block.terminator = "fallthrough"
            block.imported_call = None
            block.unsupported_reason = None

    return blocks
