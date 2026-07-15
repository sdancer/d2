from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import subprocess
from typing import Any

from capstone import x86_const
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from .cfg import Block
from .api import ApiSpec
from .pe import PEImage


CONTROL_TERMINATORS = {
    "ret",
    "call",
    "import_call",
    "import_jump",
    "indirect_call",
    "jump",
    "conditional",
    "indirect_jump",
    "jump_table",
}

HOST_THUNK_BASE = 0xE0000000

_MODELED_EFLAG_ACCESS = (
    (
        x86_const.X86_EFLAGS_TEST_CF,
        x86_const.X86_EFLAGS_MODIFY_CF
        | x86_const.X86_EFLAGS_RESET_CF
        | x86_const.X86_EFLAGS_SET_CF,
    ),
    (
        x86_const.X86_EFLAGS_TEST_PF,
        x86_const.X86_EFLAGS_MODIFY_PF
        | x86_const.X86_EFLAGS_RESET_PF
        | x86_const.X86_EFLAGS_SET_PF,
    ),
    (
        x86_const.X86_EFLAGS_TEST_ZF,
        x86_const.X86_EFLAGS_MODIFY_ZF
        | x86_const.X86_EFLAGS_RESET_ZF
        | x86_const.X86_EFLAGS_SET_ZF,
    ),
    (
        x86_const.X86_EFLAGS_TEST_SF,
        x86_const.X86_EFLAGS_MODIFY_SF
        | x86_const.X86_EFLAGS_RESET_SF
        | x86_const.X86_EFLAGS_SET_SF,
    ),
    (
        x86_const.X86_EFLAGS_TEST_OF,
        x86_const.X86_EFLAGS_MODIFY_OF
        | x86_const.X86_EFLAGS_RESET_OF
        | x86_const.X86_EFLAGS_SET_OF,
    ),
)
_ALL_MODELED_EFLAGS = (1 << len(_MODELED_EFLAG_ACCESS)) - 1
_OPTIONAL_FLAG_MNEMONICS = {
    "adc",
    "add",
    "and",
    "cmp",
    "dec",
    "inc",
    "neg",
    "or",
    "sbb",
    "sub",
    "test",
    "xor",
}


def host_thunk_pc(key: str) -> int:
    value = 0x811C9DC5
    for byte in key.lower().encode("utf-8"):
        value = ((value ^ byte) * 0x01000193) & 0xFFFFFFFF
    return HOST_THUNK_BASE | (value & 0x0FFFFFFC)


@dataclass(frozen=True)
class UnsupportedSite:
    rva: int
    instruction: str
    reason: str


REGISTERS: dict[str, tuple[str, int, int]] = {
    "eax": ("eax", 0, 32), "ax": ("eax", 0, 16),
    "al": ("eax", 0, 8), "ah": ("eax", 8, 8),
    "ebx": ("ebx", 0, 32), "bx": ("ebx", 0, 16),
    "bl": ("ebx", 0, 8), "bh": ("ebx", 8, 8),
    "ecx": ("ecx", 0, 32), "cx": ("ecx", 0, 16),
    "cl": ("ecx", 0, 8), "ch": ("ecx", 8, 8),
    "edx": ("edx", 0, 32), "dx": ("edx", 0, 16),
    "dl": ("edx", 0, 8), "dh": ("edx", 8, 8),
    "esi": ("esi", 0, 32), "si": ("esi", 0, 16),
    "edi": ("edi", 0, 32), "di": ("edi", 0, 16),
    "ebp": ("ebp", 0, 32), "bp": ("ebp", 0, 16),
    "esp": ("esp", 0, 32), "sp": ("esp", 0, 16),
}


def _mask(bits: int) -> int:
    return 0xFFFFFFFF if bits == 32 else (1 << bits) - 1


class CGenerator:
    def __init__(
        self,
        image: PEImage,
        blocks: dict[int, Block],
        api_specs: dict[str, ApiSpec] | None = None,
        load_base: int | None = None,
        global_pc: bool = False,
        internal_targets: dict[str, int] | None = None,
    ):
        self.image = image
        self.blocks = blocks
        self.api_specs = api_specs or {}
        self.load_base = image.image_base if load_base is None else load_base
        self.global_pc = global_pc
        self.internal_targets = internal_targets or {}
        self.used_apis: dict[str, ApiSpec] = {}
        self.unsupported: list[UnsupportedSite] = []

    def _pc(self, rva: int) -> int:
        pc = self.load_base + rva if self.global_pc else rva
        return pc & 0xFFFFFFFF

    def _dynamic_pc(self, expression: str) -> str:
        if self.global_pc:
            return expression
        return (
            f"(({expression}) >= 0x{HOST_THUNK_BASE:08x}u ? "
            f"({expression}) : ({expression}) - 0x{self.load_base:08x}u)"
        )

    def _fail(self, instruction: Any, reason: str) -> None:
        self.unsupported.append(
            UnsupportedSite(
                rva=int(instruction.address) - self.image.image_base,
                instruction=f"{instruction.mnemonic} {instruction.op_str}".strip(),
                reason=reason,
            )
        )

    @staticmethod
    def _reg(instruction: Any, operand: Any) -> tuple[str, int, int] | None:
        return REGISTERS.get(instruction.reg_name(operand.reg))

    def _address(self, instruction: Any, operand: Any) -> str | None:
        memory = operand.mem
        if memory.segment:
            segment = instruction.reg_name(memory.segment)
            if segment == "fs":
                parts: list[str] = ["fs_base"]
            elif segment in ("ds", "es", "ss"):
                parts = []
            else:
                self._fail(instruction, f"unsupported {segment}-relative memory")
                return None
        else:
            parts = []
        if memory.base:
            reg = REGISTERS.get(instruction.reg_name(memory.base))
            if reg is None or reg[2] != 32:
                self._fail(instruction, "unsupported memory base register")
                return None
            parts.append(reg[0])
        if memory.index:
            reg = REGISTERS.get(instruction.reg_name(memory.index))
            if reg is None or reg[2] != 32:
                self._fail(instruction, "unsupported memory index register")
                return None
            parts.append(f"({reg[0]} * {int(memory.scale)}u)")
        displacement = self.image.relocate_instruction_value(
            instruction,
            int(getattr(instruction, "disp_offset", 0)),
            int(memory.disp),
            self.load_base,
        )
        if displacement or not parts:
            parts.append(f"0x{displacement:08x}u")
        return " + ".join(parts)

    def _read(self, instruction: Any, operand: Any) -> tuple[str, int] | None:
        bits = int(operand.size) * 8
        if operand.type == X86_OP_IMM:
            value = self.image.relocate_instruction_value(
                instruction,
                int(getattr(instruction, "imm_offset", 0)),
                int(operand.imm),
                self.load_base,
            )
            return f"0x{value & _mask(bits):x}u", bits
        if operand.type == X86_OP_REG:
            reg = self._reg(instruction, operand)
            if reg is None:
                self._fail(instruction, "unsupported register")
                return None
            base, shift, reg_bits = reg
            expression = base if reg_bits == 32 else f"(({base} >> {shift}) & 0x{_mask(reg_bits):x}u)"
            return expression, reg_bits
        if operand.type == X86_OP_MEM:
            memory = operand.mem
            if bits == 32 and not memory.base and not memory.index and not memory.segment:
                symbol = self.image.import_by_iat_va.get(int(memory.disp) & 0xFFFFFFFF)
                if symbol is not None:
                    key = symbol.display_name
                    internal_target = self.internal_targets.get(key)
                    if internal_target is not None:
                        return f"0x{internal_target:08x}u", bits
                    spec = self.api_specs.get(key)
                    if (
                        spec is not None
                        and self._intrinsic_import(key) is None
                        and key.lower() != "dsound.dll!#2"
                    ):
                        self.used_apis[key] = spec
                        return f"0x{host_thunk_pc(spec.key):08x}u", bits
            address = self._address(instruction, operand)
            if address is None:
                return None
            if bits not in (8, 16, 32):
                self._fail(instruction, f"unsupported {bits}-bit memory read")
                return None
            return f"load{bits}({address})", bits
        self._fail(instruction, "unsupported operand kind")
        return None

    def _write(self, instruction: Any, operand: Any, value: str) -> str | None:
        bits = int(operand.size) * 8
        if operand.type == X86_OP_REG:
            reg = self._reg(instruction, operand)
            if reg is None:
                self._fail(instruction, "unsupported destination register")
                return None
            base, shift, reg_bits = reg
            if reg_bits == 32:
                return f"{base} = (uint32_t)({value});"
            field_mask = _mask(reg_bits) << shift
            return (
                f"{base} = ({base} & 0x{(~field_mask) & 0xFFFFFFFF:08x}u) | "
                f"((((uint32_t)({value})) & 0x{_mask(reg_bits):x}u) << {shift});"
            )
        if operand.type == X86_OP_MEM:
            address = self._address(instruction, operand)
            if address is None:
                return None
            if bits not in (8, 16, 32):
                self._fail(instruction, f"unsupported {bits}-bit memory write")
                return None
            return f"store{bits}({address}, (uint{bits}_t)({value}));"
        self._fail(instruction, "unsupported destination operand")
        return None

    def _fpu_value(self, instruction: Any, operand: Any) -> str | None:
        if operand.type == X86_OP_MEM:
            address = self._address(instruction, operand)
            if address is None:
                return None
            bits = int(operand.size) * 8
            if bits == 32:
                return f"(double)load_f32({address})"
            if bits == 64:
                return f"load_f64({address})"
            self._fail(instruction, f"unsupported {bits}-bit x87 memory operand")
            return None
        if operand.type == X86_OP_REG:
            name = instruction.reg_name(operand.reg)
            match = re.fullmatch(r"st\(([0-7])\)", name)
            if match:
                return f"fpu[{int(match.group(1))}]"
        self._fail(instruction, "unsupported x87 operand")
        return None

    def _fpu_store(self, instruction: Any, operand: Any, value: str) -> str | None:
        if operand.type == X86_OP_MEM:
            address = self._address(instruction, operand)
            if address is None:
                return None
            bits = int(operand.size) * 8
            if bits == 32:
                return f"store_f32({address}, (float)({value}));"
            if bits == 64:
                return f"store_f64({address}, {value});"
        if operand.type == X86_OP_REG:
            name = instruction.reg_name(operand.reg)
            match = re.fullmatch(r"st\(([0-7])\)", name)
            if match:
                return f"fpu[{int(match.group(1))}] = {value};"
        self._fail(instruction, "unsupported x87 destination")
        return None

    def _binary(
        self,
        instruction: Any,
        operator: str,
        flags: str | None = None,
        emit_flags: bool = True,
    ) -> list[str] | None:
        if len(instruction.operands) != 2:
            self._fail(instruction, "expected two operands")
            return None
        left = self._read(instruction, instruction.operands[0])
        right = self._read(instruction, instruction.operands[1])
        if left is None or right is None:
            return None
        bits = left[1]
        if bits not in (8, 16, 32) or right[1] != bits:
            self._fail(instruction, "arithmetic requires equal 8-, 16-, or 32-bit operands")
            return None
        lines = [f"a = {left[0]};", f"b = {right[0]};", f"result = (a {operator} b) & 0x{_mask(bits):x}u;"]
        if flags and emit_flags:
            if flags == "logic32":
                lines.append(f"flags_logic32(result, {bits}u);")
            else:
                lines.append(f"flags_{flags}(a, b, result, {bits}u);")
        write = self._write(instruction, instruction.operands[0], "result")
        if write is None:
            return None
        lines.append(write)
        return lines

    def lift_instruction(
        self, instruction: Any, emit_flags: bool = True
    ) -> list[str] | None:
        mnemonic = instruction.mnemonic
        operands = instruction.operands
        if mnemonic == "nop":
            return []
        if mnemonic == "mov" and len(operands) == 2:
            value = self._read(instruction, operands[1])
            if value is None:
                return None
            write = self._write(instruction, operands[0], value[0])
            return [write] if write else None
        if mnemonic in ("movzx", "movsx") and len(operands) == 2:
            value = self._read(instruction, operands[1])
            if value is None:
                return None
            expression = value[0]
            if mnemonic == "movsx":
                expression = f"(uint32_t)(int32_t)(int{value[1]}_t)({expression})"
            write = self._write(instruction, operands[0], expression)
            return [write] if write else None
        if mnemonic == "lea" and len(operands) == 2 and operands[1].type == X86_OP_MEM:
            address = self._address(instruction, operands[1])
            write = self._write(instruction, operands[0], address or "0") if address else None
            return [write] if write else None
        if mnemonic == "add":
            return self._binary(instruction, "+", "add32", emit_flags)
        if mnemonic == "sub":
            return self._binary(instruction, "-", "sub32", emit_flags)
        if mnemonic == "xor":
            return self._binary(instruction, "^", "logic32", emit_flags)
        if mnemonic == "and":
            return self._binary(instruction, "&", "logic32", emit_flags)
        if mnemonic == "or":
            return self._binary(instruction, "|", "logic32", emit_flags)
        if mnemonic in ("adc", "sbb") and len(operands) == 2:
            left = self._read(instruction, operands[0])
            right = self._read(instruction, operands[1])
            if left is None or right is None or left[1] not in (8, 16, 32) or left[1] != right[1]:
                self._fail(instruction, f"{mnemonic} requires equal integer operands")
                return None
            bits = left[1]
            write = self._write(instruction, operands[0], "result")
            if write is None:
                return None
            helper = "flags_adc" if mnemonic == "adc" else "flags_sbb"
            operator = "+" if mnemonic == "adc" else "-"
            lines = [
                f"a = {left[0]};",
                f"b = {right[0]};",
                "old_cf = cf;",
                f"result = (a {operator} b {operator} old_cf) & 0x{_mask(bits):x}u;",
            ]
            if emit_flags:
                lines.append(f"{helper}(a, b, result, old_cf, {bits}u);")
            return [*lines, write]
        if mnemonic in ("inc", "dec") and len(operands) == 1:
            value = self._read(instruction, operands[0])
            if value is None or value[1] not in (8, 16, 32):
                self._fail(instruction, "inc/dec requires an 8-, 16-, or 32-bit operand")
                return None
            operator = "+" if mnemonic == "inc" else "-"
            flag_fn = "flags_inc" if mnemonic == "inc" else "flags_dec"
            bits = value[1]
            write = self._write(instruction, operands[0], "result")
            if write is None:
                return None
            lines = [
                f"a = {value[0]};",
                f"result = (a {operator} 1u) & 0x{_mask(bits):x}u;",
            ]
            if emit_flags:
                lines.append(f"{flag_fn}(a, result, {bits}u);")
            return [*lines, write]
        if mnemonic in ("cmp", "test") and len(operands) == 2:
            left = self._read(instruction, operands[0])
            right = self._read(instruction, operands[1])
            if left is None or right is None or left[1] not in (8, 16, 32) or left[1] != right[1]:
                self._fail(instruction, f"{mnemonic} requires equal 8-, 16-, or 32-bit operands")
                return None
            bits = left[1]
            if not emit_flags:
                return []
            operator = "-" if mnemonic == "cmp" else "&"
            flag_fn = "flags_sub32" if mnemonic == "cmp" else "flags_logic32"
            return [f"a = {left[0]};", f"b = {right[0]};", f"result = (a {operator} b) & 0x{_mask(bits):x}u;", f"{flag_fn}(a, b, result, {bits}u);" if mnemonic == "cmp" else f"{flag_fn}(result, {bits}u);"]
        if mnemonic in ("not", "neg") and len(operands) == 1:
            value = self._read(instruction, operands[0])
            if value is None or value[1] not in (8, 16, 32):
                self._fail(instruction, f"{mnemonic} requires an integer operand")
                return None
            bits = value[1]
            if mnemonic == "not":
                expression = f"(~({value[0]})) & 0x{_mask(bits):x}u"
                write = self._write(instruction, operands[0], expression)
                return [write] if write else None
            write = self._write(instruction, operands[0], "result")
            if write is None:
                return None
            lines = [
                f"a = {value[0]};",
                f"result = (0u - a) & 0x{_mask(bits):x}u;",
            ]
            if emit_flags:
                lines.append(f"flags_sub32(0u, a, result, {bits}u);")
            return [*lines, write]
        if mnemonic in ("shl", "sal", "shr", "sar") and len(operands) == 2:
            value = self._read(instruction, operands[0])
            count = self._read(instruction, operands[1])
            if value is None or count is None or value[1] not in (8, 16, 32):
                self._fail(instruction, "shift requires an integer destination")
                return None
            bits = value[1]
            write = self._write(instruction, operands[0], "result")
            if write is None:
                return None
            operation = {"shl": "SHIFT_LEFT", "sal": "SHIFT_LEFT", "shr": "SHIFT_RIGHT", "sar": "SHIFT_ARITH"}[mnemonic]
            return [f"a = {value[0]};", f"b = ({count[0]}) & 31u;", f"result = shift_value(a, b, {bits}u, {operation});", write]
        if mnemonic in ("rol", "ror", "rcl", "rcr") and len(operands) == 2:
            value = self._read(instruction, operands[0])
            count = self._read(instruction, operands[1])
            if value is None or count is None or value[1] not in (8, 16, 32):
                self._fail(instruction, "rotate requires an integer destination")
                return None
            bits = value[1]
            write = self._write(instruction, operands[0], "result")
            if write is None:
                return None
            operation = {"rol": "ROTATE_LEFT", "ror": "ROTATE_RIGHT", "rcl": "ROTATE_CARRY_LEFT", "rcr": "ROTATE_CARRY_RIGHT"}[mnemonic]
            return [f"a = {value[0]};", f"b = ({count[0]}) & 31u;", f"result = rotate_value(a, b, {bits}u, {operation});", write]
        if mnemonic.startswith("set") and len(operands) == 1:
            # SETcc shares the Jcc condition spelling after the prefix.
            class ConditionInstruction:
                pass
            proxy = ConditionInstruction()
            proxy.mnemonic = "j" + mnemonic[3:]
            proxy.address = instruction.address
            proxy.op_str = instruction.op_str
            condition = self._condition(proxy)
            write = self._write(instruction, operands[0], f"({condition}) ? 1u : 0u") if condition else None
            return [write] if write else None
        if mnemonic in ("bsf", "bsr") and len(operands) == 2:
            source = self._read(instruction, operands[1])
            if source is None or source[1] not in (16, 32):
                self._fail(instruction, f"{mnemonic} requires a 16- or 32-bit source")
                return None
            write = self._write(instruction, operands[0], "result")
            if write is None:
                return None
            mask = _mask(source[1])
            scan = "__builtin_ctz(a)" if mnemonic == "bsf" else "31u - __builtin_clz(a)"
            return [
                f"a = ({source[0]}) & 0x{mask:x}u;",
                f"if (a) {{ result = {scan}; {write} zf = 0u; }} else zf = 1u;",
            ]
        if mnemonic == "xchg" and len(operands) == 2:
            left = self._read(instruction, operands[0])
            right = self._read(instruction, operands[1])
            if left is None or right is None or left[1] != right[1]:
                self._fail(instruction, "xchg requires equal integer operands")
                return None
            write_left = self._write(instruction, operands[0], "b")
            write_right = self._write(instruction, operands[1], "a")
            return [f"a = {left[0]};", f"b = {right[0]};", write_left, write_right] if write_left and write_right else None
        if mnemonic in ("mul", "imul") and len(operands) == 1:
            factor = self._read(instruction, operands[0])
            if factor is None or factor[1] not in (8, 16, 32):
                self._fail(instruction, f"{mnemonic} requires an 8-, 16-, or 32-bit operand")
                return None
            bits = factor[1]
            signed = mnemonic == "imul"
            if signed:
                product = f"wide_result = (int64_t)(int{bits}_t)(eax & 0x{_mask(bits):x}u) * (int64_t)(int{bits}_t)({factor[0]});"
                overflow = f"cf = of = wide_result != (int64_t)(int{bits}_t)((uint{bits}_t)wide_result);"
            else:
                product = f"wide_unsigned = (uint64_t)(eax & 0x{_mask(bits):x}u) * (uint64_t)(({factor[0]}) & 0x{_mask(bits):x}u);"
                overflow = f"cf = of = (wide_unsigned >> {bits}u) != 0u;"
            product_value = "(uint64_t)wide_result" if signed else "wide_unsigned"
            if bits == 8:
                result_lines = [f"eax = (eax & 0xffff0000u) | ((uint32_t){product_value} & 0xffffu);"]
            elif bits == 16:
                result_lines = [
                    f"eax = (eax & 0xffff0000u) | ((uint32_t){product_value} & 0xffffu);",
                    f"edx = (edx & 0xffff0000u) | (((uint32_t)({product_value} >> 16u)) & 0xffffu);",
                ]
            else:
                result_lines = [f"eax = (uint32_t){product_value};", f"edx = (uint32_t)({product_value} >> 32u);"]
            return [product, *result_lines, overflow]
        if mnemonic == "imul" and len(operands) in (2, 3):
            destination = operands[0]
            left = self._read(instruction, destination if len(operands) == 2 else operands[1])
            right = self._read(instruction, operands[1] if len(operands) == 2 else operands[2])
            bits = int(destination.size) * 8
            if (
                left is None
                or right is None
                or bits not in (8, 16, 32)
                or left[1] != bits
                or right[1] != bits
            ):
                self._fail(
                    instruction,
                    "two/three-operand imul requires equal 8-, 16-, or 32-bit operands",
                )
                return None
            write = self._write(instruction, destination, "result")
            return [
                f"wide_result = (int64_t)(int{bits}_t)({left[0]}) * "
                f"(int64_t)(int{bits}_t)({right[0]});",
                f"result = (uint32_t)wide_result & 0x{_mask(bits):x}u;",
                f"cf = of = wide_result != (int64_t)(int{bits}_t)"
                f"((uint{bits}_t)result);",
                write,
            ] if write else None
        if mnemonic == "div" and len(operands) == 1:
            divisor = self._read(instruction, operands[0])
            if divisor is None or divisor[1] != 32:
                self._fail(instruction, "div currently requires a 32-bit divisor")
                return None
            return [f"wide_unsigned = ((uint64_t)edx << 32) | eax;", f"b = {divisor[0]};", "if (!b || wide_unsigned / b > 0xffffffffu) { d2_status = D2_STATUS_ARITHMETIC_TRAP; return D2_ACTION_RETURN; }", "eax = (uint32_t)(wide_unsigned / b);", "edx = (uint32_t)(wide_unsigned % b);"]
        if mnemonic == "idiv" and len(operands) == 1:
            divisor = self._read(instruction, operands[0])
            if divisor is None or divisor[1] not in (8, 16, 32):
                self._fail(instruction, "idiv requires an 8-, 16-, or 32-bit divisor")
                return None
            bits = divisor[1]
            if bits == 8:
                dividend = "(int64_t)(int16_t)(eax & 0xffffu)"
                minimum, maximum = -128, 127
            elif bits == 16:
                dividend = "(int64_t)(int32_t)(((edx & 0xffffu) << 16u) | (eax & 0xffffu))"
                minimum, maximum = -32768, 32767
            else:
                dividend = "(int64_t)(((uint64_t)edx << 32u) | eax)"
                minimum, maximum = -2147483648, 2147483647
            lines = [
                f"wide_result = {dividend};",
                f"signed_divisor = (int64_t)(int{bits}_t)({divisor[0]});",
                "if (!signed_divisor || (wide_result == (-9223372036854775807LL - 1LL) && signed_divisor == -1)) { d2_status = D2_STATUS_ARITHMETIC_TRAP; return D2_ACTION_RETURN; }",
                "signed_quotient = wide_result / signed_divisor;",
                f"if (signed_quotient < {minimum}LL || signed_quotient > {maximum}LL) {{ d2_status = D2_STATUS_ARITHMETIC_TRAP; return D2_ACTION_RETURN; }}",
                "signed_remainder = wide_result % signed_divisor;",
            ]
            if bits == 8:
                lines.append("eax = (eax & 0xffff0000u) | (((uint32_t)signed_remainder & 0xffu) << 8u) | ((uint32_t)signed_quotient & 0xffu);")
            elif bits == 16:
                lines.extend([
                    "eax = (eax & 0xffff0000u) | ((uint32_t)signed_quotient & 0xffffu);",
                    "edx = (edx & 0xffff0000u) | ((uint32_t)signed_remainder & 0xffffu);",
                ])
            else:
                lines.extend(["eax = (uint32_t)signed_quotient;", "edx = (uint32_t)signed_remainder;"])
            return lines
        if mnemonic == "cdq":
            return ["edx = (eax & 0x80000000u) ? 0xffffffffu : 0u;"]
        if mnemonic == "cwde":
            return ["eax = (uint32_t)(int32_t)(int16_t)(eax & 0xffffu);"]
        if mnemonic == "cld":
            return ["df = 0;"]
        if mnemonic == "std":
            return ["df = 1;"]
        if mnemonic in ("rep stosd", "rep stosw", "rep stosb", "stosd", "stosw", "stosb"):
            repeated = mnemonic.startswith("rep ")
            bits = 32 if mnemonic.endswith("d") else 16 if mnemonic.endswith("w") else 8
            stride = bits // 8
            if repeated:
                return [f"while (ecx) {{ store{bits}(edi, (uint{bits}_t)eax); edi += df ? -{stride} : {stride}; ecx--; }}"]
            return [f"store{bits}(edi, (uint{bits}_t)eax);", f"edi += df ? -{stride} : {stride};"]
        if mnemonic in ("rep movsd", "rep movsw", "rep movsb", "movsd", "movsw", "movsb"):
            repeated = mnemonic.startswith("rep ")
            bits = 32 if mnemonic.endswith("d") else 16 if mnemonic.endswith("w") else 8
            stride = bits // 8
            if repeated:
                return [f"while (ecx) {{ store{bits}(edi, load{bits}(esi)); esi += df ? -{stride} : {stride}; edi += df ? -{stride} : {stride}; ecx--; }}"]
            return [f"store{bits}(edi, load{bits}(esi));", f"esi += df ? -{stride} : {stride};", f"edi += df ? -{stride} : {stride};"]
        if mnemonic in ("repne scasb", "repe scasb", "repz scasb"):
            repeat_while = "!zf" if mnemonic.startswith("repne") else "zf"
            return [f"do {{ if (!ecx) break; a = eax & 0xffu; b = load8(edi); result = (a - b) & 0xffu; flags_sub32(a, b, result, 8u); edi += df ? -1 : 1; ecx--; }} while (ecx && {repeat_while});"]
        if mnemonic in ("repe cmpsb", "repz cmpsb", "repne cmpsb"):
            repeat_while = "!zf" if mnemonic.startswith("repne") else "zf"
            return [f"do {{ if (!ecx) break; a = load8(esi); b = load8(edi); result = (a - b) & 0xffu; flags_sub32(a, b, result, 8u); esi += df ? -1 : 1; edi += df ? -1 : 1; ecx--; }} while (ecx && {repeat_while});"]
        if mnemonic == "fld" and len(operands) == 1:
            value = self._fpu_value(instruction, operands[0])
            return [f"fpu_push({value});"] if value else None
        if mnemonic == "fld1":
            return ["fpu_push(1.0);"]
        if mnemonic == "fldz":
            return ["fpu_push(0.0);"]
        if mnemonic == "fldpi":
            return ["fpu_push(3.14159265358979323846264338327950288);"]
        if mnemonic == "fldln2":
            return ["fpu_push(0.693147180559945309417232121458176568);"]
        if mnemonic == "fild" and len(operands) == 1 and operands[0].type == X86_OP_MEM:
            address = self._address(instruction, operands[0])
            bits = int(operands[0].size) * 8
            if address is None or bits not in (16, 32, 64):
                self._fail(instruction, "fild requires a 16-, 32-, or 64-bit integer")
                return None
            return [f"fpu_push((double)(int{bits}_t)load{bits}({address}));"]
        if mnemonic in ("fst", "fstp") and len(operands) == 1:
            store = self._fpu_store(instruction, operands[0], "fpu[0]")
            if store is None:
                return None
            return [store, "fpu_pop();"] if mnemonic == "fstp" else [store]
        if mnemonic in ("fist", "fistp") and len(operands) == 1 and operands[0].type == X86_OP_MEM:
            address = self._address(instruction, operands[0])
            bits = int(operands[0].size) * 8
            if address is None or bits not in (16, 32, 64):
                self._fail(instruction, "fist requires a 16-, 32-, or 64-bit integer destination")
                return None
            lines = [f"store{bits}({address}, (uint{bits}_t)(int{bits}_t)fpu_round(fpu[0]));"]
            if mnemonic == "fistp":
                lines.append("fpu_pop();")
            return lines
        if mnemonic == "fchs":
            return ["fpu[0] = -fpu[0];"]
        if mnemonic == "fsin":
            return ["fpu[0] = fpu_sin(fpu[0]);"]
        if mnemonic == "fcos":
            return ["fpu[0] = fpu_cos(fpu[0]);"]
        if mnemonic == "fxch" and len(operands) in (1, 2):
            value = self._fpu_value(instruction, operands[-1])
            if value is None or not value.startswith("fpu["):
                self._fail(instruction, "fxch requires an x87 stack register")
                return None
            return [f"fpu_swap({value[4:-1]});"]
        if mnemonic == "frndint":
            return ["fpu[0] = fpu_round(fpu[0]);"]
        if mnemonic in ("fadd", "fsub", "fsubr", "fmul", "fdiv", "fdivr") and len(operands) == 1:
            value = self._fpu_value(instruction, operands[0])
            if value is None:
                return None
            expression = {
                "fadd": f"fpu[0] + ({value})", "fsub": f"fpu[0] - ({value})",
                "fsubr": f"({value}) - fpu[0]", "fmul": f"fpu[0] * ({value})",
                "fdiv": f"fpu[0] / ({value})", "fdivr": f"({value}) / fpu[0]",
            }[mnemonic]
            return [f"fpu[0] = {expression};"]
        if mnemonic in ("fadd", "fsub", "fsubr", "fmul", "fdiv", "fdivr") and len(operands) == 2:
            left = self._fpu_value(instruction, operands[0])
            right = self._fpu_value(instruction, operands[1])
            if left is None or right is None:
                return None
            expression = {
                "fadd": f"({left}) + ({right})", "fsub": f"({left}) - ({right})",
                "fsubr": f"({right}) - ({left})", "fmul": f"({left}) * ({right})",
                "fdiv": f"({left}) / ({right})", "fdivr": f"({right}) / ({left})",
            }[mnemonic]
            store = self._fpu_store(instruction, operands[0], expression)
            return [store] if store else None
        if mnemonic in ("faddp", "fsubp", "fsubrp", "fmulp", "fdivp", "fdivrp") and len(operands) in (1, 2):
            destination = operands[0]
            left = self._fpu_value(instruction, destination)
            right = "fpu[0]" if len(operands) == 1 else self._fpu_value(instruction, operands[1])
            if left is None or right is None:
                return None
            expression = {
                "faddp": f"({left}) + ({right})", "fsubp": f"({left}) - ({right})",
                "fsubrp": f"({right}) - ({left})", "fmulp": f"({left}) * ({right})",
                "fdivp": f"({left}) / ({right})", "fdivrp": f"({right}) / ({left})",
            }[mnemonic]
            store = self._fpu_store(instruction, destination, expression)
            return [store, "fpu_pop();"] if store else None
        if mnemonic in ("fiadd", "fisub", "fisubr", "fimul", "fidiv", "fidivr") and len(operands) == 1 and operands[0].type == X86_OP_MEM:
            address = self._address(instruction, operands[0])
            bits = int(operands[0].size) * 8
            if address is None or bits not in (16, 32):
                self._fail(instruction, f"{mnemonic} requires a 16- or 32-bit integer operand")
                return None
            value = f"(double)(int{bits}_t)load{bits}({address})"
            expression = {
                "fiadd": f"fpu[0] + {value}", "fisub": f"fpu[0] - {value}",
                "fisubr": f"{value} - fpu[0]", "fimul": f"fpu[0] * {value}",
                "fidiv": f"fpu[0] / {value}", "fidivr": f"{value} / fpu[0]",
            }[mnemonic]
            return [f"fpu[0] = {expression};"]
        if mnemonic in ("fcomp", "fcom") and len(operands) == 1:
            value = self._fpu_value(instruction, operands[0])
            if value is None:
                return None
            lines = [f"fpu_compare(fpu[0], {value});"]
            if mnemonic == "fcomp":
                lines.append("fpu_pop();")
            return lines
        if mnemonic == "fnstsw" and len(operands) == 1:
            write = self._write(instruction, operands[0], "fpu_status")
            return [write] if write else None
        if mnemonic == "fnstcw" and len(operands) == 1 and operands[0].type == X86_OP_MEM:
            address = self._address(instruction, operands[0])
            return [f"store16({address}, fpu_control);"] if address else None
        if mnemonic == "fldcw" and len(operands) == 1 and operands[0].type == X86_OP_MEM:
            address = self._address(instruction, operands[0])
            return [f"fpu_control = load16({address});"] if address else None
        if mnemonic == "sahf":
            return ["sf = (eax >> 15) & 1u;", "zf = (eax >> 14) & 1u;", "pf = (eax >> 10) & 1u;", "cf = (eax >> 8) & 1u;"]
        if mnemonic == "wait":
            return []
        if mnemonic == "fnclex":
            return ["fpu_status &= 0xff00u;"]
        if mnemonic in ("pushal", "pusha"):
            return [
                "a = esp;",
                "esp -= 4u; store32(esp, eax);",
                "esp -= 4u; store32(esp, ecx);",
                "esp -= 4u; store32(esp, edx);",
                "esp -= 4u; store32(esp, ebx);",
                "esp -= 4u; store32(esp, a);",
                "esp -= 4u; store32(esp, ebp);",
                "esp -= 4u; store32(esp, esi);",
                "esp -= 4u; store32(esp, edi);",
            ]
        if mnemonic in ("popal", "popa"):
            return [
                "edi = load32(esp); esp += 4u;",
                "esi = load32(esp); esp += 4u;",
                "ebp = load32(esp); esp += 4u;",
                "esp += 4u;",
                "ebx = load32(esp); esp += 4u;",
                "edx = load32(esp); esp += 4u;",
                "ecx = load32(esp); esp += 4u;",
                "eax = load32(esp); esp += 4u;",
            ]
        if mnemonic == "cpuid":
            return [
                "a = eax;",
                "if (a == 0u) { eax = 1u; ebx = 0x756e6547u; edx = 0x49656e69u; ecx = 0x6c65746eu; }",
                "else if (a == 1u) { eax = 0x00000683u; ebx = 0u; ecx = 0u; edx = 0x03808011u; }",
                "else { eax = ebx = ecx = edx = 0u; }",
            ]
        if mnemonic == "rdtsc":
            return [
                "d2_tsc += 1000000000ull;",
                "eax = (uint32_t)d2_tsc;",
                "edx = (uint32_t)(d2_tsc >> 32u);",
            ]
        if mnemonic == "push" and len(operands) == 1:
            value = self._read(instruction, operands[0])
            if value is None:
                return None
            return [f"a = {value[0]};", "esp -= 4u;", "store32(esp, a);"]
        if mnemonic == "pop" and len(operands) == 1:
            write = self._write(instruction, operands[0], "load32(esp)")
            return [write, "esp += 4u;"] if write else None
        if mnemonic == "leave":
            return ["esp = ebp;", "ebp = load32(esp);", "esp += 4u;"]
        self._fail(instruction, "opcode is not implemented by the AOT lifter")
        return None

    def _condition(self, instruction: Any) -> str | None:
        conditions = {
            "je": "zf", "jz": "zf", "jne": "!zf", "jnz": "!zf",
            "ja": "(!cf && !zf)", "jae": "!cf", "jnb": "!cf", "jnc": "!cf",
            "jb": "cf", "jnae": "cf", "jc": "cf", "jbe": "(cf || zf)",
            "jg": "(!zf && sf == of)", "jge": "(sf == of)",
            "jl": "(sf != of)", "jle": "(zf || sf != of)",
            "js": "sf", "jns": "!sf", "jo": "of", "jno": "!of",
            "jp": "pf", "jpe": "pf", "jnp": "!pf", "jpo": "!pf",
            "jecxz": "ecx == 0",
        }
        result = conditions.get(instruction.mnemonic)
        if result is None:
            self._fail(instruction, "conditional branch is not implemented")
        return result

    def _intrinsic_import(self, key: str) -> list[str] | None:
        normalized = key.lower()
        if normalized == "crtdll.dll!_cipow":
            return ["fpu[1] = fpu_integer_pow(fpu[1], fpu[0]);", "fpu_pop();"]
        if normalized == "crtdll.dll!_ftol":
            return [
                "wide_result = (int64_t)fpu[0];",
                "eax = (uint32_t)(uint64_t)wide_result;",
                "edx = (uint32_t)((uint64_t)wide_result >> 32u);",
                "fpu_pop();",
            ]
        return None

    @staticmethod
    def _modeled_eflag_access(instruction: Any) -> tuple[int, int]:
        eflags = int(getattr(instruction, "eflags", 0))
        reads = 0
        writes = 0
        for index, (read_mask, write_mask) in enumerate(_MODELED_EFLAG_ACCESS):
            flag = 1 << index
            if eflags & read_mask:
                reads |= flag
            if instruction.mnemonic in _OPTIONAL_FLAG_MNEMONICS and eflags & write_mask:
                writes |= flag
        return reads, writes

    def _block_flag_requirements(self, block: Block) -> dict[int, bool]:
        # Flags crossing a basic-block boundary remain conservatively live.
        # Within a block, however, an unconditional arithmetic writer can
        # prove earlier flag results dead before any instruction observes them.
        live = _ALL_MODELED_EFLAGS
        requirements: dict[int, bool] = {}
        for instruction in reversed(block.instructions):
            reads, writes = self._modeled_eflag_access(instruction)
            requirements[int(instruction.address)] = not writes or bool(writes & live)
            live = (live & ~writes) | reads
        return requirements

    def _emit_block(self, block: Block) -> list[str]:
        lines = [f"case 0x{self._pc(block.rva):08x}u:"]
        body = block.instructions[:-1] if block.terminator in CONTROL_TERMINATORS else block.instructions
        flag_requirements = self._block_flag_requirements(block)
        for instruction in body:
            lifted = self.lift_instruction(
                instruction,
                emit_flags=flag_requirements.get(int(instruction.address), True),
            )
            if lifted is None:
                lines.extend(["  d2_status = D2_STATUS_UNSUPPORTED;", "  return D2_ACTION_RETURN;"])
                return lines
            lines.extend(f"  {line}" for line in lifted)

        if block.unsupported_reason:
            instruction = block.instructions[-1] if block.instructions else None
            if instruction is not None and block.terminator not in ("indirect_call", "indirect_jump"):
                self._fail(instruction, block.unsupported_reason)

        if block.terminator == "ret":
            instruction = block.instructions[-1]
            adjustment = 0
            if instruction.operands:
                adjustment = int(instruction.operands[0].imm) & 0xFFFF
            lines += [
                "  d2_next_pc = load32(esp);",
                f"  esp += {4 + adjustment}u;",
                "  if (d2_next_pc == D2_RETURN_SENTINEL) { d2_status = D2_STATUS_OK; return D2_ACTION_RETURN; }",
                "  D2_CHAIN();",
            ]
        elif block.terminator == "call":
            target, fallthrough = block.successors
            lines += ["  esp -= 4u;", f"  store32(esp, 0x{self._pc(fallthrough):08x}u);", f"  d2_next_pc = 0x{self._pc(target):08x}u;", "  D2_CHAIN();"]
        elif block.terminator == "jump":
            lines += [f"  d2_next_pc = 0x{self._pc(block.successors[0]):08x}u;", "  D2_CHAIN();"]
        elif block.terminator == "fallthrough" and block.successors:
            lines += [f"  d2_next_pc = 0x{self._pc(block.successors[0]):08x}u;", "  D2_CHAIN();"]
        elif block.terminator == "jump_table":
            instruction = block.instructions[-1]
            address = self._address(instruction, instruction.operands[0])
            if address is None:
                lines += ["  d2_status = D2_STATUS_UNSUPPORTED;", "  return D2_ACTION_RETURN;"]
            else:
                lines += [f"  d2_next_pc = {self._dynamic_pc(f'load32({address})')};", "  D2_CHAIN();"]
        elif block.terminator == "conditional":
            condition = self._condition(block.instructions[-1])
            if condition is None:
                lines += ["  d2_status = D2_STATUS_UNSUPPORTED;", "  return D2_ACTION_RETURN;"]
            else:
                target, fallthrough = block.successors
                lines += [f"  d2_next_pc = ({condition}) ? 0x{self._pc(target):08x}u : 0x{self._pc(fallthrough):08x}u;", "  D2_CHAIN();"]
        elif block.terminator == "import_call":
            assert block.imported_call is not None
            key = block.imported_call.display_name
            spec = self.api_specs.get(key)
            internal_target = self.internal_targets.get(key)
            intrinsic = self._intrinsic_import(key)
            if key.lower() == "dsound.dll!#2":
                lines += [
                    "  a = load32(esp);",
                    "  esp -= 12u;",
                    f"  store32(esp, 0x{self._pc(block.successors[0]):08x}u);",
                    "  store32(esp + 4u, 0u);",
                    "  store32(esp + 8u, (uint32_t)(uintptr_t)d2_dsound_description);",
                    "  store32(esp + 12u, (uint32_t)(uintptr_t)d2_dsound_module);",
                    "  d2_next_pc = a;",
                    "  D2_CHAIN();",
                ]
            elif intrinsic is not None:
                lines.extend(f"  {line}" for line in intrinsic)
                lines += [f"  d2_next_pc = 0x{self._pc(block.successors[0]):08x}u;", "  D2_CHAIN();"]
            elif internal_target is not None:
                lines += [
                    "  esp -= 4u;",
                    f"  store32(esp, 0x{self._pc(block.successors[0]):08x}u);",
                    f"  d2_next_pc = 0x{internal_target:08x}u;",
                    "  D2_CHAIN();",
                ]
            elif spec is None:
                instruction = block.instructions[-1]
                self._fail(instruction, f"direct API adapter required for {key}")
                lines += ["  d2_status = D2_STATUS_UNSUPPORTED;", "  return D2_ACTION_RETURN;"]
            else:
                function = "api_" + safe_module_name(spec.library + "_" + spec.name).replace(".", "_").replace("-", "_")
                self.used_apis[key] = spec
                lines.append(f"  eax = {function}(esp);")
                if spec.convention == "stdcall" and spec.arg_bytes:
                    lines.append(f"  esp += {spec.arg_bytes}u;")
                if spec.no_return:
                    lines += ["  d2_status = D2_STATUS_OK;", "  return D2_ACTION_RETURN;"]
                else:
                    lines += [
                        f"  d2_next_pc = 0x{self._pc(block.successors[0]):08x}u;",
                        "  D2_YIELD_CHAIN();",
                        "  D2_CHAIN();",
                    ]
        elif block.terminator == "import_jump":
            assert block.imported_call is not None
            key = block.imported_call.display_name
            spec = self.api_specs.get(key)
            internal_target = self.internal_targets.get(key)
            intrinsic = self._intrinsic_import(key)
            if key.lower() == "dsound.dll!#2":
                lines += [
                    "  a = load32(esp + 4u);",
                    "  store32(esp - 8u, load32(esp));",
                    "  store32(esp - 4u, 0u);",
                    "  store32(esp, (uint32_t)(uintptr_t)d2_dsound_description);",
                    "  store32(esp + 4u, (uint32_t)(uintptr_t)d2_dsound_module);",
                    "  esp -= 8u;",
                    "  d2_next_pc = a;",
                    "  D2_CHAIN();",
                ]
            elif intrinsic is not None:
                lines.extend(f"  {line}" for line in intrinsic)
                lines += [
                    "  d2_next_pc = load32(esp);",
                    "  esp += 4u;",
                    "  if (d2_next_pc == D2_RETURN_SENTINEL) { d2_status = D2_STATUS_OK; return D2_ACTION_RETURN; }",
                    "  D2_CHAIN();",
                ]
            elif internal_target is not None:
                lines += [
                    f"  d2_next_pc = 0x{internal_target:08x}u;",
                    "  D2_CHAIN();",
                ]
            elif spec is None:
                instruction = block.instructions[-1]
                self._fail(instruction, f"direct API adapter required for {key}")
                lines += ["  d2_status = D2_STATUS_UNSUPPORTED;", "  return D2_ACTION_RETURN;"]
            else:
                function = "api_" + safe_module_name(spec.library + "_" + spec.name).replace(".", "_").replace("-", "_")
                self.used_apis[key] = spec
                lines.append(f"  eax = {function}(esp + 4u);")
                cleanup = spec.arg_bytes if spec.convention == "stdcall" else 0
                lines += [
                    "  d2_next_pc = load32(esp);",
                    f"  esp += {4 + cleanup}u;",
                    "  if (d2_next_pc == D2_RETURN_SENTINEL) { d2_status = D2_STATUS_OK; return D2_ACTION_RETURN; }",
                    "  D2_YIELD_CHAIN();",
                    "  D2_CHAIN();",
                ]
        elif block.terminator in ("indirect_call", "indirect_jump"):
            instruction = block.instructions[-1]
            target = self._read(instruction, instruction.operands[0])
            if target is None or target[1] != 32:
                self._fail(instruction, "indirect control target is not a 32-bit operand")
                lines += ["  d2_status = D2_STATUS_UNSUPPORTED;", "  return D2_ACTION_RETURN;"]
            else:
                lines.append(f"  a = {target[0]};")
                if block.terminator == "indirect_call":
                    lines += ["  esp -= 4u;", f"  store32(esp, 0x{self._pc(block.successors[0]):08x}u);"]
                lines += [f"  d2_next_pc = {self._dynamic_pc('a')};", "  D2_CHAIN();"]
        else:
            reason = block.unsupported_reason or f"unexpected terminator {block.terminator}"
            if block.instructions:
                self._fail(block.instructions[-1], reason)
            lines += ["  d2_status = D2_STATUS_UNSUPPORTED;", "  return D2_ACTION_RETURN;"]
        return lines

    def generate(self) -> str:
        pages: dict[int, list[str]] = {}
        for rva in sorted(self.blocks):
            pages.setdefault(self._pc(rva) >> 12, []).extend(self._emit_block(self.blocks[rva]))
        return _render_c(pages, self.used_apis)


class LinkedCGenerator:
    def __init__(self, units: list[CGenerator]):
        self.units = units

    @property
    def unsupported(self) -> list[UnsupportedSite]:
        return [site for unit in self.units for site in unit.unsupported]

    def generate(self) -> str:
        pages: dict[int, list[str]] = {}
        used_apis: dict[str, ApiSpec] = {}
        for unit in self.units:
            for rva in sorted(unit.blocks):
                pages.setdefault(unit._pc(rva) >> 12, []).extend(unit._emit_block(unit.blocks[rva]))
            used_apis.update(unit.used_apis)
        return _render_c(pages, used_apis)


def _render_c(pages: dict[int, list[str]], used_apis: dict[str, ApiSpec]) -> str:
    shards = []
    page_dispatch = []
    for page, cases in sorted(pages.items()):
        case_text = "\n".join("    " + line for line in cases)
        shards.append(
            "#define D2_CHAIN() do { "
            f"if (!*block_fuel || (d2_next_pc >> 12) != 0x{page:05x}u) "
            "return D2_ACTION_CONTINUE; "
            "pc = d2_next_pc; goto d2_page_dispatch; } while (0)\n"
            "#define D2_YIELD_CHAIN() do { "
            "if (d2_yield_requested) return D2_ACTION_CONTINUE; "
            "} while (0)\n"
            "__attribute__((noinline))\n"
            f"static uint32_t d2_page_{page:05x}(uint32_t pc, uint32_t *block_fuel) {{\n"
            "  uint32_t a = 0, b = 0, result = 0, old_cf = 0;\n"
            "  int64_t wide_result = 0, signed_divisor = 0, signed_quotient = 0, signed_remainder = 0;\n"
            "  uint64_t wide_unsigned = 0;\n"
            "d2_page_dispatch:\n"
            "  D2_BEGIN_BLOCK(pc, block_fuel);\n"
            "  switch (pc) {\n"
            f"{case_text}\n"
            "    default: d2_status = D2_STATUS_MISSING_BLOCK; return D2_ACTION_RETURN;\n"
            "  }\n"
            "}\n"
            "#undef D2_YIELD_CHAIN\n"
            "#undef D2_CHAIN\n"
        )
        page_dispatch.append(
            f"      case 0x{page:05x}u: action = d2_page_{page:05x}(pc, block_fuel); break;"
        )
    imports = []
    host_thunk_dispatch = []
    thunk_keys: dict[int, str] = {}
    for spec in sorted(used_apis.values(), key=lambda value: value.key):
        function = "api_" + safe_module_name(spec.library + "_" + spec.name).replace(".", "_").replace("-", "_")
        imports.append(
            f'__attribute__((import_module("win32.{spec.library.lower()}"), import_name("{spec.name}"))) '
            f'extern uint32_t {function}(uint32_t);'
        )
        thunk_pc = host_thunk_pc(spec.key)
        collision = thunk_keys.get(thunk_pc)
        if collision is not None and collision != spec.key:
            raise ValueError(
                f"host thunk collision at 0x{thunk_pc:08x}: {collision} and {spec.key}"
            )
        thunk_keys[thunk_pc] = spec.key
        cleanup = spec.arg_bytes if spec.convention == "stdcall" else 0
        lines = [
            f"  if (pc == 0x{thunk_pc:08x}u) {{",
            "    uint32_t return_pc = load32(esp);",
            f"    eax = {function}(esp + 4u);",
        ]
        if spec.no_return:
            lines += [
                "    d2_status = D2_STATUS_OK;",
                "    return D2_ACTION_RETURN;",
            ]
        else:
            lines += [
                f"    esp += {4 + cleanup}u;",
                "    d2_next_pc = return_pc;",
                "    if (return_pc == D2_RETURN_SENTINEL) { d2_status = D2_STATUS_OK; return D2_ACTION_RETURN; }",
                "    return D2_ACTION_CONTINUE;",
            ]
        lines.append("  }")
        host_thunk_dispatch.extend(lines)
    has_dsound = any(key.lower() == "dsound.dll!#1" for key in used_apis)
    dsound_import = (
        '__attribute__((import_module("win32.dsound.dll"), import_name("__dispatch"))) '
        'extern uint32_t api_dsound_dispatch(uint32_t, uint32_t);'
        if has_dsound else ""
    )
    dsound_helpers = r'''
#define D2_DSOUND_PC_BASE 0xfffe0000u
static uint32_t d2_dsound_arg_bytes(uint32_t method) {
  static const uint8_t direct_sound[] = { 12, 4, 4, 16, 8, 12, 12, 4, 8, 8, 8 };
  static const uint8_t sound_buffer[] = { 12, 4, 4, 8, 12, 16, 8, 8, 8, 8, 12, 32, 16, 8, 8, 8, 8, 8, 4, 20, 4 };
  if (method < sizeof(direct_sound)) return direct_sound[method];
  if (method >= 32u && method - 32u < sizeof(sound_buffer)) return sound_buffer[method - 32u];
  return 4u;
}
''' if has_dsound else ""
    dsound_dispatch = r'''
  if (pc >= D2_DSOUND_PC_BASE && pc < D2_DSOUND_PC_BASE + 53u * 4u) {
    uint32_t method = (pc - D2_DSOUND_PC_BASE) / 4u;
    uint32_t return_pc = load32(esp);
    eax = api_dsound_dispatch(method, esp + 4u);
    esp += 4u + d2_dsound_arg_bytes(method);
    d2_next_pc = return_pc;
    if (return_pc == D2_RETURN_SENTINEL) { d2_status = D2_STATUS_OK; return D2_ACTION_RETURN; }
    return D2_ACTION_CONTINUE;
  }
''' if has_dsound else ""
    return (
        C_TEMPLATE.replace("@IMPORTS@", "\n".join(imports))
        .replace("@HOST_THUNK_BASE@", f"{HOST_THUNK_BASE:08x}")
        .replace("@HOST_THUNK_DISPATCH@", "\n".join(host_thunk_dispatch))
        .replace("@DSOUND_IMPORT@", dsound_import)
        .replace("@DSOUND_HELPERS@", dsound_helpers)
        .replace("@DSOUND_DISPATCH@", dsound_dispatch)
        .replace("@SHARDS@", "\n".join(shards))
        .replace("@PAGE_DISPATCH@", "\n".join(page_dispatch))
    )


C_TEMPLATE = r'''#include <stdint.h>

@IMPORTS@
@DSOUND_IMPORT@

enum {
  D2_STATUS_OK = 0,
  D2_STATUS_FUEL_EXHAUSTED = 1,
  D2_STATUS_MISSING_BLOCK = 2,
  D2_STATUS_UNSUPPORTED = 3,
  D2_STATUS_ARITHMETIC_TRAP = 4,
  D2_STATUS_YIELDED = 5
};
enum { D2_ACTION_CONTINUE = 0, D2_ACTION_RETURN = 1 };
#define D2_RETURN_SENTINEL 0xffffffffu

static uint32_t d2_status, d2_last_pc, d2_previous_pc, d2_next_pc;
static uint64_t d2_tsc;
static const char d2_dsound_description[] = "D2Wasm DirectSound";
static const char d2_dsound_module[] = "dsound.dll";
enum { D2_TRACE_CAPACITY = 16384u, D2_TRACE_MASK = D2_TRACE_CAPACITY - 1u };
static uint32_t d2_trace_pc[D2_TRACE_CAPACITY], d2_trace_esp[D2_TRACE_CAPACITY], d2_trace_index;
static uint32_t d2_diagnostics_enabled;
static uint32_t d2_watch_pc, d2_watch_hit, d2_watch_registers[8], d2_stop_on_watch, d2_watch_skip;
static uint32_t d2_count_pc, d2_count_hits;
static uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp, fs_base;
static uint32_t zf, sf, cf, of, pf, df;
static double fpu[8];
static uint32_t fpu_depth;
static uint16_t fpu_status;
static uint16_t fpu_control;
static volatile uint32_t d2_yield_requested;

typedef struct {
  uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp, fs_base;
  uint32_t zf, sf, cf, of, pf, df;
  double fpu[8];
  uint32_t fpu_depth;
  uint16_t fpu_status, fpu_control;
} D2CpuState;

typedef struct {
  uint32_t initialized, finished, status;
  uint32_t next_pc, last_pc, previous_pc;
  uint32_t watch_hit, watch_registers[8];
  D2CpuState cpu;
} D2ThreadContext;

static inline void d2_capture_cpu(D2CpuState *state) {
  state->eax = eax; state->ebx = ebx; state->ecx = ecx; state->edx = edx;
  state->esi = esi; state->edi = edi; state->ebp = ebp; state->esp = esp;
  state->fs_base = fs_base;
  state->zf = zf; state->sf = sf; state->cf = cf; state->of = of;
  state->pf = pf; state->df = df;
  for (uint32_t index = 0; index < 8; index++) state->fpu[index] = fpu[index];
  state->fpu_depth = fpu_depth; state->fpu_status = fpu_status;
  state->fpu_control = fpu_control;
}

static inline void d2_restore_cpu(const D2CpuState *state) {
  eax = state->eax; ebx = state->ebx; ecx = state->ecx; edx = state->edx;
  esi = state->esi; edi = state->edi; ebp = state->ebp; esp = state->esp;
  fs_base = state->fs_base;
  zf = state->zf; sf = state->sf; cf = state->cf; of = state->of;
  pf = state->pf; df = state->df;
  for (uint32_t index = 0; index < 8; index++) fpu[index] = state->fpu[index];
  fpu_depth = state->fpu_depth; fpu_status = state->fpu_status;
  fpu_control = state->fpu_control;
}

static inline uint8_t load8(uint32_t p) { return *(uint8_t *)(uintptr_t)p; }
static inline uint16_t load16(uint32_t p) { return *(uint16_t *)(uintptr_t)p; }
static inline uint32_t load32(uint32_t p) { return *(uint32_t *)(uintptr_t)p; }
static inline uint64_t load64(uint32_t p) { return *(uint64_t *)(uintptr_t)p; }
static inline void store8(uint32_t p, uint8_t v) { *(uint8_t *)(uintptr_t)p = v; }
static inline void store16(uint32_t p, uint16_t v) { *(uint16_t *)(uintptr_t)p = v; }
static inline void store32(uint32_t p, uint32_t v) { *(uint32_t *)(uintptr_t)p = v; }
static inline void store64(uint32_t p, uint64_t v) { *(uint64_t *)(uintptr_t)p = v; }
static inline float load_f32(uint32_t p) { return *(float *)(uintptr_t)p; }
static inline double load_f64(uint32_t p) { return *(double *)(uintptr_t)p; }
static inline void store_f32(uint32_t p, float v) { *(float *)(uintptr_t)p = v; }
static inline void store_f64(uint32_t p, double v) { *(double *)(uintptr_t)p = v; }
static inline void fpu_push(double value) {
  for (uint32_t index = 7; index; index--) fpu[index] = fpu[index - 1];
  fpu[0] = value; if (fpu_depth < 8) fpu_depth++;
}
static inline void fpu_pop(void) {
  for (uint32_t index = 0; index < 7; index++) fpu[index] = fpu[index + 1];
  if (fpu_depth) fpu_depth--;
}
static inline void fpu_swap(uint32_t index) {
  double temporary = fpu[0]; fpu[0] = fpu[index]; fpu[index] = temporary;
}
static inline double fpu_integer_pow(double base, double exponent) {
  int64_t signed_exponent = (int64_t)exponent;
  if ((double)signed_exponent != exponent) return 0.0;
  uint64_t remaining = signed_exponent < 0 ? (uint64_t)(-(signed_exponent + 1)) + 1u : (uint64_t)signed_exponent;
  double result = 1.0;
  while (remaining) {
    if (remaining & 1u) result *= base;
    base *= base;
    remaining >>= 1u;
  }
  return signed_exponent < 0 ? 1.0 / result : result;
}
static inline double fpu_sin(double value) {
  const double pi = 3.14159265358979323846264338327950288;
  const double half_pi = 1.57079632679489661923132169163975144;
  const double two_pi = 6.28318530717958647692528676655900576;
  int64_t turns = (int64_t)(value / two_pi);
  value -= (double)turns * two_pi;
  if (value > pi) value -= two_pi;
  else if (value < -pi) value += two_pi;
  if (value > half_pi) value = pi - value;
  else if (value < -half_pi) value = -pi - value;
  double square = value * value;
  return value * (1.0 + square * (-1.0 / 6.0 + square * (1.0 / 120.0
    + square * (-1.0 / 5040.0 + square * (1.0 / 362880.0
    + square * (-1.0 / 39916800.0 + square * (1.0 / 6227020800.0)))))));
}
static inline double fpu_cos(double value) {
  return fpu_sin(value + 1.57079632679489661923132169163975144);
}
static inline double fpu_round(double value) {
  switch ((fpu_control >> 10u) & 3u) {
    case 0: return __builtin_nearbyint(value);
    case 1: return __builtin_floor(value);
    case 2: return __builtin_ceil(value);
    default: return __builtin_trunc(value);
  }
}
static inline void fpu_compare(double left, double right) {
  fpu_status &= ~(0x0100u | 0x0400u | 0x4000u);
  if (left != left || right != right) fpu_status |= 0x4500u;
  else if (left < right) fpu_status |= 0x0100u;
  else if (left == right) fpu_status |= 0x4000u;
}
static inline uint32_t parity8(uint32_t value) {
  value ^= value >> 4; value &= 15u; return (0x6996u >> value) & 1u ? 0u : 1u;
}
static inline uint32_t width_mask(uint32_t bits) { return bits == 32u ? 0xffffffffu : ((1u << bits) - 1u); }
static inline void flags_result32(uint32_t result, uint32_t bits) {
  uint32_t sign = 1u << (bits - 1u);
  result &= width_mask(bits); zf = result == 0; sf = (result & sign) != 0; pf = parity8(result);
}
static inline void flags_add32(uint32_t a, uint32_t b, uint32_t result, uint32_t bits) {
  uint32_t mask = width_mask(bits), sign = 1u << (bits - 1u);
  a &= mask; b &= mask; result &= mask; flags_result32(result, bits);
  cf = ((uint64_t)a + (uint64_t)b) > mask; of = ((~(a ^ b) & (a ^ result)) & sign) != 0;
}
static inline void flags_sub32(uint32_t a, uint32_t b, uint32_t result, uint32_t bits) {
  uint32_t mask = width_mask(bits), sign = 1u << (bits - 1u);
  a &= mask; b &= mask; result &= mask; flags_result32(result, bits);
  cf = a < b; of = (((a ^ b) & (a ^ result)) & sign) != 0;
}
static inline void flags_logic32(uint32_t result, uint32_t bits) { flags_result32(result, bits); cf = 0; of = 0; }
static inline void flags_inc(uint32_t a, uint32_t result, uint32_t bits) {
  uint32_t old_cf = cf; flags_add32(a, 1u, result, bits); cf = old_cf;
}
static inline void flags_dec(uint32_t a, uint32_t result, uint32_t bits) {
  uint32_t old_cf = cf; flags_sub32(a, 1u, result, bits); cf = old_cf;
}

@DSOUND_HELPERS@
static inline void flags_adc(uint32_t a, uint32_t b, uint32_t result, uint32_t carry, uint32_t bits) {
  uint32_t mask = width_mask(bits), effective = (b + carry) & mask, sign = 1u << (bits - 1u);
  flags_result32(result, bits); cf = ((uint64_t)(a & mask) + (uint64_t)(b & mask) + carry) > mask;
  of = ((~(a ^ effective) & (a ^ result)) & sign) != 0;
}
static inline void flags_sbb(uint32_t a, uint32_t b, uint32_t result, uint32_t borrow, uint32_t bits) {
  uint32_t mask = width_mask(bits), effective = (b + borrow) & mask, sign = 1u << (bits - 1u);
  flags_result32(result, bits); cf = (uint64_t)(a & mask) < (uint64_t)(b & mask) + borrow;
  of = (((a ^ effective) & (a ^ result)) & sign) != 0;
}
enum { SHIFT_LEFT = 0, SHIFT_RIGHT = 1, SHIFT_ARITH = 2 };
static inline uint32_t shift_value(uint32_t value, uint32_t count, uint32_t bits, uint32_t operation) {
  uint32_t mask = width_mask(bits), sign = 1u << (bits - 1u), result = value & mask;
  if (!count) return result;
  if (count <= bits) {
    cf = operation == SHIFT_LEFT ? ((result >> (bits - count)) & 1u) : ((result >> (count - 1u)) & 1u);
  }
  if (operation == SHIFT_LEFT) result = (result << count) & mask;
  else if (operation == SHIFT_RIGHT) result >>= count;
  else {
    int32_t signed_value = bits == 32u ? (int32_t)result : (int32_t)(result | ((result & sign) ? ~mask : 0u));
    result = ((uint32_t)(signed_value >> count)) & mask;
  }
  flags_result32(result, bits);
  if (count == 1u) {
    if (operation == SHIFT_LEFT) of = ((result & sign) != 0) ^ cf;
    else if (operation == SHIFT_RIGHT) of = (value & sign) != 0;
    else of = 0;
  }
  return result;
}
enum { ROTATE_LEFT = 0, ROTATE_RIGHT = 1, ROTATE_CARRY_LEFT = 2, ROTATE_CARRY_RIGHT = 3 };
static inline uint32_t rotate_value(uint32_t value, uint32_t count, uint32_t bits, uint32_t operation) {
  uint32_t mask = width_mask(bits), sign = 1u << (bits - 1u), result = value & mask;
  count &= 31u;
  if (operation >= ROTATE_CARRY_LEFT) count %= bits + 1u;
  else count %= bits;
  if (!count) return result;
  uint32_t effective_count = count;
  if (operation == ROTATE_LEFT) {
    result = ((result << count) | (result >> (bits - count))) & mask;
    cf = result & 1u;
  } else if (operation == ROTATE_RIGHT) {
    result = ((result >> count) | (result << (bits - count))) & mask;
    cf = (result >> (bits - 1u)) & 1u;
  } else {
    while (count--) {
      uint32_t old_cf = cf;
      if (operation == ROTATE_CARRY_LEFT) {
        cf = (result >> (bits - 1u)) & 1u;
        result = ((result << 1u) | old_cf) & mask;
      } else {
        cf = result & 1u;
        result = (result >> 1u) | (old_cf << (bits - 1u));
      }
    }
  }
  if (effective_count == 1u) {
    if (operation == ROTATE_LEFT || operation == ROTATE_CARRY_LEFT) of = ((result & sign) != 0) ^ cf;
    else of = ((result >> (bits - 1u)) ^ (result >> (bits - 2u))) & 1u;
  }
  return result;
}

#define D2_BEGIN_BLOCK(pc_value, fuel_pointer) do { \
  if (!*(fuel_pointer)) return D2_ACTION_CONTINUE; \
  (*(fuel_pointer))--; \
  uint32_t d2_current_pc = (pc_value); \
  d2_previous_pc = d2_last_pc; \
  d2_last_pc = d2_current_pc; \
  if (__builtin_expect(d2_diagnostics_enabled, 0)) { \
    d2_trace_pc[d2_trace_index & D2_TRACE_MASK] = d2_current_pc; \
    d2_trace_esp[d2_trace_index & D2_TRACE_MASK] = esp; \
    d2_trace_index++; \
    if (d2_current_pc == d2_count_pc) d2_count_hits++; \
    if (!d2_watch_hit && d2_current_pc == d2_watch_pc) { \
      if (d2_watch_skip) { d2_watch_skip--; } \
      else { \
        d2_watch_hit = 1; \
        d2_watch_registers[0] = eax; d2_watch_registers[1] = ebx; \
        d2_watch_registers[2] = ecx; d2_watch_registers[3] = edx; \
        d2_watch_registers[4] = esi; d2_watch_registers[5] = edi; \
        d2_watch_registers[6] = ebp; d2_watch_registers[7] = esp; \
        if (d2_stop_on_watch) { \
          d2_status = D2_STATUS_YIELDED; \
          return D2_ACTION_RETURN; \
        } \
      } \
    } \
  } \
} while (0)

@SHARDS@

__attribute__((noinline))
static uint32_t d2_dispatch_block(uint32_t pc, uint32_t *block_fuel) {
  for (;;) {
    if (pc >= 0x@HOST_THUNK_BASE@u) {
      D2_BEGIN_BLOCK(pc, block_fuel);
@DSOUND_DISPATCH@
@HOST_THUNK_DISPATCH@
      d2_status = D2_STATUS_MISSING_BLOCK;
      return D2_ACTION_RETURN;
    }
    uint32_t action;
    switch (pc >> 12) {
@PAGE_DISPATCH@
      default: d2_status = D2_STATUS_MISSING_BLOCK; return D2_ACTION_RETURN;
    }
    if (action == D2_ACTION_RETURN || d2_yield_requested || !*block_fuel) {
      return action;
    }
    pc = d2_next_pc;
  }
}

static void d2_initialize_cpu(uint32_t entry_rva, uint32_t initial_esp) {
  eax = ebx = ecx = edx = esi = edi = ebp = 0;
  zf = sf = cf = of = pf = df = 0;
  fpu_depth = 0; fpu_status = 0; fpu_control = 0x037fu;
  esp = initial_esp;
  esp -= 4u;
  store32(esp, D2_RETURN_SENTINEL);
  d2_status = D2_STATUS_OK;
  d2_next_pc = entry_rva;
  d2_trace_index = 0;
  d2_watch_hit = 0;
  d2_yield_requested = 0;
}

__attribute__((noinline))
static uint32_t d2_execute(uint32_t block_fuel) {
  while (block_fuel) {
    if (d2_dispatch_block(d2_next_pc, &block_fuel) == D2_ACTION_RETURN) return eax;
    if (d2_yield_requested) {
      d2_status = D2_STATUS_YIELDED;
      return eax;
    }
  }
  d2_status = D2_STATUS_FUEL_EXHAUSTED;
  return eax;
}

__attribute__((export_name("d2_run")))
uint32_t d2_run(uint32_t entry_rva, uint32_t initial_esp, uint32_t block_fuel) {
  d2_initialize_cpu(entry_rva, initial_esp);
  return d2_execute(block_fuel);
}

static uint32_t d2_invoke_status;

__attribute__((export_name("d2_invoke_current")))
uint32_t d2_invoke_current(uint32_t entry_rva, uint32_t arguments,
                           uint32_t argument_count, uint32_t block_fuel) {
  uint32_t outer_esp = esp;
  uint32_t outer_status = d2_status, outer_last_pc = d2_last_pc;
  uint32_t outer_previous_pc = d2_previous_pc, outer_next_pc = d2_next_pc;
  uint32_t outer_yield_requested = d2_yield_requested;
  while (argument_count) {
    argument_count--;
    esp -= 4u;
    store32(esp, load32(arguments + argument_count * 4u));
  }
  esp -= 4u;
  store32(esp, D2_RETURN_SENTINEL);
  d2_status = D2_STATUS_OK;
  d2_next_pc = entry_rva;
  d2_yield_requested = 0;
  uint32_t result = d2_execute(block_fuel);
  d2_invoke_status = d2_status;
  esp = outer_esp;
  d2_status = outer_status; d2_last_pc = outer_last_pc;
  d2_previous_pc = outer_previous_pc; d2_next_pc = outer_next_pc;
  d2_yield_requested = outer_yield_requested;
  return result;
}

__attribute__((export_name("d2_invoke_status")))
uint32_t d2_get_invoke_status(void) { return d2_invoke_status; }

__attribute__((export_name("d2_run_context")))
uint32_t d2_run_context(uint32_t context_pointer, uint32_t entry_rva,
                        uint32_t initial_esp, uint32_t block_fuel) {
  D2ThreadContext *context = (D2ThreadContext *)(uintptr_t)context_pointer;
  D2CpuState outer_cpu;
  d2_capture_cpu(&outer_cpu);
  uint32_t outer_status = d2_status, outer_last_pc = d2_last_pc;
  uint32_t outer_previous_pc = d2_previous_pc, outer_next_pc = d2_next_pc;
  uint32_t outer_trace_index = d2_trace_index, outer_watch_hit = d2_watch_hit;
  uint32_t outer_watch_registers[8];
  for (uint32_t index = 0; index < 8; index++) outer_watch_registers[index] = d2_watch_registers[index];
  uint32_t outer_yield_requested = d2_yield_requested;

  if (!context->initialized) {
    d2_initialize_cpu(entry_rva, initial_esp);
    context->initialized = 1;
    context->finished = 0;
    context->watch_hit = 0;
  } else {
    d2_restore_cpu(&context->cpu);
    d2_status = D2_STATUS_OK;
    d2_next_pc = context->next_pc;
    d2_last_pc = context->last_pc;
    d2_previous_pc = context->previous_pc;
    d2_trace_index = 0;
    d2_watch_hit = context->watch_hit;
    for (uint32_t index = 0; index < 8; index++) d2_watch_registers[index] = context->watch_registers[index];
    d2_yield_requested = 0;
  }
  uint32_t result = d2_execute(block_fuel);
  d2_capture_cpu(&context->cpu);
  context->status = d2_status;
  context->next_pc = d2_next_pc;
  context->last_pc = d2_last_pc;
  context->previous_pc = d2_previous_pc;
  context->watch_hit = d2_watch_hit;
  for (uint32_t index = 0; index < 8; index++) context->watch_registers[index] = d2_watch_registers[index];
  if (d2_status != D2_STATUS_YIELDED && d2_status != D2_STATUS_FUEL_EXHAUSTED) {
    context->finished = 1;
  }

  d2_restore_cpu(&outer_cpu);
  d2_status = outer_status; d2_last_pc = outer_last_pc;
  d2_previous_pc = outer_previous_pc; d2_next_pc = outer_next_pc;
  d2_trace_index = outer_trace_index; d2_watch_hit = outer_watch_hit;
  for (uint32_t index = 0; index < 8; index++) d2_watch_registers[index] = outer_watch_registers[index];
  d2_yield_requested = outer_yield_requested;
  return result;
}

__attribute__((export_name("d2_request_yield")))
void d2_request_yield(void) { d2_yield_requested = 1; }

__attribute__((export_name("d2_context_status")))
uint32_t d2_context_status(uint32_t context_pointer) {
  return ((D2ThreadContext *)(uintptr_t)context_pointer)->status;
}

__attribute__((export_name("d2_context_finished")))
uint32_t d2_context_finished(uint32_t context_pointer) {
  return ((D2ThreadContext *)(uintptr_t)context_pointer)->finished;
}

__attribute__((export_name("d2_context_watch_hit")))
uint32_t d2_context_watch_hit(uint32_t context_pointer) {
  return ((D2ThreadContext *)(uintptr_t)context_pointer)->watch_hit;
}

__attribute__((export_name("d2_context_watch_register")))
uint32_t d2_context_watch_register(uint32_t context_pointer, uint32_t index) {
  D2ThreadContext *context = (D2ThreadContext *)(uintptr_t)context_pointer;
  return index < 8u ? context->watch_registers[index] : 0u;
}

__attribute__((export_name("d2_last_status")))
uint32_t d2_last_status(void) { return d2_status; }

__attribute__((export_name("d2_last_rva")))
uint32_t d2_last_rva(void) { return d2_last_pc; }

__attribute__((export_name("d2_previous_rva")))
uint32_t d2_previous_rva(void) { return d2_previous_pc; }

__attribute__((export_name("d2_trace_count")))
uint32_t d2_trace_count(void) {
  return d2_trace_index < D2_TRACE_CAPACITY ? d2_trace_index : D2_TRACE_CAPACITY;
}

__attribute__((export_name("d2_trace_pc")))
uint32_t d2_get_trace_pc(uint32_t back) {
  return d2_trace_pc[(d2_trace_index - 1u - back) & D2_TRACE_MASK];
}

__attribute__((export_name("d2_trace_esp")))
uint32_t d2_get_trace_esp(uint32_t back) {
  return d2_trace_esp[(d2_trace_index - 1u - back) & D2_TRACE_MASK];
}

__attribute__((export_name("d2_set_fs_base")))
void d2_set_fs_base(uint32_t value) { fs_base = value; }

__attribute__((export_name("d2_set_watch_pc")))
void d2_set_watch_pc(uint32_t value) {
  d2_watch_pc = value;
  if (value) d2_diagnostics_enabled = 1;
}

__attribute__((export_name("d2_set_stop_on_watch")))
void d2_set_stop_on_watch(uint32_t value) { d2_stop_on_watch = value; }

__attribute__((export_name("d2_set_watch_skip")))
void d2_set_watch_skip(uint32_t value) { d2_watch_skip = value; }

__attribute__((export_name("d2_set_count_pc")))
void d2_set_count_pc(uint32_t value) {
  d2_count_pc = value; d2_count_hits = 0;
  if (value) d2_diagnostics_enabled = 1;
}

__attribute__((export_name("d2_set_diagnostics")))
void d2_set_diagnostics(uint32_t value) { d2_diagnostics_enabled = value != 0; }

__attribute__((export_name("d2_count_hits")))
uint32_t d2_get_count_hits(void) { return d2_count_hits; }

__attribute__((export_name("d2_watch_hit")))
uint32_t d2_get_watch_hit(void) { return d2_watch_hit; }

__attribute__((export_name("d2_watch_register")))
uint32_t d2_get_watch_register(uint32_t index) { return index < 8u ? d2_watch_registers[index] : 0u; }
'''


def compile_wasm(
    source: Path,
    output: Path,
    initial_memory: int = 16 * 1024 * 1024,
    opt_level: str = "0",
) -> None:
    optimization_flags = []
    if opt_level != "0":
        # Lifted x86 depends on wrapping arithmetic and type-punned guest
        # memory. Page dispatch functions carry explicit noinline attributes;
        # leave ordinary inlining enabled so tiny load/store and flag helpers
        # do not become a function call for every lifted x86 instruction.
        optimization_flags = [
            "-fwrapv",
            "-fno-strict-aliasing",
            "-fno-vectorize",
            "-fno-slp-vectorize",
        ]
    command = [
        "clang",
        "--target=wasm32-unknown-unknown",
        f"-O{opt_level}",
        *optimization_flags,
        "-nostdlib",
        "-Wl,--no-entry",
        "-Wl,--export-memory",
        f"-Wl,--initial-memory={initial_memory}",
        "-Wl,--max-memory=2147483648",
        "-o",
        str(output),
        str(source),
    ]
    subprocess.run(command, check=True)


def safe_module_name(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", value)
