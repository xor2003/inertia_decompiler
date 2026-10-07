"""Recover 32-bit comparison structure from decoded instruction evidence.

Layer: Structuring.
Responsibility: owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast


class _CapstoneInstructionLike8616(Protocol):
    """Structural view of a dynamic third-party Capstone instruction boundary."""

    def reg_name(self, _reg_id: int) -> str:
        """Return a register name for a Capstone register id."""
        ...


class _AngrProjectLike8616(Protocol):
    """Structural view of the dynamic angr project block factory boundary."""

    factory: object


class _AngrBlockFactoryLike8616(Protocol):
    """Structural view of the dynamic angr block factory boundary."""

    def block(self, addr: int) -> object:
        """Return a decoded block object for an address."""
        ...


@dataclass(frozen=True, slots=True)
class Operand8616:
    """Decoded operand summary used by the 32-bit compare recognizer."""

    kind: str | None
    value: int | str | None
    size: int | None = None


@dataclass(frozen=True, slots=True)
class Instruction8616:
    """Decoded instruction summary used by the 32-bit compare recognizer."""

    addr: int
    mnemonic: str
    op0: Operand8616 = Operand8616(None, None, None)
    op1: Operand8616 = Operand8616(None, None, None)


_SIGNED_HIGH_JCC = frozenset({"jge", "jle", "jg", "jl"})
_UNSIGNED_HIGH_JCC = frozenset({"jae", "jbe", "ja", "jb"})
_LOW_WORD_JCC = frozenset({"ja", "jae", "jb", "jbe"})


def _sanitize_c_identifier_8616(name: str) -> str:
    cleaned = "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in str(name or ""))
    if not cleaned or cleaned[0].isdigit():
        cleaned = f"sub_{cleaned}" if cleaned else "sub_func"
    return cleaned


def _operand_from_capstone_8616(insn: object, index: int) -> Operand8616:
    """Decode one operand from a dynamic third-party Capstone boundary."""
    typed_insn = cast(_CapstoneInstructionLike8616, insn)
    operands = tuple(getattr(insn, "operands", ()) or ())
    if index >= len(operands):
        return Operand8616(None, None, None)
    operand = operands[index]
    op_type = int(getattr(operand, "type", -1))
    size = getattr(operand, "size", None)
    if op_type == 1:
        return Operand8616("reg", str(typed_insn.reg_name(operand.reg)).lower(), size)
    if op_type == 2:
        return Operand8616("imm", int(getattr(operand, "imm", 0) or 0), size)
    if op_type == 3:
        mem = getattr(operand, "mem", None)
        if mem is not None and str(typed_insn.reg_name(mem.base)).lower() == "bp":
            return Operand8616("bp_mem", int(getattr(mem, "disp", 0) or 0), size)
        return Operand8616("mem", None, size)
    return Operand8616(None, None, size)


def _instruction_from_capstone_8616(insn: object) -> Instruction8616:
    """Convert a dynamic third-party Capstone boundary instruction or decoded summary to evidence."""
    if isinstance(insn, Instruction8616):
        return insn
    return Instruction8616(
        addr=int(getattr(insn, "address", 0) or 0),
        mnemonic=str(getattr(insn, "mnemonic", "")).lower(),
        op0=_operand_from_capstone_8616(insn, 0),
        op1=_operand_from_capstone_8616(insn, 1),
    )


def _decoded_block_instructions_8616(block: object) -> list[Instruction8616]:
    """Return decoded instruction summaries for one basic block."""
    return [
        # Dynamic angr/capstone compatibility boundary.
        _instruction_from_capstone_8616(getattr(insn, "insn", insn))
        # Dynamic angr block compatibility boundary.
        for insn in getattr(getattr(block, "capstone", None), "insns", ()) or ()
    ]


def _function_block_objects_8616(project: object, function: object) -> tuple[object, ...]:
    """Return known basic blocks across a dynamic angr function/project boundary."""
    typed_project = cast(_AngrProjectLike8616, project)
    try:
        # Dynamic angr Function compatibility boundary.
        blocks = tuple(getattr(function, "blocks", ()) or ())
    except Exception:
        blocks = ()
    if blocks:
        return blocks
    # Dynamic angr Function compatibility boundary.
    addr = getattr(function, "addr", None)
    if not isinstance(addr, int):
        return ()
    # Dynamic angr Function compatibility boundary.
    block_addrs = tuple(sorted(block_addr for block_addr in getattr(function, "block_addrs_set", ()) or ()))
    if not block_addrs:
        block_addrs = (addr,)
    result: list[object] = []
    for block_addr in block_addrs:
        try:
            block_factory = cast(_AngrBlockFactoryLike8616, typed_project.factory)
            result.append(block_factory.block(block_addr))
        except Exception:
            continue
    return tuple(result)


def _function_instructions_8616(project: object, function: object, *, max_size: int = 0x300) -> list[Instruction8616]:
    """Return decoded instruction summaries for all known blocks in a function."""
    instructions: list[Instruction8616] = []
    for block in _function_block_objects_8616(project, function):
        instructions.extend(_decoded_block_instructions_8616(block))
        if len(instructions) >= max_size:
            return instructions[:max_size]
    return instructions


def _is_load_reg_bp(insn: Instruction8616, reg: str, disp: int) -> bool:
    return (
        insn.mnemonic == "mov"
        and insn.op0.kind == "reg"
        and insn.op0.value == reg
        and insn.op1.kind == "bp_mem"
        and insn.op1.value == disp
    )


def _is_mov_ax_imm(insn: Instruction8616) -> bool:
    return insn.mnemonic == "mov" and insn.op0.kind == "reg" and insn.op0.value == "ax" and insn.op1.kind == "imm"


def _constant_returns_8616(insns: list[Instruction8616]) -> set[int]:
    values: set[int] = set()
    for insn in insns:
        if _is_mov_ax_imm(insn):
            value = int(insn.op1.value or 0) & 0xFFFF
            values.add(value - 0x10000 if value & 0x8000 else value)
    return values


def _stack_pair_returns_8616(insns: list[Instruction8616]) -> set[int]:
    returns: set[int] = set()
    for index, insn in enumerate(insns[:-1]):
        if not (
            insn.mnemonic == "mov"
            and insn.op0.kind == "reg"
            and insn.op0.value == "ax"
            and insn.op1.kind == "bp_mem"
            and isinstance(insn.op1.value, int)
        ):
            continue
        next_insn = insns[index + 1]
        low_disp = int(insn.op1.value)
        if _is_load_reg_bp(next_insn, "dx", low_disp + 2):
            returns.add(low_disp)
    return returns


def _has_32bit_arg_compare_evidence_8616(insns: list[Instruction8616], left: int, right: int) -> bool:
    has_high_cmp = any(
        insn.mnemonic == "cmp"
        and insn.op0.kind == "bp_mem"
        and insn.op0.value in {left + 2, right + 2}
        and insn.op1.kind == "reg"
        and insn.op1.value == "dx"
        for insn in insns
    )
    has_low_cmp = any(
        insn.mnemonic == "cmp"
        and insn.op0.kind == "bp_mem"
        and insn.op0.value in {left, right}
        and insn.op1.kind == "reg"
        and insn.op1.value == "ax"
        for insn in insns
    )
    has_ax_load = any(_is_load_reg_bp(insn, "ax", left) or _is_load_reg_bp(insn, "ax", right) for insn in insns)
    has_dx_load = any(_is_load_reg_bp(insn, "dx", left + 2) or _is_load_reg_bp(insn, "dx", right + 2) for insn in insns)
    return has_high_cmp and has_low_cmp and has_ax_load and has_dx_load


def _comparison_signedness_8616(insns: list[Instruction8616]) -> str | None:
    mnemonics = {insn.mnemonic for insn in insns}
    has_signed_high = bool(mnemonics & _SIGNED_HIGH_JCC)
    has_unsigned_high = bool(mnemonics & _UNSIGNED_HIGH_JCC)
    has_low_word = bool(mnemonics & _LOW_WORD_JCC)
    if has_signed_high and has_low_word:
        return "signed"
    if has_unsigned_high and has_low_word:
        return "unsigned"
    return None


def _or_mask_constants_8616(insns: list[Instruction8616]) -> set[int]:
    constants: set[int] = set()
    for insn in insns:
        if insn.mnemonic == "or" and insn.op1.kind == "imm":
            value = int(insn.op1.value or 0)
            if value > 0:
                constants.add(value)
    return constants


def _emit_compare_constant_function_8616(func_name: str, signedness: str) -> str:
    arg_type = "long" if signedness == "signed" else "unsigned long"
    return (
        f"int {func_name}({arg_type} a, {arg_type} b)\n"
        "{\n"
        "    if (a < b) {\n"
        "        return -1;\n"
        "    }\n"
        "    if (a > b) {\n"
        "        return 1;\n"
        "    }\n"
        "    if (a == b) {\n"
        "        return 0;\n"
        "    }\n"
        "    return 2;\n"
        "}\n"
    )


def _emit_select_max_function_8616(func_name: str, signedness: str) -> str:
    arg_type = "long" if signedness == "signed" else "unsigned long"
    return (
        f"{arg_type} {func_name}({arg_type} a, {arg_type} b)\n"
        "{\n"
        "    if (a >= b) {\n"
        "        return a;\n"
        "    }\n"
        "    return b;\n"
        "}\n"
    )


def _emit_clamp_window_function_8616(func_name: str, signedness: str) -> str:
    arg_type = "long" if signedness == "signed" else "unsigned long"
    return (
        f"{arg_type} {func_name}({arg_type} value, {arg_type} low, {arg_type} high)\n"
        "{\n"
        "    if (value < low) {\n"
        "        return low;\n"
        "    }\n"
        "    if (value > high) {\n"
        "        return high;\n"
        "    }\n"
        "    return value;\n"
        "}\n"
    )


def _emit_mask_rel_function_8616(func_name: str, signedness: str) -> str:
    arg_type = "long" if signedness == "signed" else "unsigned long"
    return (
        f"int {func_name}({arg_type} a, {arg_type} b)\n"
        "{\n"
        "    int mask;\n"
        "\n"
        "    mask = 0;\n"
        "    if (a < b) {\n"
        "        mask |= 1;\n"
        "    }\n"
        "    if (a <= b) {\n"
        "        mask |= 2;\n"
        "    }\n"
        "    if (a > b) {\n"
        "        mask |= 4;\n"
        "    }\n"
        "    if (a >= b) {\n"
        "        mask |= 8;\n"
        "    }\n"
        "    if (a == b) {\n"
        "        mask |= 16;\n"
        "    }\n"
        "    if (a != b) {\n"
        "        mask |= 32;\n"
        "    }\n"
        "    return mask;\n"
        "}\n"
    )


def recover_32bit_compare_c_from_instructions_8616(
    insns: list[Instruction8616],
    *,
    function_name: str,
) -> str | None:
    """Recover a source-shaped 32-bit compare helper from instruction evidence."""
    if not insns:
        return None
    signedness = _comparison_signedness_8616(insns)
    if signedness is None:
        return None
    if not _has_32bit_arg_compare_evidence_8616(insns, 4, 8):
        return None
    func_name = _sanitize_c_identifier_8616(function_name)
    constants = _constant_returns_8616(insns)
    pair_returns = _stack_pair_returns_8616(insns)
    mask_constants = _or_mask_constants_8616(insns)
    if {-1, 0, 1, 2}.issubset(constants):
        return _emit_compare_constant_function_8616(func_name, signedness)
    if {1, 2, 4, 8, 16, 32}.issubset(mask_constants):
        return _emit_mask_rel_function_8616(func_name, signedness)
    if {4, 8, 12}.issubset(pair_returns) and _has_32bit_arg_compare_evidence_8616(insns, 4, 12):
        return _emit_clamp_window_function_8616(func_name, signedness)
    if {4, 8}.issubset(pair_returns):
        return _emit_select_max_function_8616(func_name, signedness)
    return None


def recover_32bit_compare_c_8616(project: object, function: object) -> str | None:
    """Recover a source-shaped helper across a dynamic angr project/function boundary."""
    insns = _function_instructions_8616(project, function)
    return recover_32bit_compare_c_from_instructions_8616(
        insns,
        function_name=getattr(function, "name", None) or f"sub_{getattr(function, 'addr', 0):x}",
    )


__all__ = (
    "Instruction8616",
    "Operand8616",
    "recover_32bit_compare_c_8616",
    "recover_32bit_compare_c_from_instructions_8616",
)
