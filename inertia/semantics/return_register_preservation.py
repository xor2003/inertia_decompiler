# cython: language_level=3, infer_types=True
"""Classify instructions that preserve x86 return registers.

Layer: Semantics.
Responsibility: prove that one decoded instruction leaves AX and DX unchanged.
Consumes structured Capstone operands at the dynamic frontend boundary.
Do not perform CFG traversal, lowering, AST mutation, or rendered-text recovery.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Sequence
from typing import Protocol, cast

_RETURN_REGISTER_ALIASES_8616: frozenset[str] = frozenset(
    {"ax", "ah", "al", "eax", "dx", "dh", "dl", "edx"}
)


class _RegisterOperand8616(Protocol):
    """Typed view of the third-party Capstone register operand boundary."""

    type: cython.longlong
    reg: cython.longlong


class _Instruction8616(Protocol):
    """Typed view of the third-party Capstone instruction boundary."""

    mnemonic: object
    operands: Sequence[_RegisterOperand8616]

    def reg_name(self, register_id: cython.longlong) -> object:
        """Return the architecture register name for one Capstone id."""


@cython.ccall
def _operand_kind_8616(operand: _RegisterOperand8616) -> cython.longlong:
    """Return one Capstone operand kind at the typed frontend boundary."""
    return int(operand.type)


@cython.ccall
def _register_name_8616(insn: _Instruction8616, operand: _RegisterOperand8616) -> object:
    """Return one Capstone register name at the typed frontend boundary."""
    if not isinstance(operand.reg, int):
        return ""
    return str(insn.reg_name(operand.reg)).lower()


def instruction_preserves_return_registers_8616(insn: object) -> cython.bint:
    """Return whether a proven epilogue step preserves both AX and DX."""
    typed_insn = cast(_Instruction8616, insn)
    mnemonic = str(typed_insn.mnemonic).lower()
    operands = tuple(typed_insn.operands or ())
    if mnemonic in {"leave", "nop"}:
        return not operands
    if mnemonic == "pop" and len(operands) == 1 and _operand_kind_8616(operands[0]) == 1:
        register_name = _register_name_8616(typed_insn, operands[0])
        return bool(register_name) and register_name not in _RETURN_REGISTER_ALIASES_8616
    return (
        mnemonic == "mov"
        and len(operands) == 2
        and all(_operand_kind_8616(operand) == 1 for operand in iter(operands))
        and _register_name_8616(typed_insn, operands[0]) == "sp"
        and _register_name_8616(typed_insn, operands[1]) == "bp"
    )
