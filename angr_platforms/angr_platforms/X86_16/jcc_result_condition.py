"""Build zero branches from immediately preceding arithmetic register writes.

Layer: Frontend.
Responsibility: express JE/JNE through the written 16-bit result when the
adjacent decoded arithmetic instruction defines ZF from that result. Keep all
flag writes intact; this helper neither removes effects nor guesses liveness.
Other flag predicates, gaps and unsupported producers retain the FLAGS path.
"""

from __future__ import annotations

from typing import Protocol, cast

from pyvex.lifting.util.vex_helper import Type

from .ir.condition_ir import JCC_EQ_MNEMONICS_8616, JCC_NE_MNEMONICS_8616
from .jcc_condition import _ConditionInstruction

_RESULT_PRODUCER_ARITIES_8616: dict[str, int] = {
    "add_reg_imm16": 3,
    "sub_reg_imm16": 3,
    "inc_reg16": 2,
    "dec_reg16": 2,
}
_WORD_REGISTERS_8616: frozenset[str] = frozenset({"ax", "bx", "cx", "dx", "si", "di", "sp", "bp"})


class _DecodedSize8616(Protocol):
    """Capstone instruction size exposed by the frontend boundary."""

    size: int


class _PreviousInstruction8616(Protocol):
    """The preceding pyvex instruction's decoded frontend contract."""

    addr: int
    cs: _DecodedSize8616
    simple_semantics: tuple[object, ...] | None


def direct_register_result_zero_jcc_8616(
    instruction: _ConditionInstruction,
    kind: str,
    *,
    instruction_addr: int,
    previous: object | None,
) -> object | None:
    """Use the post-update result for an adjacent word-arithmetic JE/JNE.

    The previous instruction is a third-party pyvex lifecycle boundary.
    Its exact decoded adjacency is required; pending flag provenance alone
    does not prove that the result register has not since been overwritten.
    """
    if kind not in JCC_EQ_MNEMONICS_8616 | JCC_NE_MNEMONICS_8616:
        return None
    try:
        boundary = cast(_PreviousInstruction8616, previous)
        semantics = boundary.simple_semantics
        adjacent = boundary.cs.size > 0 and boundary.addr + boundary.cs.size == instruction_addr
    except AttributeError:
        return None
    if not adjacent or not isinstance(semantics, tuple) or not semantics:
        return None
    operation = semantics[0]
    if not isinstance(operation, str) or len(semantics) != _RESULT_PRODUCER_ARITIES_8616.get(operation):
        return None
    register = semantics[1]
    if not isinstance(register, str) or register not in _WORD_REGISTERS_8616:
        return None
    result = instruction.get(register, Type.int_16)
    zero = instruction.constant(0, Type.int_16)
    condition: object = result == zero if kind in JCC_EQ_MNEMONICS_8616 else result != zero
    return condition
