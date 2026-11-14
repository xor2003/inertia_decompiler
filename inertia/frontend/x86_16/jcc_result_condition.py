# cython: language_level=3, infer_types=True
"""Build zero branches from immediately preceding arithmetic register writes.

Layer: Frontend.
Responsibility: express JE/JNE through the written 16-bit result when the
adjacent decoded arithmetic instruction defines ZF from that result. Keep all
flag writes intact; this helper neither removes effects nor guesses liveness.
Other flag predicates, gaps and unsupported producers retain the FLAGS path.
"""

from __future__ import annotations
import typing
import cython

from typing import Protocol, cast

from pyvex.lifting.util.vex_helper import Type

from inertia.frontend.x86_16.jcc_condition import _ConditionInstruction
from inertia.ir.condition_ir import JCC_EQ_MNEMONICS_8616, JCC_NE_MNEMONICS_8616
import operator

_RESULT_PRODUCER_ARITIES_8616: dict[str, cython.longlong] = {
    "add_reg_imm16": 3,
    "sub_reg_imm16": 3,
    "inc_reg16": 2,
    "dec_reg16": 2,
}
_WORD_REGISTERS_8616: frozenset[str] = frozenset({"ax", "bx", "cx", "dx", "si", "di", "sp", "bp"})


class _DecodedSize8616(Protocol):
    """Capstone instruction size exposed by the frontend boundary."""

    size: cython.longlong


class _PreviousInstruction8616(Protocol):
    """The preceding pyvex instruction's decoded frontend contract."""

    addr: cython.longlong
    cs: _DecodedSize8616
    simple_semantics: object


@cython.ccall
def direct_register_result_zero_jcc_8616(
    instruction: _ConditionInstruction,
    kind: object,
    *,
    instruction_addr: cython.longlong,
    previous: object | None,
) -> object | None:
    """Use the post-update result for an adjacent word-arithmetic JE/JNE.

    The previous instruction is a third-party pyvex lifecycle boundary.
    Its exact decoded adjacency is required; pending flag provenance alone
    does not prove that the result register has not since been overwritten.
    """
    result: object
    if kind not in JCC_EQ_MNEMONICS_8616 | JCC_NE_MNEMONICS_8616:
        return None
    try:
        boundary = cast(_PreviousInstruction8616, previous)
        semantics = boundary.simple_semantics
        adjacent = boundary.cs.size > 0 and operator.eq(boundary.addr + boundary.cs.size, instruction_addr)
    except AttributeError:
        return None
    if not adjacent or not isinstance(semantics, tuple) or not semantics:
        return None
    operation = semantics[0]
    if not isinstance(operation, str) or operator.ne(len(semantics), _RESULT_PRODUCER_ARITIES_8616.get(operation)):
        return None
    register = semantics[1]
    if not isinstance(register, str) or register not in _WORD_REGISTERS_8616:
        return None
    result = instruction.get(register, Type.int_16)
    zero = instruction.constant(0, Type.int_16)
    condition: object = operator.eq(result, zero) if kind in JCC_EQ_MNEMONICS_8616 else operator.ne(result, zero)
    return condition
