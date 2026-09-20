"""Project proven word-result zero tests onto their input register.

Layer: IR.
Responsibility: invert a typed INC/DEC result-zero predicate with exact width
and producer binding. This is a comparison proof, not permission to remove the
register update or its flags. CFG ownership still determines branch polarity.
"""

from __future__ import annotations

from dataclasses import dataclass

from .condition_ir import ConditionIR
from .core import IRValue, MemSpace

_WORD_BITS: int = 16
_WORD_MASK: int = (1 << _WORD_BITS) - 1
_INPUT_ZERO_VALUES: dict[str, int] = {"inc_reg16": _WORD_MASK, "dec_reg16": 1}


@dataclass(frozen=True, slots=True)
class RegisterZeroInput8616:
    """Input value whose proven register update produces a zero word."""

    register: IRValue
    constant: int


def project_register_zero_input_8616(condition: ConditionIR) -> RegisterZeroInput8616 | None:
    """Return exact input equality evidence for a bound INC/DEC zero test.

    Keep the original condition and its update effects intact. Unknown producers,
    pre-update operand bindings and mismatched storage refuse this projection.
    """
    result_test = condition.op in {"zero", "nonzero"} and condition.rhs is None
    if not result_test or condition.width_bits != _WORD_BITS:
        return None
    binding_is_result = (
        isinstance(condition.producer_insn, int)
        and isinstance(condition.src_insn, int)
        and condition.producer_insn < condition.src_insn
        and condition.operand_bind_insn == condition.src_insn
    )
    if not binding_is_result:
        return None
    semantics = condition.producer_semantics
    if not isinstance(semantics, tuple) or len(semantics) != 3:
        return None
    operation, register_name, amount = semantics
    if not isinstance(operation, str) or operation not in _INPUT_ZERO_VALUES:
        return None
    if type(amount) is not int or amount != 1:
        return None
    register = condition.lhs
    if not isinstance(register, IRValue):
        return None
    same_word_register = (
        register.space is MemSpace.REG
        and register.size == _WORD_BITS // 8
        and isinstance(register_name, str)
        and register.name == register_name
    )
    if not same_word_register:
        return None
    return RegisterZeroInput8616(register, _INPUT_ZERO_VALUES[operation])
