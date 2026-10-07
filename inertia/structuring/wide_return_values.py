"""Build semantic AIL values for multi-register returns.

Layer: Structuring.
Responsibility: combine proven return-register sources without losing either
word and fold exact constants before C code generation.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Callable

from angr import ailment
from angr.ailment.expression import Expression


def combine_word_return_sources_8616(
    high_word: Expression,
    low_word: Expression,
    *,
    next_atom: Callable[[], int],
    ins_addr: int | None,
    wide_stack_owner: Expression | None = None,
) -> Expression:
    """Combine high:low AIL words without erasing a proven wide stack owner.

    A materialized owner is accepted only from upstream Widening/Lowering.
    Independent words use explicit shift/or composition so code generation
    cannot discard the high half.
    """
    if isinstance(high_word, ailment.Expr.Const) and isinstance(low_word, ailment.Expr.Const):
        value = ((int(high_word.value) & 0xFFFF) << 16) | (int(low_word.value) & 0xFFFF)
        if value & 0x80000000:
            value -= 0x100000000
        return ailment.Expr.Const(next_atom(), value, 32, ins_addr=ins_addr)
    if wide_stack_owner is not None:
        return wide_stack_owner
    high_wide = ailment.Expr.Convert(next_atom(), 16, 32, False, high_word, ins_addr=ins_addr)
    low_wide = ailment.Expr.Convert(next_atom(), 16, 32, False, low_word, ins_addr=ins_addr)
    shift = ailment.Expr.Const(next_atom(), 16, 8, ins_addr=ins_addr)
    shifted_high = ailment.Expr.BinaryOp(
        next_atom(),
        "Shl",
        [high_wide, shift],
        bits=32,
        ins_addr=ins_addr,
    )
    return ailment.Expr.BinaryOp(
        next_atom(),
        "Or",
        [shifted_high, low_wide],
        bits=32,
        ins_addr=ins_addr,
    )
