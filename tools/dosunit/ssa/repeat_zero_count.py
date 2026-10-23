"""Layer: dosunit SSA instruction semantics.

Responsibility: preserve exact zero-count REP state while retaining the
existing nonzero repeat summary and every modeled effect.
"""
from __future__ import annotations

from tools.dosunit.contracts.ssa import SsaExpr


def preserve_zero_count(
    before: dict[str, SsaExpr], after: dict[str, SsaExpr], counter: SsaExpr,
    memory_before: SsaExpr, memory_after: SsaExpr,
) -> SsaExpr:
    """Guard changed state by the architectural no-iteration condition.

    Control advance is applied by the caller after this state transformation.
    No direction, flag, pointer or memory-access premise is required when the
    counter is zero. Nonzero expressions remain exactly the existing summaries.
    """
    empty = SsaExpr("eq", 1, (counter, SsaExpr("const", counter.width, value=0)))
    for name, previous in before.items():
        current = after[name]
        if current is not previous:
            after[name] = SsaExpr("ite", current.width, (empty, previous, current))
    if memory_after is memory_before:
        return memory_before
    return SsaExpr("ite", 0, (empty, memory_before, memory_after))
