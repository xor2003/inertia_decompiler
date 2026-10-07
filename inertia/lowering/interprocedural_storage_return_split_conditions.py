"""Compatibility surface for typed split-return decision-graph selection.

Layer: Types/Lowering.
Responsibility: preserve the established import surface while the decision
graph owner proves strict, non-strict, equality, and inequality forms from
typed operands and exact SSA CFG edges. No semantic recovery lives in this
facade. Consumes alias, widening, and typed facts through the decision-graph
owner. Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from .interprocedural_storage_return_split_condition_graph import (
    SplitReturnConditionCandidate8616,
    select_split_return_condition_8616,
    split_return_register_matches_8616,
)

__all__ = [
    "SplitReturnConditionCandidate8616",
    "select_split_return_condition_8616",
    "split_return_register_matches_8616",
]
