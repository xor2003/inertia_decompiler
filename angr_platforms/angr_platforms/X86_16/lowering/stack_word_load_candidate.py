"""Check bounded C-AST candidates for one Alias-proven stack word load.

Layer: Types/Lowering.
Responsibility: classify whether a word-recomposition candidate is safe to
discard and whether its byte or direct-word variables match one exact machine
BP range. This module does not infer storage identity or mutate the C AST.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from .instruction_bp_stack_access import InstructionBpStackAccess8616
from .runtime_memory_helpers import segmented_memory_read_helper_8616


def stack_word_load_expression_has_side_effect_8616(node: object) -> bool:
    """Reject expression forms that cannot be discarded by materialization."""
    return any(
        (
            isinstance(candidate, structured_c.CFunctionCall)
            and segmented_memory_read_helper_8616(candidate) is None
        )
        or type(candidate).__name__
        in {"CAssignment", "CMultiStatementExpression"}
        for candidate in _iter_c_nodes_deep_8616(node)
    )


def stack_word_operand_is_captured_value_8616(node: object) -> bool:
    """Distinguish saved scalar bytes from current stack-storage projections.

    Load instruction provenance identifies where a capture originated, not
    whether the original memory still holds that value at its later use.
    Replacing such a scalar needs a separate value-lifetime proof.
    """
    return isinstance(node, structured_c.CVariable) and not isinstance(node.variable, SimStackVariable)


def stack_word_byte_pair_matches_machine_bp_view_8616(
    low: object,
    high: object,
) -> bool:
    """Require adjacent stack coordinates when both byte views are variables."""
    if not isinstance(low, structured_c.CVariable):
        return False
    if not isinstance(high, structured_c.CVariable):
        return True
    low_variable = low.variable
    high_variable = high.variable
    return bool(
        isinstance(low_variable, SimStackVariable)
        and isinstance(high_variable, SimStackVariable)
        and low_variable.base == high_variable.base == "bp"
        and isinstance(low_variable.offset, int)
        and isinstance(high_variable.offset, int)
        and high_variable.offset == low_variable.offset + 1
        and high_variable.size == 1
    )


def direct_machine_bp_word_owner_8616(
    low: object,
    load: InstructionBpStackAccess8616,
) -> structured_c.CVariable | None:
    """Return a C word whose machine-BP range exactly matches Alias evidence."""
    if not isinstance(low, structured_c.CVariable):
        return None
    variable = low.variable
    if (
        isinstance(variable, SimStackVariable)
        and variable.base == "bp"
        and variable.offset == load.displacement
        and variable.size == load.size == 2
    ):
        return low
    return None


__all__ = [
    "direct_machine_bp_word_owner_8616",
    "stack_word_byte_pair_matches_machine_bp_view_8616",
    "stack_word_load_expression_has_side_effect_8616",
    "stack_word_operand_is_captured_value_8616",
]
