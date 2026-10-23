"""Prove structured comparison-guard polarity against typed replacements.

Layer: Structuring.
Responsibility: decide whether an already-structured relational guard carries
the same truth, the inverse truth, or an unproven relation to the typed
condition comparison a compatibility consumer wants to publish.
Forbidden: rendered text matching, alias recovery, or condition invention.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.

Origin tags identify the source branch but do not prove the structured
true-arm orientation: a ``CmpLT`` guard whose true arm serves the JGE
fallthrough is the *inverse* of the typed taken predicate.  Polarity is
proven only by complete ordered operand correspondence plus an exact known
operator relation; anything else is ``UNKNOWN`` and must retain the original
expression.
"""

from __future__ import annotations

from collections.abc import Callable
from enum import Enum

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CExpression,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeChar, SimTypeInt, SimTypeNum
from angr.sim_variable import SimRegisterVariable

from .condition_storage_identity import _memory_operand_identity_8616, _strip_casts_8616

__all__ = ("ConditionComparisonPolarity8616", "condition_comparison_polarity_8616")


class ConditionComparisonPolarity8616(Enum):
    """Typed truth relation between a structured guard and a typed comparison."""

    UNKNOWN = "unknown"
    DIRECT = "direct"
    INVERTED = "inverted"


_INVERSE_COMPARISON_OPS_8616: dict[str, str] = {
    "CmpEQ": "CmpNE",
    "CmpNE": "CmpEQ",
    "CmpLT": "CmpGE",
    "CmpLE": "CmpGT",
    "CmpGT": "CmpLE",
    "CmpGE": "CmpLT",
}


def _unwrap_explicit_not_8616(node: object) -> tuple[object, bool]:
    """Remove explicit ``Not`` layers, returning the core node and parity."""
    inverted = False
    while isinstance(node, CUnaryOp) and node.op == "Not":
        inverted = not inverted
        node = node.operand
    return node, inverted


def _operand_value_width_8616(node: object) -> int | None:
    """Read the C value width independently of its backing storage extent."""
    if not isinstance(node, CExpression):
        return None
    try:
        width = node.type.with_arch(node.codegen.project.arch).size
    except (AttributeError, ValueError, NotImplementedError):
        # Third-party C types without scalar layout cannot establish this view.
        return None
    return width if isinstance(width, int) and width > 0 else None


def _operand_casts_preserve_width_8616(node: object) -> bool:
    """Refuse width-changing casts, including truncation hidden by re-extension."""
    seen: set[int] = set()
    while isinstance(node, CTypeCast):
        if id(node) in seen:
            return False
        seen.add(id(node))
        width = _operand_value_width_8616(node)
        if width is None or width != _operand_value_width_8616(node.expr):
            return False
        node = node.expr
    return True


def _operand_signedness_8616(node: object) -> bool | None:
    """Require an explicit integer interpretation at the C value boundary."""
    if not isinstance(node, CExpression):
        return None
    value_type = node.type
    if not isinstance(value_type, (SimTypeChar, SimTypeInt, SimTypeNum)):
        return None
    signed = value_type.signed
    return signed if isinstance(signed, bool) else None


def _register_storage_matches_8616(left: object, right: object, width: int) -> bool:
    """Keep register extent and region evidence in addition to its offset."""
    left_variable = left.variable if isinstance(left, CVariable) else None
    right_variable = right.variable if isinstance(right, CVariable) else None
    if not isinstance(left_variable, SimRegisterVariable) and not isinstance(right_variable, SimRegisterVariable):
        return True
    if not isinstance(left_variable, SimRegisterVariable) or not isinstance(right_variable, SimRegisterVariable):
        return False
    return bool(
        left_variable.reg == right_variable.reg
        and left_variable.size == right_variable.size
        and left_variable.size * 8 >= width
        and left_variable.region == right_variable.region
    )


def _operand_storage_matches_8616(
    structured: object,
    replacement: object,
    *,
    same_expression: Callable[[object, object], bool],
) -> bool:
    """Match full-width values before comparing storage or expression identity."""
    width = _operand_value_width_8616(structured)
    if width is None or width != _operand_value_width_8616(replacement):
        return False
    signed = _operand_signedness_8616(structured)
    if signed is None or signed != _operand_signedness_8616(replacement):
        return False
    if not (
        _operand_casts_preserve_width_8616(structured)
        and _operand_casts_preserve_width_8616(replacement)
    ):
        return False
    structured = _strip_casts_8616(structured)
    replacement = _strip_casts_8616(replacement)
    if not _register_storage_matches_8616(structured, replacement, width):
        return False
    structured_identity = _memory_operand_identity_8616(structured)
    replacement_identity = _memory_operand_identity_8616(replacement)
    if structured_identity is not None or replacement_identity is not None:
        return structured_identity == replacement_identity
    if structured is replacement:
        return True
    # General expression matching ignores nested value types. Different
    # compound trees need a separate value proof before admitting polarity.
    if not isinstance(structured, (CVariable, CConstant)) or not isinstance(
        replacement, (CVariable, CConstant)
    ):
        return False
    return bool(same_expression(structured, replacement))


def condition_comparison_polarity_8616(
    structured: object,
    replacement: object,
    *,
    same_expression: Callable[[object, object], bool],
) -> ConditionComparisonPolarity8616:
    """Return the proven truth relation between a structured guard and a typed comparison.

    ``DIRECT`` means identical truth and ``INVERTED`` means the structured
    guard is the exact logical negation of the typed predicate.  ``UNKNOWN``
    honestly refuses whenever ordered operand storage identity or the
    operator relation cannot be established; operator shape alone never
    proves operand identity, and swapped operand order is not decoded.
    """
    core, not_inverted = _unwrap_explicit_not_8616(structured)
    if (
        not isinstance(core, CBinaryOp)
        or not isinstance(replacement, CBinaryOp)
        or core.op not in _INVERSE_COMPARISON_OPS_8616
        or replacement.op not in _INVERSE_COMPARISON_OPS_8616
    ):
        return ConditionComparisonPolarity8616.UNKNOWN
    ordered_match = (
        _operand_storage_matches_8616(core.lhs, replacement.lhs, same_expression=same_expression)
        and _operand_storage_matches_8616(core.rhs, replacement.rhs, same_expression=same_expression)
    )
    if not ordered_match:
        return ConditionComparisonPolarity8616.UNKNOWN
    if core.op == replacement.op:
        polarity = ConditionComparisonPolarity8616.DIRECT
    elif _INVERSE_COMPARISON_OPS_8616[core.op] == replacement.op:
        polarity = ConditionComparisonPolarity8616.INVERTED
    else:
        return ConditionComparisonPolarity8616.UNKNOWN
    if not_inverted:
        polarity = (
            ConditionComparisonPolarity8616.INVERTED
            if polarity is ConditionComparisonPolarity8616.DIRECT
            else ConditionComparisonPolarity8616.DIRECT
        )
    return polarity
