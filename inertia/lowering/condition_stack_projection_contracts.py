# cython: language_level=3, infer_types=True
"""Typed ownership for projected stack operands used by conditions.

Layer: Types/Lowering.
Responsibility: identify the exact stack owner and byte range represented by a
structured condition operand after stack-coordinate lowering.
Consumes alias, widening, and typed facts, including canonical stack
coordinates.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Mapping
from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen import c as structured_c
import dataclasses

CONDITION_STACK_PROJECTION_TAG_8616: str = "inertia_x86_16_condition_stack_projection"


@dataclasses.dataclass(frozen=True, )
class ConditionStackProjectionFact8616:
    """Exact owner and view coordinates for one projected stack operand."""

    base: object
    owner_offset: cython.longlong
    owner_size: cython.longlong
    view_offset: cython.longlong
    view_size: cython.longlong


@cython.ccall
def condition_stack_projection_tags_8616(
    tags: Mapping[str, object] | None,
    fact: ConditionStackProjectionFact8616,
) -> object:
    """Return copied AST tags carrying one immutable projection fact."""
    result = dict(tags or {})
    result[CONDITION_STACK_PROJECTION_TAG_8616] = fact
    return result


@cython.ccall
def condition_stack_projection_fact_8616(
    expression: structured_c.CExpression,
) -> ConditionStackProjectionFact8616 | None:
    """Return the typed projection attached to an expression or outer cast."""
    current = expression
    while True:
        tags = current.tags
        fact = (
            tags.get(CONDITION_STACK_PROJECTION_TAG_8616)
            if isinstance(tags, dict)
            else None
        )
        if isinstance(fact, ConditionStackProjectionFact8616):
            return fact
        if not isinstance(current, structured_c.CTypeCast):
            return None
        current = current.expr


__all__ = (
    "CONDITION_STACK_PROJECTION_TAG_8616",
    "ConditionStackProjectionFact8616",
    "condition_stack_projection_fact_8616",
    "condition_stack_projection_tags_8616",
)
