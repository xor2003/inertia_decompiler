"""Flatten associative bitwise syntax without discarding typed view owners.

Layer: Rewrite/Postprocess cleanup.
Responsibility: keep evidence-bearing stack projections atomic during cleanup.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control
flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
"""

from __future__ import annotations

from collections.abc import Callable

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp

from ..lowering.condition_stack_projection_contracts import condition_stack_projection_fact_8616


def flatten_bitwise_terms_8616(
    expression: object,
    operator: str,
    unwrap: Callable[[object], object],
) -> list[object]:
    """Flatten syntax-only operands while retaining existing projection facts.

    Rebuilding a tagged projection from its leaves would erase its storage/view
    identity. Preserve that complete subtree; do not copy its fact to a newly
    composed expression whose mask or source may differ.
    """
    expression = unwrap(expression)
    if (
        isinstance(expression, CBinaryOp)
        and expression.op == operator
        and condition_stack_projection_fact_8616(expression) is None
    ):
        return (
            flatten_bitwise_terms_8616(expression.lhs, operator, unwrap)
            + flatten_bitwise_terms_8616(expression.rhs, operator, unwrap)
        )
    return [expression]
