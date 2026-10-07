"""Project proven terminal return expressions onto angr's render surface.

Layer: Types/Lowering.
Responsibility: clear stale angr display-collapse hints only after prior
Lowering has replaced generated carriers with a side-effect-free scalar tree.
This module changes presentation metadata, never return semantics. Unresolved
or effectful expressions retain their collapse hint and are reported refused.
Consumes alias, widening, and typed facts from the authoritative Lowering tree.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616

from .terminal_return_expressions import uncollapse_safe_scalar_expression_8616

__all__ = [
    "TerminalReturnRenderProjectionResult8616",
    "TerminalReturnRenderProjectionStatus8616",
    "project_terminal_return_renderability_8616",
]


class TerminalReturnRenderProjectionStatus8616(Enum):
    """Outcome of projecting terminal return expressions for C rendering."""

    STABLE = "stable"
    MATERIALIZED = "materialized"
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class TerminalReturnRenderProjectionResult8616:
    """Typed evidence for one terminal return render projection pass."""

    status: TerminalReturnRenderProjectionStatus8616
    candidate_count: int
    materialized_expression_count: int
    uncollapsed_node_count: int
    refused_expression_count: int

    @property
    def changed(self) -> bool:
        """Return whether any stale render-collapse hint was cleared."""
        return self.uncollapsed_node_count > 0


def _collapsed_expression_count_8616(expression: object) -> int:
    """Count collapsed C expressions in one structured subtree."""
    seen: set[int] = set()
    count = 0
    for node in (expression, *_iter_c_nodes_deep_8616(expression)):
        marker = id(node)
        if marker in seen:
            continue
        seen.add(marker)
        if isinstance(node, structured_c.CExpression) and node.collapsed:
            count += 1
    return count


def project_terminal_return_renderability_8616(
    codegen: object,
) -> TerminalReturnRenderProjectionResult8616:
    """Expose safe terminal scalar returns after their typed lowering completes."""
    try:
        root = cast(Any, codegen).cfunc.statements
    except AttributeError:
        return TerminalReturnRenderProjectionResult8616(
            TerminalReturnRenderProjectionStatus8616.STABLE,
            0,
            0,
            0,
            0,
        )

    candidates = 0
    materialized = 0
    uncollapsed = 0
    refused = 0
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, structured_c.CReturn) or not isinstance(
            node.retval,
            structured_c.CExpression,
        ):
            continue
        collapsed_before = _collapsed_expression_count_8616(node.retval)
        if collapsed_before == 0:
            continue
        candidates += 1
        if not uncollapse_safe_scalar_expression_8616(node.retval):
            refused += 1
            continue
        materialized += 1
        uncollapsed += collapsed_before - _collapsed_expression_count_8616(node.retval)

    if materialized:
        status = TerminalReturnRenderProjectionStatus8616.MATERIALIZED
    elif refused:
        status = TerminalReturnRenderProjectionStatus8616.REFUSED
    else:
        status = TerminalReturnRenderProjectionStatus8616.STABLE
    return TerminalReturnRenderProjectionResult8616(
        status,
        candidates,
        materialized,
        uncollapsed,
        refused,
    )
