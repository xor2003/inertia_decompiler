"""Prevent nested statement wrappers from producing unsafe braceless C.

Layer: Rewrite/Postprocess cleanup.
Responsibility: normalize only the rendering policy of structured ``if``
nodes whose direct or transparently nested bodies contain multiple statements.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control
flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.

The structured AST already owns the correct control-flow semantics. This pass
does not move statements, recover conditions, inspect rendered C, or change
observable effects; it only prevents angr's direct-child heuristic from
mistaking a multi-statement body for one C statement.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CIfElse, CStatements

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616

__all__ = (
    "StructuredBraceNormalizationStats8616",
    "normalize_multi_statement_braces_8616",
)


class _StructuredBraceCFunction8616(Protocol):
    """Minimal third-party generated C function surface."""

    statements: object


class _StructuredBraceCodegen8616(Protocol):
    """Dynamic angr codegen surface consumed by brace normalization."""

    cfunc: _StructuredBraceCFunction8616
    _inertia_structured_brace_normalization_stats_8616: StructuredBraceNormalizationStats8616


@dataclass(frozen=True, slots=True)
class StructuredBraceNormalizationStats8616:
    """Closed evidence census for structured brace normalization."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def changed(self) -> bool:
        """Return whether at least one branch was made explicitly braced."""
        return self.materialized_count > 0

    @property
    def closed(self) -> bool:
        """Return whether every classified branch was materialized."""
        return bool(
            0 <= self.classified_fact_count <= self.normalized_fact_count <= self.raw_fact_count
            and self.classified_fact_count
            == self.materialized_count + self.failure_count
        )


def _transparent_statement_count_8616(node: object) -> int:
    """Count rendered statements through transparent statement-list wrappers."""
    if not isinstance(node, CStatements):
        return int(node is not None)
    return sum(
        _transparent_statement_count_8616(statement)
        for statement in tuple(node.statements or ())
    )


def _requires_explicit_braces_8616(branch: CIfElse) -> bool:
    """Return whether a branch body contains multiple rendered statements."""
    if not branch.cstyle_ifs or len(branch.condition_and_nodes) != 1:
        return False
    _condition, true_body = branch.condition_and_nodes[0]
    false_body = branch.else_node
    return bool(
        _transparent_statement_count_8616(true_body) > 1
        or _transparent_statement_count_8616(false_body) > 1
    )


def normalize_multi_statement_braces_8616(codegen: object) -> bool:
    """Force braces around direct or transparently nested multi-statement bodies."""
    boundary = cast(_StructuredBraceCodegen8616, codegen)
    try:
        root = boundary.cfunc.statements
    except AttributeError:
        return False
    branches = tuple(
        node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CIfElse)
    )
    normalized = tuple(branch for branch in branches if branch.cstyle_ifs)
    classified = tuple(
        branch for branch in normalized if _requires_explicit_braces_8616(branch)
    )
    materialized_count = 0
    for branch in classified:
        branch.cstyle_ifs = False
        materialized_count += 1
    stats = StructuredBraceNormalizationStats8616(
        raw_fact_count=len(branches),
        normalized_fact_count=len(normalized),
        classified_fact_count=len(classified),
        materialized_count=materialized_count,
        failure_count=len(classified) - materialized_count,
    )
    if not stats.closed:
        raise ValueError("structured brace normalization evidence accounting is not closed")
    boundary._inertia_structured_brace_normalization_stats_8616 = stats
    return stats.changed
