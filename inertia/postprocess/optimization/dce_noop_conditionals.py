"""Prune control nodes made observationally empty by dead-code elimination.

Layer: Rewrite/Postprocess cleanup.
Responsibility: remove only explicit empty ``if/else`` nodes whose condition is
already proven safe to discard by the owning DCE purity classifier. This module
does not recover branch meaning, alias identity, types, or control flow.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control
flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import cast

from angr.analyses.decompiler.structured_codegen.c import CIfElse, CStatements


@dataclass(frozen=True, slots=True)
class DceNoopConditionalPruneStats8616:
    """Closed evidence counters for one or more no-op conditional scans."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    refused_count: int = 0

    @property
    def changed(self) -> bool:
        """Return whether at least one proven no-op conditional was removed."""
        return self.materialized_count > 0

    @property
    def closed(self) -> bool:
        """Return whether every classified fact was materialized without loss."""
        return bool(
            self.raw_fact_count == self.normalized_fact_count
            and self.raw_fact_count
            == self.classified_fact_count + self.refused_count + self.failure_count
            and self.classified_fact_count == self.materialized_count
            and self.failure_count == 0
        )

    def merge(
        self,
        other: DceNoopConditionalPruneStats8616,
    ) -> DceNoopConditionalPruneStats8616:
        """Combine deterministic counters from consecutive DCE iterations."""
        return DceNoopConditionalPruneStats8616(
            raw_fact_count=self.raw_fact_count + other.raw_fact_count,
            normalized_fact_count=(
                self.normalized_fact_count + other.normalized_fact_count
            ),
            classified_fact_count=(
                self.classified_fact_count + other.classified_fact_count
            ),
            materialized_count=self.materialized_count + other.materialized_count,
            failure_count=self.failure_count + other.failure_count,
            refused_count=self.refused_count + other.refused_count,
        )


def _explicit_empty_if_else_condition_8616(statement: object) -> object | None:
    """Return the condition of an explicit two-arm no-op, else refuse it."""
    if not isinstance(statement, CIfElse):
        return None
    pairs = statement.condition_and_nodes
    if not isinstance(pairs, (list, tuple)) or len(pairs) != 1:
        return None
    pair = pairs[0]
    if not isinstance(pair, (list, tuple)) or len(pair) != 2:
        return None
    condition, body = pair
    if not isinstance(body, CStatements) or tuple(body.statements or ()):
        return None
    else_body = statement.else_node
    if not isinstance(else_body, CStatements) or tuple(else_body.statements or ()):
        return None
    return cast(object, condition)


def prune_explicit_empty_if_else_after_dce_8616(
    statement_blocks: Iterable[object],
    *,
    condition_is_pure: Callable[[object], bool],
) -> DceNoopConditionalPruneStats8616:
    """Remove explicit empty branches only when condition evaluation is pure."""
    raw_count = 0
    classified_count = 0
    materialized_count = 0
    refused_count = 0
    seen_blocks: set[int] = set()
    for block in statement_blocks:
        if not isinstance(block, CStatements) or id(block) in seen_blocks:
            continue
        seen_blocks.add(id(block))
        rewritten: list[object] = []
        for statement in tuple(block.statements or ()):
            condition = _explicit_empty_if_else_condition_8616(statement)
            if condition is None:
                rewritten.append(statement)
                continue
            raw_count += 1
            if not condition_is_pure(condition):
                refused_count += 1
                rewritten.append(statement)
                continue
            classified_count += 1
            materialized_count += 1
        block.statements = rewritten
    return DceNoopConditionalPruneStats8616(
        raw_fact_count=raw_count,
        normalized_fact_count=raw_count,
        classified_fact_count=classified_count,
        materialized_count=materialized_count,
        failure_count=0,
        refused_count=refused_count,
    )


__all__ = [
    "DceNoopConditionalPruneStats8616",
    "prune_explicit_empty_if_else_after_dce_8616",
]
