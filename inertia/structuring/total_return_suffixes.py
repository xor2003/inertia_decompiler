"""Prune unreachable suffixes after proven total-return conditionals.

Layer: Structuring.
Responsibility: remove label-free statements that follow a structured
if/else-if/else whose every branch is a proved return.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.

This is control-flow pruning, not generic DCE. A suffix is removed only when
the preceding multi-arm node carries Structuring proof markers and every arm,
including else, terminates with one return. Labels force refusal because an
external structured goto may still enter the apparent suffix.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import cast

from angr.analyses.decompiler.structured_codegen.c import (
    CIfElse,
    CLabel,
    CStatements,
)

from .multi_arm_return_chains import is_materialized_multi_arm_return_chain_8616


@dataclass(frozen=True, slots=True)
class TotalReturnSuffixPruneStats8616:
    """Closed evidence accounting for total-return suffix pruning."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class TotalReturnSuffixPruneResult8616:
    """Mutation count and evidence status for one Structuring prune pass."""

    removed_statement_count: int = 0
    stats: TotalReturnSuffixPruneStats8616 = TotalReturnSuffixPruneStats8616()


def _contains_label_8616(root: object) -> bool:
    """Return whether one dynamic angr C-AST subtree contains a label."""
    pending = [root]
    while pending:
        current = pending.pop()
        if isinstance(current, CLabel):
            return True
        if isinstance(current, CStatements):
            pending.extend(cast(Iterable[object], current.statements or ()))
        elif isinstance(current, CIfElse):
            pending.extend(
                body
                for _condition, body in tuple(current.condition_and_nodes or ())
                if body is not None
            )
            if current.else_node is not None:
                pending.append(current.else_node)
    return False


def prune_unreachable_total_return_suffixes_8616(
    root: object,
) -> TotalReturnSuffixPruneResult8616:
    """Remove label-free suffixes after every proved total-return conditional."""
    scan = _ReturnSuffixPruneScan8616()
    if isinstance(root, CStatements):
        scan.prune_container(root)
    return TotalReturnSuffixPruneResult8616(
        removed_statement_count=scan.removed_count,
        stats=TotalReturnSuffixPruneStats8616(
            raw_fact_count=scan.raw_count,
            normalized_fact_count=scan.normalized_count,
            classified_fact_count=scan.classified_count,
            materialized_count=scan.materialized_count,
            failure_count=scan.failure_count,
        ),
    )


@dataclass(slots=True)
class _ReturnSuffixPruneScan8616:
    """Mutable counters for one total-return suffix prune scan."""

    raw_count: int = 0
    normalized_count: int = 0
    classified_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    removed_count: int = 0

    def prune_container(self, container: CStatements) -> None:
        """Prune unreachable suffixes inside one statement container."""
        statements = list(cast(Iterable[object], container.statements or ()))
        for index, statement in enumerate(tuple(statements)):
            if isinstance(statement, CStatements):
                self.prune_container(statement)
            elif isinstance(statement, CIfElse):
                for _condition, body in tuple(statement.condition_and_nodes or ()):
                    if isinstance(body, CStatements):
                        self.prune_container(body)
                if isinstance(statement.else_node, CStatements):
                    self.prune_container(statement.else_node)
                arms = tuple(statement.condition_and_nodes or ())
                if not is_materialized_multi_arm_return_chain_8616(
                    arms, statement.else_node
                ):
                    continue
                self.raw_count += 1
                self.normalized_count += 1
                suffix = statements[index + 1 :]
                if not suffix:
                    continue
                if any(_contains_label_8616(item) for item in suffix):
                    self.failure_count += 1
                    continue
                self.classified_count += 1
                self.removed_count += len(suffix)
                self.materialized_count += 1
                container.statements = statements[: index + 1]
                return
